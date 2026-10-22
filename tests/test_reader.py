"""Capture import: formats, damage handling, limits, cancellation and read-only access."""

from __future__ import annotations

import hashlib
import os

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from trace_zero.config import Limits
from trace_zero.parsing.reader import CaptureError, ParseCancelled, read_capture, read_frame_bytes, validate_capture_path

from .conftest import ETH, pcap_bytes, write_pcap

FRAME = bytes(ETH() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(flags="S"))


def test_reads_pcap_and_pcapng_identically(sample_pcap, sample_pcapng):
    a = read_capture(sample_pcap)
    b = read_capture(sample_pcapng)
    assert a.file.fmt == "pcap" and b.file.fmt == "pcapng"
    assert len(a.packets) == len(b.packets) > 2000
    assert not a.truncated and not b.truncated
    for pa, pb in zip(a.packets[:200], b.packets[:200]):
        assert (pa.src, pa.dst, pa.proto, pa.wirelen) == (pb.src, pb.dst, pb.proto, pb.wirelen)
        assert abs(pa.ts - pb.ts) < 1e-5


def test_sha256_and_file_untouched(sample_pcap):
    before = sample_pcap.read_bytes()
    st = os.stat(sample_pcap)
    r = read_capture(sample_pcap)
    assert r.file.sha256 == hashlib.sha256(before).hexdigest()
    assert sample_pcap.read_bytes() == before
    assert os.stat(sample_pcap).st_mtime_ns == st.st_mtime_ns


def test_frame_numbers_and_timestamps(tmp_path):
    f = write_pcap(tmp_path / "t.pcap", [(100.25, FRAME), (101.5, FRAME), (99.0, FRAME)])
    r = read_capture(f)
    assert [p.no for p in r.packets] == [1, 2, 3]
    assert [p.ts for p in r.packets] == [100.25, 101.5, 99.0]


def test_nanosecond_pcap(tmp_path):
    f = write_pcap(tmp_path / "ns.pcap", [(1.000000123, FRAME)], nano=True)
    r = read_capture(f)
    assert abs(r.packets[0].ts - 1.000000123) < 1e-9


def test_empty_file_rejected(tmp_path):
    f = tmp_path / "empty.pcap"
    f.write_bytes(b"")
    with pytest.raises(CaptureError, match="empty"):
        read_capture(f)


def test_header_only_capture_has_zero_packets(tmp_path):
    f = tmp_path / "hdr.pcap"
    f.write_bytes(pcap_bytes([]))
    r = read_capture(f)
    assert r.packets == [] and not r.truncated


def test_not_a_capture(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text("hello world, definitely not a capture")
    with pytest.raises(CaptureError, match="not a PCAP"):
        read_capture(f)


def test_gzip_rejected_clearly(tmp_path):
    f = tmp_path / "c.pcap.gz"
    f.write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * 20)
    with pytest.raises(CaptureError, match="compressed"):
        read_capture(f)


def test_directory_and_missing_paths(tmp_path):
    with pytest.raises(CaptureError, match="directory"):
        validate_capture_path(tmp_path, Limits())
    with pytest.raises(CaptureError, match="not found"):
        validate_capture_path(tmp_path / "missing.pcap", Limits())
    with pytest.raises(CaptureError, match="no file"):
        validate_capture_path("   ", Limits())


def test_size_limit(tmp_path):
    f = write_pcap(tmp_path / "big.pcap", [(1.0, FRAME)] * 10)
    with pytest.raises(CaptureError, match="limit"):
        validate_capture_path(f, Limits(max_file_mb=0))


def test_truncated_file_keeps_recovered_packets(tmp_path):
    data = pcap_bytes([(1.0, FRAME), (2.0, FRAME), (3.0, FRAME)])
    f = tmp_path / "cut.pcap"
    f.write_bytes(data[:-10])  # last record cut mid-packet
    r = read_capture(f)
    assert r.truncated
    assert len(r.packets) >= 2
    assert r.packets[0].src == "10.0.0.1"
    assert r.warnings or r.stop_reason


def test_truncated_inside_record_header(tmp_path):
    data = pcap_bytes([(1.0, FRAME), (2.0, FRAME)])
    f = tmp_path / "cut2.pcap"
    f.write_bytes(data[: 24 + 16 + len(FRAME) + 7])
    r = read_capture(f)
    assert len(r.packets) == 1
    assert r.truncated


def test_hostile_pcapng_block_length(tmp_path, sample_pcapng):
    data = bytearray(sample_pcapng.read_bytes())
    # Corrupt the second block's length field to an enormous value.
    shb_len = int.from_bytes(data[4:8], "little")
    data[shb_len + 4 : shb_len + 8] = (0xFFFFFFF0).to_bytes(4, "little")
    f = tmp_path / "hostile.pcapng"
    f.write_bytes(bytes(data))
    try:
        r = read_capture(f)
    except CaptureError:
        return  # refusing the file is acceptable
    assert r.truncated and len(r.packets) == 0


def test_packet_limit_truncates(tmp_path):
    f = write_pcap(tmp_path / "many.pcap", [(float(i), FRAME) for i in range(50)])
    r = read_capture(f, Limits(max_packets=20, batch_size=5))
    assert len(r.packets) == 20 and r.truncated and "limit" in r.stop_reason


def test_progress_and_cancellation(tmp_path):
    f = write_pcap(tmp_path / "p.pcap", [(float(i), FRAME) for i in range(100)])
    stages = []
    read_capture(f, Limits(batch_size=10), progress=lambda st, n, d, t: stages.append((st, n)))
    assert any(st == "parsing" and n > 0 for st, n in stages)
    calls = {"n": 0}

    def cancel():
        calls["n"] += 1
        return calls["n"] > 1

    with pytest.raises(ParseCancelled):
        read_capture(f, Limits(batch_size=10), cancelled=cancel)


def test_snaplen_truncated_frame(tmp_path):
    full = bytes(ETH() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(flags="PA") / (b"x" * 400))
    f = write_pcap(tmp_path / "snap.pcap", [(1.0, full[:60])], wirelens=[len(full)])
    p = read_capture(f).packets[0]
    assert p.caplen == 60 and p.wirelen == len(full)
    assert p.payload_len == 400  # derived from the IP header, not invented


def test_read_frame_bytes_roundtrip(sample_pcap):
    r = read_capture(sample_pcap)
    data, lt = read_frame_bytes(r.file, 5)
    assert lt == 1 and len(data) == r.packets[4].caplen


def test_read_frame_bytes_detects_modified_file(tmp_path):
    f = write_pcap(tmp_path / "m.pcap", [(1.0, FRAME)])
    r = read_capture(f)
    f.write_bytes(pcap_bytes([(1.0, FRAME), (2.0, FRAME)]))
    with pytest.raises(CaptureError, match="changed"):
        read_frame_bytes(r.file, 1)
