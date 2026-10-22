"""PCAPNG export and Wireshark filter translation (cross-checked with tshark when installed)."""

from __future__ import annotations

import shutil
import subprocess

import pytest
from scapy.utils import PcapNgReader, rdpcap

from trace_zero.analysis.filters import compile_filter, frames_filter
from trace_zero.analysis.wireshark import to_wireshark
from trace_zero.parsing.reader import CaptureError, read_capture
from trace_zero.parsing.writer import export_frames

from .conftest import ETH, write_pcap

TSHARK = shutil.which("tshark")
needs_tshark = pytest.mark.skipif(TSHARK is None, reason="tshark not installed")

EXACT = [
    "host:10.20.0.11", "src:10.20.0.0/24 !proto:arp", "dst:192.0.2.44", "port:443", "dport:1-1024", "sport:53",
    "proto:tcp", "proto:udp", "proto:icmp|icmpv6", "proto:arp", "proto:ipv4", "proto:ipv6", "proto:dns", "proto:mdns",
    "proto:http", "proto:tls", "flags:S !flags:A", "flags:SA", "flags:R", "len>1000", "len<=60", "t>200 t<205",
    "dns:telemetry", "dns:LEGACY", "mac:02:00:00:00:00:0d", "host:2001:db8::/32", "!port:445 proto:tcp host:10.20.0.14",
]


def test_export_roundtrip_is_byte_exact(sample_pcap, tmp_path):
    src = read_capture(sample_pcap)
    wanted = {p.no for p in src.packets if p.app == "DNS"}
    out = tmp_path / "dns.pcapng"
    n = export_frames(src.file, wanted, out, "unit test")
    assert n == len(wanted)
    back = read_capture(out)
    originals = [p for p in src.packets if p.no in wanted]
    assert [(p.src, p.dst, p.wirelen, p.dns.qname) for p in back.packets] == [(p.src, p.dst, p.wirelen, p.dns.qname) for p in originals]
    assert all(abs(a.ts - b.ts) < 1e-6 for a, b in zip(back.packets, originals))
    # Independent reader: scapy's own PCAPNG parser sees the same frames and the provenance comment.
    raw_src = {p.no: bytes(x) for p, x in zip(src.packets, rdpcap(str(sample_pcap))) if p.no in wanted}
    scapy_back = list(PcapNgReader(str(out)))
    assert [bytes(x) for x in scapy_back] == [raw_src[no] for no in sorted(wanted)]
    assert b"unit test" in out.read_bytes()[:200]


def test_export_refuses_source_and_changed_file(tmp_path):
    from scapy.layers.inet import IP, TCP

    f = write_pcap(tmp_path / "a.pcap", [(1.0, bytes(ETH() / IP() / TCP()))])
    r = read_capture(f)
    with pytest.raises(CaptureError):
        export_frames(r.file, {1}, f, "x")
    f.write_bytes(f.read_bytes() + b"\x00")
    with pytest.raises(CaptureError):
        export_frames(r.file, {1}, tmp_path / "b.pcapng", "x")


def test_translation_text():
    assert to_wireshark(None) == ("", [])
    expr, notes = to_wireshark(compile_filter("proto:dns !host:10.0.0.1 port:53,5353"))
    assert expr == "dns && !(ip.addr==10.0.0.1 || arp.src.proto_ipv4==10.0.0.1 || arp.dst.proto_ipv4==10.0.0.1) && (tcp.port==53 || udp.port==53 || tcp.port==5353 || udp.port==5353)"
    assert notes == []
    expr, notes = to_wireshark(compile_filter("beacon"))
    assert expr == 'frame contains "beacon"' and notes
    expr, notes = to_wireshark(frames_filter({3, 1, 2}, "evidence"))
    assert expr == "frame.number in {1 2 3}" and notes


@needs_tshark
@pytest.mark.parametrize("expr", EXACT)
def test_translation_matches_wireshark_exactly(loaded_sample, sample_pcap, expr):
    pk = loaded_sample.result.packets
    flt = compile_filter(expr, loaded_sample.index.t0)
    ours = sum(1 for p in pk if flt(p))
    ws, _notes = to_wireshark(flt, loaded_sample.index.t0)
    out = subprocess.run([TSHARK, "-r", str(sample_pcap), "-Y", ws, "-T", "fields", "-e", "frame.number"], capture_output=True, text=True, check=True)
    assert len(out.stdout.split()) == ours


@needs_tshark
def test_wireshark_reads_export(sample_pcap, tmp_path):
    src = read_capture(sample_pcap)
    out = tmp_path / "all.pcapng"
    export_frames(src.file, {p.no for p in src.packets}, out, "full copy")
    res = subprocess.run([TSHARK, "-r", str(out), "-T", "fields", "-e", "frame.len"], capture_output=True, text=True, check=True)
    assert [int(x) for x in res.stdout.split()] == [p.wirelen for p in src.packets]


def test_session_export_respects_filter_and_window(session, tmp_path):
    flt = session.compile("proto:dns")
    session.apply_view(flt, session.build_view(flt))
    tl = session.timeline
    tl.set_cursor(tl.t0 + 100)
    expected = [p.no for p in session.capture.result.packets if p.app == "DNS" and p.ts <= tl.t0 + 100]
    assert session.window_frames() == expected
    count, expr, _ = session.export_packets(tmp_path / "x.pcapng")
    assert count == len(expected) and expr.startswith("(dns) && frame.time_epoch >=")
    assert len(read_capture(tmp_path / "x.pcapng").packets) == count


def test_cli_filter_and_pcap(sample_pcap, tmp_path, capsys, monkeypatch):
    from trace_zero.cli import main

    monkeypatch.setenv("TRACE_ZERO_HOME", str(tmp_path / "home"))
    out = tmp_path / "s.pcapng"
    assert main([str(sample_pcap), "--headless", "--db", str(tmp_path / "d.db"), "--filter", "flags:S !flags:A", "--pcap", str(out)]) == 0
    text = capsys.readouterr().out
    assert "wireshark      tcp.flags.syn==1 && !(tcp.flags.ack==1)" in text
    assert all(p.is_syn for p in read_capture(out).packets)
    assert main([str(sample_pcap), "--headless", "--db", str(tmp_path / "d.db"), "--filter", "port:99999"]) == 2
