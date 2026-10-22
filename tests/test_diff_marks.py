"""Window comparison (A/B diff)."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from trace_zero.analysis.diff import diff_windows
from trace_zero.analysis.index import CaptureIndex
from trace_zero.parsing.reader import read_capture

from .conftest import ETH, write_pcap


def syn(t, src, dst, dport, size=0):
    pkt = ETH() / IP(src=src, dst=dst) / TCP(sport=40000 + int(t), dport=dport, flags="S")
    return (t, bytes(pkt / Raw(b"x" * size)) if size else bytes(pkt))


def test_diff_finds_new_and_gone_items(tmp_path):
    frames = [
        syn(1.0, "10.0.0.1", "10.0.0.2", 80),
        syn(2.0, "10.0.0.3", "10.0.0.2", 80),
        syn(3.0, "10.0.0.1", "10.0.0.2", 80, size=100),
        # window B
        syn(11.0, "10.0.0.1", "10.0.0.2", 80, size=1000),
        syn(12.0, "10.0.0.1", "10.0.0.9", 22),
        (13.0, bytes(ETH() / IP(src="10.0.0.1", dst="10.0.0.53") / UDP(sport=5000, dport=53) / Raw(b"q" * 20))),
    ]
    idx = CaptureIndex(read_capture(write_pcap(tmp_path / "d.pcap", frames)))
    d = diff_windows(idx.view(None), (0.0, 5.0), (10.0, 15.0))
    by = {}
    for r in d.rows:
        by.setdefault(r.change, []).append(r.item)
    assert by["NEW HOST"] == ["10.0.0.9", "10.0.0.53"]
    assert by["GONE HOST"] == ["10.0.0.3"]
    assert "10.0.0.1 → 10.0.0.9" in by["NEW LINK"] and "10.0.0.3 → 10.0.0.2" in by["GONE LINK"]
    assert set(by["NEW SERVICE"]) == {"10.0.0.9 TCP/22", "10.0.0.53 UDP/53"}
    assert "GONE SERVICE" not in by  # 10.0.0.2:80 opened in both windows
    assert "10.0.0.2" in by["MORE"]  # traffic rate to .2 rose
    assert (d.a_packets, d.b_packets) == (3, 3)


def test_identical_windows_have_no_changes(loaded_sample):
    idx = loaded_sample.index
    w = (idx.t0 + 10, idx.t0 + 60)
    assert diff_windows(idx.view(None), w, w).rows == []


def test_sample_late_window_shows_upload_destination(loaded_sample):
    idx = loaded_sample.index
    d = diff_windows(idx.view(None), (idx.t0, idx.t0 + 150), (idx.t0 + 150, idx.t1))
    new_hosts = [r.item for r in d.rows if r.change == "NEW HOST"]
    assert "203.0.113.99" in new_hosts and "198.51.100.66" in new_hosts
