"""Windowed aggregation must equal brute force and be deterministic."""

from __future__ import annotations

import random

from trace_zero.analysis.filters import compile_filter
from trace_zero.analysis.index import CaptureIndex, CaptureView, _add_packet, classify_ip
from trace_zero.models import PacketRecord, ParseResult, FileInfo

INFO = FileInfo(path="x", name="x", size=0, sha256="0" * 64, mtime_ns=0, fmt="pcap")


def brute(index: CaptureIndex, lo: float, hi: float, flt=None):
    hosts: dict = {}
    edges: dict = {}
    for i in index.order:
        p = index.packets[i]
        if lo <= p.ts <= hi and (flt is None or flt(p)):
            _add_packet(hosts, edges, p)
    return hosts, edges


def test_window_matches_brute_force(loaded_sample):
    idx = loaded_sample.index
    rng = random.Random(3)
    view = idx.view(None)
    for _ in range(40):
        a, b = sorted(rng.uniform(idx.t0 - 1, idx.t1 + 1) for _ in range(2))
        stats = view.window(a, b)
        hosts, edges = brute(idx, a, b)
        assert stats.hosts == hosts
        assert stats.edges == edges
        assert stats.packets == sum(1 for p in idx.packets if a <= p.ts <= b)


def test_filtered_view_matches_brute_force(loaded_sample):
    idx = loaded_sample.index
    flt = compile_filter("proto:tcp !port:445")
    view = CaptureView(idx, flt)
    a, b = idx.t0 + 50, idx.t0 + 220
    stats = view.window(a, b)
    hosts, edges = brute(idx, a, b, flt)
    assert stats.hosts == hosts and stats.edges == edges


def test_determinism(loaded_sample):
    idx = loaded_sample.index
    v1 = CaptureView(idx, None)
    v2 = CaptureView(idx, None)
    w1 = v1.window(idx.t0 + 10, idx.t0 + 200)
    _ = v1.window(idx.t0, idx.t1)  # unrelated query in between
    w1b = v1.window(idx.t0 + 10, idx.t0 + 200)
    w2 = v2.window(idx.t0 + 10, idx.t0 + 200)
    assert w1.host_rows() == w1b.host_rows() == w2.host_rows()
    assert w1.pairs() == w2.pairs()


def test_histogram_counts_everything(loaded_sample):
    idx = loaded_sample.index
    view = idx.view(None)
    for bins in (1, 7, 100, 333):
        counts = view.histogram(idx.t0, idx.t1, bins)
        assert len(counts) == bins and sum(counts) == len(idx.packets)


def test_out_of_order_capture_is_sorted():
    pk = [
        PacketRecord(no=1, ts=5.0, wirelen=60, caplen=60, linktype=1, src="10.0.0.1", dst="10.0.0.2", net="IPv4"),
        PacketRecord(no=2, ts=1.0, wirelen=60, caplen=60, linktype=1, src="10.0.0.3", dst="10.0.0.2", net="IPv4"),
        PacketRecord(no=3, ts=3.0, wirelen=60, caplen=60, linktype=1, src="10.0.0.1", dst="10.0.0.2", net="IPv4"),
    ]
    idx = CaptureIndex(ParseResult(file=INFO, packets=pk))
    assert not idx.sorted_in_file
    assert (idx.t0, idx.t1) == (1.0, 5.0)
    view = idx.view(None)
    assert view.ts == [1.0, 3.0, 5.0]
    # First observations follow capture time, not file order: frame #2 (t=1.0) comes first.
    first = [e for e in idx.events if e.ts == 1.0]
    assert idx.events[0].ts == 1.0 and idx.events[0].frame == 2
    assert {e.ref for e in first if e.kind == "host"} == {"10.0.0.2", "10.0.0.3"}
    assert [e.kind for e in first] == ["host", "host", "conn"]
    assert set(view.window(0, 3.0).hosts) == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
    assert set(view.window(0, 2.0).hosts) == {"10.0.0.3", "10.0.0.2"}


def test_empty_capture_index():
    idx = CaptureIndex(ParseResult(file=INFO, packets=[]))
    view = idx.view(None)
    assert len(view) == 0 and view.window(0, 10).packets == 0
    assert view.histogram(0, 0, 10) == [0] * 10


def test_host_metadata_only_from_observations(loaded_sample):
    idx = loaded_sample.index
    web = idx.hosts["203.0.113.10"]
    assert "www.example.com" in web.dns_names or "static.example.org" in web.dns_names
    assert 443 in web.ports_accepting
    srv = idx.hosts["10.20.0.80"]
    assert srv.dns_names == {}  # never resolved in the capture -> no name
    assert set(srv.macs) == {"02:00:00:00:00:50"}


def test_classify_ip():
    assert classify_ip("10.1.2.3") == "private"
    assert classify_ip("192.0.2.1") == "documentation range"
    assert classify_ip("224.0.0.251") == "multicast"
    assert classify_ip("8.8.8.8") == "public"
    assert classify_ip("fe80::1") == "link-local"
