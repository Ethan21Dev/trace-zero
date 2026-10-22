"""Flow table states and TCP/UDP stream reassembly."""

from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Raw

from trace_zero.analysis.flows import build_flows
from trace_zero.analysis.index import CaptureIndex
from trace_zero.analysis.streams import printable_lines, reassemble
from trace_zero.parsing.reader import read_capture, read_frames

from .conftest import ETH, write_pcap

C, S = "10.0.0.1", "10.0.0.2"


def tcp(src, dst, sport, dport, flags, seq=0, ack=0, payload=b""):
    pkt = ETH() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    return bytes(pkt / Raw(payload)) if payload else bytes(pkt)


def load(tmp_path, frames, name="f.pcap"):
    result = read_capture(write_pcap(tmp_path / name, frames))
    idx = CaptureIndex(result)
    return result, idx, build_flows(idx.packets, idx.order)


REQ = b"GET /a HTTP/1.1\r\nHost: legacy.example.com\r\nUser-Agent: test\r\n\r\n"
RESP = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nServer: unit\r\n\r\nhello world"


def http_session(t=1.0, sport=40000):
    """Handshake, request split in two segments delivered out of order, a retransmission, response, FIN/FIN."""
    c0, s0 = 1000, 5000
    return [
        (t, tcp(C, S, sport, 80, "S", seq=c0)),
        (t + 0.01, tcp(S, C, 80, sport, "SA", seq=s0, ack=c0 + 1)),
        (t + 0.02, tcp(C, S, sport, 80, "A", seq=c0 + 1, ack=s0 + 1)),
        (t + 0.04, tcp(C, S, sport, 80, "PA", seq=c0 + 1 + 20, ack=s0 + 1, payload=REQ[20:])),  # second half first
        (t + 0.03, tcp(C, S, sport, 80, "PA", seq=c0 + 1, ack=s0 + 1, payload=REQ[:20])),
        (t + 0.05, tcp(C, S, sport, 80, "PA", seq=c0 + 1, ack=s0 + 1, payload=REQ[:20])),  # retransmission
        (t + 0.06, tcp(S, C, 80, sport, "PA", seq=s0 + 1, ack=c0 + 1 + len(REQ), payload=RESP)),
        (t + 0.07, tcp(C, S, sport, 80, "FA", seq=c0 + 1 + len(REQ), ack=s0 + 1 + len(RESP))),
        (t + 0.08, tcp(S, C, 80, sport, "FA", seq=s0 + 1 + len(RESP), ack=c0 + 2 + len(REQ))),
    ]


def test_flow_states(tmp_path):
    frames = http_session()
    frames += [
        (2.0, tcp(C, S, 40001, 3389, "S", seq=1)),
        (2.001, tcp(S, C, 3389, 40001, "RA", ack=2)),
        (3.0, tcp(C, S, 40002, 22, "S", seq=1)),
        (4.0, tcp(C, S, 40003, 445, "PA", seq=77, payload=b"midstream")),
        (5.0, bytes(ETH() / IP(src=C, dst="10.0.0.53") / UDP(sport=5000, dport=53) / DNS(qd=DNSQR(qname="a.example")))),
        (5.1, bytes(ETH() / IP(src="10.0.0.53", dst=C) / UDP(sport=53, dport=5000) / DNS(qr=1, qd=DNSQR(qname="a.example")))),
    ]
    _r, _idx, flows = load(tmp_path, frames)
    by_port = {f.b_port: f for f in flows}
    http = by_port[80]
    assert (http.a, http.a_port, http.b, http.initiator_known) == (C, 40000, S, True)
    assert http.state == "closed" and http.app == "HTTP" and http.pkts_ab == 6 and http.pkts_ba == 3
    assert by_port[3389].state == "refused"
    assert by_port[22].state == "no reply"
    assert by_port[445].state == "mid-stream" and not by_port[445].initiator_known
    assert by_port[53].state == "two-way" and by_port[53].proto == "UDP"


def test_port_reuse_splits_flows(tmp_path):
    frames = http_session(1.0) + http_session(10.0)
    _r, _idx, flows = load(tmp_path, frames)
    assert len(flows) == 2 and all(f.state == "closed" for f in flows)
    assert flows[0].ref != flows[1].ref


def test_synack_first_still_finds_client(tmp_path):
    frames = [(1.0, tcp(S, C, 80, 40000, "SA", seq=5, ack=1)), (1.1, tcp(C, S, 40000, 80, "A", seq=1, ack=6))]
    _r, _idx, flows = load(tmp_path, frames)
    assert flows[0].a == C and flows[0].initiator_known


def test_icmp_error_linked_to_flow(tmp_path):
    q = IP(src=C, dst="10.0.0.53") / UDP(sport=5000, dport=53)
    frames = [
        (1.0, bytes(ETH() / q / Raw(b"x" * 20))),
        (1.1, bytes(ETH() / IP(src="10.0.0.53", dst=C) / ICMP(type=3, code=3) / bytes(q)[:28])),
    ]
    _r, _idx, flows = load(tmp_path, frames)
    udp = next(f for f in flows if f.proto == "UDP")
    assert udp.icmp_errors == [2]


def test_reassembly_orders_dedupes_and_decodes_http(tmp_path):
    result, idx, flows = load(tmp_path, http_session())
    flow = flows[0]
    frames = read_frames(result.file, set(flow.frames))
    stream = reassemble(flow, frames, {p.no: p.ts for p in idx.packets})
    assert stream.data("a") == REQ
    assert stream.data("b") == RESP
    assert stream.retransmitted == 1 and stream.conflicting == 0 and stream.gaps == 0
    titles = [t for t, _rows in stream.decoded]
    assert any("GET /a HTTP/1.1" in t for t in titles) and any("HTTP/1.1 200 OK" in t for t in titles)
    req_headers = dict(next(rows for t, rows in stream.decoded if "GET" in t))
    assert req_headers["Host"] == "legacy.example.com" and req_headers["User-Agent"] == "test"


def test_reassembly_reports_gaps_and_conflicting_retransmissions(tmp_path):
    frames = [
        (1.0, tcp(C, S, 40000, 80, "S", seq=100)),
        (1.1, tcp(C, S, 40000, 80, "PA", seq=101, payload=b"AAAA")),
        (1.2, tcp(C, S, 40000, 80, "PA", seq=101, payload=b"ABCD")),  # same seq, different bytes
        (1.3, tcp(C, S, 40000, 80, "PA", seq=111, payload=b"ZZZZ")),  # 6-byte hole before this
    ]
    result, idx, flows = load(tmp_path, frames)
    stream = reassemble(flows[0], read_frames(result.file, set(flows[0].frames)), {p.no: p.ts for p in idx.packets})
    assert stream.conflicting == 1 and stream.gaps == 1 and stream.gap_bytes == 6
    assert stream.data("a") == b"AAAAZZZZ"  # first copy kept, gap not filled with invented bytes
    assert any("DIFFERENT" in i for i in stream.issues()) and any("never captured" in i for i in stream.issues())
    assert any(c.note and "6 bytes missing" in c.note for c in stream.chunks)


def test_sequence_wraparound(tmp_path):
    base = (1 << 32) - 3
    frames = [
        (1.0, tcp(C, S, 40000, 80, "S", seq=base - 1)),
        (1.1, tcp(C, S, 40000, 80, "PA", seq=base, payload=b"abc")),
        (1.2, tcp(C, S, 40000, 80, "PA", seq=0, payload=b"def")),
    ]
    result, idx, flows = load(tmp_path, frames)
    stream = reassemble(flows[0], read_frames(result.file, set(flows[0].frames)), {})
    assert stream.data("a") == b"abcdef"


def test_dns_over_tcp_spanning_segments(tmp_path):
    msg = bytes(DNS(id=1, qd=DNSQR(qname="tcp.example")))
    wire = len(msg).to_bytes(2, "big") + msg
    frames = [
        (1.0, tcp(C, S, 40000, 53, "S", seq=10)),
        (1.1, tcp(C, S, 40000, 53, "PA", seq=11, payload=wire[:7])),
        (1.2, tcp(C, S, 40000, 53, "PA", seq=11 + 7, payload=wire[7:])),
    ]
    result, idx, flows = load(tmp_path, frames)
    stream = reassemble(flows[0], read_frames(result.file, set(flows[0].frames)), {})
    rows = dict(stream.decoded)[next(t for t, _ in stream.decoded if t.startswith("DNS over TCP"))]
    assert rows[0][1].startswith("query tcp.example")


def test_printable_lines_escape_controls():
    lines = printable_lines(b"line1\r\nbad\x1b[31mred\nok")
    assert lines == ["line1", "bad\\x1b[31mred", "ok"]


def test_sample_flows_cover_scenarios(loaded_sample):
    idx = loaded_sample.index
    flows = build_flows(idx.packets, idx.order)
    states = {f.state for f in flows}
    assert {"closed", "refused"} <= states
    assert sum(1 for f in flows if f.state == "refused" and f.b_port == 3389 and f.a == "10.20.0.13") == 12
