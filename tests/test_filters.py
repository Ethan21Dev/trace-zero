from __future__ import annotations

import pytest

from trace_zero.analysis.filters import FilterError, compile_filter, frames_filter
from trace_zero.models import DnsInfo, PacketRecord, TCP_ACK, TCP_SYN


def pkt(**kw) -> PacketRecord:
    base = dict(no=1, ts=100.0, wirelen=60, caplen=60, linktype=1)
    base.update(kw)
    return PacketRecord(**base)


SYN = pkt(no=1, src="10.0.0.1", dst="10.0.0.2", net="IPv4", transport="TCP", sport=40000, dport=443, tcp_flags=TCP_SYN, eth_src="02:00:00:00:00:01")
SYNACK = pkt(no=2, ts=100.5, src="10.0.0.2", dst="10.0.0.1", net="IPv4", transport="TCP", sport=443, dport=40000, tcp_flags=TCP_SYN | TCP_ACK, wirelen=1400)
DNSQ = pkt(
    no=3,
    ts=130.0,
    src="10.0.0.1",
    dst="192.0.2.53",
    net="IPv4",
    transport="UDP",
    app="DNS",
    sport=5000,
    dport=53,
    dns=DnsInfo(txid=1, is_response=False, opcode=0, rcode=0, truncated=False, qname="Mail.Example.com", qtype="A", qdcount=1, ancount=0),
)
V6 = pkt(no=4, src="2001:db8::1", dst="2001:db8::2", net="IPv6", transport="ICMPv6", icmp_type=128, icmp_code=0)
ARP = pkt(no=5, src="10.0.0.9", dst="10.0.0.1", net="ARP", arp_op=1, errors=("truncated ARP body",))
ALL = [SYN, SYNACK, DNSQ, V6, ARP]


def run(expr: str, t0: float = 100.0) -> list[int]:
    f = compile_filter(expr, t0)
    return [p.no for p in ALL if f(p)]


def test_empty_is_none():
    assert compile_filter("   ") is None


@pytest.mark.parametrize(
    "expr,expected",
    [
        ("host:10.0.0.1", [1, 2, 3, 5]),
        ("src:10.0.0.1", [1, 3]),
        ("dst:10.0.0.1", [2, 5]),
        ("host:10.0.0.0/30", [1, 2, 3, 5]),
        ("host:2001:db8::/32", [4]),
        ("port:443", [1, 2]),
        ("dport:400-500", [1]),
        ("proto:tcp", [1, 2]),
        ("proto:dns|icmpv6", [3, 4]),
        ("proto:udp,arp", [3, 5]),
        ("proto:ipv6", [4]),
        ("flags:S", [1, 2]),
        ("flags:SA", [2]),
        ("len>1000", [2]),
        ("len<=60", [1, 3, 4, 5]),
        ("t>=30", [3]),
        ("t<1", [1, 2, 4, 5]),
        ("dns:example", [3]),
        ("mac:02:00:00:00:00:01", [1]),
        ("no:2-4", [2, 3, 4]),
        ("error", [5]),
        ("!proto:tcp", [3, 4, 5]),
        ("proto:tcp !flags:A", [1]),
        ("mail", [3]),
        ("who-has", [5]),
    ],
)
def test_expressions(expr, expected):
    assert run(expr) == expected


@pytest.mark.parametrize(
    "bad",
    ["host:not-an-ip", "port:70000", "port:abc", "proto:quic", "flags:Z", "bogus:1", "len>x", 'unterminated "quote', "x" * 1001],
)
def test_invalid_expressions_raise(bad):
    with pytest.raises(FilterError):
        compile_filter(bad)


def test_frames_filter():
    f = frames_filter({2, 4}, "evidence")
    assert [p.no for p in ALL if f(p)] == [2, 4]
    assert f.display == "evidence"
