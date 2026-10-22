"""Frame decoder: correct fields for valid input, no exceptions and no invented fields for bad input."""

from __future__ import annotations

import random
import struct

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.packet import Raw

from trace_zero.models import TCP_ACK, TCP_SYN

from .conftest import ETH
from trace_zero.parsing.decoder import decode_frame
from trace_zero.samples import tls_client_hello


def dec(pkt_or_bytes, linktype: int = 1):
    data = bytes(pkt_or_bytes)
    return decode_frame(1, 1000.0, data, len(data), linktype)


def test_ethernet_ipv4_tcp_fields():
    p = dec(Ether(src="02:00:00:00:00:0a", dst="02:00:00:00:00:0b") / IP(src="10.0.0.1", dst="10.0.0.2", ttl=61, id=0x1234) / TCP(sport=1234, dport=80, flags="S", seq=42, window=1000))
    assert (p.eth_src, p.eth_dst) == ("02:00:00:00:00:0a", "02:00:00:00:00:0b")
    assert (p.net, p.src, p.dst, p.ttl, p.ip_id) == ("IPv4", "10.0.0.1", "10.0.0.2", 61, 0x1234)
    assert (p.transport, p.sport, p.dport, p.tcp_seq, p.tcp_win) == ("TCP", 1234, 80, 42, 1000)
    assert p.tcp_flags == TCP_SYN and p.is_syn and not p.is_synack
    assert p.payload_len == 0
    assert p.errors == ()
    assert p.app is None  # nothing decoded above TCP -> no protocol is claimed


def test_port_alone_never_labels_application():
    p = dec(ETH() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5555, dport=443, flags="PA") / Raw(b"not tls at all"))
    assert p.app is None and p.proto == "TCP"


def test_synack_and_vlan():
    p = dec(ETH() / Dot1Q(vlan=42) / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(flags="SA"))
    assert p.vlan == 42
    assert p.is_synack and p.tcp_flags == TCP_SYN | TCP_ACK


def test_udp_dns_query_and_response():
    q = dec(ETH() / IP(src="10.0.0.5", dst="10.0.0.53") / UDP(sport=5000, dport=53) / DNS(id=9, rd=1, qd=DNSQR(qname="www.example.com", qtype="AAAA")))
    assert q.app == "DNS" and q.dns is not None
    assert (q.dns.is_response, q.dns.qname, q.dns.qtype, q.dns.txid) == (False, "www.example.com", "AAAA", 9)
    assert q.dns.malformed is None
    r = dec(
        ETH()
        / IP(src="10.0.0.53", dst="10.0.0.5")
        / UDP(sport=53, dport=5000)
        / DNS(id=9, qr=1, rcode=0, qd=DNSQR(qname="www.example.com"), an=DNSRR(rrname="www.example.com", rdata="192.0.2.1", ttl=60))
    )
    assert r.dns.is_response and r.dns.ancount == 1
    assert r.dns.answers[0].value == "192.0.2.1" and r.dns.answers[0].rtype == "A" and r.dns.answers[0].ttl == 60
    assert "192.0.2.1" in r.info


def test_nxdomain_rcode():
    r = dec(ETH() / IP() / UDP(sport=53, dport=4000) / DNS(qr=1, rcode=3, qd=DNSQR(qname="nope.example")))
    assert r.dns.rcode == 3 and r.dns.rcode_name == "NXDOMAIN"


def test_garbage_on_dns_port_is_flagged_not_trusted():
    p = dec(ETH() / IP() / UDP(sport=1111, dport=53) / Raw(b"\x00\x01\x02garbage-not-dns\xff\xff\xff\xff\xff\xff"))
    assert p.dns is None or p.dns.malformed is not None


def test_short_dns_payload():
    p = dec(ETH() / IP() / UDP(sport=1111, dport=53) / Raw(b"\x00\x01"))
    assert p.dns is None
    assert any("too short" in e for e in p.errors)


def test_mdns_label():
    p = dec(ETH() / IP(dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(qd=DNSQR(qname="_x._tcp.local", qtype="PTR")))
    assert p.app == "MDNS"


def test_ipv6_with_fragment_header_and_icmpv6():
    p = dec(ETH() / IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=7) / TCP(sport=1, dport=2, flags="S"))
    assert (p.net, p.src, p.dst, p.ttl, p.transport) == ("IPv6", "2001:db8::1", "2001:db8::2", 7, "TCP")
    frag = dec(ETH() / IPv6() / IPv6ExtHdrFragment(offset=0, m=1) / UDP(sport=10, dport=20) / Raw(b"x" * 8))
    assert frag.fragment and frag.transport == "UDP"


def test_non_first_ipv4_fragment_has_no_transport():
    p = dec(ETH() / IP(src="10.0.0.1", dst="10.0.0.2", frag=100, proto=6) / Raw(b"\x00" * 40))
    assert p.fragment and p.transport is None and p.sport is None


def test_icmp_and_arp():
    p = dec(ETH() / IP() / ICMP(type=8, code=0))
    assert p.transport == "ICMP" and p.icmp_type == 8 and "echo-request" in p.info
    a = dec(Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc="10.0.0.1", pdst="10.0.0.9", hwsrc="02:00:00:00:00:01"))
    assert (a.net, a.src, a.dst, a.arp_op) == ("ARP", "10.0.0.1", "10.0.0.9", 1)
    assert "who-has" in a.info


def test_http_request_and_tls_sni():
    h = dec(ETH() / IP() / TCP(sport=4000, dport=8080, flags="PA") / Raw(b"GET /a HTTP/1.1\r\nHost: legacy.example.com\r\n\r\n"))
    assert h.app == "HTTP" and h.app_info == "GET legacy.example.com/a"
    t = dec(ETH() / IP() / TCP(sport=4000, dport=443, flags="PA") / Raw(tls_client_hello("svc.example.org")))
    assert t.app == "TLS" and t.app_info == "ClientHello SNI=svc.example.org"


def test_truncated_tls_hello_does_not_invent_sni():
    hello = tls_client_hello("svc.example.org")[:30]
    t = dec(ETH() / IP() / TCP(sport=4000, dport=443, flags="PA") / Raw(hello))
    assert t.app == "TLS" and "SNI=" not in (t.app_info or "")


def test_raw_ip_linktype_and_loopback():
    raw = bytes(IP(src="10.1.1.1", dst="10.1.1.2") / UDP(sport=1, dport=2))
    assert dec(raw, linktype=101).src == "10.1.1.1"
    assert dec(raw, linktype=228).dst == "10.1.1.2"
    null = struct.pack("<I", 2) + raw
    assert dec(null, linktype=0).src == "10.1.1.1"


def test_linux_sll():
    raw = bytes(IP(src="10.2.2.2", dst="10.2.2.3") / TCP(flags="S"))
    hdr = struct.pack("!HHH8sH", 0, 1, 6, b"\x02\x00\x00\x00\x00\x07\x00\x00", 0x0800)
    p = dec(hdr + raw, linktype=113)
    assert p.src == "10.2.2.2" and p.eth_src == "02:00:00:00:00:07" and p.is_syn


def test_unknown_linktype_records_only_timing_and_length():
    p = dec(b"\x01\x02\x03\x04", linktype=147)
    assert p.src is None and p.net is None and p.wirelen == 4
    assert "not decoded" in p.info


@pytest.mark.parametrize(
    "data,needle",
    [
        (b"\x00" * 10, "Ethernet"),
        (bytes(ETH() / IP())[:20], "IPv4"),
        (bytes(ETH() / IP() / TCP())[:40], "TCP"),
        (bytes(ETH() / IP() / UDP())[:38], "UDP"),
        (bytes(ETH(type=0x86DD) / IPv6())[:30], "IPv6"),
    ],
)
def test_truncated_headers_are_reported(data, needle):
    p = dec(data)
    assert any(needle in e for e in p.errors), p.errors


def test_bad_ipv4_header_length():
    raw = bytearray(bytes(ETH() / IP() / TCP()))
    raw[14] = 0x42  # version 4, IHL 2 (8 bytes) - invalid
    p = dec(bytes(raw))
    assert any("header length" in e for e in p.errors)
    assert p.transport is None


def test_fuzz_random_frames_never_raise():
    rng = random.Random(7)
    base = [
        bytes(ETH() / IP() / TCP(flags="S") / Raw(b"x" * 20)),
        bytes(ETH() / IP() / UDP(dport=53) / DNS(qd=DNSQR(qname="a.example"))),
        bytes(ETH() / IPv6() / UDP(dport=53) / DNS(qd=DNSQR(qname="a.example"))),
        bytes(ETH() / IP() / TCP(dport=443) / Raw(tls_client_hello("x.example"))),
    ]
    for _ in range(3000):
        frame = bytearray(rng.choice(base))
        for _ in range(rng.randrange(1, 8)):
            frame[rng.randrange(len(frame))] = rng.randrange(256)
        frame = bytes(frame[: rng.randrange(len(frame) + 1)])
        for lt in (1, 101, 113, 276, 0):
            rec = decode_frame(1, 0.0, frame, len(frame), lt)
            assert rec.caplen == len(frame)
            _ = rec.info  # summary must also be safe
