"""Deterministic synthetic capture generator.

Produces an offline capture file only - nothing is sent on any network.
Addresses come from RFC 1918 and the RFC 5737 / RFC 3849 documentation
ranges; DNS names use RFC 2606 reserved names. The scenario includes benign
baseline traffic plus a few patterns that the heuristics should surface:

* repeated refused connection attempts       (10.20.0.13 -> 10.20.0.80:3389)
* a destination-port sweep in synthetic data (10.20.0.14 -> 10.20.0.80)
* a traffic-volume burst                      (198.51.100.7 -> 10.20.0.12)
* a DNS query burst with NXDOMAIN answers     (10.20.0.11)
* a periodic check-in every ~5 s              (10.20.0.12 -> 192.0.2.44:8443)
* a second MAC answering ARP for the gateway  (02:00:00:00:00:66 claims 10.20.0.1)
* an unsolicited and a conflicting DNS answer (to 10.20.0.12 / 10.20.0.13)
* a long upload to a late new destination     (10.20.0.13 -> 203.0.113.99:443)
* TLS SNI that disagrees with DNS answers     (10.20.0.12 -> 198.51.100.66, SNI updates.example.com)

It also contains a DHCP exchange (host name ws-11-finance), TLS certificates
and an ICMP port-unreachable quoting the UDP probe that caused it.
"""

from __future__ import annotations

import random
from pathlib import Path

from trace_zero.parsing import scapy_bridge  # noqa: F401  (silences scapy logging)

from scapy.layers.dns import DNS, DNSQR, DNSRR  # noqa: E402
from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import ICMPv6ND_NS, IPv6  # noqa: E402
from scapy.layers.l2 import ARP, Ether  # noqa: E402
from scapy.packet import Packet, Raw  # noqa: E402
from scapy.utils import PcapNgWriter, PcapWriter  # noqa: E402

T0 = 1768467600.0  # 2026-01-15 09:00:00 UTC
DURATION = 300.0

GW = "10.20.0.1"
RESOLVER = "10.20.0.53"
FILESRV = "10.20.0.80"
WS = ["10.20.0.11", "10.20.0.12", "10.20.0.13", "10.20.0.14"]
WEB_TLS = "203.0.113.10"
WEB_HTTP = "198.51.100.7"
BEACON = "192.0.2.44"
V6_LOCAL = "2001:db8:20::11"
V6_REMOTE = "2001:db8:ff::10"


def _mac(ip: str) -> str:
    last = int(ip.split(".")[-1]) if "." in ip else 0x11
    return f"02:00:00:00:00:{last:02x}"


GW_MAC = _mac(GW)


def tls_client_hello(sni: str) -> bytes:
    name = sni.encode()
    sni_ext = (
        (0).to_bytes(2, "big")
        + (len(name) + 5).to_bytes(2, "big")
        + (len(name) + 3).to_bytes(2, "big")
        + b"\x00"
        + len(name).to_bytes(2, "big")
        + name
    )
    body = (
        b"\x03\x03"
        + bytes(32)
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + len(sni_ext).to_bytes(2, "big")
        + sni_ext
    )
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content


def _seq(*parts: bytes) -> bytes:
    return _der(0x30, b"".join(parts))


def _x509_name(cn: str) -> bytes:
    return _seq(_der(0x31, _seq(_der(0x06, bytes.fromhex("550403")), _der(0x0C, cn.encode()))))


def synthetic_certificate(subject: str, issuer: str, sans: list[str]) -> bytes:
    """A structurally valid X.509 DER blob (unsigned placeholder signature) for sample data."""
    san = _seq(*[_der(0x82, s.encode()) for s in sans])
    extensions = _der(0xA3, _seq(_seq(_der(0x06, bytes.fromhex("551d11")), _der(0x04, san))))
    alg = _seq(_der(0x06, bytes.fromhex("2a864886f70d01010b")), b"\x05\x00")
    validity = _seq(_der(0x17, b"260101000000Z"), _der(0x17, b"270101000000Z"))
    spki = _seq(alg, _der(0x03, b"\x00" + bytes(32)))
    tbs = _seq(_der(0xA0, _der(0x02, b"\x02")), _der(0x02, b"\x10\x01"), alg, _x509_name(issuer), validity, _x509_name(subject), spki, extensions)
    return _seq(tbs, alg, _der(0x03, b"\x00" + bytes(64)))


def tls_server_hello_certificate(name: str) -> bytes:
    """TLS 1.2 ServerHello + Certificate in one record."""
    exts = (0xFF01).to_bytes(2, "big") + b"\x00\x01\x00" + (0x0017).to_bytes(2, "big") + b"\x00\x00"
    sh_body = b"\x03\x03" + bytes(32) + b"\x00" + (0xC02F).to_bytes(2, "big") + b"\x00" + len(exts).to_bytes(2, "big") + exts
    server_hello = b"\x02" + len(sh_body).to_bytes(3, "big") + sh_body
    cert = synthetic_certificate(name, "Example Test CA", [name])
    chain = len(cert).to_bytes(3, "big") + cert
    cert_body = len(chain).to_bytes(3, "big") + chain
    cert_msg = b"\x0b" + len(cert_body).to_bytes(3, "big") + cert_body
    hs = server_hello + cert_msg
    return b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs


def dhcp_message(msg_type: int, xid: int, mac: str, yiaddr: str = "0.0.0.0", hostname: str | None = None, server: str | None = None) -> bytes:
    import socket

    hw = bytes.fromhex(mac.replace(":", ""))
    hdr = bytes([1 if msg_type in (1, 3) else 2, 1, 6, 0]) + xid.to_bytes(4, "big") + bytes(4)
    hdr += bytes(4) + socket.inet_aton(yiaddr) + bytes(8) + hw + bytes(10) + bytes(192)
    opts = bytes([53, 1, msg_type])
    if hostname:
        opts += bytes([12, len(hostname)]) + hostname.encode()
    if server:
        opts += bytes([54, 4]) + socket.inet_aton(server) + bytes([51, 4]) + (3600).to_bytes(4, "big")
    return hdr + b"\x63\x82\x53\x63" + opts + b"\xff"


class _Builder:
    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)
        self.pkts: list[tuple[float, int, Packet]] = []
        self._seq = 0
        self._sport = 40000

    def add(self, t: float, pkt: Packet) -> None:
        self._seq += 1
        self.pkts.append((T0 + t, self._seq, pkt))

    def eth(self, src: str, dst: str) -> Ether:
        smac = _mac(src) if src.startswith("10.20.") else GW_MAC
        dmac = _mac(dst) if dst.startswith("10.20.") else GW_MAC
        return Ether(src=smac, dst=dmac)

    def ephemeral(self) -> int:
        self._sport = 40000 + (self._sport - 40000 + 1) % 20000
        return self._sport

    def dns(self, t: float, client: str, name: str, answer: str | None, rcode: int = 0, qtype: str = "A") -> float:
        sport = self.ephemeral()
        txid = self.rng.randrange(65536)
        q = DNS(id=txid, rd=1, qd=DNSQR(qname=name, qtype=qtype))
        self.add(t, self.eth(client, RESOLVER) / IP(src=client, dst=RESOLVER, ttl=64) / UDP(sport=sport, dport=53) / q)
        an = [DNSRR(rrname=name, type=qtype, ttl=300, rdata=answer)] if answer else []
        r = DNS(id=txid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name, qtype=qtype), an=an)
        rt = t + 0.004 + self.rng.random() * 0.01
        self.add(rt, self.eth(RESOLVER, client) / IP(src=RESOLVER, dst=client, ttl=64) / UDP(sport=53, dport=sport) / r)
        return rt

    def tcp_session(
        self,
        t: float,
        client: str,
        server: str,
        dport: int,
        first_payload: bytes = b"",
        response: bytes = b"",
        data_pkts: int = 3,
        size: int = 600,
        gap: float = 0.03,
        server_ttl: int = 52,
    ) -> float:
        sport = self.ephemeral()
        cip = IP(src=client, dst=server, ttl=64)
        sip = IP(src=server, dst=client, ttl=server_ttl)
        c2s = self.eth(client, server)
        s2c = self.eth(server, client)
        cseq, sseq = self.rng.randrange(1 << 31), self.rng.randrange(1 << 31)
        self.add(t, c2s / cip / TCP(sport=sport, dport=dport, flags="S", seq=cseq, window=64240))
        t += gap
        self.add(t, s2c / sip / TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1, window=65160))
        t += gap / 2
        cseq += 1
        sseq += 1
        self.add(t, c2s / cip / TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq))
        if first_payload:
            t += 0.002
            self.add(t, c2s / cip / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq) / Raw(first_payload))
            cseq += len(first_payload)
        if response:
            t += gap
            self.add(t, s2c / sip / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq) / Raw(response))
            sseq += len(response)
        for _ in range(data_pkts):
            t += gap * self.rng.uniform(0.2, 1.0)
            body = bytes(self.rng.randrange(256) for _ in range(16)) * (size // 16)
            self.add(t, s2c / sip / TCP(sport=dport, dport=sport, flags="A", seq=sseq, ack=cseq) / Raw(body))
            sseq += len(body)
        t += gap
        self.add(t, c2s / cip / TCP(sport=sport, dport=dport, flags="FA", seq=cseq, ack=sseq))
        t += gap / 2
        self.add(t, s2c / sip / TCP(sport=dport, dport=sport, flags="FA", seq=sseq, ack=cseq + 1))
        t += 0.001
        self.add(t, c2s / cip / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1))
        return t

    def refused(self, t: float, client: str, server: str, dport: int) -> None:
        sport = self.ephemeral()
        seq = self.rng.randrange(1 << 31)
        self.add(t, self.eth(client, server) / IP(src=client, dst=server, ttl=64) / TCP(sport=sport, dport=dport, flags="S", seq=seq))
        self.add(
            t + 0.0008,
            self.eth(server, client) / IP(src=server, dst=client, ttl=64) / TCP(sport=dport, dport=sport, flags="RA", seq=0, ack=seq + 1),
        )


def build_packets(seed: int = 1337, scale: int = 1) -> list[tuple[float, Packet]]:
    """Build the scenario. ``scale`` repeats the baseline traffic for load testing."""
    b = _Builder(seed)
    rng = b.rng
    domains = ["www.example.com", "static.example.org", "mail.example.net", "updates.example.com"]
    for _ in range(scale):
        # Baseline: DNS + TLS sessions from each workstation.
        for _i in range(70):
            client = rng.choice(WS)
            t = rng.uniform(0, DURATION - 5)
            name = rng.choice(domains)
            t = b.dns(t, client, name, WEB_TLS)
            b.tcp_session(t + 0.01, client, WEB_TLS, 443, first_payload=tls_client_hello(name), response=tls_server_hello_certificate(name), data_pkts=rng.randrange(2, 7))
        # Plain HTTP.
        for _i in range(14):
            client = rng.choice(WS)
            t = rng.uniform(0, DURATION - 5)
            t = b.dns(t, client, "legacy.example.com", WEB_HTTP)
            req = b"GET /status/index.html HTTP/1.1\r\nHost: legacy.example.com\r\nUser-Agent: sample/1.0\r\n\r\n"
            resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 64\r\n\r\n" + b"x" * 64
            b.tcp_session(t + 0.01, client, WEB_HTTP, 80, first_payload=req, response=resp, data_pkts=1)
        # File server traffic.
        for _i in range(18):
            client = rng.choice(WS)
            t = rng.uniform(0, DURATION - 5)
            b.tcp_session(t, client, FILESRV, 445, first_payload=b"\x00\x00\x00\x40" + bytes(64), data_pkts=rng.randrange(3, 9), size=1200, gap=0.002, server_ttl=64)
        # ARP and ICMP housekeeping.
        for i in range(30):
            t = i * 10 + rng.random()
            asker = rng.choice(WS)
            b.add(t, Ether(src=_mac(asker), dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=_mac(asker), psrc=asker, pdst=GW))
            b.add(t + 0.0005, Ether(src=GW_MAC, dst=_mac(asker)) / ARP(op=2, hwsrc=GW_MAC, psrc=GW, hwdst=_mac(asker), pdst=asker))
        for i in range(20):
            t = i * 15 + 2.5
            b.add(t, b.eth(WS[0], GW) / IP(src=WS[0], dst=GW) / ICMP(type=8, id=7, seq=i) / Raw(b"tracezero-ping!!" * 2))
            b.add(t + 0.0009, b.eth(GW, WS[0]) / IP(src=GW, dst=WS[0]) / ICMP(type=0, id=7, seq=i) / Raw(b"tracezero-ping!!" * 2))
        # mDNS chatter and a little IPv6.
        for i in range(12):
            t = i * 25 + 1.0
            b.add(
                t,
                Ether(src=_mac(WS[2]), dst="01:00:5e:00:00:fb")
                / IP(src=WS[2], dst="224.0.0.251", ttl=255)
                / UDP(sport=5353, dport=5353)
                / DNS(qd=DNSQR(qname="_printer._tcp.local", qtype="PTR")),
            )
        for i in range(6):
            t = 30 + i * 40
            b.add(
                t,
                Ether(src="02:00:00:00:00:11", dst="33:33:ff:00:00:10")
                / IPv6(src=V6_LOCAL, dst="ff02::1:ff00:10", hlim=255)
                / ICMPv6ND_NS(tgt=V6_REMOTE),
            )
            v6 = IPv6(src=V6_LOCAL, dst=V6_REMOTE)
            v6r = IPv6(src=V6_REMOTE, dst=V6_LOCAL, hlim=58)
            sp = b.ephemeral()
            e1 = Ether(src="02:00:00:00:00:11", dst=GW_MAC)
            e2 = Ether(src=GW_MAC, dst="02:00:00:00:00:11")
            b.add(t + 0.1, e1 / v6 / TCP(sport=sp, dport=443, flags="S"))
            b.add(t + 0.13, e2 / v6r / TCP(sport=443, dport=sp, flags="SA"))
            b.add(t + 0.14, e1 / v6 / TCP(sport=sp, dport=443, flags="A"))

    # Scenario A: repeated refused connection attempts.
    for i in range(12):
        b.refused(60 + i * 2.4 + rng.random() * 0.2, WS[2], FILESRV, 3389)

    # Scenario B: destination-port sweep (synthetic packets only).
    open_ports = {22, 80, 445}
    for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 631, 636, 993, 995,
                              1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5900, 5985, 6379, 8000, 8080, 8443,
                              8888, 9000, 9090, 9200, 9418, 11211, 27017, 50000, 5601, 7001]):
        t = 120 + i * 0.2
        if port in open_ports:
            sport = b.ephemeral()
            b.add(t, b.eth(WS[3], FILESRV) / IP(src=WS[3], dst=FILESRV) / TCP(sport=sport, dport=port, flags="S"))
            b.add(t + 0.0007, b.eth(FILESRV, WS[3]) / IP(src=FILESRV, dst=WS[3]) / TCP(sport=port, dport=sport, flags="SA"))
            b.add(t + 0.0011, b.eth(WS[3], FILESRV) / IP(src=WS[3], dst=FILESRV) / TCP(sport=sport, dport=port, flags="R"))
        else:
            b.refused(t, WS[3], FILESRV, port)

    # Scenario C: traffic-volume burst.
    sport = b.ephemeral()
    b.add(199.9, b.eth(WS[1], WEB_HTTP) / IP(src=WS[1], dst=WEB_HTTP) / TCP(sport=sport, dport=80, flags="S"))
    b.add(199.93, b.eth(WEB_HTTP, WS[1]) / IP(src=WEB_HTTP, dst=WS[1], ttl=52) / TCP(sport=80, dport=sport, flags="SA"))
    blob = bytes(range(256)) * 5 + bytes(120)
    for i in range(420):
        b.add(200 + i * 0.0045, b.eth(WEB_HTTP, WS[1]) / IP(src=WEB_HTTP, dst=WS[1], ttl=52) / TCP(sport=80, dport=sport, flags="A", seq=1 + i * len(blob)) / Raw(blob))
    b.add(202.0, b.eth(WS[1], WEB_HTTP) / IP(src=WS[1], dst=WEB_HTTP) / TCP(sport=sport, dport=80, flags="FA"))

    # Scenario D: DNS query burst with NXDOMAIN answers.
    for i in range(80):
        label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(12))
        b.dns(240 + i * 0.11, WS[0], f"{label}.telemetry.example", None, rcode=3, qtype="TXT")

    # Scenario E: periodic check-in every ~5 seconds.
    t = 3.0
    while t < DURATION - 2:
        b.tcp_session(t, WS[1], BEACON, 8443, first_payload=b"\x17\x03\x03\x00\x30" + bytes(48), data_pkts=1, size=96, gap=0.04)
        t += 5.0 + rng.uniform(-0.15, 0.15)

    # DHCP: 10.20.0.11 obtains its address and announces a host name.
    ws_mac = _mac(WS[0])
    for i, (mtype, src, dst, yi) in enumerate([(1, "0.0.0.0", "255.255.255.255", "0.0.0.0"), (2, GW, "255.255.255.255", WS[0]),
                                                (3, "0.0.0.0", "255.255.255.255", "0.0.0.0"), (5, GW, "255.255.255.255", WS[0])]):
        sport, dport = (68, 67) if mtype in (1, 3) else (67, 68)
        payload = dhcp_message(mtype, 0x5EED, ws_mac, yi, hostname="ws-11-finance" if mtype in (1, 3) else None, server=GW if mtype in (2, 5) else None)
        eth = Ether(src=ws_mac if mtype in (1, 3) else GW_MAC, dst="ff:ff:ff:ff:ff:ff")
        b.add(0.2 + i * 0.01, eth / IP(src=src, dst=dst, ttl=64) / UDP(sport=sport, dport=dport) / Raw(payload))

    # ICMP port unreachable quoting a UDP probe.
    probe = IP(src=WS[3], dst=FILESRV) / UDP(sport=b.ephemeral(), dport=161) / Raw(b"\x30\x26")
    b.add(125.0, b.eth(WS[3], FILESRV) / probe)
    b.add(125.001, b.eth(FILESRV, WS[3]) / IP(src=FILESRV, dst=WS[3]) / ICMP(type=3, code=3) / Raw(bytes(probe)[:28]))

    # Scenario F (TZ-R6): a second MAC starts answering ARP for the gateway address.
    rogue = "02:00:00:00:00:66"
    for k, t in enumerate((271.0, 272.0, 273.5)):
        victim = WS[k % len(WS)]
        b.add(t, Ether(src=rogue, dst=_mac(victim)) / ARP(op=2, hwsrc=rogue, psrc=GW, hwdst=_mac(victim), pdst=victim))

    # Scenario G (TZ-R7): an unsolicited DNS answer and a conflicting duplicate answer.
    spoof = DNS(id=0xBEEF, qr=1, rd=1, ra=1, qd=DNSQR(qname="updates.example.com"), an=[DNSRR(rrname="updates.example.com", ttl=60, rdata="198.51.100.200")])
    b.add(150.0, b.eth(RESOLVER, WS[1]) / IP(src=RESOLVER, dst=WS[1]) / UDP(sport=53, dport=33333) / spoof)
    sport = b.ephemeral()
    q = DNS(id=0x1234, rd=1, qd=DNSQR(qname="mail.example.net"))
    b.add(160.0, b.eth(WS[2], RESOLVER) / IP(src=WS[2], dst=RESOLVER) / UDP(sport=sport, dport=53) / q)
    for k, ans in enumerate(("203.0.113.25", "198.51.100.201")):
        r = DNS(id=0x1234, qr=1, rd=1, ra=1, qd=DNSQR(qname="mail.example.net"), an=[DNSRR(rrname="mail.example.net", ttl=300, rdata=ans)])
        b.add(160.004 + k * 0.002, b.eth(RESOLVER, WS[2]) / IP(src=RESOLVER, dst=WS[2]) / UDP(sport=53, dport=sport) / r)

    # Scenario H (TZ-R8, TZ-R9): a long upload to a destination first seen late in the capture.
    up_t = b.dns(209.0, WS[2], "files.example.net", "203.0.113.99")
    up_sport = b.ephemeral()
    cip, sip = IP(src=WS[2], dst="203.0.113.99", ttl=64), IP(src="203.0.113.99", dst=WS[2], ttl=52)
    c2s, s2c = b.eth(WS[2], "203.0.113.99"), b.eth("203.0.113.99", WS[2])
    b.add(up_t + 0.01, c2s / cip / TCP(sport=up_sport, dport=443, flags="S", seq=1000))
    b.add(up_t + 0.04, s2c / sip / TCP(sport=443, dport=up_sport, flags="SA", seq=9000, ack=1001))
    b.add(up_t + 0.05, c2s / cip / TCP(sport=up_sport, dport=443, flags="A", seq=1001, ack=9001))
    hello = tls_client_hello("files.example.net")
    b.add(up_t + 0.06, c2s / cip / TCP(sport=up_sport, dport=443, flags="PA", seq=1001, ack=9001) / Raw(hello))
    seq = 1001 + len(hello)
    chunk = bytes(range(256)) * 3 + bytes(232)
    for k in range(560):
        t = up_t + 0.1 + k * 0.125
        b.add(t, c2s / cip / TCP(sport=up_sport, dport=443, flags="A", seq=seq, ack=9001) / Raw(chunk))
        seq += len(chunk)
        if k % 10 == 9:
            b.add(t + 0.02, s2c / sip / TCP(sport=443, dport=up_sport, flags="A", seq=9001, ack=seq))
    b.add(up_t + 70.5, c2s / cip / TCP(sport=up_sport, dport=443, flags="FA", seq=seq, ack=9001))

    # Scenario I (TZ-R10): TLS naming a host whose DNS answers point elsewhere.
    b.dns(229.0, WS[1], "updates.example.com", WEB_TLS)
    b.tcp_session(230.0, WS[1], "198.51.100.66", 443, first_payload=tls_client_hello("updates.example.com"), data_pkts=1, size=96)

    b.pkts.sort(key=lambda item: (item[0], item[1]))
    return [(ts, pkt) for ts, _seq, pkt in b.pkts]


def generate_sample(path: str | Path, fmt: str = "pcap", seed: int = 1337, scale: int = 1) -> int:
    """Write the synthetic capture. Returns the packet count."""
    path = Path(path)
    if fmt not in ("pcap", "pcapng"):
        raise ValueError("fmt must be 'pcap' or 'pcapng'")
    pkts = build_packets(seed=seed, scale=scale)
    path.parent.mkdir(parents=True, exist_ok=True)
    writer_cls = PcapNgWriter if fmt == "pcapng" else PcapWriter
    writer = writer_cls(str(path), linktype=1) if fmt == "pcap" else writer_cls(str(path))
    try:
        for ts, pkt in pkts:
            pkt.time = ts
            writer.write(pkt)
    finally:
        writer.close()
    return len(pkts)
