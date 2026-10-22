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
            b.tcp_session(t + 0.01, client, WEB_TLS, 443, first_payload=tls_client_hello(name), data_pkts=rng.randrange(2, 7))
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
