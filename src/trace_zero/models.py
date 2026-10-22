"""Core data models.

Every field on ``PacketRecord`` is either decoded from the capture or ``None``.
Nothing is guessed: a missing value means the capture did not contain it, the
layer was not decoded, or the data was malformed (see ``errors``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trace_zero.parsing.tls import TlsInfo

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80

_FLAG_LETTERS = (
    (TCP_SYN, "S"),
    (TCP_ACK, "A"),
    (TCP_FIN, "F"),
    (TCP_RST, "R"),
    (TCP_PSH, "P"),
    (TCP_URG, "U"),
    (TCP_ECE, "E"),
    (TCP_CWR, "C"),
)

LINKTYPE_NAMES = {
    0: "NULL",
    1: "ETHERNET",
    12: "RAW",
    14: "RAW",
    101: "RAW",
    108: "LOOP",
    113: "LINUX_SLL",
    228: "IPV4",
    229: "IPV6",
    276: "LINUX_SLL2",
}

ICMP_TYPES = {
    0: "echo-reply",
    3: "dest-unreachable",
    5: "redirect",
    8: "echo-request",
    11: "time-exceeded",
    12: "parameter-problem",
    13: "timestamp",
    14: "timestamp-reply",
}

ICMPV6_TYPES = {
    1: "dest-unreachable",
    2: "packet-too-big",
    3: "time-exceeded",
    4: "parameter-problem",
    128: "echo-request",
    129: "echo-reply",
    133: "router-solicit",
    134: "router-advert",
    135: "neighbor-solicit",
    136: "neighbor-advert",
}

DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def tcp_flag_str(flags: int | None) -> str:
    if flags is None:
        return ""
    return "".join(letter for bit, letter in _FLAG_LETTERS if flags & bit)


def parse_tcp_flags(text: str) -> int:
    """Convert letters like 'SA' into a bitmask. Raises ValueError on unknown letters."""
    mask = 0
    lookup = {letter: bit for bit, letter in _FLAG_LETTERS}
    for ch in text.upper():
        if ch not in lookup:
            raise ValueError(f"unknown TCP flag letter {ch!r} (use S A F R P U E C)")
        mask |= lookup[ch]
    return mask


@dataclass(slots=True)
class DnsAnswer:
    name: str
    rtype: str
    value: str
    ttl: int | None


@dataclass(slots=True)
class DnsInfo:
    txid: int
    is_response: bool
    opcode: int
    rcode: int
    truncated: bool
    qname: str | None
    qtype: str | None
    qdcount: int
    ancount: int
    answers: tuple[DnsAnswer, ...] = ()
    malformed: str | None = None

    @property
    def rcode_name(self) -> str:
        return DNS_RCODES.get(self.rcode, str(self.rcode))


DHCP_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}


@dataclass(slots=True)
class DhcpInfo:
    op: int
    xid: int
    msg_type: int | None
    client_mac: str | None
    ciaddr: str | None
    yiaddr: str | None
    hostname: str | None = None
    requested_ip: str | None = None
    server_id: str | None = None
    vendor_class: str | None = None
    lease_s: int | None = None

    @property
    def type_name(self) -> str:
        return DHCP_TYPES.get(self.msg_type or 0, f"type {self.msg_type}") if self.msg_type else "BOOTP"

    @property
    def summary(self) -> str:
        parts = [f"DHCP {self.type_name} xid=0x{self.xid:08x}"]
        if self.client_mac:
            parts.append(f"client {self.client_mac}")
        if self.hostname:
            parts.append(f"host-name {self.hostname}")
        if self.requested_ip:
            parts.append(f"requested {self.requested_ip}")
        if self.yiaddr and self.yiaddr != "0.0.0.0":
            parts.append(f"assigned {self.yiaddr}")
        return " ".join(parts)


@dataclass(slots=True)
class PacketRecord:
    """One captured frame, decoded as far as the data safely allows."""

    no: int  # 1-based frame number in file order
    ts: float  # capture timestamp, seconds since the epoch
    wirelen: int  # original length on the wire
    caplen: int  # bytes actually stored in the capture
    linktype: int
    eth_src: str | None = None
    eth_dst: str | None = None
    vlan: int | None = None
    ethertype: int | None = None
    net: str | None = None  # IPv4 / IPv6 / ARP
    src: str | None = None
    dst: str | None = None
    ttl: int | None = None  # IPv4 TTL or IPv6 hop limit
    ip_id: int | None = None
    fragment: bool = False
    ip_proto: int | None = None
    transport: str | None = None  # TCP / UDP / ICMP / ICMPv6
    sport: int | None = None
    dport: int | None = None
    tcp_flags: int | None = None
    tcp_seq: int | None = None
    tcp_ack: int | None = None
    tcp_win: int | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    arp_op: int | None = None
    arp_hw: str | None = None  # ARP sender hardware address (the MAC claiming 'src')
    payload_len: int | None = None
    app: str | None = None  # DNS / MDNS / LLMNR / HTTP / TLS (only when decoded)
    app_info: str | None = None  # decoded, sanitised application detail
    dns: DnsInfo | None = None
    tls: TlsInfo | None = None
    dhcp: DhcpInfo | None = None
    # ICMP error messages quote the packet that caused them: (proto, src, sport, dst, dport).
    icmp_orig: tuple[str, str, int | None, str, int | None] | None = None
    errors: tuple[str, ...] = ()

    @property
    def proto(self) -> str:
        if self.app:
            return self.app
        if self.transport:
            return self.transport
        if self.net:
            return self.net
        if self.ethertype is not None:
            return f"0x{self.ethertype:04x}"
        return "L2"

    @property
    def flags_str(self) -> str:
        return tcp_flag_str(self.tcp_flags)

    @property
    def is_syn(self) -> bool:
        return self.tcp_flags is not None and bool(self.tcp_flags & TCP_SYN) and not self.tcp_flags & TCP_ACK

    @property
    def is_synack(self) -> bool:
        f = self.tcp_flags
        return f is not None and bool(f & TCP_SYN) and bool(f & TCP_ACK)

    @property
    def is_rst(self) -> bool:
        return self.tcp_flags is not None and bool(self.tcp_flags & TCP_RST)

    @property
    def info(self) -> str:
        """Short human summary assembled only from decoded fields."""
        parts: list[str] = []
        if self.dns is not None:
            d = self.dns
            if d.is_response:
                parts.append(f"response {d.qtype or '?'} {d.qname or '?'}")
                if d.rcode:
                    parts.append(d.rcode_name)
                values = [a.value for a in d.answers[:3]]
                if values:
                    parts.append("-> " + ", ".join(values) + (" ..." if len(d.answers) > 3 else ""))
            else:
                parts.append(f"query {d.qtype or '?'} {d.qname or '?'}")
            if d.malformed:
                parts.append(f"[malformed: {d.malformed}]")
        elif self.app_info:
            parts.append(self.app_info)
        elif self.transport == "TCP":
            parts.append(f"[{self.flags_str}]")
            if self.payload_len:
                parts.append(f"len={self.payload_len}")
        elif self.transport in ("ICMP", "ICMPv6"):
            names = ICMP_TYPES if self.transport == "ICMP" else ICMPV6_TYPES
            name = names.get(self.icmp_type or -1, f"type={self.icmp_type}")
            parts.append(f"{name} code={self.icmp_code}")
            if self.icmp_orig:
                proto, osrc, osport, odst, odport = self.icmp_orig
                a = f"{osrc}:{osport}" if osport is not None else osrc
                b = f"{odst}:{odport}" if odport is not None else odst
                parts.append(f"for {proto} {a} -> {b}")
        elif self.transport == "UDP":
            parts.append(f"len={self.payload_len}")
        elif self.net == "ARP":
            if self.arp_op == 1:
                parts.append(f"who-has {self.dst} tell {self.src}")
            elif self.arp_op == 2:
                parts.append(f"{self.src} is-at {self.eth_src}")
            else:
                parts.append(f"op={self.arp_op}")
        elif self.net is None and self.ethertype is not None:
            parts.append(f"ethertype 0x{self.ethertype:04x} (not decoded)")
        elif self.net is None:
            parts.append(f"linktype {LINKTYPE_NAMES.get(self.linktype, self.linktype)} (not decoded)")
        if self.fragment:
            parts.append("[fragment]")
        if self.errors:
            parts.append("[" + "; ".join(self.errors) + "]")
        return " ".join(parts)


def fmt_ts(ts: float | None, with_date: bool = False) -> str:
    """UTC timestamp. Captures carry UTC epoch values; local time is not assumed."""
    if ts is None:
        return "-"
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    if with_date:
        return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond:06d}Z"
    return dt.strftime("%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def fmt_rel(seconds: float) -> str:
    sign = "-" if seconds < 0 else "+"
    s = abs(seconds)
    if s < 1:
        return f"{sign}{s * 1000:.1f}ms"
    if s < 120:
        return f"{sign}{s:.3f}s"
    if s < 7200:
        return f"{sign}{int(s // 60)}m{s % 60:04.1f}s"
    return f"{sign}{int(s // 3600)}h{int(s % 3600 // 60):02d}m"


def fmt_duration(seconds: float) -> str:
    return fmt_rel(seconds)[1:]


def fmt_bytes(n: int | float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024 or unit == "GB":
            return f"{int(n)} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


@dataclass(frozen=True, slots=True)
class FileInfo:
    path: str
    name: str
    size: int
    sha256: str
    mtime_ns: int
    fmt: str  # "pcap" | "pcapng"


@dataclass(slots=True)
class ParseResult:
    file: FileInfo
    packets: list[PacketRecord]
    linktypes: set[int] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)
    truncated: bool = False  # parsing stopped early (limit, damage, cancellation)
    stop_reason: str | None = None
    elapsed_s: float = 0.0
    cached: bool = False  # restored from the on-disk cache instead of parsed
    # Multi-capture timelines: (file, frame offset, frame count) per source. Empty = single file.
    sources: list[tuple[FileInfo, int, int]] = field(default_factory=list)

    def source_list(self) -> list[tuple[FileInfo, int, int]]:
        return self.sources or [(self.file, 0, len(self.packets))]

    def locate(self, no: int) -> tuple[FileInfo, int]:
        """Map a timeline frame number to (source file, frame number inside that file)."""
        for info, offset, count in self.source_list():
            if offset < no <= offset + count:
                return info, no - offset
        raise KeyError(no)
