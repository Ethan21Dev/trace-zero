"""Flow (connection) table.

A flow groups packets between two endpoints for one transport protocol. TCP
flows split when a new SYN reuses a closed 4-tuple; UDP and ICMP flows split
after an idle gap. The initiator is reported as *known* only when the capture
proves it (TCP SYN, ICMP echo request); otherwise it is the first sender seen.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field

from trace_zero.models import PacketRecord

IDLE_SPLIT_S = 120.0

STATE_HELP = {
    "closed": "FIN observed from both sides",
    "reset": "connection torn down with RST after it was established",
    "refused": "SYN answered with RST (port closed or connection rejected)",
    "open": "handshake completed, no close observed before the capture ends",
    "half-open": "SYN and SYN-ACK observed, but no client ACK",
    "no reply": "SYN observed with no answer in the capture",
    "mid-stream": "no handshake observed; the connection began before the capture",
    "two-way": "packets observed in both directions",
    "one-way": "packets observed in one direction only",
}


@dataclass(slots=True)
class Flow:
    id: int
    proto: str
    a: str
    a_port: int | None
    b: str
    b_port: int | None
    initiator_known: bool
    first: float
    last: float
    pkts_ab: int = 0
    pkts_ba: int = 0
    bytes_ab: int = 0
    bytes_ba: int = 0
    payload_ab: int = 0
    payload_ba: int = 0
    frames: list[int] = field(default_factory=list)
    syn: bool = False
    synack: bool = False
    ack_after_synack: bool = False
    fin_a: bool = False
    fin_b: bool = False
    rst_a: bool = False
    rst_b: bool = False
    apps: Counter = field(default_factory=Counter)
    icmp_errors: list[int] = field(default_factory=list)

    @property
    def ref(self) -> str:
        return f"{self.proto}|{self.a}|{self.a_port}|{self.b}|{self.b_port}|{self.frames[0]}"

    @property
    def closed(self) -> bool:
        return (self.fin_a and self.fin_b) or self.rst_a or self.rst_b

    @property
    def state(self) -> str:
        if self.proto == "TCP":
            if self.rst_a or self.rst_b:
                return "refused" if self.syn and not self.synack else "reset"
            if self.fin_a and self.fin_b:
                return "closed"
            if self.synack and self.ack_after_synack:
                return "open"
            if self.syn and self.synack:
                return "half-open"
            if self.syn:
                return "no reply"
            return "mid-stream"
        return "two-way" if self.pkts_ab and self.pkts_ba else "one-way"

    @property
    def app(self) -> str | None:
        return self.apps.most_common(1)[0][0] if self.apps else None

    @property
    def duration(self) -> float:
        return self.last - self.first

    @property
    def packets(self) -> int:
        return self.pkts_ab + self.pkts_ba

    @property
    def bytes(self) -> int:
        return self.bytes_ab + self.bytes_ba

    def endpoint(self, side: str) -> str:
        ip, port = (self.a, self.a_port) if side == "a" else (self.b, self.b_port)
        if port is None:
            return ip
        return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _proto(p: PacketRecord) -> str | None:
    if p.transport:
        return p.transport
    if p.ip_proto is not None:
        return f"IP/{p.ip_proto}"
    return None


def _key(proto: str, src: str, sport: int | None, dst: str, dport: int | None) -> tuple:
    # Canonical, direction-independent key; plain tuple order is enough (no address parsing).
    e1 = (src, -1 if sport is None else sport)
    e2 = (dst, -1 if dport is None else dport)
    return (proto, e1, e2) if e1 <= e2 else (proto, e2, e1)


def build_flows(packets: list[PacketRecord], rows: Sequence[int]) -> list[Flow]:
    """Build flows from packet indices given in capture-time order."""
    flows: list[Flow] = []
    active: dict[tuple, Flow] = {}
    pending_icmp: list[tuple[tuple, int]] = []
    for i in rows:
        p = packets[i]
        if p.src is None or p.dst is None or p.net == "ARP":
            continue
        proto = _proto(p)
        if proto is None:
            continue
        if p.icmp_orig is not None:
            oproto, osrc, osport, odst, odport = p.icmp_orig
            pending_icmp.append((_key(oproto, osrc, osport, odst, odport), p.no))
        key = _key(proto, p.src, p.sport, p.dst, p.dport)
        f = active.get(key)
        new = f is None
        if f is not None:
            if proto == "TCP" and p.is_syn and f.closed:
                new = True
            elif proto != "TCP" and p.ts - f.last > IDLE_SPLIT_S:
                new = True
            elif proto == "TCP" and p.ts - f.last > IDLE_SPLIT_S * 10 and p.is_syn:
                new = True
        if new:
            if proto == "TCP" and p.is_synack:
                a, ap, b, bp, known = p.dst, p.dport, p.src, p.sport, True
            elif proto == "TCP":
                a, ap, b, bp, known = p.src, p.sport, p.dst, p.dport, p.is_syn
            elif proto in ("ICMP", "ICMPv6"):
                known = p.icmp_type in (8, 128)
                a, ap, b, bp = p.src, p.sport, p.dst, p.dport
            else:
                a, ap, b, bp, known = p.src, p.sport, p.dst, p.dport, False
            f = Flow(len(flows), proto, a, ap, b, bp, known, p.ts, p.ts)
            flows.append(f)
            active[key] = f
        forward = p.src == f.a and p.sport == f.a_port
        if forward:
            f.pkts_ab += 1
            f.bytes_ab += p.wirelen
            f.payload_ab += p.payload_len or 0
        else:
            f.pkts_ba += 1
            f.bytes_ba += p.wirelen
            f.payload_ba += p.payload_len or 0
        f.last = max(f.last, p.ts)
        f.frames.append(p.no)
        if p.app:
            f.apps[p.app] += 1
        if proto == "TCP" and p.tcp_flags is not None:
            if p.is_syn and forward:
                f.syn = True
            elif p.is_synack and not forward:
                f.synack = True
            elif f.synack and forward and p.tcp_flags & 0x10:
                f.ack_after_synack = True
            if p.tcp_flags & 0x01:
                if forward:
                    f.fin_a = True
                else:
                    f.fin_b = True
            if p.tcp_flags & 0x04:
                if forward:
                    f.rst_a = True
                else:
                    f.rst_b = True
    # Link ICMP errors to the flow they quote (most recent flow with that key).
    for key, no in pending_icmp:
        f = active.get(key)
        if f is not None:
            f.icmp_errors.append(no)
    return flows


def flows_in_window(flows: list[Flow], lo: float, hi: float) -> list[Flow]:
    """Flows whose observed span (first to last packet) overlaps [lo, hi]."""
    return [f for f in flows if f.first <= hi and f.last >= lo]
