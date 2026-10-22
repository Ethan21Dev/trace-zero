"""Translate TRACE//ZERO filter expressions into Wireshark display filters.

Most terms have an exact Wireshark equivalent. Where they do not (free-text
search, the decode-error flag), the closest expression is produced and the
translation is reported as approximate, so the analyst knows to check it.
"""

from __future__ import annotations

import ipaddress
import re
import shlex

from trace_zero.analysis.filters import _CMP_RE, PacketFilter

_PROTO = {
    "tcp": "tcp", "udp": "udp", "icmp": "icmp", "icmpv6": "icmpv6", "arp": "arp", "ipv4": "ip", "ipv6": "ipv6",
    # TRACE//ZERO labels only HTTP request/status lines and TLS handshakes, not continuation data.
    "dns": "dns", "mdns": "mdns", "llmnr": "llmnr", "http": "(http.request || http.response)", "tls": "tls.handshake", "dhcp": "dhcp",
}
_FLAGS = {"S": "syn", "A": "ack", "F": "fin", "R": "reset", "P": "push", "U": "urg", "E": "ece", "C": "cwr"}
_MAX_FRAMES = 2000


def _alts(value: str) -> list[str]:
    return [v for v in re.split(r"[|,]", value) if v]


def _quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


_ARP = {"addr": ("arp.src.proto_ipv4", "arp.dst.proto_ipv4"), "src": ("arp.src.proto_ipv4",), "dst": ("arp.dst.proto_ipv4",)}


def _addr(field: str, value: str) -> str:
    if ":" in value:
        return f"ipv6.{field}=={value}"
    ipaddress.ip_network(value, strict=False)  # validated by the filter compiler already
    # TRACE//ZERO also treats ARP sender/target addresses as packet addresses.
    return " || ".join([f"ip.{field}=={value}"] + [f"{f}=={value}" for f in _ARP[field]])


def _ports(fields: list[str], value: str) -> str:
    parts = []
    for v in _alts(value):
        if "-" in v:
            a, b = v.split("-", 1)
            parts += [f"{f} in {{{a}..{b}}}" for f in fields]
        else:
            parts += [f"{f}=={v}" for f in fields]
    return " || ".join(parts)


def _wrap(expr: str) -> str:
    return f"({expr})" if (" || " in expr or " && " in expr) else expr


def _term(token: str, t0: float, notes: list[str]) -> str:
    m = _CMP_RE.match(token)
    if m:
        key, op, raw = m.groups()
        op = "==" if op == "=" else op
        if key == "len":
            return f"frame.len {op} {raw}"
        return f"frame.time_epoch {op} {t0 + float(raw):.6f}"
    if ":" in token:
        key, _, value = token.partition(":")
        key = key.lower()
        if key in ("host", "ip", "src", "dst"):
            field = {"host": "addr", "ip": "addr", "src": "src", "dst": "dst"}[key]
            return " || ".join(_addr(field, v) for v in _alts(value))
        if key == "port":
            return _ports(["tcp.port", "udp.port"], value)
        if key == "sport":
            return _ports(["tcp.srcport", "udp.srcport"], value)
        if key == "dport":
            return _ports(["tcp.dstport", "udp.dstport"], value)
        if key == "proto":
            return " || ".join(_PROTO[v.lower()] for v in _alts(value))
        if key == "flags":
            return " && ".join(f"tcp.flags.{_FLAGS[c]}==1" for c in value.upper())
        if key == "dns":
            return f"lower(dns.qry.name) contains {_quote(value.lower())}"
        if key == "mac":
            return " || ".join(f"eth.addr=={v.lower()}" for v in _alts(value))
        if key == "no":
            notes.append("frame numbers refer to the original capture; they change in an exported file")
            return " || ".join(f"frame.number in {{{v.replace('-', '..')}}}" if "-" in v else f"frame.number=={v}" for v in _alts(value))
    if token.lower() == "error":
        notes.append("'error' approximated as Wireshark's malformed/expert-error flags")
        return "_ws.malformed || _ws.expert.severity==error"
    notes.append(f"free text {token!r} approximated as a raw-bytes search")
    return f"frame contains {_quote(token)}"


def to_wireshark(flt: PacketFilter | None, t0: float = 0.0) -> tuple[str, list[str]]:
    """Returns (display filter, notes). An empty filter means 'all packets'."""
    notes: list[str] = []
    if flt is None:
        return "", notes
    if flt.frame_set is not None:
        frames = sorted(flt.frame_set)
        notes.append("evidence selections are expressed as frame numbers of the original capture")
        if len(frames) > _MAX_FRAMES:
            notes.append(f"only the first {_MAX_FRAMES} frame numbers are listed")
            frames = frames[:_MAX_FRAMES]
        return "frame.number in {" + " ".join(map(str, frames)) + "}", notes
    parts = []
    for raw in shlex.split(flt.text):
        neg = False
        tok = raw
        while tok[:1] in ("!", "-") and len(tok) > 1 and not tok[1:2].isdigit():
            neg = not neg
            tok = tok[1:]
        expr = _term(tok, t0, notes)
        parts.append(f"!({expr})" if neg else _wrap(expr))
    return " && ".join(parts), notes
