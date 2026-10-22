"""Packet filter expressions.

Whitespace-separated terms are ANDed. Prefix a term with ``!`` to negate it.
Alternatives inside one term are separated with ``|`` or ``,``.

    host:10.0.0.5         src or dst (CIDR allowed: host:10.0.0.0/24)
    src:/dst:             directional address match
    port:443  sport:  dport:   single port or range (port:1000-2000)
    proto:tcp|dns         protocol at any layer (tcp udp icmp icmpv6 arp ipv4 ipv6 dns mdns llmnr http tls)
    flags:S               TCP flags present (S A F R P U E C), e.g. flags:SA
    len>100 len<=60       wire length comparisons (> < >= <= =)
    t>12.5  t<=30         seconds relative to the first packet
    dns:example           substring of the DNS question name
    mac:02:00:00:00:00:01 Ethernet source or destination
    no:100-200            frame number or range
    error                 frames with decode errors / malformed fields
    text                  bare words match the summary, addresses and protocol
"""

from __future__ import annotations

import ipaddress
import operator
import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass, field

from trace_zero.models import PacketRecord, parse_tcp_flags

Predicate = Callable[[PacketRecord], bool]

PROTOCOLS = {"tcp", "udp", "icmp", "icmpv6", "arp", "ipv4", "ipv6", "dns", "mdns", "llmnr", "http", "tls", "dhcp"}
_CMP_RE = re.compile(r"^(len|t)(>=|<=|>|<|=)(.+)$")
_OPS = {">": operator.gt, "<": operator.lt, ">=": operator.ge, "<=": operator.le, "=": operator.eq}


class FilterError(ValueError):
    pass


@dataclass
class PacketFilter:
    text: str
    predicate: Predicate
    # Explicit frame-number restriction (used for finding evidence views).
    frame_set: frozenset[int] | None = None
    label: str | None = None
    terms: list[str] = field(default_factory=list)

    def __call__(self, pkt: PacketRecord) -> bool:
        if self.frame_set is not None and pkt.no not in self.frame_set:
            return False
        return self.predicate(pkt)

    @property
    def display(self) -> str:
        return self.label or self.text


def _alternatives(value: str) -> list[str]:
    parts = [p for p in re.split(r"[|,]", value) if p]
    if not parts:
        raise FilterError("empty value")
    return parts


def _addr_matcher(values: list[str]) -> Callable[[str | None], bool]:
    exact: set[str] = set()
    nets = []
    for v in values:
        if "/" in v:
            try:
                nets.append(ipaddress.ip_network(v, strict=False))
            except ValueError as exc:
                raise FilterError(f"invalid network {v!r}") from exc
        else:
            try:
                exact.add(str(ipaddress.ip_address(v)))
            except ValueError as exc:
                raise FilterError(f"invalid IP address {v!r}") from exc
    cache: dict[str, bool] = {}

    def match(addr: str | None) -> bool:
        if addr is None:
            return False
        if addr in exact:
            return True
        if not nets:
            return False
        hit = cache.get(addr)
        if hit is None:
            try:
                ip = ipaddress.ip_address(addr)
                hit = any(ip.version == n.version and ip in n for n in nets)
            except ValueError:
                hit = False
            cache[addr] = hit
        return hit

    return match


def _range_matcher(values: list[str], what: str, lo: int, hi: int) -> Callable[[int | None], bool]:
    ranges: list[tuple[int, int]] = []
    for v in values:
        try:
            if "-" in v:
                a, b = v.split("-", 1)
                r = (int(a), int(b))
            else:
                r = (int(v), int(v))
        except ValueError as exc:
            raise FilterError(f"invalid {what} {v!r}") from exc
        if not (lo <= r[0] <= r[1] <= hi):
            raise FilterError(f"{what} out of range: {v!r}")
        ranges.append(r)

    def match(x: int | None) -> bool:
        return x is not None and any(a <= x <= b for a, b in ranges)

    return match


def _proto_pred(values: list[str]) -> Predicate:
    wanted = set()
    for v in values:
        v = v.lower()
        if v not in PROTOCOLS:
            raise FilterError(f"unknown protocol {v!r} (known: {', '.join(sorted(PROTOCOLS))})")
        wanted.add(v)

    def pred(p: PacketRecord) -> bool:
        return any(
            x is not None and x.lower() in wanted for x in (p.app, p.transport, p.net)
        )

    return pred


def _term(token: str, t0: float) -> Predicate:
    m = _CMP_RE.match(token)
    if m:
        key, op_s, raw = m.groups()
        try:
            value = float(raw)
        except ValueError as exc:
            raise FilterError(f"invalid number in {token!r}") from exc
        op = _OPS[op_s]
        if key == "len":
            return lambda p: op(p.wirelen, value)
        return lambda p: op(p.ts - t0, value)
    if ":" in token and not token.lower().startswith(("http:", "https:")):
        key, _, value = token.partition(":")
        key = key.lower()
        if key in ("host", "ip", "src", "dst"):
            match = _addr_matcher(_alternatives(value))
            if key == "src":
                return lambda p: match(p.src)
            if key == "dst":
                return lambda p: match(p.dst)
            return lambda p: match(p.src) or match(p.dst)
        if key in ("port", "sport", "dport"):
            pm = _range_matcher(_alternatives(value), "port", 0, 65535)
            if key == "sport":
                return lambda p: pm(p.sport)
            if key == "dport":
                return lambda p: pm(p.dport)
            return lambda p: pm(p.sport) or pm(p.dport)
        if key == "proto":
            return _proto_pred(_alternatives(value))
        if key == "flags":
            try:
                mask = parse_tcp_flags(value)
            except ValueError as exc:
                raise FilterError(str(exc)) from exc
            if not mask:
                raise FilterError("flags: needs at least one flag letter")
            return lambda p: p.tcp_flags is not None and (p.tcp_flags & mask) == mask
        if key == "dns":
            needle = value.lower()
            if not needle:
                raise FilterError("dns: needs a name fragment")
            return lambda p: p.dns is not None and p.dns.qname is not None and needle in p.dns.qname.lower()
        if key == "mac":
            macs = {v.lower() for v in _alternatives(value)}
            return lambda p: p.eth_src in macs or p.eth_dst in macs
        if key == "no":
            nm = _range_matcher(_alternatives(value), "frame number", 1, 2**63)
            return lambda p: nm(p.no)
        raise FilterError(f"unknown filter field {key!r}")
    if token.lower() == "error":
        return lambda p: bool(p.errors) or (p.dns is not None and p.dns.malformed is not None)
    needle = token.lower()

    def text_pred(p: PacketRecord) -> bool:
        return (
            needle in p.info.lower()
            or needle in p.proto.lower()
            or (p.src is not None and needle in p.src)
            or (p.dst is not None and needle in p.dst)
        )

    return text_pred


def compile_filter(text: str, t0: float = 0.0) -> PacketFilter | None:
    """Compile an expression. Returns None for an empty expression."""
    text = text.strip()
    if not text:
        return None
    if len(text) > 1000:
        raise FilterError("filter expression is too long")
    try:
        tokens = shlex.split(text)
    except ValueError as exc:
        raise FilterError(f"cannot parse expression: {exc}") from exc
    preds: list[tuple[bool, Predicate]] = []
    for tok in tokens:
        neg = False
        while tok[:1] in ("!", "-") and len(tok) > 1 and not tok[1:2].isdigit():
            neg = not neg
            tok = tok[1:]
        preds.append((neg, _term(tok, t0)))

    def predicate(p: PacketRecord) -> bool:
        for neg, pred in preds:
            if pred(p) == neg:
                return False
        return True

    return PacketFilter(text=text, predicate=predicate, terms=tokens)


def frames_filter(frames: set[int] | frozenset[int], label: str) -> PacketFilter:
    """Filter restricted to explicit frame numbers (e.g. a finding's evidence)."""
    return PacketFilter(text=label, predicate=lambda p: True, frame_set=frozenset(frames), label=label)
