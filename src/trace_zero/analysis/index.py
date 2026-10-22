"""Time-ordered capture index and windowed aggregation.

``CaptureIndex`` is built once per import. ``CaptureView`` is the index seen
through a filter; it pre-aggregates fixed-size blocks of packets so that a
time-window query merges whole blocks and only scans the partial blocks at
either edge. Results are cached, so scrubbing back and forth is cheap and the
same (view, window) always produces the same state.
"""

from __future__ import annotations

import ipaddress
from bisect import bisect_left, bisect_right
from collections import Counter, OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, fields

from trace_zero.models import PacketRecord, ParseResult

BLOCK = 1024

# Host aggregate slots
H_PKTS_OUT, H_PKTS_IN, H_BYTES_OUT, H_BYTES_IN, H_FIRST, H_LAST = range(6)
# Edge aggregate slots
E_PKTS, E_BYTES, E_FIRST, E_LAST, E_PROTOS = range(5)


def _add_packet(hosts: dict, edges: dict, p: PacketRecord) -> None:
    src = p.src
    if src is None:
        return
    ts, size = p.ts, p.wirelen
    h = hosts.get(src)
    if h is None:
        hosts[src] = [1, 0, size, 0, ts, ts]
    else:
        h[0] += 1
        h[2] += size
        if ts < h[4]:
            h[4] = ts
        if ts > h[5]:
            h[5] = ts
    if p.net == "ARP":
        return  # ARP target addresses are questions, not communication peers
    dst = p.dst
    if dst is None:
        return
    h = hosts.get(dst)
    if h is None:
        hosts[dst] = [0, 1, 0, size, ts, ts]
    else:
        h[1] += 1
        h[3] += size
        if ts < h[4]:
            h[4] = ts
        if ts > h[5]:
            h[5] = ts
    key = (src, dst)
    e = edges.get(key)
    proto = p.proto
    if e is None:
        edges[key] = [1, size, ts, ts, {proto: 1}]
    else:
        e[0] += 1
        e[1] += size
        if ts < e[2]:
            e[2] = ts
        if ts > e[3]:
            e[3] = ts
        protos = e[4]
        protos[proto] = protos.get(proto, 0) + 1


def _merge(hosts: dict, edges: dict, bh: dict, be: dict) -> None:
    for ip, s in bh.items():
        h = hosts.get(ip)
        if h is None:
            hosts[ip] = s.copy()
        else:
            h[0] += s[0]
            h[1] += s[1]
            h[2] += s[2]
            h[3] += s[3]
            if s[4] < h[4]:
                h[4] = s[4]
            if s[5] > h[5]:
                h[5] = s[5]
    for key, s in be.items():
        e = edges.get(key)
        if e is None:
            edges[key] = [s[0], s[1], s[2], s[3], dict(s[4])]
        else:
            e[0] += s[0]
            e[1] += s[1]
            if s[2] < e[2]:
                e[2] = s[2]
            if s[3] > e[3]:
                e[3] = s[3]
            protos = e[4]
            for k, v in s[4].items():
                protos[k] = protos.get(k, 0) + v


@dataclass
class WindowStats:
    lo: float
    hi: float
    i0: int  # first position (inclusive) in the view
    i1: int  # last position (exclusive) in the view
    bytes: int
    hosts: dict[str, list]
    edges: dict[tuple[str, str], list]

    @property
    def packets(self) -> int:
        return self.i1 - self.i0

    def host_rows(self) -> list[tuple[str, list]]:
        """Hosts ordered by total bytes, then address (deterministic)."""
        return sorted(
            self.hosts.items(),
            key=lambda kv: (-(kv[1][H_BYTES_OUT] + kv[1][H_BYTES_IN]), ip_sort_key(kv[0])),
        )

    def peers(self, ip: str) -> list[dict]:
        """Conversation partners of ``ip`` with per-direction totals."""
        out: dict[str, dict] = {}
        for (a, b), e in self.edges.items():
            if a == ip:
                peer, direction = b, "out"
            elif b == ip:
                peer, direction = a, "in"
            else:
                continue
            row = out.setdefault(
                peer,
                {"peer": peer, "out_pkts": 0, "in_pkts": 0, "bytes": 0, "first": e[E_FIRST], "last": e[E_LAST], "protos": Counter()},
            )
            row[f"{direction}_pkts"] += e[E_PKTS]
            row["bytes"] += e[E_BYTES]
            row["first"] = min(row["first"], e[E_FIRST])
            row["last"] = max(row["last"], e[E_LAST])
            row["protos"].update(e[E_PROTOS])
        return sorted(out.values(), key=lambda r: (-r["bytes"], ip_sort_key(r["peer"])))

    def pairs(self) -> list[dict]:
        """Undirected conversations, largest first."""
        out: dict[tuple[str, str], dict] = {}
        for (a, b), e in self.edges.items():
            key = (a, b) if ip_sort_key(a) <= ip_sort_key(b) else (b, a)
            row = out.setdefault(
                key, {"a": key[0], "b": key[1], "ab": 0, "ba": 0, "bytes": 0, "first": e[E_FIRST], "last": e[E_LAST], "protos": Counter()}
            )
            row["ab" if (a, b) == key else "ba"] += e[E_PKTS]
            row["bytes"] += e[E_BYTES]
            row["first"] = min(row["first"], e[E_FIRST])
            row["last"] = max(row["last"], e[E_LAST])
            row["protos"].update(e[E_PROTOS])
        return sorted(out.values(), key=lambda r: (-r["bytes"], ip_sort_key(r["a"]), ip_sort_key(r["b"])))


def ip_sort_key(ip: str) -> tuple[int, int]:
    try:
        addr = ipaddress.ip_address(ip)
        return (addr.version, int(addr))
    except ValueError:
        return (9, 0)


def classify_ip(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if a.is_loopback:
        return "loopback"
    if a.is_multicast:
        return "multicast"
    if a.is_link_local:
        return "link-local"
    if a.version == 4 and str(a) == "255.255.255.255":
        return "broadcast"
    if a.is_unspecified:
        return "unspecified"
    # Documentation ranges are "private" to the ipaddress module; name them precisely.
    for net in _DOC_NETS:
        if a.version == net.version and a in net:
            return "documentation range"
    if a.is_private:
        return "private"
    return "public"


_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


@dataclass
class HostMeta:
    """Facts about one address, observed across the whole capture."""

    ip: str
    first: float
    last: float
    pkts_out: int = 0
    pkts_in: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    macs: dict[str, int] = field(default_factory=dict)  # MAC -> first frame where seen as source
    dns_names: dict[str, int] = field(default_factory=dict)  # name -> first answering frame
    ttls: Counter = field(default_factory=Counter)
    protocols: Counter = field(default_factory=Counter)
    dports_initiated: Counter = field(default_factory=Counter)  # (proto, port) this host opened
    ports_accepting: Counter = field(default_factory=Counter)  # TCP ports where SYN-ACK was sent
    dns_queries: int = 0
    dhcp_names: dict[str, int] = field(default_factory=dict)  # DHCP host-name -> frame
    tls_names: dict[str, int] = field(default_factory=dict)  # SNI / certificate names served here -> frame
    tls_client_fps: Counter = field(default_factory=Counter)  # JA4 fingerprints sent by this host
    tls_server_fps: Counter = field(default_factory=Counter)  # JA3S fingerprints sent by this host

    @property
    def scope(self) -> str:
        return classify_ip(self.ip)


_HOST_FIELDS = [f.name for f in fields(HostMeta)]
_HOST_COUNTERS = {"ttls", "protocols", "dports_initiated", "ports_accepting", "tls_client_fps", "tls_server_fps"}


@dataclass(frozen=True)
class TimelineEvent:
    ts: float
    kind: str  # host | conn | finding
    label: str
    ref: str
    frame: int | None = None


class CaptureIndex:
    def __init__(self, result: ParseResult, snapshot: dict | None = None) -> None:
        self.result = result
        self.packets: list[PacketRecord] = result.packets
        self._views: OrderedDict[str, CaptureView] = OrderedDict()
        if snapshot is not None:
            self._restore(snapshot)
            return
        pk = self.packets
        n = len(pk)
        if all(pk[i].ts <= pk[i + 1].ts for i in range(n - 1)):
            self.order: list[int] = list(range(n))
            self.sorted_in_file = True
        else:
            self.order = sorted(range(n), key=lambda i: pk[i].ts)
            self.sorted_in_file = False
        self.t0 = pk[self.order[0]].ts if n else 0.0
        self.t1 = pk[self.order[-1]].ts if n else 0.0
        self.by_no = {p.no: i for i, p in enumerate(pk)} if n and pk[-1].no != n else None
        self.hosts: dict[str, HostMeta] = {}
        self.host_positions: dict[str, list[int]] = {}
        self.events: list[TimelineEvent] = []
        self.proto_counts: Counter = Counter()
        self.total_bytes = 0
        self._pending_names: dict[str, dict[str, int]] = {}
        self._build()

    # -- cache support: plain-data snapshot of everything _build derives ----------------
    def snapshot(self) -> dict:
        full = self.view(None, key="")
        return {
            "order": self.order,
            "sorted_in_file": self.sorted_in_file,
            "t0": self.t0,
            "t1": self.t1,
            "hosts": [tuple(dict(v) if isinstance(v, Counter) else v for v in (getattr(m, f) for f in _HOST_FIELDS)) for m in self.hosts.values()],
            "host_positions": self.host_positions,
            "events": [(e.ts, e.kind, e.label, e.ref, e.frame) for e in self.events],
            "proto_counts": dict(self.proto_counts),
            "total_bytes": self.total_bytes,
            "blocks": full.blocks,
        }

    def _restore(self, snap: dict) -> None:
        n = len(self.packets)
        self.order = snap["order"]
        if len(self.order) != n:
            raise ValueError("index snapshot does not match the packet list")
        self.sorted_in_file = snap["sorted_in_file"]
        self.t0, self.t1 = snap["t0"], snap["t1"]
        self.by_no = {p.no: i for i, p in enumerate(self.packets)} if n and self.packets[-1].no != n else None
        self.hosts = {}
        for values in snap["hosts"]:
            kw = {f: (Counter(v) if f in _HOST_COUNTERS else v) for f, v in zip(_HOST_FIELDS, values)}
            self.hosts[kw["ip"]] = HostMeta(**kw)
        self.host_positions = snap["host_positions"]
        self.events = [TimelineEvent(*e) for e in snap["events"]]
        self.proto_counts = Counter(snap["proto_counts"])
        self.total_bytes = snap["total_bytes"]
        self._pending_names = {}
        self.cache_view("", CaptureView(self, None, blocks=snap["blocks"]))

    @property
    def span(self) -> float:
        return max(0.0, self.t1 - self.t0)

    def packet(self, no: int) -> PacketRecord | None:
        if self.by_no is not None:
            i = self.by_no.get(no)
            return None if i is None else self.packets[i]
        if 1 <= no <= len(self.packets):
            return self.packets[no - 1]
        return None

    def _build(self) -> None:
        hosts = self.hosts
        positions = self.host_positions
        seen_pairs: set[tuple[str, str]] = set()
        events = self.events
        pk = self.packets
        udp_flows: set[tuple] = set()
        dhcp_names: dict[str, tuple[str, int]] = {}  # client MAC -> (host-name, frame)
        dhcp_addrs: dict[str, str] = {}  # client MAC -> address confirmed by ACK or already in use
        for pos, idx in enumerate(self.order):
            p = pk[idx]
            self.proto_counts[p.proto] += 1
            self.total_bytes += p.wirelen
            src, dst = p.src, p.dst
            if src is None:
                continue
            for ip, outbound in ((src, True), (dst, False)):
                if ip is None or (not outbound and p.net == "ARP"):
                    continue
                m = hosts.get(ip)
                if m is None:
                    m = hosts[ip] = HostMeta(ip=ip, first=p.ts, last=p.ts)
                    positions[ip] = []
                    events.append(TimelineEvent(p.ts, "host", f"first observation of {ip}", ip, p.no))
                m.last = p.ts
                positions[ip].append(pos)
                m.protocols[p.proto] += 1
                if outbound:
                    m.pkts_out += 1
                    m.bytes_out += p.wirelen
                    if p.eth_src and p.eth_src not in m.macs and len(m.macs) < 32:
                        m.macs[p.eth_src] = p.no
                    if p.ttl is not None:
                        m.ttls[p.ttl] += 1
                else:
                    m.pkts_in += 1
                    m.bytes_in += p.wirelen
            if p.net == "ARP" or dst is None:
                continue
            pair = (src, dst) if src <= dst else (dst, src)
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                events.append(TimelineEvent(p.ts, "conn", f"first packet {src} -> {dst} ({p.proto})", f"{pair[0]}|{pair[1]}", p.no))
            m_src = hosts[src]
            if p.transport == "TCP" and p.tcp_flags is not None:
                if p.is_syn:
                    m_src.dports_initiated[("TCP", p.dport)] += 1
                elif p.is_synack:
                    m_src.ports_accepting[p.sport] += 1
            elif p.transport == "UDP" and p.sport is not None:
                flow = (src, p.sport, dst, p.dport)
                if (dst, p.dport, src, p.sport) not in udp_flows and flow not in udp_flows:
                    udp_flows.add(flow)
                    m_src.dports_initiated[("UDP", p.dport)] += 1
            if p.dhcp is not None:
                d = p.dhcp
                if d.client_mac:
                    if d.hostname:
                        dhcp_names.setdefault(d.client_mac, (d.hostname, p.no))
                    if d.msg_type == 5 and d.yiaddr and d.yiaddr != "0.0.0.0":
                        dhcp_addrs[d.client_mac] = d.yiaddr
                    elif d.ciaddr and d.ciaddr != "0.0.0.0":
                        dhcp_addrs.setdefault(d.client_mac, d.ciaddr)
            if p.tls is not None:
                t = p.tls
                if t.sni and dst in hosts and len(hosts[dst].tls_names) < 64:
                    hosts[dst].tls_names.setdefault(t.sni, p.no)
                for name in ((t.cert_subject_cn,) if t.cert_subject_cn else ()) + t.cert_san:
                    if len(m_src.tls_names) < 64:
                        m_src.tls_names.setdefault(name, p.no)
                if t.ja4:
                    m_src.tls_client_fps[t.ja4] += 1
                if t.ja3s:
                    m_src.tls_server_fps[t.ja3s] += 1
            if p.dns is not None:
                d = p.dns
                if not d.is_response:
                    m_src.dns_queries += 1
                else:
                    for ans in d.answers:
                        if ans.rtype in ("A", "AAAA"):
                            target = hosts.get(ans.value)
                            if target is not None and ans.name not in target.dns_names and len(target.dns_names) < 64:
                                target.dns_names[ans.name] = p.no
                            elif target is None:
                                self._pending_names.setdefault(ans.value, {}).setdefault(ans.name, p.no)
        # Names answered before the address itself was observed.
        for ip, names in self._pending_names.items():
            m = hosts.get(ip)
            if m is not None:
                for name, no in names.items():
                    m.dns_names.setdefault(name, no)
        self._pending_names.clear()
        for mac, (hostname, no) in dhcp_names.items():
            addr = dhcp_addrs.get(mac)
            if addr is not None and addr in hosts:
                hosts[addr].dhcp_names.setdefault(hostname, no)
        # At equal timestamps a host's first observation precedes the link it appears on.
        events.sort(key=lambda e: (e.ts, 0 if e.kind == "host" else 1, e.ref))

    def view(self, flt: Callable[[PacketRecord], bool] | None, key: str = "") -> CaptureView:
        cached = self._views.get(key)
        if cached is not None:
            self._views.move_to_end(key)
            return cached
        v = CaptureView(self, flt)
        self._views[key] = v
        while len(self._views) > 8:
            self._views.popitem(last=False)
        return v

    def cache_view(self, key: str, view: CaptureView) -> None:
        self._views[key] = view
        while len(self._views) > 8:
            self._views.popitem(last=False)

    def cached_view(self, key: str) -> CaptureView | None:
        return self._views.get(key)


class CaptureView:
    """The capture through a filter: time-sorted positions plus block aggregates."""

    def __init__(self, index: CaptureIndex, flt: Callable[[PacketRecord], bool] | None, blocks: list | None = None) -> None:
        self.index = index
        pk = index.packets
        if flt is None:
            self.rows: list[int] = list(index.order)
        else:
            self.rows = [i for i in index.order if flt(pk[i])]
        self.ts: list[float] = [pk[i].ts for i in self.rows]
        self.blocks: list[tuple[dict, dict, int]] = []
        if blocks is not None and flt is None and len(blocks) == -(-len(self.rows) // BLOCK):
            self.blocks = blocks  # restored from cache (unfiltered view only)
        for start in range(0, len(self.rows) if not self.blocks else 0, BLOCK):
            hosts: dict = {}
            edges: dict = {}
            size = 0
            for i in self.rows[start : start + BLOCK]:
                p = pk[i]
                size += p.wirelen
                _add_packet(hosts, edges, p)
            self.blocks.append((hosts, edges, size))
        self._cache: OrderedDict[tuple[int, int], WindowStats] = OrderedDict()
        self._hist_cache: dict[tuple, list[int]] = {}
        self.flows_cache: list | None = None  # filled lazily by Session.flows()

    def __len__(self) -> int:
        return len(self.rows)

    def bounds(self, lo: float, hi: float) -> tuple[int, int]:
        """Positions [i0, i1) of packets with lo <= ts <= hi."""
        return bisect_left(self.ts, lo), bisect_right(self.ts, hi)

    def packet_at(self, pos: int) -> PacketRecord:
        return self.index.packets[self.rows[pos]]

    def window(self, lo: float, hi: float) -> WindowStats:
        i0, i1 = self.bounds(lo, hi)
        key = (i0, i1)
        hit = self._cache.get(key)
        if hit is not None:
            self._cache.move_to_end(key)
            # Same packets, possibly different requested bounds.
            return WindowStats(lo, hi, i0, i1, hit.bytes, hit.hosts, hit.edges)
        hosts: dict = {}
        edges: dict = {}
        size = 0
        pk = self.index.packets
        rows = self.rows
        b0 = -(-i0 // BLOCK)  # first block fully inside
        b1 = i1 // BLOCK  # first block not fully inside
        if b0 >= b1:
            for pos in range(i0, i1):
                p = pk[rows[pos]]
                size += p.wirelen
                _add_packet(hosts, edges, p)
        else:
            for pos in range(i0, b0 * BLOCK):
                p = pk[rows[pos]]
                size += p.wirelen
                _add_packet(hosts, edges, p)
            for b in range(b0, b1):
                bh, be, bsize = self.blocks[b]
                _merge(hosts, edges, bh, be)
                size += bsize
            for pos in range(b1 * BLOCK, i1):
                p = pk[rows[pos]]
                size += p.wirelen
                _add_packet(hosts, edges, p)
        stats = WindowStats(lo, hi, i0, i1, size, hosts, edges)
        self._cache[key] = stats
        while len(self._cache) > 48:
            self._cache.popitem(last=False)
        return stats

    def histogram(self, t0: float, t1: float, bins: int) -> list[int]:
        """Packet counts in ``bins`` equal-width bins over [t0, t1]."""
        key = (t0, t1, bins)
        hit = self._hist_cache.get(key)
        if hit is not None:
            return hit
        if bins <= 0:
            return []
        width = (t1 - t0) / bins if t1 > t0 else 0.0
        counts = []
        prev = bisect_left(self.ts, t0)
        for b in range(bins):
            edge = t0 + width * (b + 1)
            nxt = bisect_right(self.ts, edge) if b < bins - 1 else bisect_right(self.ts, t1)
            counts.append(nxt - prev)
            prev = nxt
        if len(self._hist_cache) > 16:
            self._hist_cache.clear()
        self._hist_cache[key] = counts
        return counts

    def next_ts(self, t: float) -> float | None:
        i = bisect_right(self.ts, t)
        return self.ts[i] if i < len(self.ts) else None

    def prev_ts(self, t: float) -> float | None:
        i = bisect_left(self.ts, t)
        return self.ts[i - 1] if i > 0 else None

    def last_position_at(self, t: float) -> int | None:
        """Position of the last packet with ts <= t."""
        i = bisect_right(self.ts, t) - 1
        return i if i >= 0 else None

    def slice_rows(self, i0: int, i1: int) -> Sequence[int]:
        return self.rows[i0:i1]
