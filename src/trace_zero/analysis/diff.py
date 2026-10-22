"""Compare two time windows of the same (filtered) capture view.

Answers "what changed between window A and window B": hosts and links that
appear or disappear, services (destination ports being opened) that are new
or gone, and hosts whose traffic rate changed most. Windows may differ in
length, so volume changes are compared as rates (bytes per second).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from trace_zero.analysis.index import E_BYTES, E_PKTS, E_PROTOS, H_BYTES_IN, H_BYTES_OUT, CaptureView, WindowStats, ip_sort_key

MAX_SCAN = 2_000_000


@dataclass
class DiffRow:
    change: str  # NEW HOST, GONE HOST, NEW LINK, GONE LINK, NEW SERVICE, GONE SERVICE, MORE, LESS
    item: str
    a: str
    b: str
    detail: str
    kind: str  # host | conversation | none
    ref: str


@dataclass
class WindowDiff:
    a: tuple[float, float]
    b: tuple[float, float]
    a_packets: int
    b_packets: int
    a_bytes: int
    b_bytes: int
    rows: list[DiffRow] = field(default_factory=list)
    services_truncated: bool = False

    def count(self, change: str) -> int:
        return sum(1 for r in self.rows if r.change == change)


def _services(view: CaptureView, stats: WindowStats) -> tuple[set[tuple[str, str, int]], bool]:
    """(server, proto, port) opened in the window: TCP SYNs and first packets of UDP flows."""
    pk = view.index.packets
    out: set[tuple[str, str, int]] = set()
    udp_seen: set[tuple] = set()
    end = min(stats.i1, stats.i0 + MAX_SCAN)
    for pos in range(stats.i0, end):
        p = pk[view.rows[pos]]
        if p.dst is None or p.dport is None:
            continue
        if p.transport == "TCP" and p.is_syn:
            out.add((p.dst, "TCP", p.dport))
        elif p.transport == "UDP":
            key = (p.src, p.sport, p.dst, p.dport)
            rev = (p.dst, p.dport, p.src, p.sport)
            if key not in udp_seen and rev not in udp_seen:
                udp_seen.add(key)
                out.add((p.dst, "UDP", p.dport))
    return out, end < stats.i1


def _rate(nbytes: int, span: float) -> float:
    return nbytes / max(span, 1e-3)


def _fmt_rate(r: float) -> str:
    for unit in ("B/s", "KB/s", "MB/s"):
        if r < 1024 or unit == "MB/s":
            return f"{r:.0f} {unit}" if unit == "B/s" else f"{r:.1f} {unit}"
        r /= 1024
    return f"{r:.1f} MB/s"


def diff_windows(view: CaptureView, a: tuple[float, float], b: tuple[float, float], top_volume: int = 15) -> WindowDiff:
    wa = view.window(*a)
    wb = view.window(*b)
    d = WindowDiff(a, b, wa.packets, wb.packets, wa.bytes, wb.bytes)
    rows = d.rows

    def host_bytes(w: WindowStats, ip: str) -> int:
        h = w.hosts.get(ip)
        return 0 if h is None else h[H_BYTES_OUT] + h[H_BYTES_IN]

    for ip in sorted(set(wb.hosts) - set(wa.hosts), key=ip_sort_key):
        rows.append(DiffRow("NEW HOST", ip, "-", f"{host_bytes(wb, ip):,} B", "only in B", "host", ip))
    for ip in sorted(set(wa.hosts) - set(wb.hosts), key=ip_sort_key):
        rows.append(DiffRow("GONE HOST", ip, f"{host_bytes(wa, ip):,} B", "-", "only in A", "host", ip))

    def pair_ref(x: str, y: str) -> str:
        lo, hi = sorted((x, y), key=ip_sort_key)
        return f"{lo}|{hi}"

    for key in sorted(set(wb.edges) - set(wa.edges), key=lambda k: (ip_sort_key(k[0]), ip_sort_key(k[1]))):
        e = wb.edges[key]
        protos = ",".join(sorted(e[E_PROTOS]))
        rows.append(DiffRow("NEW LINK", f"{key[0]} → {key[1]}", "-", f"{e[E_PKTS]:,} pkts", protos, "conversation", pair_ref(*key)))
    for key in sorted(set(wa.edges) - set(wb.edges), key=lambda k: (ip_sort_key(k[0]), ip_sort_key(k[1]))):
        e = wa.edges[key]
        protos = ",".join(sorted(e[E_PROTOS]))
        rows.append(DiffRow("GONE LINK", f"{key[0]} → {key[1]}", f"{e[E_PKTS]:,} pkts", "-", protos, "conversation", pair_ref(*key)))

    sa, ta = _services(view, wa)
    sb, tb = _services(view, wb)
    d.services_truncated = ta or tb
    for server, proto, port in sorted(sb - sa, key=lambda s: (ip_sort_key(s[0]), s[1], s[2])):
        rows.append(DiffRow("NEW SERVICE", f"{server} {proto}/{port}", "-", "opened", "first opened in B", "host", server))
    for server, proto, port in sorted(sa - sb, key=lambda s: (ip_sort_key(s[0]), s[1], s[2])):
        rows.append(DiffRow("GONE SERVICE", f"{server} {proto}/{port}", "opened", "-", "not opened in B", "host", server))

    span_a = a[1] - a[0]
    span_b = b[1] - b[0]
    changes = []
    for ip in set(wa.hosts) & set(wb.hosts):
        ra = _rate(host_bytes(wa, ip), span_a)
        rb = _rate(host_bytes(wb, ip), span_b)
        if max(ra, rb) <= 0:
            continue
        factor = (rb + 1) / (ra + 1)
        if factor >= 2 or factor <= 0.5:
            changes.append((abs(rb - ra), ip, ra, rb, factor))
    changes.sort(key=lambda c: (-c[0], ip_sort_key(c[1])))
    for _delta, ip, ra, rb, factor in changes[:top_volume]:
        label = "MORE" if factor > 1 else "LESS"
        rows.append(DiffRow(label, ip, _fmt_rate(ra), _fmt_rate(rb), f"{factor:.1f}x rate", "host", ip))
    return d
