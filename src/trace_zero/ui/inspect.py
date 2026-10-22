"""Inspector content: details for hosts, packets, conversations and findings.

Sections are labelled by provenance:
  DECODED         fields parsed from the frame
  OBSERVED        facts aggregated from captured packets
  HEURISTIC       output of an anomaly rule (possible anomaly, not a verdict)
  ANALYST NOTES   text written by people (interpretation)
  RAW BYTES       undecoded frame bytes, shown only on request
"""

from __future__ import annotations

from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.style import Style
from rich.table import Table
from rich.text import Text

from trace_zero.analysis.anomaly import RULES, Finding
from trace_zero.analysis.index import E_BYTES, E_FIRST, E_LAST, E_PKTS, E_PROTOS, H_BYTES_IN, H_BYTES_OUT, H_PKTS_IN, H_PKTS_OUT, WindowStats, classify_ip
from trace_zero.models import ICMP_TYPES, ICMPV6_TYPES, LINKTYPE_NAMES, PacketRecord, fmt_bytes, fmt_duration, fmt_rel, fmt_ts
from trace_zero.sanitize import clean, hexdump
from trace_zero.session import Session
from trace_zero.ui import theme

KEY_W = 12


class Doc:
    """Builds inspector content: section headings, key/value grids and free lines."""

    def __init__(self) -> None:
        self.items: list[RenderableType] = []
        self._grid: Table | None = None

    def _end_grid(self) -> None:
        self._grid = None

    def section(self, title: str, tag: str = "", tag_style=theme.S_FAINT) -> None:
        self._end_grid()
        head = Text(no_wrap=True, overflow="ellipsis")
        if self.items:
            self.items.append(Text(""))
        head.append(title, theme.S_CYAN)
        if tag:
            head.append(f"  {tag}", tag_style)
        self.items.append(head)

    def kv(self, key: str, value: object, style=theme.S_TEXT) -> None:
        if value is None or value == "":
            return
        if self._grid is None:
            self._grid = Table.grid(padding=(0, 1))
            self._grid.add_column(width=KEY_W + 2, no_wrap=True)
            self._grid.add_column(ratio=1, overflow="fold")
            self.items.append(self._grid)
        val = value if isinstance(value, Text) else Text(clean(value, 400), style=style)
        self._grid.add_row(Text(f"  {key}", style=theme.S_LABEL, overflow="ellipsis"), val)

    def line(self, value: str | Text, style=theme.S_TEXT) -> None:
        self._end_grid()
        body = value.copy() if isinstance(value, Text) else Text(clean(value, 2000), style=style)
        self.items.append(Padding(body, (0, 0, 0, 2)))

    def dim(self, value: str) -> None:
        self.line(value, theme.S_DIM)

    def render(self) -> Group:
        return Group(*self.items)


def _notes(doc: Doc, session: Session, kind: str, ref: str) -> None:
    from trace_zero.session import Selection

    sel = Selection(kind, ref)
    notes = session.notes_for(sel)
    marked = session.is_bookmarked(sel)
    doc.section("ANALYST NOTES", "interpretation", theme.S_AMBER)
    if marked:
        doc.line(Text("■ bookmarked", style=theme.S_AMBER))
    if not notes:
        doc.dim("none  (a: add note   m: bookmark)")
    for n in notes:
        doc.line(Text(fmt_ts(n.created_at, True)[:19] + "Z", style=theme.S_FAINT))
        for para in n.body.splitlines() or [""]:
            doc.line(para, theme.S_AMBER)


def overview(session: Session) -> Group:
    doc = Doc()
    if session.capture is None:
        doc.section("NO CAPTURE LOADED")
        doc.dim("o        open a PCAP / PCAPNG file")
        doc.dim("?        keyboard reference")
        doc.dim("")
        doc.dim("Captures are opened read-only. Nothing is uploaded;")
        doc.dim("analysis runs entirely on this machine.")
        return doc.render()
    r = session.capture.result
    idx = session.capture.index
    doc.section("CAPTURE", "observed")
    doc.kv("file", r.file.name)
    doc.kv("format", r.file.fmt)
    doc.kv("size", f"{fmt_bytes(r.file.size)} ({r.file.size:,} B)")
    doc.kv("sha256", r.file.sha256)
    doc.kv("packets", f"{len(r.packets):,}")
    doc.kv("on wire", fmt_bytes(idx.total_bytes))
    if r.packets:
        doc.kv("first", fmt_ts(idx.t0, True))
        doc.kv("last", fmt_ts(idx.t1, True))
        doc.kv("duration", fmt_duration(idx.span))
    doc.kv("link types", ", ".join(LINKTYPE_NAMES.get(lt, str(lt)) for lt in sorted(r.linktypes)) or "-")
    doc.kv("hosts", f"{len(idx.hosts):,}")
    if not idx.sorted_in_file:
        doc.kv("ordering", Text("frames are not time-ordered in file; timeline uses capture timestamps", style=theme.S_AMBER))
    errors = sum(1 for p in r.packets if p.errors)
    if errors:
        doc.kv("malformed", Text(f"{errors:,} frames (filter: error)", style=theme.S_AMBER))
    if r.truncated:
        doc.kv("import", Text(f"TRUNCATED - {r.stop_reason}", style=theme.S_RED))
    for w in r.warnings[:8]:
        doc.line(Text("! " + clean(w, 300), style=theme.S_AMBER))
    doc.section("PROTOCOLS", "observed")
    for proto, n in idx.proto_counts.most_common(12):
        doc.kv(proto, f"{n:,}")
    f = session.capture.findings
    doc.section("POSSIBLE ANOMALIES", "heuristic")
    if not f:
        doc.dim("no heuristic fired")
    for sev in ("HIGH", "MEDIUM", "LOW"):
        n = sum(1 for x in f if x.severity == sev)
        if n:
            doc.kv(sev, str(n), theme.SEVERITY_STYLE[sev])
    if f:
        doc.dim("f: findings view")
    return doc.render()


def host(session: Session, ip: str, stats: WindowStats | None) -> Group:
    doc = Doc()
    idx = session.capture.index
    meta = idx.hosts.get(ip)
    doc.section(f"HOST {ip}")
    doc.kv("scope", classify_ip(ip))
    cursor = session.timeline.cursor if session.timeline else None
    w = stats.hosts.get(ip) if stats else None
    doc.section("IN WINDOW", "observed" + (", filtered" if session.filter else ""))
    if w is None:
        doc.dim("not observed in the current window")
    else:
        doc.kv("sent", f"{w[H_PKTS_OUT]:,} pkts  {fmt_bytes(w[H_BYTES_OUT])}")
        doc.kv("received", f"{w[H_PKTS_IN]:,} pkts  {fmt_bytes(w[H_BYTES_IN])}")
        doc.kv("first", fmt_ts(w[4], True))
        doc.kv("last", fmt_ts(w[5], True))
        if cursor is not None:
            doc.kv("last packet", f"{fmt_duration(cursor - w[5])} before cursor (historical observation)")
        peers = stats.peers(ip)
        doc.kv("peers", str(len(peers)))
        for row in peers[:8]:
            arrow = "⇄" if row["out_pkts"] and row["in_pkts"] else ("→" if row["out_pkts"] else "←")
            protos = ",".join(p for p, _ in row["protos"].most_common(3))
            doc.line(Text.assemble((f"{arrow} ", theme.S_CYAN), (f"{row['peer']:<16}", theme.S_TEXT), (f" {fmt_bytes(row['bytes']):>9}  {protos}", theme.S_DIM)))
    if meta is not None:
        doc.section("ENTIRE CAPTURE", "observed")
        doc.kv("sent", f"{meta.pkts_out:,} pkts  {fmt_bytes(meta.bytes_out)}")
        doc.kv("received", f"{meta.pkts_in:,} pkts  {fmt_bytes(meta.bytes_in)}")
        doc.kv("first seen", fmt_ts(meta.first, True))
        doc.kv("last seen", fmt_ts(meta.last, True))
        doc.kv("protocols", ", ".join(f"{p} {n}" for p, n in meta.protocols.most_common(6)))
        if meta.macs:
            doc.kv("MAC (as src)", ", ".join(f"{m} (#{no})" for m, no in list(meta.macs.items())[:4]))
        if meta.ttls:
            doc.kv("TTL sent", ", ".join(f"{t}×{n}" for t, n in meta.ttls.most_common(4)))
        if meta.dns_names:
            doc.kv("DNS answers", ", ".join(f"{n} (#{no})" for n, no in list(meta.dns_names.items())[:5]))
        if meta.ports_accepting:
            doc.kv("accepts TCP", ", ".join(str(p) for p in sorted(meta.ports_accepting)[:16]) + "  (SYN-ACK sent)")
        if meta.dports_initiated:
            top = sorted(meta.dports_initiated.items(), key=lambda kv: -kv[1])[:10]
            doc.kv("initiated to", ", ".join(f"{proto}/{port}" for (proto, port), _ in top))
        if meta.dns_queries:
            doc.kv("DNS queries", f"{meta.dns_queries:,}")
        doc.dim("Only metadata present in the capture is shown; hostnames come")
        doc.dim("solely from DNS answers observed in this capture.")
    related = [f for f in session.capture.findings if ip in f.hosts]
    if related:
        doc.section("POSSIBLE ANOMALIES", "heuristic")
        for f in related[:6]:
            doc.line(Text.assemble((f"{f.severity:<7}", theme.SEVERITY_STYLE[f.severity]), (f.title, theme.S_TEXT)))
    _notes(doc, session, "host", ip)
    return doc.render()


def conversation(session: Session, ref: str, stats: WindowStats | None) -> Group:
    a, _, b = ref.partition("|")
    doc = Doc()
    doc.section(f"CONVERSATION {a} ⇄ {b}")
    doc.section("IN WINDOW", "observed")
    cursor = session.timeline.cursor if session.timeline else None
    for s, d in ((a, b), (b, a)):
        e = stats.edges.get((s, d)) if stats else None
        if e is None:
            doc.kv(f"{s} →", "no packets observed in window")
            continue
        protos = ", ".join(f"{p} {n}" for p, n in sorted(e[E_PROTOS].items(), key=lambda kv: -kv[1])[:4])
        doc.kv(f"{s} →", f"{e[E_PKTS]:,} pkts  {fmt_bytes(e[E_BYTES])}  [{protos}]")
        doc.kv("  first/last", f"{fmt_ts(e[E_FIRST])} / {fmt_ts(e[E_LAST])}")
        if cursor is not None:
            doc.kv("  last seen", f"{fmt_duration(cursor - e[E_LAST])} before cursor")
    # Handshake evidence across the whole capture.
    idx = session.capture.index
    pk = idx.packets
    positions = idx.host_positions.get(a, [])
    syn_ab = syn_ba = synack = 0
    first_syn = None
    services = set()
    for pos in positions:
        p = pk[idx.order[pos]]
        if {p.src, p.dst} != {a, b}:
            continue
        if p.transport == "TCP" and p.tcp_flags is not None:
            if p.is_syn:
                if p.src == a:
                    syn_ab += 1
                else:
                    syn_ba += 1
                first_syn = first_syn or p
                services.add(f"{p.dst}:{p.dport}/tcp")
            elif p.is_synack:
                synack += 1
    doc.section("CONNECTION DIRECTION", "observed, entire capture")
    if syn_ab or syn_ba:
        doc.kv("SYN", f"{a} → {b}: {syn_ab}   {b} → {a}: {syn_ba}")
        doc.kv("SYN-ACK", str(synack))
        if first_syn is not None:
            doc.kv("first SYN", f"#{first_syn.no} {first_syn.src} → {first_syn.dst}:{first_syn.dport}")
        doc.kv("services", ", ".join(sorted(services)[:10]))
    else:
        doc.dim("no TCP handshake observed; initiator cannot be determined")
        doc.dim("from this capture (arrows show packet direction only)")
    _notes(doc, session, "conversation", ref)
    return doc.render()


def packet(session: Session, p: PacketRecord, raw: dict | None = None, hex_per_line: int = 16) -> Group:
    doc = Doc()
    idx = session.capture.index
    doc.section(f"FRAME #{p.no}", "decoded")
    doc.kv("time (UTC)", fmt_ts(p.ts, True))
    doc.kv("relative", f"T{fmt_rel(p.ts - idx.t0)}")
    doc.kv("epoch", f"{p.ts:.6f}")
    doc.kv("wire length", f"{p.wirelen} B")
    cap_note = "" if p.caplen >= p.wirelen else "  (snapped: payload not fully captured)"
    doc.kv("captured", f"{p.caplen} B{cap_note}")
    doc.kv("link type", f"{LINKTYPE_NAMES.get(p.linktype, 'other')} ({p.linktype})")
    if p.eth_src or p.eth_dst:
        doc.section("LINK", "decoded")
        doc.kv("src MAC", p.eth_src)
        doc.kv("dst MAC", p.eth_dst)
        if p.vlan is not None:
            doc.kv("VLAN", str(p.vlan))
        if p.ethertype is not None:
            doc.kv("ethertype", f"0x{p.ethertype:04x}")
    if p.net:
        doc.section(p.net, "decoded")
        doc.kv("source", p.src)
        doc.kv("destination", p.dst)
        if p.net == "ARP":
            doc.kv("operation", {1: "request", 2: "reply"}.get(p.arp_op or 0, str(p.arp_op)))
        else:
            doc.kv("TTL / hops", p.ttl)
            if p.ip_id is not None:
                doc.kv("IP ID", f"0x{p.ip_id:04x}")
            if p.ip_proto is not None:
                doc.kv("protocol #", p.ip_proto)
            if p.fragment:
                doc.kv("fragment", "yes")
    if p.transport:
        doc.section(p.transport, "decoded")
        doc.kv("src port", p.sport)
        doc.kv("dst port", p.dport)
        if p.transport == "TCP":
            doc.kv("flags", f"{p.flags_str or '-'}  (0x{(p.tcp_flags or 0):02x})")
            doc.kv("seq", p.tcp_seq)
            doc.kv("ack", p.tcp_ack)
            doc.kv("window", p.tcp_win)
        if p.icmp_type is not None:
            names = ICMP_TYPES if p.transport == "ICMP" else ICMPV6_TYPES
            doc.kv("type", f"{p.icmp_type} {names.get(p.icmp_type, '')}".strip())
            doc.kv("code", p.icmp_code)
        doc.kv("payload", f"{p.payload_len} B" if p.payload_len is not None else None)
    if p.dns is not None:
        d = p.dns
        doc.section(p.app or "DNS", "decoded by scapy")
        doc.kv("type", "response" if d.is_response else "query")
        doc.kv("transaction", f"0x{d.txid:04x}")
        doc.kv("question", f"{d.qname or '-'}  {d.qtype or ''}")
        if d.is_response:
            doc.kv("rcode", d.rcode_name, theme.S_AMBER if d.rcode else theme.S_TEXT)
            doc.kv("answers", f"{d.ancount}")
            for a in d.answers[:12]:
                doc.line(Text.assemble((f"{a.rtype:<6}", theme.S_DIM), (a.value, theme.S_TEXT), (f"  ttl {a.ttl}", theme.S_FAINT)))
        if d.truncated:
            doc.kv("truncated", "TC bit set")
        if d.malformed:
            doc.kv("malformed", Text(d.malformed, style=theme.S_AMBER))
    elif p.app and p.app_info:
        doc.section(p.app, "decoded")
        doc.line(p.app_info)
    elif p.app_info:
        doc.section("NOTE", "decoder")
        doc.line(p.app_info, theme.S_DIM)
    if p.errors:
        doc.section("DECODE ISSUES", "malformed or truncated input", theme.S_AMBER)
        for err in p.errors:
            doc.line(err, theme.S_AMBER)
    related = [f for f in session.capture.findings if p.no in f.frames]
    if related:
        doc.section("CITED BY", "heuristic")
        for f in related:
            doc.line(Text.assemble((f"{f.severity:<7}", theme.SEVERITY_STYLE[f.severity]), (f.title, theme.S_TEXT)))
    _notes(doc, session, "packet", str(p.no))
    if raw is None:
        doc.section("RAW BYTES", "hidden — press x to load (untrusted, undecoded)")
    elif raw.get("loading"):
        doc.section("RAW BYTES", "loading…")
    elif raw.get("error"):
        doc.section("RAW BYTES", "unavailable", theme.S_RED)
        doc.line(raw["error"], theme.S_RED)
    else:
        doc.section("SCAPY DISSECTION", "full decode, values sanitised")
        if raw.get("note"):
            doc.dim(raw["note"])
        for name, rows in raw.get("layers", []):
            doc.line(Text(name, style=theme.S_TEXT))
            for key, value in rows:
                doc.kv(key, value, theme.S_DIM)
        doc.section("RAW BYTES", "undecoded, untrusted", theme.S_AMBER)
        for line in hexdump(raw.get("data", b""), hex_per_line):
            doc.line(line, theme.S_FAINT)
        if raw.get("clipped"):
            doc.dim(f"... clipped at {raw['clipped']:,} bytes")
    return doc.render()


def finding(session: Session, f: Finding) -> Group:
    doc = Doc()
    doc.section("POSSIBLE ANOMALY", "heuristic output — not proof of malicious activity", theme.S_AMBER)
    doc.line(Text(f.title, style=Style(color=theme.TEXT, bold=True)))
    doc.kv("severity", f.severity, theme.SEVERITY_STYLE[f.severity])
    doc.kv("rule", f"{f.rule}  {RULES[f.rule].name}")
    doc.kv("confidence", f.confidence)
    doc.line(f.confidence_reason, theme.S_DIM)
    doc.kv("hosts", ", ".join(f.hosts))
    doc.kv("first event", fmt_ts(f.first_ts, True))
    doc.kv("last event", fmt_ts(f.last_ts, True))
    doc.kv("span", fmt_duration(f.last_ts - f.first_ts))
    if session.timeline and f.first_ts > session.timeline.cursor:
        doc.line(Text("not yet observed at the timeline cursor", style=theme.S_AMBER))
    doc.section("EXPLANATION")
    doc.line(f.explanation)
    doc.section("RULE")
    doc.line(RULES[f.rule].description, theme.S_DIM)
    doc.section("METRICS", "computed")
    for k, v in f.metrics.items():
        doc.kv(k, v if not isinstance(v, list) else ", ".join(map(str, v[:10])))
    doc.section("SUPPORTING FRAMES", f"{f.frame_count:,} total — enter: show as packet list")
    frames = f.frames[:60]
    doc.line(" ".join(f"#{n}" for n in frames) + (" …" if f.frame_count > len(frames) else ""), theme.S_DIM)
    _notes(doc, session, "finding", f.id)
    return doc.render()
