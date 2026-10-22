"""Investigation summary model shared by the JSON and HTML exports.

The report keeps three kinds of content strictly apart:

* observed_facts           computed deterministically from capture data
* heuristic_findings       possible anomalies produced by transparent rules
* analyst_interpretations  notes and bookmarks written by people
"""

from __future__ import annotations

import os
import re
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any

from trace_zero import PRODUCT, TAGLINE, __version__
from trace_zero.analysis.anomaly import RULES
from trace_zero.analysis.index import classify_ip
from trace_zero.models import LINKTYPE_NAMES, fmt_ts

TOP_N = 50


def _iso(ts: float | None) -> str | None:
    return None if ts is None else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def build_report(session) -> dict[str, Any]:
    inv = session.investigation
    store = session.store
    report: dict[str, Any] = {
        "generator": {
            "product": PRODUCT,
            "tagline": TAGLINE,
            "version": __version__,
            "generated_at_utc": _iso(time.time()),
        },
        "investigation": {
            "id": inv.id,
            "name": inv.name,
            "description": inv.description,
            "created_at_utc": _iso(inv.created_at),
            "updated_at_utc": _iso(inv.updated_at),
            "captures_examined": [
                {k: c[k] for k in ("filename", "path", "sha256", "size", "fmt", "packet_count", "truncated")}
                | {"imported_at_utc": _iso(c["imported_at"])}
                for c in store.captures(inv.id)
            ],
        },
        "capture": None,
        "observed_facts": None,
        "heuristic_findings": {
            "notice": "Possible anomalies flagged by transparent heuristics. They indicate traffic worth review, "
            "not proof of malicious activity.",
            "rules": {rid: {"name": r.name, "description": r.description} for rid, r in RULES.items()},
            "findings": [],
        },
        "analyst_interpretations": {
            "notice": "Written by analysts. These are interpretations, not data derived from the capture.",
            "notes": [],
            "bookmarks": [],
        },
        "activity_journal": [
            {"at_utc": _iso(e.at), "kind": e.kind, "message": e.message} for e in store.events(inv.id)
        ],
    }
    sha = session.sha
    notes = store.notes(inv.id, sha if sha else None)
    report["analyst_interpretations"]["notes"] = [
        {"target_kind": n.target_kind, "target_ref": n.target_ref, "body": n.body, "created_at_utc": _iso(n.created_at)} for n in notes
    ]
    if session.capture is None:
        return report
    loaded = session.capture
    r = loaded.result
    idx = loaded.index
    report["analyst_interpretations"]["bookmarks"] = [
        {"kind": b.kind, "ref": b.ref, "label": b.label, "created_at_utc": _iso(b.created_at)} for b in store.bookmarks(inv.id, sha)
    ]
    report["capture"] = {
        "filename": r.file.name,
        "path": r.file.path,
        "sha256": r.file.sha256,
        "size_bytes": r.file.size,
        "format": r.file.fmt,
        "packets": len(r.packets),
        "bytes_on_wire": idx.total_bytes,
        "first_packet_utc": fmt_ts(idx.t0, True) if r.packets else None,
        "last_packet_utc": fmt_ts(idx.t1, True) if r.packets else None,
        "duration_s": round(idx.span, 6),
        "link_types": sorted(LINKTYPE_NAMES.get(lt, str(lt)) for lt in r.linktypes),
        "time_ordered_in_file": idx.sorted_in_file,
        "truncated": r.truncated,
        "stop_reason": r.stop_reason,
        "parser_warnings": r.warnings,
        "parse_seconds": round(r.elapsed_s, 3),
        "frames_with_decode_errors": sum(1 for p in r.packets if p.errors),
    }
    full = idx.view(None, key="").window(idx.t0, idx.t1) if r.packets else None
    hosts = []
    for ip, m in sorted(idx.hosts.items(), key=lambda kv: -(kv[1].bytes_out + kv[1].bytes_in))[:TOP_N]:
        hosts.append(
            {
                "ip": ip,
                "scope": classify_ip(ip),
                "packets_sent": m.pkts_out,
                "packets_received": m.pkts_in,
                "bytes_sent": m.bytes_out,
                "bytes_received": m.bytes_in,
                "first_seen_utc": fmt_ts(m.first, True),
                "last_seen_utc": fmt_ts(m.last, True),
                "mac_addresses": [{"mac": mac, "first_frame": no} for mac, no in m.macs.items()],
                "dns_names_resolving_here": [{"name": n, "frame": no} for n, no in m.dns_names.items()],
                "ttl_values_sent": dict(m.ttls.most_common(5)),
                "tcp_ports_accepting": sorted(m.ports_accepting),
                "protocols": dict(m.protocols.most_common()),
            }
        )
    conversations = []
    for row in (full.pairs() if full else [])[:TOP_N]:
        conversations.append(
            {
                "a": row["a"],
                "b": row["b"],
                "packets_a_to_b": row["ab"],
                "packets_b_to_a": row["ba"],
                "bytes": row["bytes"],
                "first_utc": fmt_ts(row["first"], True),
                "last_utc": fmt_ts(row["last"], True),
                "protocols": dict(row["protos"].most_common()),
            }
        )
    qnames = Counter(p.dns.qname for p in r.packets if p.dns and not p.dns.is_response and p.dns.qname)
    report["observed_facts"] = {
        "notice": "Computed directly from capture data. Times are UTC capture timestamps.",
        "protocols": dict(idx.proto_counts.most_common()),
        "host_count": len(idx.hosts),
        "top_hosts": hosts,
        "top_conversations": conversations,
        "dns_queries_top": [{"name": n, "queries": c} for n, c in qnames.most_common(TOP_N)],
        "timeline_events": [
            {"time_utc": fmt_ts(e.ts, True), "kind": e.kind, "description": e.label, "frame": e.frame} for e in idx.events[:500]
        ],
    }
    finding_notes: dict[str, list[str]] = {}
    for n in notes:
        if n.target_kind == "finding":
            finding_notes.setdefault(n.target_ref, []).append(n.body)
    statuses = session.triage()
    sups = session.suppressions()
    findings_out = []
    for f in loaded.findings:
        status = statuses.get(f.id)
        sup = session.suppression_for(f, sups)
        findings_out.append(
            f.to_dict()
            | {
                "analyst_notes": finding_notes.get(f.id, []),
                "analyst_status": status[0] if status else "new",
                "analyst_status_reason": status[1] if status else "",
                "suppressed_by": {"rule": sup.rule, "host": sup.host, "reason": sup.reason} if sup else None,
            }
        )
    report["heuristic_findings"]["findings"] = findings_out
    report["analyst_interpretations"]["suppression_rules"] = [
        {"rule": x.rule, "host": x.host or None, "reason": x.reason, "created_at_utc": _iso(x.created_at)} for x in sups
    ]
    report["analyst_interpretations"]["timeline_marks"] = [
        {"time_utc": fmt_ts(m.ts, True), "label": m.label, "created_at_utc": _iso(m.created_at)} for m in session.marks()
    ]
    if session.filter is not None:
        report["view_at_export"] = {"filter": session.filter.display}
    return report


def slug(text: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-.")
    return (s or "investigation")[:60]


def atomic_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tz-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tz-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def export_targets(directory: Path, name: str, capture_path: str | None) -> tuple[Path, Path]:
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    base = directory / f"{slug(name)}-{stamp}"
    json_path, html_path = base.with_suffix(".json"), base.with_suffix(".html")
    if capture_path:
        cap = Path(capture_path).resolve()
        if cap in (json_path.resolve(), html_path.resolve()):
            raise OSError("refusing to overwrite the capture file")
    return json_path, html_path
