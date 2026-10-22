"""Self-contained HTML report.

Every value is HTML-escaped (capture content is untrusted), and a strict
Content-Security-Policy forbids scripts and any network fetch, so opening the
report never contacts an external service.
"""

from __future__ import annotations

from html import escape
from typing import Any

CSS = """
:root{--bg:#0b0d0e;--panel:#111416;--line:#262b2e;--text:#c9cfd2;--dim:#7d878c;--cyan:#4fd1d9;--green:#7fb685;--amber:#d9a441;--red:#d0605e}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
main{max-width:1180px;margin:0 auto;padding:28px 20px 60px}
header{border-bottom:1px solid var(--line);padding-bottom:14px;margin-bottom:22px}
.brand{color:var(--cyan);font-weight:700;letter-spacing:.08em}
.tag{color:var(--dim);letter-spacing:.12em;font-size:11px}
h1{font-size:15px;margin:10px 0 0;font-weight:600}
h2{font-size:12px;letter-spacing:.14em;color:var(--cyan);border-bottom:1px solid var(--line);padding-bottom:6px;margin:34px 0 10px;text-transform:uppercase}
h3{font-size:13px;margin:0 0 6px}
.notice{color:var(--dim);font-size:12px;margin:0 0 12px;border-left:2px solid var(--line);padding-left:10px}
.notice.interp{border-left-color:var(--amber)}
table{width:100%;border-collapse:collapse;margin:6px 0 14px}
th,td{text-align:left;padding:3px 8px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}
th{color:var(--dim);font-weight:500;font-size:11px;letter-spacing:.08em;text-transform:uppercase}
td.n{text-align:right;white-space:nowrap}
dl{display:grid;grid-template-columns:200px 1fr;gap:2px 14px;margin:0}
dt{color:var(--dim)} dd{margin:0;word-break:break-all}
.card{background:var(--panel);border:1px solid var(--line);padding:12px 14px;margin:10px 0}
.sev{display:inline-block;min-width:62px;font-size:11px;letter-spacing:.1em}
.HIGH{color:var(--red)} .MEDIUM{color:var(--amber)} .LOW{color:var(--green)}
.meta{color:var(--dim);font-size:12px}
.interp-card{border-left:2px solid var(--amber)}
.warn{color:var(--amber)}
code{color:var(--cyan)}
footer{margin-top:40px;color:var(--dim);font-size:11px;border-top:1px solid var(--line);padding-top:10px}
@media print{:root{--bg:#fff;--panel:#fafafa;--line:#ccc;--text:#111;--dim:#555;--cyan:#035d63;--green:#2d5e33;--amber:#7a5200;--red:#8a1f1d}}
"""


def e(value: Any) -> str:
    return escape("" if value is None else str(value), quote=True)


def _table(headers: list[str], rows: list[list[Any]], numeric: set[int] | None = None) -> str:
    numeric = numeric or set()
    head = "".join(f"<th>{e(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f'<td class="n">{e(c)}</td>' if i in numeric else f"<td>{e(c)}</td>" for i, c in enumerate(r)) + "</tr>"
        for r in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body or '<tr><td>none</td></tr>'}</tbody></table>"


def _dl(pairs: list[tuple[str, Any]]) -> str:
    return "<dl>" + "".join(f"<dt>{e(k)}</dt><dd>{e(v)}</dd>" for k, v in pairs) + "</dl>"


def render_html(report: dict[str, Any]) -> str:
    gen = report["generator"]
    inv = report["investigation"]
    cap = report.get("capture")
    facts = report.get("observed_facts")
    hf = report["heuristic_findings"]
    ai = report["analyst_interpretations"]
    out: list[str] = []
    out.append(
        f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(gen['product'])} report - {e(inv['name'])}</title><style>{CSS}</style></head><body><main>
<header><div class="brand">{e(gen['product'])}</div><div class="tag">{e(gen['tagline'])}</div>
<h1>Investigation report: {e(inv['name'])}</h1>
<div class="meta">generated {e(gen['generated_at_utc'])} &middot; version {e(gen['version'])}</div></header>"""
    )
    out.append("<h2>Investigation</h2>")
    out.append(
        _dl(
            [
                ("name", inv["name"]),
                ("created (UTC)", inv["created_at_utc"]),
                ("last updated (UTC)", inv["updated_at_utc"]),
                ("captures examined", len(inv["captures_examined"])),
            ]
        )
    )
    if inv["captures_examined"]:
        out.append(
            _table(
                ["file", "sha256", "packets", "imported (UTC)"],
                [[c["filename"], c["sha256"], c["packet_count"], c["imported_at_utc"]] for c in inv["captures_examined"]],
                {2},
            )
        )
    if cap:
        out.append("<h2>Capture</h2>")
        out.append('<p class="notice">Original capture treated as read-only evidence. Integrity hash computed at import.</p>')
        out.append(
            _dl(
                [
                    ("file", cap["filename"]),
                    ("path", cap["path"]),
                    ("sha256", cap["sha256"]),
                    ("format", cap["format"]),
                    ("size (bytes)", cap["size_bytes"]),
                    ("packets", cap["packets"]),
                    ("first packet (UTC)", cap["first_packet_utc"]),
                    ("last packet (UTC)", cap["last_packet_utc"]),
                    ("duration (s)", cap["duration_s"]),
                    ("link types", ", ".join(cap["link_types"])),
                    ("frames with decode errors", cap["frames_with_decode_errors"]),
                    ("import truncated", f"yes - {cap['stop_reason']}" if cap["truncated"] else "no"),
                ]
            )
        )
        if len(cap.get("sources", [])) > 1:
            out.append('<p class="notice">Several captures merged onto one timeline. Frames are numbered consecutively; the combined SHA-256 covers the sorted source hashes. Packets seen by more than one sensor appear once per capture.</p>')
            out.append(
                _table(
                    ["file", "sha256", "format", "frames", "packets"],
                    [[c["filename"], c["sha256"], c["format"], f'{c["first_frame"]}-{c["first_frame"] + c["packets"] - 1}', c["packets"]] for c in cap["sources"]],
                    {4},
                )
            )
        if cap["parser_warnings"]:
            out.append('<p class="warn">Parser warnings:</p><ul>' + "".join(f"<li>{e(w)}</li>" for w in cap["parser_warnings"]) + "</ul>")
    if facts:
        out.append("<h2>Observed facts</h2>")
        out.append(f'<p class="notice">{e(facts["notice"])}</p>')
        out.append("<h3>Protocols</h3>")
        out.append(_table(["protocol", "packets"], [[k, v] for k, v in facts["protocols"].items()], {1}))
        out.append(f"<h3>Hosts (top {len(facts['top_hosts'])} of {facts['host_count']})</h3>")
        out.append(
            _table(
                ["address", "scope", "pkts out", "pkts in", "bytes out", "bytes in", "first seen", "last seen", "MAC", "DNS names (observed)"],
                [
                    [
                        h["ip"],
                        h["scope"],
                        h["packets_sent"],
                        h["packets_received"],
                        h["bytes_sent"],
                        h["bytes_received"],
                        h["first_seen_utc"],
                        h["last_seen_utc"],
                        ", ".join(m["mac"] for m in h["mac_addresses"]) or "-",
                        ", ".join(f"{n['name']} (#{n['frame']})" for n in h["dns_names_resolving_here"]) or "-",
                    ]
                    for h in facts["top_hosts"]
                ],
                {2, 3, 4, 5},
            )
        )
        out.append("<h3>Conversations</h3>")
        out.append(
            _table(
                ["a", "b", "a->b pkts", "b->a pkts", "bytes", "first", "last", "protocols"],
                [
                    [c["a"], c["b"], c["packets_a_to_b"], c["packets_b_to_a"], c["bytes"], c["first_utc"], c["last_utc"], ", ".join(f"{k}:{v}" for k, v in c["protocols"].items())]
                    for c in facts["top_conversations"]
                ],
                {2, 3, 4},
            )
        )
        if facts["dns_queries_top"]:
            out.append("<h3>DNS questions observed</h3>")
            out.append(_table(["name", "queries"], [[d["name"], d["queries"]] for d in facts["dns_queries_top"]], {1}))
    ref = report.get("reference_data")
    if ref and ref.get("hosts"):
        out.append("<h2>Reference data</h2>")
        out.append(f'<p class="notice">{e(ref["notice"])}</p>')
        out.append("<ul>" + "".join(f"<li>{e(src)}</li>" for src in ref["sources"]) + "</ul>")
        out.append(_table(["address", "field", "value"], [[ip, r["field"], r["value"]] for ip, rows in ref["hosts"].items() for r in rows]))
    out.append("<h2>Heuristic findings - possible anomalies</h2>")
    out.append(f'<p class="notice">{e(hf["notice"])}</p>')
    if not hf["findings"]:
        out.append('<p class="meta">No heuristic fired for this capture.</p>')
    for f in hf["findings"]:
        frames = ", ".join(f"#{n}" for n in f["supporting_frames"][:40])
        more = f" (+{f['supporting_frame_count'] - 40} more)" if f["supporting_frame_count"] > 40 else ""
        out.append(
            f"""<div class="card"><h3><span class="sev {e(f['severity'])}">{e(f['severity'])}</span>{e(f['title'])}</h3>
<div class="meta">{e(f['rule'])} &middot; {e(f['rule_name'])} &middot; id {e(f['id'])}</div>
<p>{e(f['explanation'])}</p>"""
            + _dl(
                [
                    ("hosts", ", ".join(f["hosts"])),
                    ("first event (UTC)", f["first_time_utc"]),
                    ("last event (UTC)", f["last_time_utc"]),
                    ("confidence", f"{f['confidence']} - {f['confidence_reason']}"),
                    ("analyst triage", f"{f.get('analyst_status', 'new')}" + (f" - {f['analyst_status_reason']}" if f.get("analyst_status_reason") else "")),
                    ("suppressed", f"yes - {f['suppressed_by']['reason']}" if f.get("suppressed_by") else "no"),
                    ("supporting frames", f"{f['supporting_frame_count']}: {frames}{more}"),
                    ("rule", f["rule_description"]),
                ]
            )
            + "".join(f'<div class="card interp-card"><span class="meta">ANALYST NOTE</span><br>{e(n)}</div>' for n in f["analyst_notes"])
            + "</div>"
        )
    out.append("<h2>Analyst interpretations</h2>")
    out.append(f'<p class="notice interp">{e(ai["notice"])}</p>')
    if ai["notes"]:
        out.append(
            _table(
                ["written (UTC)", "about", "note"],
                [[n["created_at_utc"], f"{n['target_kind']} {n['target_ref']}".strip(), n["body"]] for n in ai["notes"]],
            )
        )
    else:
        out.append('<p class="meta">No analyst notes recorded.</p>')
    if ai.get("suppression_rules"):
        out.append("<h3>Suppression rules</h3>")
        out.append(_table(["created (UTC)", "rule", "host", "reason"], [[x["created_at_utc"], x["rule"], x["host"] or "(any host)", x["reason"]] for x in ai["suppression_rules"]]))
    if ai.get("timeline_marks"):
        out.append("<h3>Timeline marks</h3>")
        out.append(_table(["capture time (UTC)", "label"], [[m["time_utc"], m["label"]] for m in ai["timeline_marks"]]))
    out.append("<h3>Bookmarks</h3>")
    out.append(_table(["created (UTC)", "kind", "reference", "label"], [[b["created_at_utc"], b["kind"], b["ref"], b["label"]] for b in ai["bookmarks"]]))
    if facts and facts["timeline_events"]:
        out.append("<h2>Capture timeline (first observations)</h2>")
        out.append(_table(["time (UTC)", "kind", "event", "frame"], [[t["time_utc"], t["kind"], t["description"], t["frame"]] for t in facts["timeline_events"]], {3}))
    out.append("<h2>Activity journal</h2>")
    out.append(_table(["time (UTC)", "kind", "activity"], [[j["at_utc"], j["kind"], j["message"]] for j in report["activity_journal"]]))
    out.append(f"<footer>{e(gen['product'])} {e(gen['version'])} &middot; {e(gen['tagline'])}</footer></main></body></html>\n")
    return "".join(out)
