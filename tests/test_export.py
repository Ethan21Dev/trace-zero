from __future__ import annotations

import json

from trace_zero.export import build_report, export_all, render_html, write_json
from trace_zero.models import DnsInfo, PacketRecord
from trace_zero.session import Selection


def test_report_separates_facts_findings_and_interpretation(session):
    f = session.capture.findings[0]
    session.add_note(Selection("finding", f.id), "analyst thinks this is the backup job")
    session.toggle_bookmark(Selection("host", "10.20.0.12"))
    rep = build_report(session)
    assert rep["capture"]["sha256"] == session.sha
    assert rep["capture"]["packets"] == len(session.capture.result.packets)
    assert rep["observed_facts"]["host_count"] == len(session.capture.index.hosts)
    hf = rep["heuristic_findings"]
    assert "not proof" in hf["notice"]
    assert set(hf["rules"]) == {"TZ-R1", "TZ-R2", "TZ-R3", "TZ-R4", "TZ-R5"}
    exported = next(x for x in hf["findings"] if x["id"] == f.id)
    assert exported["analyst_notes"] == ["analyst thinks this is the backup job"]
    assert exported["supporting_frames"]
    ai = rep["analyst_interpretations"]
    assert "interpretations" in ai["notice"]
    assert ai["bookmarks"][0]["ref"] == "10.20.0.12"
    # Analyst text must not leak into the observed-facts section.
    assert "backup job" not in json.dumps(rep["observed_facts"])


def test_export_files(session, tmp_path):
    json_path, html_path = export_all(session, tmp_path / "out")
    data = json.loads(json_path.read_text())
    assert data["investigation"]["name"] == "test-investigation"
    html = html_path.read_text()
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    assert "<script" not in html
    assert "Observed facts" in html and "Analyst interpretations" in html
    assert any(e.kind == "export" for e in session.store.events(session.investigation.id))


def test_export_without_capture(config, store):
    from trace_zero.session import Session

    s = Session(config, store, store.create_investigation("empty"))
    s.add_note(None, "investigation-level note")
    rep = build_report(s)
    assert rep["capture"] is None and rep["observed_facts"] is None
    assert rep["analyst_interpretations"]["notes"][0]["body"] == "investigation-level note"
    assert "<html" in render_html(rep)


def test_html_escapes_hostile_capture_strings(session, tmp_path):
    rep = build_report(session)
    evil = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'
    rep["observed_facts"]["dns_queries_top"].insert(0, {"name": evil, "queries": 1})
    rep["investigation"]["name"] = evil
    html = render_html(rep)
    assert "<script>alert(1)" not in html and "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_json_roundtrip_is_valid(session, tmp_path):
    p = write_json(build_report(session), tmp_path / "r.json")
    assert json.loads(p.read_text())["generator"]["product"] == "TRACE//ZERO"


def test_info_with_control_characters_is_sanitised():
    from trace_zero.sanitize import clean

    dns = DnsInfo(txid=1, is_response=False, opcode=0, rcode=0, truncated=False, qname=clean("a\x1b[2Jb.example"), qtype="A", qdcount=1, ancount=0)
    p = PacketRecord(no=1, ts=0, wirelen=1, caplen=1, linktype=1, dns=dns)
    assert "\x1b" not in p.info and "\\x1b" in p.info
