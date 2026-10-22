"""Chain of custody: changed-evidence warnings, re-verification, export digests."""

from __future__ import annotations

import hashlib
import json
import shutil

from trace_zero.cli import main
from trace_zero.config import Config
from trace_zero.custody import verify, write_digest
from trace_zero.export import build_report, export_all
from trace_zero.session import Session, load_capture
from trace_zero.storage import Store


def _session(tmp_path, name="custody"):
    cfg = Config(db_path=tmp_path / "c.db", export_dir=tmp_path / "exports", cache_dir=tmp_path / "cache")
    store = Store(cfg.db_path)
    return cfg, store, Session(cfg, store, store.open_or_create(name))


def test_write_digest_is_sha256sum_compatible(tmp_path):
    f = tmp_path / "out.bin"
    f.write_bytes(b"evidence")
    digest = write_digest(f)
    assert digest == hashlib.sha256(b"evidence").hexdigest()
    assert (tmp_path / "out.bin.sha256").read_text() == f"{digest}  out.bin\n"


def test_verify_reports_match_mismatch_and_missing(tmp_path):
    a = tmp_path / "a"
    a.write_bytes(b"one")
    good = hashlib.sha256(b"one").hexdigest()
    results = verify([("a", str(a), good), ("a2", str(a), "0" * 64), ("gone", str(tmp_path / "missing"), good)])
    assert [r.verdict for r in results] == ["MATCH", "MISMATCH", "UNAVAILABLE"]
    assert results[0].ok and not results[1].ok and not results[2].ok


def test_changed_file_at_same_path_is_flagged(tmp_path, sample_pcap):
    cap = tmp_path / "evidence.pcap"
    shutil.copy(sample_pcap, cap)
    cfg, store, s = _session(tmp_path)
    s.attach(load_capture(cap, cfg))
    assert s.custody_warnings == []
    data = bytearray(cap.read_bytes())
    data[-1] ^= 0xFF  # tamper with the last payload byte
    cap.write_bytes(bytes(data))
    s.attach(load_capture(cap, cfg))
    assert len(s.custody_warnings) == 1 and "evidence.pcap" in s.custody_warnings[0]
    kinds = [e.kind for e in store.events(s.investigation.id)]
    assert "custody" in kinds
    assert build_report(s)["chain_of_custody"]["warnings"] == s.custody_warnings
    store.close()


def test_session_verify_and_export_digests(tmp_path, sample_pcap):
    cap = tmp_path / "evidence.pcap"
    shutil.copy(sample_pcap, cap)
    cfg, store, s = _session(tmp_path)
    s.attach(load_capture(cap, cfg))
    assert all(v.ok for v in s.verify_evidence())
    json_path, html_path = export_all(s, tmp_path / "exports")
    for path in (json_path, html_path):
        sidecar = path.with_name(path.name + ".sha256").read_text()
        assert sidecar.split()[0] == hashlib.sha256(path.read_bytes()).hexdigest()
    pcap_out = tmp_path / "exports" / "sel.pcapng"
    s.export_packets(pcap_out)
    digest = hashlib.sha256(pcap_out.read_bytes()).hexdigest()
    messages = [e.message for e in store.events(s.investigation.id) if e.kind == "export"]
    assert any(m.startswith(f"sel.pcapng sha256 {digest}") for m in messages)
    report = json.loads(json_path.read_text())
    assert any(ev["kind"] == "verify" for ev in report["chain_of_custody"]["events"])
    cap.write_bytes(b"\x00" * 64)
    results = s.verify_evidence()
    assert [v.verdict for v in results] == ["MISMATCH"]
    store.close()


def test_cli_verify_exit_codes(tmp_path, sample_pcap, capsys):
    cap = tmp_path / "evidence.pcap"
    shutil.copy(sample_pcap, cap)
    db = str(tmp_path / "v.db")
    assert main([str(cap), "--headless", "--db", db, "-i", "case-1"]) == 0
    capsys.readouterr()
    assert main(["--verify", "--db", db, "-i", "case-1"]) == 0
    assert "MATCH" in capsys.readouterr().out
    cap.unlink()
    assert main(["--verify", "--db", db, "-i", "case-1"]) == 3
    out = capsys.readouterr().out
    assert "UNAVAILABLE" in out and "0 of 1" in out
    assert main(["--verify", "--db", db, "-i", "no-such-case"]) == 1
