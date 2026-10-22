"""Investigation exports: JSON summary and readable HTML report."""

from __future__ import annotations

import json
from pathlib import Path

from trace_zero.export.html_report import render_html
from trace_zero.export.report import atomic_write, build_report, export_targets


def write_json(report: dict, path: Path) -> Path:
    atomic_write(path, json.dumps(report, indent=2, sort_keys=False, ensure_ascii=False) + "\n")
    return path


def write_html(report: dict, path: Path) -> Path:
    atomic_write(path, render_html(report))
    return path


def export_all(session, directory: Path) -> tuple[Path, Path]:
    capture_paths = [i.path for i, _o, _c in session.capture.result.source_list()] if session.capture else []
    json_path, html_path = export_targets(directory, session.investigation.name, capture_paths)
    report = build_report(session)
    write_json(report, json_path)
    write_html(report, html_path)
    session.store.log(session.investigation.id, "export", f"exported {json_path.name} and {html_path.name}")
    return json_path, html_path


__all__ = ["build_report", "export_all", "render_html", "write_html", "write_json"]
