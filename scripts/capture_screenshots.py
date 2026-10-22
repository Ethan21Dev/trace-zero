#!/usr/bin/env python3
"""Render real screenshots of TRACE//ZERO into docs/screenshots/.

Runs the actual application headlessly (Textual's test driver) against the
synthetic sample capture, sends real keystrokes, and saves Textual's own SVG
export of the screen. Nothing here is mocked: if a feature breaks, the
screenshot shows it.

    python scripts/capture_screenshots.py
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from textual.widgets import TextArea  # noqa: E402

from trace_zero.config import Config  # noqa: E402
from trace_zero.samples import generate_sample  # noqa: E402
from trace_zero.session import Session  # noqa: E402
from trace_zero.storage import Store  # noqa: E402
from trace_zero.ui.app import TraceZeroApp  # noqa: E402

OUT = ROOT / "docs" / "screenshots"

SHOTS: list[tuple[str, tuple[int, int], list[str]]] = [
    ("01-workspace-map", (160, 46), ["down", "down", "enter"]),
    ("02-replay-sliding-window", (160, 46), ["home", "w", "right_square_bracket", *["right"] * 9, "h", "down", "n"]),
    ("03-findings", (160, 46), ["f", "down"]),
    ("04-finding-evidence", (160, 46), ["f", "enter", "shift+left"]),
    ("05-packet-inspector-raw", (160, 46), ["p", "slash", "@filter:dns:legacy", "enter", "up", "x", "@wait", "i", "pagedown", "pagedown"]),
    ("06-journal", (160, 46), ["f", "down", "m", "a", "@note", "b", "down", "down", "down"]),
    ("07-compact-100x32", (100, 32), ["p"]),
    ("08-help", (120, 40), ["question_mark"]),
]


async def shoot(capture: Path, workdir: Path, name: str, size: tuple[int, int], keys: list[str]) -> Path:
    cfg = Config(db_path=workdir / f"{name}.db", export_dir=workdir / "exports")
    store = Store(cfg.db_path)
    session = Session(cfg, store, store.open_or_create("Sample investigation"))
    app = TraceZeroApp(session, str(capture))
    async with app.run_test(size=size) as pilot:
        while session.capture is None:
            await pilot.pause(0.05)
        await app.workers.wait_for_complete()
        await pilot.pause(0.2)
        for key in keys:
            if key == "@wait":
                await app.workers.wait_for_complete()
                await pilot.pause(0.2)
            elif key.startswith("@filter:"):
                app.screen.query_one("Input").value = key.split(":", 1)[1]
            elif key == "@note":
                app.screen.query_one(TextArea).text = "Matches the failed RDP logins reported by the helpdesk; confirm with the asset owner."
                await pilot.press("ctrl+s")
            else:
                await pilot.press(key)
            await pilot.pause(0.05)
        await pilot.pause(0.3)
        app.clear_notifications()
        await pilot.pause(0.1)
        path = OUT / f"{name}.svg"
        app.save_screenshot(str(path))
    store.close()
    return path


async def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        capture = work / "trace-zero-sample.pcapng"
        generate_sample(capture, fmt="pcapng")
        for name, size, keys in SHOTS:
            path = await shoot(capture, work, name, size, keys)
            print(f"wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    asyncio.run(main())
