#!/usr/bin/env python3
"""Build a standalone trace-zero executable with PyInstaller, then smoke-test it.

    pip install pyinstaller
    python scripts/build_binary.py            # -> dist/trace-zero[.exe]

The executable bundles Python, Textual, Rich and Scapy. It is a single file
for the platform it was built on (build on Windows for Windows, and so on).
The smoke test runs the binary offline: version, sample generation and a
headless analysis of that sample.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build() -> Path:
    name = "trace-zero"
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--onefile",
        "--name", name,
        "--distpath", str(ROOT / "dist"),
        "--workpath", str(ROOT / "build" / "pyinstaller"),
        "--specpath", str(ROOT / "build"),
        "--paths", str(ROOT / "src"),
        # Data files: the Textual stylesheet.
        "--collect-data", "trace_zero",
        # Textual and Scapy import many modules by name at runtime.
        "--collect-submodules", "textual",
        "--collect-submodules", "scapy.layers",
        "--collect-submodules", "scapy.contrib",
        "--collect-data", "textual",
        # Never needed offline; keeps the binary smaller.
        "--exclude-module", "tkinter",
        "--exclude-module", "matplotlib",
        "--exclude-module", "IPython",
        str(ROOT / "packaging" / "entry.py"),
    ]
    subprocess.run(cmd, check=True, cwd=ROOT)
    exe = ROOT / "dist" / (name + (".exe" if os.name == "nt" else ""))
    if not exe.exists():
        raise SystemExit(f"build did not produce {exe}")
    return exe


def smoke(exe: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="tz-smoke-") as tmp:
        env = dict(os.environ, TRACE_ZERO_HOME=str(Path(tmp) / "home"))
        run = lambda *args: subprocess.run([str(exe), *args], check=True, capture_output=True, text=True, env=env, timeout=300)  # noqa: E731
        print(run("--version").stdout.strip())
        sample = Path(tmp) / "sample.pcapng"
        run("--generate-sample", str(sample), "--format", "pcapng")
        report = Path(tmp) / "report.json"
        out = run(str(sample), "--headless", "--db", str(Path(tmp) / "t.db"), "--json", str(report), "--html", str(Path(tmp) / "r.html")).stdout
        data = json.loads(report.read_text(encoding="utf-8"))
        assert data["capture"]["packets"] == 3324, data["capture"]["packets"]
        assert data["heuristic_findings"]["findings"], "no findings"
        assert (Path(tmp) / "report.json.sha256").exists()
        print(out.splitlines()[4])
    print(f"smoke test passed: {exe} ({exe.stat().st_size / 1e6:.1f} MB)")


def main() -> int:
    exe = ROOT / "dist" / ("trace-zero" + (".exe" if os.name == "nt" else ""))
    if "--smoke-only" not in sys.argv:
        exe = build()
    smoke(exe)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
