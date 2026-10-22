"""Where the file browser starts, and the folders it offers as quick jumps.

When the executable is started by double-clicking it (or from a browser's
download list) on Windows, the working directory is often C:\\Windows\\System32,
which is no place to look for captures. The browser therefore starts in the
folder used last, else the working directory only if it holds captures, else
Downloads, else the home folder.
"""

from __future__ import annotations

import os
import string
import sys
from pathlib import Path

from trace_zero.parsing.reader import CAPTURE_SUFFIXES


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _holds_captures(folder: Path, limit: int = 2000) -> bool:
    try:
        with os.scandir(folder) as entries:
            for n, entry in enumerate(entries):
                if n >= limit:
                    return False
                if Path(entry.name).suffix.lower() in CAPTURE_SUFFIXES:
                    return True
    except OSError:
        return False
    return False


def places(export_dir: Path | None = None) -> list[tuple[str, Path]]:
    """(label, folder) quick jumps that exist on this machine."""
    home = Path.home()
    candidates: list[tuple[str, Path]] = [
        ("Downloads", home / "Downloads"),
        ("Desktop", home / "Desktop"),
        ("Desktop", home / "OneDrive" / "Desktop"),
        ("Documents", home / "Documents"),
        ("Documents", home / "OneDrive" / "Documents"),
        ("Home", home),
    ]
    if export_dir is not None:
        candidates.append(("Exports", Path(export_dir).expanduser()))
    if sys.platform == "win32":
        candidates += [(f"Drive {letter}:", Path(f"{letter}:\\")) for letter in string.ascii_uppercase]
    else:
        candidates.append(("Root", Path("/")))
    out: list[tuple[str, Path]] = []
    seen: set[str] = set()
    for label, folder in candidates:
        key = os.path.normcase(str(folder))
        if key in seen or not _is_dir(folder):
            continue
        if label in {lbl for lbl, _ in out}:
            continue  # e.g. a OneDrive Desktop when the local one exists
        seen.add(key)
        out.append((label, folder))
    return out


def initial_dir(last: str | None = None, cwd: Path | None = None) -> Path:
    """The folder the browser opens in."""
    if last and _is_dir(Path(last)):
        return Path(last)
    cwd = cwd or Path.cwd()
    if _holds_captures(cwd):
        return cwd
    downloads = Path.home() / "Downloads"
    if _is_dir(downloads):
        return downloads
    return Path.home()
