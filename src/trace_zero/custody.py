"""Chain of custody: evidence re-verification and export digests.

* Every capture is hashed (SHA-256) at import; the hash is stored with the
  investigation. Re-importing a path whose content hash changed is flagged.
* ``verify`` re-hashes the evidence files on demand and compares them with the
  recorded hashes. Results go to the activity journal.
* Every file TRACE//ZERO exports gets a ``<name>.sha256`` sidecar in
  ``sha256sum`` format, and the digest is written to the journal, so an export
  can later be shown to be unchanged (``sha256sum -c report.json.sha256``).
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from pathlib import Path

from trace_zero.export.report import atomic_write

_CHUNK = 4 * 1024 * 1024


def sha256_file(path: str | Path, cancelled=None) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(_CHUNK):
            digest.update(chunk)
            if cancelled is not None and cancelled():
                raise InterruptedError("verification cancelled")
    return digest.hexdigest()


def write_digest(path: str | Path) -> str:
    """Hash an exported file and write ``<file>.sha256`` next to it. Returns the hex digest."""
    path = Path(path)
    digest = sha256_file(path)
    atomic_write(path.with_name(path.name + ".sha256"), f"{digest}  {path.name}\n")
    return digest


def read_digest(path: str | Path) -> str:
    """The digest recorded in ``<file>.sha256`` by ``write_digest``."""
    path = Path(path)
    return path.with_name(path.name + ".sha256").read_text(encoding="utf-8").split()[0]


@dataclass(frozen=True)
class Verification:
    name: str
    path: str
    expected: str
    actual: str | None
    error: str | None
    at: float

    @property
    def ok(self) -> bool:
        return self.error is None and self.actual == self.expected

    @property
    def verdict(self) -> str:
        if self.error is not None:
            return "UNAVAILABLE"
        return "MATCH" if self.ok else "MISMATCH"

    def describe(self) -> str:
        if self.error is not None:
            return f"{self.name}: UNAVAILABLE - {self.error}"
        if self.ok:
            return f"{self.name}: MATCH sha256 {self.expected}"
        return f"{self.name}: MISMATCH - recorded {self.expected}, now {self.actual}"


def verify(evidence: list[tuple[str, str, str]], cancelled=None) -> list[Verification]:
    """Re-hash (name, path, recorded sha256) entries. Never raises for missing files."""
    out = []
    for name, path, expected in evidence:
        try:
            actual, error = sha256_file(path, cancelled), None
        except OSError as exc:
            actual, error = None, exc.strerror or str(exc)
        out.append(Verification(name, path, expected, actual, error, time.time()))
    return out


def changed_since_last_import(prior: list[tuple[str, float, str]], sha: str) -> list[tuple[str, float, str]]:
    """Earlier imports of the same path whose recorded hash differs from ``sha``."""
    return [p for p in prior if p[0] != sha]
