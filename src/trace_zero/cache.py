"""On-disk cache of parsed captures, keyed by the capture's SHA-256.

Reopening a capture skips parsing (and, when the heuristic settings are
unchanged, anomaly detection and the flow table). Design choices:

* No pickle: objects are flattened to plain tuples/lists/dicts and stored with
  ``marshal``, which only constructs basic types and never runs code.
* Every file carries a SHA-256 over its payload; a mismatch (truncation,
  corruption, tampering by anything that cannot also recompute it) discards it.
* The key covers the cache format, TRACE//ZERO version, Python version (marshal
  is version-specific), the capture hash and every limit that affects parsing.
* Total size is bounded; least recently used files are evicted first.
Delete the cache directory at any time to clear it.
"""

from __future__ import annotations

import hashlib
import logging
import marshal
import os
import sys
import tempfile
from collections import Counter
from dataclasses import fields
from pathlib import Path

from trace_zero import __version__
from trace_zero.analysis.anomaly import Finding
from trace_zero.analysis.flows import Flow
from trace_zero.config import AnomalyConfig, Limits
from trace_zero.models import DhcpInfo, DnsAnswer, DnsInfo, FileInfo, PacketRecord
from trace_zero.parsing.tls import TlsInfo

log = logging.getLogger("trace_zero")

FORMAT = 3
MAGIC = b"TZC\x03"
CHUNK = 20_000
_REC_FIELDS = [f.name for f in fields(PacketRecord)]
_DNS_FIELDS = [f.name for f in fields(DnsInfo)]
_TLS_FIELDS = [f.name for f in fields(TlsInfo)]
_DHCP_FIELDS = [f.name for f in fields(DhcpInfo)]
_FINDING_FIELDS = [f.name for f in fields(Finding)]
_FLOW_FIELDS = [f.name for f in fields(Flow)]


def _key(*parts: object) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()


def capture_key(info: FileInfo, limits: Limits) -> str:
    return _key(FORMAT, __version__, sys.version_info[:2], info.sha256, info.size, limits.max_packets, limits.max_dns_payload)


def analysis_key(info: FileInfo, limits: Limits, anomaly: AnomalyConfig) -> str:
    return _key(capture_key(info, limits), repr(anomaly))


# -- encoding --------------------------------------------------------------------------
def _enc_record(p: PacketRecord) -> tuple:
    values = []
    for name in _REC_FIELDS:
        v = getattr(p, name)
        if name == "dns" and v is not None:
            v = tuple(
                tuple((a.name, a.rtype, a.value, a.ttl) for a in v.answers) if n == "answers" else getattr(v, n) for n in _DNS_FIELDS
            )
        elif name == "tls" and v is not None:
            v = tuple(getattr(v, n) for n in _TLS_FIELDS)
        elif name == "dhcp" and v is not None:
            v = tuple(getattr(v, n) for n in _DHCP_FIELDS)
        values.append(v)
    return tuple(values)


_DNS_I, _TLS_I, _DHCP_I = _REC_FIELDS.index("dns"), _REC_FIELDS.index("tls"), _REC_FIELDS.index("dhcp")
_ANS_I = _DNS_FIELDS.index("answers")


def _dec_record(t: tuple) -> PacketRecord:
    if t[_DNS_I] is None and t[_TLS_I] is None and t[_DHCP_I] is None:
        return PacketRecord(*t)  # common case: positional construction, no nested objects
    v = list(t)
    if v[_DNS_I] is not None:
        d = list(v[_DNS_I])
        d[_ANS_I] = tuple(DnsAnswer(*a) for a in d[_ANS_I])
        v[_DNS_I] = DnsInfo(*d)
    if v[_TLS_I] is not None:
        v[_TLS_I] = TlsInfo(*v[_TLS_I])
    if v[_DHCP_I] is not None:
        v[_DHCP_I] = DhcpInfo(*v[_DHCP_I])
    return PacketRecord(*v)


def _enc_flow(f: Flow) -> tuple:
    return tuple(dict(getattr(f, n)) if n == "apps" else getattr(f, n) for n in _FLOW_FIELDS)


def _dec_flow(t: tuple) -> Flow:
    kw = dict(zip(_FLOW_FIELDS, t))
    kw["apps"] = Counter(kw["apps"])
    return Flow(**kw)


def _enc_finding(f: Finding) -> tuple:
    return tuple(getattr(f, n) for n in _FINDING_FIELDS)


def _dec_finding(t: tuple) -> Finding:
    kw = dict(zip(_FINDING_FIELDS, t))
    kw["hosts"] = tuple(kw["hosts"])
    return Finding(**kw)


# -- file handling -----------------------------------------------------------------------
def _write(path: Path, parts) -> None:
    """Write an iterable of objects as length-prefixed marshal blobs (bounded peak memory)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tzc-", dir=str(path.parent))
    digest = hashlib.sha256()
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(MAGIC + bytes(32))
            for part in parts:
                blob = marshal.dumps(part)
                frame = len(blob).to_bytes(8, "little") + blob
                digest.update(frame)
                fh.write(frame)
            fh.seek(len(MAGIC))
            fh.write(digest.digest())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read(path: Path) -> list | None:
    """Return the list of stored objects, or None if missing, corrupt or not ours."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if data[:4] != MAGIC or len(data) < 36:
        return None
    body = memoryview(data)[36:]
    if hashlib.sha256(body).digest() != data[4:36]:
        log.warning("discarding corrupt cache file %s", path.name)
        try:
            path.unlink()
        except OSError:
            pass
        return None
    parts = []
    pos = 0
    try:
        while pos < len(body):
            n = int.from_bytes(body[pos : pos + 8], "little")
            parts.append(marshal.loads(body[pos + 8 : pos + 8 + n]))
            pos += 8 + n
    except (ValueError, EOFError, TypeError):
        return None
    return parts


class CaptureCache:
    def __init__(self, directory: Path, max_mb: int) -> None:
        self.dir = Path(directory)
        self.max_bytes = max_mb * 1024 * 1024

    @property
    def enabled(self) -> bool:
        return self.max_bytes > 0

    def _path(self, info: FileInfo, key: str, kind: str) -> Path:
        return self.dir / f"{info.sha256[:16]}-{key[:16]}.{kind}.tzc"

    def load_packets(self, info: FileInfo, limits: Limits):
        """Returns (packets, linktypes, warnings, truncated, stop_reason) or None."""
        if not self.enabled:
            return None
        key = capture_key(info, limits)
        parts = _read(self._path(info, key, "packets"))
        try:
            if not parts or not isinstance(parts[0], dict) or parts[0].get("key") != key:
                return None
            head = parts[0]
            packets = [_dec_record(t) for chunk in parts[1:] for t in chunk]
            if len(packets) != head["count"]:
                return None
            os.utime(self._path(info, key, "packets"))
            return packets, set(head["linktypes"]), list(head["warnings"]), bool(head["truncated"]), head["stop_reason"]
        except (KeyError, TypeError, ValueError) as exc:
            log.warning("ignoring unreadable cache entry: %s", exc)
            return None

    def store_packets(self, info: FileInfo, limits: Limits, result) -> None:
        if not self.enabled:
            return
        key = capture_key(info, limits)
        head = {
            "key": key,
            "count": len(result.packets),
            "linktypes": sorted(result.linktypes),
            "warnings": list(result.warnings),
            "truncated": result.truncated,
            "stop_reason": result.stop_reason,
        }
        pk = result.packets
        chunks = ([_enc_record(p) for p in pk[i : i + CHUNK]] for i in range(0, len(pk), CHUNK))
        self._store(self._path(info, key, "packets"), [head], chunks)

    def load_index(self, info: FileInfo, limits: Limits) -> dict | None:
        if not self.enabled:
            return None
        key = capture_key(info, limits)
        parts = _read(self._path(info, key, "index"))
        if parts and isinstance(parts[0], dict) and parts[0].get("key") == key and isinstance(parts[0].get("index"), dict):
            return parts[0]["index"]
        return None

    def store_index(self, info: FileInfo, limits: Limits, index) -> None:
        if not self.enabled:
            return
        key = capture_key(info, limits)
        self._store(self._path(info, key, "index"), [{"key": key, "index": index.snapshot()}])

    def load_analysis(self, info: FileInfo, limits: Limits, anomaly: AnomalyConfig):
        """Returns (findings, flows) or None."""
        if not self.enabled:
            return None
        key = analysis_key(info, limits, anomaly)
        parts = _read(self._path(info, key, "analysis"))
        try:
            if not parts or not isinstance(parts[0], dict) or parts[0].get("key") != key:
                return None
            return [_dec_finding(t) for t in parts[0]["findings"]], [_dec_flow(t) for t in parts[0]["flows"]]
        except (KeyError, TypeError, ValueError) as exc:
            log.warning("ignoring unreadable analysis cache entry: %s", exc)
            return None

    def store_analysis(self, info: FileInfo, limits: Limits, anomaly: AnomalyConfig, findings, flows) -> None:
        if not self.enabled:
            return
        key = analysis_key(info, limits, anomaly)
        payload = {"key": key, "findings": [_enc_finding(f) for f in findings], "flows": [_enc_flow(f) for f in flows]}
        self._store(self._path(info, key, "analysis"), [payload])

    def _store(self, path: Path, *parts) -> None:
        try:
            _write(path, (obj for group in parts for obj in group))
            self._evict()
        except (OSError, ValueError) as exc:  # a cache failure must never break an import
            log.warning("could not write cache %s: %s", path.name, exc)

    def _evict(self) -> None:
        try:
            files = sorted(self.dir.glob("*.tzc"), key=lambda f: f.stat().st_mtime)
            total = sum(f.stat().st_size for f in files)
            while files and total > self.max_bytes:
                victim = files.pop(0)
                total -= victim.stat().st_size
                victim.unlink()
        except OSError:
            pass

    def clear(self) -> int:
        n = 0
        for f in self.dir.glob("*.tzc"):
            try:
                f.unlink()
                n += 1
            except OSError:
                pass
        return n
