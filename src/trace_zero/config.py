"""Configuration: resource limits, heuristic thresholds and storage paths.

Configuration is optional. Defaults are safe for moderately large captures.
A TOML file may override any value (see ``config.example.toml``).
"""

from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any


class ConfigError(Exception):
    """Raised when a configuration file is invalid."""


@dataclass(frozen=True)
class Limits:
    # Captures larger than this are refused before any parsing happens.
    max_file_mb: int = 1024
    # Parsing stops (and the capture is flagged as truncated) after this many packets.
    max_packets: int = 1_000_000
    # Packets decoded between progress updates / cancellation checks.
    batch_size: int = 5000
    # Upper bound for the raw-bytes view of a single packet.
    max_raw_bytes: int = 65535
    # Maximum DNS payload size handed to the DNS decoder.
    max_dns_payload: int = 4096
    # On-disk cache of parsed captures (0 disables). Evicts least recently used.
    cache_max_mb: int = 2048


@dataclass(frozen=True)
class AnomalyConfig:
    # Repeated connection attempts: SYNs from one source to one destination:port.
    repeat_min_attempts: int = 6
    repeat_window_s: float = 120.0
    # Port fan-out: distinct destination ports contacted by one source.
    fanout_min_ports: int = 20
    fanout_window_s: float = 60.0
    # Traffic-volume spike: robust z-score over per-bin byte totals.
    spike_bin_s: float = 1.0
    spike_min_bins: int = 10
    spike_z: float = 6.0
    spike_min_factor: float = 4.0
    spike_min_bytes: int = 20_000
    # DNS query spike: per-source query counts per bin.
    dns_bin_s: float = 10.0
    dns_min_queries: int = 20
    dns_min_factor: float = 4.0
    # Frequent pair communication.
    pair_min_pairs: int = 5
    pair_min_contacts: int = 20
    pair_z: float = 5.0
    pair_periodic_z: float = 2.0
    pair_periodic_cv: float = 0.25
    # DNS responses without a matching query (per client).
    dns_unsolicited_min: int = 1
    dns_startup_grace_s: float = 1.0
    # Heavy outbound transfer from an internal to an external host.
    outbound_min_bytes: int = 500_000
    outbound_ratio: float = 5.0
    # New external destination late in the capture.
    late_fraction: float = 0.5
    late_min_baseline_s: float = 60.0
    late_min_bytes: int = 5_000
    # Supporting packet references stored per finding.
    max_refs: int = 500


def default_data_dir() -> Path:
    """Platform data directory for the investigation database."""
    override = os.environ.get("TRACE_ZERO_HOME")
    if override:
        return Path(override).expanduser()
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "trace-zero"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "trace-zero"
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "trace-zero"


def default_config_path() -> Path:
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "trace-zero" / "config.toml"
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "trace-zero" / "config.toml"


@dataclass(frozen=True)
class Config:
    limits: Limits = field(default_factory=Limits)
    anomaly: AnomalyConfig = field(default_factory=AnomalyConfig)
    db_path: Path = field(default_factory=lambda: default_data_dir() / "investigations.db")
    export_dir: Path = field(default_factory=lambda: Path.home() / "trace-zero-exports")
    cache_dir: Path = field(default_factory=lambda: default_data_dir() / "cache")


def _merge_section(obj: Any, data: dict[str, Any], section: str) -> Any:
    known = {f.name: f for f in fields(obj)}
    updates: dict[str, Any] = {}
    for key, value in data.items():
        if key not in known:
            raise ConfigError(f"[{section}] unknown key: {key}")
        current = getattr(obj, key)
        expected = type(current)
        if expected is float and isinstance(value, int) and not isinstance(value, bool):
            value = float(value)
        if not isinstance(value, expected) or isinstance(value, bool) != isinstance(current, bool):
            raise ConfigError(f"[{section}] {key}: expected {expected.__name__}")
        if isinstance(value, (int, float)) and (value < 0 or (value == 0 and key != "cache_max_mb")):
            raise ConfigError(f"[{section}] {key}: must be positive")
        updates[key] = value
    return replace(obj, **updates)


def load_config(path: Path | None = None) -> Config:
    """Load configuration. A missing default config file is not an error."""
    explicit = path is not None
    path = path or default_config_path()
    cfg = Config()
    if not path.exists():
        if explicit:
            raise ConfigError(f"config file not found: {path}")
        return cfg
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    limits = _merge_section(cfg.limits, data.get("limits", {}), "limits")
    anomaly = _merge_section(cfg.anomaly, data.get("anomaly", {}), "anomaly")
    paths = data.get("paths", {})
    unknown = set(data) - {"limits", "anomaly", "paths"}
    if unknown:
        raise ConfigError(f"unknown config sections: {', '.join(sorted(unknown))}")
    db_path = Path(paths["db"]).expanduser() if "db" in paths else cfg.db_path
    export_dir = Path(paths["exports"]).expanduser() if "exports" in paths else cfg.export_dir
    cache_dir = Path(paths["cache"]).expanduser() if "cache" in paths else cfg.cache_dir
    return Config(limits=limits, anomaly=anomaly, db_path=db_path, export_dir=export_dir, cache_dir=cache_dir)
