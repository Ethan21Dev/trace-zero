"""On-disk capture cache."""

from __future__ import annotations

import dataclasses

from trace_zero.cache import CaptureCache
from trace_zero.config import AnomalyConfig, Config, Limits
from trace_zero.session import load_capture


def cfg(tmp_path, **limits) -> Config:
    return Config(limits=Limits(**limits), db_path=tmp_path / "db", export_dir=tmp_path / "ex", cache_dir=tmp_path / "cache")


def test_second_load_comes_from_cache_and_is_identical(sample_pcap, tmp_path):
    c = cfg(tmp_path)
    first = load_capture(sample_pcap, c)
    second = load_capture(sample_pcap, c)
    assert not first.result.cached and second.result.cached
    assert [dataclasses.astuple(p) for p in first.result.packets] == [dataclasses.astuple(p) for p in second.result.packets]
    assert [f.to_dict() for f in first.findings] == [f.to_dict() for f in second.findings]
    f1 = first.index.view(None, key="").flows_cache
    f2 = second.index.view(None, key="").flows_cache
    assert [(f.ref, f.state, f.frames, dict(f.apps)) for f in f1] == [(f.ref, f.state, f.frames, dict(f.apps)) for f in f2]
    assert second.result.file.sha256 == first.result.file.sha256


def test_corrupted_cache_is_discarded(sample_pcap, tmp_path):
    c = cfg(tmp_path)
    load_capture(sample_pcap, c)
    for f in (tmp_path / "cache").glob("*.packets.tzc"):
        data = bytearray(f.read_bytes())
        data[100] ^= 0xFF
        f.write_bytes(bytes(data))
    again = load_capture(sample_pcap, c)
    assert not again.result.cached and len(again.result.packets) > 0


def test_changed_settings_invalidate(sample_pcap, tmp_path):
    load_capture(sample_pcap, cfg(tmp_path))
    limited = load_capture(sample_pcap, cfg(tmp_path, max_packets=100))
    assert not limited.result.cached and len(limited.result.packets) == 100
    c = cfg(tmp_path)
    c2 = dataclasses.replace(c, anomaly=AnomalyConfig(repeat_min_attempts=99))
    restored = load_capture(sample_pcap, c2)
    assert restored.result.cached  # packets reused ...
    assert not any(f.rule == "TZ-R1" for f in restored.findings)  # ... but detection re-ran with new thresholds


def test_disabled_and_eviction(sample_pcap, tmp_path):
    off = cfg(tmp_path, cache_max_mb=0)
    load_capture(sample_pcap, off)
    assert not list((tmp_path / "cache").glob("*.tzc")) if (tmp_path / "cache").exists() else True
    assert not load_capture(sample_pcap, off).result.cached
    cache = CaptureCache(tmp_path / "cache", 1)
    (tmp_path / "cache").mkdir(exist_ok=True)
    for i in range(3):
        (tmp_path / "cache" / f"old{i}.x.tzc").write_bytes(b"\0" * 600_000)
    cache._evict()
    assert sum(f.stat().st_size for f in (tmp_path / "cache").glob("*.tzc")) <= 1024 * 1024


def test_no_cache_flag(sample_pcap, tmp_path):
    c = cfg(tmp_path)
    load_capture(sample_pcap, c)
    assert not load_capture(sample_pcap, c, use_cache=False).result.cached


def test_cli_cache_flags(sample_pcap, tmp_path, capsys, monkeypatch):
    from trace_zero.cli import main

    monkeypatch.setenv("TRACE_ZERO_HOME", str(tmp_path / "home"))
    args = [str(sample_pcap), "--headless", "--db", str(tmp_path / "d.db")]
    assert main(args) == 0 and "(from cache)" not in capsys.readouterr().out
    assert main(args) == 0 and "(from cache)" in capsys.readouterr().out
    assert main(args + ["--no-cache"]) == 0 and "(from cache)" not in capsys.readouterr().out
    assert main(["--clear-cache"]) == 0 and "removed" in capsys.readouterr().out
    assert main(args) == 0 and "(from cache)" not in capsys.readouterr().out
