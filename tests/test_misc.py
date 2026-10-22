"""Sanitisation, configuration, CLI and map geometry."""

from __future__ import annotations

import json

import pytest

from trace_zero.cli import main
from trace_zero.config import ConfigError, load_config
from trace_zero.sanitize import clean, hexdump
from trace_zero.ui.mapgeo import MapEdge, MapNode, layout, render_map


# -- sanitise ---------------------------------------------------------------------
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("plain.example.com", "plain.example.com"),
        ("bell\x07", "bell\\x07"),
        ("\x1b]0;pwned\x07title", "\\x1b]0;pwned\\x07title"),
        ("csi\x9b31m", "csi\\x9b31m"),
        ("rtl‮evil", "rtl\\u202eevil"),
        (b"\xff\xfe-bytes", "\\xff\\xfe-bytes"),
        (None, ""),
    ],
)
def test_clean(raw, expected):
    assert clean(raw) == expected


def test_clean_truncates():
    assert len(clean("x" * 1000, 50)) == 50


def test_hexdump():
    lines = hexdump(bytes(range(20)))
    assert lines[0].startswith("000000  00 01 02")
    assert lines[1].startswith("000010  10 11 12 13")
    assert all(ch.isprintable() for line in lines for ch in line)


# -- config -----------------------------------------------------------------------
def test_config_defaults_when_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    cfg = load_config()
    assert cfg.limits.max_packets > 0


def test_config_file(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('[limits]\nmax_packets = 10\n[anomaly]\nspike_z = 3\n[paths]\ndb = "~/x.db"\n')
    cfg = load_config(p)
    assert cfg.limits.max_packets == 10 and cfg.anomaly.spike_z == 3.0
    assert cfg.db_path.name == "x.db"


@pytest.mark.parametrize(
    "body",
    ["[limits]\nmax_packets = -1\n", "[limits]\nnope = 1\n", "[weird]\n", "[limits]\nmax_packets = 'many'\n", "not toml ["],
)
def test_config_errors(tmp_path, body):
    p = tmp_path / "c.toml"
    p.write_text(body)
    with pytest.raises(ConfigError):
        load_config(p)


def test_example_config_is_valid():
    from pathlib import Path

    example = Path(__file__).resolve().parents[1] / "config.example.toml"
    assert load_config(example).limits.max_file_mb > 0


# -- cli ------------------------------------------------------------------------------
def test_cli_headless(sample_pcap, tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("TRACE_ZERO_HOME", str(tmp_path / "home"))
    out_json = tmp_path / "r.json"
    rc = main([str(sample_pcap), "--headless", "--db", str(tmp_path / "db.sqlite"), "--json", str(out_json), "--html", str(tmp_path / "r.html")])
    assert rc == 0
    text = capsys.readouterr().out
    assert "possible anomalies" in text and "TZ-R1" in text
    assert json.loads(out_json.read_text())["capture"]["packets"] > 0


def test_cli_headless_bad_file(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("TRACE_ZERO_HOME", str(tmp_path / "home"))
    bad = tmp_path / "bad.pcap"
    bad.write_text("nope")
    assert main([str(bad), "--headless", "--db", str(tmp_path / "db.sqlite")]) == 1
    assert "not a PCAP" in capsys.readouterr().err


def test_cli_generate_sample(tmp_path):
    out = tmp_path / "s.pcapng"
    assert main(["--generate-sample", str(out), "--format", "pcapng"]) == 0
    assert out.read_bytes()[:4] == b"\x0a\x0d\x0d\x0a"


# -- map geometry ------------------------------------------------------------------
def test_layout_is_deterministic_and_collision_free():
    ips = [f"10.0.0.{i}" for i in range(1, 25)]
    a = layout(ips, 80, 24, 15)
    b = layout(list(reversed(ips)), 80, 24, 15)
    assert a == b
    assert len(set(a.values())) == len(ips)
    assert all(0 <= x < 80 and 0 <= y < 24 for x, y in a.values())


def test_render_map_labels_and_arrows():
    nodes = [MapNode("10.0.0.1", "active", True), MapNode("10.0.0.2", "active"), MapNode("10.0.0.3", "dormant")]
    edges = [MapEdge("10.0.0.1", "10.0.0.2", True, False, True, True)]
    lines = render_map(70, 16, nodes, edges)
    text = "\n".join(line.plain for line in lines)
    assert len(lines) == 16 and all(line.cell_len <= 70 for line in lines)
    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        assert ip in text
    assert "◉" in text and "○" in text  # selected and dormant markers
    assert any(ch in text for ch in "▸◂▴▾")  # direction arrow


def test_render_map_tiny_canvas():
    lines = render_map(3, 2, [MapNode("10.0.0.1", "active")], [])
    assert len(lines) == 2


# -- docs ---------------------------------------------------------------------------
def test_keybinding_doc_matches_keymap():
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, str(root / "scripts" / "gen_keybindings.py"), "--check"], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_every_documented_key_is_bound():
    """Each key in the help/keymap has a real binding on the main screen or the tables."""
    from trace_zero.ui.screens.main import MainScreen
    from trace_zero.ui.widgets.table import VirtualTable

    bound = set()
    for b in list(MainScreen.BINDINGS) + list(VirtualTable.BINDINGS):
        bound.update(k.strip() for k in b.key.split(","))
    names = {
        "?": "question_mark", "/": "slash", "<": "less_than_sign", ">": "greater_than_sign",
        "+": "plus", "-": "minus", "[": "left_square_bracket", "]": "right_square_bracket",
        "pgup": "pageup", "pgdn": "pagedown", "left": "left", "right": "right",
    }
    expected = {
        "?", "q", "o", "/", "esc", "h", "n", "p", "f", "b", "t", "i", "space", "left", "right",
        "shift+left", "shift+right", "<", ">", "home", "end", "+", "-", "w", "[", "]", "m", "a",
        "x", "delete", "e", "r", "ctrl+n", "l", "s", "S", "up", "down", "pgup", "pgdn", "enter",
        "ctrl+home", "ctrl+end",
    }
    for key in expected:
        name = {"esc": "escape"}.get(key, names.get(key, key))
        assert name in bound, f"documented key {key!r} has no binding"


def test_example_config_documents_every_setting_with_its_default():
    import dataclasses
    import tomllib
    from pathlib import Path

    from trace_zero.config import AnomalyConfig, Limits

    data = tomllib.loads((Path(__file__).resolve().parents[1] / "config.example.toml").read_text(encoding="utf-8"))
    for section, cls in (("limits", Limits), ("anomaly", AnomalyConfig)):
        documented = data[section]
        for f in dataclasses.fields(cls):
            assert f.name in documented, f"[{section}] {f.name} missing from config.example.toml"
            assert documented[f.name] == getattr(cls(), f.name), f"[{section}] {f.name} differs from the default"
