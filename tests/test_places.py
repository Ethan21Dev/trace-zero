"""The file browser's starting folder and quick jumps."""

from __future__ import annotations

from pathlib import Path

from trace_zero.config import Config
from trace_zero.session import Session
from trace_zero.storage import Store
from trace_zero.ui.app import TraceZeroApp
from trace_zero.ui.places import initial_dir, places
from trace_zero.ui.screens.dialogs import OpenCaptureScreen
from trace_zero.ui.widgets.table import VirtualTable


def test_initial_dir_never_starts_in_a_folder_without_captures(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "Downloads").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    system32 = tmp_path / "Windows" / "System32"
    system32.mkdir(parents=True)
    (system32 / "kernel32.dll").write_bytes(b"")
    # launched from System32 (double-click / browser): go to Downloads
    assert initial_dir(None, cwd=system32) == home / "Downloads"
    # a working directory that holds captures is a good start
    work = tmp_path / "case"
    work.mkdir()
    (work / "a.pcapng").write_bytes(b"")
    assert initial_dir(None, cwd=work) == work
    # the folder used last wins, unless it no longer exists
    assert initial_dir(str(work), cwd=system32) == work
    assert initial_dir(str(tmp_path / "gone"), cwd=system32) == home / "Downloads"
    # no Downloads folder: home
    (home / "Downloads").rmdir()
    assert initial_dir(None, cwd=system32) == home


def test_places_lists_existing_folders_once(tmp_path, monkeypatch):
    home = tmp_path / "home"
    for name in ("Downloads", "Documents", "OneDrive/Desktop"):
        (home / name).mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    found = places(tmp_path / "missing-exports")
    labels = [label for label, _ in found]
    assert labels[:4] == ["Downloads", "Desktop", "Documents", "Home"]
    assert dict(found)["Desktop"] == home / "OneDrive" / "Desktop"
    assert "Exports" not in labels  # only folders that exist


async def test_start_screen_offers_live_and_browser_remembers_folder(tmp_path, sample_pcap):
    cfg = Config(db_path=tmp_path / "p.db", export_dir=tmp_path / "exports", cache_dir=tmp_path / "cache")
    store = Store(cfg.db_path)
    s = Session(cfg, store, store.open_or_create("places"))
    app = TraceZeroApp(s)
    async with app.run_test(size=(160, 48)) as pilot:
        main = app.main
        splash = str(main.query_one("#view-empty").render())
        assert "F  live" in splash and "o  open" in splash
        assert ("F", "live") in main.query_one("StatusBar").keys
        await pilot.press("o")
        browser = app.screen
        assert isinstance(browser, OpenCaptureScreen)
        assert browser.query_one("#places", VirtualTable).count >= 1
        tree_cls = type(browser.query_one("#tree"))
        assert all(ord(c) < 0x2600 for c in tree_cls.ICON_NODE + tree_cls.ICON_NODE_EXPANDED + tree_cls.ICON_FILE)  # no emoji
        # typing a folder browses it; backspace in the tree goes up a level
        browser.query_one("#path").value = str(sample_pcap.parent)
        await pilot.press("enter")
        tree = browser.query_one("#tree")
        assert Path(tree.path) == sample_pcap.parent
        tree.focus()
        await pilot.press("backspace")
        assert Path(tree.path) == sample_pcap.parent.parent
        browser.query_one("#path").value = str(sample_pcap)
        browser.query_one("#path").focus()
        await pilot.press("enter")
        for _ in range(100):
            if s.capture is not None:
                break
            await pilot.pause(0.05)
        await app.workers.wait_for_complete()
        assert s.capture is not None
        assert store.get_pref("last_folder") == str(sample_pcap.parent)
        await pilot.press("o")
        assert Path(app.screen.query_one("#tree").path) == sample_pcap.parent
    store.close()
