from __future__ import annotations

import pytest

from trace_zero.storage import StorageError, Store


def test_create_rename_and_list(store):
    inv = store.create_investigation("Case 7")
    assert store.find_investigation("Case 7").id == inv.id
    renamed = store.rename_investigation(inv.id, "  Case   7b ")
    assert renamed.name == "Case 7b"
    assert [i.name for i in store.list_investigations()] == ["Case 7b"]
    kinds = [e.kind for e in store.events(inv.id)]
    assert kinds.count("investigation") == 2


@pytest.mark.parametrize("bad", ["", "   ", "x" * 81, "bell\x07name"])
def test_invalid_names(store, bad):
    with pytest.raises(StorageError):
        store.create_investigation(bad)


def test_duplicate_names(store):
    store.create_investigation("A")
    b = store.create_investigation("B")
    with pytest.raises(StorageError):
        store.create_investigation("A")
    with pytest.raises(StorageError):
        store.rename_investigation(b.id, "A")


def test_open_or_create(store):
    first = store.open_or_create(None)
    assert first.name.startswith("INV-")
    assert store.open_or_create(None).id == first.id
    named = store.open_or_create("Named")
    assert store.open_or_create("Named").id == named.id


def test_bookmarks_toggle_and_scope(store):
    a = store.create_investigation("A")
    b = store.create_investigation("B")
    assert store.toggle_bookmark(a.id, "sha1", "packet", "42", "label") is True
    assert store.is_bookmarked(a.id, "sha1", "packet", "42")
    assert not store.is_bookmarked(b.id, "sha1", "packet", "42")
    assert not store.is_bookmarked(a.id, "sha2", "packet", "42")
    assert store.toggle_bookmark(a.id, "sha1", "packet", "42") is False
    assert store.bookmarks(a.id, "sha1") == []
    store.toggle_bookmark(a.id, "sha1", "host", "10.0.0.1")
    bm = store.bookmarks(a.id, "sha1")[0]
    store.delete_bookmark(a.id, bm.id)
    assert store.bookmarks(a.id, "sha1") == []


def test_invalid_bookmark_kind(store):
    inv = store.create_investigation("A")
    with pytest.raises(StorageError):
        store.toggle_bookmark(inv.id, "sha", "evil", "1")


def test_notes(store):
    inv = store.create_investigation("A")
    store.add_note(inv.id, "sha1", "finding", "TZ-R1-abc", "looks like a misconfigured RDP client")
    store.add_note(inv.id, "", "investigation", "", "case opened after helpdesk ticket")
    store.add_note(inv.id, "sha2", "host", "10.0.0.9", "other capture")
    notes = store.notes(inv.id, "sha1")
    assert {n.target_kind for n in notes} == {"finding", "investigation"}
    assert len(store.notes(inv.id, "sha1", "finding", "TZ-R1-abc")) == 1
    with pytest.raises(StorageError):
        store.add_note(inv.id, "sha1", "finding", "x", "   ")
    with pytest.raises(StorageError):
        store.add_note(inv.id, "sha1", "finding", "x", "y" * 9000)
    store.delete_note(inv.id, notes[0].id)
    assert len(store.notes(inv.id, "sha1")) == 1


def test_persistence_across_connections(config):
    s1 = Store(config.db_path)
    inv = s1.create_investigation("Persist")
    s1.toggle_bookmark(inv.id, "sha", "packet", "1")
    s1.close()
    s2 = Store(config.db_path)
    assert s2.find_investigation("Persist") is not None
    assert len(s2.bookmarks(inv.id, "sha")) == 1
    s2.close()


def test_corrupt_database_reports_cleanly(tmp_path):
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"this is not sqlite" * 100)
    with pytest.raises(StorageError):
        Store(bad)


def test_sql_injection_is_inert(store):
    name = "x'); DROP TABLE investigations; --"
    inv = store.create_investigation(name)
    assert store.get_investigation(inv.id).name == name
    tables = {r[0] for r in store.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "investigations" in tables
    assert len(store.list_investigations()) == 1


V1_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO meta VALUES ('schema_version', '1');
CREATE TABLE investigations (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL, updated_at REAL NOT NULL);
CREATE TABLE bookmarks (id INTEGER PRIMARY KEY, investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    capture_sha256 TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('packet', 'host', 'finding', 'conversation')),
    ref TEXT NOT NULL, label TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, UNIQUE (investigation_id, capture_sha256, kind, ref));
CREATE TABLE notes (id INTEGER PRIMARY KEY, investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    capture_sha256 TEXT NOT NULL DEFAULT '', target_kind TEXT NOT NULL CHECK (target_kind IN ('investigation', 'packet', 'host', 'finding', 'conversation')),
    target_ref TEXT NOT NULL DEFAULT '', body TEXT NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL);
INSERT INTO investigations VALUES (1, 'Old case', '', 1, 1);
INSERT INTO bookmarks VALUES (1, 1, 'sha', 'packet', '42', 'old label', 1);
INSERT INTO notes VALUES (1, 1, 'sha', 'host', '10.0.0.1', 'old note', 1, 1);
"""


def test_v1_database_migrates_in_place(tmp_path):
    import sqlite3

    path = tmp_path / "v1.db"
    conn = sqlite3.connect(path)
    conn.executescript(V1_SCHEMA)
    conn.close()
    store = Store(path)
    inv = store.find_investigation("Old case")
    assert [b.ref for b in store.bookmarks(inv.id, "sha")] == ["42"]
    assert [n.body for n in store.notes(inv.id, "sha")] == ["old note"]
    assert store.toggle_bookmark(inv.id, "sha", "flow", "TCP|a|1|b|2|7") is True  # new kind accepted
    assert store.conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0] == "2"
    store.close()
    Store(path).close()  # reopening a migrated database is a no-op


def test_marks_triage_suppressions_filters(store):
    inv = store.create_investigation("T")
    m = store.add_mark(inv.id, "sha", 12.5, "  lateral   movement starts ")
    assert [(x.ts, x.label) for x in store.marks(inv.id, "sha")] == [(12.5, "lateral movement starts")]
    store.delete_mark(inv.id, m)
    assert store.marks(inv.id, "sha") == []
    store.set_finding_status(inv.id, "sha", "TZ-R1-x", "benign", "known backup job")
    store.set_finding_status(inv.id, "sha", "TZ-R1-x", "escalated", "")
    assert store.finding_statuses(inv.id, "sha") == {"TZ-R1-x": ("escalated", "")}
    with pytest.raises(StorageError):
        store.set_finding_status(inv.id, "sha", "TZ-R1-x", "ignored")
    with pytest.raises(StorageError):
        store.add_suppression(inv.id, "TZ-R5", "", "  ")
    store.add_suppression(inv.id, "TZ-R5", "10.0.0.5", "monitoring agent")
    sup = store.suppressions(inv.id)[0]
    assert sup.matches("TZ-R5", ("10.0.0.5", "10.0.0.9")) and not sup.matches("TZ-R5", ("10.0.0.6",)) and not sup.matches("TZ-R1", ("10.0.0.5",))
    for i in range(60):
        store.record_filter(f"port:{i}")
    store.record_filter("port:3")
    hist = store.filter_history()
    assert len(hist) == 50 and hist[0] == "port:3"
    store.save_filter("web", "port:80|443")
    store.save_filter("web", "port:443")
    assert store.saved_filters() == [("web", "port:443")]
    store.delete_saved_filter("web")
    assert store.saved_filters() == []
