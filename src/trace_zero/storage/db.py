"""SQLite persistence for investigations.

Stores analyst-side data only: investigation metadata, which captures were
examined (path + SHA-256, never the capture contents), bookmarks, analyst
notes and an activity journal. Capture files are never written to.

Analyst-written text (notes, bookmark labels) is interpretation and is kept
apart from observed packet facts throughout the application and exports.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = 2

BOOKMARK_KINDS = ('packet', 'host', 'finding', 'conversation', 'flow')
NOTE_KINDS = ('investigation',) + BOOKMARK_KINDS
FINDING_STATUSES = ('open', 'benign', 'escalated')

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS captures (
    id INTEGER PRIMARY KEY,
    investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    fmt TEXT NOT NULL,
    packet_count INTEGER NOT NULL,
    first_ts REAL,
    last_ts REAL,
    truncated INTEGER NOT NULL DEFAULT 0,
    imported_at REAL NOT NULL,
    UNIQUE (investigation_id, sha256)
);
CREATE TABLE IF NOT EXISTS bookmarks (
    id INTEGER PRIMARY KEY,
    investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    capture_sha256 TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('packet', 'host', 'finding', 'conversation', 'flow')),
    ref TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    UNIQUE (investigation_id, capture_sha256, kind, ref)
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    capture_sha256 TEXT NOT NULL DEFAULT '',
    target_kind TEXT NOT NULL CHECK (target_kind IN ('investigation', 'packet', 'host', 'finding', 'conversation', 'flow')),
    target_ref TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    at REAL NOT NULL,
    kind TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS marks (
    id INTEGER PRIMARY KEY,
    investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    capture_sha256 TEXT NOT NULL,
    ts REAL NOT NULL,
    label TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS finding_status (
    investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    capture_sha256 TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open', 'benign', 'escalated')),
    reason TEXT NOT NULL DEFAULT '',
    updated_at REAL NOT NULL,
    PRIMARY KEY (investigation_id, capture_sha256, finding_id)
);
CREATE TABLE IF NOT EXISTS suppressions (
    id INTEGER PRIMARY KEY,
    investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    rule TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL,
    created_at REAL NOT NULL,
    UNIQUE (investigation_id, rule, host)
);
CREATE TABLE IF NOT EXISTS saved_filters (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    expression TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS filter_history (
    id INTEGER PRIMARY KEY,
    expression TEXT NOT NULL UNIQUE,
    used_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_marks_inv ON marks(investigation_id, capture_sha256, ts);
CREATE INDEX IF NOT EXISTS ix_bookmarks_inv ON bookmarks(investigation_id, capture_sha256);
CREATE INDEX IF NOT EXISTS ix_notes_inv ON notes(investigation_id, capture_sha256);
CREATE INDEX IF NOT EXISTS ix_events_inv ON events(investigation_id, at);
"""

MAX_NAME = 80
MAX_NOTE = 8000


class StorageError(Exception):
    pass


@dataclass(frozen=True)
class Investigation:
    id: int
    name: str
    description: str
    created_at: float
    updated_at: float


@dataclass(frozen=True)
class Bookmark:
    id: int
    kind: str
    ref: str
    label: str
    created_at: float


@dataclass(frozen=True)
class Note:
    id: int
    target_kind: str
    target_ref: str
    body: str
    created_at: float
    updated_at: float


@dataclass(frozen=True)
class Mark:
    id: int
    ts: float
    label: str
    created_at: float


@dataclass(frozen=True)
class Suppression:
    id: int
    rule: str
    host: str
    reason: str
    created_at: float

    def matches(self, rule: str, hosts: tuple[str, ...]) -> bool:
        return self.rule == rule and (not self.host or self.host in hosts)


@dataclass(frozen=True)
class Event:
    id: int
    at: float
    kind: str
    message: str


def _clean_name(name: str) -> str:
    name = " ".join(name.split())
    if not name:
        raise StorageError("name must not be empty")
    if len(name) > MAX_NAME:
        raise StorageError(f"name is longer than {MAX_NAME} characters")
    if any(ord(c) < 32 for c in name):
        raise StorageError("name contains control characters")
    return name


class Store:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path) if str(path) != ":memory:" else None
        try:
            if self.path is not None:
                self.path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(str(path) if self.path is None else str(self.path))
        except (OSError, sqlite3.Error) as exc:
            raise StorageError(f"cannot open investigation database {path}: {exc}") from exc
        self.conn.row_factory = sqlite3.Row
        try:
            self.conn.execute("PRAGMA foreign_keys = ON")
            self.conn.execute("PRAGMA journal_mode = WAL" if self.path else "PRAGMA journal_mode = MEMORY")
            self.conn.executescript(SCHEMA)
            row = self.conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            if row is None:
                self.conn.execute("INSERT INTO meta VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
            elif int(row["value"]) > SCHEMA_VERSION:
                raise StorageError("database was created by a newer TRACE//ZERO version")
            elif int(row["value"]) < 2:
                self._migrate_to_v2()
            self.conn.commit()
        except sqlite3.DatabaseError as exc:
            raise StorageError(f"investigation database is unusable ({exc}); move it aside to start fresh") from exc

    def _migrate_to_v2(self) -> None:
        """v1 -> v2: widen the kind CHECK constraints (adds 'flow'). Data is copied unchanged."""
        block = SCHEMA[SCHEMA.index("CREATE TABLE IF NOT EXISTS bookmarks") : SCHEMA.index("CREATE TABLE IF NOT EXISTS events")]
        self.conn.commit()
        self.conn.execute("PRAGMA foreign_keys = OFF")
        try:
            self.conn.executescript(
                "BEGIN;"
                "ALTER TABLE bookmarks RENAME TO bookmarks_v1;"
                "ALTER TABLE notes RENAME TO notes_v1;"
                + block
                + "INSERT INTO bookmarks SELECT * FROM bookmarks_v1;"
                "INSERT INTO notes SELECT * FROM notes_v1;"
                "DROP TABLE bookmarks_v1; DROP TABLE notes_v1;"
                "CREATE INDEX IF NOT EXISTS ix_bookmarks_inv ON bookmarks(investigation_id, capture_sha256);"
                "CREATE INDEX IF NOT EXISTS ix_notes_inv ON notes(investigation_id, capture_sha256);"
                "UPDATE meta SET value='2' WHERE key='schema_version';"
                "COMMIT;"
            )
        except sqlite3.Error:
            self.conn.rollback()
            raise
        finally:
            self.conn.execute("PRAGMA foreign_keys = ON")

    def close(self) -> None:
        self.conn.close()

    def _exec(self, sql: str, args: tuple = ()) -> sqlite3.Cursor:
        try:
            cur = self.conn.execute(sql, args)
            self.conn.commit()
            return cur
        except sqlite3.IntegrityError as exc:
            self.conn.rollback()
            raise StorageError(str(exc)) from exc
        except sqlite3.Error as exc:
            self.conn.rollback()
            raise StorageError(f"database error: {exc}") from exc

    # -- investigations ------------------------------------------------------
    def create_investigation(self, name: str, description: str = "") -> Investigation:
        name = _clean_name(name)
        now = time.time()
        if self.conn.execute("SELECT 1 FROM investigations WHERE name=?", (name,)).fetchone():
            raise StorageError(f"an investigation named '{name}' already exists")
        cur = self._exec(
            "INSERT INTO investigations (name, description, created_at, updated_at) VALUES (?,?,?,?)",
            (name, description, now, now),
        )
        inv = self.get_investigation(cur.lastrowid)
        self.log(inv.id, "investigation", f"investigation created: {name}")
        return inv

    def get_investigation(self, inv_id: int) -> Investigation:
        row = self.conn.execute("SELECT * FROM investigations WHERE id=?", (inv_id,)).fetchone()
        if row is None:
            raise StorageError(f"investigation {inv_id} not found")
        return Investigation(row["id"], row["name"], row["description"], row["created_at"], row["updated_at"])

    def find_investigation(self, name: str) -> Investigation | None:
        row = self.conn.execute("SELECT id FROM investigations WHERE name=?", (" ".join(name.split()),)).fetchone()
        return self.get_investigation(row["id"]) if row else None

    def list_investigations(self) -> list[Investigation]:
        rows = self.conn.execute("SELECT * FROM investigations ORDER BY updated_at DESC, id DESC").fetchall()
        return [Investigation(r["id"], r["name"], r["description"], r["created_at"], r["updated_at"]) for r in rows]

    def rename_investigation(self, inv_id: int, name: str) -> Investigation:
        name = _clean_name(name)
        old = self.get_investigation(inv_id)
        if name == old.name:
            return old
        if self.conn.execute("SELECT 1 FROM investigations WHERE name=? AND id<>?", (name, inv_id)).fetchone():
            raise StorageError(f"an investigation named '{name}' already exists")
        self._exec("UPDATE investigations SET name=?, updated_at=? WHERE id=?", (name, time.time(), inv_id))
        self.log(inv_id, "investigation", f"renamed from '{old.name}' to '{name}'")
        return self.get_investigation(inv_id)

    def touch(self, inv_id: int) -> None:
        self._exec("UPDATE investigations SET updated_at=? WHERE id=?", (time.time(), inv_id))

    def open_or_create(self, name: str | None) -> Investigation:
        if name:
            return self.find_investigation(name) or self.create_investigation(name)
        existing = self.list_investigations()
        if existing:
            return existing[0]
        return self.create_investigation(time.strftime("INV-%Y%m%d-%H%M%S", time.gmtime()))

    # -- captures --------------------------------------------------------------
    def record_capture(self, inv_id: int, info, packet_count: int, first_ts, last_ts, truncated: bool) -> None:
        self._exec(
            """INSERT INTO captures (investigation_id, path, filename, sha256, size, fmt, packet_count,
                                     first_ts, last_ts, truncated, imported_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT (investigation_id, sha256) DO UPDATE SET
                 path=excluded.path, filename=excluded.filename, imported_at=excluded.imported_at""",
            (inv_id, info.path, info.name, info.sha256, info.size, info.fmt, packet_count, first_ts, last_ts, int(truncated), time.time()),
        )
        self.touch(inv_id)

    def captures(self, inv_id: int) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM captures WHERE investigation_id=? ORDER BY imported_at DESC", (inv_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    # -- bookmarks ---------------------------------------------------------------
    def toggle_bookmark(self, inv_id: int, sha: str, kind: str, ref: str, label: str = "") -> bool:
        """Returns True if a bookmark now exists, False if it was removed."""
        row = self.conn.execute(
            "SELECT id FROM bookmarks WHERE investigation_id=? AND capture_sha256=? AND kind=? AND ref=?",
            (inv_id, sha, kind, ref),
        ).fetchone()
        if row:
            self._exec("DELETE FROM bookmarks WHERE id=?", (row["id"],))
            self.log(inv_id, "bookmark", f"bookmark removed: {kind} {ref}")
            return False
        self._exec(
            "INSERT INTO bookmarks (investigation_id, capture_sha256, kind, ref, label, created_at) VALUES (?,?,?,?,?,?)",
            (inv_id, sha, kind, ref, label[:200], time.time()),
        )
        self.log(inv_id, "bookmark", f"bookmarked {kind} {ref}")
        self.touch(inv_id)
        return True

    def bookmarks(self, inv_id: int, sha: str) -> list[Bookmark]:
        rows = self.conn.execute(
            "SELECT * FROM bookmarks WHERE investigation_id=? AND capture_sha256=? ORDER BY created_at, id",
            (inv_id, sha),
        ).fetchall()
        return [Bookmark(r["id"], r["kind"], r["ref"], r["label"], r["created_at"]) for r in rows]

    def is_bookmarked(self, inv_id: int, sha: str, kind: str, ref: str) -> bool:
        return (
            self.conn.execute(
                "SELECT 1 FROM bookmarks WHERE investigation_id=? AND capture_sha256=? AND kind=? AND ref=?",
                (inv_id, sha, kind, ref),
            ).fetchone()
            is not None
        )

    def delete_bookmark(self, inv_id: int, bookmark_id: int) -> None:
        self._exec("DELETE FROM bookmarks WHERE id=? AND investigation_id=?", (bookmark_id, inv_id))
        self.log(inv_id, "bookmark", f"bookmark {bookmark_id} deleted")

    # -- notes -----------------------------------------------------------------
    def add_note(self, inv_id: int, sha: str, target_kind: str, target_ref: str, body: str) -> Note:
        body = body.strip()
        if not body:
            raise StorageError("note is empty")
        if len(body) > MAX_NOTE:
            raise StorageError(f"note is longer than {MAX_NOTE} characters")
        now = time.time()
        cur = self._exec(
            """INSERT INTO notes (investigation_id, capture_sha256, target_kind, target_ref, body, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?)""",
            (inv_id, sha, target_kind, target_ref, body, now, now),
        )
        self.log(inv_id, "note", f"note added to {target_kind} {target_ref}".rstrip())
        self.touch(inv_id)
        return Note(cur.lastrowid, target_kind, target_ref, body, now, now)

    def notes(self, inv_id: int, sha: str | None = None, target_kind: str | None = None, target_ref: str | None = None) -> list[Note]:
        sql = "SELECT * FROM notes WHERE investigation_id=?"
        args: list = [inv_id]
        if sha is not None:
            sql += " AND (capture_sha256=? OR target_kind='investigation')"
            args.append(sha)
        if target_kind is not None:
            sql += " AND target_kind=?"
            args.append(target_kind)
        if target_ref is not None:
            sql += " AND target_ref=?"
            args.append(target_ref)
        rows = self.conn.execute(sql + " ORDER BY created_at, id", tuple(args)).fetchall()
        return [Note(r["id"], r["target_kind"], r["target_ref"], r["body"], r["created_at"], r["updated_at"]) for r in rows]

    def delete_note(self, inv_id: int, note_id: int) -> None:
        self._exec("DELETE FROM notes WHERE id=? AND investigation_id=?", (note_id, inv_id))
        self.log(inv_id, "note", f"note {note_id} deleted")

    # -- journal -----------------------------------------------------------------
    def log(self, inv_id: int, kind: str, message: str) -> None:
        self._exec("INSERT INTO events (investigation_id, at, kind, message) VALUES (?,?,?,?)", (inv_id, time.time(), kind, message[:500]))

    def events(self, inv_id: int, limit: int = 500) -> list[Event]:
        rows = self.conn.execute(
            "SELECT * FROM events WHERE investigation_id=? ORDER BY at DESC, id DESC LIMIT ?", (inv_id, limit)
        ).fetchall()
        return [Event(r["id"], r["at"], r["kind"], r["message"]) for r in reversed(rows)]

    # -- timeline marks ------------------------------------------------------------
    def add_mark(self, inv_id: int, sha: str, ts: float, label: str) -> int:
        label = " ".join(label.split())[:120]
        if not label:
            raise StorageError("mark label is empty")
        cur = self._exec(
            "INSERT INTO marks (investigation_id, capture_sha256, ts, label, created_at) VALUES (?,?,?,?,?)",
            (inv_id, sha, ts, label, time.time()),
        )
        self.log(inv_id, "mark", f"timeline mark '{label}' at {ts:.6f}")
        self.touch(inv_id)
        return int(cur.lastrowid)

    def marks(self, inv_id: int, sha: str) -> list[Mark]:
        rows = self.conn.execute(
            "SELECT * FROM marks WHERE investigation_id=? AND capture_sha256=? ORDER BY ts, id", (inv_id, sha)
        ).fetchall()
        return [Mark(r["id"], r["ts"], r["label"], r["created_at"]) for r in rows]

    def delete_mark(self, inv_id: int, mark_id: int) -> None:
        self._exec("DELETE FROM marks WHERE id=? AND investigation_id=?", (mark_id, inv_id))
        self.log(inv_id, "mark", f"timeline mark {mark_id} deleted")

    # -- finding triage --------------------------------------------------------------
    def set_finding_status(self, inv_id: int, sha: str, finding_id: str, status: str, reason: str = "") -> None:
        if status not in FINDING_STATUSES:
            raise StorageError(f"unknown status {status!r}")
        self._exec(
            """INSERT INTO finding_status (investigation_id, capture_sha256, finding_id, status, reason, updated_at)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT (investigation_id, capture_sha256, finding_id)
               DO UPDATE SET status=excluded.status, reason=excluded.reason, updated_at=excluded.updated_at""",
            (inv_id, sha, finding_id, status, reason.strip()[:500], time.time()),
        )
        self.log(inv_id, "triage", f"finding {finding_id} marked {status}" + (f": {reason.strip()[:200]}" if reason.strip() else ""))
        self.touch(inv_id)

    def finding_statuses(self, inv_id: int, sha: str) -> dict[str, tuple[str, str]]:
        rows = self.conn.execute(
            "SELECT finding_id, status, reason FROM finding_status WHERE investigation_id=? AND capture_sha256=?", (inv_id, sha)
        ).fetchall()
        return {r["finding_id"]: (r["status"], r["reason"]) for r in rows}

    # -- suppression rules ---------------------------------------------------------------
    def add_suppression(self, inv_id: int, rule: str, host: str, reason: str) -> int:
        reason = reason.strip()
        if not reason:
            raise StorageError("a suppression needs a reason")
        cur = self._exec(
            """INSERT INTO suppressions (investigation_id, rule, host, reason, created_at) VALUES (?,?,?,?,?)
               ON CONFLICT (investigation_id, rule, host) DO UPDATE SET reason=excluded.reason""",
            (inv_id, rule, host, reason[:500], time.time()),
        )
        self.log(inv_id, "triage", f"suppression added: {rule} {host or '(any host)'}: {reason[:200]}")
        self.touch(inv_id)
        return int(cur.lastrowid)

    def suppressions(self, inv_id: int) -> list[Suppression]:
        rows = self.conn.execute("SELECT * FROM suppressions WHERE investigation_id=? ORDER BY id", (inv_id,)).fetchall()
        return [Suppression(r["id"], r["rule"], r["host"], r["reason"], r["created_at"]) for r in rows]

    def delete_suppression(self, inv_id: int, sup_id: int) -> None:
        self._exec("DELETE FROM suppressions WHERE id=? AND investigation_id=?", (sup_id, inv_id))
        self.log(inv_id, "triage", f"suppression {sup_id} removed")

    # -- filters (global, not tied to an investigation) -----------------------------------------
    def record_filter(self, expression: str, keep: int = 50) -> None:
        expression = expression.strip()
        if not expression:
            return
        self._exec(
            "INSERT INTO filter_history (expression, used_at) VALUES (?,?) ON CONFLICT (expression) DO UPDATE SET used_at=excluded.used_at",
            (expression[:1000], time.time()),
        )
        self._exec("DELETE FROM filter_history WHERE id NOT IN (SELECT id FROM filter_history ORDER BY used_at DESC LIMIT ?)", (keep,))

    def filter_history(self, limit: int = 50) -> list[str]:
        rows = self.conn.execute("SELECT expression FROM filter_history ORDER BY used_at DESC, id DESC LIMIT ?", (limit,)).fetchall()
        return [r["expression"] for r in rows]

    def save_filter(self, name: str, expression: str) -> None:
        name = _clean_name(name)
        if not expression.strip():
            raise StorageError("cannot save an empty filter")
        self._exec(
            "INSERT INTO saved_filters (name, expression, created_at) VALUES (?,?,?) ON CONFLICT (name) DO UPDATE SET expression=excluded.expression",
            (name, expression.strip()[:1000], time.time()),
        )

    def saved_filters(self) -> list[tuple[str, str]]:
        rows = self.conn.execute("SELECT name, expression FROM saved_filters ORDER BY name").fetchall()
        return [(r["name"], r["expression"]) for r in rows]

    def delete_saved_filter(self, name: str) -> None:
        self._exec("DELETE FROM saved_filters WHERE name=?", (name,))

    # -- chain of custody --------------------------------------------------------------------------
    def prior_hashes(self, path: str) -> list[tuple[str, float, str]]:
        """Every (sha256, imported_at, investigation name) previously recorded for this path."""
        rows = self.conn.execute(
            """SELECT c.sha256, c.imported_at, i.name FROM captures c JOIN investigations i ON i.id = c.investigation_id
               WHERE c.path=? ORDER BY c.imported_at""",
            (path,),
        ).fetchall()
        return [(r["sha256"], r["imported_at"], r["name"]) for r in rows]
