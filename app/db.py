"""
app/db.py
=========

SQLite connection handling, schema creation and the in-place migrations that keep
an older `demo.db` working.

Deliberately free of any Flask decorator: `close_db` is registered by the package
factory with `app.teardown_appcontext(close_db)` rather than decorated here, so
this module imports nothing from the package and can never take part in an import
cycle.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from flask import g
from werkzeug.security import generate_password_hash

from app.config import ADMIN_PASSWORD, ADMIN_USERNAME, DB_PATH, PHRASE, SCHEMA_PATH


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_iso(text: str) -> datetime:
    """Read a stored timestamp back as an aware UTC datetime.

    Everything this app writes goes through `now_iso()` and is therefore
    timezone-aware, but a database carried over from an earlier build can hold
    naive strings. Subtracting a naive datetime from an aware one raises
    TypeError, which would surface as a 500 from the lock check rather than
    anywhere near the row that caused it -- so assume UTC when the offset is
    missing.
    """
    stamp = datetime.fromisoformat(text)
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        ensure_db()
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    """Registered as the teardown_appcontext handler by app/__init__.py."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _ensure_column(con, table: str, column: str, decl: str) -> None:
    """Add a column to an existing table if a pre-migration demo.db lacks it."""
    cols = [r[1] for r in con.execute(f"PRAGMA table_info({table})")]
    if column not in cols:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


_schema_ready = False


def ensure_db() -> None:
    """Create the schema on first use if nothing has done so yet.

    `python app.py` calls `init_db()` explicitly, but `flask run`, gunicorn and
    any other WSGI entry point never execute the `__main__` block -- those
    deployments used to serve their first request against a database with no
    tables. Doing it here means the first query always finds a schema, whatever
    started the process.
    """
    if not _schema_ready:
        init_db()


def init_db() -> None:
    global _schema_ready
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA_PATH.read_text())
    # Databases created before the phrase / admin-rhythm features miss the two
    # nullable columns; add them in place so existing demo data keeps working.
    _ensure_column(con, "users", "password_hash", "TEXT")
    _ensure_column(con, "admins", "profile_json", "TEXT")
    _ensure_column(con, "attempts", "outcome", "TEXT")
    # Every pre-migration user enrolled with the default phrase, so their
    # knowledge factor is known and can be backfilled.
    con.execute(
        "UPDATE users SET password_hash = ? WHERE password_hash IS NULL",
        (generate_password_hash(PHRASE),),
    )
    # Rows logged before `outcome` existed predate the retry allowance, so every
    # one of their non-accepts really was a strike. Writing that in means the
    # streak logic never has to special-case a NULL.
    con.execute(
        "UPDATE attempts SET outcome = CASE WHEN accepted = 1 THEN 'accept' ELSE 'reject' END "
        "WHERE outcome IS NULL"
    )
    if con.execute("SELECT 1 FROM admins WHERE username = ?", (ADMIN_USERNAME,)).fetchone() is None:
        con.execute(
            "INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
            (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD), now_iso()),
        )
    # Expired session rows are dead weight -- nothing ever deleted them, so both
    # tables grew without bound across restarts.
    purge_expired_sessions(con)
    con.commit()
    con.close()
    _schema_ready = True


def purge_expired_sessions(con) -> None:
    """Drop session rows that can no longer authenticate anyone. Caller commits."""
    stamp = now_iso()
    con.execute("DELETE FROM sessions WHERE expires_at < ?", (stamp,))
    con.execute("DELETE FROM user_sessions WHERE expires_at < ?", (stamp,))
