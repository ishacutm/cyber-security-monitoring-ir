"""Request-scoped SQLite connection; callers own atomic transactions."""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import current_app, g


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"], timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    path = Path(current_app.config["DATABASE"])
    path.parent.mkdir(parents=True, exist_ok=True)
    get_db().executescript(Path(__file__).with_name("schema.sql").read_text())


def audit(db, action, entity_type, entity_id, description, at=None):
    db.execute(
        "INSERT INTO audit_logs(timestamp,action,entity_type,entity_id,description) VALUES(?,?,?,?,?)",
        (at or utcnow(), action, entity_type, entity_id, description),
    )
