from datetime import datetime, timedelta

from database.db import audit, utcnow
from flask import current_app

from detection.rules import BY_EVENT


def evaluate_event(db, event_id: int, detected_at=None):
    event = db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
    if event is None:
        raise ValueError("Unknown event.")
    rule = BY_EVENT.get(event["event_type"])
    if not rule or rule["id"] == "RULE-008":
        return None
    existing = db.execute(
        "SELECT id FROM alerts WHERE event_id=? AND rule_id=?", (event_id, rule["id"])
    ).fetchone()
    if existing:
        return existing["id"]
    if rule["id"] == "RULE-001":
        window = current_app.config["DETECTION_WINDOW_SECONDS"]
        lower = (
            datetime.fromisoformat(event["timestamp"]) - timedelta(seconds=window)
        ).isoformat(timespec="microseconds")
        pair = (event["source_ip"], event["username"], lower, event["timestamp"])
        count = db.execute(
            "SELECT COUNT(*) FROM events WHERE event_type='failed_login' AND source_ip=? AND username=? AND timestamp>=? AND timestamp<=?",
            pair,
        ).fetchone()[0]
        if count < current_app.config["FAILED_LOGIN_THRESHOLD"]:
            return None
        # Correlate using event time, not wall time (also works on historical demos).
        duplicate = db.execute(
            "SELECT a.id FROM alerts a JOIN events e ON e.id=a.event_id WHERE a.rule_id='RULE-001' AND a.source_ip=? AND a.username=? AND e.timestamp>=? AND e.timestamp<=?",
            pair,
        ).fetchone()
        if duplicate:
            return None
    timestamp = detected_at or utcnow()
    cur = db.execute(
        "INSERT INTO alerts(timestamp,rule_name,event_id,severity,status,hostname,username,source_ip,title,description,rule_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (
            timestamp,
            rule["name"],
            event_id,
            rule["severity"],
            "OPEN",
            event["hostname"],
            event["username"],
            event["source_ip"],
            rule["title"],
            "SIMULATED: " + rule["description"],
            rule["id"],
        ),
    )
    audit(
        db, "DETECTED", "alert", cur.lastrowid, "SIMULATED: " + rule["title"], timestamp
    )
    return cur.lastrowid
