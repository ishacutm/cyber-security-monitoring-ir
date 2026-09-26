import json
from datetime import datetime, timedelta, timezone

from database.db import audit, utcnow
from detection.engine import evaluate_event
from flask import current_app

from simulator.scenarios import SCENARIOS


def generate(
    db,
    scenario: str,
    at=None,
    source_ip="192.0.2.10",
    username="test_user",
    hostname="LAB-WINDOWS-01",
) -> dict:
    if scenario not in SCENARIOS:
        raise ValueError("Unknown simulation scenario.")
    event_type = "failed_login" if scenario == "brute_force" else scenario
    _, description, severity = SCENARIOS[event_type]
    count = (
        current_app.config["FAILED_LOGIN_THRESHOLD"] if scenario == "brute_force" else 1
    )
    timestamp = at or utcnow()
    event_ids, alert_ids = [], []
    for _ in range(count):
        raw = dict(
            simulated=True,
            timestamp=timestamp,
            event_type=event_type,
            username=username,
            source_ip=source_ip,
            hostname=hostname,
            description=description,
            severity=severity,
        )
        cur = db.execute(
            "INSERT INTO events(timestamp,event_type,username,source_ip,hostname,description,severity,raw_event) VALUES(?,?,?,?,?,?,?,?)",
            (
                timestamp,
                event_type,
                username,
                source_ip,
                hostname,
                "SIMULATED: " + description,
                severity,
                json.dumps(raw),
            ),
        )
        event_ids.append(cur.lastrowid)
        detection_time = (
            (datetime.fromisoformat(timestamp) + timedelta(seconds=2)).isoformat(
                timespec="microseconds"
            )
            if at
            else None
        )
        alert_id = evaluate_event(db, cur.lastrowid, detection_time)
        if alert_id:
            alert_ids.append(alert_id)
    audit(
        db,
        "SIMULATED",
        "event",
        event_ids[-1],
        f"SIMULATED scenario {scenario}: {count} events",
        timestamp,
    )
    return {"events": event_ids, "alerts": alert_ids}


def seed_demo(db):
    """Seed only an empty event store, atomically; all historical times are fictional."""
    from incident_response.incident_manager import acknowledge, create_incident
    from incident_response.response_actions import TRANSITIONS, transition

    if db.execute("SELECT COUNT(*) FROM events").fetchone()[0]:
        return
    base = datetime.now(timezone.utc) - timedelta(hours=8)
    with db:
        for index in range(18):
            generate(
                db,
                "normal" if index % 2 == 0 else "successful_login",
                (base + timedelta(minutes=index * 20)).isoformat(
                    timespec="microseconds"
                ),
            )
        alerts = []
        scenarios = [
            "brute_force",
            "powershell",
            "privilege_change",
            "file_modification",
            "malware",
            "network_anomaly",
            "account_creation",
            "malware",
            "powershell",
            "file_modification",
            "network_anomaly",
            "privilege_change",
        ]
        for index, scenario in enumerate(scenarios):
            at = (base + timedelta(minutes=30 + index * 25)).isoformat(
                timespec="microseconds"
            )
            result = generate(
                db,
                scenario,
                at,
                f"192.0.2.{20 + index}",
                "test_user",
                f"LAB-WINDOWS-{index % 3 + 1:02}",
            )
            alerts.extend(result["alerts"])
        for index, alert_id in enumerate(alerts[:6]):
            alert = db.execute(
                "SELECT * FROM alerts WHERE id=?", (alert_id,)
            ).fetchone()
            start = datetime.fromisoformat(alert["timestamp"])
            acknowledge(
                db,
                alert_id,
                (start + timedelta(minutes=1)).isoformat(timespec="microseconds"),
            )
            incident_id = create_incident(
                db,
                alert_id,
                (start + timedelta(minutes=2)).isoformat(timespec="microseconds"),
            )
            for step, action in enumerate(list(TRANSITIONS)[:index]):
                transition(
                    db,
                    incident_id,
                    action,
                    "SIMULATED training exercise: evidence reviewed and stage validated.",
                    (start + timedelta(minutes=5 + step * 5)).isoformat(
                        timespec="microseconds"
                    ),
                )
