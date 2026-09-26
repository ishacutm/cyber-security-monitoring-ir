from uuid import uuid4

from database.db import audit, utcnow


def acknowledge(db, alert_id: int, at=None):
    alert = db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if alert is None:
        raise ValueError("Alert not found.")
    if alert["status"] != "OPEN":
        return
    now = at or utcnow()
    db.execute(
        "UPDATE alerts SET status='ACKNOWLEDGED',acknowledged_at=? WHERE id=?",
        (now, alert_id),
    )
    audit(
        db,
        "ACKNOWLEDGED",
        "alert",
        alert_id,
        "SIMULATED: Analyst acknowledged alert.",
        now,
    )


def close_alert(db, alert_id: int):
    alert = db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if alert is None:
        raise ValueError("Alert not found.")
    incident = db.execute(
        "SELECT id FROM incidents WHERE alert_id=? AND status!='CLOSED'", (alert_id,)
    ).fetchone()
    if incident:
        raise ValueError("Complete the linked incident before closing this alert.")
    if alert["status"] == "CLOSED":
        return
    acknowledge(db, alert_id)
    now = utcnow()
    db.execute(
        "UPDATE alerts SET status='CLOSED',closed_at=? WHERE id=?", (now, alert_id)
    )
    audit(db, "CLOSED", "alert", alert_id, "SIMULATED: Alert closed by analyst.", now)


def create_incident(db, alert_id: int, at=None) -> int:
    old = db.execute(
        "SELECT id FROM incidents WHERE alert_id=?", (alert_id,)
    ).fetchone()
    if old:
        return old["id"]
    alert = db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if alert is None or alert["status"] == "CLOSED":
        raise ValueError("Select an active alert to create an incident.")
    now = at or utcnow()
    acknowledge(db, alert_id, now)
    number = "SIM-IR-" + uuid4().hex[:8].upper()
    cur = db.execute(
        "INSERT INTO incidents(incident_number,title,severity,status,description,affected_host,affected_user,source_ip,created_at,updated_at,alert_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (
            number,
            alert["title"],
            alert["severity"],
            "OPEN",
            alert["description"],
            alert["hostname"],
            alert["username"],
            alert["source_ip"],
            now,
            now,
            alert_id,
        ),
    )
    incident_id = cur.lastrowid
    db.execute(
        "INSERT INTO incident_timeline(incident_id,timestamp,action,description,performed_by) VALUES(?,?,?,?,?)",
        (
            incident_id,
            alert["timestamp"],
            "DETECTION",
            alert["description"],
            "simulated_detection_engine",
        ),
    )
    db.execute(
        "INSERT INTO incident_timeline(incident_id,timestamp,action,description,performed_by) VALUES(?,?,?,?,?)",
        (
            incident_id,
            now,
            "OPEN",
            "SIMULATED: Incident created from alert.",
            "local_analyst",
        ),
    )
    audit(
        db,
        "CREATED",
        "incident",
        incident_id,
        "SIMULATED: Incident created from alert " + str(alert_id),
        now,
    )
    return incident_id
