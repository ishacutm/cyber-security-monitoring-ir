"""Response actions change SQLite records only. They never control the OS."""

from database.db import audit, utcnow

TRANSITIONS = {
    "investigate": ("OPEN", "INVESTIGATING", "Start Investigation", "root_cause"),
    "contain": (
        "INVESTIGATING",
        "CONTAINED",
        "Contain Incident",
        "containment_summary",
    ),
    "eradicate": ("CONTAINED", "ERADICATED", "Eradicate Threat", "eradication_summary"),
    "recover": ("ERADICATED", "RECOVERING", "Begin Recovery", "recovery_summary"),
    "close": ("RECOVERING", "CLOSED", "Close Incident", "lessons_learned"),
}
NOTE_FIELDS = (
    "root_cause",
    "containment_summary",
    "eradication_summary",
    "recovery_summary",
    "lessons_learned",
)


def transition(db, incident_id: int, action: str, note: str, at=None):
    if action not in TRANSITIONS:
        raise ValueError("Unknown response action.")
    note = note.strip()
    if not note or len(note) > 4000:
        raise ValueError("Enter an analyst note between 1 and 4000 characters.")
    incident = db.execute(
        "SELECT * FROM incidents WHERE id=?", (incident_id,)
    ).fetchone()
    before, after, label, field = TRANSITIONS[action]
    if incident is None or incident["status"] != before:
        raise ValueError(
            "Invalid or stale transition. Reload and follow the incident lifecycle."
        )
    now = at or utcnow()
    # field is selected only from the fixed internal mapping above, never user SQL.
    changed = db.execute(
        f"UPDATE incidents SET status=?,updated_at=?,{field}=?,closed_at=? WHERE id=? AND status=?",
        (after, now, note, now if after == "CLOSED" else None, incident_id, before),
    )
    if changed.rowcount != 1:
        raise ValueError("Incident was updated by another request. Reload.")
    description = "SIMULATED: " + label + ". " + note
    db.execute(
        "INSERT INTO incident_timeline(incident_id,timestamp,action,description,performed_by) VALUES(?,?,?,?,?)",
        (incident_id, now, after, description, "local_analyst"),
    )
    audit(db, after, "incident", incident_id, description, now)
    if after == "CLOSED":
        db.execute(
            "UPDATE alerts SET status='CLOSED',closed_at=? WHERE id=?",
            (now, incident["alert_id"]),
        )
        audit(
            db,
            "CLOSED",
            "alert",
            incident["alert_id"],
            "SIMULATED: Linked incident closed after recovery validation.",
            now,
        )


def save_notes(db, incident_id: int, values: dict):
    if any(len(values.get(field, "")) > 4000 for field in NOTE_FIELDS):
        raise ValueError("Each note must be at most 4000 characters.")
    now = utcnow()
    db.execute(
        "UPDATE incidents SET root_cause=?,containment_summary=?,eradication_summary=?,recovery_summary=?,lessons_learned=?,updated_at=? WHERE id=?",
        tuple(values.get(field, "").strip() for field in NOTE_FIELDS)
        + (now, incident_id),
    )
    db.execute(
        "INSERT INTO incident_timeline(incident_id,timestamp,action,description,performed_by) VALUES(?,?,?,?,?)",
        (
            incident_id,
            now,
            "NOTES_UPDATED",
            "SIMULATED: Investigation notes updated.",
            "local_analyst",
        ),
    )
    audit(
        db,
        "NOTES_UPDATED",
        "incident",
        incident_id,
        "SIMULATED: Analyst updated investigation notes.",
        now,
    )
