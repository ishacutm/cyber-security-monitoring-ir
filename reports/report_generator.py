import csv
import io
from datetime import datetime


def mean_duration(pairs):
    durations = []
    for start, end in pairs:
        if start and end:
            seconds = (
                datetime.fromisoformat(end) - datetime.fromisoformat(start)
            ).total_seconds()
            if seconds >= 0:
                durations.append(seconds)
    return {
        "seconds": round(sum(durations) / len(durations), 3) if durations else None,
        "samples": len(durations),
    }


def metrics(db):
    detected = db.execute(
        "SELECT e.timestamp,a.timestamp FROM alerts a JOIN events e ON a.event_id=e.id"
    ).fetchall()
    acknowledged = db.execute("SELECT timestamp,acknowledged_at FROM alerts").fetchall()
    contained = db.execute(
        "SELECT a.timestamp,MIN(t.timestamp) FROM incidents i JOIN alerts a ON i.alert_id=a.id LEFT JOIN incident_timeline t ON t.incident_id=i.id AND t.action='CONTAINED' GROUP BY i.id"
    ).fetchall()
    recovered = db.execute(
        "SELECT a.timestamp,i.closed_at FROM incidents i JOIN alerts a ON i.alert_id=a.id"
    ).fetchall()
    return {
        "MTTD": mean_duration(detected),
        "MTTA": mean_duration(acknowledged),
        "MTTC": mean_duration(contained),
        "MTTR": mean_duration(recovered),
    }


def summary(db):
    def count(sql):
        return db.execute(sql).fetchone()[0]

    return {
        "Total Events": count("SELECT COUNT(*) FROM events"),
        "Total Alerts": count("SELECT COUNT(*) FROM alerts"),
        "Open Alerts": count("SELECT COUNT(*) FROM alerts WHERE status='OPEN'"),
        "Critical Alerts": count(
            "SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'"
        ),
        "High Alerts": count("SELECT COUNT(*) FROM alerts WHERE severity='HIGH'"),
        "Open Incidents": count(
            "SELECT COUNT(*) FROM incidents WHERE status!='CLOSED'"
        ),
        "Closed Incidents": count(
            "SELECT COUNT(*) FROM incidents WHERE status='CLOSED'"
        ),
        "Total Incidents": count("SELECT COUNT(*) FROM incidents"),
        "Critical Incidents": count(
            "SELECT COUNT(*) FROM incidents WHERE severity='CRITICAL'"
        ),
        "High Incidents": count("SELECT COUNT(*) FROM incidents WHERE severity='HIGH'"),
        "Medium Incidents": count(
            "SELECT COUNT(*) FROM incidents WHERE severity='MEDIUM'"
        ),
    }


def chart_data(db):
    def group(sql):
        rows = db.execute(sql).fetchall()
        return {"labels": [row[0] for row in rows], "values": [row[1] for row in rows]}

    return {
        "severity": group("SELECT severity,COUNT(*) FROM alerts GROUP BY severity"),
        "detection": group("SELECT rule_name,COUNT(*) FROM alerts GROUP BY rule_name"),
        "events": group(
            "SELECT substr(timestamp,1,13)||':00 UTC',COUNT(*) FROM events GROUP BY substr(timestamp,1,13) ORDER BY timestamp"
        ),
        "incidents": group("SELECT status,COUNT(*) FROM incidents GROUP BY status"),
    }


def safe_cell(value):
    text = "" if value is None else str(value)
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text


def export_csv(db):
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["SIMULATED SOC report — educational data only"])
    writer.writerow(["Metric", "Value", "Completed samples"])
    for key, value in summary(db).items():
        writer.writerow([key, value, ""])
    for key, value in metrics(db).items():
        writer.writerow(
            [
                key + " (seconds)",
                value["seconds"] if value["seconds"] is not None else "N/A",
                value["samples"],
            ]
        )
    writer.writerow([])
    writer.writerow(["Detection rule", "Alerts"])
    for row in db.execute("SELECT rule_name,COUNT(*) FROM alerts GROUP BY rule_name"):
        writer.writerow(list(row))
    writer.writerow([])
    columns = [
        "incident_number",
        "title",
        "severity",
        "status",
        "affected_host",
        "created_at",
        "closed_at",
        "root_cause",
        "containment_summary",
        "eradication_summary",
        "recovery_summary",
        "lessons_learned",
    ]
    writer.writerow(columns)
    for row in db.execute("SELECT * FROM incidents ORDER BY id"):
        writer.writerow([safe_cell(row[col]) for col in columns])
    return output.getvalue()
