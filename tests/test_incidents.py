import pytest
from database.db import get_db
from incident_response.incident_manager import acknowledge, close_alert, create_incident
from incident_response.response_actions import TRANSITIONS, transition
from reports.report_generator import export_csv, metrics
from simulator.log_generator import generate


def setup_case(db):
    alert_id = generate(db, "malware")["alerts"][0]
    return alert_id, create_incident(db, alert_id)


def test_create_incident_idempotent_and_acknowledge(app):
    with app.app_context():
        db = get_db()
        alert_id, case = setup_case(db)
        assert create_incident(db, alert_id) == case
        alert = db.execute("SELECT * FROM alerts").fetchone()
        assert alert["status"] == "ACKNOWLEDGED"
        timestamp = alert["acknowledged_at"]
        acknowledge(db, alert_id)
        assert (
            db.execute("SELECT acknowledged_at FROM alerts").fetchone()[0] == timestamp
        )
        assert (
            db.execute(
                "SELECT COUNT(*) FROM audit_logs WHERE action='ACKNOWLEDGED'"
            ).fetchone()[0]
            == 1
        )
        assert db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 1


def test_all_transitions_timeline_audit_and_closure(app):
    with app.app_context():
        db = get_db()
        alert_id, case = setup_case(db)
        for action, (_, status, _, field) in TRANSITIONS.items():
            previous = db.execute("SELECT updated_at FROM incidents").fetchone()[0]
            transition(db, case, action, "SIMULATED validated " + action)
            row = db.execute("SELECT * FROM incidents").fetchone()
            assert (
                row["status"] == status
                and row[field] == "SIMULATED validated " + action
            )
            assert row["updated_at"] >= previous
            assert (
                db.execute(
                    "SELECT COUNT(*) FROM incident_timeline WHERE action=?", (status,)
                ).fetchone()[0]
                == 1
            )
            assert (
                db.execute(
                    "SELECT COUNT(*) FROM audit_logs WHERE entity_type='incident' AND action=?",
                    (status,),
                ).fetchone()[0]
                == 1
            )
        assert row["closed_at"] is not None
        assert (
            db.execute("SELECT status FROM alerts WHERE id=?", (alert_id,)).fetchone()[
                0
            ]
            == "CLOSED"
        )


def test_invalid_transition_no_partial_changes(app):
    with app.app_context():
        db = get_db()
        _, case = setup_case(db)
        before = db.execute("SELECT COUNT(*) FROM incident_timeline").fetchone()[0]
        with pytest.raises(ValueError):
            transition(db, case, "contain", "Cannot skip analysis")
        assert db.execute("SELECT status FROM incidents").fetchone()[0] == "OPEN"
        assert (
            db.execute("SELECT COUNT(*) FROM incident_timeline").fetchone()[0] == before
        )
        with pytest.raises(ValueError):
            transition(db, case, "investigate", "   ")
        with pytest.raises(ValueError):
            transition(db, case, "investigate", "x" * 4001)


def test_active_incident_blocks_alert_closure(app):
    with app.app_context():
        db = get_db()
        alert_id, _ = setup_case(db)
        with pytest.raises(ValueError):
            close_alert(db, alert_id)


def test_empty_metrics_na_and_known_durations(app):
    with app.app_context():
        db = get_db()
        assert all(value["seconds"] is None for value in metrics(db).values())
        alert_id = generate(db, "malware", "2026-01-01T09:00:00.000000+00:00")[
            "alerts"
        ][0]
        acknowledge(db, alert_id, "2026-01-01T09:01:02.000000+00:00")
        case = create_incident(db, alert_id, "2026-01-01T09:02:02.000000+00:00")
        for action, minute in [
            ("investigate", 5),
            ("contain", 10),
            ("eradicate", 15),
            ("recover", 20),
        ]:
            transition(
                db,
                case,
                action,
                "SIMULATED check",
                f"2026-01-01T09:{minute:02}:02.000000+00:00",
            )
        result = metrics(db)
        assert result["MTTD"] == {"seconds": 2.0, "samples": 1}
        assert result["MTTA"]["seconds"] == 60
        assert result["MTTC"]["seconds"] == 600
        assert result["MTTR"]["seconds"] is None
        transition(
            db,
            case,
            "close",
            "SIMULATED recovery validated",
            "2026-01-01T09:25:02.000000+00:00",
        )
        assert metrics(db)["MTTR"] == {"seconds": 1500.0, "samples": 1}


def test_export_neutralizes_formula_notes(app):
    with app.app_context():
        db = get_db()
        _, case = setup_case(db)
        transition(db, case, "investigate", "=1+1")
        output = export_csv(db)
        assert "'=1+1" in output and "SIMULATED SOC report" in output
