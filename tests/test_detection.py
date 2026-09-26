from datetime import datetime, timedelta, timezone

import pytest
from database.db import get_db
from detection.engine import evaluate_event
from simulator.log_generator import generate


def test_database_initializes(app):
    with app.app_context():
        db = get_db()
        tables = {
            r[0]
            for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert {
            "events",
            "alerts",
            "incidents",
            "incident_timeline",
            "audit_logs",
        } <= tables
        assert db.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_single_failed_login_no_alert(app):
    with app.app_context():
        result = generate(get_db(), "failed_login")
        assert len(result["events"]) == 1 and result["alerts"] == []


def test_brute_force_threshold_and_suppression(app):
    with app.app_context():
        db = get_db()
        for _ in range(4):
            assert generate(db, "failed_login")["alerts"] == []
        assert len(generate(db, "failed_login")["alerts"]) == 1
        assert generate(db, "brute_force")["alerts"] == []
        assert db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1


def test_time_window_and_user_source_isolation(app):
    with app.app_context():
        db = get_db()
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for _ in range(4):
            generate(db, "failed_login", start.isoformat(timespec="microseconds"))
        assert (
            generate(
                db,
                "failed_login",
                (start + timedelta(seconds=301)).isoformat(timespec="microseconds"),
            )["alerts"]
            == []
        )
        assert (
            generate(
                db,
                "failed_login",
                (start + timedelta(seconds=302)).isoformat(timespec="microseconds"),
                username="test_other",
            )["alerts"]
            == []
        )
        assert (
            generate(
                db,
                "failed_login",
                (start + timedelta(seconds=303)).isoformat(timespec="microseconds"),
                source_ip="192.0.2.99",
            )["alerts"]
            == []
        )
        assert generate(
            db,
            "brute_force",
            (start + timedelta(seconds=304)).isoformat(timespec="microseconds"),
        )["alerts"]
        assert generate(
            db,
            "brute_force",
            (start + timedelta(seconds=605)).isoformat(timespec="microseconds"),
        )["alerts"]


def test_inclusive_boundary_and_configurable_threshold(app):
    app.config.update(FAILED_LOGIN_THRESHOLD=3, DETECTION_WINDOW_SECONDS=60)
    with app.app_context():
        db = get_db()
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for seconds in (0, 30):
            assert not generate(
                db,
                "failed_login",
                (start + timedelta(seconds=seconds)).isoformat(timespec="microseconds"),
            )["alerts"]
        assert generate(
            db,
            "failed_login",
            (start + timedelta(seconds=60)).isoformat(timespec="microseconds"),
        )["alerts"]


@pytest.mark.parametrize(
    "scenario,rule,severity",
    [
        ("powershell", "RULE-002", "HIGH"),
        ("privilege_change", "RULE-003", "HIGH"),
        ("malware", "RULE-004", "CRITICAL"),
        ("file_modification", "RULE-005", "MEDIUM"),
        ("network_anomaly", "RULE-006", "MEDIUM"),
        ("account_creation", "RULE-007", "MEDIUM"),
    ],
)
def test_type_detections_and_idempotency(app, scenario, rule, severity):
    with app.app_context():
        db = get_db()
        result = generate(db, scenario)
        alert = db.execute("SELECT * FROM alerts").fetchone()
        assert alert["rule_id"] == rule and alert["severity"] == severity
        assert evaluate_event(db, result["events"][0]) == alert["id"]
        assert db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1


@pytest.mark.parametrize("scenario", ["normal", "successful_login"])
def test_benign_event_no_alert(app, scenario):
    with app.app_context():
        assert generate(get_db(), scenario)["alerts"] == []
