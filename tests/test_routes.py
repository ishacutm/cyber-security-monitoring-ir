import sqlite3

import pytest
from app import create_app
from database.db import get_db
from incident_response.incident_manager import create_incident
from simulator.log_generator import generate
from simulator.scenarios import SCENARIOS


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/alerts",
        "/incidents",
        "/simulator",
        "/logs",
        "/reports",
        "/about",
        "/documentation",
        "/documentation/escalation-matrix",
        "/documentation/communication-plan",
        "/api/charts",
    ],
)
def test_major_routes(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


@pytest.mark.parametrize("scenario", list(SCENARIOS))
def test_every_simulator_route(app, post, scenario):
    response = post("/simulator", {"scenario": scenario}, follow_redirects=True)
    assert response.status_code == 200 and b"SIMULATED: Generated" in response.data
    with app.app_context():
        rows = get_db().execute("SELECT * FROM events").fetchall()
        assert len(rows) == (5 if scenario == "brute_force" else 1)
        assert all("SIMULATED" in row["description"] for row in rows)


def test_full_browser_workflow(client, post, app):
    post("/simulator", {"scenario": "malware"})
    assert client.get("/alerts/1").status_code == 200
    assert post("/alerts/1/acknowledge").status_code == 302
    response = post("/alerts/1/incident")
    assert response.status_code == 302 and response.headers["Location"].endswith(
        "/incidents/1"
    )
    assert client.get("/incidents/1").status_code == 200
    assert post("/incidents/1/contain", {"note": "skip"}).status_code == 400
    for action in ["investigate", "contain", "eradicate", "recover", "close"]:
        assert (
            post(
                "/incidents/1/" + action,
                {"note": "SIMULATED stage completed"},
                follow_redirects=True,
            ).status_code
            == 200
        )
    assert post("/incidents/1/close", {"note": "repeat"}).status_code == 400
    with app.app_context():
        assert (
            get_db().execute("SELECT status FROM incidents").fetchone()[0] == "CLOSED"
        )
    csv = client.get("/reports/export.csv")
    assert csv.status_code == 200 and "attachment" in csv.headers["Content-Disposition"]
    assert b"MTTR (seconds)" in csv.data and b"CLOSED" in csv.data


def test_validation_csrf_and_missing_routes(client, post, app):
    assert client.post("/simulator", data={"scenario": "normal"}).status_code == 400
    assert post("/simulator", {"scenario": "invalid"}).status_code == 400
    for path in ["/missing", "/alerts/999", "/incidents/999", "/documentation/unknown"]:
        assert client.get(path).status_code == 404
    for path in ["/logs?page=wrong", "/logs?severity=FAKE", "/alerts?status=FAKE"]:
        assert client.get(path).status_code == 400
    assert client.get("/logs?q=%27%20OR%201%3D1--").status_code == 200
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


def test_filters_pagination_and_html_escaping(app, client, post):
    with app.app_context():
        db = get_db()
        with db:
            for _ in range(24):
                generate(db, "normal")
            alert = generate(db, "malware")["alerts"][0]
            create_incident(db, alert)
    assert b"Page 2 of 2" in client.get("/logs?page=2").data
    assert (
        b"1 matching events"
        in client.get("/logs?event_type=malware&severity=CRITICAL&q=LAB").data
    )
    assert (
        b"Malware Detection Event"
        in client.get("/alerts?severity=CRITICAL&status=ACKNOWLEDGED").data
    )
    assert b"No alerts match" in client.get("/alerts?severity=LOW").data
    post("/incidents/1/notes", {"root_cause": "<script>alert(1)</script>"})
    response = client.get("/incidents/1")
    assert (
        b"&lt;script&gt;" in response.data
        and b"<script>alert(1)</script>" not in response.data
    )


def test_seed_sizes_persistence_and_charts(tmp_path):
    config = {"TESTING": True, "DATABASE": str(tmp_path / "seed.db")}
    app = create_app(config)
    with app.app_context():
        db = get_db()
        assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 34
        assert db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 12
        assert db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 6
        assert (
            db.execute("SELECT COUNT(DISTINCT status) FROM incidents").fetchone()[0]
            == 6
        )
    app2 = create_app(config)
    with app2.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM events").fetchone()[0] == 34
    data = app2.test_client().get("/api/charts").json
    assert sum(data["severity"]["values"]) == 12 and sum(data["events"]["values"]) == 34


def test_database_error_page_and_generic_500(app, client, monkeypatch):
    import app as module

    def broken_summary(db):
        raise sqlite3.OperationalError("private database detail")

    monkeypatch.setattr(module, "summary", broken_summary)
    response = client.get("/")
    assert (
        response.status_code == 503 and b"private database detail" not in response.data
    )

    def unexpected(db):
        raise RuntimeError("private stack detail")

    monkeypatch.setattr(module, "summary", unexpected)
    app.config["PROPAGATE_EXCEPTIONS"] = False
    response = client.get("/")
    assert response.status_code == 500 and b"private stack detail" not in response.data


def test_non_ascii_csrf_token_rejected(client):
    client.get("/")
    response = client.post(
        "/simulator", data={"csrf_token": "अमान्य", "scenario": "normal"}
    )
    assert response.status_code == 400
