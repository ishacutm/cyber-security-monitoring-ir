"""Local educational SOC. Run: python app.py (never expose publicly)."""

import hmac
import secrets
import sqlite3
from pathlib import Path

from config import Config
from database.db import close_db, get_db, init_db
from detection.rules import BY_ID, RULES
from flask import (
    Flask,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from incident_response.incident_manager import acknowledge, close_alert, create_incident
from incident_response.response_actions import (
    NOTE_FIELDS,
    TRANSITIONS,
    save_notes,
    transition,
)
from reports.report_generator import chart_data, export_csv, metrics, summary
from simulator.log_generator import generate, seed_demo
from simulator.scenarios import SCENARIOS

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
DOC_DIR = Path(__file__).resolve().parent / "docs"


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    if (
        app.config["DETECTION_WINDOW_SECONDS"] < 1
        or app.config["FAILED_LOGIN_THRESHOLD"] < 1
    ):
        raise ValueError("Detection window and threshold must be positive.")
    app.teardown_appcontext(close_db)

    @app.before_request
    def protect_forms():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
        if request.method == "POST":
            token = request.form.get("csrf_token", "")
            if not token.isascii() or not hmac.compare_digest(
                token, session["csrf_token"]
            ):
                abort(400, "Form expired or invalid. Reload the page and try again.")

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.context_processor
    def common():
        return dict(severities=SEVERITIES, csrf_token=session.get("csrf_token", ""))

    @app.template_filter("timefmt")
    def timefmt(value):
        return value[:19].replace("T", " ") + " UTC" if value else "N/A"

    def lookup(table, record_id):
        # Table names are constants supplied only by route code below.
        row = (
            get_db()
            .execute(f"SELECT * FROM {table} WHERE id=?", (record_id,))
            .fetchone()
        )
        if row is None:
            abort(404)
        return row

    @app.get("/")
    def dashboard():
        db = get_db()
        return render_template(
            "dashboard.html",
            title="Operations overview",
            stats=summary(db),
            metrics=metrics(db),
            alerts=db.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT 5"
            ).fetchall(),
            incidents=db.execute(
                "SELECT * FROM incidents ORDER BY id DESC LIMIT 5"
            ).fetchall(),
        )

    @app.get("/api/charts")
    def charts():
        return chart_data(get_db())

    @app.get("/alerts")
    def alerts():
        severity, status = (
            request.args.get("severity", ""),
            request.args.get("status", ""),
        )
        query, params = "SELECT * FROM alerts WHERE 1=1", []
        for column, value, valid in [
            ("severity", severity, SEVERITIES),
            ("status", status, ("OPEN", "ACKNOWLEDGED", "CLOSED")),
        ]:
            if value:
                if value not in valid:
                    abort(400, "Invalid filter.")
                query += f" AND {column}=?"
                params.append(value)
        rows = get_db().execute(query + " ORDER BY id DESC", params).fetchall()
        return render_template(
            "alerts.html",
            title="Alert queue",
            alerts=rows,
            severity=severity,
            status=status,
        )

    @app.get("/alerts/<int:alert_id>")
    def alert_detail(alert_id):
        alert = lookup("alerts", alert_id)
        return render_template(
            "alert_detail.html",
            title="Alert investigation",
            alert=alert,
            event=lookup("events", alert["event_id"]),
            rule=BY_ID[alert["rule_id"]],
            incident=get_db()
            .execute("SELECT * FROM incidents WHERE alert_id=?", (alert_id,))
            .fetchone(),
        )

    @app.post("/alerts/<int:alert_id>/<action>")
    def alert_action(alert_id, action):
        lookup("alerts", alert_id)
        if action not in ("acknowledge", "close", "incident"):
            abort(400, "Unknown alert action.")
        db = get_db()
        with db:
            if action == "incident":
                incident_id = create_incident(db, alert_id)
                return redirect(url_for("incident_detail", incident_id=incident_id))
            (acknowledge if action == "acknowledge" else close_alert)(db, alert_id)
        flash("Simulated alert updated.", "success")
        return redirect(url_for("alert_detail", alert_id=alert_id))

    @app.get("/incidents")
    def incidents():
        return render_template(
            "incidents.html",
            title="Incident workspace",
            incidents=get_db()
            .execute("SELECT * FROM incidents ORDER BY id DESC")
            .fetchall(),
        )

    @app.get("/incidents/<int:incident_id>")
    def incident_detail(incident_id):
        incident = lookup("incidents", incident_id)
        next_action = next(
            (
                (key, value)
                for key, value in TRANSITIONS.items()
                if value[0] == incident["status"]
            ),
            None,
        )
        return render_template(
            "incident_detail.html",
            title=incident["incident_number"],
            incident=incident,
            timeline=get_db()
            .execute(
                "SELECT * FROM incident_timeline WHERE incident_id=? ORDER BY timestamp,id",
                (incident_id,),
            )
            .fetchall(),
            next_action=next_action,
            note_fields=NOTE_FIELDS,
        )

    @app.post("/incidents/<int:incident_id>/<action>")
    def incident_action(incident_id, action):
        lookup("incidents", incident_id)
        db = get_db()
        with db:
            if action == "notes":
                save_notes(db, incident_id, request.form)
            else:
                transition(db, incident_id, action, request.form.get("note", ""))
        flash("Simulated incident updated; timeline and audit recorded.", "success")
        return redirect(url_for("incident_detail", incident_id=incident_id))

    @app.get("/logs")
    def logs():
        search, severity, event_type = (
            request.args.get(key, "").strip() for key in ("q", "severity", "event_type")
        )
        if len(search) > 200:
            abort(400, "Search text is too long.")
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            abort(400, "Invalid page number.")
        query, params = " FROM events WHERE 1=1", []
        if search:
            query += " AND (description LIKE ? OR username LIKE ? OR hostname LIKE ? OR source_ip LIKE ?)"
            params.extend(["%" + search + "%"] * 4)
        for column, value, valid in [
            ("severity", severity, SEVERITIES),
            ("event_type", event_type, SCENARIOS),
        ]:
            if value:
                if value not in valid or value == "brute_force":
                    abort(400, "Invalid log filter.")
                query += f" AND {column}=?"
                params.append(value)
        db = get_db()
        count = db.execute("SELECT COUNT(*)" + query, params).fetchone()[0]
        pages = max(1, (count + 19) // 20)
        page = min(page, pages)
        rows = db.execute(
            "SELECT *" + query + " ORDER BY timestamp DESC,id DESC LIMIT ? OFFSET ?",
            params + [20, (page - 1) * 20],
        ).fetchall()
        return render_template(
            "logs.html",
            title="Event explorer",
            logs=rows,
            q=search,
            severity=severity,
            event_type=event_type,
            event_types=[s for s in SCENARIOS if s != "brute_force"],
            page=page,
            pages=pages,
            count=count,
        )

    @app.route("/simulator", methods=["GET", "POST"])
    def simulator():
        if request.method == "POST":
            db = get_db()
            with db:
                result = generate(db, request.form.get("scenario", ""))
            flash(
                f"SIMULATED: Generated {len(result['events'])} event(s) and {len(result['alerts'])} alert(s). Repeated brute-force alerts are suppressed within the configured window.",
                "success",
            )
            return redirect(url_for("simulator"))
        return render_template(
            "simulator.html",
            title="Scenario laboratory",
            scenarios=SCENARIOS,
            window=app.config["DETECTION_WINDOW_SECONDS"],
            threshold=app.config["FAILED_LOGIN_THRESHOLD"],
        )

    @app.get("/reports")
    def reports():
        db = get_db()
        return render_template(
            "reports.html",
            title="Metrics & reporting",
            stats=summary(db),
            metrics=metrics(db),
            distribution=db.execute(
                "SELECT rule_name,COUNT(*) AS total FROM alerts GROUP BY rule_name"
            ).fetchall(),
            audit=db.execute(
                "SELECT * FROM audit_logs ORDER BY id DESC LIMIT 30"
            ).fetchall(),
        )

    @app.get("/reports/export.csv")
    def export():
        return Response(
            export_csv(get_db()),
            mimetype="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=simulated-soc-report.csv"
            },
        )

    @app.get("/documentation")
    @app.get("/documentation/<slug>")
    def documentation(slug="monitoring-strategy"):
        documents = sorted(path.stem for path in DOC_DIR.glob("*.md"))
        if slug not in documents:
            abort(404)
        # Render source as escaped text, never untrusted HTML.
        content = (DOC_DIR / (slug + ".md")).read_text(encoding="utf-8")
        return render_template(
            "documentation.html",
            title="Analyst knowledge base",
            documents=documents,
            slug=slug,
            content=content,
            rules=RULES,
        )

    @app.get("/about")
    def about():
        return render_template("about.html", title="About this project")

    @app.errorhandler(ValueError)
    def validation(error):
        return render_template(
            "error.html", title="Check your input", code=400, message=str(error)
        ), 400

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(413)
    def user_error(error):
        return render_template(
            "error.html",
            title="Request could not be completed",
            code=error.code,
            message=error.description,
        ), error.code

    @app.errorhandler(sqlite3.DatabaseError)
    def database_error(error):
        app.logger.error("Database operation failed: %s", type(error).__name__)
        db = get_db()
        db.rollback()
        return render_template(
            "error.html",
            title="Storage temporarily unavailable",
            code=503,
            message="The database could not complete this request. Try again or check the local database file permissions.",
        ), 503

    @app.errorhandler(500)
    def server_error(error):
        return render_template(
            "error.html",
            title="Something went wrong",
            code=500,
            message="The request failed. Restart the local application and retry. No diagnostic details are displayed here.",
        ), 500

    with app.app_context():
        init_db()
        if app.config["SEED_DATA"]:
            seed_demo(get_db())
    return app


if __name__ == "__main__":
    try:
        create_app().run(host="127.0.0.1", port=5000, debug=False)
    except sqlite3.DatabaseError:
        raise SystemExit(
            "Database initialization failed. Check the database directory permissions and available disk space."
        ) from None
app=create_app()