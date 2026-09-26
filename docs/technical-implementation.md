# Technical implementation

## app.py and config.py

create_app builds Flask, registers routes, initializes the schema and optionally seeds demo data. Running python app.py binds only to 127.0.0.1:5000 with debug disabled. A process-random secret supports CSRF sessions unless FLASK_SECRET_KEY is set in the environment. POST requests require a session token; GET routes are read-only. Security headers constrain assets and form submissions to the same origin. The documentation page reads only allowlisted Markdown filenames and renders escaped text.

## database/db.py and schema.sql

One SQLite connection per Flask application/request context is kept in flask.g and closed at teardown. Foreign-key enforcement is enabled. Callers use connection context managers for atomic transactions. The five required tables preserve normalized events, alerts, incidents, timeline and audit entries. Indexes support login correlation. Additional columns rule_id, acknowledged_at, closed_at and incident.alert_id provide traceability and valid timing calculations. Unique event/rule and incident/alert constraints prevent duplication. Schema SQL is idempotent; this initial release has no schema migration engine.

## simulator/scenarios.py and log_generator.py

SCENARIOS defines ten safe educational buttons. generate inserts normalized event records and calls detection for each. Brute force generates the configured failed-login threshold. No subprocess, system command, socket, packet library, file modification or real account operation is used by simulations. seed_demo creates 34 events, 12 alerts and six incidents only in an empty store. Seed records include fictitious historic timestamps and staged case actions so the dashboard is meaningful on first launch.

## detection/rules.py and engine.py

RULES is the authoritative eight-rule catalog with identifiers, logic, severity, false positives, investigation and recommended response. evaluate_event checks event type and a rolling event-time window for repeated logins. Correlation groups the source IP and user. Existing event/rule alerts are reused; repeated threshold alerts are suppressed for one window. Alerts and detection audit entries are written in the caller's transaction. This synchronous educational engine assumes chronological simulator events, not late-arriving production telemetry.

## incident_response/incident_manager.py

acknowledge preserves the first acknowledgement timestamp and writes an audit entry once. close_alert prevents closing an alert with an active linked incident. create_incident reuses an existing case for an alert, acknowledges an open alert, and creates a unique SIM-IR identifier, initial detection/open timeline entries and audit record.

## incident_response/response_actions.py

TRANSITIONS permits only OPEN → INVESTIGATING → CONTAINED → ERADICATED → RECOVERING → CLOSED. The conditional UPDATE verifies the expected prior state. Each action writes a note, status, timestamp, timeline and audit within the route transaction. Closure updates the originating alert. save_notes validates length, updates all five investigation fields and records the edit. SQL data values are parameterized; dynamic column names come only from fixed internal allowlists.

## reports/report_generator.py

summary creates all-time counters. chart_data groups severity, rule, event hour and incident status. metrics joins originating records and computes completed nonnegative timing pairs with sample counts. export_csv writes counters, metrics, rule distribution and incident details. Free-text cells beginning with formula markers after whitespace are prefixed with an apostrophe to reduce spreadsheet formula injection.

## UI

Jinja renders dashboard, alerts, cases, searchable logs, simulator, reports, documentation and about pages. HTML autoescaping protects displayed notes. CSS provides responsive navigation, cards, tables and timeline. Chart.js 4.4.8 is vendored with its license; dashboard.js calls only /api/charts. No remote fonts, CDN or telemetry endpoints are used. Tables provide data if charts are unavailable. All times are displayed in UTC.

## Failure behavior and limits

Unknown records return 404. Invalid filters, notes, stages or CSRF tokens return 400. Oversized requests return 413. Database exceptions roll back and return a generic 503 page. Unexpected failures return a generic 500 page; normal users see no stack trace. Initialization errors produce a concise local startup message. Source has no hard-coded credentials.

Single-user teaching use only: no authentication, access roles, real collector, immutable audit, scale guarantees, recovery job or automated notifications. Python dependencies must be installed before offline runtime. Database persistence resides only in database/soc.db.
