# Testing and demonstration guide

Run python -m pytest -q from the project root in the virtual environment. Tests use temporary SQLite databases, seed disabled unless explicitly tested, and real CSRF tokens. No external service is contacted.

## Manual scenario checks

1. Generate Failed Login once: event count increases by one; below the configured threshold no alert appears.
2. Generate Brute Force: threshold-count failed_login rows share one source/user and produce one HIGH alert. A repeat inside the suppression window records events but no duplicate alert.
3. Generate Successful Login: one LOW event, no alert.
4. Generate Suspicious PowerShell: one HIGH RULE-002 alert; no script is executed.
5. Generate Privilege Change: one HIGH RULE-003 alert; no actual role changes.
6. Generate File Modification: one MEDIUM RULE-005 alert; no real file changes.
7. Generate Malware Detection: one CRITICAL RULE-004 alert; no malware exists.
8. Generate Suspicious Network Activity: one MEDIUM RULE-006 alert; no connection is made.
9. Generate Account Creation: one MEDIUM RULE-007 alert; no real account exists.
10. Generate Normal Activity: one LOW event and no alert.

Open Alerts, filter by severity/status, then inspect an alert's event, rule and recommendation. Acknowledge it and check Reports' audit trail. Create an incident; clicking again must open the same case. Follow all five response buttons with notes. Check status, updated timestamp, timeline, audit and summaries after each. Out-of-order stages must be rejected without partial updates. At closure the related alert closes.

Search Logs for LAB-WINDOWS, filter by type and severity, then go to the next page. Query parameters remain in pagination links. Open Reports and export the CSV; counters and samples must agree with dashboard records. Empty metric samples display N/A. Recovery-start alone must not count toward MTTR.

## Edge and safety checks

- Unknown routes and records return the custom 404 page.
- Unknown simulator scenarios or malformed filters fail without inserts.
- A missing CSRF token is rejected.
- Notes containing HTML render as text, not executable markup.
- SQLite values are parameterized, including search terms.
- Formula-like notes are neutralized in CSV.
- No external browser requests occur while navigating the local app.
- Narrow screens retain accessible navigation and horizontally scrollable tables.

## Demo reset

Stop the server before deleting the local database. Back it up if analyst notes matter. Delete only database/soc.db and start again to re-create the synthetic seed. Do not delete source or the schema.
