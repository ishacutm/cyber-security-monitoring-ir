# Monitoring strategy

Scope: three fictional lab endpoints, one fictional user identity and documentation IPs in 192.0.2.0/24. No real endpoint, account, traffic or infrastructure is monitored. The objective is to demonstrate the flow of continuous monitoring; actual event production is manual and synchronous.

## Collection and normalization

The simulator supplies UTC timestamp, event type, user, source IP, host, description, severity and raw JSON with simulated=true. SQLite stores every event. Detection evaluates immediately within the same database transaction. A failed transaction rolls back both event and detection writes.

In an operational design, continuous collection would require agents, source-health checks, clock synchronization, transport security, retention and backlog handling. Those mechanisms are outside this lab. The app's ONLINE labels are illustrative module indicators, not observed external health checks.

## Detection and triage

RULE-001 correlates failed logins using source IP AND user within a configurable inclusive rolling window, default five failures in 300 seconds. Repeat alerts for that pair are suppressed for one window measured from the triggering event of the previous alert. Type-based rules cover synthetic endpoint, file, network and account changes. Successful login and normal activity are retained for context without alerts.

Review the source event, validate whether the fictional change was authorized, acknowledge the alert, assess impact and escalate meaningful cases into incidents. Acknowledgement is idempotent. Closing an alert with an active incident is blocked to avoid inconsistent case state. Preserve rationale in incident notes and timeline. The audit trail is local application history, not tamper-proof forensic evidence.

## Coverage and false positives

Coverage is intentionally limited to ten scenarios and eight rule definitions. No real parsing, signature inspection, anomaly model or adversary attribution exists. Mistyped passwords, legitimate scripts, approved deployments, onboarding and scheduled synchronization can resemble these indicators. Severity is a starting priority, not proof of impact. Inspect the documented false-positive explanations and record analyst judgment.

## Metrics and sample population

All calculations use UTC ISO timestamps, return seconds and display the count of completed samples. Missing pairs produce N/A; no zero is invented. Negative durations are excluded. A measured zero can be valid when timestamps coincide. Seed timings are fictional training intervals; interactive measurements are elapsed lab timings, not operational performance.

- MTTD: mean alert.timestamp minus the timestamp of its triggering event. For a threshold rule this is the fifth/default qualifying event, not the first failed attempt. This measures evaluation delay rather than time since an unknown real intrusion began.
- MTTA: mean acknowledged_at minus alert.timestamp for acknowledged alerts. Incident creation also acknowledges an open alert. Repeated acknowledgement never resets the timestamp.
- MTTC: mean first CONTAINED timeline timestamp minus the originating alert.timestamp, for contained incidents.
- MTTR: mean incident.closed_at minus originating alert.timestamp for closed cases. Closure requires recovery validation and lessons learned. The RECOVERING timestamp marks recovery start and must not be used as completion.
- Average response time on Reports is explicitly MTTA, not an additional ambiguous metric.

No adjustment is made for business hours, severity, staffing or outliers. One incident can be created per alert. Report counts use all stored records; Open Alerts means exactly OPEN, while Open Incidents means every non-CLOSED stage. Critical/High alert counts include all statuses. Events-over-time groups by UTC hour, showing only occupied buckets.

## Improvement loop

Review false positives, missed coverage, escalation rationale and completed metrics after each exercise. Record a control improvement with an owner in lessons learned. Re-run the relevant scenario and compare behavior rather than optimizing an unrepresentative synthetic score.
