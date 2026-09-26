# Detection rule catalog

All data sources are synthetic. No real telemetry is inspected.

## RULE-001 — Repeated failed logins

Purpose: Repeated failures for one source IP and user.

Data source: Local simulator events table and synthetic raw JSON.

Detection logic: At least the configured threshold in the rolling time window; suppress repeat alerts for that pair for one window.

Severity: HIGH

Possible false positives: Mistyped passwords, a stale application password, or a shared test account.

Recommended analyst investigation: Compare user, source, timestamps, and any later successful login.

Recommended response: Review authentication history and verify with the account owner; simulate access restriction if warranted.

Conceptual mapping: Credential Access concept; T1110 Brute Force

## RULE-002 — Suspicious PowerShell

Purpose: A simulator event flagged as suspicious script activity.

Data source: Local simulator events table and synthetic raw JSON.

Detection logic: event_type equals powershell.

Severity: HIGH

Possible false positives: Approved administration or automation.

Recommended analyst investigation: Validate the operator and change ticket; inspect synthetic event details.

Recommended response: Review synthetic script context and simulate endpoint isolation.

Conceptual mapping: Execution concept; T1059.001 PowerShell

## RULE-003 — Privilege change

Purpose: A synthetic role assignment changed.

Data source: Local simulator events table and synthetic raw JSON.

Detection logic: event_type equals privilege_change.

Severity: HIGH

Possible false positives: Approved access provisioning.

Recommended analyst investigation: Check the fictional approver, role, and business need.

Recommended response: Verify authorization and record a simulated role rollback.

Conceptual mapping: Privilege Escalation concept; no technique attribution

## RULE-004 — Malware indicator

Purpose: A fictitious endpoint protection verdict; no malware exists.

Data source: Local simulator events table and synthetic raw JSON.

Detection logic: event_type equals malware.

Severity: CRITICAL

Possible false positives: A benign test artifact incorrectly classified by a sensor.

Recommended analyst investigation: Validate the synthetic verdict and determine the affected host scope.

Recommended response: Simulate containment and record clean recovery validation.

Conceptual mapping: No unique ATT&CK technique inferred from a malware label

## RULE-005 — Important file change

Purpose: A simulated important configuration file changed.

Data source: Local simulator events table and synthetic raw JSON.

Detection logic: event_type equals file_modification.

Severity: MEDIUM

Possible false positives: Approved deployment or configuration update.

Recommended analyst investigation: Review the fictional change ticket and baseline differences.

Recommended response: Compare the approved baseline and simulate restoring it.

Conceptual mapping: No unique tactic or technique without change context

## RULE-006 — Network anomaly

Purpose: A synthetic unusual connection pattern.

Data source: Local simulator events table and synthetic raw JSON.

Detection logic: event_type equals network_anomaly.

Severity: MEDIUM

Possible false positives: Legitimate scheduled synchronization.

Recommended analyst investigation: Inspect timing, frequency, destination and business purpose.

Recommended response: Investigate destination context and simulate an egress restriction.

Conceptual mapping: Command and Control concept only; no proof of C2

## RULE-007 — Account creation

Purpose: A new fictional account needs validation.

Data source: Local simulator events table and synthetic raw JSON.

Detection logic: event_type equals account_creation.

Severity: MEDIUM

Possible false positives: Authorized onboarding.

Recommended analyst investigation: Compare account creation to the approved request.

Recommended response: Verify provisioning approval; record simulated suspension if unapproved.

Conceptual mapping: Persistence concept only; legitimate creation is common

## RULE-008 — Normal activity

Purpose: Routine simulated activity and successful logins are stored without alerts.

Data source: Local simulator events table and synthetic raw JSON.

Detection logic: normal and successful_login produce no alert.

Severity: LOW

Possible false positives: Not applicable: no alert generated.

Recommended analyst investigation: Use as context alongside suspicious events.

Recommended response: Retain for context; no response required.

Conceptual mapping: None
