# Illustrative escalation matrix

These are teaching priorities, not organizational SLAs. A sensor label alone does not establish actual compromise or impact. Analysts validate the evidence and business context first.

CRITICAL
Meaning: major simulated business impact, fictitious malware/ransomware indicator, or potentially widespread compromise.
Owner: SOC analyst immediately escalates to Security Lead and System Owner; Management is informed as impact is assessed.
Exercise target: acknowledge within 5 minutes; begin containment planning immediately after validation.
Example: simulated malware verdict on LAB-WINDOWS-01. No malware is present.

HIGH
Meaning: suspicious privileged-account activity, repeated authentication failures, or significant endpoint activity.
Owner: SOC / IT with Security Lead review and System Owner consultation.
Exercise target: acknowledge within 15 minutes; prioritize evidence review and containment decisions.
Example: five failures from one source/user or synthetic PowerShell activity.

MEDIUM
Meaning: limited suspicious activity needing investigation.
Owner: SOC / IT; consult the System Owner; escalate if scope or impact increases.
Exercise target: acknowledge within 60 minutes and document investigation in the exercise session.
Example: unapproved configuration change, network anomaly or new account.

LOW
Meaning: informational or low-risk events.
Owner: SOC / IT during routine review.
Exercise target: review when correlated context makes it relevant.
Example: normal service checks and successful logins. These events produce no alerts.

Application behavior: rules assign fixed initial severity. The application displays and filters it, but does not send notifications or enforce timers. Incident severity inherits the source alert. A production escalation process must support reassessment, ownership changes and organization-approved time targets.
