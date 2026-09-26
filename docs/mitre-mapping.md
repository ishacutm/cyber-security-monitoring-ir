# Educational MITRE ATT&CK mapping

Synthetic event categories are learning prompts, not evidence of real adversary activity. A single indicator cannot prove a technique or tactic.

| Scenario | Conceptual association | Interpretation limit |
| --- | --- | --- |
| Repeated failed authentication | Credential Access; T1110 Brute Force | Failures can result from errors or stale credentials |
| Suspicious PowerShell | Execution; T1059.001 PowerShell | Legitimate administration is common; this lab executes no scripts |
| Privilege change | Privilege Escalation concept | Authorized role management is not an attack; no technique is established |
| Network anomaly | Command and Control concept | Frequency or destination alone does not prove C2 |
| Account creation | Persistence concept | Authorized onboarding is ordinary behavior |
| File change / malware label | No unique technique assigned | Need detailed behavior and context before mapping |
| Normal activity | None | Context only |

Official technique references:
- https://attack.mitre.org/techniques/T1110/
- https://attack.mitre.org/techniques/T1059/001/

The lab does not implement these adversary behaviors; it stores descriptive synthetic records only.
