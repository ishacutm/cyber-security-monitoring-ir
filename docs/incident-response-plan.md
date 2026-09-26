# Incident response plan

This plan is a safe teaching workflow. Every response button changes SQLite records only; it never disables accounts, blocks addresses, kills processes, deletes files or restores a real machine.

1. Preparation: agree on fictional assets, severity criteria, analyst responsibilities, communication owners and success criteria. Review the rule catalog and the documentation IP range. Use only synthetic evidence.
2. Detection: collect normalized events, evaluate rules and inspect alerts with their underlying events. A detection entry preserves alert time on the incident timeline.
3. Analysis: acknowledge the alert, validate context and possible false positives, assess affected host/user and business impact, then create an incident if appropriate. Start Investigation moves OPEN to INVESTIGATING. Enter the initial hypothesis; update the root-cause field as evidence develops.
4. Containment: record a simulated isolation or access-restriction decision and its rationale, scope and business trade-offs. Contain Incident moves to CONTAINED without taking action on the host.
5. Eradication: record which fictional cause would be removed, such as a test configuration error or unauthorized role assignment. Eradicate Threat moves to ERADICATED; no files, roles or processes are changed.
6. Recovery: record planned restoration and validation checks, then Begin Recovery. RECOVERING means the recovery process has started, not that service is known to be restored.
7. Closure and lessons learned: confirm synthetic recovery checks are complete; document lessons learned and an improvement owner. Close Incident moves to CLOSED, records closed_at and closes the linked alert. Recovery summary can be updated with detailed validation before closure.

Each transition requires a nonempty analyst note of at most 4000 characters. State, timestamp, timeline and audit updates are atomic. Out-of-order or repeated transitions fail safely. Notes can be revised later, including after closure, and this adds a timeline and audit entry. There is no reopening or incident-merging feature in this assignment.

The stage sequence is an illustrative operational playbook. NIST SP 800-61 Rev. 3 frames incident response within CSF 2.0 risk management; do not describe this simple sequence as the exact NIST lifecycle. See framework-mapping.md.
