# Communication plan

This is a tabletop plan. The application sends no emails, messages or notifications. All recipients are fictional roles, and no real contact details are stored.

SOC / IT
When: on detection, triage and each response stage.
Share: incident number, synthetic timestamps, indicator summary, affected host/user, current severity, evidence confidence and next action.
Owner: assigned analyst (represented by local_analyst in the app).

Security Lead
When: critical/high cases, scope changes, uncertain containment or conflicting priorities.
Share: validated facts, uncertainty, impact assessment, proposed containment, resource needs and decision log.
Owner: SOC analyst; lead approves escalation and response coordination.

System Owner
When: the affected fictional service is identified and before simulated containment/recovery decisions.
Share: service scope, expected disruption, alternatives and recovery validation criteria.
Owner: Security Lead coordinates with SOC / IT.

Legal / Privacy
When: suspected personal-data exposure, contractual notification concerns or evidence-preservation questions.
Share: minimum necessary facts, data categories, known/unknown scope, timestamps and relevant contractual context.
Owner: Security Lead requests review; Legal / Privacy determines obligations.

Management
When: material business impact, critical cases or major response decisions.
Share: concise impact summary, confidence level, response status, decisions needed and next update time.
Owner: Security Lead.

Communications
When: a stakeholder statement may be needed.
Share: approved facts, approved audience, holding statement and update cadence. Avoid speculation and unsupported attribution.
Owner: Communications drafts; Security Lead, Legal / Privacy and Management approve as appropriate.

External parties
When: approved obligations or operational needs justify contact with customers, partners, providers or authorities.
Share: only approved, necessary information through verified channels.
Owner: authorized Communications or Legal / Privacy representative; analysts do not independently disclose data.

Suggested exercise update format: incident number; classification (SIMULATED); time in UTC; confirmed facts; unknowns; impact; actions completed; decisions required; next update time; communication owner.

Actual legal/regulatory requirements depend on jurisdiction, contract, organization and incident type. No universal reporting deadline is assumed here. This educational plan is not a determination of legal obligations.
