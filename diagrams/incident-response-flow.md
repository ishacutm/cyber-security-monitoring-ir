# Incident response flow

```mermaid
flowchart TD
    D[Detect] --> A[Analyze]
    A --> V{Incident warranted?}
    V -->|No| F[Close alert after triage]
    V -->|Yes| C[Contain]
    C --> E[Eradicate]
    E --> R[Recover and validate]
    R --> L[Close and record lessons]
    L --> P[Improve preparation]
    P --> D
```

Buttons simulate the stages. Review evidence and false positives before creating a case. The application state machine is a simplified educational playbook, not an exact reproduction of a standards framework.
