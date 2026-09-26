# Monitoring architecture

```mermaid
flowchart TD
    S[Safe event simulator] --> E[SQLite events]
    E --> D[Detection engine]
    D --> A[Alert manager]
    A --> I[Incident manager]
    I --> T[Timeline and audit]
    E --> R[Dashboard and reports]
    A --> R
    T --> R
```

All components run locally in one Flask application. Event generation and detection share an atomic transaction; each analyst action has its own transaction. No real telemetry or external system integration is present.
