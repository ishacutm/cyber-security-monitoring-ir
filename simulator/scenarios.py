SCENARIOS = {
    "failed_login": (
        "Generate Failed Login",
        "A fictional authentication attempt failed.",
        "LOW",
    ),
    "brute_force": (
        "Generate Brute Force",
        "Five synthetic failed logins for the same source and user.",
        "HIGH",
    ),
    "successful_login": (
        "Generate Successful Login",
        "A fictional user signed in successfully.",
        "LOW",
    ),
    "powershell": (
        "Generate Suspicious PowerShell",
        "Synthetic sensor flagged unusual script activity; no script ran.",
        "HIGH",
    ),
    "privilege_change": (
        "Generate Privilege Change",
        "A fictional role changed from reader to administrator.",
        "HIGH",
    ),
    "file_modification": (
        "Generate File Modification",
        "A fictional important configuration file changed; no file was touched.",
        "MEDIUM",
    ),
    "malware": (
        "Generate Malware Detection",
        "Fictitious training indicator detected; no malware or payload exists.",
        "CRITICAL",
    ),
    "network_anomaly": (
        "Generate Suspicious Network Activity",
        "Synthetic unusual traffic pattern; no connection was made.",
        "MEDIUM",
    ),
    "account_creation": (
        "Generate Account Creation",
        "A fictional account was provisioned; no real account was created.",
        "MEDIUM",
    ),
    "normal": (
        "Generate Normal Activity",
        "Routine fictional service health check completed.",
        "LOW",
    ),
}
