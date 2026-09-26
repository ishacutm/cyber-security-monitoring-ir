PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, event_type TEXT NOT NULL,
 username TEXT NOT NULL, source_ip TEXT NOT NULL, hostname TEXT NOT NULL,
 description TEXT NOT NULL, severity TEXT NOT NULL, raw_event TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS event_correlation ON events(event_type,source_ip,username,timestamp);
CREATE TABLE IF NOT EXISTS alerts (
 id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, rule_name TEXT NOT NULL,
 event_id INTEGER NOT NULL REFERENCES events(id), severity TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN','ACKNOWLEDGED','CLOSED')),
 hostname TEXT NOT NULL, username TEXT NOT NULL, source_ip TEXT NOT NULL,
 title TEXT NOT NULL, description TEXT NOT NULL,
 rule_id TEXT NOT NULL, acknowledged_at TEXT, closed_at TEXT,
 UNIQUE(event_id,rule_id)
);
CREATE INDEX IF NOT EXISTS alert_correlation ON alerts(rule_id,source_ip,username,timestamp);
CREATE TABLE IF NOT EXISTS incidents (
 id INTEGER PRIMARY KEY, incident_number TEXT UNIQUE NOT NULL, title TEXT NOT NULL,
 severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'OPEN'
 CHECK(status IN ('OPEN','INVESTIGATING','CONTAINED','ERADICATED','RECOVERING','CLOSED')),
 description TEXT NOT NULL, affected_host TEXT NOT NULL, affected_user TEXT NOT NULL,
 source_ip TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, closed_at TEXT,
 root_cause TEXT NOT NULL DEFAULT '', containment_summary TEXT NOT NULL DEFAULT '',
 eradication_summary TEXT NOT NULL DEFAULT '', recovery_summary TEXT NOT NULL DEFAULT '',
 lessons_learned TEXT NOT NULL DEFAULT '',
 alert_id INTEGER NOT NULL UNIQUE REFERENCES alerts(id)
);
CREATE TABLE IF NOT EXISTS incident_timeline (
 id INTEGER PRIMARY KEY, incident_id INTEGER NOT NULL REFERENCES incidents(id),
 timestamp TEXT NOT NULL, action TEXT NOT NULL, description TEXT NOT NULL, performed_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_logs (
 id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, action TEXT NOT NULL,
 entity_type TEXT NOT NULL, entity_id INTEGER NOT NULL, description TEXT NOT NULL
);
