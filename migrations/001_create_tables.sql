-- Migration 001: OCSF findings table
-- One row per correlated (asset, finding) pair.
-- All in-memory correlation happens before insert; only matched results land here.

CREATE TABLE IF NOT EXISTS schema_migrations (
    filename   TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ocsf_findings (
    id            UUID PRIMARY KEY,
    customer_id   TEXT NOT NULL,
    account_id    TEXT NOT NULL,
    class_uid     INT NOT NULL DEFAULT 2004,  -- OCSF: Vulnerability Finding
    severity_id   INT NOT NULL,               -- OCSF severity 1-5
    severity      TEXT NOT NULL,
    status_id     INT NOT NULL,               -- OCSF status
    status        TEXT NOT NULL,
    region        TEXT NOT NULL,
    finding_uid   TEXT NOT NULL,              -- source finding ARN
    resource_uid  TEXT NOT NULL,              -- EC2 instance_id
    resource_name TEXT NOT NULL DEFAULT '',
    cve_id        TEXT NOT NULL DEFAULT '',
    package_name  TEXT NOT NULL DEFAULT '',
    time          BIGINT NOT NULL,            -- epoch ms of last_observed_at
    raw           JSONB NOT NULL,             -- full OCSF document
    UNIQUE (customer_id, finding_uid)
);

CREATE INDEX IF NOT EXISTS idx_ocsf_customer   ON ocsf_findings (customer_id);
CREATE INDEX IF NOT EXISTS idx_ocsf_resource   ON ocsf_findings (customer_id, resource_uid);
CREATE INDEX IF NOT EXISTS idx_ocsf_severity   ON ocsf_findings (customer_id, severity_id DESC);
