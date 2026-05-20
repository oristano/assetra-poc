-- Migration 003: flatten ocsf_findings into a complete data-product table.
-- Every field a customer needs is a queryable column; raw stays for auditability.
-- resource_details holds asset-type-specific fields so the schema never changes
-- when new asset types (RDS, Lambda, …) are added.

ALTER TABLE ocsf_findings
    ADD COLUMN IF NOT EXISTS title             TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS description       TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS resource_type     TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS resource_details  JSONB NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS installed_version TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS fixed_version     TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_observed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_observed_at  TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_ocsf_resource_type
    ON ocsf_findings (customer_id, resource_type);

CREATE INDEX IF NOT EXISTS idx_ocsf_cve
    ON ocsf_findings (cve_id) WHERE cve_id != '';

-- Replace the diagnostic view to expose all flat columns.
DROP VIEW IF EXISTS ocsf_asset_summary;
CREATE VIEW ocsf_asset_summary AS
SELECT
    customer_id,
    resource_uid,
    resource_name,
    resource_type,
    region,
    account_id,
    COUNT(*)         AS finding_count,
    MAX(severity_id) AS max_severity_id,
    MIN(first_observed_at) AS first_seen,
    MAX(last_observed_at)  AS last_seen
FROM ocsf_findings
GROUP BY customer_id, resource_uid, resource_name, resource_type, region, account_id;
