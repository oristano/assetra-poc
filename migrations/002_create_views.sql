-- Migration 002: diagnostic view over OCSF findings

CREATE OR REPLACE VIEW ocsf_asset_summary AS
SELECT
    customer_id,
    resource_uid,
    resource_name,
    region,
    account_id,
    COUNT(*)        AS finding_count,
    MAX(severity_id) AS max_severity_id,
    MIN(time)       AS first_seen_ms,
    MAX(time)       AS last_seen_ms
FROM ocsf_findings
GROUP BY customer_id, resource_uid, resource_name, region, account_id;
