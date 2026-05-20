-- Correlation summary: findings grouped per asset (from ocsf_asset_summary view)
SELECT
    resource_uid,
    resource_name,
    region,
    account_id,
    finding_count,
    max_severity_id,
    TO_TIMESTAMP(last_seen_ms / 1000.0) AS last_seen_at
FROM ocsf_asset_summary
WHERE customer_id = '12345'
ORDER BY max_severity_id DESC, finding_count DESC;

-- Full OCSF records for a specific asset
SELECT finding_uid, severity, status, cve_id, package_name, raw
FROM ocsf_findings
WHERE customer_id = '12345'
  AND resource_uid = 'i-001'
ORDER BY severity_id DESC;
