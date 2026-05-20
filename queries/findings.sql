-- All OCSF findings ordered by severity
SELECT
    finding_uid,
    resource_uid    AS instance_id,
    resource_name,
    region,
    severity,
    status,
    cve_id,
    package_name,
    TO_TIMESTAMP(time / 1000.0) AS last_observed_at
FROM ocsf_findings
WHERE customer_id = '12345'
ORDER BY severity_id DESC, time DESC;

-- Raw OCSF document for a specific finding
SELECT raw
FROM ocsf_findings
WHERE customer_id = '12345'
  AND finding_uid = 'arn:aws:inspector2:us-east-1:123456789012:finding/abc001';
