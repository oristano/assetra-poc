-- All unique assets with their highest severity and finding count
SELECT
    resource_uid   AS instance_id,
    resource_name  AS name,
    region,
    account_id,
    COUNT(*)       AS finding_count,
    MAX(severity_id) AS max_severity_id,
    severity       AS highest_severity
FROM ocsf_findings
WHERE customer_id = '12345'
GROUP BY resource_uid, resource_name, region, account_id, severity
ORDER BY MAX(severity_id) DESC, resource_uid;
