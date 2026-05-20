#!/bin/sh
# Loads CSV files into the 'csv' schema so the app can query them via SQL,
# exactly as it would query real Steampipe. Swap STEAMPIPE_HOST/PORT to point
# at a live Steampipe instance when proper credentials are available.
set -e

psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<'SQL'
CREATE SCHEMA csv;

CREATE TABLE csv.mock_ec2_instances (
    instance_id      TEXT,
    name             TEXT,
    state            TEXT,
    instance_type    TEXT,
    private_ip       TEXT,
    public_ip        TEXT,
    platform         TEXT,
    region           TEXT,
    account_id       TEXT,
    tags_json        TEXT
);
COPY csv.mock_ec2_instances
    FROM '/data/aws/ec2/mock_ec2_instances.csv'
    DELIMITER ',' CSV HEADER;

CREATE TABLE csv.mock_inspector_findings (
    finding_arn       TEXT,
    aws_account_id    TEXT,
    resource_id       TEXT,
    resource_type     TEXT,
    finding_type      TEXT,
    severity          TEXT,
    status            TEXT,
    title             TEXT,
    description       TEXT,
    cve_id            TEXT,
    package_name      TEXT,
    installed_version TEXT,
    fixed_version     TEXT,
    first_observed_at TEXT,
    last_observed_at  TEXT
);
COPY csv.mock_inspector_findings
    FROM '/data/aws/inspector2/mock_inspector_findings.csv'
    DELIMITER ',' CSV HEADER;
SQL
