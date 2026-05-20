-- Migration 004: add provenance columns for cloud resource identity,
-- vulnerability scanner source, and pipeline version.

ALTER TABLE ocsf_findings
    ADD COLUMN IF NOT EXISTS resource_arn     TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS scanner          TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS pipeline_version TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_ocsf_scanner
    ON ocsf_findings (customer_id, scanner);
