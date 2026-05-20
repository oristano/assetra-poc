-- Migration 006: add network exposure classification to ocsf_findings.
-- Phase 1 uses a simplified algorithm (public IP presence as proxy).
-- Phase 2 will replace this with full path evaluation once SG/routing data is available.
-- exposure_confidence tracks how much data backed the classification.

ALTER TABLE ocsf_findings
    ADD COLUMN IF NOT EXISTS exposure_class      TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS exposure_confidence TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS exposure_evidence   JSONB NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_ocsf_exposure
    ON ocsf_findings (customer_id, exposure_class);
