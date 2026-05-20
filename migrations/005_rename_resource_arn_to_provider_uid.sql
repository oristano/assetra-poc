-- Migration 005: rename resource_arn to provider_uid.
-- provider_uid is the cloud provider's canonical fully-qualified identifier
-- (AWS ARN, Azure Resource ID, GCP Resource Name) — provider-agnostic naming.

ALTER TABLE ocsf_findings RENAME COLUMN resource_arn TO provider_uid;
