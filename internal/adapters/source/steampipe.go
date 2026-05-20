package source

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/assetra/assetra-poc/internal/domain"
)

// SteampipeReader implements domain.SourceReader by querying Steampipe's
// Postgres-compatible endpoint. Adding a new asset type means adding a new
// method here backed by its Steampipe connection (CSV, AWS, GCP, etc.).
type SteampipeReader struct {
	pool *pgxpool.Pool
}

func NewSteampipeReader(pool *pgxpool.Pool) *SteampipeReader {
	return &SteampipeReader{pool: pool}
}

func (r *SteampipeReader) LoadEC2Instances(ctx context.Context) ([]domain.RawEC2Instance, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT
			instance_id,
			name,
			state,
			instance_type,
			COALESCE(private_ip, '')  AS private_ip,
			COALESCE(public_ip, '')   AS public_ip,
			COALESCE(platform, '')    AS platform,
			region,
			account_id,
			COALESCE(tags_json, '')   AS tags_json
		FROM csv.mock_ec2_instances
	`)
	if err != nil {
		return nil, fmt.Errorf("query steampipe ec2 instances: %w", err)
	}
	defer rows.Close()

	var out []domain.RawEC2Instance
	for rows.Next() {
		var inst domain.RawEC2Instance
		if err := rows.Scan(
			&inst.InstanceID, &inst.Name, &inst.State, &inst.InstanceType,
			&inst.PrivateIP, &inst.PublicIP, &inst.Platform,
			&inst.Region, &inst.AccountID, &inst.TagsJSON,
		); err != nil {
			return nil, fmt.Errorf("scan ec2 instance: %w", err)
		}
		out = append(out, inst)
	}
	return out, rows.Err()
}

func (r *SteampipeReader) LoadInspectorFindings(ctx context.Context) ([]domain.RawInspectorFinding, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT
			finding_arn,
			aws_account_id,
			resource_id,
			resource_type,
			finding_type,
			severity,
			status,
			title,
			COALESCE(description, '')        AS description,
			COALESCE(cve_id, '')             AS cve_id,
			COALESCE(package_name, '')       AS package_name,
			COALESCE(installed_version, '')  AS installed_version,
			COALESCE(fixed_version, '')      AS fixed_version,
			COALESCE(first_observed_at, '')  AS first_observed_at,
			COALESCE(last_observed_at, '')   AS last_observed_at
		FROM csv.mock_inspector_findings
	`)
	if err != nil {
		return nil, fmt.Errorf("query steampipe inspector findings: %w", err)
	}
	defer rows.Close()

	var out []domain.RawInspectorFinding
	for rows.Next() {
		var f domain.RawInspectorFinding
		if err := rows.Scan(
			&f.FindingARN, &f.AWSAccountID, &f.ResourceID, &f.ResourceType, &f.FindingType,
			&f.Severity, &f.Status, &f.Title, &f.Description, &f.CVEID, &f.PackageName,
			&f.InstalledVersion, &f.FixedVersion, &f.FirstObservedAt, &f.LastObservedAt,
		); err != nil {
			return nil, fmt.Errorf("scan inspector finding: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
