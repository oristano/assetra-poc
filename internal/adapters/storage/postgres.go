package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/assetra/assetra-poc/internal/domain"
)

type PostgresStorage struct {
	pool *pgxpool.Pool
}

func NewPostgresStorage(pool *pgxpool.Pool) *PostgresStorage {
	return &PostgresStorage{pool: pool}
}

func (s *PostgresStorage) UpsertOCSFFinding(ctx context.Context, f domain.OCSFFinding) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ocsf_findings (
			id, customer_id, account_id, class_uid,
			severity_id, severity, status_id, status, region,
			finding_uid, title, description,
			resource_uid, provider_uid, resource_name, resource_type, resource_details,
			cve_id, package_name, installed_version, fixed_version,
			first_observed_at, last_observed_at, time, raw,
			scanner, pipeline_version,
			exposure_class, exposure_confidence, exposure_evidence
		) VALUES (
			$1::uuid, $2, $3, $4,
			$5, $6, $7, $8, $9,
			$10, $11, $12,
			$13, $14, $15, $16, $17::jsonb,
			$18, $19, $20, $21,
			$22, $23, $24, $25::jsonb,
			$26, $27,
			$28, $29, $30::jsonb
		)
		ON CONFLICT (customer_id, finding_uid) DO UPDATE SET
			severity_id       = EXCLUDED.severity_id,
			severity          = EXCLUDED.severity,
			status_id         = EXCLUDED.status_id,
			status            = EXCLUDED.status,
			title             = EXCLUDED.title,
			description       = EXCLUDED.description,
			provider_uid      = EXCLUDED.provider_uid,
			resource_name     = EXCLUDED.resource_name,
			resource_type     = EXCLUDED.resource_type,
			resource_details  = EXCLUDED.resource_details,
			cve_id            = EXCLUDED.cve_id,
			package_name      = EXCLUDED.package_name,
			installed_version = EXCLUDED.installed_version,
			fixed_version     = EXCLUDED.fixed_version,
			first_observed_at = EXCLUDED.first_observed_at,
			last_observed_at  = EXCLUDED.last_observed_at,
			time              = EXCLUDED.time,
			raw               = EXCLUDED.raw,
			scanner            = EXCLUDED.scanner,
			pipeline_version   = EXCLUDED.pipeline_version,
			exposure_class     = EXCLUDED.exposure_class,
			exposure_confidence = EXCLUDED.exposure_confidence,
			exposure_evidence  = EXCLUDED.exposure_evidence
	`,
		f.ID, f.CustomerID, f.AccountID, f.ClassUID,
		f.SeverityID, f.Severity, f.StatusID, f.Status, f.Region,
		f.FindingUID, f.Title, f.Description,
		f.ResourceUID, f.ProviderUID, f.ResourceName, f.ResourceType, f.ResourceDetails,
		f.CVEID, f.PackageName, f.InstalledVersion, f.FixedVersion,
		parseRFC3339(f.FirstObservedAt), parseRFC3339(f.LastObservedAt), f.Time, f.Raw,
		f.Scanner, f.PipelineVersion,
		f.ExposureClass, f.ExposureConfidence, f.ExposureEvidence,
	)
	if err != nil {
		return fmt.Errorf("upsert ocsf finding %s: %w", f.FindingUID, err)
	}
	return nil
}

func (s *PostgresStorage) GetInspectResult(ctx context.Context, customerID string) (domain.InspectResult, error) {
	var result domain.InspectResult

	if err := s.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM ocsf_findings WHERE customer_id = $1", customerID,
	).Scan(&result.TotalFindings); err != nil {
		return result, fmt.Errorf("count findings: %w", err)
	}

	if err := s.pool.QueryRow(ctx,
		"SELECT COUNT(DISTINCT resource_uid) FROM ocsf_findings WHERE customer_id = $1", customerID,
	).Scan(&result.UniqueAssets); err != nil {
		return result, fmt.Errorf("count unique assets: %w", err)
	}

	// Severity breakdown
	sevRows, err := s.pool.Query(ctx,
		"SELECT severity, COUNT(*) FROM ocsf_findings WHERE customer_id = $1 GROUP BY severity", customerID,
	)
	if err != nil {
		return result, fmt.Errorf("query severity breakdown: %w", err)
	}
	result.BySeverity = make(map[string]int)
	for sevRows.Next() {
		var sev string
		var cnt int
		if err := sevRows.Scan(&sev, &cnt); err != nil {
			sevRows.Close()
			return result, fmt.Errorf("scan severity row: %w", err)
		}
		result.BySeverity[sev] = cnt
	}
	sevRows.Close()
	if err := sevRows.Err(); err != nil {
		return result, fmt.Errorf("severity rows: %w", err)
	}

	// Exposure breakdown
	expRows, err := s.pool.Query(ctx,
		"SELECT exposure_class, COUNT(*) FROM ocsf_findings WHERE customer_id = $1 GROUP BY exposure_class", customerID,
	)
	if err != nil {
		return result, fmt.Errorf("query exposure breakdown: %w", err)
	}
	result.ByExposure = make(map[string]int)
	for expRows.Next() {
		var cls string
		var cnt int
		if err := expRows.Scan(&cls, &cnt); err != nil {
			expRows.Close()
			return result, fmt.Errorf("scan exposure row: %w", err)
		}
		result.ByExposure[cls] = cnt
	}
	expRows.Close()
	if err := expRows.Err(); err != nil {
		return result, fmt.Errorf("exposure rows: %w", err)
	}

	// Per-asset summaries: highest severity per asset
	assetRows, err := s.pool.Query(ctx, `
		WITH top AS (
			SELECT DISTINCT ON (resource_uid)
				resource_uid, resource_name, region, severity
			FROM ocsf_findings
			WHERE customer_id = $1
			ORDER BY resource_uid, severity_id DESC
		)
		SELECT t.resource_uid, t.resource_name, t.region, t.severity,
		       COUNT(f.id) AS finding_count
		FROM top t
		JOIN ocsf_findings f ON f.resource_uid = t.resource_uid AND f.customer_id = $1
		GROUP BY t.resource_uid, t.resource_name, t.region, t.severity
		ORDER BY finding_count DESC, t.resource_uid
	`, customerID)
	if err != nil {
		return result, fmt.Errorf("query asset summaries: %w", err)
	}
	defer assetRows.Close()

	for assetRows.Next() {
		var sum domain.AssetSummary
		if err := assetRows.Scan(
			&sum.ResourceUID, &sum.ResourceName, &sum.Region,
			&sum.HighestSeverity, &sum.FindingCount,
		); err != nil {
			return result, fmt.Errorf("scan asset summary: %w", err)
		}
		result.Summaries = append(result.Summaries, sum)
	}
	if err := assetRows.Err(); err != nil {
		return result, err
	}

	// Individual findings — all flat columns, ordered by severity desc
	findingRows, err := s.pool.Query(ctx, `
		SELECT
			id, customer_id, account_id, class_uid,
			severity_id, severity, status_id, status, region,
			finding_uid, title, description,
			resource_uid, provider_uid, resource_name, resource_type,
			resource_details::text,
			cve_id, package_name, installed_version, fixed_version,
			COALESCE(to_char(first_observed_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), '') AS first_observed_at,
			COALESCE(to_char(last_observed_at,  'YYYY-MM-DD"T"HH24:MI:SS"Z"'), '') AS last_observed_at,
			time,
			scanner, pipeline_version,
			exposure_class, exposure_confidence, exposure_evidence::text
		FROM ocsf_findings
		WHERE customer_id = $1
		ORDER BY severity_id DESC, resource_uid, finding_uid
	`, customerID)
	if err != nil {
		return result, fmt.Errorf("query findings: %w", err)
	}
	defer findingRows.Close()

	for findingRows.Next() {
		var f domain.OCSFFinding
		if err := findingRows.Scan(
			&f.ID, &f.CustomerID, &f.AccountID, &f.ClassUID,
			&f.SeverityID, &f.Severity, &f.StatusID, &f.Status, &f.Region,
			&f.FindingUID, &f.Title, &f.Description,
			&f.ResourceUID, &f.ProviderUID, &f.ResourceName, &f.ResourceType,
			&f.ResourceDetails,
			&f.CVEID, &f.PackageName, &f.InstalledVersion, &f.FixedVersion,
			&f.FirstObservedAt, &f.LastObservedAt,
			&f.Time,
			&f.Scanner, &f.PipelineVersion,
			&f.ExposureClass, &f.ExposureConfidence, &f.ExposureEvidence,
		); err != nil {
			return result, fmt.Errorf("scan finding: %w", err)
		}
		result.Findings = append(result.Findings, f)
	}

	return result, findingRows.Err()
}

func (s *PostgresStorage) ResetAll(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, "TRUNCATE TABLE ocsf_findings")
	if err != nil {
		return fmt.Errorf("reset ocsf_findings: %w", err)
	}
	return nil
}

func parseRFC3339(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}
