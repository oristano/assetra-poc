// Package correlation provides an in-memory SQLite correlator that joins
// asset tables with security findings.
//
// # Adding a new asset type
//
// When RDS (or Lambda, ECS, …) support is added:
//  1. Add RawRDSInstance to domain/entities.go
//  2. Add an rds_instances table in createSchema()
//  3. Add a bulk-insert call in Load()
//  4. The existing JOIN query picks up new assets automatically because the
//     LEFT JOIN is against the ec2_instances table; add a UNION ALL branch
//     in queryMatched() for the new type
//  5. Extend queryUnmatched() with an extra NOT EXISTS clause
package correlation

import (
	"context"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/assetra/assetra-poc/internal/domain"
	"github.com/assetra/assetra-poc/internal/usecase"
)

// MemDBCorrelator implements usecase.Correlator using an in-memory SQLite
// database. Each call to Correlate opens a fresh DB, loads the data, runs
// SQL JOINs, and closes the DB. This keeps the implementation stateless and
// safe for concurrent use.
type MemDBCorrelator struct{}

func New() *MemDBCorrelator { return &MemDBCorrelator{} }

// Correlate loads instances and findings into SQLite, runs a LEFT JOIN to
// match findings to assets, and returns matched pairs plus unmatched findings.
func (m *MemDBCorrelator) Correlate(
	ctx context.Context,
	instances []domain.RawEC2Instance,
	findings []domain.RawInspectorFinding,
) (usecase.CorrelationResult, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return usecase.CorrelationResult{}, fmt.Errorf("open in-memory sqlite: %w", err)
	}
	defer db.Close()

	if err := createSchema(ctx, db); err != nil {
		return usecase.CorrelationResult{}, fmt.Errorf("create schema: %w", err)
	}
	if err := loadEC2(ctx, db, instances); err != nil {
		return usecase.CorrelationResult{}, fmt.Errorf("load ec2 instances: %w", err)
	}
	if err := loadFindings(ctx, db, findings); err != nil {
		return usecase.CorrelationResult{}, fmt.Errorf("load findings: %w", err)
	}

	matched, err := queryMatched(ctx, db)
	if err != nil {
		return usecase.CorrelationResult{}, fmt.Errorf("query matched: %w", err)
	}
	unmatched, err := queryUnmatched(ctx, db)
	if err != nil {
		return usecase.CorrelationResult{}, fmt.Errorf("query unmatched: %w", err)
	}

	return usecase.CorrelationResult{Matched: matched, Unmatched: unmatched}, nil
}

// createSchema sets up the in-memory tables.
// Add new asset tables here when new asset types are introduced.
func createSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
		CREATE TABLE ec2_instances (
			instance_id   TEXT PRIMARY KEY,
			name          TEXT NOT NULL DEFAULT '',
			state         TEXT NOT NULL DEFAULT '',
			instance_type TEXT NOT NULL DEFAULT '',
			private_ip    TEXT NOT NULL DEFAULT '',
			public_ip     TEXT NOT NULL DEFAULT '',
			platform      TEXT NOT NULL DEFAULT '',
			region        TEXT NOT NULL DEFAULT '',
			account_id    TEXT NOT NULL DEFAULT '',
			tags_json     TEXT NOT NULL DEFAULT '{}'
		);

		-- findings are asset-type-agnostic: resource_id joins to whichever
		-- asset table owns that ID.
		CREATE TABLE findings (
			finding_arn       TEXT PRIMARY KEY,
			aws_account_id    TEXT NOT NULL DEFAULT '',
			resource_id       TEXT NOT NULL,
			resource_type     TEXT NOT NULL DEFAULT '',
			finding_type      TEXT NOT NULL DEFAULT '',
			severity          TEXT NOT NULL DEFAULT '',
			status            TEXT NOT NULL DEFAULT '',
			title             TEXT NOT NULL DEFAULT '',
			description       TEXT NOT NULL DEFAULT '',
			cve_id            TEXT NOT NULL DEFAULT '',
			package_name      TEXT NOT NULL DEFAULT '',
			installed_version TEXT NOT NULL DEFAULT '',
			fixed_version     TEXT NOT NULL DEFAULT '',
			first_observed_at TEXT NOT NULL DEFAULT '',
			last_observed_at  TEXT NOT NULL DEFAULT ''
		);

		CREATE INDEX idx_findings_resource ON findings (resource_id);
	`)
	return err
}

// loadEC2 bulk-inserts EC2 instances inside a transaction.
func loadEC2(ctx context.Context, db *sql.DB, instances []domain.RawEC2Instance) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO ec2_instances
		  (instance_id, name, state, instance_type, private_ip, public_ip,
		   platform, region, account_id, tags_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, i := range instances {
		tags := i.TagsJSON
		if tags == "" {
			tags = "{}"
		}
		if _, err := stmt.ExecContext(ctx,
			i.InstanceID, i.Name, i.State, i.InstanceType,
			i.PrivateIP, i.PublicIP, i.Platform, i.Region,
			i.AccountID, tags,
		); err != nil {
			tx.Rollback()
			return fmt.Errorf("insert ec2 %s: %w", i.InstanceID, err)
		}
	}
	return tx.Commit()
}

// loadFindings bulk-inserts Inspector2 findings inside a transaction.
func loadFindings(ctx context.Context, db *sql.DB, findings []domain.RawInspectorFinding) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO findings
		  (finding_arn, aws_account_id, resource_id, resource_type, finding_type,
		   severity, status, title, description, cve_id, package_name,
		   installed_version, fixed_version, first_observed_at, last_observed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, f := range findings {
		if _, err := stmt.ExecContext(ctx,
			f.FindingARN, f.AWSAccountID, f.ResourceID, f.ResourceType, f.FindingType,
			f.Severity, f.Status, f.Title, f.Description, f.CVEID, f.PackageName,
			f.InstalledVersion, f.FixedVersion, f.FirstObservedAt, f.LastObservedAt,
		); err != nil {
			tx.Rollback()
			return fmt.Errorf("insert finding %s: %w", f.FindingARN, err)
		}
	}
	return tx.Commit()
}

// queryMatched returns all assets LEFT JOINed with their findings.
// Assets with no findings are included with an empty Findings slice.
//
// When a new asset type is added, add a UNION ALL branch here that joins
// the new asset table with findings using the appropriate resource ID column.
func queryMatched(ctx context.Context, db *sql.DB) ([]usecase.CorrelatedAsset, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT
			a.instance_id, a.name, a.state, a.instance_type,
			a.private_ip,  a.public_ip, a.platform, a.region, a.account_id, a.tags_json,
			f.finding_arn,       f.aws_account_id,    f.resource_id,
			f.resource_type,     f.finding_type,      f.severity,
			f.status,            f.title,             f.description,
			f.cve_id,            f.package_name,      f.installed_version,
			f.fixed_version,     f.first_observed_at, f.last_observed_at
		FROM ec2_instances a
		LEFT JOIN findings f ON f.resource_id = a.instance_id
		ORDER BY a.instance_id, f.finding_arn
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Group findings by asset; preserve insertion order.
	grouped := make(map[string]*usecase.CorrelatedAsset)
	order := make([]string, 0)

	for rows.Next() {
		var inst domain.RawEC2Instance
		var (
			findingARN, awsAccountID, resourceID, resourceType sql.NullString
			findingType, severity, status, title, desc         sql.NullString
			cveID, pkgName, installedVer, fixedVer             sql.NullString
			firstObserved, lastObserved                        sql.NullString
		)

		if err := rows.Scan(
			&inst.InstanceID, &inst.Name, &inst.State, &inst.InstanceType,
			&inst.PrivateIP, &inst.PublicIP, &inst.Platform, &inst.Region,
			&inst.AccountID, &inst.TagsJSON,
			&findingARN, &awsAccountID, &resourceID, &resourceType,
			&findingType, &severity, &status, &title, &desc,
			&cveID, &pkgName, &installedVer, &fixedVer,
			&firstObserved, &lastObserved,
		); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}

		if _, seen := grouped[inst.InstanceID]; !seen {
			ca := &usecase.CorrelatedAsset{Instance: inst}
			grouped[inst.InstanceID] = ca
			order = append(order, inst.InstanceID)
		}

		if findingARN.Valid {
			grouped[inst.InstanceID].Findings = append(
				grouped[inst.InstanceID].Findings,
				domain.RawInspectorFinding{
					FindingARN:       findingARN.String,
					AWSAccountID:     awsAccountID.String,
					ResourceID:       resourceID.String,
					ResourceType:     resourceType.String,
					FindingType:      findingType.String,
					Severity:         severity.String,
					Status:           status.String,
					Title:            title.String,
					Description:      desc.String,
					CVEID:            cveID.String,
					PackageName:      pkgName.String,
					InstalledVersion: installedVer.String,
					FixedVersion:     fixedVer.String,
					FirstObservedAt:  firstObserved.String,
					LastObservedAt:   lastObserved.String,
				},
			)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	result := make([]usecase.CorrelatedAsset, 0, len(order))
	for _, id := range order {
		result = append(result, *grouped[id])
	}
	return result, nil
}

// queryUnmatched returns findings whose resource_id doesn't match any known asset.
// When new asset tables are added, extend the WHERE clause with additional
// NOT EXISTS conditions.
func queryUnmatched(ctx context.Context, db *sql.DB) ([]domain.RawInspectorFinding, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT
			f.finding_arn, f.aws_account_id, f.resource_id, f.resource_type,
			f.finding_type, f.severity, f.status, f.title, f.description,
			f.cve_id, f.package_name, f.installed_version, f.fixed_version,
			f.first_observed_at, f.last_observed_at
		FROM findings f
		WHERE NOT EXISTS (
			SELECT 1 FROM ec2_instances a WHERE a.instance_id = f.resource_id
		)
		-- When RDS is added:
		-- AND NOT EXISTS (SELECT 1 FROM rds_instances r WHERE r.db_instance_id = f.resource_id)
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var unmatched []domain.RawInspectorFinding
	for rows.Next() {
		var f domain.RawInspectorFinding
		if err := rows.Scan(
			&f.FindingARN, &f.AWSAccountID, &f.ResourceID, &f.ResourceType,
			&f.FindingType, &f.Severity, &f.Status, &f.Title, &f.Description,
			&f.CVEID, &f.PackageName, &f.InstalledVersion, &f.FixedVersion,
			&f.FirstObservedAt, &f.LastObservedAt,
		); err != nil {
			return nil, fmt.Errorf("scan unmatched: %w", err)
		}
		unmatched = append(unmatched, f)
	}
	return unmatched, rows.Err()
}
