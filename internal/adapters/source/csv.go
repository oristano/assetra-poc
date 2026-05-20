package source

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/assetra/assetra-poc/internal/domain"
)

// CSVReader implements domain.SourceReader by reading local CSV files directly.
// This is the primary source adapter for the POC. Steampipe is kept configured
// for interactive SQL queries but the app reads CSVs without exec overhead.
type CSVReader struct {
	ec2Path       string
	inspectorPath string
}

// NewCSVReader creates a reader rooted at dataDir.
func NewCSVReader(dataDir string) *CSVReader {
	return &CSVReader{
		ec2Path:       filepath.Join(dataDir, "aws/ec2/mock_ec2_instances.csv"),
		inspectorPath: filepath.Join(dataDir, "aws/inspector2/mock_inspector_findings.csv"),
	}
}

func (r *CSVReader) LoadEC2Instances(ctx context.Context) ([]domain.RawEC2Instance, error) {
	records, idx, err := readCSV(r.ec2Path)
	if err != nil {
		return nil, fmt.Errorf("read ec2 csv: %w", err)
	}

	instances := make([]domain.RawEC2Instance, 0, len(records))
	for _, rec := range records {
		instances = append(instances, domain.RawEC2Instance{
			InstanceID:   field(rec, idx, "instance_id"),
			Name:         field(rec, idx, "name"),
			State:        field(rec, idx, "state"),
			InstanceType: field(rec, idx, "instance_type"),
			PrivateIP:    field(rec, idx, "private_ip"),
			PublicIP:     field(rec, idx, "public_ip"),
			Platform:     field(rec, idx, "platform"),
			Region:       field(rec, idx, "region"),
			AccountID:    field(rec, idx, "account_id"),
			TagsJSON:     field(rec, idx, "tags_json"),
		})
	}
	return instances, nil
}

func (r *CSVReader) LoadInspectorFindings(ctx context.Context) ([]domain.RawInspectorFinding, error) {
	records, idx, err := readCSV(r.inspectorPath)
	if err != nil {
		return nil, fmt.Errorf("read inspector csv: %w", err)
	}

	findings := make([]domain.RawInspectorFinding, 0, len(records))
	for _, rec := range records {
		findings = append(findings, domain.RawInspectorFinding{
			FindingARN:       field(rec, idx, "finding_arn"),
			AWSAccountID:     field(rec, idx, "aws_account_id"),
			ResourceID:       field(rec, idx, "resource_id"),
			ResourceType:     field(rec, idx, "resource_type"),
			FindingType:      field(rec, idx, "finding_type"),
			Severity:         field(rec, idx, "severity"),
			Status:           field(rec, idx, "status"),
			Title:            field(rec, idx, "title"),
			Description:      field(rec, idx, "description"),
			CVEID:            field(rec, idx, "cve_id"),
			PackageName:      field(rec, idx, "package_name"),
			InstalledVersion: field(rec, idx, "installed_version"),
			FixedVersion:     field(rec, idx, "fixed_version"),
			FirstObservedAt:  field(rec, idx, "first_observed_at"),
			LastObservedAt:   field(rec, idx, "last_observed_at"),
		})
	}
	return findings, nil
}

// readCSV opens a CSV file and returns all data rows plus a column→index map.
func readCSV(path string) ([][]string, map[string]int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.TrimLeadingSpace = true

	header, err := r.Read()
	if err != nil {
		return nil, nil, fmt.Errorf("read header from %s: %w", path, err)
	}

	idx := make(map[string]int, len(header))
	for i, h := range header {
		idx[h] = i
	}

	var records [][]string
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read record from %s: %w", path, err)
		}
		records = append(records, rec)
	}

	return records, idx, nil
}

// field safely returns the value at column name from a record row.
func field(rec []string, idx map[string]int, col string) string {
	i, ok := idx[col]
	if !ok || i >= len(rec) {
		return ""
	}
	return rec[i]
}
