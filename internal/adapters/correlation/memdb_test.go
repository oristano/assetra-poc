package correlation_test

import (
	"context"
	"testing"

	"github.com/assetra/assetra-poc/internal/adapters/correlation"
	"github.com/assetra/assetra-poc/internal/domain"
)

func TestMemDBCorrelator_MatchedAndUnmatched(t *testing.T) {
	c := correlation.New()
	ctx := context.Background()

	instances := []domain.RawEC2Instance{
		{InstanceID: "i-001", Name: "web"},
		{InstanceID: "i-002", Name: "db"},
	}
	findings := []domain.RawInspectorFinding{
		{FindingARN: "arn:1", ResourceID: "i-001", Severity: "CRITICAL"},
		{FindingARN: "arn:2", ResourceID: "i-001", Severity: "HIGH"},
		{FindingARN: "arn:3", ResourceID: "i-999", Severity: "HIGH"}, // unmatched
	}

	result, err := c.Correlate(ctx, instances, findings)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}

	if len(result.Matched) != 2 {
		t.Fatalf("expected 2 matched assets, got %d", len(result.Matched))
	}
	if len(result.Unmatched) != 1 {
		t.Fatalf("expected 1 unmatched finding, got %d", len(result.Unmatched))
	}
	if result.Unmatched[0].FindingARN != "arn:3" {
		t.Errorf("unexpected unmatched finding: %s", result.Unmatched[0].FindingARN)
	}
}

func TestMemDBCorrelator_MultipleFindingsPerAsset(t *testing.T) {
	c := correlation.New()
	ctx := context.Background()

	instances := []domain.RawEC2Instance{{InstanceID: "i-001"}}
	findings := []domain.RawInspectorFinding{
		{FindingARN: "arn:1", ResourceID: "i-001"},
		{FindingARN: "arn:2", ResourceID: "i-001"},
		{FindingARN: "arn:3", ResourceID: "i-001"},
	}

	result, err := c.Correlate(ctx, instances, findings)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}

	if len(result.Matched[0].Findings) != 3 {
		t.Errorf("expected 3 findings on i-001, got %d", len(result.Matched[0].Findings))
	}
}

func TestMemDBCorrelator_AssetWithNoFindings(t *testing.T) {
	c := correlation.New()
	ctx := context.Background()

	instances := []domain.RawEC2Instance{
		{InstanceID: "i-001"},
		{InstanceID: "i-002"}, // no findings
	}
	findings := []domain.RawInspectorFinding{
		{FindingARN: "arn:1", ResourceID: "i-001"},
	}

	result, err := c.Correlate(ctx, instances, findings)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}

	if len(result.Matched) != 2 {
		t.Fatalf("expected both assets in Matched, got %d", len(result.Matched))
	}

	var i002Findings int
	for _, m := range result.Matched {
		if m.Instance.InstanceID == "i-002" {
			i002Findings = len(m.Findings)
		}
	}
	if i002Findings != 0 {
		t.Errorf("expected 0 findings for i-002, got %d", i002Findings)
	}
}

func TestMemDBCorrelator_EmptyInputs(t *testing.T) {
	c := correlation.New()
	ctx := context.Background()

	result, err := c.Correlate(ctx, nil, nil)
	if err != nil {
		t.Fatalf("Correlate with empty inputs: %v", err)
	}
	if len(result.Matched) != 0 || len(result.Unmatched) != 0 {
		t.Errorf("expected empty result, got matched=%d unmatched=%d",
			len(result.Matched), len(result.Unmatched))
	}
}

func TestMemDBCorrelator_Idempotent(t *testing.T) {
	c := correlation.New()
	ctx := context.Background()

	instances := []domain.RawEC2Instance{{InstanceID: "i-001", Name: "web"}}
	findings := []domain.RawInspectorFinding{
		{FindingARN: "arn:1", ResourceID: "i-001", Severity: "HIGH"},
	}

	r1, err := c.Correlate(ctx, instances, findings)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := c.Correlate(ctx, instances, findings)
	if err != nil {
		t.Fatal(err)
	}

	if len(r1.Matched) != len(r2.Matched) {
		t.Errorf("results differ between calls: %d vs %d", len(r1.Matched), len(r2.Matched))
	}
}
