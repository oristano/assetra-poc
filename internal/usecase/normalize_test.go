package usecase_test

import (
	"testing"

	"github.com/assetra/assetra-poc/internal/domain"
	"github.com/assetra/assetra-poc/internal/usecase"
)

func TestNormalizeToOCSF_BasicFields(t *testing.T) {
	inst := domain.RawEC2Instance{
		InstanceID:   "i-001",
		Name:         "web-server-1",
		Region:       "us-east-1",
		AccountID:    "123456789012",
		InstanceType: "t3.medium",
	}
	finding := domain.RawInspectorFinding{
		FindingARN:   "arn:aws:inspector2:us-east-1:123456789012:finding/abc001",
		AWSAccountID: "123456789012",
		ResourceID:   "i-001",
		Severity:     "CRITICAL",
		Status:       "ACTIVE",
		CVEID:        "CVE-2021-44228",
		PackageName:  "log4j-core",
		LastObservedAt: "2024-01-15T00:00:00Z",
	}

	record := usecase.NormalizeToOCSF(inst, finding, "12345")

	if record.CustomerID != "12345" {
		t.Errorf("expected customer_id=12345, got %s", record.CustomerID)
	}
	if record.ClassUID != 2004 {
		t.Errorf("expected class_uid=2004, got %d", record.ClassUID)
	}
	if record.SeverityID != 5 {
		t.Errorf("expected severity_id=5 for CRITICAL, got %d", record.SeverityID)
	}
	if record.Severity != "Critical" {
		t.Errorf("expected severity=Critical, got %s", record.Severity)
	}
	if record.StatusID != 1 {
		t.Errorf("expected status_id=1 for ACTIVE, got %d", record.StatusID)
	}
	if record.ResourceUID != "i-001" {
		t.Errorf("expected resource_uid=i-001, got %s", record.ResourceUID)
	}
	if record.FindingUID != finding.FindingARN {
		t.Errorf("expected finding_uid=%s, got %s", finding.FindingARN, record.FindingUID)
	}
	if record.ID == "" {
		t.Error("expected non-empty ID")
	}
}

func TestNormalizeToOCSF_DeterministicID(t *testing.T) {
	inst := domain.RawEC2Instance{InstanceID: "i-001"}
	finding := domain.RawInspectorFinding{FindingARN: "arn:1", AWSAccountID: "123"}

	r1 := usecase.NormalizeToOCSF(inst, finding, "12345")
	r2 := usecase.NormalizeToOCSF(inst, finding, "12345")

	if r1.ID != r2.ID {
		t.Errorf("expected deterministic ID but got %s != %s", r1.ID, r2.ID)
	}
}

func TestNormalizeToOCSF_RawContainsOCSFKeys(t *testing.T) {
	inst := domain.RawEC2Instance{InstanceID: "i-001", Region: "us-east-1"}
	finding := domain.RawInspectorFinding{
		FindingARN:   "arn:1",
		AWSAccountID: "123456789012",
		Severity:     "HIGH",
		Status:       "ACTIVE",
	}

	record := usecase.NormalizeToOCSF(inst, finding, "12345")

	if record.Raw == "" {
		t.Fatal("expected non-empty raw JSON")
	}
	for _, key := range []string{"class_uid", "severity_id", "cloud", "resource", "finding_info"} {
		if !contains(record.Raw, key) {
			t.Errorf("raw JSON missing expected key: %s", key)
		}
	}
}

func TestNormalizeToOCSF_SeverityMapping(t *testing.T) {
	cases := []struct {
		input  string
		wantID int
		wantStr string
	}{
		{"CRITICAL", 5, "Critical"},
		{"HIGH", 4, "High"},
		{"MEDIUM", 3, "Medium"},
		{"LOW", 2, "Low"},
		{"INFORMATIONAL", 1, "Informational"},
		{"unknown", 0, "Unknown"},
	}

	for _, tc := range cases {
		inst := domain.RawEC2Instance{InstanceID: "i-001"}
		f := domain.RawInspectorFinding{FindingARN: "arn:x", Severity: tc.input}
		r := usecase.NormalizeToOCSF(inst, f, "12345")
		if r.SeverityID != tc.wantID {
			t.Errorf("severity %s: got id=%d, want %d", tc.input, r.SeverityID, tc.wantID)
		}
		if r.Severity != tc.wantStr {
			t.Errorf("severity %s: got str=%s, want %s", tc.input, r.Severity, tc.wantStr)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
