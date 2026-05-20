package usecase

import (
	"context"

	"github.com/assetra/assetra-poc/internal/domain"
)

// Correlator runs in-memory correlation between source assets and findings.
// The MemDBCorrelator (adapters/correlation) is the production implementation.
// Adding a new asset type (RDS, Lambda, …) means extending the implementation —
// the interface and result types stay the same.
type Correlator interface {
	Correlate(ctx context.Context, instances []domain.RawEC2Instance, findings []domain.RawInspectorFinding) (CorrelationResult, error)
}

// CorrelatedAsset pairs one EC2 instance with all findings that target it.
type CorrelatedAsset struct {
	Instance domain.RawEC2Instance
	Findings []domain.RawInspectorFinding
}

// CorrelationResult is returned by every Correlator implementation.
type CorrelationResult struct {
	// Matched contains every known asset, even those with zero findings.
	Matched []CorrelatedAsset
	// Unmatched contains findings whose resource_id matched no known asset.
	Unmatched []domain.RawInspectorFinding
}
