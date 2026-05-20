package domain

import "context"

// SourceReader abstracts the data source layer (CSV files, Steampipe, AWS API, …).
type SourceReader interface {
	LoadEC2Instances(ctx context.Context) ([]RawEC2Instance, error)
	LoadInspectorFindings(ctx context.Context) ([]RawInspectorFinding, error)
}

// OCSFStorage abstracts the persistence layer for OCSF findings.
type OCSFStorage interface {
	UpsertOCSFFinding(ctx context.Context, f OCSFFinding) error
	GetInspectResult(ctx context.Context, customerID string) (InspectResult, error)
	ResetAll(ctx context.Context) error
}
