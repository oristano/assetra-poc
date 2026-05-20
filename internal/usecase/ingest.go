package usecase

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/assetra/assetra-poc/internal/domain"
)

// IngestUseCase orchestrates the full pipeline:
// load assets → load findings → correlate (via SQLite) → persist OCSF records.
type IngestUseCase struct {
	source          domain.SourceReader
	correlator      Correlator
	storage         domain.OCSFStorage
	customerID      string
	scanner         string
	pipelineVersion string
	logger          *slog.Logger
}

func NewIngestUseCase(
	source domain.SourceReader,
	correlator Correlator,
	storage domain.OCSFStorage,
	customerID string,
	scanner string,
	pipelineVersion string,
	logger *slog.Logger,
) *IngestUseCase {
	return &IngestUseCase{
		source:          source,
		correlator:      correlator,
		storage:         storage,
		customerID:      customerID,
		scanner:         scanner,
		pipelineVersion: pipelineVersion,
		logger:          logger,
	}
}

// Run executes the ingest pipeline. Idempotent: repeated runs upsert, not duplicate.
func (u *IngestUseCase) Run(ctx context.Context) error {
	start := time.Now()
	u.logger.Info("ingest started", slog.String("step", "start"), slog.String("customer_id", u.customerID))

	// --- Load ---
	u.logger.Info("loading ec2 instances", slog.String("step", "load"))
	instances, err := u.source.LoadEC2Instances(ctx)
	if err != nil {
		return fmt.Errorf("load ec2 instances: %w", err)
	}
	u.logger.Info("ec2 instances loaded", slog.Int("count", len(instances)))

	u.logger.Info("loading inspector findings", slog.String("step", "load"))
	findings, err := u.source.LoadInspectorFindings(ctx)
	if err != nil {
		return fmt.Errorf("load inspector findings: %w", err)
	}
	u.logger.Info("inspector findings loaded", slog.Int("count", len(findings)))

	// --- Correlate via in-memory SQLite ---
	u.logger.Info("correlating findings to assets", slog.String("step", "correlate"))
	result, err := u.correlator.Correlate(ctx, instances, findings)
	if err != nil {
		return fmt.Errorf("correlate: %w", err)
	}

	for _, f := range result.Unmatched {
		u.logger.Warn("unmatched finding — no asset found",
			slog.String("source_finding_id", f.FindingARN),
			slog.String("resource_id", f.ResourceID),
		)
	}
	u.logger.Info("correlation complete",
		slog.Int("matched", len(findings)-len(result.Unmatched)),
		slog.Int("unmatched", len(result.Unmatched)),
	)

	// --- Persist matched pairs as OCSF records ---
	upserted := 0
	for _, corr := range result.Matched {
		for _, f := range corr.Findings {
			record := NormalizeToOCSF(corr.Instance, f, u.customerID, u.scanner, u.pipelineVersion)
			if err := u.storage.UpsertOCSFFinding(ctx, record); err != nil {
				return fmt.Errorf("upsert ocsf finding: %w", err)
			}
			upserted++
		}
	}

	u.logger.Info("ingest complete",
		slog.String("step", "done"),
		slog.Int("ocsf_records_upserted", upserted),
		slog.Int("unmatched_findings_skipped", len(result.Unmatched)),
		slog.Int64("duration_ms", time.Since(start).Milliseconds()),
	)

	return nil
}
