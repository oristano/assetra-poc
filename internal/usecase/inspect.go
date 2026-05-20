package usecase

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/assetra/assetra-poc/internal/domain"
)

// InspectUseCase queries the OCSF findings table and returns a summary.
type InspectUseCase struct {
	storage    domain.OCSFStorage
	customerID string
	logger     *slog.Logger
}

func NewInspectUseCase(storage domain.OCSFStorage, customerID string, logger *slog.Logger) *InspectUseCase {
	return &InspectUseCase{storage: storage, customerID: customerID, logger: logger}
}

func (u *InspectUseCase) Run(ctx context.Context) (domain.InspectResult, error) {
	result, err := u.storage.GetInspectResult(ctx, u.customerID)
	if err != nil {
		return domain.InspectResult{}, fmt.Errorf("get inspect result: %w", err)
	}

	u.logger.Info("inspect summary",
		slog.String("customer_id", u.customerID),
		slog.Int("total_findings", result.TotalFindings),
		slog.Int("unique_assets", result.UniqueAssets),
	)

	return result, nil
}
