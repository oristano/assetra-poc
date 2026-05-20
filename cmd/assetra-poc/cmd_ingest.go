package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/assetra/assetra-poc/internal/adapters/correlation"
	"github.com/assetra/assetra-poc/internal/adapters/source"
	"github.com/assetra/assetra-poc/internal/adapters/storage"
	"github.com/assetra/assetra-poc/internal/infrastructure/logging"
	"github.com/assetra/assetra-poc/internal/usecase"
)

func init() {
	rootCmd.AddCommand(ingestCmd)
}

var ingestCmd = &cobra.Command{
	Use:   "ingest",
	Short: "Fetch assets from Steampipe, correlate via SQLite, and store OCSF records in PostgreSQL",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		cfg, pool, err := initDeps(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return err
		}
		defer pool.Close()

		spPool, err := initSteampipePool(ctx, cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return err
		}
		defer spPool.Close()

		logger := logging.New(cfg.LogLevel)

		src := source.NewSteampipeReader(spPool)
		corr := correlation.New()
		store := storage.NewPostgresStorage(pool)
		uc := usecase.NewIngestUseCase(src, corr, store, cfg.CustomerID, "amazon-inspector2", version, logger)

		if err := uc.Run(ctx); err != nil {
			return fmt.Errorf("ingest failed: %w", err)
		}

		fmt.Println("Ingest complete.")
		return nil
	},
}
