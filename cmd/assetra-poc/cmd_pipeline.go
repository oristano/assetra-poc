package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/assetra/assetra-poc/internal/adapters/correlation"
	"github.com/assetra/assetra-poc/internal/adapters/source"
	"github.com/assetra/assetra-poc/internal/adapters/storage"
	dbpkg "github.com/assetra/assetra-poc/internal/infrastructure/db"
	"github.com/assetra/assetra-poc/internal/infrastructure/logging"
	"github.com/assetra/assetra-poc/internal/usecase"
)

func init() {
	rootCmd.AddCommand(pipelineCmd)
}

var pipelineCmd = &cobra.Command{
	Use:   "pipeline",
	Short: "Run the full pipeline: migrate → ingest → inspect",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		cfg, pool, err := initDeps(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return err
		}
		defer pool.Close()

		logger := logging.New(cfg.LogLevel)

		spPool, err := initSteampipePool(ctx, cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return err
		}
		defer spPool.Close()

		// --- Migrate ---
		fmt.Println("==> migrate")
		if err := dbpkg.RunMigrations(ctx, pool, cfg.MigrationsDir, logger); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}

		// --- Ingest ---
		fmt.Println("==> ingest")
		src := source.NewSteampipeReader(spPool)
		corr := correlation.New()
		store := storage.NewPostgresStorage(pool)
		ingestUC := usecase.NewIngestUseCase(src, corr, store, cfg.CustomerID, "amazon-inspector2", version, logger)
		if err := ingestUC.Run(ctx); err != nil {
			return fmt.Errorf("ingest: %w", err)
		}

		// --- Inspect ---
		fmt.Println("==> inspect")
		inspectUC := usecase.NewInspectUseCase(store, cfg.CustomerID, logger)
		result, err := inspectUC.Run(ctx)
		if err != nil {
			return fmt.Errorf("inspect: %w", err)
		}

		printInspectResult(cfg.CustomerID, result)
		return nil
	},
}
