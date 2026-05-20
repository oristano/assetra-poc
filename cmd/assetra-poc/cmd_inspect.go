package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/assetra/assetra-poc/internal/adapters/storage"
	"github.com/assetra/assetra-poc/internal/infrastructure/logging"
	"github.com/assetra/assetra-poc/internal/usecase"
)

func init() {
	rootCmd.AddCommand(inspectCmd)
}

var inspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Print a summary of OCSF findings stored in PostgreSQL",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		cfg, pool, err := initDeps(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return err
		}
		defer pool.Close()

		logger := logging.New(cfg.LogLevel)

		store := storage.NewPostgresStorage(pool)
		uc := usecase.NewInspectUseCase(store, cfg.CustomerID, logger)

		result, err := uc.Run(ctx)
		if err != nil {
			return fmt.Errorf("inspect failed: %w", err)
		}

		printInspectResult(cfg.CustomerID, result)
		return nil
	},
}
