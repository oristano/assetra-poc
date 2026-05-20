package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/assetra/assetra-poc/internal/adapters/storage"
	"github.com/assetra/assetra-poc/internal/infrastructure/logging"
)

func init() {
	rootCmd.AddCommand(resetCmd)
}

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Clear all ingested data from the database for a clean re-run",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		cfg, pool, err := initDeps(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return err
		}
		defer pool.Close()

		logger := logging.New(cfg.LogLevel)
		logger.Info("resetting all tables")

		store := storage.NewPostgresStorage(pool)
		if err := store.ResetAll(ctx); err != nil {
			return fmt.Errorf("reset failed: %w", err)
		}

		fmt.Println("All tables cleared.")
		return nil
	},
}
