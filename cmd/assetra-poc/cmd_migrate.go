package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/assetra/assetra-poc/internal/infrastructure/db"
	"github.com/assetra/assetra-poc/internal/infrastructure/logging"
)

func init() {
	rootCmd.AddCommand(migrateCmd)
}

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Apply pending database migrations",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		cfg, pool, err := initDeps(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return err
		}
		defer pool.Close()

		logger := logging.New(cfg.LogLevel)

		if err := db.RunMigrations(ctx, pool, cfg.MigrationsDir, logger); err != nil {
			return fmt.Errorf("migrations failed: %w", err)
		}

		fmt.Println("Migrations complete.")
		return nil
	},
}
