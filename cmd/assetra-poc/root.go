package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/assetra/assetra-poc/internal/infrastructure/config"
	"github.com/assetra/assetra-poc/internal/infrastructure/db"
	"github.com/assetra/assetra-poc/internal/infrastructure/logging"

	"github.com/jackc/pgx/v5/pgxpool"
)

const version = "0.1.0"

var rootCmd = &cobra.Command{
	Use:   "assetra-poc",
	Short: "Assetra local mock POC — asset vulnerability correlation engine",
}

// Execute is the main entrypoint called from main.go.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// initSteampipePool opens a pool to the source data layer (currently source-db;
// swap STEAMPIPE_HOST/PORT to point at real Steampipe when available).
func initSteampipePool(ctx context.Context, cfg *config.Config) (*pgxpool.Pool, error) {
	pool, err := db.WaitForDB(ctx, cfg.SteampipeDSN(), 60*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to source db: %w", err)
	}
	return pool, nil
}

// initDeps loads config, sets up logging, and opens a DB connection.
// Used by commands that need database access.
func initDeps(ctx context.Context) (*config.Config, *pgxpool.Pool, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, fmt.Errorf("load config: %w", err)
	}

	logger := logging.New(cfg.LogLevel)
	logger.Info("application starting",
		"version", version,
		"env", cfg.AppEnv,
		"log_level", cfg.LogLevel,
	)

	logger.Info("connecting to database",
		"host", cfg.PostgresHost,
		"port", cfg.PostgresPort,
		"db", cfg.PostgresDB,
	)

	pool, err := db.WaitForDB(ctx, cfg.PostgresDSN(), 30*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to database: %w", err)
	}

	logger.Info("database connection established")
	return cfg, pool, nil
}
