package db

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RunMigrations applies any pending SQL migration files in migrationsDir.
// Applied migrations are tracked in the schema_migrations table.
func RunMigrations(ctx context.Context, pool *pgxpool.Pool, migrationsDir string, logger *slog.Logger) error {
	logger.Info("migration started", slog.String("step", "migrate"), slog.String("dir", migrationsDir))

	if err := ensureMigrationsTable(ctx, pool); err != nil {
		return fmt.Errorf("ensure migrations table: %w", err)
	}

	files, err := listMigrationFiles(migrationsDir)
	if err != nil {
		return fmt.Errorf("list migration files: %w", err)
	}

	applied := 0
	for _, file := range files {
		filename := filepath.Base(file)

		already, err := isMigrationApplied(ctx, pool, filename)
		if err != nil {
			return fmt.Errorf("check migration %s: %w", filename, err)
		}
		if already {
			logger.Debug("migration already applied", slog.String("file", filename))
			continue
		}

		logger.Info("applying migration", slog.String("file", filename))

		content, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", filename, err)
		}

		if _, err := pool.Exec(ctx, string(content)); err != nil {
			return fmt.Errorf("execute migration %s: %w", filename, err)
		}

		if _, err := pool.Exec(ctx,
			"INSERT INTO schema_migrations (filename) VALUES ($1) ON CONFLICT DO NOTHING",
			filename,
		); err != nil {
			return fmt.Errorf("record migration %s: %w", filename, err)
		}

		logger.Info("migration applied", slog.String("file", filename))
		applied++
	}

	logger.Info("migration finished",
		slog.String("step", "migrate"),
		slog.Int("applied", applied),
		slog.Int("total_files", len(files)),
	)
	return nil
}

func ensureMigrationsTable(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			filename   TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	return err
}

func isMigrationApplied(ctx context.Context, pool *pgxpool.Pool, filename string) (bool, error) {
	var exists bool
	err := pool.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE filename = $1)",
		filename,
	).Scan(&exists)
	return exists, err
}

func listMigrationFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir %s: %w", dir, err)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}

	sort.Strings(files)
	return files, nil
}
