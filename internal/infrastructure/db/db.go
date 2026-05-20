package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPool creates a pgx connection pool from the given DSN.
func NewPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	return pool, nil
}

// WaitForSteampipe retries the connection to Steampipe until ready or timeout.
// It forces simple query protocol because Steampipe does not support prepared statements.
func WaitForSteampipe(ctx context.Context, dsn string, timeout time.Duration) (*pgxpool.Pool, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error

	for {
		cfg, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			return nil, fmt.Errorf("parse steampipe dsn: %w", err)
		}
		cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err == nil {
			if pingErr := pool.Ping(ctx); pingErr == nil {
				return pool, nil
			} else {
				lastErr = pingErr
				pool.Close()
			}
		} else {
			lastErr = err
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout waiting for steampipe after %s: %w", timeout, lastErr)
		}

		time.Sleep(2 * time.Second)
	}
}

// WaitForDB retries the connection until Postgres is ready or timeout is reached.
func WaitForDB(ctx context.Context, dsn string, timeout time.Duration) (*pgxpool.Pool, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error

	for {
		pool, err := NewPool(ctx, dsn)
		if err == nil {
			if pingErr := pool.Ping(ctx); pingErr == nil {
				return pool, nil
			} else {
				lastErr = pingErr
				pool.Close()
			}
		} else {
			lastErr = err
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout waiting for database after %s: %w", timeout, lastErr)
		}

		time.Sleep(2 * time.Second)
	}
}
