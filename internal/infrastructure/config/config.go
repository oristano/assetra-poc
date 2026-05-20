package config

import (
	"fmt"
	"os"
)

// Config holds all runtime configuration loaded from environment variables.
type Config struct {
	AppEnv           string
	LogLevel         string
	CustomerID       string
	PostgresHost     string
	PostgresPort     string
	PostgresDB       string
	PostgresUser     string
	PostgresPassword string
	SteampipeHost     string
	SteampipePort     string
	SteampipeDB       string
	SteampipeUser     string
	SteampipePassword string
	DataDir          string
	MigrationsDir    string
}

// Load reads configuration from environment variables.
// Returns an error if any required variable is missing.
func Load() (*Config, error) {
	password := os.Getenv("POSTGRES_PASSWORD")
	if password == "" {
		return nil, fmt.Errorf("POSTGRES_PASSWORD environment variable is required")
	}

	return &Config{
		AppEnv:            getEnv("APP_ENV", "development"),
		LogLevel:          getEnv("LOG_LEVEL", "info"),
		CustomerID:        getEnv("CUSTOMER_ID", "12345"),
		PostgresHost:      getEnv("POSTGRES_HOST", "localhost"),
		PostgresPort:      getEnv("POSTGRES_PORT", "5432"),
		PostgresDB:        getEnv("POSTGRES_DB", "assetra"),
		PostgresUser:      getEnv("POSTGRES_USER", "assetra"),
		PostgresPassword:  password,
		SteampipeHost:     getEnv("STEAMPIPE_HOST", "localhost"),
		SteampipePort:     getEnv("STEAMPIPE_PORT", "9193"),
		SteampipeDB:       getEnv("STEAMPIPE_DB", "steampipe"),
		SteampipeUser:     getEnv("STEAMPIPE_USER", "steampipe"),
		SteampipePassword: getEnv("STEAMPIPE_PASSWORD", "steampipe"),
		DataDir:           getEnv("DATA_DIR", "./data"),
		MigrationsDir:     getEnv("MIGRATIONS_DIR", "./migrations"),
	}, nil
}

// PostgresDSN returns a pgx-compatible connection string for Postgres.
func (c *Config) PostgresDSN() string {
	return fmt.Sprintf(
		"postgresql://%s:%s@%s:%s/%s?sslmode=disable",
		c.PostgresUser, c.PostgresPassword,
		c.PostgresHost, c.PostgresPort,
		c.PostgresDB,
	)
}

// SteampipeDSN returns a pgx-compatible connection string for Steampipe.
func (c *Config) SteampipeDSN() string {
	return fmt.Sprintf(
		"postgresql://%s:%s@%s:%s/%s?sslmode=disable",
		c.SteampipeUser, c.SteampipePassword,
		c.SteampipeHost, c.SteampipePort,
		c.SteampipeDB,
	)
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
