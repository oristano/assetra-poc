// Package steampipe provides a reference adapter that queries Steampipe
// via CLI exec (steampipe query --output json). It is not used by the main
// ingest flow in this POC — the CSVReader adapter is used instead for
// simplicity and reliability in Docker. This package shows the intended
// integration path for when Steampipe is the authoritative query layer.
package steampipe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

// QueryJSON runs a Steampipe SQL query and parses the JSON output.
// Requires the `steampipe` binary to be on PATH and a service to be running.
func QueryJSON(ctx context.Context, query string) ([]map[string]interface{}, error) {
	cmd := exec.CommandContext(ctx, "steampipe", "query", "--output", "json", query)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("steampipe query failed: %w\nstderr: %s", err, stderr.String())
	}

	var rows []map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &rows); err != nil {
		return nil, fmt.Errorf("parse steampipe json: %w", err)
	}

	return rows, nil
}
