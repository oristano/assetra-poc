# Assetra POC

A local, containerised proof-of-concept for the Assetra asset vulnerability correlation engine.

## Purpose

Assetra ingests cloud asset inventory (EC2 instances) and security findings (AWS Inspector2),
correlates findings to assets, normalises both into a canonical schema, computes enrichment
metadata (severity counts, highest severity, active-finding flag), and exposes everything
through a CLI and PostgreSQL.

This POC is intentionally small. It proves the architectural direction without any real AWS
integration, authentication, queues, or microservices.

---

## POC Scope

| In scope                              | Out of scope                                   |
|---------------------------------------|------------------------------------------------|
| EC2 assets (mock CSV)                 | Real AWS API calls                             |
| Inspector2 findings (mock CSV)        | Auth / IAM / Secrets Manager                   |
| Asset ↔ Finding correlation           | Multi-cloud support                            |
| Normalised PostgreSQL schema          | REST API, gRPC, Kafka                          |
| Asset enrichment (severity summary)   | Kubernetes / production deployment             |
| CLI: migrate / ingest / inspect       | Web UI                                         |
| Steampipe for interactive SQL queries | Tenancy / RBAC                                 |

---

## Architecture Overview

```
CSV files (data/)
      │
      ▼
CSVReader adapter          ← implements domain.SourceReader
      │ LoadEC2Instances / LoadInspectorFindings
      ▼
IngestUseCase
  ├── loads assets + findings into memory
  ├── Correlate()           ← pure function, unit-tested
  │     match finding.resource_id == instance.instance_id
  └── NormalizeToOCSF()     ← builds OCSF Vulnerability Finding document
      │
      ▼
PostgresStorage adapter    ← implements domain.OCSFStorage
      │ upsert OCSF records
      ▼
PostgreSQL
  ├── ocsf_findings         (one row per correlated asset+finding pair)
  └── ocsf_asset_summary    (view: findings grouped by asset)

Steampipe (sidecar)        ← CSV plugin, for interactive SQL queries only
```

**OCSF class_uid 2004** — Vulnerability Finding. Each row contains:
- Flat columns for querying (severity, status, resource_uid, cve_id, …)
- Full OCSF document in the `raw` JSONB column
- `customer_id` and `account_id` on every row

IDs are **deterministic UUID v5** keyed on `(customer_id, finding_arn)` so
repeated `ingest` runs upsert, never duplicate.

---

## Folder Structure

```
assetra-poc/
├── cmd/assetra-poc/          CLI entrypoints (Cobra)
├── internal/
│   ├── domain/               Entities and interfaces (no deps on infra)
│   ├── usecase/              Business logic: correlate, normalize, enrich
│   ├── adapters/
│   │   ├── source/           CSVReader (implements SourceReader)
│   │   ├── storage/          PostgresStorage (implements AssetStorage)
│   │   └── steampipe/        Reference Steampipe exec adapter
│   └── infrastructure/
│       ├── config/           Env-var config loader
│       ├── db/               pgxpool factory + migration runner
│       └── logging/          slog setup
├── migrations/               SQL migration files (applied in lexical order)
├── data/aws/                 Mock CSV files
├── queries/                  Example SQL queries
├── steampipe/                Steampipe CSV plugin config
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── .env.example
```

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) with Compose v2
- [OrbStack](https://orbstack.dev/) (or Docker Desktop) on macOS
- Go 1.22+ — required for:
  - generating `go.sum` before the first Docker build
  - running tests locally

**First-time setup:** after cloning, run once to generate `go.sum`:

```bash
cd assetra-poc
go mod tidy
```

---

## How to Run with Docker Compose

```bash
# 1. Copy env file
cp .env.example .env

# 2. Start all services (postgres + steampipe + app)
docker compose up -d --build

# 3. Apply migrations
docker compose exec app ./assetra-poc migrate

# 4. Run the ingest pipeline
docker compose exec app ./assetra-poc ingest

# 5. Print the inspect summary
docker compose exec app ./assetra-poc inspect
```

Or use the Makefile shortcuts:

```bash
make up       # start services
make migrate  # apply migrations
make ingest   # ingest data
make inspect  # show summary
make reset    # clear all data
make down     # stop services
make logs     # tail all logs
make test     # run unit tests locally
make psql     # open psql shell
```

---

## How to Run Migrations

```bash
docker compose exec app ./assetra-poc migrate
```

Migration files are loaded from `/migrations` (mounted from `./migrations/` in the repo).
Each `.sql` file is applied once, in lexical order. Applied filenames are tracked in
the `schema_migrations` table.

---

## How to Ingest Data

```bash
docker compose exec app ./assetra-poc ingest
```

The ingest command:
1. Reads `mock_ec2_instances.csv` and `mock_inspector_findings.csv` from `/data`
2. Correlates each finding to its EC2 asset via `resource_id == instance_id`
3. Logs unmatched findings as warnings (they are stored with `asset_id = NULL`)
4. Upserts normalised assets, findings, and enrichment into PostgreSQL
5. Emits a structured log summary when complete

The command is safe to run multiple times — all writes use upsert semantics.

---

## How to Inspect Results

```bash
docker compose exec app ./assetra-poc inspect
```

Prints:

```
=== Assetra Inspect ===

  Total Assets:        3
  Total Findings:      3
  Unmatched Findings:  1

  Asset Details:

  INSTANCE ID   NAME           REGION      FINDINGS  HIGHEST SEVERITY
  ──────────    ────────────   ─────────   ────────  ────────────────
  i-001         web-server-1   us-east-1   2         CRITICAL
  i-002         db-server-1    us-east-1   1         MEDIUM
  i-003         backup-server  us-west-2   0         -
```

---

## How Steampipe Is Used

Steampipe runs as a sidecar service that exposes the CSV files as SQL tables via the
[CSV plugin](https://hub.steampipe.io/plugins/turbot/csv).

Table naming convention: the CSV plugin creates a table for each file using the filename
(without extension) prefixed by the connection name.

| File                              | Steampipe table                     |
|-----------------------------------|-------------------------------------|
| `mock_ec2_instances.csv`          | `csv.mock_ec2_instances`            |
| `mock_inspector_findings.csv`     | `csv.mock_inspector_findings`       |

**Interactive query session:**

```bash
docker compose exec steampipe steampipe query

# Example queries:
> select instance_id, name, region from csv.mock_ec2_instances;
> select finding_arn, severity, resource_id from csv.mock_inspector_findings;
```

**The app itself does not exec Steampipe** — it reads the CSV files directly for
simplicity and reliability. The Steampipe adapter in `internal/adapters/steampipe/`
documents the intended exec-based integration path for future iterations.

---

## Logging

Logs are emitted as **structured JSON** to stdout. Set `LOG_LEVEL` to `debug`, `info`,
`warn`, or `error`.

Key log events:

| Event                          | Level  | Key fields                              |
|--------------------------------|--------|-----------------------------------------|
| application starting           | info   | version, env, log_level                 |
| database connection established| info   |                                         |
| ec2 instances loaded           | info   | count                                   |
| inspector findings loaded      | info   | count                                   |
| unmatched finding              | warn   | source_finding_id, resource_id          |
| correlation complete           | info   | matched_findings, unmatched_findings    |
| ingest complete                | info   | assets_upserted, findings_upserted, duration_ms |
| migration applied              | info   | file                                    |
| inspect summary                | info   | asset_count, finding_count, unmatched_count |

View logs with:

```bash
docker compose logs -f app
```

---

## Example SQL Queries Against PostgreSQL

```bash
# Open a psql shell
make psql
# or: docker compose exec postgres psql -U assetra -d assetra
```

```sql
-- All assets with enrichment
SELECT native_id, name, region, finding_count_total, highest_severity
FROM assets a
LEFT JOIN asset_enrichment ae ON ae.asset_id = a.id;

-- Full correlation view (one row per asset-finding pair)
SELECT * FROM asset_findings_summary ORDER BY native_id;

-- Unmatched findings
SELECT source_finding_id, severity, cve_id FROM findings WHERE asset_id IS NULL;

-- Findings grouped by asset
SELECT native_id, asset_name, severity, cve_id, package_name
FROM asset_findings_summary
ORDER BY native_id, severity;

-- Applied migrations
SELECT filename, applied_at FROM schema_migrations ORDER BY applied_at;
```

---

## Limitations of the POC

- Only EC2 and Inspector2 are modelled; no other asset or finding types.
- No real AWS calls — all data is from local CSV mocks.
- No authentication, multi-tenancy, or RBAC.
- No REST API; CLI only.
- Steampipe is a sidecar for interactive queries only; the app reads CSVs directly.
- `schema_migrations` is a simple table; no rollback support.

---

## Next Steps Toward Real AWS / Inspector Integration

1. **Real source adapter**: replace `CSVReader` with an AWS SDK adapter that calls
   `ec2:DescribeInstances` and `inspector2:ListFindings`.
2. **Steampipe integration**: implement `internal/adapters/steampipe/` as the primary
   source adapter, querying Steampipe's PostgreSQL FDW endpoint.
3. **Streaming**: for large accounts, stream assets and findings rather than loading
   all into memory at once.
4. **Scheduling**: add a background worker that runs ingest on a cron schedule.
5. **Multi-cloud**: extend the domain model with `GCPComputeInstance`,
   `AzureVirtualMachine`, etc., behind the same `SourceReader` interface.
6. **Additional finding sources**: Trivy, Snyk, Wiz, etc. — all behind `SourceReader`.
7. **REST / GraphQL API**: expose assets and findings over HTTP.
8. **Observability**: add Prometheus metrics, distributed tracing.
