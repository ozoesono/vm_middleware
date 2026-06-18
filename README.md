# VM Middleware

A batch application that turns raw Tenable findings into prioritised, business-aware
vulnerability records. It pulls findings from the Tenable One Inventory API
(Exposure Management), enriches them with business context from asset tags, applies a
configurable risk formula, reconciles each finding against previously stored state, and
produces CSV reports. CVE descriptions are filled in from the NIST NVD because Tenable
leaves them empty for Cloud Security findings.

There is no web server or UI. It runs as a command-line pipeline against a PostgreSQL
database, and is built to run later as scheduled AWS Lambda functions.

## What it does

Each run goes through the same stages:

1. **Ingest** — fetch the assets carrying a given tag, then stream their findings from
   Tenable page by page. Every page is committed and checkpointed, so an interrupted run
   resumes from where it stopped rather than starting over.
2. **Enrich** — parse the asset tags into business context (portfolio, service,
   environment, criticality, owner), with optional overrides from a CSV.
3. **Score** — compute a risk score and rating per finding from VPR and asset
   criticality, and work out the SLA due date and status. Weights, thresholds and SLA
   days are all set in YAML.
4. **Reconcile** — compare this run's findings against what is already stored and apply
   the right state transition: NEW, STILL OPEN, REMEDIATED, RECURRENCE, or STALE.
5. **Report** — generate CSVs on demand from the stored findings. CVE descriptions come
   from a cached NVD lookup that runs separately so it never blocks the pipeline.

## Stack

- Python 3.10+
- PostgreSQL 16 (run locally in Docker)
- SQLAlchemy 2.0 and Alembic for the data layer and migrations
- Pydantic and YAML for configuration
- httpx and tenacity for HTTP with retries
- structlog for JSON logging
- pytest for the test suite

## Getting started

### Prerequisites

- Python 3.10 or newer
- Docker and Docker Compose (for the local database)
- Tenable API keys (access key and secret key) with read access to Exposure Management
- Optional: a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key),
  which makes CVE enrichment about ten times faster

### 1. Install

```bash
make install
```

This creates a virtualenv in `.venv` and installs the project with its dev dependencies.

### 2. Configure

Copy the example environment file and fill in your credentials:

```bash
cp .env.example .env
```

The variables you need:

| Variable | Required | Purpose |
|---|---|---|
| `DATABASE_URL` | yes | Connection string. Defaults to the local Docker database on port 5435. |
| `TENABLE_ACCESS_KEY` | yes | Tenable API access key. |
| `TENABLE_SECRET_KEY` | yes | Tenable API secret key. |
| `TENABLE_BASE_URL` | yes | Tenable endpoint (defaults to `https://cloud.tenable.com`). |
| `NVD_API_KEY` | no | Speeds up CVE enrichment. Read from the environment when present. |
| `CONFIG_DIR` | no | Where the YAML config lives (defaults to `config`). |
| `LOG_LEVEL` | no | `INFO` by default. |

Operational behaviour lives in `config/*.yaml` and can be changed without touching code:

| File | Controls |
|---|---|
| `tenable.yaml` | API endpoint, requested properties, page size, retries, stale threshold |
| `scoring.yaml` | Risk formula, weights, thresholds, criticality scores |
| `sla_policy.yaml` | SLA days per severity, business-day handling |
| `nvd.yaml` | Cache TTL, whether NVD runs inline, per-run cap |
| `rollout.yaml` | Phased Jira rollout (Phase 2) |
| `schedule.yaml` | Cron schedule (Phase 2) |
| `jira.yaml` | Jira connection (Phase 2) |

### 3. Start the database

```bash
make db-up
```

This starts PostgreSQL 16 in a container named `vm-middleware-db`, listening on
`localhost:5435`.

### 4. Run the migrations

```bash
make db-migrate
```

### 5. Try it with mock data

You can exercise the whole pipeline without Tenable credentials using the bundled
fixtures, then generate a report:

```bash
make run-pipeline-mock
.venv/bin/python scripts/generate_report.py --report findings --out findings.csv
```

## Commands

All commands assume the virtualenv at `.venv`. The `make` targets wrap the most common ones.

### Pipeline

```bash
# Run against a portfolio tag (the normal case).
# caffeinate keeps macOS awake for long runs.
caffeinate -i .venv/bin/python scripts/run_local.py --tag Portfolio-Business-Growth

# Multiple tags accumulate (OR logic)
.venv/bin/python scripts/run_local.py --tag Portfolio-A --tag Portfolio-B

# Filter by severity as well
.venv/bin/python scripts/run_local.py --tag Portfolio-A --severity Critical --severity High

# Run against mock fixtures (no Tenable needed)
.venv/bin/python scripts/run_local.py --mock
make run-pipeline-mock

# Force a brand new run instead of resuming an incomplete one
.venv/bin/python scripts/run_local.py --tag Portfolio-A --start-fresh
```

Resume is automatic: if a previous run for the same tag did not finish, the next run
continues from its checkpoint. Use `--start-fresh` to override that.

### Reports

```bash
# List the available reports
.venv/bin/python scripts/generate_report.py --list

# Full findings export
.venv/bin/python scripts/generate_report.py --report findings --out findings.csv

# Risk summary, criticals and highs only, one portfolio
.venv/bin/python scripts/generate_report.py \
    --report risk-summary \
    --portfolio Business-Growth \
    --risk-rating CRITICAL --risk-rating HIGH \
    --out risk.csv
```

Reports: `findings`, `risk-summary`, `sla-breaches`, `sla-approaching`, `recurrence`,
`portfolio-summary`.

Filters (each repeatable; values OR within a key, keys AND together):
`--portfolio`, `--service`, `--environment`, `--asset-criticality`, `--risk-rating`,
`--severity`, `--state`, `--sla-status`, `--source`. With no `--out`, the CSV goes to stdout.

### CVE enrichment (NVD)

CVE descriptions are fetched separately from the pipeline so a slow NVD backfill never
holds up findings. The cache accumulates, so this is safe to stop and re-run.

```bash
# How many CVEs still need fetching
.venv/bin/python scripts/enrich_nvd.py --status

# Fetch the next 500 and exit (good for a cron job)
.venv/bin/python scripts/enrich_nvd.py --max 500

# Backfill everything (slow without an API key)
.venv/bin/python scripts/enrich_nvd.py
```

### Database

Migrations:

```bash
make db-migrate                 # upgrade to the latest schema
make db-rollback                # step back one migration
make db-revision msg="add x"    # autogenerate a new migration
```

Query the database directly. Either open a shell inside the container:

```bash
docker exec -it vm-middleware-db psql -U vm_user -d vm_middleware
```

or connect from the host using the mapped port (needs a local `psql`):

```bash
psql "postgresql://vm_user:vm_local_pass@localhost:5435/vm_middleware"
```

Useful queries:

```sql
-- Recent pipeline runs and their state
SELECT id, status, started_at, completed_at,
       findings_fetched, findings_new, findings_remediated,
       last_batch_idx, total_batches
FROM pipeline_runs
ORDER BY started_at DESC
LIMIT 5;

-- Findings by risk rating
SELECT risk_rating, COUNT(*)
FROM findings
GROUP BY risk_rating
ORDER BY COUNT(*) DESC;

-- NVD cache coverage
SELECT COUNT(*) AS total_cves,
       MIN(last_fetched_at) AS oldest,
       MAX(last_fetched_at) AS newest
FROM cve_details;
```

### Tests and dev

```bash
make test            # run the suite
make test-cov        # with coverage
make lint            # ruff check + format check
make format          # ruff autofix + format
```

## Project layout

```
config/         YAML configuration (scoring, SLA, Tenable, NVD, rollout, schedule)
db/             Alembic config and migrations (001-006)
scripts/        Entry points: run_local.py, generate_report.py, enrich_nvd.py
src/
  common/       Config loader, DB session, ORM models, logging, tag parser
  ingestion/    Tenable client, tagged-asset pre-flight, normalisation, enrichment, NVD
  scoring/      Risk models (custom VPR+ACS, Lumin CES), SLA calculation
  reconciliation/  State machine that diffs a run against stored findings
  reporting/    CSV report builders
  pipeline.py   Orchestrator
  lambdas/      AWS Lambda entry points (Phase 2)
tests/          Unit tests and fixtures
```

## Deployment

Local development runs everything against the Docker PostgreSQL instance. The production
target is AWS in a UK region: EventBridge triggers a Step Functions workflow that runs
the pipeline on Lambda against RDS PostgreSQL, with reports delivered to S3. The same
codebase runs in both places; only the entry point differs.
