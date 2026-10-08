# VM Middleware

A batch application that turns raw Tenable findings into prioritised, business-aware
vulnerability records. It pulls findings from the Tenable One Inventory API
(Exposure Management), enriches them with business context from asset tags, applies a
configurable risk formula, reconciles each finding against previously stored state, and
produces CSV reports. Optional Jira delivery creates and maintains tickets in each
team's configured Jira instance and project. CVE descriptions come from the NIST NVD because Tenable
leaves them empty for Cloud Security findings.

There is no web server or UI. Work runs through **Celery workers with Redis as the
broker and Celery Beat for scheduling** (pipeline, Jira delivery, NVD backfill and housekeeping), all
wired together with docker-compose. The same jobs can also be run as one-off CLI
commands against a local PostgreSQL database.

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

Jira delivery runs as a separate bounded task. It reads current finding state and
queued reconciliation actions, so a Jira outage does not block ingestion. Delivery
is disabled in the supplied configuration.

## Stack

- Python 3.10+
- PostgreSQL 16 (run locally in Docker)
- Celery 5 + Redis 7 (worker execution, Beat scheduling, overlap locking)
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
| `REDIS_URL` | yes (workers) | Celery broker/backend. Defaults to `redis://localhost:6379/0`; compose overrides it to the `redis` service. |
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
| `schedule.yaml` | Beat schedule: pipeline cron, NVD interval, maintenance cron |
| `rollout.yaml` | Jira pilot teams, scored risk ratings and global creation limit |
| `jira.yaml` | Jira instances, credential references, delivery switch and retry settings |
| `teams/*.yaml` | Team ownership selectors, Jira project, workflow, fields and creation limits |

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

### Scheduled stack (Celery + Redis)

The full stack runs in docker-compose: `postgres`, `redis`, a one-shot `migrate`
service, a Celery `worker`, and Celery `beat`. Beat takes its schedule from
`config/schedule.yaml`: the pipeline runs on `cron`, NVD backfill fetches a bounded
chunk every `nvd_interval_minutes`, and housekeeping (reap abandoned runs, prune aged
STALE findings) runs on `maintenance_cron`. Jira delivery ticks every
`jira_interval_seconds` and reads fresh Jira/team configuration each time.
A Redis lock ensures a beat tick never
starts a second pipeline run while one is already active.

```bash
make stack-up        # build the image and start postgres, redis, migrate, worker, beat
make stack-logs      # follow worker and beat logs
make stack-ps        # service status
make stack-down      # stop everything
```

Trigger a job by hand through the worker (bypasses the schedule, still uses the lock):

```bash
docker compose exec worker celery -A src.celery_app:celery_app call src.tasks.run_pipeline_task
docker compose exec worker celery -A src.celery_app:celery_app call src.tasks.maintenance_task
```

The CLI below remains fully supported for one-off and mock runs; it talks directly to
PostgreSQL and does not need the worker containers.

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
`portfolio-summary`, `workstream-summary`, `jira-sync`, `team-summary`.

Filters (each repeatable; values OR within a key, keys AND together):
`--portfolio`, `--service`, `--environment`, `--asset-criticality`, `--risk-rating`,
`--severity`, `--state`, `--sla-status`, `--source`, `--team`, `--owner-team`,
`--jira-sync-status`. With no `--out`, the CSV goes to stdout. `--team` selects the
canonical team ID recorded when delivery last evaluated the finding; `--owner-team`
filters the source ownership field and also works before Jira delivery is enabled.

### Jira onboarding

The integration creates one ticket per finding. Multiple teams can share a Jira
connection, use different projects, or reference separate Jira instances. Team
onboarding uses YAML and credentials; it needs no Python changes.

Run migration `008` before starting the updated workers or querying the new reports:

```bash
make db-migrate
```

Connections live under `jira.instances` in `config/jira.yaml`. Each connection has a
stable ID, `deployment: cloud` or `deployment: data_center`, an HTTPS `base_url` and
an `auth` mapping. Cloud uses API v3 and ADF descriptions; Data Center uses API v2 and
text descriptions. The Data Center adapter requires the paginated create-metadata
endpoints. Check compatibility with the team's deployed version during onboarding.

Use `auth.type: basic` with `email_env` and `token_env` for an email/API-token pair,
or `auth.type: bearer` with `token_env` for a bearer credential. YAML holds the
environment variable names. The worker reads their values from its environment.
For Cloud credentials that use the Atlassian API gateway, set `base_url` to
`https://api.atlassian.com/ex/jira/<cloudId>` and `browse_url` to the team's Jira site.
Credential provisioning, expiry and rotation remain the operator's responsibility.

Copy `config/teams/platform.yaml` for each team and set its `team_id`, ownership
selectors, instance ID and project. A team's `match` can use `service_owner_team`,
`portfolio`, `service` and `environment`. Values within a selector use OR; selectors
use AND. Matching ignores case and surrounding whitespace. The loader rejects
overlapping rules, unknown keys, duplicate team IDs and missing instance references.
Unmatched findings remain unticketed and appear as `UNROUTED` after delivery examines them.

Each team can set priority names, labels, component names, initial assignment,
literal `custom_fields` values keyed by Jira field ID, and close/reopen transitions.
`assignee` uses `accountId` for Cloud or `name` for Data Center. Transition settings
accept the transition name or ID, which can differ from the destination status name.
Use `transitions.close_fields` and `transitions.reopen_fields` for required transition
fields, such as resolution. Quote dates in custom YAML values.

```bash
# Offline schema validation; no database or Jira connection
.venv/bin/python scripts/jira.py validate

# Read-only routing, eligibility and proposed payloads from the local database
.venv/bin/python scripts/jira.py preview --team team-platform --limit 25

# Read Jira's create metadata using the configured credentials; creates no tickets
.venv/bin/python scripts/jira.py check --team team-platform
```

Set the team's `enabled: true` to preview eligible creates, while keeping the global
`jira.enabled: false`. Include its ID in the active rollout phase's `team_filter`, or
use an empty list to allow all configured teams. Both the team and rollout risk
filters apply to the scored `risk_rating`; the legacy rollout setting is named
`severity_filter`. Preview does not reserve capacity, contact Jira, or change database
records. It shows eligibility and payloads, alongside delivery status and the next
scheduled attempt; a paused failure still requires an explicit retry.

`check` validates the configured issue type, required create fields and enumerated
values returned by Jira. It does not prove every workflow transition or update
permission. The worker checks available transitions and their required fields on
each actual issue. Use a small pilot to verify the team's full lifecycle.

When ready, set `jira.enabled: true`. Beat then delivers bounded batches, or run one
batch manually:

```bash
.venv/bin/python scripts/jira.py sync
.venv/bin/python scripts/generate_report.py --report jira-sync --team team-platform
.venv/bin/python scripts/generate_report.py --report team-summary
```

The worker also picks up existing eligible OPEN findings without tickets. Global
and team creation limits share the most recent completed ingestion run as their
budget period, so repeated worker ticks cannot reset the allowance. Successful
creates and unresolved create attempts consume capacity; explicit Jira rejections
release their reservation. A new completed ingestion run starts a new allowance.
Updates, closures and reopens do not consume creation capacity. Setting a team's
`enabled: false` stops new tickets but allows its linked tickets to stay in sync.
The global switch stops all Jira delivery on the next batch.

Compose mounts `config/` read-only into worker and Beat. Jira/team/rollout changes
take effect on the next batch without rebuilding the image. Publish related YAML
changes together. New or rotated environment credentials require recreating the
worker container; schedule changes require restarting Beat. Findings deferred for
routing or eligibility are rechecked after `refresh_seconds`, subject to batch
capacity. Existing ticket work takes priority over onboarding new findings.

### Jira lifecycle and recovery

Tenable remains the remediation source. Only an explicit `FIXED` finding in
`REMEDIATED` state closes a ticket. A returning OPEN finding reopens a resolved
ticket. Missing/STALE findings do neither. SLA/risk changes update managed ticket
fields; the worker preserves subsequent human assignment and team-added labels.
Resolved issues are reopened before editing, and already-resolved fixed or stale
issues receive status checks only. The worker never automatically deletes tickets.

Ticket bindings retain instance, issue ID, project and team. Changing a routing
rule does not move existing tickets. Field/workflow changes apply when a team's
destination still matches the binding; otherwise the saved destination settings
remain in use. Keep bound connection IDs and URLs stable. A removed connection or
changed API address blocks delivery until corrected. Stale retention preserves
linked findings, uncertain creates and pending Jira work.

A PostgreSQL advisory lock serializes CLI and Celery delivery, including across
database commits. Use a direct or session-pooled PostgreSQL connection for this
worker; transaction-mode pooling cannot preserve that lock. SQLite is only used
for isolated tests.

Before sending CREATE, the worker commits the destination, creation reservation and
an attempt marker. Each ticket carries a `vmf-<finding UUID>` label. If the response
is lost, the finding becomes `UNCERTAIN` and subsequent batches search for that label.
They do not repeat CREATE while the outcome is unknown. Zero search results can
reflect indexing delay; multiple matches require operator investigation.

Rate limits and transient failures use persisted backoff, including `Retry-After`.
An instance cooldown does not stop delivery to another instance. Outside uncertain
CREATE recovery, permanent errors or exhausted retries become `FAILED`.
Inspect `jira-sync` for status, the
last error and ticket URL; `jira_sync_log` records API method/path/status without
credentials or raw response bodies. After correcting a failure:

```bash
.venv/bin/python scripts/jira.py retry --finding-id <finding-uuid>
```

To recover a known ticket or explicitly adopt a legacy ticket with no instance
binding, supply its team and key. This command reads Jira and updates the local
binding; the next enabled sync may update the ticket:

```bash
.venv/bin/python scripts/jira.py adopt \
    --finding-id <finding-uuid> --team team-platform --issue-key PLAT-123
```

Recovery of an uncertain CREATE requires the matching correlation label. If an
operator confirms in Jira that no ticket was created, `retry` also accepts
`--clear-uncertain-create`. That flag permits a fresh CREATE and can cause a duplicate
if used before the earlier outcome is resolved. Ordinary retries retain the marker.

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

The PostgreSQL migration and locking tests run only when
`VM_JIRA_TEST_DATABASE_URL` points to an isolated test database. They create and
remove disposable schemas within it. Jira HTTP tests use mock transports; a real
team's credentials, fields and workflows still need pilot validation.

## Project layout

```
config/         YAML configuration, Jira connections and teams/*.yaml
db/             Alembic config and migrations (001-008)
scripts/        CLI entry points: run_local.py, generate_report.py, enrich_nvd.py, jira.py
src/
  celery_app.py Celery app: Redis broker config + Beat schedule (from schedule.yaml)
  tasks.py      Celery tasks: pipeline, Jira delivery, NVD backfill, maintenance
  common/       Config loader, DB session, ORM models, logging, tag parser
  ingestion/    Tenable client, tagged-asset pre-flight, normalisation, enrichment, NVD
  scoring/      Risk models (custom VPR+ACS, Lumin CES), SLA calculation
  reconciliation/  State machine that diffs a run against stored findings
  reporting/    CSV report builders
  integration/  Jira routing, payloads, HTTP adapter, previews and delivery
  pipeline.py   Orchestrator
tests/          Unit tests and fixtures
Dockerfile      Worker/beat image (python:3.12-slim, non-root)
docker-compose.yaml  postgres + redis + migrate + worker + beat
```

## Deployment

Local development runs everything in docker-compose: PostgreSQL, Redis, a one-shot
Alembic migration, a Celery worker, and Celery Beat. The production target follows the
same shape: a managed Redis (e.g. AWS ElastiCache) as broker, worker and beat deployed
as long-running services (e.g. ECS), PostgreSQL on RDS, and reports delivered to S3.
The same codebase and image run in both places; only the environment differs.
