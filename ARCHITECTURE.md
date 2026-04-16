# VM Middleware -- Architecture Document (v2)

> **Version**: 2.0
> **Status**: Phase 0 (Foundation) -- implemented and operational
> **Last updated**: 2026-04-16

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Tenable One Inventory API -- Single Source of Truth](#2-tenable-one-inventory-api----single-source-of-truth)
3. [Reconciliation Engine](#3-reconciliation-engine)
4. [Pipeline Flow](#4-pipeline-flow)
5. [Data Model](#5-data-model)
6. [Scoring Engine](#6-scoring-engine)
7. [SLA Policy](#7-sla-policy)
8. [Enrichment](#8-enrichment)
9. [Jira Ticketing](#9-jira-ticketing)
10. [Project Structure](#10-project-structure)
11. [Technology Stack](#11-technology-stack)
12. [Configuration Reference](#12-configuration-reference)
13. [Phase Alignment](#13-phase-alignment)
14. [Key Design Decisions](#14-key-design-decisions)
15. [Non-Functional Requirements](#15-non-functional-requirements)

---

## 1. System Overview

The VM Middleware is a vulnerability management orchestration system that ingests
findings from the Tenable One Inventory API, enriches them with business context,
applies configurable risk scoring, detects remediations via state reconciliation,
and creates Jira tickets for service teams.

### Architecture Diagram

```
+----------------------------------------------------------------------+
|                         TENABLE ONE PLATFORM                         |
|  +----------+  +----------------+  +-------+  +-----------+         |
|  | Nessus   |  | Cloud Security |  |  WAS  |  | 3rd-Party |         |
|  | (VM)     |  | (CNAPP)        |  |       |  | Connectors|         |
|  +----+-----+  +-------+--------+  +---+---+  +-----+-----+         |
|       |                |                |            |               |
|       +--------+-------+-------+--------+            |               |
|                |               |                     |               |
|          +-----v---------------v---------------------v-----+         |
|          |     Tenable One Inventory (Exposure Mgmt)       |         |
|          |     Unified findings across all modules          |         |
|          +--+--------------------------------------------+--+         |
|             |                                            |           |
|   POST /api/v1/t1/inventory/         POST /api/v1/t1/inventory/      |
|     findings/search (sync)             export/findings (async)       |
+---------|-------------------------------------------|---------+
          |                                           |
          +-------------------+  +--------------------+
                              |  |
                              v  v
+----------------------------------------------------------------------+
|                        VM MIDDLEWARE                                  |
|                                                                      |
|  +--------------------+     +------------------+                     |
|  | Tenable Client     |     | Enrichment       |                     |
|  | (httpx + tenacity) |     | (CSV / AWS Tags) |                     |
|  +---------+----------+     +--------+---------+                     |
|            |                         |                               |
|            v                         v                               |
|  +--------------------+     +------------------+                     |
|  | Ingestion          |---->| Staging Table    |                     |
|  | (normalise + stage)|     | (findings_staging)|                    |
|  +--------------------+     +--------+---------+                     |
|                                      |                               |
|                              +-------v--------+                      |
|                              | Reconciliation  |                     |
|                              | Engine          |                     |
|                              | (state mgmt)    |                     |
|                              +---+----+---+----+                     |
|                                  |    |   |                          |
|                          +-------+    |   +-------+                  |
|                          v            v           v                  |
|                   +----------+  +---------+  +---------+             |
|                   | Scoring  |  | SLA     |  | Jira    |             |
|                   | Engine   |  | Calc    |  | Action  |             |
|                   +----------+  +---------+  | Queue   |             |
|                                              +---------+             |
|                                                  |                   |
|  +-------------------+     +---------------------v------+            |
|  | CSV Reports       |     | Jira Integration           |            |
|  | (Phase 2)         |     | (Phase 1-2)                |            |
|  +-------------------+     +----------------------------+            |
|                                                                      |
|  +-----------------------------------------------------------+      |
|  |                     PostgreSQL 16                          |      |
|  |  findings | findings_staging | enrichment_mappings |       |      |
|  |  jira_action_queue | pipeline_runs | risk_exceptions       |      |
|  +-----------------------------------------------------------+      |
+----------------------------------------------------------------------+

Deployment (Phase 2):
  - Lambda: pipeline execution (triggered by EventBridge cron)
  - ECS Fargate: API service (FastAPI, on-demand queries)
  - RDS PostgreSQL: persistent storage
  - No S3 -- all data in PostgreSQL
```

---

## 2. Tenable One Inventory API -- Single Source of Truth

### Why One Source Is Sufficient

The Tenable One Inventory API (Exposure Management) is a **unified aggregation
layer** that consolidates findings from every Tenable module into a single
queryable dataset. There is no need to query individual product APIs separately.

| Tenable Module               | What It Covers                                      |
|------------------------------|-----------------------------------------------------|
| Vulnerability Management     | Infrastructure CVEs, missing patches, host vulns    |
| Cloud Security (CNAPP)       | Cloud misconfigs, container vulns, IaC findings     |
| Web App Scanning (WAS)       | OWASP Top 10, web-specific vulnerabilities          |
| Third-party connectors       | Orca, Prisma Cloud, etc. via Tenable integrations   |

Every finding in the Inventory carries a `source` field indicating its origin
module, so downstream consumers can distinguish between infrastructure vulns,
cloud misconfigs, and web findings without needing separate API calls.

### Two Retrieval Modes

The middleware supports two modes, configurable via `tenable.retrieval_mode`:

**Mode 1: Synchronous Search** (default)

- Endpoint: `POST /api/v1/t1/inventory/findings/search`
- Paginated with `offset` + `limit` (up to 10,000 per page)
- Immediate results -- no job queue
- Best for datasets under approximately 50,000 findings
- Supports `extra_properties` to include VPR, ACR, AES, EPSS, CVE, solution, etc.

**Mode 2: Async Export**

- Endpoint: `POST /api/v1/t1/inventory/export/findings`
- Queues an export job, returns an `export_id`
- Poll `GET /api/v1/export/{export_id}/status` until FINISHED
- Download JSON chunks via `GET /api/v1/export/{export_id}/download/{chunk_id}`
- Designed for large datasets (50k+ findings)
- Configurable poll interval (default: 10s) and max wait (default: 600s)

The `TenableClient.fetch_findings()` method automatically dispatches to the
correct mode based on configuration. Both modes return the same normalised
finding structure.

### Authentication

API keys are passed via the `X-ApiKeys` header:

```
X-ApiKeys: accessKey={access_key};secretKey={secret_key}
```

Credentials are sourced from environment variables (`TENABLE_ACCESS_KEY`,
`TENABLE_SECRET_KEY`), never stored in config files.

### Retry and Error Handling

- Automatic retry on 429 (rate limit) with exponential backoff via `tenacity`
- Up to 3 retries per request, backoff multiplier of 2, min 4s, max 60s
- Distinct exceptions: `TenableAPIError`, `TenableRateLimitError`, `TenableExportTimeoutError`
- 401 and 403 errors raise immediately (no retry)

---

## 3. Reconciliation Engine

The reconciliation engine is the core state management component. It compares
the current pipeline run's staged findings against the stored findings database
to determine what changed.

### State Transition Model

```
                          +------------------+
     New finding          |                  |         Tenable state = Fixed
    in staging   -------->|      OPEN        |------------------------+
    (not in DB)           |                  |                        |
                          +--------+---------+                        |
                                   |                                  |
                                   | not in staging,                  |
                                   | last_seen > threshold            |
                                   v                                  v
                          +------------------+            +------------------+
                          |                  |            |                  |
                          |     STALE        |            |   REMEDIATED     |
                          |                  |            |                  |
                          +------------------+            +--------+---------+
                                                                   |
                                                                   | Tenable state =
                                                                   | Active/Resurfaced
                                                                   v
                                                          +------------------+
                                                          |  OPEN            |
                                                          |  (is_recurrence  |
                                                          |   = true)        |
                                                          +------------------+
```

### Five Reconciliation Paths

| Path         | Condition                                                         | Action                                                        | Jira Queue   |
|--------------|-------------------------------------------------------------------|---------------------------------------------------------------|--------------|
| **NEW**      | Finding in staging, not in `findings` table                       | INSERT into findings, score, calculate SLA                    | CREATE       |
| **STILL OPEN** | In both staging and findings, Tenable state = Active           | UPDATE scores, last_seen, enrichment; re-evaluate SLA         | UPDATE (if SLA status changed) |
| **REMEDIATED** | In both, Tenable state = Fixed                                 | Set state=REMEDIATED, record remediated_at, compute time_to_fix | CLOSE      |
| **RECURRENCE** | Previously REMEDIATED, now Active/Resurfaced in staging        | Reopen, set is_recurrence=true, increment recurrence_count, reset SLA | REOPEN |
| **STALE**    | In findings as OPEN, NOT in staging, last_seen > stale_threshold | Set state=STALE (not auto-closed -- requires investigation)   | None         |

### Why Reconciliation Instead of Jira Push Notifications

Tenable does not provide webhooks or push notifications for state changes.
The middleware must poll on a schedule and compare the full dataset to detect
remediations. This "pull and reconcile" pattern is the only reliable way to
detect that a finding has been fixed without requiring manual intervention.

### Reconciliation Algorithm (Simplified)

```
1. Load all staged findings (current run) into lookup by tenable_finding_id
2. For each OPEN/STALE finding in DB:
   a. If found in staging AND state=Fixed      -> REMEDIATED
   b. If found in staging AND state=Active      -> STILL OPEN (update)
   c. If NOT in staging AND stale threshold hit -> STALE
3. For each REMEDIATED finding in DB:
   a. If found in staging AND state=Active/Resurfaced -> RECURRENCE
4. For each staged finding NOT already processed -> NEW
5. Flush Jira action queue entries
```

---

## 4. Pipeline Flow

The pipeline runs as a sequential process. In Phase 0, a local runner
(`src/pipeline.py`) executes all steps. In Phase 2, AWS Step Functions
will orchestrate Lambda invocations for each step.

```
Step 1: Enrichment Sync
  - Load business context from CSV into enrichment_mappings table
  - (Phase 1: also sync from AWS Tags API)

Step 2: Tenable Ingestion
  - Fetch all findings via TenableClient.fetch_findings()
  - Normalise each finding to canonical schema
  - Bulk insert into findings_staging table

Step 2b: Apply Enrichment
  - Match staged findings against enrichment_mappings (by asset_id, then asset_name)
  - Write enrichment data into staging records via tenable_tags._enrichment JSON

Step 3: Scoring and Reconciliation
  - Run reconciliation engine (compare staging vs stored findings)
  - Score each new/updated finding via scoring engine
  - Calculate SLA due dates and status
  - Populate jira_action_queue with CREATE/UPDATE/CLOSE/REOPEN actions

Step 4: Jira Sync (Phase 1-2)
  - Process jira_action_queue entries
  - Create/update/close/reopen Jira tickets
  - Log all API calls to jira_sync_log
  - In Phase 0: actions are logged but not executed

Step 5: Pipeline Completion
  - Clean up staging table for this run
  - Update pipeline_runs record with statistics
  - Print summary
```

### Pipeline Run Record

Every execution creates a `PipelineRun` record tracking:
- Status (RUNNING / SUCCESS / FAILED)
- Trigger (manual / scheduled)
- Counts: fetched, new, updated, remediated, recurred, stale
- Jira ticket counts: created, updated, closed
- Error list (if any)
- Timing (started_at, completed_at)

---

## 5. Data Model

All tables use UUID primary keys and are managed via SQLAlchemy ORM with
Alembic migrations. PostgreSQL 16 is the only supported database.

### 5.1 Finding

The core finding table stores scored, enriched vulnerability and misconfiguration
records.

| Column                 | Type          | Description                                           |
|------------------------|---------------|-------------------------------------------------------|
| id                     | UUID (PK)     | Internal identifier                                   |
| tenable_finding_id     | VARCHAR(255)  | Tenable's finding ID (unique, indexed)                |
| tenable_asset_id       | VARCHAR(255)  | Tenable's asset UUID                                  |
| title                  | VARCHAR(1000) | Finding title / plugin name                           |
| cve_id                 | VARCHAR(50)   | CVE identifier (nullable)                             |
| severity               | VARCHAR(20)   | Tenable severity: Critical/High/Medium/Low/Info       |
| vpr_score              | FLOAT         | Vulnerability Priority Rating (0.1-10.0)              |
| acr                    | INTEGER       | Asset Criticality Rating (1-10)                       |
| aes                    | INTEGER       | Asset Exposure Score (0-1000)                         |
| epss_score             | FLOAT         | Exploit Prediction Scoring System (0-100)             |
| exploit_maturity       | VARCHAR(50)   | Exploit maturity level                                |
| cvssv3_score           | FLOAT         | CVSSv3 base score                                     |
| source                 | VARCHAR(50)   | Origin module: Nessus / CloudSecurity / WAS           |
| plugin_id              | VARCHAR(50)   | Tenable plugin identifier                             |
| solution               | TEXT          | Recommended remediation                               |
| asset_name             | VARCHAR(500)  | Asset hostname or identifier                          |
| asset_type             | VARCHAR(100)  | Asset type (host, cloud resource, container, etc.)    |
| asset_ip               | VARCHAR(50)   | IP address                                            |
| asset_hostname         | VARCHAR(500)  | FQDN                                                 |
| portfolio              | VARCHAR(255)  | Business portfolio (from enrichment)                  |
| service                | VARCHAR(255)  | Service name (from enrichment)                        |
| environment            | VARCHAR(50)   | Environment: prod / staging / dev                     |
| data_sensitivity       | VARCHAR(50)   | Data sensitivity classification                       |
| asset_criticality      | VARCHAR(20)   | CRITICAL / HIGH / MEDIUM / LOW                        |
| asset_criticality_score| FLOAT         | Normalised criticality (0.25-1.0)                     |
| service_owner          | VARCHAR(255)  | Individual owner                                      |
| service_owner_team     | VARCHAR(255)  | Owning team                                           |
| risk_model             | VARCHAR(20)   | "custom" or "lumin_ces"                               |
| risk_score             | FLOAT         | Computed risk score (0.0-1.0)                         |
| risk_rating            | VARCHAR(20)   | CRITICAL / HIGH / MEDIUM / LOW                        |
| sla_days               | INTEGER       | SLA window in days                                    |
| sla_due_date           | DATE          | first_seen + sla_days                                 |
| sla_status             | VARCHAR(20)   | WITHIN_SLA / APPROACHING / BREACHED                   |
| state                  | VARCHAR(20)   | OPEN / REMEDIATED / STALE                             |
| tenable_state          | VARCHAR(20)   | Active / Fixed / Resurfaced / New                     |
| first_seen             | DATETIME      | When Tenable first detected the finding               |
| last_seen              | DATETIME      | Most recent Tenable observation                       |
| remediated_at          | DATETIME      | When state changed to REMEDIATED                      |
| time_to_fix_days       | INTEGER       | Days between first_seen and remediated_at             |
| is_recurrence          | BOOLEAN       | Whether this finding has recurred                     |
| recurrence_count       | INTEGER       | Number of times the finding recurred                  |
| jira_ticket_key        | VARCHAR(50)   | Linked Jira ticket (e.g., VULN-123)                   |
| jira_ticket_status     | VARCHAR(50)   | Current Jira ticket status                            |
| jira_created_at        | DATETIME      | When Jira ticket was created                          |
| jira_closed_at         | DATETIME      | When Jira ticket was closed                           |
| created_at             | DATETIME      | Row creation time                                     |
| updated_at             | DATETIME      | Last modification time                                |
| last_run_id            | UUID          | Pipeline run that last touched this record            |

**Indexes**: state+risk_rating, sla_due_date+sla_status, portfolio+service,
last_seen, jira_ticket_key.

### 5.2 FindingStaging

Temporary table holding normalised findings from the current pipeline run.
Schema mirrors Finding but includes `run_id` for isolation and `tenable_tags`
(JSON) for carrying raw tag data and enrichment context through the pipeline.
Cleared after each run completes.

### 5.3 EnrichmentMapping

Asset-to-business context mappings. Keyed by `(asset_identifier, identifier_type)`
with a unique constraint. Sources: `csv`, `aws_tags`, `manual`.

Fields: portfolio, service, environment, data_sensitivity, asset_criticality,
asset_criticality_score, service_owner, service_owner_team.

### 5.4 EnrichmentOverride

Manual per-field overrides uploaded via CSV. Allows overriding a single field
for a specific asset without replacing the entire enrichment mapping.

### 5.5 JiraActionQueue

Queue of pending Jira operations produced by reconciliation. Each entry has:
- `action`: CREATE / UPDATE / CLOSE / REOPEN
- `payload`: JSON with action-specific data (title, risk_rating, reason, etc.)
- `status`: PENDING / DONE / FAILED
- Linked to `run_id` and `finding_id`

### 5.6 JiraSyncLog

Audit trail of all Jira API calls. Records request payload, response status,
response body, and success flag. Used for debugging and compliance.

### 5.7 PipelineRun

Pipeline execution metadata. Tracks status, trigger source, all reconciliation
counts, Jira ticket counts, errors, and timing.

### 5.8 RiskException

Risk acceptance workflow. Tracks exception requests with justification,
compensating controls, expiry date, and approval decision chain
(PENDING / APPROVED / REJECTED).

---

## 6. Scoring Engine

The scoring engine supports two configurable models. The active model is set
via `scoring.active_model` in `config/scoring.yaml`.

### 6.1 Custom Model (default)

Formula:

```
risk_score = (vpr_normalised * vpr_weight) + (acs * acs_weight)
```

Where:
- `vpr_normalised` = VPR score / 10.0 (clamped to 0.0-1.0)
- `acs` = asset criticality score (0.25-1.0, from enrichment)
- Default weights: VPR 50%, ACS 50%

**VPR Fallback**: When VPR is unavailable, severity maps to a fallback:

| Severity | Fallback VPR |
|----------|-------------|
| Critical | 9.0         |
| High     | 7.0         |
| Medium   | 5.0         |
| Low      | 2.0         |
| Info     | 0.5         |

**ACS Default**: If no enrichment data exists, ACS defaults to 0.25 (LOW).

**Rating Thresholds** (configurable):

| Risk Rating | Score Threshold |
|-------------|-----------------|
| CRITICAL    | >= 0.75         |
| HIGH        | >= 0.50         |
| MEDIUM      | >= 0.30         |
| LOW         | < 0.30          |

### 6.2 Lumin CES Model

Uses Tenable's native Asset Exposure Score (AES) when available, which
represents Tenable's own CES = f(VPR, ACR) calculation.

If AES is not available, approximates CES:

```
approximate_ces = ((vpr / 10) * 500) + ((acr / 10) * 500)
```

CES is on a 0-1000 scale, normalised to 0.0-1.0 for consistency.

**CES Rating Thresholds** (configurable):

| Risk Rating | CES Threshold |
|-------------|---------------|
| CRITICAL    | >= 800        |
| HIGH        | >= 600        |
| MEDIUM      | >= 400        |
| LOW         | < 400         |

### 6.3 Scoring Dispatch

The `score_finding()` function in `src/scoring/engine.py` reads the active
model from config and delegates to the appropriate model. Both models return
a `ScoringResult` dataclass with `risk_score`, `risk_rating`, and `risk_model`.

---

## 7. SLA Policy

A **unified SLA policy** applies to all finding types -- no split between
vulnerabilities and misconfigurations. SLA is determined by risk rating.

| Risk Rating | SLA (calendar days) |
|-------------|---------------------|
| CRITICAL    | 10                  |
| HIGH        | 30                  |
| MEDIUM      | 45                  |
| LOW         | 90                  |

### SLA Status Determination

```
due_date = first_seen + sla_days

if today > due_date:              BREACHED
elif days_remaining <= 5:         APPROACHING
else:                             WITHIN_SLA
```

- `approaching_warning_days` is configurable (default: 5)
- `use_business_days` is supported but defaults to false
- SLA is recalculated on each pipeline run
- On recurrence, SLA resets from the new first_seen date

---

## 8. Enrichment

Enrichment adds business context to findings so that risk scoring accounts for
asset criticality and tickets are routed to the correct service teams.

### Enrichment Fields

| Field                  | Purpose                                |
|------------------------|----------------------------------------|
| portfolio              | Business portfolio / department        |
| service                | Service or application name            |
| environment            | prod / staging / dev                   |
| data_sensitivity       | PII / PHI / financial / public         |
| asset_criticality      | CRITICAL / HIGH / MEDIUM / LOW         |
| asset_criticality_score| Normalised score (0.25-1.0)            |
| service_owner          | Individual responsible                 |
| service_owner_team     | Team responsible                       |

### Criticality Score Mapping

| Criticality | Score |
|-------------|-------|
| CRITICAL    | 1.0   |
| HIGH        | 0.75  |
| MEDIUM      | 0.50  |
| LOW         | 0.25  |

### Enrichment Sources (by priority)

1. **EnrichmentOverride** -- manual per-field overrides (highest priority)
2. **EnrichmentMapping (CSV)** -- bulk mappings loaded from CSV files
3. **EnrichmentMapping (AWS Tags)** -- auto-synced from AWS resource tags (Phase 1)
4. **Tenable Tags** -- fallback if no mapping exists

### Matching Logic

Staged findings are matched against enrichment mappings by:
1. `tenable_asset_id` (exact match, identifier_type = "asset_id")
2. `asset_name` (case-insensitive, identifier_type = "asset_name")

Enrichment data is attached to staging records via the `tenable_tags._enrichment`
JSON field, then propagated to the `findings` table during reconciliation.

---

## 9. Jira Ticketing

### Phased Rollout Control

Jira ticket creation is gated by a rollout configuration that controls which
findings get tickets. This prevents overwhelming service teams during initial
deployment.

**Rollout Phases** (configured in `config/rollout.yaml`):

| Phase           | Severity Filter          | Team Filter          | Max Tickets/Run |
|-----------------|--------------------------|----------------------|-----------------|
| pilot           | CRITICAL, HIGH           | team-platform, team-api | 50           |
| critical_high   | CRITICAL, HIGH           | (all teams)          | 100             |
| medium          | CRITICAL, HIGH, MEDIUM   | (all teams)          | 200             |
| full            | ALL                      | (all teams)          | 500             |

### Jira Configuration

- Default project: configurable (e.g., "VULN")
- Portfolio-to-project mapping for routing tickets to team-specific Jira projects
- Priority mapping: risk rating to Jira priority (CRITICAL -> Highest, etc.)
- Labels: all tickets tagged with "vm-middleware"
- Close transition: "Done"
- Reopen transition: "To Do"

### Action Queue Pattern

Reconciliation produces Jira actions (CREATE / UPDATE / CLOSE / REOPEN) in the
`jira_action_queue` table. A separate Jira sync step processes the queue,
executes API calls, and logs results to `jira_sync_log`. This decouples
reconciliation from Jira availability.

---

## 10. Project Structure

```
vm-middleware/
|-- pyproject.toml              # Project metadata and dependencies
|-- Makefile                    # Developer shortcuts
|-- docker-compose.yaml         # Local PostgreSQL 16
|-- .env.example                # Environment variable template
|
|-- config/
|   |-- scoring.yaml            # Scoring model selection and thresholds
|   |-- sla_policy.yaml         # SLA days per risk rating
|   |-- rollout.yaml            # Jira rollout phase configuration
|   |-- schedule.yaml           # Pipeline cron schedule
|   |-- tenable.yaml            # Tenable API settings and retrieval mode
|   |-- jira.yaml               # Jira project, priority, and transition config
|
|-- src/
|   |-- common/
|   |   |-- config.py           # YAML loader + Pydantic settings models
|   |   |-- db.py               # SQLAlchemy engine, session factory, Base
|   |   |-- logging.py          # Structured JSON logging (structlog)
|   |   |-- models.py           # All SQLAlchemy ORM models
|   |
|   |-- ingestion/
|   |   |-- tenable_client.py   # HTTP client for Tenable One Inventory API
|   |   |-- tenable_ingestion.py# Normalisation and staging orchestrator
|   |   |-- enrichment.py       # CSV loader and enrichment applicator
|   |
|   |-- scoring/
|   |   |-- engine.py           # Scoring dispatcher (routes to active model)
|   |   |-- custom_model.py     # Custom weighted model (VPR + ACS)
|   |   |-- lumin_model.py      # Lumin CES model (AES-based)
|   |   |-- sla.py              # SLA due date and status calculation
|   |   |-- types.py            # ScoringResult dataclass
|   |
|   |-- reconciliation/
|   |   |-- reconciler.py       # Core reconciliation engine
|   |
|   |-- integration/            # Jira client (Phase 1)
|   |-- reporting/              # CSV report generation (Phase 2)
|   |-- api/                    # FastAPI routers and schemas (Phase 2)
|   |-- lambdas/                # AWS Lambda handlers (Phase 2)
|   |-- pipeline.py             # Sequential pipeline runner
|
|-- db/
|   |-- alembic.ini             # Alembic configuration
|   |-- migrations/
|       |-- env.py              # Alembic environment
|       |-- versions/           # Migration scripts
|
|-- tests/
|   |-- conftest.py             # Shared fixtures and test DB session
|   |-- unit/
|   |   |-- test_scoring.py     # Scoring model tests
|   |   |-- test_sla.py         # SLA calculation tests
|   |   |-- test_reconciliation.py # Reconciliation path tests
|   |   |-- test_tenable_client.py # API client tests (mocked)
|   |-- integration/            # Integration tests (Phase 1)
|
|-- scripts/
|   |-- run_local.py            # Local pipeline entry point
```

---

## 11. Technology Stack

| Component          | Technology                         | Purpose                              |
|--------------------|------------------------------------|--------------------------------------|
| Language           | Python 3.12+                       | Primary runtime                      |
| ORM                | SQLAlchemy 2.0+                    | Database access and models           |
| Migrations         | Alembic 1.13+                      | Schema versioning                    |
| Database           | PostgreSQL 16                      | Persistent storage (no S3)           |
| HTTP client        | httpx 0.27+                        | Tenable API communication            |
| Retry logic        | tenacity 8.0+                      | Exponential backoff for API calls    |
| Config validation  | Pydantic 2.0+ / pydantic-settings  | Typed config models                  |
| Config format      | YAML                               | Human-readable configuration         |
| Logging            | structlog 24.0+                    | Structured JSON logging              |
| Testing            | pytest 8.0+ / respx / factory-boy  | Unit and integration tests           |
| Linting            | ruff                               | Code quality and formatting          |
| Containerisation   | Docker Compose                     | Local development database           |
| API (Phase 2)      | FastAPI                            | REST API service                     |
| Compute (Phase 2)  | AWS Lambda                         | Pipeline execution                   |
| Service (Phase 2)  | ECS Fargate                        | API hosting                          |
| Scheduling         | EventBridge (Phase 2)              | Cron-triggered pipeline runs         |

---

## 12. Configuration Reference

### Environment Variables

| Variable             | Required | Default                          | Description                    |
|----------------------|----------|----------------------------------|--------------------------------|
| DATABASE_URL         | Yes      | postgresql://...localhost:5432   | PostgreSQL connection string   |
| TENABLE_ACCESS_KEY   | Yes*     | (empty)                          | Tenable API access key         |
| TENABLE_SECRET_KEY   | Yes*     | (empty)                          | Tenable API secret key         |
| JIRA_API_TOKEN       | No       | (empty)                          | Jira API token (Phase 1+)      |
| JIRA_USER_EMAIL      | No       | (empty)                          | Jira user email (Phase 1+)     |
| CONFIG_DIR           | No       | config                           | Path to YAML config directory  |
| LOG_LEVEL            | No       | INFO                             | Logging level                  |

*Required for production; not needed when using `--mock` mode.

### YAML Configuration Files

**config/scoring.yaml**

```yaml
scoring:
  active_model: "custom"           # "custom" | "lumin_ces"
  custom:
    vpr_weight: 0.50
    acs_weight: 0.50
    thresholds:
      critical: 0.75
      high: 0.50
      medium: 0.30
  lumin:
    ces_thresholds:
      critical: 800
      high: 600
      medium: 400
```

**config/sla_policy.yaml**

```yaml
sla:
  critical: 10
  high: 30
  medium: 45
  low: 90
  use_business_days: false
  approaching_warning_days: 5
```

**config/tenable.yaml**

```yaml
tenable:
  base_url: "https://cloud.tenable.com"
  retrieval_mode: "search"         # "search" | "export"
  findings_endpoint: "/api/v1/t1/inventory/findings/search"
  export_endpoint: "/api/v1/t1/inventory/export/findings"
  page_size: 10000
  extra_properties: "asset_name,vpr_score,cve,solution,acr,aes,..."
  severity_filter: null
  stale_threshold_days: 7
  request_timeout_seconds: 120
  max_retries: 3
  export_poll_interval: 10
  export_max_wait: 600
```

**config/rollout.yaml**

```yaml
rollout:
  phase: "pilot"
  phases:
    pilot:
      severity_filter: ["CRITICAL", "HIGH"]
      team_filter: ["team-platform", "team-api"]
      max_tickets_per_run: 50
    critical_high:
      severity_filter: ["CRITICAL", "HIGH"]
      team_filter: []
      max_tickets_per_run: 100
    medium:
      severity_filter: ["CRITICAL", "HIGH", "MEDIUM"]
      team_filter: []
      max_tickets_per_run: 200
    full:
      severity_filter: ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
      team_filter: []
      max_tickets_per_run: 500
```

**config/schedule.yaml**

```yaml
schedule:
  cron: "0 6 * * *"               # Daily at 06:00 UTC
  timezone: "UTC"
  enabled: true
```

**config/jira.yaml**

```yaml
jira:
  base_url: "https://org.atlassian.net"
  default_project: "VULN"
  issue_type: "Task"
  labels: ["vm-middleware"]
  priority_mapping:
    CRITICAL: "Highest"
    HIGH: "High"
    MEDIUM: "Medium"
    LOW: "Low"
  portfolio_project_mapping: {}
  close_transition: "Done"
  reopen_transition: "To Do"
```

---

## 13. Phase Alignment

### Phase 0 -- Foundation (CURRENT)

Implemented and operational. Provides end-to-end pipeline execution locally.

| Component                          | Status      |
|------------------------------------|-------------|
| Project scaffolding                | Complete    |
| YAML configuration system          | Complete    |
| PostgreSQL database + Alembic      | Complete    |
| SQLAlchemy data models (9 tables)  | Complete    |
| Structured logging (structlog)     | Complete    |
| Tenable client (sync + async)      | Complete    |
| Ingestion + normalisation          | Complete    |
| Enrichment from CSV                | Complete    |
| Custom scoring model               | Complete    |
| Lumin CES scoring model            | Complete    |
| SLA calculation                    | Complete    |
| Reconciliation engine (5 paths)    | Complete    |
| Jira action queue (no execution)   | Complete    |
| Pipeline runner (sequential)       | Complete    |
| Mock Tenable client                | Complete    |
| Unit tests (scoring, SLA, recon)   | Complete    |

### Phase 1 -- Integration

| Component                          | Status      |
|------------------------------------|-------------|
| Jira API client + ticket creation  | Not started |
| Jira sync step (process queue)     | Not started |
| AWS Tags enrichment source         | Not started |
| Rollout gate enforcement           | Not started |
| Risk exception workflow            | Not started |
| Integration tests                  | Not started |

### Phase 2 -- Production Deployment

| Component                          | Status      |
|------------------------------------|-------------|
| FastAPI API service                | Not started |
| AWS Lambda handlers                | Not started |
| ECS Fargate deployment             | Not started |
| Step Functions orchestration       | Not started |
| EventBridge cron scheduling        | Not started |
| CSV report generation              | Not started |
| RDS PostgreSQL setup               | Not started |
| CloudWatch monitoring              | Not started |
| E2E tests                          | Not started |

---

## 14. Key Design Decisions

### Single Tenable API source

The Tenable One Inventory API aggregates all modules. Querying individual
product APIs (Nessus, Cloud Security, WAS) would require separate clients,
different authentication, and manual deduplication. The Inventory API
eliminates this complexity.

### Pull-and-reconcile over push notifications

Tenable does not offer webhooks for finding state changes. The middleware
polls on a schedule and reconciles the full dataset. This is reliable but
means remediation detection has latency equal to the schedule interval.

### Unified SLA policy

No distinction between vulnerabilities and misconfigurations. Both types
are scored identically and subject to the same SLA windows. This simplifies
policy management and avoids debates about classification.

### PostgreSQL only -- no S3

All data lives in PostgreSQL. Findings are rows, not files. This simplifies
queries, eliminates ETL between storage tiers, and keeps the operational
footprint small. The dataset size (typically under 500k findings) is well
within PostgreSQL's comfort zone.

### Staging table pattern

Findings are ingested into a temporary staging table, then compared against
the persistent findings table during reconciliation. This ensures the
reconciliation logic operates on a consistent snapshot and prevents partial
updates if ingestion fails midway.

### Jira action queue (decoupled)

Reconciliation produces Jira actions into a queue table rather than calling
Jira directly. This decouples reconciliation from Jira availability, enables
retry of failed Jira calls, and provides an audit trail. The queue can be
drained by a separate step or Lambda.

### Configurable scoring models

Two models exist to support different organisational maturity levels. The
custom model lets teams emphasise asset criticality (via enrichment). The
Lumin model delegates scoring to Tenable's own CES calculation for
organisations that trust Tenable's built-in risk assessment.

### Hybrid deployment (Lambda + Fargate)

Lambda handles the batch pipeline (scheduled, bursty, short-lived).
ECS Fargate hosts the API service (long-running, always-on). This optimises
cost: Lambda charges per invocation, Fargate provides consistent latency for
API queries.

### Phased Jira rollout

Service teams are onboarded gradually. The pilot phase limits tickets to
Critical/High findings for selected teams. Each subsequent phase widens the
scope. This prevents alert fatigue and builds trust in the system before
full-scale deployment.

---

## 15. Non-Functional Requirements

### Performance

- Pipeline should complete within 15 minutes for up to 200,000 findings
- Ingestion uses batch inserts (500 records per flush) to PostgreSQL
- Tenable API pagination at 10,000 findings per page
- Database indexes on all join and filter columns

### Reliability

- Automatic retry on Tenable API rate limits (429) with exponential backoff
- Pipeline run tracking with RUNNING / SUCCESS / FAILED status
- Staging table isolation prevents partial corruption of the findings table
- Transaction-scoped database sessions with rollback on error

### Security

- API credentials in environment variables, never in config files or logs
- Tenable keys via `X-ApiKeys` header (not URL parameters)
- Jira API token via environment variable
- No secrets in YAML configuration

### Observability

- Structured JSON logging via structlog with context (run_id, step name)
- Pipeline run statistics persisted to database
- Jira API call audit trail in jira_sync_log
- Console renderer available in DEBUG mode for local development

### Maintainability

- All configuration externalised to YAML files with sensible defaults
- Pydantic models validate configuration at startup
- SQLAlchemy models provide type-safe database access
- Alembic manages schema evolution
- ruff enforces consistent code style (Python 3.12 target, 100-char lines)

### Testability

- MockTenableClient for local development without API credentials
- conftest.py provides shared fixtures and in-memory database sessions
- Unit tests cover scoring models, SLA calculation, and all reconciliation paths
- Integration test directory prepared for Phase 1
