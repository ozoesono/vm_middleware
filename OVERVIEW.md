# VM Middleware — Top-Level Architecture Overview

> **Purpose**: A 10-minute orientation for new engineers, stakeholders,
> and anyone needing the system shape without the implementation detail.
>
> For deep technical detail, see [ARCHITECTURE.md](./ARCHITECTURE.md).
> For the simplest possible summary, see [architecture_simple.md](./architecture_simple.md).

---

## What it does

The VM Middleware is a vulnerability-management orchestration system that:

1. **Pulls** findings from Tenable Exposure Management (filtered by tag, server-side)
2. **Enriches** each finding with business context (portfolio, service, environment, criticality)
3. **Scores** every finding with a configurable risk formula
4. **Tracks** SLA compliance and detects remediations / recurrences
5. **Enriches** CVEs with NVD descriptions and vendor advisory references
6. **Routes** prioritised findings to Jira (Phase 2)
7. **Reports** the resulting risk picture via CSV exports

It sits between Tenable (the data source) and Jira (the workflow), adding the
business context, risk prioritisation, and operational automation that neither
system provides natively.

---

## The problem it solves

| Problem | How the middleware solves it |
|---|---|
| Tenable has data but no way to route it to teams | Computes risk score + queues Jira ticket creation with the right ownership |
| Tenable's native risk score doesn't reflect business value | Configurable formula `(VPR × w) + (asset_criticality × w)` driven by tags |
| Tenable returns no `finding_solution` for Cloud Security findings | Enriches every CVE with NVD description + vendor references (cached) |
| Findings/search API silently ignores tag filters | Two-stage strategy: filter tagged assets, then filter findings by asset_id (server-side) |
| 4M+ findings overwhelm local memory | Streaming pipeline with per-page commit + resume checkpoint |
| No Jira webhook for "ticket resolved" | Pull-and-reconcile; Tenable state is the source of truth |
| Scattered reports across screenshots, spreadsheets | Single PostgreSQL source feeds six CSV report types |

---

## Core components

### 1. Tenable client
Wraps the Tenable One Inventory API. Two endpoints used:
- `assets/search` with **advanced query** for tag filtering
- `findings/search` with **batched server-side filter** on `asset_id`

Handles auth, pagination, retries, rate limits, and the API's documentation gaps.

### 2. Tag taxonomy & parser
Naming convention `<Category>-<Value>` in PascalCase. The parser extracts
category and value from each tag — used both for filtering and for enriching
findings with business context.

### 3. Streaming ingestion
Page-by-page fetch, normalise, stage. Each page commits to PostgreSQL and
advances a checkpoint, so a 15-minute run is interruption-safe and resumable.

### 4. Enrichment engine
Three sources, applied in priority order:
- **Asset tags** (primary): parsed from Tenable, populates portfolio, service, environment, criticality, sensitivity, owner
- **CSV overrides**: manual corrections via uploaded mapping files
- **NVD**: CVE descriptions, CVSS, CWE, references — fills the gap left by Tenable for Cloud Security findings

### 5. Scoring engine
Configurable formula. Two models (Custom VPR+ACS, Lumin CES). Maps numeric
score to a rating (CRITICAL / HIGH / MEDIUM / LOW) via tunable thresholds.

### 6. SLA engine
Calculates due dates from `first_seen` + severity-based SLA days. Tracks
status: WITHIN_SLA / APPROACHING / BREACHED.

### 7. Reconciliation engine
Five-state machine that compares the current run against stored findings:
NEW / STILL OPEN / REMEDIATED / RECURRENCE / STALE. Drives Jira ticket
lifecycle (Phase 2) without needing Jira push notifications.

### 8. CSV reporting
Six report types: full findings, risk summary, SLA breaches, SLA approaching,
recurrence, portfolio summary. All accept the same filter set.

---

## Data flow

```
Tenable Exposure Management
        |
   advanced query        server-side asset_id filter
        |                            |
        v                            v
+-------------------------------------------------------+
|                    VM MIDDLEWARE                       |
|                                                       |
|   pre-flight  →  stream pages  →  enrich  →  score    |
|                                                       |
|        +-----+-----+-----+-----+-----+               |
|              |     |     |                            |
|         tag enrich  CSV  NVD                          |
|                                                       |
|         risk formula + SLA                            |
|                                                       |
|         reconciliation (5-state machine)              |
|              |                                        |
|         findings table + jira_action_queue            |
|                                                       |
+-------------------------------------------------------+
        |                            |
        v                            v
     CSV reports                  Jira (Phase 2)
```

The pipeline is fully **pull-based and idempotent**: any run is safely
re-runnable without producing duplicates or losing state.

---

## Technology choices

| Layer | Technology | Why |
|---|---|---|
| Language | Python 3.10+ | Mature ecosystem for security tooling, fast iteration |
| HTTP | httpx + tenacity | Solid retry semantics, easy mocking in tests |
| ORM | SQLAlchemy 2.0 + Alembic | Migrations + complex reporting queries |
| Database | PostgreSQL 16 | Relational, queryable, single source of truth |
| Config | Pydantic + YAML | Typed, validated, env-overridable |
| Logging | structlog | Structured JSON output ready for any aggregator |
| Tests | pytest | 116 unit tests covering all pipeline stages |
| Compute (prod) | AWS Lambda + EventBridge | Scheduled pipeline, serverless cost |
| Local dev | Docker Compose | One-command Postgres setup |

### What we deliberately avoided

- S3 storage — PostgreSQL holds everything (simpler ops)
- DynamoDB — relational queries win for reporting
- Dashboards / web UI — CSV exports meet the immediate need
- Async/await — sync HTTP is fine at this scale
- Microservices — one orchestrator is plenty

---

## Deployment topology

### Local development
- Docker Compose for PostgreSQL on port 5435
- Pipeline via CLI (`.venv/bin/python3 scripts/run_local.py`)
- Mock client loads JSON fixtures for offline testing

### Production (Phase 1+)

```
EventBridge (cron, configurable)
       |
       v
   Step Functions ──→ Lambda (pipeline)
                         |
                         v
                    RDS PostgreSQL ←── Lambda / CLI (reports)
                         |
                    pgvector / etc. (future)
```

- Secrets in AWS Secrets Manager (Tenable keys, Jira token, NVD key, DB credentials)
- VPC-private RDS, Lambda in VPC subnets for RDS access
- CloudWatch logs + metrics + alarms
- X-Ray tracing across the pipeline

---

## Key design decisions

1. **Tenable Inventory API is the single source.** No per-module integration. The API aggregates VM, Cloud Security, WAS, container findings.

2. **Two-stage filter via the assets endpoint.** `findings/search` ignores tag filters; `assets/search` accepts an advanced query. We fetch tagged asset_ids first, then filter findings server-side by those IDs.

3. **Tag taxonomy encodes category in the value.** The API doesn't return Tenable's UI category field. `Category-Value` in PascalCase with the parser splitting on the first hyphen.

4. **Pull, don't listen.** Each run re-pulls and compares to stored state. No webhooks; no Jira state dependency.

5. **Tenable finding `id` as the dedup key.** Stable across scans, unique across sources, persists through state changes.

6. **Don't auto-close on missing findings.** Disappearance from the API ≠ remediation. Only an explicit Tenable `FIXED` state closes a Jira ticket.

7. **Streaming pipeline with checkpoint resume.** Each page commits + advances a checkpoint. Network failures, screen sleep, etc. cost at most one page.

8. **Configurable risk model.** Criticality scores, formula weights, and rating thresholds are all in `scoring.yaml`. Switching from custom to Lumin CES is a config flip.

9. **NVD enrichment for descriptions.** Tenable returns no `finding_solution` for Cloud Security findings. NVD provides the gap fill, cached per CVE.

10. **PostgreSQL only.** No S3, no DynamoDB. Single relational store keeps ops simple.

11. **CSV over dashboards.** Six report types, same filter set, downstream tools handle visualisation.

---

## Current status

| Phase | Status | Scope |
|---|---|---|
| Phase 0 — Foundation | Complete | Data model, ingestion, reconciliation, scoring, SLA, local dev |
| Phase 0+ — Risk model | Complete | Tag taxonomy, asset-tag enrichment, NVD enrichment, CSV reports |
| Phase 1 — Production baseline | Next | Lambda deployment, EventBridge schedule, AWS Secrets, validation runs |
| Phase 2 — Jira + reporting v2 | Planned | Jira integration, phased rollout, exception management |
| Phase 3 — Expansion | Planned | Azure, ASM, executive reporting, SIEM/SOAR |
| Phase 4 — Optimisation | Planned | Maturity reassessment, automation, BAU handover |

116 unit tests passing as of v3.

---

## Documentation map

| File | Audience | Length |
|---|---|---|
| [OVERVIEW.md](./OVERVIEW.md) | New engineers, stakeholders — 10-min read | ~220 lines |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Implementors — full technical detail | ~700 lines |
| [architecture_simple.md](./architecture_simple.md) | Quick reference — one page | ~65 lines |
| [tag_taxonomy.txt](./tag_taxonomy.txt) | Tag naming convention reference | — |
| [user_stories.txt](./user_stories.txt) | Phased user-story backlog | — |
| `README.md` | Developer quickstart (install, test, run) | — |
