# VM Middleware — Top-Level Architecture Overview

> **Purpose**: Quick-read architectural summary for new engineers, stakeholders,
> and anyone needing a 10-minute orientation on what this system does and how it fits together.
>
> For deep technical detail, see [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## What It Does

The VM Middleware is a vulnerability management orchestration system that:

1. **Pulls** vulnerability findings from Tenable Exposure Management
2. **Enriches** them with business context (portfolio, service, environment, criticality)
3. **Scores** them using a configurable risk model (VPR + asset criticality)
4. **Tracks** SLA compliance and detects remediations
5. **Routes** prioritised findings to service teams via Jira tickets
6. **Reports** on exposure, compliance, and trends via CSV exports

It sits between Tenable (the data source) and Jira (the action system), adding
the business context, prioritisation, and automation that neither system
provides natively.

---

## The Problem It Solves

| Problem | How the Middleware Solves It |
|---|---|
| Tenable has vulnerability data but no workflow to route it to teams | Automates Jira ticket creation with correct ownership and SLA |
| Tenable's native risk scoring doesn't match our business model | Applies a configurable weighted formula (VPR + ACS) per organisation policy |
| Service teams fear ticket volume overwhelming their backlog | Phased rollout controller filters by severity and team |
| No Jira push notifications for remediation tracking | Reconciles Tenable state on every run to auto-close tickets |
| Scattered reporting across Tenable UI, spreadsheets, emails | Single PostgreSQL source of truth feeds all reports |

---

## Core Components

### 1. Tenable Client
- Talks to the **Tenable One Inventory API** (Exposure Management layer)
- Single endpoint returns findings from VM, Cloud Security, WAS, and containers
- Two modes: synchronous search (for <50k findings) or async bulk export
- Handles authentication, pagination, retries, rate limiting

### 2. Ingestion & Normalisation
- Fetches raw findings and maps them into a canonical data model
- Writes to a `findings_staging` table (per pipeline run)
- Tenable's `finding_id` is the stable unique identifier

### 3. Enrichment Engine
- Looks up each finding's asset against an enrichment store
- Populates: portfolio, service, environment, data sensitivity, asset criticality, service owner
- Sources: Tenable tags (Phase 1), CSV uploads, AWS resource tags

### 4. Scoring Engine
- Configurable risk model, two options:
  - **Custom**: `risk_score = (VPR × weight) + (ACS × weight)` with tuneable thresholds
  - **Lumin CES**: uses Tenable's native Cyber Exposure Score
- Outputs a risk rating: CRITICAL / HIGH / MEDIUM / LOW

### 5. SLA Engine
- Calculates due dates based on risk rating
- Tracks status: `WITHIN_SLA` / `APPROACHING` / `BREACHED`
- Unified policy (no split between vulnerability types — configurable)

### 6. Reconciliation Engine
- Compares current Tenable state against stored findings
- Handles five state transitions:
  - **NEW** — first time seen → create ticket
  - **STILL OPEN** — re-observed as active → update ticket
  - **REMEDIATED** — Tenable reports Fixed → close ticket
  - **RECURRENCE** — previously fixed, now back → reopen ticket
  - **STALE** — missing from results beyond threshold → flag for review

### 7. Jira Integration
- Creates, updates, closes, and reopens tickets based on reconciliation output
- Phased rollout: pilot → critical/high → medium → full
- Queue-based (separates Jira API calls from pipeline execution)

### 8. API Service
- FastAPI app for CSV report generation, config management, exception requests
- Deployed as a persistent service (ECS Fargate in production)
- No UI dashboards — CSV is the reporting format

---

## Data Flow

```
Tenable Exposure Management
        │
        │  POST /api/v1/t1/inventory/findings/search  (sync)
        │  POST /api/v1/t1/inventory/export/findings  (async bulk)
        ▼
┌──────────────────────────────────────────────────────────────┐
│                    VM MIDDLEWARE PIPELINE                    │
│                                                              │
│  [1] Ingest  →  [2] Enrich  →  [3] Score  →  [4] SLA         │
│                                                              │
│                            │                                 │
│                            ▼                                 │
│                    [5] Reconcile                             │
│                            │                                 │
│                            ▼                                 │
│                   [6] Jira Actions                           │
│                  (create/update/close)                       │
│                                                              │
│                            │                                 │
│                            ▼                                 │
│                    [7] CSV Reports                           │
│                                                              │
│                   (all data in PostgreSQL)                   │
└──────────────────────────────────────────────────────────────┘
        │                                │
        ▼                                ▼
     Jira Cloud                    PostgreSQL 16
  (ticket lifecycle)           (single source of truth)
```

The pipeline runs on a configurable schedule (default: daily).
Each run is a full reconciliation — the middleware doesn't depend on
push notifications from Jira.

---

## Technology Choices

| Layer | Technology | Why |
|---|---|---|
| Language | Python 3.12+ | Security tooling ecosystem, Tenable SDK alignment |
| HTTP client | httpx + tenacity | Async-capable, built-in retries |
| Data model | Pydantic + SQLAlchemy | Type safety + relational queries |
| Database | PostgreSQL 16 | Complex reporting queries, relational integrity |
| Migrations | Alembic | Schema versioning |
| API framework | FastAPI | OpenAPI docs, async support |
| Compute (prod) | AWS Lambda + EventBridge | Scheduled pipeline, serverless cost |
| API host (prod) | ECS Fargate | Persistent service for reports |
| Config | YAML + env vars | Human-readable, editable via API |
| Testing | pytest | Standard Python test tooling |

**What we deliberately avoided:**
- S3 for raw data archiving (PostgreSQL holds everything)
- DynamoDB (relational queries win for reporting)
- Dashboard UIs in Phase 0-2 (CSV exports meet immediate needs)
- Microservices (monolithic pipeline is simpler for this scope)

---

## Deployment Topology

### Local Development
- Docker Compose for PostgreSQL
- Pipeline runs via CLI (`python scripts/run_local.py`)
- Mock Tenable client loads fixtures from JSON

### Production (Phase 1+)
```
  EventBridge (cron)
         │
         ▼
   Step Functions ──→ Lambda: Pipeline execution
                             │
                             ▼
                         RDS PostgreSQL
                             ▲
                             │
                        ECS Fargate: API Service (FastAPI)
                             ▲
                             │
                   Users (via AWS ALB + OIDC SSO)
```

- All secrets (Tenable keys, Jira token, DB credentials) in AWS Secrets Manager
- VPC-private RDS, Lambda, ECS
- CloudWatch logs + metrics + alarms
- X-Ray for distributed tracing

---

## Key Design Decisions

1. **Single data source** — The Tenable One Inventory API aggregates all Tenable modules. We don't integrate with VM, Cloud Security, or WAS APIs separately.

2. **Pull and reconcile** (not push) — The middleware re-pulls all findings each run and compares state. This eliminates the need for webhook infrastructure and makes the system self-healing.

3. **Tenable finding_id as primary key** — Stable across scans, unique across modules, persists through state changes. No composite keys or hashes needed.

4. **Don't auto-close on missing findings** — A finding absent from the API might be a decommissioned asset, not a remediation. We mark it `STALE` for human review. Only Tenable's explicit `FIXED` state triggers ticket closure.

5. **Configurable scoring** — Organisations can switch between custom weighted formula and Tenable Lumin CES via config. No code change required.

6. **Phased rollout controller** — Config-driven filters prevent flooding service teams with tickets on day one.

7. **PostgreSQL only** — No S3, no DynamoDB. Relational DB handles raw findings, history, reports, and config in one place.

---

## Current Status

| Phase | Status | Scope |
|---|---|---|
| Phase 0 — Foundation | ✅ Complete | Ingestion, scoring, SLA, reconciliation, local dev environment |
| Phase 1 — Production Baseline | 🔜 Next | Lambda deployment, scheduler, tag-based filtering, baseline report |
| Phase 2 — Jira & Reporting | 📋 Planned | Jira integration, phased rollout, CSV reports, exception management |
| Phase 3 — Expansion | 📋 Planned | Azure, ASM, executive reporting, SIEM integration |
| Phase 4 — Optimisation | 📋 Planned | Maturity reassessment, automation, handover to BAU |

---

## Documentation Map

- [OVERVIEW.md](./OVERVIEW.md) — this document (top-level summary)
- [ARCHITECTURE.md](./ARCHITECTURE.md) — detailed technical architecture with data model, algorithms, configuration reference
- [README.md](./README.md) — developer quickstart (install, test, run)
