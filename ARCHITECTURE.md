# VM Middleware — Architecture Document

> **Version**: 3.1
> **Status**: Approved for Phase 0+ implementation; subject to TDA review for Phase 1
> **Last updated**: 20 May 2026
> **Owner**: Security Engineering
>
> For implementation specifics (API quirks, field mappings, working payloads,
> debugging notes), see [IMPLEMENTATION_NOTES.md](./IMPLEMENTATION_NOTES.md).

---

## Table of Contents

1. [Introduction and Goals](#1-introduction-and-goals)
2. [Constraints](#2-constraints)
3. [System Context](#3-system-context)
4. [Solution Strategy](#4-solution-strategy)
5. [Building Block View](#5-building-block-view)
6. [Runtime View](#6-runtime-view)
7. [Deployment View](#7-deployment-view)
8. [Data View](#8-data-view)
9. [Cross-Cutting Concerns](#9-cross-cutting-concerns)
10. [Architectural Decisions](#10-architectural-decisions)
11. [Quality Requirements](#11-quality-requirements)
12. [Risks and Technical Debt](#12-risks-and-technical-debt)
13. [Glossary](#13-glossary)

---

## 1. Introduction and Goals

### 1.1 Business problem

The organisation holds licences for six Tenable modules but operationally
leverages fewer than two. Vulnerability data is being detected by Tenable
Cloud Security (~4.4M findings across ~2M assets) but is **trapped in the
Tenable platform** with no operational workflow to:

- Apply business context (which assets matter, who owns them)
- Apply the organisation's risk model (the corporate VPR+ACS formula)
- Map findings to service teams via Jira
- Track SLA compliance and remediation
- Produce auditable risk reports

The VM Middleware closes this gap, moving programme maturity from
**Level 1 (Initial/Ad-Hoc)** towards the target **Level 3 (Defined)**
per ISO 27002 control 8.8.

### 1.2 Stakeholders

| Stakeholder | Concern |
|---|---|
| CISO / Security Director | Risk posture, audit evidence, programme maturity |
| Vulnerability Manager | Process ownership, prioritisation, exception management |
| Vulnerability Review Board (VRB) | High-risk findings, SLA breaches, scoring calibration |
| Security Engineering | System design, implementation, day-to-day operation |
| Service Owners | Receive prioritised tickets, expected to remediate within SLA |
| Internal Audit / Compliance | Traceability of detection → decision → action |
| Project Sponsor | Delivery, cost, schedule, return on Tenable investment |

### 1.3 Goals (quality attributes that drove the design)

In rough priority order:

1. **Auditability** — Every detection, scoring decision, ticket action, and exception must be traceable. Decisions must survive an audit two years later.
2. **Configurability** — Risk formula, SLA policy, rollout phase, criticality scoring, and scheduling must all be adjustable without code change.
3. **Resilience** — Long-running pipelines (~10–20 minutes against the real Tenable instance) must survive transient failures and resume from where they stopped.
4. **Maintainability** — A small team will run this. The codebase, data model, and operational runbooks must remain comprehensible to one engineer.
5. **Reproducibility** — Identical input produces identical output. No hidden state, no implicit ordering effects.
6. **Operational safety** — Phased rollout to teams; never auto-close a Jira ticket on inferred (rather than asserted) remediation; never overwhelm a service team with ticket volume.
7. **Security** — OFFICIAL-SENSITIVE data classification. Secrets handled via secrets management; least-privilege IAM; encryption in transit and at rest.

### 1.4 Non-goals (deliberately out of scope)

- CMDB replacement
- Bulk vulnerability remediation execution
- Replacement of Tenable with another platform
- Real-time / event-driven processing (daily scheduled cadence is sufficient)
- Web UI / dashboards (Phase 0+; CSV reports meet the requirement)
- Findings from sources Tenable doesn't already ingest

---

## 2. Constraints

### 2.1 Technical constraints

| # | Constraint | Origin |
|---|---|---|
| C1 | No agents may be deployed on endpoints | Organisation policy |
| C2 | All findings must come via the Tenable Inventory API (Exposure Management). No per-module APIs. | Architectural simplification chosen during Phase 0 design |
| C3 | The Tenable Inventory API is **in beta**: filter semantics undocumented and unstable | Tenable platform constraint |
| C4 | Tenable `finding_solution` is null for 100% of Cloud Security findings | Tenable platform constraint (verified empirically) |
| C5 | No Jira webhook is consumed; the middleware cannot subscribe to Jira state changes | Jira tenancy constraint (no admin access to install webhooks) |
| C6 | Asset ownership data must be sourceable from Tenable tags or a CSV mapping; CMDB is not available | Organisation constraint |
| C7 | Python is the implementation language | Specified by the implementation plan (alignment with security tooling ecosystem) |

### 2.2 Organisational constraints

| # | Constraint | Implication |
|---|---|---|
| O1 | Small delivery team (1.0 FTE engineer for Weeks 1–12, 0.4 thereafter) | Architecture must remain simple; avoid microservices; favour single-process orchestration |
| O2 | Service teams have low appetite for ticket volume | Phased rollout controller is mandatory; pilot before broad rollout |
| O3 | Government sector classification: OFFICIAL-SENSITIVE | Encryption everywhere; UK-based AWS regions; auditable access |

### 2.3 Assumptions

| # | Assumption | Risk if false |
|---|---|---|
| A1 | Tenable Cloud Security correctly detects vulnerabilities on the assets in scope | Wrong data drives wrong decisions |
| A2 | Asset criticality can be expressed via a `Criticality-*` tag in Tenable | Risk scores would default to 0.25 (LOW) for all assets |
| A3 | The NVD API remains free and continues to publish CVE descriptions | Description column in reports would degrade for new CVEs |
| A4 | Service ownership tagging in Tenable will be completed before Phase 2 rollout | Tickets won't have an owner; manual assignment required |

---

## 3. System Context

```
              +-------------------------+
              |  Tenable One Platform    |
              |  (Exposure Management)   |
              +-----------+-------------+
                          | findings (read)
                          | assets   (read)
                          v
+------------+   +-------------------+   +---------------+
|  NVD       +-->|  VM Middleware    +-->|  Jira Cloud   |
|  (NIST)    |   |                   |   |  (Phase 2)    |
+------------+   +-------------------+   +---------------+
   ^ CVE detail              |
   | (read, cached)           | scored findings (read)
                              | risk reports (CSV)
                              v
                  +-------------------------+
                  |  Security Engineering   |
                  |  + Service Owners       |
                  |  + VRB / CISO           |
                  +-------------------------+
```

### 3.1 External actors and interfaces

| Actor / system | Direction | Interface | Purpose |
|---|---|---|---|
| **Tenable One Inventory API** | Inbound (read) | HTTPS, `X-ApiKeys` auth | Source of all vulnerability findings, asset metadata, and tags |
| **NVD (NIST National Vulnerability Database)** | Inbound (read) | HTTPS, optional API key | CVE descriptions, CVSS, CWE, references — fills the gap left by Tenable for Cloud Security findings |
| **Jira Cloud** *(Phase 2)* | Outbound (write) | REST API, OAuth/API token | Ticket lifecycle: create, update, close, reopen |
| **Security Engineering / VRB / CISO** | Outbound (read) | CSV reports via CLI; future dashboards | Risk reporting, exception management, programme governance |
| **Service Owners** *(Phase 2)* | Outbound (write via Jira) | Jira tickets | Receive prioritised, SLA-tracked remediation work |

### 3.2 What the middleware is not

It is not a vulnerability scanner, not a CMDB, not a ticket-management UI, and not a remediation executor. It is an orchestration and enrichment layer between Tenable and Jira, with risk reporting as a first-class output.

---

## 4. Solution Strategy

The four most strategically significant choices, with rationale tied to the goals in §1.3:

### 4.1 Pull-and-reconcile, not push

Each pipeline run re-pulls findings from Tenable and reconciles them against
stored state in PostgreSQL. The middleware never subscribes to events from
Tenable or Jira.

**Drives**: resilience (§1.3 #3), auditability (§1.3 #1), simplicity (§1.3 #4).
Eliminates webhook infrastructure, idempotency tracking, and out-of-order
event handling. Any run can be re-run without harm.

**Cost**: latency between a finding being fixed in Tenable and the Jira
ticket closing is bounded by the pipeline cadence (default daily). Accepted.

### 4.2 Single source via the Tenable Inventory API

The middleware integrates only with the Tenable Inventory API (Exposure
Management). VM, Cloud Security, WAS, and container findings all come
through this one endpoint, with a `sensor_type` field indicating origin.

**Drives**: maintainability (§1.3 #4). No per-module client code, no
per-module schema mapping.

**Cost**: the Inventory API is in beta with thin documentation (constraint
C3). The team has invested in mapping the actual API behaviour
(see [IMPLEMENTATION_NOTES.md](./IMPLEMENTATION_NOTES.md)).

### 4.3 Two-stage server-side filtering by tag

Because the findings/search endpoint silently ignores tag filters, but the
assets/search endpoint accepts an advanced query, the pipeline filters in two
stages:

1. Pre-fetch tagged asset IDs via `assets/search` (advanced query)
2. Stream findings via `findings/search`, server-side-filtered by asset_id batches

**Drives**: scalability. Avoids pulling all 4.4M findings to keep ~163K
relevant ones.

**Cost**: two HTTP-level interactions instead of one. Mitigated by caching
the asset list on the pipeline run record so resume doesn't re-fetch.

### 4.4 Tag taxonomy encoding category in value

Tag names follow the convention `<Category>-<Value>` in PascalCase, with the
category constrained to a single word. A taxonomy parser splits on the first
hyphen.

**Drives**: configurability (§1.3 #2). The same tag stream serves both
filtering and enrichment.

**Cost**: requires governance — the VM Manager must enforce taxonomy
compliance when teams create tags. The middleware logs warnings on
non-conforming tags but does not enforce.

---

## 5. Building Block View

This is the logical decomposition of the system. Each block has a single,
clear responsibility.

### 5.1 Level 1 — system overview

```
                     +----------------------+
                     |    VM Middleware     |
                     |                      |
                     |  +---------------+   |
                     |  |  Orchestrator |   |
                     |  +-------+-------+   |
                     |          |           |
                     |   +------+------+    |
                     |   |             |    |
                     |  Ingestion  Reporting |
                     |   |             |    |
                     |   +-----+-------+    |
                     |         |            |
                     |   +-----v-----+      |
                     |   | Reconciler |      |
                     |   +-----+-----+      |
                     |         |            |
                     |   +-----v-----+      |
                     |   |  Scoring  |      |
                     |   +-----+-----+      |
                     |         |            |
                     |   +-----v-----+      |
                     |   | Persistence|     |
                     |   +-----------+      |
                     +----------------------+
```

### 5.2 Level 2 — building blocks

| Block | Responsibility | Key dependencies |
|---|---|---|
| **Orchestrator** | Drives the pipeline: setup/resume run, sequencing of ingestion → enrichment → reconciliation → reporting hand-off | Persistence (PipelineRun) |
| **Ingestion** | All external data acquisition. Subdivided into Tenable client, NVD client, and CSV loader. | Tenable Inventory API, NVD API |
| **Enrichment** | Applies business context to staged findings. Three sources: parsed Tenable tags, CSV overrides, NVD CVE data. | Tag parser, NVD cache |
| **Scoring** | Computes risk score + risk rating per finding using the active model (custom VPR+ACS or Lumin CES). Computes SLA due date + status. | Configuration |
| **Reconciler** | Compares this run's staged findings to stored findings; produces state transitions (NEW / STILL OPEN / REMEDIATED / RECURRENCE / STALE). Emits Jira action queue entries. | Persistence (Finding, FindingStaging, JiraActionQueue) |
| **Reporting** | Generates CSV exports on demand from the canonical scored findings (read-side query). | Persistence (Finding, CveDetails) |
| **Persistence** | PostgreSQL schema + access. Single source of truth. | — |
| **Configuration** | Loads YAML configuration with env-var overrides into typed objects. Single read at orchestrator start. | — |

### 5.3 Internal interfaces between blocks

Each interface is in-process; no network or queue between components in
Phase 0+. Stability requirements:

| Interface | Contract |
|---|---|
| Ingestion → Persistence | Writes to `findings_staging` (per-run, additive, page-by-page commit) |
| Enrichment → Persistence | Updates `findings_staging.tenable_tags["_enrichment"]`; upserts to `cve_details` |
| Reconciler → Persistence | Upserts `findings`; inserts to `jira_action_queue`; updates `pipeline_runs` |
| Reporting → Persistence | Read-only query. LEFT JOIN findings with cve_details. |
| Orchestrator → all | Passes the active `AppConfig` and `run_id` |

---

## 6. Runtime View

Three scenarios cover the operationally significant paths.

### 6.1 Scenario A — Tagged pipeline run (the primary path)

The default operational pattern: run daily, filtered to one or more portfolio
tags, scoring and reconciling every finding on those tagged assets.

```
Engineer / scheduler
     |
     v
1. Orchestrator: create PipelineRun (status=RUNNING)
     |
     v
2. Ingestion (pre-flight)
     | calls Tenable assets/search advanced query
     | -> dict[asset_id -> [tag_names]]   (~33K assets for a portfolio)
     | persists to pipeline_runs.asset_ids_for_run
     v
3. Ingestion (streaming)
     | for each batch of 500 asset_ids:
     |    calls findings/search with structured asset_id filter
     |    normalises page -> findings_staging
     |    commits + advances checkpoint
     v
4. Enrichment
     | apply asset-tag enrichment (parses tag_names per finding)
     | apply CSV overrides on top
     | enrich CVEs via NVD (cached, refreshed every 60 days)
     v
5. Reconciliation
     | join findings_staging with findings on tenable_finding_id
     | apply risk formula
     | compute SLA due date + status
     | detect transitions (NEW/STILL OPEN/REMEDIATED/RECURRENCE/STALE)
     | populate jira_action_queue
     v
6. Cleanup
     | delete this run's findings_staging rows
     | mark PipelineRun SUCCESS
     v
[Done — scored findings now queryable for reporting]
```

Typical duration: 5–10 minutes for ~33K assets / ~163K findings on a warm
NVD cache. First-ever run takes 20–60 minutes depending on CVE diversity
and NVD API key availability.

### 6.2 Scenario B — Interrupted run and resume

The pipeline supports interruption-safe execution: each page commits its
findings + advances a checkpoint before the next page is requested.

```
Interruption (network failure, SIGINT, system sleep)
     |
     v
PipelineRun is left in RUNNING / PARTIAL_FAILURE state with:
   asset_ids_for_run   = [persisted full asset list]
   last_batch_idx      = N  (next batch to fetch)
   pages_completed     = M

(later)

Engineer / scheduler runs again with --resume
     |
     v
Orchestrator finds the most recent unfinished run.
Verifies the tag_filter matches the current request.
If matched: resume from last_batch_idx (skip enrichment that already completed).
If not matched: start a fresh run (avoid mixing data).
```

Resume cost: at most one page of repeat work (~30 seconds).

### 6.3 Scenario C — Report generation (read path)

Independent of the ingestion pipeline. The reports are read-side queries
against the canonical `findings` table joined with `cve_details`.

```
Engineer
     |
     v
generate_report.py CLI
     | parses --report name + filter args
     | calls reporting.generate(session, report_name, filters)
     v
Reporting block
     | builds SQLAlchemy query: findings LEFT JOIN cve_details
     | applies filters (portfolio, severity, risk_rating, ...)
     | formats Description / Solution / References columns
     | writes CSV
     v
CSV file
```

Read-side queries do not affect pipeline state and can run during a pipeline
run if needed (the staging table is per-run-id, no contention).

---

## 7. Deployment View

### 7.1 Local development

```
+---------------------------+
| Developer workstation      |
|                            |
|  +---------------------+   |
|  | Python venv         |   |
|  |   src/pipeline.py   |   |
|  |   scripts/*.py      |   |
|  +----------+----------+   |
|             | psycopg2     |
|             v              |
|  +---------------------+   |
|  | Docker: postgres:16 |   |
|  +---------------------+   |
+---------------------------+
       |
       | HTTPS
       v
[Tenable Inventory API]      [NVD API]
```

One-command setup: `make install && make db-up && make db-migrate`.

### 7.2 Production target (Phase 1+)

```
+----------------------------------------------------------+
| AWS Account — UK region                                   |
|                                                          |
|  +----------------+      +-----------------------+        |
|  | EventBridge    +----->|  Step Functions       |        |
|  | cron schedule  |      |  (pipeline workflow)  |        |
|  +----------------+      +-----------+-----------+        |
|                                      |                    |
|                                      v                    |
|                          +-----------------------+        |
|                          |  Lambda — pipeline     |        |
|                          |  (VPC-attached)        |        |
|                          +-----------+-----------+        |
|                                      |                    |
|                                      v                    |
|                          +-----------------------+        |
|                          |  RDS PostgreSQL 16     |        |
|                          |  Multi-AZ              |        |
|                          +-----------------------+        |
|                                      ^                    |
|                                      | (read-only)        |
|                          +-----------+-----------+        |
|                          |  Lambda — reporting    |        |
|                          |  (CSV → S3 / signed URL)|       |
|                          +-----------------------+        |
|                                                          |
|  Secrets Manager: Tenable / NVD / Jira credentials       |
|  CloudWatch:      logs, metrics, alarms                   |
|  X-Ray:           distributed tracing                     |
+----------------------------------------------------------+
        |
        | HTTPS through NAT
        v
[Tenable Cloud]  [NVD]  [Jira Cloud — Phase 2]
```

Notes:
- Lambda runtime is the same Python codebase as local; differs only in entry handler.
- No S3 in the data path — PostgreSQL is the single store. S3 is used only as a delivery channel for generated CSV reports.
- RDS in a private subnet; Lambda in a VPC subnet with NAT egress for external API calls.

---

## 8. Data View

### 8.1 Canonical entities

```
                  +-------------+
                  |  Finding    |   * canonical scored record
                  |             |
                  |  PK: id      |
                  |  UQ: tenable_finding_id
                  +------+------+
                         |
              +----------+----------+
              |                     |
              v                     v
     +-----------------+     +----------------+
     | PipelineRun     |     |  CveDetails    |
     |  (history of    |     |  (NVD cache)   |
     |   ingestion     |     |                |
     |   activity)     |     |  PK: cve_id    |
     +-----------------+     +----------------+

     +---------------------+
     | EnrichmentMapping   |   * CSV-loaded overrides
     |  asset_id -> ctx     |
     +---------------------+

     +---------------------+
     | JiraActionQueue     |   * Phase 2: pending actions
     +---------------------+

     +---------------------+
     | RiskException       |   * Phase 2: risk-acceptance log
     +---------------------+
```

### 8.2 Lifecycle of a finding

```
[ingested]  -> findings_staging       (per-run, transient)
[scored]    -> findings (state=OPEN)  (canonical, persistent)
[fixed]     -> findings (state=REMEDIATED, remediated_at set)
[returns]   -> findings (state=OPEN, is_recurrence=true, recurrence_count++)
[missing]   -> findings (state=STALE)  (for human review; no auto-close)
```

The `tenable_finding_id` is the stable identity across all transitions. Our
internal `id` is a UUID that exists for relational hygiene.

### 8.3 Why PostgreSQL

| Choice | Alternative considered | Why PostgreSQL won |
|---|---|---|
| Single relational store | Multi-store (PostgreSQL + S3 + DynamoDB) | Reporting queries dominate (~80% of read time). Joins, aggregates, ORDER BY, GROUP BY all relational. Operational simplicity (one backup, one restore, one failure mode). |
| Persistent cache table for CVE detail | Redis / external cache | CVE detail is large, infrequently changed, and queried via JOIN. A table with a TTL column is simpler than introducing a cache server. |
| Per-run staging table | Per-run S3 prefix | Staging data is needed for set operations against the canonical findings table; doing this in SQL is dramatically simpler than reading S3 in Python. |

---

## 9. Cross-Cutting Concerns

### 9.1 Security

| Concern | Approach |
|---|---|
| Secrets | All credentials in `.env` locally; AWS Secrets Manager in production. Never in code, YAML, or logs. |
| Network | RDS in private subnet. Lambda in VPC with NAT egress. No public DB endpoints. |
| Auth (downstream) | Tenable: `X-ApiKeys` header. NVD: optional `apiKey` header. Jira (Phase 2): API token. |
| Data classification | OFFICIAL-SENSITIVE. Encryption at rest (KMS) and in transit (TLS 1.2+). |
| Least privilege | Per-Lambda IAM roles in production. Tenable API key scoped to read-only Inventory. |
| Audit | All API calls logged via structlog JSON. `pipeline_runs` table preserves per-run statistics + errors indefinitely. |

### 9.2 Observability

| Aspect | Implementation |
|---|---|
| Logs | structlog JSON; one event per significant pipeline step. `run_id` correlates all events from a pipeline run. |
| Metrics | CloudWatch metrics emitted from Lambda: pipeline duration, findings_fetched, findings_new, error count. |
| Tracing | X-Ray across pipeline; spans for each pipeline stage. |
| Run state | `pipeline_runs` table is the source of truth for "did the run succeed and how many findings did it touch". |

### 9.3 Error handling

Three layers:

| Layer | Strategy |
|---|---|
| HTTP transient (429, 5xx) | Tenacity-driven exponential backoff with bounded retries. Logged as warnings. |
| Per-page failure | Page is rolled back; checkpoint stays where it was. The next run with `--resume` retries the page. |
| Pipeline-wide failure | Run marked `PARTIAL_FAILURE`, errors persisted on the PipelineRun row. Next `--resume` picks up. |

The system never silently drops data. A failed page leaves the checkpoint
unchanged so it will be retried.

### 9.4 Scalability strategy

| Dimension | Current | Headroom |
|---|---|---|
| Total Tenable findings | Tested at 4.4M | The pipeline does not load this into memory (streaming). Limited only by RDS size. |
| Tagged assets per run | Tested at 33K | Linear scaling. 100K would take ~15 min instead of 5. |
| Unique CVEs to enrich | Tested at ~2K | NVD rate limit is the bottleneck. With API key: 50 req / 30s → ~20 min for 2K. 10K would take ~100 min. |
| Concurrent runs | Single | Not required by the use case; would require run-level isolation if added. |

### 9.5 Configuration management

All operational behaviour is configurable via YAML:

| Config | What it changes |
|---|---|
| `scoring.yaml` | Risk formula, weights, thresholds, criticality scores |
| `sla_policy.yaml` | Days-per-severity, business-day mode, approaching window |
| `rollout.yaml` | Which severities + teams currently get Jira tickets |
| `tenable.yaml` | API endpoint, retrieval mode, extra properties, retry behaviour |
| `schedule.yaml` | Pipeline cron expression (Phase 1) |

Code changes are not required for: changing the risk formula, tightening SLAs, expanding the Jira rollout, or onboarding a new portfolio tag.

---

## 10. Architectural Decisions

These are the architecturally significant decisions, recorded in
ADR-light format. Each: Context → Decision → Consequences → Alternatives.

### ADR-001: Pull-and-reconcile rather than push

- **Context**: Both Tenable and Jira can emit events, but consuming them requires webhook infrastructure, idempotency tracking, and ordering guarantees. The team has limited capacity and the latency requirements (daily) are lax.
- **Decision**: The middleware re-pulls from Tenable on each scheduled run and reconciles against its stored state. No event subscriptions in or out.
- **Consequences**: Idempotency is free. Resilience is high. Latency between Tenable detecting a fix and the Jira ticket closing is bounded by the pipeline cadence (default 24h).
- **Alternatives considered**:
  - **Webhook-driven**: rejected. Requires either polling Tenable's webhook configuration or running an inbound webhook receiver — both add infrastructure and security surface.
  - **Streaming via Kinesis / EventBridge bus**: rejected. Overkill for daily-cadence data.

### ADR-002: Single source via the Tenable Inventory API

- **Context**: Tenable exposes per-module APIs (VM Workbenches, Cloud Security, WAS) and the unified Inventory API. The first option means per-module client code; the second is in beta with thinner documentation.
- **Decision**: Integrate only with the Inventory API. Treat `sensor_type` as the disambiguator.
- **Consequences**: One client to maintain. Coverage of all Tenable sources for free as Tenable adds them.
- **Alternatives considered**:
  - **Per-module APIs**: rejected. 3–4× the code; per-module schema drift; loss of unified state model.

### ADR-003: Two-stage filtering for tag-based scoping

- **Context**: Empirically, `findings/search` silently ignores structured tag filters. `assets/search` accepts an advanced query. Filtering 4.4M findings client-side is wasteful.
- **Decision**: Pre-fetch tagged asset_ids via `assets/search` (advanced query). Then call `findings/search` with a structured asset_id filter in batches of 500.
- **Consequences**: 5-minute run for ~163K filtered findings instead of 20-minute run pulling all 4.4M.
- **Alternatives considered**:
  - **Client-side filtering of all findings**: rejected on performance grounds.
  - **Using `findings/export` (async bulk)**: rejected — does not return tag data.

### ADR-004: Tag taxonomy encoding category in value

- **Context**: The Tenable Inventory API returns tags as flat strings (`tag_names`). The UI lets users set a `Category` field, but the API does not expose it.
- **Decision**: All tags use the form `<Category>-<Value>` in PascalCase, with single-word categories. A parser splits on the first hyphen.
- **Consequences**: One naming convention serves both filtering and enrichment. Tags that don't conform are warned and ignored.
- **Alternatives considered**:
  - **Mapping table**: rejected. Requires manual maintenance of `tag_name → category` mappings outside Tenable.
  - **Querying Tenable's UI database**: not available via API.

### ADR-005: Streaming pipeline with per-page checkpoint

- **Context**: A run can take 20+ minutes against the real Tenable instance. Network failures and laptop sleep are common during development. A previous design loaded everything into memory and lost progress on any failure.
- **Decision**: Process the result set page-by-page, committing each page to the database and advancing a checkpoint on `pipeline_runs` before requesting the next page.
- **Consequences**: Resume safety with at most one page of repeat work (~30s). Memory usage is bounded regardless of dataset size.
- **Alternatives considered**:
  - **Restart-on-failure with deduplication**: rejected. Requires complex set arithmetic to identify what was already processed.

### ADR-006: PostgreSQL as the single store

- **Context**: Several stores were proposed: S3 for raw findings, DynamoDB for state, Redis for CVE cache, PostgreSQL for reporting.
- **Decision**: Use PostgreSQL for everything. No S3 (except as a delivery channel for generated CSVs), no DynamoDB, no Redis.
- **Consequences**: One backup, one restore, one failure mode. Reporting queries are pure SQL.
- **Alternatives considered**:
  - **Multi-store**: rejected. Operational complexity outweighed the benefits for the volumes we handle (4.4M findings fits comfortably in PostgreSQL).

### ADR-007: NVD enrichment for finding descriptions

- **Context**: Tenable returns `finding_solution = null` for 100% of Cloud Security findings. Reports without descriptions and remediation guidance are not usable by resolvers.
- **Decision**: Maintain a `cve_details` table populated from NVD. Look up unique CVEs per run; cache for 60 days.
- **Consequences**: Reports have rich Description and References columns. Cost is an extra ~20 minutes on the first run (with NVD API key); seconds thereafter.
- **Alternatives considered**:
  - **Tenable VM Workbenches API for description**: rejected. Works only for Nessus plugin findings, not Cloud Security. Doesn't cover the ~99% case.
  - **AI-generated descriptions**: rejected for Phase 0+. Audit risk too high (hallucinated content).

### ADR-008: CSV reporting, no dashboards

- **Context**: The spec calls for "be able to create CSV reports". Building a dashboard layer requires UI engineering capacity we don't have.
- **Decision**: Ship six CSV report types via a CLI. Defer dashboards to a future phase if needed.
- **Consequences**: Downstream tools (Excel, PowerBI, Tableau) provide visualisation. Time-to-first-report was a few days.
- **Alternatives considered**:
  - **Embedded dashboard (Grafana / QuickSight)**: deferred. Would add deployment, RBAC, and licensing concerns.

### ADR-009: Configurable risk formula

- **Context**: The organisation defined a specific corporate formula (VPR + ACS, weighted). Tenable also offers Lumin's CES. We don't know yet which will be preferred operationally.
- **Decision**: Support both via `scoring.yaml`. Default to the custom formula; allow switching with no code change.
- **Consequences**: The VRB can experiment with thresholds and weights without engineering involvement.
- **Alternatives considered**:
  - **Hardcoded formula**: rejected. Tuning would require a release cycle.

### ADR-010: Do not auto-close on disappearance

- **Context**: A finding disappearing from a Tenable scan could mean: it was remediated, the asset was decommissioned, the asset was untagged, or Tenable simply didn't re-scan. We can't tell which without context.
- **Decision**: Disappearance flags a finding as `STALE` for human review. Only an explicit Tenable state of `FIXED` closes a Jira ticket.
- **Consequences**: No false closures. Stale findings need periodic VRB attention.
- **Alternatives considered**:
  - **Auto-close after N days missing**: rejected. Risks closing real, unremediated tickets when assets briefly drop out of scan coverage.

### ADR-011: Single Python process; no microservices

- **Context**: With one orchestrator + a small DB, the pipeline is straightforward. Microservices would add deployment, IPC, and observability complexity.
- **Decision**: One Python codebase, one orchestrator binary, in-process function calls between building blocks.
- **Consequences**: Easy to reason about, debug, and run locally. Constrains us to single-machine throughput, which is comfortably sufficient.
- **Alternatives considered**:
  - **Microservices per building block**: rejected. Operational cost outweighs benefits at our scale.

---

## 11. Quality Requirements

Specific, measurable quality scenarios. These are how the architecture
will be evaluated.

| # | Quality attribute | Scenario | Acceptance |
|---|---|---|---|
| QR1 | Auditability | Given any closed Jira ticket, when an auditor asks why it was closed, then the system can show the Tenable run, the prior state, the `state=FIXED` evidence, and the timestamp. | All preserved in `findings` + `pipeline_runs` indefinitely |
| QR2 | Configurability | Changing the SLA for HIGH severity from 30 to 14 days takes < 5 minutes and requires no code change. | Edit `sla_policy.yaml`, re-run pipeline. Verified. |
| QR3 | Resilience | A pipeline interrupted at any point during ingestion can be resumed with at most one page of repeat work. | `--resume` validated in dev. Per-page commit ensures it. |
| QR4 | Maintainability | A new engineer can run the pipeline locally and generate a CSV report within 30 minutes of cloning. | Validated via README + `make install`. |
| QR5 | Reproducibility | Running the pipeline twice against an unchanged Tenable state produces identical findings table contents. | Confirmed: second run shows 0 NEW, all UPDATED. |
| QR6 | Security | No secret value ever appears in source control, YAML configuration, or log output. | `.env` is gitignored. structlog formats omit credential fields. Reviewed manually. |
| QR7 | Scalability | The pipeline completes within 30 minutes against 10× current scale (33M findings, 200K assets). | Untested at that scale. Pre-flight cost scales linearly with tagged assets; findings stream is unaffected by total volume. |
| QR8 | Operational safety | When rollout phase = `pilot`, only the configured pilot teams receive new Jira tickets. | Phase 2 implementation pending; design verified in `rollout.yaml`. |

---

## 12. Risks and Technical Debt

### 12.1 Active risks

| # | Risk | Probability | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Tenable Inventory API contract changes (it is in beta) | Medium | High — would break ingestion | Field-by-field property requests are explicit; failures are loud. Probe scripts in `scripts/` validate the contract at any time. |
| R2 | NVD outage or rate-limit policy change | Low | Medium — reports lose richness for new CVEs until restored | Errors are non-fatal; cached entries continue to serve. |
| R3 | Tag taxonomy drift if not enforced by governance | Medium | Medium — unparseable tags reduce enrichment coverage | Middleware logs invalid tags. Quarterly VRB review per taxonomy doc. |
| R4 | Jira ticket volume overwhelms service teams in Phase 2 | Medium | High — rollback of programme | Phased rollout controller is mandatory; pilot teams first. |
| R5 | Pipeline duration grows linearly with tagged assets; eventually exceeds Lambda timeout (15 min) | Low | Medium | Phase 1 deploys on Step Functions, which can checkpoint across Lambda invocations. |
| R6 | Multiple concurrent pipeline runs (e.g. cron + manual) corrupt state | Low | High | Future: add a run-level mutex (DB row lock). Today: docs warn against. |

### 12.2 Technical debt

| # | Item | When to address |
|---|---|---|
| TD1 | One-off `scripts/probe_*.py` debugging files are committed. They served their purpose but clutter the directory. | Phase 1 housekeeping |
| TD2 | The CSV reporting layer is read-only (good) but doesn't yet stream — full export of `findings` into memory before writing | When the table exceeds ~1M rows; add cursor-based streaming |
| TD3 | The `findings_staging` table is per-run but indexed only by `run_id` + `tenable_finding_id` — large runs slow down the reconciliation join | Add composite index when run sizes exceed ~250K |
| TD4 | The Phase 0+ deployment is local-only. Production architecture is designed but not yet built. | Phase 1 |
| TD5 | No automated end-to-end test against a real Tenable instance — all tests use fixtures | Phase 1 validation gate |

---

## 13. Glossary

| Term | Definition |
|---|---|
| **ACS** | Asset Criticality Score — normalised business-criticality value (0.25–1.0) used in the custom risk formula. Derived from the `Criticality-*` tag. |
| **ACR** | Asset Criticality Rating — Tenable's native asset rating (1–10). Used in Lumin scoring. |
| **AES** | Asset Exposure Score — Tenable's native composite score (0–1000). |
| **CES** | Cyber Exposure Score — Tenable Lumin's per-finding score, function of VPR and ACR. |
| **CVE** | Common Vulnerabilities and Exposures — the public identifier for a known vulnerability. |
| **CVSS** | Common Vulnerability Scoring System — industry-standard 0–10 severity score. |
| **CWE** | Common Weakness Enumeration — taxonomy of vulnerability types. |
| **Finding** | A single instance of a weakness on a specific asset. The unit of work tracked by the middleware. |
| **NVD** | National Vulnerability Database (NIST) — authoritative public CVE data source. |
| **Reconciliation** | The pipeline step that compares this run's staged findings to the stored canonical findings to detect state transitions. |
| **STALE** | A finding that is in the canonical store as OPEN but did not appear in the current run beyond the configured threshold. Flagged for human review. |
| **Tag taxonomy** | The `<Category>-<Value>` PascalCase naming convention used to encode business context in Tenable tag names. |
| **VPR** | Vulnerability Priority Rating — Tenable's threat-context-aware severity score (0.1–10.0). |
| **VRB** | Vulnerability Review Board — fortnightly governance forum reviewing high-risk findings, exceptions, and SLA trends. |
