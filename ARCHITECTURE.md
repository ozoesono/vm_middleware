# VM Middleware — Architecture Document (v3)

> **Version**: 3.0
> **Status**: Phase 0 + risk-scoring + reporting — implemented and operational
> **Last updated**: 2026-05-20

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Tenable One Inventory API — Source of Truth](#2-tenable-one-inventory-api--source-of-truth)
3. [Tag Taxonomy & Filtering Strategy](#3-tag-taxonomy--filtering-strategy)
4. [Pipeline Flow](#4-pipeline-flow)
5. [Reconciliation Engine](#5-reconciliation-engine)
6. [Data Model](#6-data-model)
7. [Scoring Engine](#7-scoring-engine)
8. [SLA Policy](#8-sla-policy)
9. [Enrichment Sources](#9-enrichment-sources)
10. [NVD Enrichment](#10-nvd-enrichment)
11. [CSV Reporting](#11-csv-reporting)
12. [Jira Ticketing (planned)](#12-jira-ticketing-planned)
13. [Project Structure](#13-project-structure)
14. [Technology Stack](#14-technology-stack)
15. [Configuration Reference](#15-configuration-reference)
16. [Phase Alignment](#16-phase-alignment)
17. [Key Design Decisions](#17-key-design-decisions)
18. [Non-Functional Requirements](#18-non-functional-requirements)

---

## 1. System Overview

The VM Middleware is a vulnerability management orchestration system that ingests
findings from the Tenable One Inventory API (Exposure Management), enriches them
with business context (portfolio, service, environment, asset criticality),
applies a configurable risk-scoring formula, detects remediations via state
reconciliation, enriches CVEs with NVD descriptions and remediation references,
and produces CSV reports for risk reporting.

### 1.1 Architecture Diagram

```
+--------------------------------------------------------------------------+
|                         TENABLE ONE PLATFORM                              |
|                                                                          |
|   Nessus (VM)      Cloud Security      WAS         3rd-party connectors  |
|         \\               |               /              /                  |
|          +-------> Inventory layer (Exposure Mgmt) <----+                |
|                              |                                           |
|     +------------------------+--------------------------+                |
|     |                                                   |                |
|  POST /api/v1/t1/inventory/             POST /api/v1/t1/inventory/       |
|     assets/search                          findings/search               |
|     (advanced query: tag filter)           (server-side asset_id filter) |
+-----|---------------------------------------------------|----------------+
      |                                                   |
      v                                                   v
+--------------------------------------------------------------------------+
|                            VM MIDDLEWARE                                  |
|                                                                          |
|   1. Pre-flight (when --tag is set)                                       |
|      assets/search advanced query 'Assets HAS tag_names = "X"'            |
|         -> dict[asset_id -> tag_names list]                               |
|                                                                          |
|   2. Streaming ingestion (page-by-page commit, resume-safe)               |
|      Batches of 500 asset_ids -> findings/search server-side filter       |
|         -> findings_staging table (per pipeline run)                      |
|                                                                          |
|   3. Enrichment                                                          |
|      a. From Tenable tags: portfolio/service/environment/criticality      |
|      b. From CSV overrides (optional manual corrections)                  |
|      c. From NVD: CVE description, CVSS, CWE, references (cached)         |
|                                                                          |
|   4. Reconciliation                                                      |
|      Joins findings_staging with findings on tenable_finding_id           |
|      State transitions: NEW / STILL OPEN / REMEDIATED / RECURRENCE / STALE|
|      Risk formula applied: (VPR x w_vpr) + (ACS x w_acs)                  |
|      SLA dates calculated                                                 |
|      Jira action queue populated                                          |
|                                                                          |
|   5. CSV reporting                                                        |
|      generate_report.py CLI                                              |
|      Six reports: findings / risk-summary / sla-breaches /                |
|      sla-approaching / recurrence / portfolio-summary                     |
|                                                                          |
|   PostgreSQL 16                                                          |
|     findings | findings_staging | enrichment_mappings | cve_details      |
|     jira_action_queue | pipeline_runs | risk_exceptions                  |
+--------------------------------------------------------------------------+
```

### 1.2 What changed since v2

This is v3 because several substantive things were added since the v2 document
(2026-04-16):

| Area | Change |
|------|--------|
| Filter strategy | Discovered Tenable's findings/search rejects most structured filters but **accepts asset_id filter when paired with `query.mode=simple` + `query.text=""`**. Plus assets/search **accepts advanced query syntax**. The pipeline now uses both. |
| Pre-flight | Tagged-asset pre-fetch builds an in-memory `asset_id → tag_names` map; **all** asset tags (not just the filter tag) get captured for enrichment. |
| Streaming | Pipeline now processes findings page-by-page with per-page commit and a checkpoint, so a 15-minute run is interruption-safe. `--resume` flag added. |
| Batched fetch | Findings are pulled in batches of 500 asset_ids per request (server-side filter), so we no longer pull all 4.4M findings to keep ~163K. |
| Tag taxonomy | Formal naming convention: `Category-Value` in PascalCase (single-word categories). `tag_parser` module validates and parses. |
| Asset-tag enrichment | New enrichment path: parses each asset's tag_names, populates portfolio / service / environment / criticality / sensitivity / owner on every finding. |
| Configurable criticality | Criticality labels → ACS scores are now in `config/scoring.yaml`, not hardcoded. |
| NVD enrichment | `cve_details` table caches NVD descriptions, CVSS, CWE, and references. Tenable doesn't return descriptions for Cloud Security findings; NVD fills that gap. |
| CSV reporting | Six report types via `generate_report.py`. The findings report includes rich Description and Solution columns built from NVD + Tenable data. |

---

## 2. Tenable One Inventory API — Source of Truth

The Tenable Inventory API is the unified aggregation layer over every Tenable
module (VM, Cloud Security, WAS, container security, third-party connectors).
Each finding carries a `sensor_type` indicating its origin module.

### 2.1 Endpoints used

| Endpoint | Used for |
|---|---|
| `POST /api/v1/t1/inventory/findings/properties` | Discover valid filter/extra-property names |
| `POST /api/v1/t1/inventory/assets/search` | Pre-fetch tagged asset IDs (with advanced query) |
| `POST /api/v1/t1/inventory/findings/search` | Stream findings, batched by asset_id |
| `POST /api/v1/t1/inventory/findings/export` | Available but **not used**: doesn't return tag data |

### 2.2 Field name reality (vs documentation)

Many property names differ from what older Tenable docs suggest. The names
the middleware actually uses (verified via `/findings/properties`):

| Concept | Property name |
|---|---|
| Finding identifier | `id` (top-level), referred to as `tenable_finding_id` in our DB |
| Asset reference | `asset_id` (top-level) |
| State | `state` (top-level) — values: `ACTIVE`, `FIXED`, `RESURFACED`, `NEW` |
| Severity | `severity` (top-level — uppercase) |
| VPR | `finding_vpr_score` |
| CVE list | `finding_cves` (list, take first) |
| CVSS v3 | `finding_cvss3_base_score` |
| Solution | `finding_solution` *(often null for Cloud Security findings)* |
| Plugin ID | `finding_detection_id` |
| Tags | `tag_names` + `tag_ids` (lists) |
| Source module | `sensor_type` (e.g. `NESSUS`, `CLOUD_SCAN`, `CS:AC_AWS`, `WAS`) |
| Asset class | `asset_class` |
| First/last observed | `first_observed_at`, `last_observed_at` |

### 2.3 API quirks discovered

| Behaviour | Workaround |
|---|---|
| POST endpoints return **415 Unsupported Media Type** if you send `json=None` | Always send `json={}` even with no filters |
| Sort by `severity:desc` returns **400 unknown query property** | Use `finding_severity:desc` |
| `findings/search` **silently ignores** structured `filters` for tag fields | Use advanced query on `assets/search`, then filter findings by `asset_id` |
| `findings/search` only supports `query.mode=simple` (advanced returns 500) | Combine `query.mode=simple` + `query.text=""` with structured `filters` |
| The working filter operator is `=`, not `eq` | Always use `"operator": "="`, value as a **list** |
| `findings/export` endpoint **doesn't return tag data** | Don't use export mode when filtering by tag |
| `finding_solution` is **null for Cloud Security findings** (0% populated) | Enrich via NVD API for CVE-based findings |

The working filter payload — discovered empirically:

```json
{
  "query": {"mode": "simple", "text": ""},
  "filters": [
    {"property": "asset_id", "operator": "=", "value": ["uuid1", "uuid2", ...]}
  ]
}
```

---

## 3. Tag Taxonomy & Filtering Strategy

### 3.1 The taxonomy

Because the Inventory API only returns flat tag strings (no category context),
the category is encoded into the tag name:

```
<Category>-<Value>
```

- Both parts use **PascalCase**.
- The hyphen is the separator.
- **Categories must be single-word** so the parser can split on the first hyphen unambiguously.
- The first hyphen separates category from value; subsequent hyphens are part of the value.

Approved categories: `Portfolio`, `Service`, `Environment`, `Sensitivity`,
`Criticality`, `Owner`, `Region`, `Compliance`, `Application`.

Examples:

```
Portfolio-Business-Growth        -> category=Portfolio, value=Business-Growth
Service-Payment-Api              -> category=Service, value=Payment-Api
Environment-Prod                 -> category=Environment, value=Prod
Criticality-Critical             -> category=Criticality, value=Critical
Owner-Team-Payments              -> category=Owner, value=Team-Payments
```

Full reference: `tag_taxonomy.txt` at the repo root.

### 3.2 Why this matters for filtering

In the Tenable UI you can create tags with separate `Category` and `Value`
fields, but the **API returns only the Value field** when you request
`tag_names`. So `Category="Environment", Value="Prod"` appears in the API
as just `"Prod"`.

**To make the API value carry the category**, you must put the full taxonomic
name in Tenable's Value field, e.g. set `Value="Environment-Prod"` directly.
The category field then becomes purely UI-grouping metadata.

### 3.3 The filtering strategy

Because `findings/search` ignores tag filters, the middleware uses a
**two-stage approach** when a `tag_filter` is configured:

**Stage 1 — pre-flight on assets/search (advanced query)**

```http
POST /api/v1/t1/inventory/assets/search
?extra_properties=asset_id,asset_name,tag_names
{
  "query": {
    "mode": "advanced",
    "text": "Assets HAS tag_names = \"Portfolio-Business-Growth\""
  }
}
```

This genuinely filters. Paginated. Returns each tagged asset with **all** of
its tag_names (not just the filter tag), so we capture the full enrichment
context in one pass.

Result: `dict[asset_id → list[tag_names]]`.

**Stage 2 — batched findings/search (structured filter)**

For each batch of 500 asset_ids, call:

```http
POST /api/v1/t1/inventory/findings/search?extra_properties=...
{
  "query": {"mode": "simple", "text": ""},
  "filters": [
    {"property": "asset_id", "operator": "=", "value": ["uuid1", ..., "uuid500"]}
  ]
}
```

This filters server-side. Paginated. We never pull findings that aren't on
tagged assets.

Performance: 33,000 tagged assets / 500 per batch = 66 batches. ~5 minutes
total vs ~20 minutes if we pulled all 4.4M findings and filtered client-side.

### 3.4 Validation & warnings

Any tag that doesn't match the taxonomy (no hyphen, or unknown category) is
logged as a `tag_invalid_format` warning by the enrichment engine and
otherwise ignored. The pipeline doesn't fail on bad tags; it just doesn't
enrich.

---

## 4. Pipeline Flow

### 4.1 Steps

```
[CLI / scheduler]
      |
      v
  Setup or resume a PipelineRun row
      |
      v
  Step 1 — CSV enrichment sync (optional, file-based overrides)
      |
      v
  Step 2 — Tenable ingestion
      |
      |  if tag_filter is set:
      |       Stage 2a — assets/search advanced query
      |          -> asset_ids + asset_tags_map persisted on the run
      |       Stage 2b — findings/search batched by asset_id
      |          -> findings_staging committed per page, checkpoint saved
      |
      |  else (legacy path, no tag):
      |       findings/search streaming all
      |
      v
  Step 3a — Apply asset-tag enrichment (portfolio/criticality/etc.)
  Step 3b — Apply CSV overrides on top
  Step 3c — NVD enrichment: fetch description/CWE/references for new CVEs
      |
      v
  Step 4 — Scoring + reconciliation
      |       Risk formula applied to every finding
      |       State transitions detected (NEW / STILL OPEN / REMEDIATED / etc.)
      |       Jira action queue populated
      |
      v
  Step 5 — Cleanup: clear staging rows for this run, mark run SUCCESS
      |
      v
  [Done — CSV reports can now query the findings table]
```

### 4.2 Streaming + checkpoint resume

Each page committed to the DB also advances a checkpoint on `pipeline_runs`:

- `last_offset` (for the legacy non-batched path)
- `last_batch_idx` (for the tagged path)
- `pages_completed`, `findings_fetched`, `total_findings_expected`

If the run is interrupted (network failure, screen sleep, ctrl-C), the next
run with `--resume` finds the most recent `RUNNING`/`PARTIAL_FAILURE`/`FAILED`
record, verifies its tag_filter matches the current request (otherwise starts
fresh), and resumes from the saved checkpoint.

The pre-flight asset list (`asset_ids_for_run`) is persisted on the run row so
we don't re-fetch tagged assets on resume.

### 4.3 NVD enrichment

After ingestion + enrichment, the pipeline collects every distinct CVE from
the run's staging rows, checks the `cve_details` cache for entries older than
`ttl_days` (default 60), and fetches the missing ones from NVD.

Rate-limited per NVD docs:
- without API key: 5 requests / 30 seconds
- with API key: 50 requests / 30 seconds (set `NVD_API_KEY` in `.env`)

Errors are non-fatal; missing CVEs just don't get enriched on this run.

---

## 5. Reconciliation Engine

Operates on `findings_staging` (this run) joined with `findings` (everything
the middleware has ever seen) on `tenable_finding_id`.

### 5.1 Five state transitions

| Transition | Condition | Action |
|---|---|---|
| NEW | finding exists in staging, not in findings table | INSERT, score, calculate SLA, queue Jira CREATE |
| STILL OPEN | both exist, Tenable state = ACTIVE | UPDATE last_seen, re-score, re-calculate SLA |
| REMEDIATED | exists in DB as OPEN, Tenable state = FIXED | mark `state = REMEDIATED`, compute `time_to_fix_days`, queue Jira CLOSE |
| RECURRENCE | exists as REMEDIATED, Tenable state = ACTIVE/RESURFACED | reopen, increment `recurrence_count`, queue Jira REOPEN |
| STALE | exists in DB as OPEN but **not** in staging, `last_seen` > stale_threshold_days | mark `state = STALE` for human review (does NOT auto-close ticket) |

A REMEDIATED finding that is still FIXED in the API is skipped — no action.

### 5.2 Why STALE != REMEDIATED

A finding that disappears from the API can mean:
- The asset was decommissioned (not a remediation)
- The asset was untagged from the filter portfolio (not a remediation)
- The vulnerability really is fixed (but Tenable hasn't re-scanned)

We never auto-close Jira tickets on disappearance. Only an explicit Tenable
`FIXED` state triggers closure.

---

## 6. Data Model

PostgreSQL 16. All tables in the `public` schema. Migrations under `db/migrations/`.

### 6.1 Tables

| Table | Purpose |
|---|---|
| `findings` | Canonical scored finding records. Primary key is internal `id`; `tenable_finding_id` is UNIQUE. |
| `findings_staging` | Per-run staging. Cleared at end of pipeline. |
| `enrichment_mappings` | CSV-loaded asset-to-business-context overrides. |
| `enrichment_overrides` | Granular field-level overrides (rarely used). |
| `cve_details` | NVD-enriched per-CVE data (PK: `cve_id`). LEFT-JOINed by reports. |
| `jira_action_queue` | Pending CREATE/UPDATE/CLOSE/REOPEN actions (Phase 2). |
| `jira_sync_log` | Audit log of Jira API calls (Phase 2). |
| `pipeline_runs` | Run metadata + checkpoint + statistics. |
| `risk_exceptions` | Risk-acceptance requests (Phase 2). |

### 6.2 Key columns on `findings`

```text
identity:           id, tenable_finding_id (UNIQUE), tenable_asset_id

source data:        title, cve_id, severity, vpr_score, cvssv3_score,
                    source (sensor_type), plugin_id, solution

enrichment:         portfolio, service, environment, data_sensitivity,
                    asset_criticality, asset_criticality_score,
                    service_owner, service_owner_team

scoring (output):   risk_model, risk_score, risk_rating
SLA:                sla_days, sla_due_date, sla_status

state:              state (OPEN/REMEDIATED/STALE/RISK_ACCEPTED),
                    tenable_state (ACTIVE/FIXED/RESURFACED/NEW),
                    first_seen, last_seen, remediated_at,
                    time_to_fix_days, is_recurrence, recurrence_count

Jira:               jira_ticket_key, jira_ticket_status,
                    jira_created_at, jira_closed_at

metadata:           created_at, updated_at, last_run_id
```

### 6.3 Key columns on `pipeline_runs`

```text
identity:           id, started_at, completed_at, status, trigger

run statistics:     findings_fetched, findings_new, findings_updated,
                    findings_remediated, findings_recurred, findings_stale,
                    jira_tickets_*

checkpoint:         last_offset, pages_completed,
                    total_findings_expected, tag_filter

batched checkpoint: asset_ids_for_run (JSON: {ids: [...], tags: {...}}),
                    last_batch_idx, total_batches

errors:             errors (JSON list)
```

### 6.4 Key columns on `cve_details`

```text
cve_id (PK)
description (text)
cvss_v3_score, cvss_v3_severity
cwe_id, cwe_name
published_at
references (JSON: [{url, source, tags}])
source ('nvd')
last_fetched_at
```

---

## 7. Scoring Engine

### 7.1 The formula

```
risk_score = (vpr_normalised × vpr_weight) + (acs × acs_weight)
```

Where:
- `vpr_normalised` = `vpr_score / 10.0` (Tenable VPR is 0.0–10.0; we map to 0.0–1.0)
- `acs` = `asset_criticality_score` (0.25–1.0; sourced from the `Criticality-*` tag)
- `vpr_weight` + `acs_weight` configurable, default 0.5 each

Risk rating mapping (configurable thresholds):

| risk_score >= | risk_rating |
|---|---|
| 0.75 | CRITICAL |
| 0.50 | HIGH |
| 0.30 | MEDIUM |
| else | LOW |

### 7.2 Two models supported

| Model | Description |
|---|---|
| `custom` | Default. The weighted VPR+ACS formula above. |
| `lumin_ces` | Uses Tenable's native AES (Asset Exposure Score) if present, falls back to approximation `(VPR/10 × 500) + (ACR/10 × 500)`. |

Switch via `scoring.active_model` in `config/scoring.yaml`.

### 7.3 Criticality → ACS mapping (configurable)

```yaml
scoring:
  criticality_scores:
    CRITICAL: 1.0
    HIGH: 0.75
    MEDIUM: 0.50
    LOW: 0.25
  default_criticality_score: 0.25   # used when asset has no Criticality tag
```

### 7.4 Worked example

CVE on an asset tagged `Criticality-Critical`, VPR=9.6:

```
risk_score = (9.6/10 × 0.5) + (1.0 × 0.5) = 0.48 + 0.5 = 0.98  →  CRITICAL
```

Same CVE on an asset with no Criticality tag (ACS defaults to 0.25):

```
risk_score = (9.6/10 × 0.5) + (0.25 × 0.5) = 0.48 + 0.125 = 0.605  →  HIGH
```

The formula deliberately lets asset business value compress or amplify the
raw VPR.

---

## 8. SLA Policy

Single unified policy (no split between vulnerability types in current scope):

```yaml
sla:
  critical: 10    # days
  high: 30
  medium: 45
  low: 90
  use_business_days: false
  approaching_warning_days: 5
```

`sla_due_date` = `first_seen + sla_days`.
`sla_status`:

| Status | Condition |
|---|---|
| WITHIN_SLA | `due_date - today > approaching_warning_days` |
| APPROACHING | `0 <= due_date - today <= approaching_warning_days` |
| BREACHED | `due_date < today` |

---

## 9. Enrichment Sources

Three sources, applied in priority order (last write wins):

1. **Asset-tag enrichment** (primary) — parses each asset's full set of `tag_names` via the taxonomy parser. Populates portfolio / service / environment / data_sensitivity / asset_criticality / asset_criticality_score / service_owner_team.
2. **CSV overrides** — `tests/fixtures/sample_enrichment.csv` or any CSV at `--enrichment` path. Manual corrections for assets where Tenable tags are wrong or missing.
3. **AWS Tags sync** (planned, Phase 1) — pull AWS resource tags via the Tagging API for assets that aren't in Tenable yet.

The asset-tag path is the workhorse: the pipeline already pulls all of each
asset's tags during the pre-flight, so this enrichment is free.

---

## 10. NVD Enrichment

Tenable's Inventory API returns `finding_solution = null` for 100% of Cloud
Security findings (confirmed: 0 / 213,398 populated in test data). Without
descriptions or remediation guidance, the CSV report would be useless for
resolvers.

The middleware addresses this with NVD enrichment.

### 10.1 What it provides

For each unique CVE in a pipeline run, fetch from NVD and cache in `cve_details`:

| Field | Source | What it's for |
|---|---|---|
| description | NVD `cve.descriptions[lang=en].value` | Description column in the report — the official summary of the vulnerability |
| cvss_v3_score / severity | NVD `cve.metrics.cvssMetricV31` | Cross-check against Tenable VPR |
| cwe_id | NVD `cve.weaknesses[0].description[lang=en].value` | Weakness classification |
| references | NVD `cve.references` | Vendor advisories — these contain the actual fix steps |

### 10.2 Cache strategy

- Keyed on `cve_id`.
- `last_fetched_at` updated on each refresh.
- Re-fetch only when older than `ttl_days` (default 60).
- Cache survives pipeline runs; subsequent runs only fetch newly-seen CVEs.

### 10.3 API key

NVD rate-limits anonymous traffic to 5 requests / 30 seconds. With a free API
key (`NVD_API_KEY` in `.env`) the limit rises to 50/30s. For an initial fetch
of ~2,000 unique CVEs:

- without key: ~3.5 hours
- with key: ~20 minutes

Subsequent runs only fetch new CVEs (typically a handful per day).

### 10.4 Limitations

- Cloud misconfigurations (no CVE) get no NVD enrichment. The Description column falls back to title + asset context.
- NVD doesn't provide step-by-step "solution" text. The Solution column combines Tenable's `finding_solution` (if any) with vendor reference URLs (which contain the fix steps).

---

## 11. CSV Reporting

Six reports, all generated by `scripts/generate_report.py`.

| Report | Contents |
|---|---|
| `findings` | Full export with rich Description, Solution, References columns |
| `risk-summary` | Counts grouped by risk_rating × portfolio × asset_criticality |
| `sla-breaches` | All findings with `sla_status = BREACHED` |
| `sla-approaching` | All findings with `sla_status = APPROACHING` |
| `recurrence` | Findings that resurfaced after remediation |
| `portfolio-summary` | Per-portfolio rollup: totals, severity breakdown, breaches, avg risk |

### 11.1 Filtering

All reports accept any combination of the same filters:

```
--portfolio --service --environment --asset-criticality
--risk-rating --severity --state --sla-status --source
```

Repeatable flags become OR within a key, AND across keys.

### 11.2 The Description column

Built per finding from a LEFT JOIN with `cve_details`. Example output:

```
CVE-2023-2640  •  Severity: HIGH

In Ubuntu kernels overlayfs ovl_copy_up_meta_inode_data skip_idmap check missed
permission check that allowed user with CAP_SYS_ADMIN to escalate.

CVSS v3: 7.8  •  VPR: 9.6  •  CWE: CWE-863  •  Source: CLOUD_SCAN

Affected asset: 767397682808.dkr.ecr.eu-west-2.amazonaws.com/datahub/bf:build-987f...
```

### 11.3 The Solution column

```
[Tenable's solution if present, otherwise synthesised guidance]

References:
- https://ubuntu.com/security/CVE-2023-2640
- https://nvd.nist.gov/vuln/CVE-2023-2640
- ...
```

The references contain the actual vendor-specific fix steps — that's where
resolvers click through for the "how".

---

## 12. Jira Ticketing (planned)

In Phase 0+ scope the reconciliation engine already produces a `jira_action_queue`
(CREATE / UPDATE / CLOSE / REOPEN actions). The actual Jira API integration
is Phase 2.

### 12.1 Design

| Action | Trigger | Effect |
|---|---|---|
| CREATE | NEW finding above severity threshold AND in a piloted team | Create Jira issue, store key on the finding |
| UPDATE | STILL OPEN finding with risk_score change > threshold | Add comment with new score |
| CLOSE | finding becomes REMEDIATED | Transition Jira issue to Done, comment with time-to-fix |
| REOPEN | finding becomes RECURRENCE | Reopen Jira issue, comment with recurrence count |

### 12.2 Phased rollout controller

`config/rollout.yaml` defines which severities + teams currently receive
tickets. Defaults to a pilot:

```yaml
rollout:
  phase: "pilot"
  phases:
    pilot: { severity_filter: [CRITICAL, HIGH], team_filter: [team-platform], max_tickets_per_run: 50 }
    critical_high: { severity_filter: [CRITICAL, HIGH], team_filter: [], max_tickets_per_run: 100 }
    medium: { severity_filter: [CRITICAL, HIGH, MEDIUM], ... }
    full: { severity_filter: [CRITICAL, HIGH, MEDIUM, LOW], ... }
```

This prevents flooding teams on day one. Phase changes are config-only.

---

## 13. Project Structure

```
vm-middleware/
├── ARCHITECTURE.md                  ← this file
├── OVERVIEW.md                       ← 10-min top-level summary
├── architecture_simple.md/.txt       ← one-page condensed version
├── tag_taxonomy.txt                  ← the naming convention
├── user_stories.txt                  ← phased user-story backlog
├── pyproject.toml                    ← dependencies, build config
├── Makefile                          ← install / db-up / db-migrate / test
├── docker-compose.yaml               ← local PostgreSQL
│
├── config/
│   ├── tenable.yaml                  ← endpoint, properties, retrieval mode, tag_filter
│   ├── scoring.yaml                  ← formula weights, thresholds, criticality scores
│   ├── sla_policy.yaml               ← SLA days per severity
│   ├── rollout.yaml                  ← phased Jira rollout
│   ├── schedule.yaml                 ← cron for scheduled runs (Phase 2)
│   └── jira.yaml                     ← Jira config (Phase 2)
│
├── db/
│   ├── alembic.ini
│   └── migrations/versions/
│       ├── 001_initial_schema.py
│       ├── 002_pipeline_checkpoints.py
│       ├── 003_widen_string_columns.py
│       ├── 004_batch_checkpoint.py
│       └── 005_cve_details.py
│
├── src/
│   ├── common/
│   │   ├── config.py                 ← Pydantic config loader (YAML + env vars)
│   │   ├── db.py                     ← SQLAlchemy session, engine
│   │   ├── models.py                 ← all ORM tables
│   │   ├── logging.py                ← structlog setup
│   │   └── tag_parser.py             ← parses Category-Value tags
│   │
│   ├── ingestion/
│   │   ├── tenable_client.py         ← findings/search + batched asset_id filter
│   │   ├── tenable_ingestion.py      ← normalise → staging
│   │   ├── tagged_assets.py          ← pre-flight: assets/search advanced query
│   │   ├── enrichment.py             ← asset-tag + CSV enrichment
│   │   └── nvd_enrichment.py         ← NVD CVE fetch + cache
│   │
│   ├── reconciliation/
│   │   └── reconciler.py             ← five-state machine
│   │
│   ├── scoring/
│   │   ├── engine.py                 ← dispatcher
│   │   ├── custom_model.py           ← VPR + ACS formula
│   │   ├── lumin_model.py            ← Lumin CES model
│   │   ├── sla.py                    ← SLA calculations
│   │   └── types.py                  ← ScoringResult
│   │
│   ├── reporting/
│   │   └── csv_reports.py            ← six report types
│   │
│   ├── pipeline.py                   ← orchestrator
│   │
│   └── lambdas/                      ← AWS Lambda entry points (Phase 2)
│
├── scripts/
│   ├── run_local.py                  ← CLI: --tag --mode --severity --resume
│   ├── generate_report.py            ← CLI: --report --filter --out
│   ├── seed_enrichment.py            ← seed CSV mappings
│   └── probe_*.py                    ← API discovery probes (one-off scripts)
│
└── tests/
    ├── conftest.py
    ├── fixtures/
    │   ├── sample_tenable_findings.json
    │   └── sample_enrichment.csv
    └── unit/
        ├── test_scoring.py
        ├── test_sla.py
        ├── test_reconciliation.py
        ├── test_tag_parser.py
        ├── test_tenable_client.py
        ├── test_streaming.py
        ├── test_asset_id_filter.py
        ├── test_asset_tag_enrichment.py
        ├── test_csv_reports.py
        └── test_nvd_enrichment.py
```

116 unit tests passing.

---

## 14. Technology Stack

| Layer | Choice |
|---|---|
| Language | Python 3.10+ |
| HTTP client | `httpx` + `tenacity` (retries with exponential backoff) |
| ORM | SQLAlchemy 2.0 |
| Migrations | Alembic |
| Config | Pydantic + YAML |
| Logging | structlog (JSON) |
| Database | PostgreSQL 16 |
| Dev DB host | Docker Compose |
| Tests | pytest |
| CLI parsing | argparse |

### What we deliberately avoided

- S3 for raw data (PostgreSQL holds everything — simpler ops)
- DynamoDB (relational queries win for reporting)
- Async/await throughout (sync HTTP works fine at this scale)
- Dashboards / UI (CSV exports meet immediate need)
- Web framework like FastAPI (no public API in Phase 0)
- Microservices (one orchestrator is plenty)
- Redis (PostgreSQL handles caching via `cve_details`)

---

## 15. Configuration Reference

Every config is YAML in `config/`. Anything sensitive (API keys) lives in
`.env` and is read via Pydantic settings.

### 15.1 `tenable.yaml`

```yaml
tenable:
  base_url: "https://cloud.tenable.com"
  findings_endpoint: "/api/v1/t1/inventory/findings/search"
  retrieval_mode: "search"
  extra_properties: "finding_vpr_score,finding_cvss3_base_score,finding_cves,finding_solution,finding_detection_id,asset_name,asset_class,sensor_type,first_observed_at,last_observed_at,last_updated,tag_names,tag_ids,ipv4_addresses,product"
  page_size: 10000
  request_timeout_seconds: 120
  max_retries: 3
  stale_threshold_days: 7
  severity_filter: null         # not used currently
  tag_filter: null              # set per-run via --tag CLI flag
```

### 15.2 `scoring.yaml`

```yaml
scoring:
  active_model: "custom"
  custom:
    vpr_weight: 0.50
    acs_weight: 0.50
    thresholds: { critical: 0.75, high: 0.50, medium: 0.30 }
  lumin:
    ces_thresholds: { critical: 800, high: 600, medium: 400 }
  criticality_scores:
    CRITICAL: 1.0
    HIGH: 0.75
    MEDIUM: 0.50
    LOW: 0.25
  default_criticality_score: 0.25
```

### 15.3 `sla_policy.yaml`

```yaml
sla:
  critical: 10
  high: 30
  medium: 45
  low: 90
  use_business_days: false
  approaching_warning_days: 5
```

### 15.4 `.env` (secrets)

```bash
DATABASE_URL=postgresql://vm_user:vm_local_pass@localhost:5435/vm_middleware
TENABLE_ACCESS_KEY=...
TENABLE_SECRET_KEY=...
NVD_API_KEY=...                    # optional but strongly recommended
# Phase 2:
# JIRA_BASE_URL=...
# JIRA_API_TOKEN=...
# JIRA_USER_EMAIL=...
```

---

## 16. Phase Alignment

| Phase | Status | Scope |
|---|---|---|
| Phase 0 — Foundation | Complete | Data model, ingestion, reconciliation, scoring, SLA, local dev |
| Phase 0+ — Risk model | Complete | Tag taxonomy, asset-tag enrichment, NVD enrichment, CSV reports |
| Phase 1 — Production baseline | Next | Lambda deployment, EventBridge schedule, AWS Secrets, validation runs |
| Phase 2 — Jira + reporting v2 | Planned | Jira integration, phased rollout, exception management, dashboards (optional) |
| Phase 3 — Expansion | Planned | Azure, ASM, executive reporting, SIEM/SOAR integration |
| Phase 4 — Optimisation | Planned | Maturity reassessment, automation, BAU handover |

---

## 17. Key Design Decisions

1. **Tenable Inventory API as the single source.** Avoids per-module integration. Confirmed it aggregates VM, Cloud Security, WAS, and container findings.

2. **Tenable `id` field as the dedup key.** Stable across scans, unique across sources, persists through state changes — better than composite hashes.

3. **Pull-and-reconcile rather than push.** Each run re-pulls and compares to stored state. No webhooks, no Jira state dependency.

4. **Don't auto-close on missing findings.** Disappearance ≠ remediation. Only an explicit Tenable `FIXED` state closes a Jira ticket. Stale findings flag for human review.

5. **Tag taxonomy encodes the category in the value.** The Inventory API doesn't return Tenable's UI-only category field. `Category-Value` in PascalCase is the workaround; the parser splits on the first hyphen.

6. **Two-stage filtering by tag.** `findings/search` ignores tag filters, but `assets/search` accepts advanced query. So we pre-fetch tagged asset_ids, then batch-filter findings server-side by asset_id.

7. **Streaming pipeline with per-page commit + checkpoint.** Survives interruption. A 15-minute run is resumable from the last committed page.

8. **Configurable risk formula.** Criticality scores, weights, and thresholds are all in `scoring.yaml`. Switching from VPR+ACS to Lumin CES is a config flip.

9. **NVD enrichment for descriptions/references.** Tenable returns no `finding_solution` for Cloud Security findings. NVD provides the gap fill, cached per CVE with configurable TTL.

10. **PostgreSQL-only storage.** No S3, no DynamoDB, no Redis. Relational queries dominate (reporting); a single database keeps ops simple.

11. **CSV over dashboards.** Spec calls for CSV reports; we don't build a UI. Six report types accept the same filter set; downstream tools (Excel, PowerBI) handle visualisation.

---

## 18. Non-Functional Requirements

| Requirement | Current state |
|---|---|
| Local dev setup time | < 5 minutes (`make install && make db-up && make db-migrate`) |
| Pipeline runtime (tagged, with NVD key) | ~10 minutes for ~33,000 assets / 163,000 findings on first run; ~5 minutes on subsequent runs (NVD cache warm) |
| Resume safety | Per-page commits + run checkpoint; interruption costs at most one page (< 30 seconds of work) |
| Test coverage | 116 unit tests; full reconciliation, scoring, SLA, enrichment, NVD, and reporting paths covered |
| Reproducibility | Deterministic config + Docker DB → identical results across machines |
| Auditability | Every API call logged via structlog (JSON); per-run statistics persisted in `pipeline_runs` |
| Observability | structlog JSON output ready for ingestion into CloudWatch / Datadog / etc. |
| Security | Secrets via `.env` (gitignored). No credentials in code or YAML config. |
| Scale ceiling (current) | Tested at 4.4M total findings, 163K filtered; pre-flight asset cap ~33K; should handle 10x with no architectural change |
