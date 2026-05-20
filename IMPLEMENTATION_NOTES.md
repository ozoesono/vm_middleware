# VM Middleware — Implementation Notes

> Engineering reference, not architecture. Lives alongside but separate from
> [ARCHITECTURE.md](./ARCHITECTURE.md).
>
> This document holds the API quirks, field mappings, working payloads, and
> debugging context that an engineer needs day-to-day but that aren't
> appropriate for the architecture record.

---

## Contents

1. [Tenable Inventory API — field reference](#1-tenable-inventory-api--field-reference)
2. [Tenable Inventory API — quirks and workarounds](#2-tenable-inventory-api--quirks-and-workarounds)
3. [Working filter payloads](#3-working-filter-payloads)
4. [NVD API usage](#4-nvd-api-usage)
5. [Configuration reference](#5-configuration-reference)
6. [Project structure](#6-project-structure)
7. [Database schema (column-level)](#7-database-schema-column-level)
8. [Probe scripts](#8-probe-scripts)
9. [Common operational tasks](#9-common-operational-tasks)

---

## 1. Tenable Inventory API — field reference

The property names below were verified empirically via
`GET /api/v1/t1/inventory/findings/properties` — they differ from older
Tenable documentation in several places.

| Concept | Property name | Notes |
|---|---|---|
| Finding identifier | `id` (top-level) | Stored as `tenable_finding_id` in our DB. UNIQUE. |
| Asset reference | `asset_id` (top-level) | UUID. |
| State | `state` (top-level) | Values: `ACTIVE`, `FIXED`, `RESURFACED`, `NEW`. |
| Severity | `severity` (top-level) | Uppercase: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. |
| VPR | `finding_vpr_score` | 0.0 to 10.0. May be null. |
| CVE list | `finding_cves` | List. Often a single element. We take the first. |
| CVSS v3 | `finding_cvss3_base_score` | 0.0 to 10.0. |
| Solution | `finding_solution` | **Null for 100% of Cloud Security findings** (verified: 0/213,398). Populated for some Nessus findings. |
| Plugin ID | `finding_detection_id` | Long composite strings for Cloud Security (e.g. `CLOUD_SCAN:AWSS3BUCKETPUBLICACCESSEXISTSFINDING_CRITICAL`). |
| Tags | `tag_names` + `tag_ids` | Both lists. `tag_names` contains the human-readable label (which under our taxonomy carries the category encoded as a prefix). |
| Source module | `sensor_type` | `NESSUS`, `CLOUD_SCAN`, `CS:AC_AWS`, `WAS`, etc. |
| Asset class | `asset_class` | `containerImage`, `device`, `S3`, `ELB`, etc. |
| IPs | `ipv4_addresses` | List. Take first. |
| First observed | `first_observed_at` | ISO 8601 string. |
| Last observed | `last_observed_at` | ISO 8601 string. |

### Asset properties (different endpoint)

`GET /api/v1/t1/inventory/assets/properties` returns:
`external_tags`, `tag_count`, `tag_ids`, `tag_names`, ...

Available filter properties for assets include `tag_names` and `tag_ids` —
but the assets endpoint also accepts the advanced query language, which is
what we use.

---

## 2. Tenable Inventory API — quirks and workarounds

Verified behaviours that differ from documentation.

| Symptom | Workaround |
|---|---|
| `POST` returns **415 Unsupported Media Type** when body is `null` | Always send `json={}` even with no filters. |
| Sort by `severity:desc` returns **400 unknown query property: severity** | Use `finding_severity:desc`. |
| Structured `filters` for tag properties on `findings/search` return 200 but the filter is silently ignored (total = unfiltered total) | Don't filter findings by tag directly. Use the two-stage strategy (§3.1). |
| `findings/search` with `query.mode=Advanced` returns **500** | Use `query.mode=simple` for findings/search (advanced works on assets/search). |
| `findings/search` with `query.mode=Simple` and a text query returns 0 matches even for valid asset IDs | Combine `query.mode=simple` + `query.text=""` (empty) **with** structured `filters` (§3.2). |
| Filter operator `eq` returns 400 on `findings/search` | Use `"operator": "="`. The value must be a list. |
| `POST /api/v1/t1/inventory/findings/export` accepts `tag_names` as a requested property but returns null for it | Don't use export mode if you need tag data. Use the search endpoint with pagination instead. |
| `finding_solution` is null for Cloud Security findings | Enrich via NVD (§4). |

Discovery scripts that produced these findings live under `scripts/probe_*.py`
(§8).

---

## 3. Working filter payloads

### 3.1 Stage 1 — get tagged assets via advanced query

```http
POST /api/v1/t1/inventory/assets/search?extra_properties=asset_id,asset_name,tag_names
Content-Type: application/json
X-ApiKeys: accessKey=...;secretKey=...

{
  "query": {
    "mode": "advanced",
    "text": "Assets HAS tag_names = \"Portfolio-Business-Growth\""
  }
}
```

Returns the assets matching the tag plus **all** of their tag_names (so we
get the full enrichment context — Criticality, Environment, Service, etc. —
in one pass).

The tag string uses our taxonomy: `<Category>-<Value>` in PascalCase
(see [tag_taxonomy.txt](./tag_taxonomy.txt)).

### 3.2 Stage 2 — get findings server-side-filtered by asset_id batch

```http
POST /api/v1/t1/inventory/findings/search?offset=0&limit=10000&extra_properties=finding_vpr_score,finding_cvss3_base_score,finding_cves,finding_solution,finding_detection_id,asset_name,asset_class,sensor_type,first_observed_at,last_observed_at,last_updated,tag_names,tag_ids,ipv4_addresses,product
Content-Type: application/json
X-ApiKeys: accessKey=...;secretKey=...

{
  "query": {"mode": "simple", "text": ""},
  "filters": [
    {
      "property": "asset_id",
      "operator": "=",
      "value": ["uuid-1", "uuid-2", ..., "uuid-500"]
    }
  ]
}
```

Filters server-side. Up to ~500 asset_ids per request works reliably.

---

## 4. NVD API usage

Endpoint: `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX-XXXX`

Rate limits:
- Without API key: 5 requests / 30 seconds
- With API key: 50 requests / 30 seconds — strongly recommended
- Get a key at https://nvd.nist.gov/developers/request-an-api-key (free)
- Set in `.env` as `NVD_API_KEY=...`

Response shape (what we use):

```json
{
  "vulnerabilities": [{
    "cve": {
      "id": "CVE-2023-2640",
      "published": "2023-05-22T16:15:00.000",
      "descriptions": [{"lang": "en", "value": "..."}],
      "metrics": {
        "cvssMetricV31": [{"cvssData": {"baseScore": 7.8, "baseSeverity": "HIGH"}}]
      },
      "weaknesses": [{"description": [{"lang": "en", "value": "CWE-863"}]}],
      "references": [{"url": "https://...", "source": "vendor", "tags": [...]}]
    }
  }]
}
```

Cached for 60 days in the `cve_details` table. See `src/ingestion/nvd_enrichment.py`.

---

## 5. Configuration reference

### `tenable.yaml`

```yaml
tenable:
  base_url: "https://cloud.tenable.com"
  findings_endpoint: "/api/v1/t1/inventory/findings/search"
  retrieval_mode: "search"               # "search" or "export"
  extra_properties: "finding_vpr_score,finding_cvss3_base_score,finding_cves,finding_solution,finding_detection_id,asset_name,asset_class,sensor_type,first_observed_at,last_observed_at,last_updated,tag_names,tag_ids,ipv4_addresses,product"
  page_size: 10000
  request_timeout_seconds: 120
  max_retries: 3
  stale_threshold_days: 7
  tag_filter: null                       # set per-run via --tag CLI flag
```

### `scoring.yaml`

```yaml
scoring:
  active_model: "custom"                 # "custom" or "lumin_ces"
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
  criticality_scores:
    CRITICAL: 1.0
    HIGH: 0.75
    MEDIUM: 0.50
    LOW: 0.25
  default_criticality_score: 0.25
```

### `sla_policy.yaml`

```yaml
sla:
  critical: 10    # days
  high: 30
  medium: 45
  low: 90
  use_business_days: false
  approaching_warning_days: 5
```

### `.env`

```bash
DATABASE_URL=postgresql://vm_user:vm_local_pass@localhost:5435/vm_middleware
TENABLE_ACCESS_KEY=...
TENABLE_SECRET_KEY=...
NVD_API_KEY=...                    # optional but strongly recommended
# Phase 2:
# JIRA_BASE_URL=https://org.atlassian.net
# JIRA_API_TOKEN=...
# JIRA_USER_EMAIL=...
```

---

## 6. Project structure

```
vm-middleware/
├── ARCHITECTURE.md                   ← architecture doc (decisions, views)
├── ARCHITECTURE.docx                 ← Word version of architecture doc
├── IMPLEMENTATION_NOTES.md           ← this file (engineering reference)
├── OVERVIEW.md                       ← top-level summary (10-min read)
├── architecture_simple.md/.txt       ← one-page condensed version
├── tag_taxonomy.txt                  ← the naming convention
├── user_stories.txt                  ← phased user-story backlog
│
├── pyproject.toml                    ← dependencies, build config
├── Makefile                          ← install / db-up / db-migrate / test
├── docker-compose.yaml               ← local PostgreSQL
│
├── config/
│   ├── tenable.yaml                  ← endpoint, properties, retrieval, tag_filter
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
│   │   ├── config.py                 ← Pydantic config loader
│   │   ├── db.py                     ← SQLAlchemy session, engine
│   │   ├── models.py                 ← ORM tables
│   │   ├── logging.py                ← structlog setup
│   │   └── tag_parser.py             ← Category-Value parser
│   │
│   ├── ingestion/
│   │   ├── tenable_client.py         ← findings/search + batched asset_id filter
│   │   ├── tenable_ingestion.py      ← normalise → staging
│   │   ├── tagged_assets.py          ← pre-flight assets/search advanced query
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
│   │   ├── sla.py                    ← SLA calculation
│   │   └── types.py                  ← ScoringResult
│   │
│   ├── reporting/
│   │   └── csv_reports.py            ← six report types
│   │
│   ├── pipeline.py                   ← orchestrator
│   └── lambdas/                      ← AWS Lambda entry points (Phase 2)
│
├── scripts/
│   ├── run_local.py                  ← CLI: --tag --mode --severity --resume
│   ├── generate_report.py            ← CLI: --report --filter --out
│   ├── seed_enrichment.py            ← seed CSV mappings
│   └── probe_*.py                    ← API discovery probes (one-off)
│
└── tests/
    ├── conftest.py
    ├── fixtures/
    │   ├── sample_tenable_findings.json
    │   └── sample_enrichment.csv
    └── unit/
        └── *.py                       ← 116 unit tests
```

---

## 7. Database schema (column-level)

### `findings` (canonical scored records)

```text
identity:           id (UUID PK), tenable_finding_id (UNIQUE), tenable_asset_id

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

### `pipeline_runs`

```text
identity:           id (UUID PK), started_at, completed_at, status, trigger

run statistics:     findings_fetched, findings_new, findings_updated,
                    findings_remediated, findings_recurred, findings_stale,
                    jira_tickets_created/updated/closed

checkpoint:         last_offset, pages_completed,
                    total_findings_expected, tag_filter

batched checkpoint: asset_ids_for_run (JSON: {ids: [...], tags: {...}}),
                    last_batch_idx, total_batches

errors:             errors (JSON list)
```

### `cve_details`

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

### Other tables

| Table | Purpose |
|---|---|
| `findings_staging` | Per-run ingestion buffer. Same columns as the source data section of `findings` plus `run_id`. Cleared at end of pipeline. |
| `enrichment_mappings` | CSV-loaded asset → business context overrides |
| `enrichment_overrides` | Granular field-level overrides |
| `jira_action_queue` | Pending Phase 2 actions (CREATE/UPDATE/CLOSE/REOPEN) |
| `jira_sync_log` | Phase 2 audit log of Jira API calls |
| `risk_exceptions` | Phase 2 risk-acceptance log |

---

## 8. Probe scripts

The `scripts/probe_*.py` files in the repo are one-off discovery scripts that
established the API contract we documented in §1 and §2.

Useful when re-validating after a Tenable platform change:

| Script | What it discovers |
|---|---|
| `probe_advanced_assets.py` | Confirms the advanced query syntax on assets/search |
| `probe_asset_id_thorough.py` | Tries 16 filter shapes for asset_id on findings/search |
| `probe_findings_simple_mode.py` | Tests query.mode=simple combinations |
| `probe_query_params.py` | Tests query-parameter tag filters |
| `probe_description_props.py` | Looks for description-related properties |
| `probe_remediation_fields.py` | Dumps all populated fields for sample findings |
| `probe_filter_shapes.py` | Generic filter shape discovery |
| `probe_mode_values.py` | Exhaustive `mode` value testing |
| `probe_doc_validated.py` | Validates filters using documented property names |

These are not part of the production pipeline. Treat as utility scripts.
Candidates for cleanup (see ARCHITECTURE.md §12.2 TD1).

---

## 9. Common operational tasks

### Run the pipeline for a portfolio

```bash
caffeinate -i .venv/bin/python3 scripts/run_local.py --tag Portfolio-Business-Growth
```

`caffeinate -i` (macOS) prevents the laptop from sleeping during a long run.

### Resume an interrupted run

```bash
.venv/bin/python3 scripts/run_local.py --tag Portfolio-Business-Growth --resume
```

The most recent RUNNING/PARTIAL_FAILURE/FAILED run for that tag filter is
picked up from the last committed checkpoint.

### Generate a CSV report

```bash
# List reports
.venv/bin/python3 scripts/generate_report.py --list

# Full findings export
.venv/bin/python3 scripts/generate_report.py --report findings --out findings.csv

# Risk summary, criticals + highs only, one portfolio
.venv/bin/python3 scripts/generate_report.py \
    --report risk-summary \
    --portfolio Business-Growth \
    --risk-rating CRITICAL --risk-rating HIGH \
    --out risk-bg.csv
```

### Inspect run state

```sql
-- in psql or via docker exec
SELECT id, status, started_at, completed_at,
       findings_fetched, findings_new, findings_remediated,
       last_batch_idx, total_batches
FROM pipeline_runs
ORDER BY started_at DESC
LIMIT 5;
```

### Check NVD cache state

```sql
SELECT
  COUNT(*) AS total_cves,
  MIN(last_fetched_at) AS oldest,
  MAX(last_fetched_at) AS newest
FROM cve_details;
```

### Validate the Tenable API contract

Re-run the probes (§8) if filter behaviour seems wrong:

```bash
.venv/bin/python3 scripts/probe_advanced_assets.py --tag Portfolio-Business-Growth
.venv/bin/python3 scripts/probe_asset_id_thorough.py
```

### Apply a schema migration

```bash
cd db && DATABASE_URL=postgresql://vm_user:vm_local_pass@localhost:5435/vm_middleware \
    ../.venv/bin/alembic upgrade head
```

Or, equivalently: `make db-migrate`.
