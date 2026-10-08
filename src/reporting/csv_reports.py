"""CSV report generation.

Reports read straight from the `findings` table (post-scoring), so they
reflect the applied risk formula. No dashboards — CSV is the consumable
output for risk reporting, as per the spec.

Available reports:
    findings              Full findings export (all fields, filterable)
    risk-summary          Counts grouped by risk_rating x portfolio x criticality
    sla-breaches          Findings whose SLA has been breached
    sla-approaching       Findings approaching their SLA deadline
    recurrence            Findings that resurfaced after remediation
    portfolio-summary     Per-portfolio rollup (totals, breaches, avg risk)
    workstream-summary    Open/stale split by container / host-CVE / cloud-misconfig
"""

from __future__ import annotations

import csv
import io
from collections import defaultdict
from typing import Any

from sqlalchemy import case, func, or_
from sqlalchemy.orm import Session

from src.common.config import AppConfig
from src.common.logging import get_logger
from src.common.models import CveDetails, Finding
from src.exclusions.policy import DEFAULT_REGISTRIES, Classification

logger = get_logger("csv_reports")


# Filtering helper


def _apply_filters(query, filters: dict[str, Any] | None):
    """Apply optional column filters to a Finding query.

    Supported keys: portfolio, service, environment, asset_criticality,
    risk_rating, severity, state, sla_status, source.
    Values may be a single string or a list (IN filter).
    """
    filters = filters or {}
    policy = filters.get("_exclusion_policy") or AppConfig().exclusions
    dialect = query.session.get_bind().dialect.name
    if filters.get("excluded_only"):
        query = query.filter(or_(
            policy.sql(Finding, dialect), Finding.processing_status == "PAUSED"))
    elif not filters.get("include_excluded"):
        query = query.filter(policy.active_sql(Finding, dialect))

    column_map = {
        "portfolio": Finding.portfolio,
        "service": Finding.service,
        "environment": Finding.environment,
        "asset_criticality": Finding.asset_criticality,
        "risk_rating": Finding.risk_rating,
        "severity": Finding.severity,
        "state": Finding.state,
        "sla_status": Finding.sla_status,
        "source": Finding.source,
        "team": Finding.jira_team_id,
        "service_owner_team": Finding.service_owner_team,
        "jira_sync_status": Finding.jira_sync_status,
        "processing_status": Finding.processing_status,
    }
    for key, value in filters.items():
        col = column_map.get(key)
        if col is None or value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            query = query.filter(col.in_(list(value)))
        else:
            query = query.filter(col == value)
    return query


def _write_csv(rows: list[dict], fieldnames: list[str]) -> str:
    """Serialise a list of dict rows into a CSV string."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow(r)
    return buf.getvalue()


# Report: full findings export

FINDINGS_COLUMNS = [
    "tenable_finding_id",
    "cve_id",
    "cve_ids",
    "plugin_id",
    "title",
    "severity",
    "description",       # NVD description (rich text)
    "solution",          # Combined remediation guidance
    "references",        # Vendor advisory URLs (newline-separated)
    "cwe",               # NVD weakness type
    "vpr_score",
    "cvssv3_score",
    "risk_model",
    "risk_score",
    "risk_rating",
    "asset_name",
    "asset_type",
    "asset_ip",
    "portfolio",
    "service",
    "environment",
    "data_sensitivity",
    "asset_criticality",
    "asset_criticality_score",
    "service_owner",
    "service_owner_team",
    "source",
    "state",
    "tenable_state",
    "sla_days",
    "sla_due_date",
    "sla_status",
    "first_seen",
    "last_seen",
    "remediated_at",
    "time_to_fix_days",
    "is_recurrence",
    "recurrence_count",
    "jira_ticket_key",
    "jira_ticket_status",
    "jira_team_id",
    "jira_instance_id",
    "jira_ticket_url",
    "jira_sync_status",
    "jira_sync_error",
    "jira_last_synced_at",
    "processing_status",
    "exclusion_rule_ids",
    "exclusion_reason",
    "exclusion_until",
    "last_observed_at",
]


def _format_solution(finding: Finding, cve: CveDetails | None) -> str:
    """Build the Solution column. Prefer Tenable's solution if present, fall
    back to NVD-derived guidance. Always include vendor advisory references
    if available — those have the actual fix steps."""
    parts = []

    if finding.solution and finding.solution.strip():
        parts.append(finding.solution.strip())
    elif cve and cve.description:
        # No Tenable solution — give the resolver something actionable
        parts.append(
            f"No vendor-specific solution available from Tenable. "
            f"Refer to vendor advisories (links below) for remediation steps "
            f"specific to your environment. General guidance: upgrade the "
            f"affected component to a patched version."
        )

    # Always include references — they contain the concrete fix steps
    if cve and cve.references:
        ref_lines = []
        for ref in cve.references[:8]:  # cap at 8 to keep CSV readable
            if isinstance(ref, dict) and ref.get("url"):
                ref_lines.append(f"- {ref['url']}")
        if ref_lines:
            parts.append("References:\n" + "\n".join(ref_lines))

    return "\n\n".join(parts) if parts else ""


def _format_description(finding: Finding, cve: CveDetails | None) -> str:
    """Build the Description column. Combines finding identity, CVE summary,
    and asset context — all the info a resolver needs to understand the issue.
    """
    parts = []

    # 1. Identity line
    header = f"{finding.cve_id or finding.title or 'Finding'}"
    if finding.severity:
        header += f"  •  Severity: {finding.severity}"
    parts.append(header)

    # 2. NVD description (the real explanation)
    if cve and cve.description:
        parts.append(cve.description.strip())
    elif finding.title and finding.title != finding.cve_id:
        # Tenable name is sometimes more than just a CVE id
        parts.append(finding.title)

    # 3. Context
    ctx_bits = []
    if cve and cve.cvss_v3_score is not None:
        ctx_bits.append(f"CVSS v3: {cve.cvss_v3_score}")
    if finding.vpr_score is not None:
        ctx_bits.append(f"VPR: {finding.vpr_score}")
    if cve and cve.cwe_id:
        ctx_bits.append(f"CWE: {cve.cwe_id}")
    if finding.source:
        ctx_bits.append(f"Source: {finding.source}")
    if ctx_bits:
        parts.append("  •  ".join(ctx_bits))

    # 4. Affected asset
    if finding.asset_name:
        asset_line = f"Affected asset: {finding.asset_name}"
        if finding.asset_ip:
            asset_line += f" ({finding.asset_ip})"
        parts.append(asset_line)

    return "\n\n".join(parts)


def report_findings(session: Session, filters: dict | None = None) -> str:
    """Full findings export with rich description + solution columns.

    LEFT JOINs cve_details (NVD-enriched data) so the report shows the
    proper CVE description and remediation references even when Tenable
    omits them (which it does for Cloud Security findings).
    """
    q = _apply_filters(
        session.query(Finding, CveDetails)
        .outerjoin(CveDetails, Finding.cve_id == CveDetails.cve_id),
        filters,
    )
    q = q.order_by(Finding.risk_score.desc())

    rows = []
    for finding, cve in q.all():
        row = {col: getattr(finding, col, None) for col in FINDINGS_COLUMNS if col not in (
            "description", "solution", "references", "cwe"
        )}
        row["description"] = _format_description(finding, cve)
        row["solution"] = _format_solution(finding, cve)
        row["cwe"] = cve.cwe_id if cve else None
        if cve and cve.references:
            urls = [r["url"] for r in cve.references if isinstance(r, dict) and r.get("url")]
            row["references"] = "\n".join(urls)
        else:
            row["references"] = ""
        rows.append(row)

    logger.info("report_findings_generated", rows=len(rows), filters=filters)
    return _write_csv(rows, FINDINGS_COLUMNS)


# Report: risk summary (risk_rating x portfolio x criticality)


def report_risk_summary(session: Session, filters: dict | None = None) -> str:
    """Counts grouped by risk_rating, portfolio, and asset_criticality."""
    q = _apply_filters(
        session.query(
            Finding.risk_rating,
            Finding.portfolio,
            Finding.asset_criticality,
            func.count(Finding.id).label("count"),
            func.avg(Finding.risk_score).label("avg_risk_score"),
        ),
        filters,
    ).group_by(
        Finding.risk_rating, Finding.portfolio, Finding.asset_criticality
    )

    rating_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    rows = []
    for r in q.all():
        rows.append({
            "risk_rating": r.risk_rating,
            "portfolio": r.portfolio or "(untagged)",
            "asset_criticality": r.asset_criticality or "(none)",
            "count": r.count,
            "avg_risk_score": round(r.avg_risk_score or 0, 4),
        })
    rows.sort(key=lambda x: (rating_order.get(x["risk_rating"], 9), -x["count"]))

    logger.info("report_risk_summary_generated", rows=len(rows))
    return _write_csv(
        rows,
        ["risk_rating", "portfolio", "asset_criticality", "count", "avg_risk_score"],
    )


# Report: SLA breaches / approaching

SLA_COLUMNS = [
    "tenable_finding_id", "cve_id", "title", "risk_rating", "risk_score",
    "asset_name", "portfolio", "service", "environment", "asset_criticality",
    "service_owner_team", "sla_days", "sla_due_date", "sla_status",
    "first_seen", "jira_ticket_key",
]


def report_sla_breaches(session: Session, filters: dict | None = None) -> str:
    """All findings whose SLA status is BREACHED."""
    f = dict(filters or {})
    f["sla_status"] = "BREACHED"
    q = _apply_filters(session.query(Finding), f).order_by(Finding.sla_due_date)
    rows = [{c: getattr(x, c, None) for c in SLA_COLUMNS} for x in q.all()]
    logger.info("report_sla_breaches_generated", rows=len(rows))
    return _write_csv(rows, SLA_COLUMNS)


def report_sla_approaching(session: Session, filters: dict | None = None) -> str:
    """All findings whose SLA status is APPROACHING."""
    f = dict(filters or {})
    f["sla_status"] = "APPROACHING"
    q = _apply_filters(session.query(Finding), f).order_by(Finding.sla_due_date)
    rows = [{c: getattr(x, c, None) for c in SLA_COLUMNS} for x in q.all()]
    logger.info("report_sla_approaching_generated", rows=len(rows))
    return _write_csv(rows, SLA_COLUMNS)


# Report: recurrence

RECURRENCE_COLUMNS = [
    "tenable_finding_id", "cve_id", "title", "risk_rating", "asset_name",
    "portfolio", "service", "recurrence_count", "remediated_at",
    "last_seen", "jira_ticket_key",
]


def report_recurrence(session: Session, filters: dict | None = None) -> str:
    """Findings that resurfaced after being remediated."""
    q = _apply_filters(
        session.query(Finding).filter(Finding.is_recurrence.is_(True)),
        filters,
    ).order_by(Finding.recurrence_count.desc())
    rows = [{c: getattr(x, c, None) for c in RECURRENCE_COLUMNS} for x in q.all()]
    logger.info("report_recurrence_generated", rows=len(rows))
    return _write_csv(rows, RECURRENCE_COLUMNS)


# Report: portfolio summary


def report_portfolio_summary(session: Session, filters: dict | None = None) -> str:
    """Per-portfolio rollup: totals, risk breakdown, SLA breaches, avg risk."""
    q = _apply_filters(session.query(Finding), filters)

    agg: dict[str, dict] = defaultdict(lambda: {
        "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
        "sla_breached": 0, "open": 0, "remediated": 0,
        "risk_score_sum": 0.0,
    })

    for f in q.all():
        p = f.portfolio or "(untagged)"
        a = agg[p]
        a["total"] += 1
        a["risk_score_sum"] += f.risk_score or 0
        rr = (f.risk_rating or "").lower()
        if rr in ("critical", "high", "medium", "low"):
            a[rr] += 1
        if f.sla_status == "BREACHED":
            a["sla_breached"] += 1
        if f.state == "OPEN":
            a["open"] += 1
        elif f.state == "REMEDIATED":
            a["remediated"] += 1

    rows = []
    for portfolio, a in sorted(agg.items()):
        rows.append({
            "portfolio": portfolio,
            "total_findings": a["total"],
            "critical": a["critical"],
            "high": a["high"],
            "medium": a["medium"],
            "low": a["low"],
            "open": a["open"],
            "remediated": a["remediated"],
            "sla_breached": a["sla_breached"],
            "avg_risk_score": round(a["risk_score_sum"] / a["total"], 4) if a["total"] else 0,
        })
    rows.sort(key=lambda x: -x["total_findings"])

    logger.info("report_portfolio_summary_generated", portfolios=len(rows))
    return _write_csv(rows, [
        "portfolio", "total_findings", "critical", "high", "medium", "low",
        "open", "remediated", "sla_breached", "avg_risk_score",
    ])


# Report: workstream summary (container / host-CVE / cloud-misconfig)

DEFAULT_CONTAINER_PATTERNS = DEFAULT_REGISTRIES

WORKSTREAM_CONTAINER = "container_image"
WORKSTREAM_HOST_CVE = "host_cve"
WORKSTREAM_MISCONFIG = "cloud_misconfig"


def classify_workstream(
    asset_name: str | None,
    cve_id: str | None,
    container_patterns: list[str] | None = None,
    asset_type: str | None = None,
) -> str:
    """Bucket a finding into a remediation workstream.

    container_image  — a container image (any registry); fix by rebuilding on a
                       patched base image.
    host_cve         — a CVE on a non-container asset (host/VM); patch the host.
    cloud_misconfig  — a non-container finding with no CVE; a configuration issue.
    """
    classifier = Classification(container_name_patterns=(
        container_patterns if container_patterns is not None else DEFAULT_CONTAINER_PATTERNS))
    if classifier.container(asset_type, asset_name):
        return WORKSTREAM_CONTAINER
    return WORKSTREAM_HOST_CVE if cve_id else WORKSTREAM_MISCONFIG


def report_workstream_summary(
    session: Session,
    filters: dict | None = None,
    container_patterns: list[str] | None = None,
) -> str:
    """Open/stale counts split by remediation workstream.

    Container images are detected by registry substring (not just ECR), so
    Docker Hub / GHCR / GCR images are counted correctly. Non-container
    findings split into host CVEs (patchable) and cloud misconfigurations.
    """
    policy = (filters or {}).get("_exclusion_policy") or AppConfig().exclusions
    classifier = policy.classification
    if container_patterns is not None and "_exclusion_policy" not in (filters or {}):
        classifier = classifier.model_copy(update={"container_name_patterns": container_patterns})
    container_cond = classifier.container_sql(Finding)

    workstream = case(
        (container_cond, WORKSTREAM_CONTAINER),
        (Finding.cve_id.isnot(None), WORKSTREAM_HOST_CVE),
        else_=WORKSTREAM_MISCONFIG,
    )

    q = _apply_filters(
        session.query(
            workstream.label("workstream"),
            func.sum(case((Finding.state == "OPEN", 1), else_=0)).label("open_findings"),
            func.sum(case((Finding.state == "STALE", 1), else_=0)).label("stale_findings"),
            func.count(func.distinct(Finding.tenable_asset_id)).label("distinct_assets"),
        ),
        filters,
    ).group_by(workstream)

    order = {WORKSTREAM_CONTAINER: 0, WORKSTREAM_HOST_CVE: 1, WORKSTREAM_MISCONFIG: 2}
    rows = []
    for r in q.all():
        rows.append({
            "workstream": r.workstream,
            "open_findings": int(r.open_findings or 0),
            "stale_findings": int(r.stale_findings or 0),
            "distinct_assets": int(r.distinct_assets or 0),
        })
    rows.sort(key=lambda x: order.get(x["workstream"], 9))

    logger.info("report_workstream_summary_generated", rows=len(rows))
    return _write_csv(
        rows, ["workstream", "open_findings", "stale_findings", "distinct_assets"]
    )


def report_jira_sync(session: Session, filters: dict | None = None) -> str:
    """Delivery state per finding, including findings that have no Jira ticket."""
    filters = {"include_excluded": True, **(filters or {})}
    columns = ["id", "tenable_finding_id", "service_owner_team", "jira_team_id",
               "risk_rating", "state", "sla_status", "jira_instance_id", "jira_ticket_key",
               "jira_ticket_url", "jira_ticket_status", "jira_sync_status", "jira_sync_error",
               "jira_attempts", "jira_last_synced_at", "jira_next_sync_at",
               "processing_status", "exclusion_rule_ids", "exclusion_reason", "exclusion_until",
               "last_observed_at"]
    findings = _apply_filters(session.query(Finding), filters).order_by(Finding.risk_score.desc())
    return _write_csv([{col: getattr(f, col) for col in columns} for f in findings], columns)


def report_team_summary(session: Session, filters: dict | None = None) -> str:
    """Counts by resolved team and source ownership, including unticketed open risk."""
    from sqlalchemy import and_
    columns = ["jira_team_id", "service_owner_team", "open_findings", "unticketed_open",
               "sla_breaches", "delivery_errors"]
    query = _apply_filters(session.query(
        Finding.jira_team_id, Finding.service_owner_team,
        func.sum(case((Finding.state == "OPEN", 1), else_=0)).label("open_findings"),
        func.sum(case((and_(Finding.state == "OPEN", Finding.jira_ticket_key.is_(None)), 1),
                      else_=0)).label("unticketed_open"),
        func.sum(case((and_(Finding.state.in_(["OPEN", "STALE"]),
                           Finding.sla_status == "BREACHED"), 1),
                      else_=0)).label("sla_breaches"),
        func.sum(case((Finding.jira_sync_status.in_(
            ["FAILED", "UNCERTAIN", "BLOCKED", "RETRY"]), 1),
                      else_=0)).label("delivery_errors"),
    ), filters).group_by(Finding.jira_team_id, Finding.service_owner_team)
    return _write_csv([dict(row._mapping) for row in query], columns)


# Dispatcher


def report_exclusions(session: Session, filters: dict | None = None) -> str:
    """Diagnostic report of paused findings; active work reports exclude them."""
    filters = {**(filters or {}), "excluded_only": True}
    return report_findings(session, filters)

REPORTS = {
    "findings": report_findings,
    "risk-summary": report_risk_summary,
    "sla-breaches": report_sla_breaches,
    "sla-approaching": report_sla_approaching,
    "recurrence": report_recurrence,
    "portfolio-summary": report_portfolio_summary,
    "workstream-summary": report_workstream_summary,
    "jira-sync": report_jira_sync,
    "team-summary": report_team_summary,
    "exclusions": report_exclusions,
}


def generate(
    session: Session,
    report_name: str,
    filters: dict | None = None,
    container_patterns: list[str] | None = None,
    exclusion_policy=None,
) -> str:
    """Generate a named report and return the CSV string."""
    fn = REPORTS.get(report_name)
    filters = dict(filters or {})
    if exclusion_policy is not None:
        filters["_exclusion_policy"] = exclusion_policy
    if fn is None:
        raise ValueError(
            f"Unknown report '{report_name}'. Available: {sorted(REPORTS)}"
        )
    if report_name == "workstream-summary":
        return fn(session, filters, container_patterns)
    return fn(session, filters)
