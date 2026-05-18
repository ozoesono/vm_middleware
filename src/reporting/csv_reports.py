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
"""

from __future__ import annotations

import csv
import io
from collections import defaultdict
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from src.common.logging import get_logger
from src.common.models import Finding

logger = get_logger("csv_reports")


# ---------------------------------------------------------------------------
# Filtering helper
# ---------------------------------------------------------------------------


def _apply_filters(query, filters: dict[str, Any] | None):
    """Apply optional column filters to a Finding query.

    Supported keys: portfolio, service, environment, asset_criticality,
    risk_rating, severity, state, sla_status, source.
    Values may be a single string or a list (IN filter).
    """
    if not filters:
        return query

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


# ---------------------------------------------------------------------------
# Report: full findings export
# ---------------------------------------------------------------------------

FINDINGS_COLUMNS = [
    "tenable_finding_id",
    "cve_id",
    "title",
    "severity",
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
    "solution",
]


def report_findings(session: Session, filters: dict | None = None) -> str:
    """Full findings export with all key fields."""
    q = _apply_filters(session.query(Finding), filters)
    q = q.order_by(Finding.risk_score.desc())

    rows = []
    for f in q.all():
        rows.append({col: getattr(f, col, None) for col in FINDINGS_COLUMNS})

    logger.info("report_findings_generated", rows=len(rows), filters=filters)
    return _write_csv(rows, FINDINGS_COLUMNS)


# ---------------------------------------------------------------------------
# Report: risk summary (risk_rating x portfolio x criticality)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Report: SLA breaches / approaching
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Report: recurrence
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Report: portfolio summary
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

REPORTS = {
    "findings": report_findings,
    "risk-summary": report_risk_summary,
    "sla-breaches": report_sla_breaches,
    "sla-approaching": report_sla_approaching,
    "recurrence": report_recurrence,
    "portfolio-summary": report_portfolio_summary,
}


def generate(session: Session, report_name: str, filters: dict | None = None) -> str:
    """Generate a named report and return the CSV string."""
    fn = REPORTS.get(report_name)
    if fn is None:
        raise ValueError(
            f"Unknown report '{report_name}'. Available: {sorted(REPORTS)}"
        )
    return fn(session, filters)
