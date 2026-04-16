"""Tenable ingestion orchestrator — fetches, normalises, and stages findings."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from src.common.logging import get_logger
from src.common.models import FindingStaging

logger = get_logger("tenable_ingestion")


def _parse_datetime(value: Any) -> datetime | None:
    """Parse a datetime from various Tenable formats."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        # Try common formats
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
    return None


def _safe_float(value: Any) -> float | None:
    """Safely convert a value to float."""
    if value is None:
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def _safe_int(value: Any) -> int | None:
    """Safely convert a value to int."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _get_extra(finding: dict, key: str) -> Any:
    """Get a value from finding's extra_properties or top-level."""
    extra = finding.get("extra_properties", {})
    if isinstance(extra, dict):
        if key in extra:
            return extra[key]
    # Also check top-level
    return finding.get(key)


def normalise_finding(finding: dict[str, Any], run_id: uuid.UUID) -> FindingStaging:
    """Normalise a raw Tenable API finding into a FindingStaging record."""
    return FindingStaging(
        id=uuid.uuid4(),
        run_id=run_id,
        tenable_finding_id=str(finding.get("id", "")),
        tenable_asset_id=str(_get_extra(finding, "asset_id") or finding.get("asset_id", "")),
        title=str(finding.get("name", _get_extra(finding, "finding_name") or "Unknown")),
        cve_id=_get_extra(finding, "cve"),
        severity=str(finding.get("severity", "Info")),
        vpr_score=_safe_float(_get_extra(finding, "vpr_score")),
        acr=_safe_int(_get_extra(finding, "acr")),
        aes=_safe_int(_get_extra(finding, "aes")),
        epss_score=_safe_float(_get_extra(finding, "epss_score")),
        exploit_maturity=_get_extra(finding, "exploit_maturity"),
        cvssv3_score=_safe_float(_get_extra(finding, "cvssv3_base_score")),
        source=_get_extra(finding, "source"),
        plugin_id=str(_get_extra(finding, "plugin_id") or ""),
        solution=_get_extra(finding, "solution"),
        tenable_state=str(finding.get("state", "Active")),
        asset_name=_get_extra(finding, "asset_name"),
        asset_type=_get_extra(finding, "asset_type"),
        asset_ip=_get_extra(finding, "asset_ip"),
        asset_hostname=_get_extra(finding, "asset_hostname"),
        tenable_tags=_get_extra(finding, "tags"),
        first_seen=_parse_datetime(_get_extra(finding, "first_seen")),
        last_seen=_parse_datetime(_get_extra(finding, "last_seen")),
    )


def ingest_findings(
    findings: list[dict[str, Any]],
    run_id: uuid.UUID,
    session: Session,
    batch_size: int = 500,
) -> int:
    """Normalise and insert findings into the staging table.

    Returns the number of findings staged.
    """
    # Clear staging table for this run
    session.query(FindingStaging).filter(FindingStaging.run_id == run_id).delete()
    session.flush()

    count = 0
    batch: list[FindingStaging] = []

    for raw_finding in findings:
        try:
            staged = normalise_finding(raw_finding, run_id)
            batch.append(staged)
            count += 1

            if len(batch) >= batch_size:
                session.bulk_save_objects(batch)
                session.flush()
                batch = []
        except Exception as e:
            logger.warning("finding_normalisation_error", error=str(e), finding_id=raw_finding.get("id"))
            continue

    # Flush remaining batch
    if batch:
        session.bulk_save_objects(batch)
        session.flush()

    logger.info("findings_staged", count=count, run_id=str(run_id))
    return count
