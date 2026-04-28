"""Tenable ingestion orchestrator — fetches, normalises, and stages findings.

Field mapping from Tenable One Inventory API to our data model:

    Tenable API field         →  Our model field
    ─────────────────────────────────────────────
    id                        →  tenable_finding_id
    name                      →  title (this is the CVE ID)
    asset_id                  →  tenable_asset_id
    state                     →  tenable_state (ACTIVE/FIXED/RESURFACED)
    severity                  →  severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
    extra_properties:
      finding_vpr_score       →  vpr_score
      finding_cvss3_base_score → cvssv3_score
      finding_cves            →  cve_id (list → first item)
      finding_solution        →  solution
      finding_severity        →  (use top-level severity instead)
      finding_detection_id    →  plugin_id
      asset_name              →  asset_name
      asset_class             →  asset_type
      sensor_type             →  source
      first_observed_at       →  first_seen
      last_observed_at        →  last_seen
      tag_names               →  tenable_tags
      tag_ids                 →  (stored in tenable_tags)
      ipv4_addresses          →  asset_ip (list → first item)
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from src.common.logging import get_logger
from src.common.models import FindingStaging

logger = get_logger("tenable_ingestion")

# The extra_properties we request from the Tenable Inventory API
EXTRA_PROPERTIES = ",".join([
    "finding_vpr_score",
    "finding_cvss3_base_score",
    "finding_cves",
    "finding_solution",
    "finding_detection_id",
    "asset_name",
    "asset_class",
    "sensor_type",
    "first_observed_at",
    "last_observed_at",
    "last_updated",
    "tag_names",
    "tag_ids",
    "ipv4_addresses",
    "product",
])


def _parse_datetime(value: Any) -> datetime | None:
    """Parse a datetime from various Tenable formats."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        # Unix timestamp
        try:
            return datetime.utcfromtimestamp(value)
        except (ValueError, OSError):
            return None
    if isinstance(value, str):
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        ):
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
    if isinstance(extra, dict) and key in extra:
        return extra[key]
    return finding.get(key)


def _first_item(value: Any) -> str | None:
    """Extract first item from a list, or return the value as-is."""
    if isinstance(value, list):
        return str(value[0]) if value else None
    if value is not None:
        return str(value)
    return None


def normalise_finding(finding: dict[str, Any], run_id: uuid.UUID) -> FindingStaging:
    """Normalise a raw Tenable Inventory API finding into a FindingStaging record.

    Maps from actual Tenable One Inventory field names to our canonical model.
    """
    extra = finding.get("extra_properties", {}) or {}

    # CVE: finding_cves is a list like ["CVE-2023-2640"], take the first
    cve_list = extra.get("finding_cves", [])
    cve_id = _first_item(cve_list)

    # IP: ipv4_addresses is a list, take the first
    ip_list = extra.get("ipv4_addresses", [])
    asset_ip = _first_item(ip_list)

    # Tags: combine tag_names and tag_ids into a dict for enrichment processing
    tag_names = extra.get("tag_names", [])
    tag_ids = extra.get("tag_ids", [])
    tenable_tags = None
    if tag_names or tag_ids:
        tenable_tags = {"tag_names": tag_names, "tag_ids": tag_ids}

    return FindingStaging(
        id=uuid.uuid4(),
        run_id=run_id,
        tenable_finding_id=str(finding.get("id", "")),
        tenable_asset_id=str(finding.get("asset_id", "")),

        # Finding details
        title=str(finding.get("name", "Unknown")),
        cve_id=cve_id,
        severity=str(finding.get("severity", "Info")),
        vpr_score=_safe_float(extra.get("finding_vpr_score")),
        acr=None,   # Not available in Inventory API
        aes=None,   # Not available in Inventory API
        epss_score=None,  # Not available in Inventory API
        exploit_maturity=None,  # Not available in Inventory API
        cvssv3_score=_safe_float(extra.get("finding_cvss3_base_score")),
        source=extra.get("sensor_type"),
        plugin_id=str(extra.get("finding_detection_id", "") or ""),
        solution=extra.get("finding_solution"),

        # State
        tenable_state=str(finding.get("state", "ACTIVE")),

        # Asset details
        asset_name=extra.get("asset_name"),
        asset_type=extra.get("asset_class"),
        asset_ip=asset_ip,
        asset_hostname=None,  # Not directly available

        # Tags and timestamps
        tenable_tags=tenable_tags,
        first_seen=_parse_datetime(extra.get("first_observed_at")),
        last_seen=_parse_datetime(extra.get("last_observed_at")),
    )


def filter_by_tags(
    findings: list[dict[str, Any]],
    tag_filter: list[str] | None,
) -> list[dict[str, Any]]:
    """Apply client-side tag filtering using tag_names from each finding.

    Keeps any finding whose tag_names array contains AT LEAST ONE of the
    tags in tag_filter. tag_names is unreliable in the export endpoint,
    so this is a fallback — prefer filter_by_asset_ids.
    """
    if not tag_filter:
        return findings

    wanted = {t.strip() for t in tag_filter if t}
    if not wanted:
        return findings

    kept: list[dict[str, Any]] = []
    for f in findings:
        extra = f.get("extra_properties", {}) or {}
        tag_names = extra.get("tag_names") or []
        if isinstance(tag_names, list) and any(t in wanted for t in tag_names):
            kept.append(f)

    logger.info(
        "tag_filter_applied",
        wanted_tags=list(wanted),
        before=len(findings),
        after=len(kept),
        dropped=len(findings) - len(kept),
    )
    return kept


def filter_by_asset_ids(
    findings: list[dict[str, Any]],
    asset_id_set: set[str] | None,
) -> list[dict[str, Any]]:
    """Filter findings to only those whose asset_id is in asset_id_set.

    This is the preferred filtering method — asset_id is always present
    on a finding, unlike tag_names which is sometimes empty.

    The asset_id_set is built upfront by tagged_assets.fetch_tagged_asset_ids().
    """
    if asset_id_set is None:
        return findings
    if not asset_id_set:
        # explicitly empty set — drop everything
        logger.info("asset_id_filter_empty_set_drops_all", before=len(findings))
        return []

    kept: list[dict[str, Any]] = []
    for f in findings:
        aid = f.get("asset_id")
        if aid and aid in asset_id_set:
            kept.append(f)

    logger.info(
        "asset_id_filter_applied",
        target_count=len(asset_id_set),
        before=len(findings),
        after=len(kept),
        dropped=len(findings) - len(kept),
    )
    return kept


def ingest_findings(
    findings: list[dict[str, Any]],
    run_id: uuid.UUID,
    session: Session,
    batch_size: int = 500,
    tag_filter: list[str] | None = None,
    clear_staging: bool = True,
) -> int:
    """Normalise and insert findings into the staging table.

    If tag_filter is provided, findings are filtered client-side first.
    When called from the streaming pipeline, clear_staging=False so each
    page accumulates instead of wiping prior pages.

    Returns the number of findings staged.
    """
    if tag_filter:
        findings = filter_by_tags(findings, tag_filter)

    if not clear_staging:
        return _ingest_resilient(findings, run_id, session, batch_size)

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
            logger.warning(
                "finding_normalisation_error",
                error=str(e),
                finding_id=raw_finding.get("id"),
            )
            continue

    # Flush remaining batch
    if batch:
        session.bulk_save_objects(batch)
        session.flush()

    logger.info("findings_staged", count=count, run_id=str(run_id))
    return count


def _ingest_resilient(
    findings: list[dict[str, Any]],
    run_id: uuid.UUID,
    session: Session,
    batch_size: int,
) -> int:
    """Ingest findings without clearing staging.

    Tries bulk_save_objects first for speed. If a batch fails (e.g. one
    bad row), falls back to one-by-one inserts so a single bad finding
    doesn't kill the entire batch. Skipped findings are logged.
    """
    count = 0
    batch: list[FindingStaging] = []

    def _flush(batch_to_save: list[FindingStaging]) -> int:
        if not batch_to_save:
            return 0
        try:
            session.bulk_save_objects(batch_to_save)
            session.flush()
            return len(batch_to_save)
        except Exception as bulk_err:
            session.rollback()
            logger.warning(
                "bulk_insert_failed_falling_back_to_per_row",
                error=str(bulk_err)[:200],
                batch_size=len(batch_to_save),
            )
            saved = 0
            for sf in batch_to_save:
                try:
                    session.add(sf)
                    session.flush()
                    saved += 1
                except Exception as row_err:
                    session.rollback()
                    logger.warning(
                        "row_insert_failed",
                        finding_id=sf.tenable_finding_id,
                        error=str(row_err)[:200],
                    )
            return saved

    for raw_finding in findings:
        try:
            staged = normalise_finding(raw_finding, run_id)
            batch.append(staged)
            if len(batch) >= batch_size:
                count += _flush(batch)
                batch = []
        except Exception as e:
            logger.warning(
                "finding_normalisation_error",
                error=str(e),
                finding_id=raw_finding.get("id"),
            )
            continue

    if batch:
        count += _flush(batch)

    return count
