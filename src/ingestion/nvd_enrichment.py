"""Fetch CVE detail data from NVD (NIST National Vulnerability Database).

Tenable's Inventory API doesn't return descriptions/solutions for Cloud
Security findings — only the CVE ID. NVD provides:
  - Description (the official summary of the vulnerability)
  - CVSS v3 metrics
  - CWE classification (the weakness type)
  - References (URLs to vendor advisories with remediation guidance)

We cache results in the `cve_details` table keyed by cve_id. A CVE is
only re-fetched if it's never been seen or is older than `ttl_days`.

NVD API:
  - GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<id>
  - No auth: 5 requests per 30s
  - With API key: 50 requests per 30s
  - Set NVD_API_KEY in your .env to dramatically speed this up.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import not_, or_
from sqlalchemy.orm import Session

from src.common.logging import get_logger
from src.common.models import CveDetails, FindingStaging

logger = get_logger("nvd_enrichment")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limits per NVD docs
RATE_LIMIT_NO_KEY = (5, 30)    # 5 requests per 30s
RATE_LIMIT_WITH_KEY = (50, 30)  # 50 requests per 30s


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _parse_nvd_response(data: dict, cve_id: str) -> dict | None:
    """Extract the fields we want from an NVD JSON 2.0 response."""
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    cve = vulns[0].get("cve", {})
    if cve.get("id") != cve_id:
        return None

    # English description
    description = None
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value")
            break

    # CVSS v3
    cvss_score = None
    cvss_severity = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cd = m.get("cvssData", {})
            cvss_score = cd.get("baseScore")
            cvss_severity = cd.get("baseSeverity")
            break

    # CWE (weakness type)
    cwe_id = None
    cwe_name = None
    for w in cve.get("weaknesses", []):
        for desc in w.get("description", []):
            if desc.get("lang") == "en" and desc.get("value"):
                cwe_id = desc["value"]
                break
        if cwe_id:
            break

    # References
    refs = []
    for ref in cve.get("references", []):
        refs.append({
            "url": ref.get("url"),
            "source": ref.get("source"),
            "tags": ref.get("tags", []),
        })

    # Published date
    published_at = None
    pub_str = cve.get("published")
    if pub_str:
        try:
            published_at = datetime.fromisoformat(pub_str.replace("Z", "+00:00")).replace(tzinfo=None)
        except (ValueError, AttributeError):
            pass

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_v3_score": cvss_score,
        "cvss_v3_severity": cvss_severity,
        "cwe_id": cwe_id,
        "cwe_name": cwe_name,
        "published_at": published_at,
        "references": refs,
    }


def _fetch_one(client: httpx.Client, cve_id: str, api_key: str | None) -> dict | None:
    """Fetch a single CVE's details from NVD. Returns parsed dict or None."""
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    try:
        r = client.get(NVD_URL, params={"cveId": cve_id}, headers=headers)
        if r.status_code == 404:
            logger.warning("nvd_cve_not_found", cve_id=cve_id)
            return None
        if r.status_code == 429:
            logger.warning("nvd_rate_limited_sleeping", cve_id=cve_id)
            time.sleep(10)
            r = client.get(NVD_URL, params={"cveId": cve_id}, headers=headers)
        if r.status_code != 200:
            logger.warning("nvd_fetch_error", cve_id=cve_id, status=r.status_code, text=r.text[:200])
            return None
        return _parse_nvd_response(r.json(), cve_id)
    except (httpx.HTTPError, ValueError) as e:
        logger.warning("nvd_request_failed", cve_id=cve_id, error=str(e))
        return None


def _filter_to_fetch(session: Session, cve_ids: set[str], ttl_days: int) -> list[str]:
    """Given candidate CVEs, return the sorted subset that needs fetching
    (never cached, or cached but older than ttl_days)."""
    if not cve_ids:
        return []
    cutoff = _utcnow() - timedelta(days=ttl_days)
    existing = (
        session.query(CveDetails.cve_id, CveDetails.last_fetched_at)
        .filter(CveDetails.cve_id.in_(cve_ids))
        .all()
    )
    fresh_ids = {row.cve_id for row in existing if row.last_fetched_at >= cutoff}
    return sorted(cve_ids - fresh_ids)


def _fetch_and_cache(
    session: Session,
    to_fetch: list[str],
    api_key: str | None,
) -> int:
    """Fetch each CVE from NVD and upsert into cve_details. Rate-limited.
    Commits every 50 so an interruption keeps prior progress. Returns count cached."""
    if not to_fetch:
        return 0

    rate_count, rate_window = RATE_LIMIT_WITH_KEY if api_key else RATE_LIMIT_NO_KEY
    sleep_between = rate_window / rate_count

    cached = 0
    last_call = 0.0
    with httpx.Client(timeout=60) as client:
        for i, cve_id in enumerate(to_fetch, 1):
            elapsed = time.time() - last_call
            if elapsed < sleep_between:
                time.sleep(sleep_between - elapsed)

            details = _fetch_one(client, cve_id, api_key)
            last_call = time.time()
            if details is None:
                continue

            existing_row = session.query(CveDetails).filter_by(cve_id=cve_id).first()
            if existing_row:
                for k, v in details.items():
                    setattr(existing_row, k, v)
                existing_row.last_fetched_at = _utcnow()
            else:
                session.add(CveDetails(**details, last_fetched_at=_utcnow(), source="nvd"))
            cached += 1

            if i % 50 == 0:
                session.commit()
                logger.info("nvd_progress", done=i, of=len(to_fetch), cached=cached)

    session.commit()
    logger.info("nvd_enrichment_done", cached=cached, of=len(to_fetch))
    return cached


def enrich_unique_cves_for_run(
    session: Session,
    run_id,
    ttl_days: int = 60,
    api_key: str | None = None,
    max_fetch: int | None = None,
) -> int:
    """Enrich CVEs from a run's STAGING table. Bounded by max_fetch.

    Used inline by the pipeline only when nvd.inline_enrichment is on AND
    a max is set — so it never blocks the pipeline for hours.
    """
    api_key = api_key or os.environ.get("NVD_API_KEY")

    cve_rows = (
        session.query(FindingStaging.cve_id)
        .filter(FindingStaging.run_id == run_id, FindingStaging.cve_id.isnot(None))
        .distinct()
        .all()
    )
    unique_cves = {r[0] for r in cve_rows if r[0]}
    to_fetch = _filter_to_fetch(session, unique_cves, ttl_days)

    if max_fetch is not None and max_fetch >= 0:
        to_fetch = to_fetch[:max_fetch]

    logger.info(
        "nvd_enrichment_start",
        scope="staging",
        unique_cves=len(unique_cves),
        to_fetch=len(to_fetch),
        max_fetch=max_fetch,
        api_key_present=bool(api_key),
    )
    return _fetch_and_cache(session, to_fetch, api_key)


def distinct_finding_cves(
    session: Session,
    exclude_container: bool = False,
    container_patterns: list[str] | None = None,
) -> set[str]:
    """Return the distinct cve_ids on the canonical findings table.

    When exclude_container is set, findings whose asset_name matches any
    container registry pattern are dropped, so only host/VM (and other
    non-container) CVEs remain. A CVE that appears on at least one
    non-container asset is kept even if it also appears on container images.
    """
    from src.common.models import Finding  # local import to avoid cycles

    q = session.query(Finding.cve_id).filter(Finding.cve_id.isnot(None))
    if exclude_container and container_patterns:
        registry_match = or_(*[Finding.asset_name.ilike(f"%{p}%") for p in container_patterns])
        q = q.filter(or_(Finding.asset_name.is_(None), not_(registry_match)))
    return {r[0] for r in q.distinct().all() if r[0]}


def enrich_cves_from_findings(
    session: Session,
    ttl_days: int = 60,
    api_key: str | None = None,
    max_fetch: int | None = None,
    exclude_container: bool = False,
    container_patterns: list[str] | None = None,
) -> int:
    """Enrich CVEs from the canonical FINDINGS table — the standalone path.

    Scans every distinct cve_id on findings, fetches those not yet cached
    (or stale), and caches them. Fully resumable: the cache accumulates,
    so re-running picks up where it left off. Bound the work per invocation
    with max_fetch (good for Lambda — fetch a chunk per scheduled run).

    Set exclude_container to fetch only non-container (host/VM) CVE
    descriptions — avoids grinding through the hundreds of thousands of
    distinct container-image CVEs when only the host workstream is needed.

    Returns the number of CVEs cached this invocation.
    """
    api_key = api_key or os.environ.get("NVD_API_KEY")

    unique_cves = distinct_finding_cves(session, exclude_container, container_patterns)
    to_fetch = _filter_to_fetch(session, unique_cves, ttl_days)

    if max_fetch is not None and max_fetch >= 0:
        to_fetch = to_fetch[:max_fetch]

    rate_count, rate_window = RATE_LIMIT_WITH_KEY if api_key else RATE_LIMIT_NO_KEY
    sleep_between = rate_window / rate_count
    logger.info(
        "nvd_enrichment_start",
        scope="findings",
        unique_cves=len(unique_cves),
        to_fetch=len(to_fetch),
        max_fetch=max_fetch,
        api_key_present=bool(api_key),
        est_seconds=int(len(to_fetch) * sleep_between),
    )
    return _fetch_and_cache(session, to_fetch, api_key)
