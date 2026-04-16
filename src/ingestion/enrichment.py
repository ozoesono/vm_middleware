"""Enrichment sync — loads asset-to-business context mappings from CSV or database."""

from __future__ import annotations

import csv
import uuid
from pathlib import Path

from sqlalchemy.orm import Session

from src.common.logging import get_logger
from src.common.models import EnrichmentMapping, FindingStaging

logger = get_logger("enrichment")

# Mapping from asset_criticality string to normalised score (0.25 - 1.0)
CRITICALITY_SCORES = {
    "CRITICAL": 1.0,
    "HIGH": 0.75,
    "MEDIUM": 0.50,
    "LOW": 0.25,
}


def load_enrichment_from_csv(csv_path: str, session: Session) -> int:
    """Load enrichment mappings from a CSV file into the database.

    Expected CSV columns:
        asset_identifier, identifier_type, portfolio, service, environment,
        data_sensitivity, asset_criticality, service_owner, service_owner_team

    Returns the number of mappings loaded.
    """
    path = Path(csv_path)
    if not path.exists():
        logger.warning("enrichment_csv_not_found", path=csv_path)
        return 0

    count = 0
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            asset_id = row.get("asset_identifier", "").strip()
            if not asset_id:
                continue

            identifier_type = row.get("identifier_type", "asset_name").strip()
            criticality = row.get("asset_criticality", "").strip().upper()
            criticality_score = CRITICALITY_SCORES.get(criticality)

            # Upsert: check if mapping exists
            existing = (
                session.query(EnrichmentMapping)
                .filter(
                    EnrichmentMapping.asset_identifier == asset_id,
                    EnrichmentMapping.identifier_type == identifier_type,
                )
                .first()
            )

            if existing:
                existing.portfolio = row.get("portfolio", "").strip() or existing.portfolio
                existing.service = row.get("service", "").strip() or existing.service
                existing.environment = row.get("environment", "").strip() or existing.environment
                existing.data_sensitivity = row.get("data_sensitivity", "").strip() or existing.data_sensitivity
                existing.asset_criticality = criticality or existing.asset_criticality
                existing.asset_criticality_score = criticality_score or existing.asset_criticality_score
                existing.service_owner = row.get("service_owner", "").strip() or existing.service_owner
                existing.service_owner_team = row.get("service_owner_team", "").strip() or existing.service_owner_team
                existing.source = "csv"
            else:
                mapping = EnrichmentMapping(
                    id=uuid.uuid4(),
                    asset_identifier=asset_id,
                    identifier_type=identifier_type,
                    portfolio=row.get("portfolio", "").strip() or None,
                    service=row.get("service", "").strip() or None,
                    environment=row.get("environment", "").strip() or None,
                    data_sensitivity=row.get("data_sensitivity", "").strip() or None,
                    asset_criticality=criticality or None,
                    asset_criticality_score=criticality_score,
                    service_owner=row.get("service_owner", "").strip() or None,
                    service_owner_team=row.get("service_owner_team", "").strip() or None,
                    source="csv",
                )
                session.add(mapping)
            count += 1

    session.flush()
    logger.info("enrichment_csv_loaded", path=csv_path, mappings=count)
    return count


def apply_enrichment(session: Session, run_id: uuid.UUID) -> int:
    """Apply enrichment data to staged findings.

    Matches staged findings against enrichment_mappings by asset_name or asset_id
    and updates the staging records with business context.

    Returns the number of findings enriched.
    """
    # Load all enrichment mappings into a lookup dict
    mappings = session.query(EnrichmentMapping).all()
    lookup_by_name: dict[str, EnrichmentMapping] = {}
    lookup_by_id: dict[str, EnrichmentMapping] = {}

    for m in mappings:
        if m.identifier_type == "asset_name" and m.asset_identifier:
            lookup_by_name[m.asset_identifier.lower()] = m
        elif m.identifier_type == "asset_id" and m.asset_identifier:
            lookup_by_id[m.asset_identifier] = m

    # Apply to staged findings
    staged_findings = session.query(FindingStaging).filter(FindingStaging.run_id == run_id).all()
    enriched_count = 0

    for sf in staged_findings:
        mapping = None

        # Try matching by asset_id first, then asset_name
        if sf.tenable_asset_id:
            mapping = lookup_by_id.get(sf.tenable_asset_id)
        if mapping is None and sf.asset_name:
            mapping = lookup_by_name.get(sf.asset_name.lower())

        # Also try extracting enrichment from Tenable tags
        if mapping is None and sf.tenable_tags:
            # Tenable tags can carry portfolio/service/environment info
            # This is a fallback — CSV/manual mappings take priority
            continue

        if mapping:
            # We store enrichment data on the staging record via tenable_tags field
            # as a JSON dict that the reconciler will pick up
            sf.tenable_tags = sf.tenable_tags or {}
            sf.tenable_tags["_enrichment"] = {
                "portfolio": mapping.portfolio,
                "service": mapping.service,
                "environment": mapping.environment,
                "data_sensitivity": mapping.data_sensitivity,
                "asset_criticality": mapping.asset_criticality,
                "asset_criticality_score": mapping.asset_criticality_score,
                "service_owner": mapping.service_owner,
                "service_owner_team": mapping.service_owner_team,
            }
            enriched_count += 1

    session.flush()
    logger.info("enrichment_applied", enriched=enriched_count, total=len(staged_findings), run_id=str(run_id))
    return enriched_count
