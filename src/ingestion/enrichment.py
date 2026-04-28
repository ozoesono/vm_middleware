"""Enrichment sync — loads asset-to-business context mappings from CSV or database.

Enrichment sources, in priority order:
  1. CSV-based enrichment_mappings (manual override, highest priority)
  2. Tenable tags (parsed via the tag taxonomy: Category-Value)

Tags that don't follow the taxonomy (see tag_taxonomy.txt) are logged as
warnings but otherwise ignored.
"""

from __future__ import annotations

import csv
import uuid
from pathlib import Path

from sqlalchemy.orm import Session

from src.common.logging import get_logger
from src.common.models import EnrichmentMapping, FindingStaging
from src.common.tag_parser import CATEGORY_TO_FIELD, parse_tags

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


def apply_asset_tags_enrichment(
    session: Session,
    run_id: uuid.UUID,
    asset_tags_map: dict[str, list[str]] | None,
    criticality_scores: dict[str, float],
    default_criticality_score: float,
) -> int:
    """Enrich staged findings using a pre-fetched asset_id → tag_names map.

    For each finding in the staging table:
      - look up its asset_id in the map
      - parse the asset's tag_names through the taxonomy parser
      - populate enrichment fields (portfolio, service, environment, etc.)
      - set asset_criticality_score from the Criticality-* tag value

    Args:
        asset_tags_map: dict[asset_id, list[tag_name]] from tagged_assets fetch
        criticality_scores: e.g. {"CRITICAL": 1.0, "HIGH": 0.75, ...}
        default_criticality_score: ACS to use if no Criticality tag is present

    Returns the number of findings enriched.
    """
    if not asset_tags_map:
        logger.info("apply_asset_tags_no_map_skipping")
        return 0

    staged = session.query(FindingStaging).filter(FindingStaging.run_id == run_id).all()
    enriched = 0
    missing_criticality = 0

    for sf in staged:
        if not sf.tenable_asset_id:
            continue
        tag_names = asset_tags_map.get(sf.tenable_asset_id)
        if not tag_names:
            continue

        parsed_dict, _ = parse_tags(tag_names)

        # Build the enrichment payload from parsed tags
        criticality_label = parsed_dict.get("Criticality")
        if criticality_label:
            crit_score = criticality_scores.get(
                criticality_label.upper(), default_criticality_score
            )
        else:
            missing_criticality += 1
            criticality_label = None
            crit_score = default_criticality_score

        enrichment_payload = {
            "portfolio": parsed_dict.get("Portfolio"),
            "service": parsed_dict.get("Service"),
            "environment": parsed_dict.get("Environment"),
            "data_sensitivity": parsed_dict.get("Sensitivity"),
            "asset_criticality": criticality_label,
            "asset_criticality_score": crit_score,
            "service_owner_team": parsed_dict.get("Owner"),
        }

        # Persist on the staging record under tenable_tags["_enrichment"]
        sf.tenable_tags = sf.tenable_tags or {}
        existing = sf.tenable_tags.get("_enrichment", {})
        existing.update({k: v for k, v in enrichment_payload.items() if v is not None})
        sf.tenable_tags["_enrichment"] = existing
        # Always set criticality score (even default) so scoring works
        sf.tenable_tags["_enrichment"]["asset_criticality_score"] = crit_score
        enriched += 1

    session.flush()
    logger.info(
        "asset_tags_enrichment_applied",
        enriched=enriched,
        total_staged=len(staged),
        missing_criticality=missing_criticality,
        run_id=str(run_id),
    )
    return enriched


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

    invalid_tag_count = 0

    for sf in staged_findings:
        # Start by extracting whatever we can from Tenable tags (lower priority)
        tag_enrichment = _extract_tag_enrichment(sf)
        if tag_enrichment.get("_invalid_count", 0) > 0:
            invalid_tag_count += tag_enrichment.pop("_invalid_count")

        # Then try CSV/manual mapping (higher priority — overrides tag values)
        mapping = None
        if sf.tenable_asset_id:
            mapping = lookup_by_id.get(sf.tenable_asset_id)
        if mapping is None and sf.asset_name:
            mapping = lookup_by_name.get(sf.asset_name.lower())

        if mapping:
            # CSV mapping wins — overlay it on top of tag-based enrichment
            tag_enrichment.update({
                "portfolio": mapping.portfolio or tag_enrichment.get("portfolio"),
                "service": mapping.service or tag_enrichment.get("service"),
                "environment": mapping.environment or tag_enrichment.get("environment"),
                "data_sensitivity": mapping.data_sensitivity or tag_enrichment.get("data_sensitivity"),
                "asset_criticality": mapping.asset_criticality or tag_enrichment.get("asset_criticality"),
                "asset_criticality_score": mapping.asset_criticality_score or tag_enrichment.get("asset_criticality_score"),
                "service_owner": mapping.service_owner or tag_enrichment.get("service_owner"),
                "service_owner_team": mapping.service_owner_team or tag_enrichment.get("service_owner_team"),
            })

        # Persist enrichment under a reserved key in tenable_tags
        if tag_enrichment:
            sf.tenable_tags = sf.tenable_tags or {}
            sf.tenable_tags["_enrichment"] = tag_enrichment
            enriched_count += 1

    session.flush()
    logger.info(
        "enrichment_applied",
        enriched=enriched_count,
        total=len(staged_findings),
        invalid_tags=invalid_tag_count,
        run_id=str(run_id),
    )
    return enriched_count


def _extract_tag_enrichment(sf: FindingStaging) -> dict:
    """Extract enrichment data from a staging finding's Tenable tags.

    Parses tag_names using the taxonomy parser. Returns a dict of the
    enrichment fields that could be populated from tags. Logs warnings
    for any tags that don't conform to the taxonomy.
    """
    if not sf.tenable_tags or not isinstance(sf.tenable_tags, dict):
        return {}

    tag_names = sf.tenable_tags.get("tag_names") or []
    if not tag_names:
        return {}

    parsed_dict, all_parsed = parse_tags(tag_names)

    enrichment: dict = {}
    for category, value in parsed_dict.items():
        field = CATEGORY_TO_FIELD.get(category)
        if field:
            enrichment[field] = value

    # If we parsed a Criticality tag, also populate the score
    if enrichment.get("asset_criticality"):
        enrichment["asset_criticality_score"] = CRITICALITY_SCORES.get(
            enrichment["asset_criticality"].upper(), 0.25
        )

    # Track how many tags failed validation (caller logs the total)
    invalid_count = sum(1 for p in all_parsed if not p.is_valid)
    if invalid_count > 0:
        enrichment["_invalid_count"] = invalid_count

    return enrichment
