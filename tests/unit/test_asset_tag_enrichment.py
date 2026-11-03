"""Tests for the asset-tag-based enrichment flow."""

import uuid

import pytest

from src.common.models import EnrichmentMapping, FindingStaging
from src.ingestion.enrichment import apply_asset_tags_enrichment, apply_enrichment


CRITICALITY_SCORES = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.50, "LOW": 0.25}


def _make_staged(session, run_id, finding_id, asset_id, **kwargs):
    sf = FindingStaging(
        id=uuid.uuid4(),
        run_id=run_id,
        tenable_finding_id=finding_id,
        tenable_asset_id=asset_id,
        title="t",
        severity="HIGH",
        tenable_state="ACTIVE",
        **kwargs,
    )
    session.add(sf)
    session.flush()
    return sf


class TestApplyAssetTagsEnrichment:
    def test_critical_asset_score(self, db_session, run_id):
        _make_staged(db_session, run_id, "f1", "asset-A")
        asset_tags = {"asset-A": ["Portfolio-Payments", "Criticality-Critical"]}

        count = apply_asset_tags_enrichment(
            db_session, run_id, asset_tags, CRITICALITY_SCORES, 0.25
        )
        assert count == 1

        sf = db_session.query(FindingStaging).filter_by(tenable_finding_id="f1").first()
        enrichment = sf.tenable_tags["_enrichment"]
        assert enrichment["asset_criticality"] == "Critical"
        assert enrichment["asset_criticality_score"] == 1.0
        assert enrichment["portfolio"] == "Payments"

    def test_no_criticality_uses_default(self, db_session, run_id):
        _make_staged(db_session, run_id, "f1", "asset-A")
        asset_tags = {"asset-A": ["Portfolio-Payments"]}

        apply_asset_tags_enrichment(
            db_session, run_id, asset_tags, CRITICALITY_SCORES, 0.25
        )

        sf = db_session.query(FindingStaging).filter_by(tenable_finding_id="f1").first()
        enrichment = sf.tenable_tags["_enrichment"]
        assert enrichment["asset_criticality_score"] == 0.25
        assert enrichment.get("asset_criticality") is None

    def test_finding_without_matching_asset_skipped(self, db_session, run_id):
        _make_staged(db_session, run_id, "f1", "unknown-asset")
        asset_tags = {"asset-A": ["Criticality-Critical"]}

        count = apply_asset_tags_enrichment(
            db_session, run_id, asset_tags, CRITICALITY_SCORES, 0.25
        )
        assert count == 0

    def test_full_tag_set_enrichment(self, db_session, run_id):
        _make_staged(db_session, run_id, "f1", "asset-A")
        asset_tags = {
            "asset-A": [
                "Portfolio-Business-Growth",
                "Service-Payment-Api",
                "Environment-Prod",
                "Criticality-High",
                "Sensitivity-Confidential",
                "Owner-Team-Payments",
            ]
        }

        apply_asset_tags_enrichment(
            db_session, run_id, asset_tags, CRITICALITY_SCORES, 0.25
        )

        sf = db_session.query(FindingStaging).filter_by(tenable_finding_id="f1").first()
        e = sf.tenable_tags["_enrichment"]
        assert e["portfolio"] == "Business-Growth"
        assert e["service"] == "Payment-Api"
        assert e["environment"] == "Prod"
        assert e["asset_criticality"] == "High"
        assert e["asset_criticality_score"] == 0.75
        assert e["data_sensitivity"] == "Confidential"
        assert e["service_owner_team"] == "Team-Payments"

    def test_empty_map(self, db_session, run_id):
        _make_staged(db_session, run_id, "f1", "asset-A")
        count = apply_asset_tags_enrichment(
            db_session, run_id, {}, CRITICALITY_SCORES, 0.25
        )
        assert count == 0

    def test_none_map(self, db_session, run_id):
        _make_staged(db_session, run_id, "f1", "asset-A")
        count = apply_asset_tags_enrichment(
            db_session, run_id, None, CRITICALITY_SCORES, 0.25
        )
        assert count == 0


def test_asset_enrichment_survives_commit_with_existing_tag_json(db_session, run_id):
    sf = _make_staged(
        db_session, run_id, "f1", "asset-A",
        tenable_tags={"tag_names": [], "tag_ids": ["tag-1"]},
    )
    db_session.commit()
    apply_asset_tags_enrichment(
        db_session, run_id,
        {"asset-A": ["Portfolio-Business-Growth", "Owner-Team-Platform"]},
        CRITICALITY_SCORES, 0.25,
    )
    db_session.commit()
    db_session.expire_all()
    assert sf.tenable_tags["_enrichment"]["portfolio"] == "Business-Growth"
    assert sf.tenable_tags["_enrichment"]["service_owner_team"] == "Team-Platform"
    assert sf.tenable_tags["tag_ids"] == ["tag-1"]


def test_finding_tag_enrichment_survives_commit(db_session, run_id):
    sf = _make_staged(
        db_session, run_id, "f1", "asset-A",
        tenable_tags={"tag_names": ["Portfolio-Business-Growth"]},
    )
    db_session.commit()
    apply_enrichment(db_session, run_id)
    db_session.commit()
    db_session.expire_all()
    assert sf.tenable_tags["_enrichment"]["portfolio"] == "Business-Growth"


@pytest.mark.parametrize("csv_override", [False, True])
def test_partial_finding_tags_preserve_asset_enrichment(db_session, run_id, csv_override):
    sf = _make_staged(
        db_session, run_id, "f1", "asset-A",
        tenable_tags={"tag_names": ["Environment-Prod"]},
    )
    db_session.commit()
    apply_asset_tags_enrichment(
        db_session, run_id,
        {"asset-A": ["Portfolio-Business-Growth", "Owner-Team-Platform"]},
        CRITICALITY_SCORES, 0.25,
    )
    db_session.commit()
    if csv_override:
        db_session.add(EnrichmentMapping(
            asset_identifier="asset-A", identifier_type="asset_id",
            portfolio="CSV-Portfolio",
        ))
        db_session.commit()
    apply_enrichment(db_session, run_id)
    db_session.commit()
    db_session.expire_all()
    enrichment = sf.tenable_tags["_enrichment"]
    assert enrichment["portfolio"] == ("CSV-Portfolio" if csv_override else "Business-Growth")
    assert enrichment["service_owner_team"] == "Team-Platform"
    assert enrichment["environment"] == "Prod"
