"""Tests for the asset-tag-based enrichment flow."""

import uuid

import pytest

from src.common.models import FindingStaging
from src.ingestion.enrichment import apply_asset_tags_enrichment


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
        # asset_criticality label should be absent
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
