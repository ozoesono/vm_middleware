"""Tests for account-split tag variants: fetch expansion + safe suffix-collapse.

Tenable caps a tag at 5 AWS accounts, so a logical tag is stored as
Tag-Name-1, Tag-Name-2, … The middleware expands --tag Tag-Name across those
variants when fetching, and collapses them back to the logical tag for
enrichment.
"""

import uuid

import pytest

from src.common.config import TenableConfig
from src.common.models import FindingStaging
from src.common.tag_parser import collapse_tag_variants
from src.ingestion.enrichment import _extract_tag_enrichment, apply_asset_tags_enrichment
from src.ingestion import tagged_assets
from src.ingestion.tagged_assets import TaggedAssetsError, fetch_tagged_assets_with_tags

from unittest.mock import patch


CRITICALITY_SCORES = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.50, "LOW": 0.25}


# ---- collapse_tag_variants ----


class TestCollapseTagVariants:
    LOGICAL = ["Portfolio-Data-Services"]

    def test_numbered_variant_collapses_to_logical(self):
        out = collapse_tag_variants(
            ["Portfolio-Data-Services-2", "Criticality-High"], self.LOGICAL
        )
        assert out == ["Portfolio-Data-Services", "Criticality-High"]

    def test_base_tag_unchanged(self):
        assert collapse_tag_variants(["Portfolio-Data-Services"], self.LOGICAL) == [
            "Portfolio-Data-Services"
        ]

    def test_legit_value_ending_in_number_is_untouched(self):
        # Region-eu-west-2 is a real value, NOT a split variant of any filter tag.
        assert collapse_tag_variants(["Region-eu-west-2"], self.LOGICAL) == [
            "Region-eu-west-2"
        ]

    def test_variants_dedupe_to_single_logical(self):
        out = collapse_tag_variants(
            ["Portfolio-Data-Services-1", "Portfolio-Data-Services-2"], self.LOGICAL
        )
        assert out == ["Portfolio-Data-Services"]

    def test_non_digit_suffix_not_collapsed(self):
        assert collapse_tag_variants(["Portfolio-Data-Services-x"], self.LOGICAL) == [
            "Portfolio-Data-Services-x"
        ]

    def test_no_logical_tags_is_noop(self):
        tags = ["Portfolio-Data-Services-2"]
        assert collapse_tag_variants(tags, None) == tags
        assert collapse_tag_variants(tags, []) == tags

    def test_collapses_when_the_filter_tag_itself_ends_in_a_number(self):
        # If the user explicitly declares 'Region-eu-west' a logical (split) tag,
        # then its -N variants SHOULD collapse — that is their stated intent.
        assert collapse_tag_variants(["Region-eu-west-2"], ["Region-eu-west"]) == [
            "Region-eu-west"
        ]


# ---- fetch expansion ----


def _fake_fetch(tag_to_assets, errors=None):
    """Build a stand-in for _fetch_assets_page keyed on the tag in the query."""
    errors = errors or {}

    def fake(client, config, text_query, offset, limit):
        tag = text_query.split('"')[1]
        if tag in errors:
            raise TaggedAssetsError(f"boom {tag}", status_code=errors[tag])
        assets = tag_to_assets.get(tag, [])
        if offset > 0:
            return {"pagination": {"total": len(assets)}, "data": []}
        data = [
            {"id": a["id"], "extra_properties": {"tag_names": a["tags"]}}
            for a in assets
        ]
        return {"pagination": {"total": len(assets)}, "data": data}

    return fake


def _fetch(tag_to_assets, tags, errors=None, max_variants=50):
    fake = _fake_fetch(tag_to_assets, errors)
    with patch.object(tagged_assets, "_fetch_assets_page", side_effect=fake):
        return fetch_tagged_assets_with_tags(
            TenableConfig(), "ak", "sk", tags, page_size=1000, max_variants=max_variants
        )


class TestFetchExpansion:
    def test_within_5_accounts_uses_unsuffixed_base(self):
        result = _fetch(
            {"Portfolio-DS": [{"id": "a1", "tags": ["Portfolio-DS", "Criticality-High"]}]},
            ["Portfolio-DS"],
        )
        assert set(result) == {"a1"}

    def test_split_tag_unions_numbered_variants_when_base_empty(self):
        result = _fetch(
            {
                # base 'Portfolio-DS' absent (>5 accounts, so only numbered exist)
                "Portfolio-DS-1": [{"id": "a1", "tags": ["Portfolio-DS-1"]}],
                "Portfolio-DS-2": [{"id": "a2", "tags": ["Portfolio-DS-2"]}],
            },
            ["Portfolio-DS"],
        )
        assert set(result) == {"a1", "a2"}

    def test_stops_at_first_empty_numbered_variant(self):
        result = _fetch(
            {
                "Portfolio-DS": [{"id": "a0", "tags": ["Portfolio-DS"]}],
                "Portfolio-DS-1": [{"id": "a1", "tags": ["Portfolio-DS-1"]}],
                # no -2 → sequence stops; a3 must NOT be reached even if present
                "Portfolio-DS-3": [{"id": "a3", "tags": ["Portfolio-DS-3"]}],
            },
            ["Portfolio-DS"],
        )
        assert set(result) == {"a0", "a1"}

    def test_client_error_on_variant_is_treated_as_absent(self):
        # base 400 (unknown tag), -1 has data, -2 400 → stop after -1
        result = _fetch(
            {"Portfolio-DS-1": [{"id": "a1", "tags": ["Portfolio-DS-1"]}]},
            ["Portfolio-DS"],
            errors={"Portfolio-DS": 400, "Portfolio-DS-2": 400},
        )
        assert set(result) == {"a1"}

    def test_server_error_propagates(self):
        with pytest.raises(TaggedAssetsError):
            _fetch(
                {"Portfolio-DS": [{"id": "a1", "tags": ["Portfolio-DS"]}]},
                ["Portfolio-DS"],
                errors={"Portfolio-DS": 500},
            )

    def test_variant_cap_bounds_the_probe(self):
        result = _fetch(
            {
                "Portfolio-DS-1": [{"id": "a1", "tags": ["Portfolio-DS-1"]}],
                "Portfolio-DS-2": [{"id": "a2", "tags": ["Portfolio-DS-2"]}],
                "Portfolio-DS-3": [{"id": "a3", "tags": ["Portfolio-DS-3"]}],
            },
            ["Portfolio-DS"],
            max_variants=2,
        )
        assert set(result) == {"a1", "a2"}  # -3 never probed

    def test_multiple_logical_tags_each_expand(self):
        result = _fetch(
            {
                "Portfolio-A": [{"id": "a1", "tags": ["Portfolio-A"]}],
                "Portfolio-B-1": [{"id": "b1", "tags": ["Portfolio-B-1"]}],
            },
            ["Portfolio-A", "Portfolio-B"],
        )
        assert set(result) == {"a1", "b1"}


# ---- enrichment collapse integration ----


def _make_staged(session, run_id, tag_names):
    sf = FindingStaging(
        id=uuid.uuid4(),
        run_id=run_id,
        tenable_finding_id="f1",
        tenable_asset_id="asset-A",
        title="t",
        severity="HIGH",
        tenable_state="ACTIVE",
        tenable_tags={"tag_names": tag_names, "tag_ids": []},
    )
    session.add(sf)
    session.flush()
    return sf


class TestEnrichmentCollapse:
    def test_extract_tag_enrichment_collapses_variant(self, db_session, run_id):
        sf = _make_staged(db_session, run_id, ["Portfolio-Data-Services-2", "Criticality-High"])
        enrich = _extract_tag_enrichment(sf, ["Portfolio-Data-Services"])
        assert enrich["portfolio"] == "Data-Services"

    def test_extract_without_logical_leaves_suffix(self, db_session, run_id):
        sf = _make_staged(db_session, run_id, ["Portfolio-Data-Services-2"])
        enrich = _extract_tag_enrichment(sf, None)
        assert enrich["portfolio"] == "Data-Services-2"

    def test_apply_asset_tags_enrichment_collapses_variant(self, db_session, run_id):
        # tenable_tags left unset (as in production, where findings/search returns
        # no tag_names); enrichment comes from the asset map, keyed by asset_id.
        sf = FindingStaging(
            id=uuid.uuid4(), run_id=run_id, tenable_finding_id="f1",
            tenable_asset_id="asset-A", title="t", severity="HIGH", tenable_state="ACTIVE",
        )
        db_session.add(sf)
        db_session.flush()
        asset_tags = {"asset-A": ["Portfolio-Data-Services-2", "Criticality-Medium"]}

        apply_asset_tags_enrichment(
            db_session, run_id, asset_tags, CRITICALITY_SCORES, 0.25,
            logical_tags=["Portfolio-Data-Services"],
        )

        sf = db_session.query(FindingStaging).filter_by(tenable_finding_id="f1").first()
        assert sf.tenable_tags["_enrichment"]["portfolio"] == "Data-Services"
