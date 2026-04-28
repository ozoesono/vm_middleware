"""Tests for asset_id-based filtering and the advanced query builder."""

import pytest

from src.ingestion.tagged_assets import _build_advanced_query
from src.ingestion.tenable_ingestion import filter_by_asset_ids


class TestBuildAdvancedQuery:
    def test_single_tag(self):
        q = _build_advanced_query(["Portfolio-Business-Growth"])
        assert q == 'Assets HAS tag_names = "Portfolio-Business-Growth"'

    def test_multiple_tags_or(self):
        q = _build_advanced_query(["Portfolio-A", "Portfolio-B"])
        assert q == (
            '(Assets HAS tag_names = "Portfolio-A") OR '
            '(Assets HAS tag_names = "Portfolio-B")'
        )

    def test_three_tags(self):
        q = _build_advanced_query(["A", "B", "C"])
        assert "OR" in q
        assert q.count("Assets HAS") == 3


class TestFilterByAssetIds:
    @staticmethod
    def _make(asset_id):
        return {"id": "f1", "asset_id": asset_id, "name": "x", "severity": "HIGH", "state": "ACTIVE"}

    def test_none_set_keeps_all(self):
        findings = [self._make("a1"), self._make("a2")]
        assert len(filter_by_asset_ids(findings, None)) == 2

    def test_empty_set_drops_all(self):
        """Empty set means: 'we looked, no assets match' — keep nothing."""
        findings = [self._make("a1"), self._make("a2")]
        assert filter_by_asset_ids(findings, set()) == []

    def test_keeps_only_matching(self):
        findings = [self._make("a1"), self._make("a2"), self._make("a3")]
        result = filter_by_asset_ids(findings, {"a1", "a3"})
        ids = [f["asset_id"] for f in result]
        assert ids == ["a1", "a3"]

    def test_finding_without_asset_id_dropped(self):
        findings = [{"id": "f1", "name": "x", "severity": "LOW", "state": "ACTIVE"}]
        # No asset_id field on the finding — dropped
        assert filter_by_asset_ids(findings, {"a1"}) == []
