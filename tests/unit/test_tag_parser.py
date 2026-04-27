"""Tests for the Tenable tag taxonomy parser."""

import pytest

from src.common.tag_parser import (
    APPROVED_CATEGORIES,
    CATEGORY_TO_FIELD,
    parse_tag,
    parse_tags,
)


class TestParseSingleTag:
    """Tests for parse_tag()."""

    def test_simple_valid_tag(self):
        result = parse_tag("Environment-Prod")
        assert result.is_valid
        assert result.category == "Environment"
        assert result.value == "Prod"
        assert result.warning is None

    def test_multi_word_value(self):
        result = parse_tag("Service-Payment-Api")
        assert result.is_valid
        assert result.category == "Service"
        assert result.value == "Payment-Api"

    def test_long_multi_word_value(self):
        result = parse_tag("Owner-Team-Customer-Experience")
        assert result.is_valid
        assert result.category == "Owner"
        assert result.value == "Team-Customer-Experience"

    def test_no_hyphen_invalid(self):
        result = parse_tag("Prod")
        assert not result.is_valid
        assert result.category is None
        assert result.value is None
        assert "No hyphen" in result.warning

    def test_unknown_category_invalid(self):
        result = parse_tag("Foo-Bar")
        assert not result.is_valid
        assert result.category == "Foo"
        assert result.value == "Bar"
        assert "Unknown category" in result.warning

    def test_empty_string_invalid(self):
        result = parse_tag("")
        assert not result.is_valid
        assert "empty" in result.warning.lower()

    def test_none_invalid(self):
        result = parse_tag(None)
        assert not result.is_valid

    def test_whitespace_stripped(self):
        result = parse_tag("  Portfolio-Payments  ")
        assert result.is_valid
        assert result.category == "Portfolio"
        assert result.value == "Payments"

    def test_empty_value_invalid(self):
        result = parse_tag("Portfolio-")
        assert not result.is_valid

    def test_empty_category_invalid(self):
        result = parse_tag("-Payments")
        assert not result.is_valid

    def test_all_approved_categories(self):
        """Every approved category should parse as valid."""
        for cat in APPROVED_CATEGORIES:
            result = parse_tag(f"{cat}-TestValue")
            assert result.is_valid, f"{cat} should be valid"
            assert result.category == cat


class TestParseTagsList:
    """Tests for parse_tags()."""

    def test_parse_multiple_tags(self):
        tags = ["Portfolio-Payments", "Environment-Prod", "Criticality-Critical"]
        parsed_dict, all_parsed = parse_tags(tags)
        assert parsed_dict == {
            "Portfolio": "Payments",
            "Environment": "Prod",
            "Criticality": "Critical",
        }
        assert len(all_parsed) == 3
        assert all(p.is_valid for p in all_parsed)

    def test_parse_mixed_valid_invalid(self):
        tags = ["Portfolio-Payments", "RandomTag", "Environment-Prod"]
        parsed_dict, all_parsed = parse_tags(tags)
        assert parsed_dict == {
            "Portfolio": "Payments",
            "Environment": "Prod",
        }
        assert len(all_parsed) == 3
        invalid = [p for p in all_parsed if not p.is_valid]
        assert len(invalid) == 1
        assert invalid[0].raw == "RandomTag"

    def test_empty_list(self):
        parsed_dict, all_parsed = parse_tags([])
        assert parsed_dict == {}
        assert all_parsed == []

    def test_none_input(self):
        parsed_dict, all_parsed = parse_tags(None)
        assert parsed_dict == {}
        assert all_parsed == []

    def test_category_collision_last_wins(self):
        """If two tags have the same category, the last one wins."""
        tags = ["Environment-Prod", "Environment-Staging"]
        parsed_dict, all_parsed = parse_tags(tags)
        assert parsed_dict["Environment"] == "Staging"


class TestCategoryFieldMapping:
    """Tests for the CATEGORY_TO_FIELD lookup used by enrichment."""

    def test_all_mapped_categories_are_approved(self):
        """Every category in the field map must be approved."""
        for cat in CATEGORY_TO_FIELD:
            assert cat in APPROVED_CATEGORIES

    def test_critical_field_mappings(self):
        assert CATEGORY_TO_FIELD["Portfolio"] == "portfolio"
        assert CATEGORY_TO_FIELD["Service"] == "service"
        assert CATEGORY_TO_FIELD["Environment"] == "environment"
        assert CATEGORY_TO_FIELD["Sensitivity"] == "data_sensitivity"
        assert CATEGORY_TO_FIELD["Criticality"] == "asset_criticality"
        assert CATEGORY_TO_FIELD["Owner"] == "service_owner_team"
