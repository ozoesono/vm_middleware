"""Tag parser for the Tenable taxonomy: <Category>-<Value> in PascalCase.

See tag_taxonomy.txt at the repo root for the full convention.

Parsing rule: split on the FIRST hyphen.
  - Everything before the first hyphen = category
  - Everything after = value

A tag is VALID if:
  - It contains at least one hyphen
  - The category prefix matches one of the approved categories
"""

from __future__ import annotations

from dataclasses import dataclass

from src.common.logging import get_logger
from src.common.ownership import unique_names

logger = get_logger("tag_parser")

APPROVED_CATEGORIES = {
    "Portfolio",
    "Service",
    "Environment",
    "Sensitivity",
    "Criticality",
    "Owner",
    "Region",
    "Compliance",
    "Application",
}


@dataclass
class ParsedTag:
    """The result of parsing a Tenable tag string."""

    raw: str
    category: str | None
    value: str | None
    is_valid: bool
    warning: str | None


def parse_tag(raw: str) -> ParsedTag:
    """Parse a single tag string into a ParsedTag.

    Examples:
        parse_tag("Environment-Prod")
            → ParsedTag(category="Environment", value="Prod", is_valid=True)
        parse_tag("Service-Payment-Api")
            → ParsedTag(category="Service", value="Payment-Api", is_valid=True)
        parse_tag("Prod")
            → ParsedTag(category=None, value=None, is_valid=False,
                        warning="No hyphen — cannot derive category")
    """
    if not raw or not isinstance(raw, str):
        return ParsedTag(
            raw=str(raw),
            category=None,
            value=None,
            is_valid=False,
            warning="Tag is empty or not a string",
        )

    raw_stripped = raw.strip()

    if "-" not in raw_stripped:
        return ParsedTag(
            raw=raw_stripped,
            category=None,
            value=None,
            is_valid=False,
            warning="No hyphen — cannot derive category",
        )

    category, _, value = raw_stripped.partition("-")
    category = category.strip()
    value = value.strip()

    if not category or not value:
        return ParsedTag(
            raw=raw_stripped,
            category=category or None,
            value=value or None,
            is_valid=False,
            warning="Empty category or value after split",
        )

    if category not in APPROVED_CATEGORIES:
        return ParsedTag(
            raw=raw_stripped,
            category=category,
            value=value,
            is_valid=False,
            warning=f"Unknown category '{category}' (not in approved list)",
        )

    return ParsedTag(
        raw=raw_stripped,
        category=category,
        value=value,
        is_valid=True,
        warning=None,
    )


def parse_tags(tag_names: list[str]) -> tuple[dict[str, str | list[str]], list[ParsedTag]]:
    """Parse a list of tag strings into a category→value dict and warnings.

    Service values are retained as an ordered list. Other categories keep the
    last value and log a warning on collisions.

    Returns:
        (parsed_dict, all_parsed_tags)

        parsed_dict: {"Portfolio": "Payments", "Environment": "Prod", ...}
                     — only includes valid tags.

        all_parsed_tags: List of ParsedTag objects including invalid ones,
                         so callers can log/report all warnings.
    """
    parsed_dict: dict[str, str | list[str]] = {}
    all_parsed: list[ParsedTag] = []

    if not tag_names:
        return parsed_dict, all_parsed

    for raw in tag_names:
        parsed = parse_tag(raw)
        all_parsed.append(parsed)

        if parsed.is_valid:
            if parsed.category == "Service":
                parsed_dict.setdefault(parsed.category, []).append(parsed.value)
                continue
            if parsed.category in parsed_dict:
                logger.warning(
                    "tag_category_collision",
                    category=parsed.category,
                    previous_value=parsed_dict[parsed.category],
                    new_value=parsed.value,
                    raw=parsed.raw,
                )
            parsed_dict[parsed.category] = parsed.value
        else:
            logger.warning(
                "tag_invalid_format",
                tag=parsed.raw,
                warning=parsed.warning,
            )

    if "Service" in parsed_dict:
        parsed_dict["Service"] = unique_names(parsed_dict["Service"])
    return parsed_dict, all_parsed


CATEGORY_TO_FIELD = {
    "Portfolio": "portfolio",
    "Service": "service",
    "Environment": "environment",
    "Sensitivity": "data_sensitivity",
    "Criticality": "asset_criticality",
    "Owner": "service_owner_team",
}
