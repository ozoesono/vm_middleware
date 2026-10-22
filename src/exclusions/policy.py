"""One exclusion policy for ingestion, prioritisation, reports and Jira delivery."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import and_, false, func, literal, not_, or_, select

from src.common.jira_config import UniqueKeyLoader

Fields = Literal[
    "asset_kind",
    "asset_type",
    "asset_name",
    "asset_id",
    "finding_id",
    "detection_id",
    "cve",
    "title",
    "source",
    "owner_team",
    "portfolio",
    "service",
    "environment",
]
COLUMNS = {
    "asset_type": "asset_type",
    "asset_name": "asset_name",
    "asset_id": "tenable_asset_id",
    "finding_id": "tenable_finding_id",
    "detection_id": "plugin_id",
    "title": "title",
    "source": "source",
    "owner_team": "service_owner_team",
    "portfolio": "portfolio",
    "service": "service",
    "environment": "environment",
}
ENRICHMENT_FIELDS = {"owner_team", "portfolio", "service", "environment"}
DEFAULT_REGISTRIES = [
    ".dkr.ecr.",
    "docker.io/",
    "ghcr.io/",
    "gcr.io/",
    "quay.io/",
    "registry.k8s.io/",
    "public.ecr.aws/",
    "mcr.microsoft.com/",
    "container-registry.oracle.com/",
]


def utcnow():
    return datetime.now(timezone.utc)


def aware(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Condition(Strict):
    field: Fields
    operator: Literal["equals", "in", "contains", "starts_with"] = "equals"
    value: str | list[str]
    case_sensitive: bool = True

    @model_validator(mode="after")
    def valid_value(self):
        if self.operator == "in":
            if not isinstance(self.value, list) or not 1 <= len(self.value) <= 100:
                raise ValueError("in requires a nonempty list of at most 100 values")
        elif not isinstance(self.value, str):
            raise ValueError("this operator requires one string")
        values = self.value if isinstance(self.value, list) else [self.value]
        if any(not v.strip() or len(v) > 1000 for v in values):
            raise ValueError("match values must be nonempty strings of at most 1000 characters")
        if self.field == "asset_kind" and any(
            (v if self.case_sensitive else v.lower()) not in ("container", "other") for v in values
        ):
            raise ValueError("asset_kind must be container or other")
        if self.operator in ("contains", "starts_with") and self.field not in (
            "asset_name",
            "title",
        ):
            raise ValueError("substring operators are only supported for asset_name and title")
        return self

    def matches(self, values: list[str]) -> bool:
        wanted = self.value if isinstance(self.value, list) else [self.value]
        if not self.case_sensitive:
            values, wanted = ([v.lower() for v in values], [v.lower() for v in wanted])
        if self.operator in ("equals", "in"):
            return any(v in wanted for v in values)
        if self.operator == "contains":
            return any(wanted[0] in v for v in values)
        return any(v.startswith(wanted[0]) for v in values)

    def sql(self, column, dialect="postgresql"):
        wanted = self.value if isinstance(self.value, list) else [self.value]
        if not self.case_sensitive:
            column, wanted = func.lower(column), [v.lower() for v in wanted]
        if self.operator in ("equals", "in"):
            expression = column.in_(wanted)
        elif self.operator == "contains":
            position = (
                func.instr(column, wanted[0])
                if dialect == "sqlite"
                else func.strpos(column, wanted[0])
            )
            expression = position > 0
        else:
            expression = func.substr(column, 1, len(wanted[0])) == wanted[0]
        return func.coalesce(expression, false())


class Match(Strict):
    all: list[Condition] = Field(default_factory=list, max_length=20)
    any: list[Condition] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def nonempty(self):
        if not self.all and not self.any:
            raise ValueError("a rule must have at least one match condition")
        return self


class Rule(Strict):
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]*$", max_length=100)
    enabled: bool = True
    reason: str = Field(min_length=1, max_length=2000)
    owner: str = Field(min_length=1, max_length=255)
    expires_at: datetime | None = None
    match: Match

    @field_validator("owner", "reason")
    @classmethod
    def meaningful_metadata(cls, value):
        if not value.strip():
            raise ValueError("owner and reason cannot be blank")
        return value

    @field_validator("expires_at", mode="before")
    @classmethod
    def explicit_timestamp(cls, value):
        if value is not None and not isinstance(value, (str, datetime)):
            raise ValueError("expires_at must be an ISO timestamp with a timezone")
        if isinstance(value, str) and "T" not in value:
            raise ValueError("expires_at must include date, time and timezone")
        return value

    @field_validator("expires_at")
    @classmethod
    def expiry_has_timezone(cls, value):
        if value and value.utcoffset() is None:
            raise ValueError("expires_at must include a timezone, for example 2027-01-08T00:00:00Z")
        return aware(value) if value else None

    def active(self, now: datetime) -> bool:
        return self.enabled and (self.expires_at is None or aware(now) < self.expires_at)


class Classification(Strict):
    container_asset_types: list[str] = Field(
        default_factory=lambda: [
            "containerImage",
            "container",
            "container_image",
            "container-image",
        ]
    )
    container_name_patterns: list[str] = Field(default_factory=lambda: list(DEFAULT_REGISTRIES))

    @field_validator("container_asset_types", "container_name_patterns")
    @classmethod
    def nonempty_values(cls, values):
        if any(not value.strip() for value in values):
            raise ValueError("classification values cannot be empty")
        return values

    def container(self, asset_type, asset_name):
        kind = (asset_type or "").strip().lower()
        if kind in {v.strip().lower() for v in self.container_asset_types}:
            return True
        # A known host/device type takes precedence over an image-like name.
        return kind in ("", "unknown") and any(
            p.lower() in (asset_name or "").lower() for p in self.container_name_patterns
        )

    def container_sql(self, model):
        kind = func.lower(func.trim(func.coalesce(model.asset_type, "")))
        return or_(
            kind.in_([v.strip().lower() for v in self.container_asset_types]),
            and_(
                kind.in_(["", "unknown"]),
                or_(
                    false(),
                    *[
                        func.lower(func.coalesce(model.asset_name, "")).contains(
                            p.lower(), autoescape=True
                        )
                        for p in self.container_name_patterns
                    ],
                ),
            ),
        )


class ExclusionPolicy(Strict):
    enabled: bool = True
    refresh_batch_size: int = Field(default=1000, ge=1, le=10000)
    classification: Classification = Field(default_factory=Classification)
    rules: list[Rule] = Field(default_factory=list, max_length=500)

    @model_validator(mode="after")
    def unique_ids(self):
        ids = [rule.id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("exclusion rule IDs must be unique across all files")
        return self

    @property
    def fingerprint(self):
        return hashlib.sha256(
            json.dumps(self.model_dump(mode="json"), sort_keys=True).encode()
        ).hexdigest()

    def run_fingerprint(self, now=None):
        now = now or utcnow()
        active = [r.id for r in self.rules if self.enabled and r.active(now)]
        return hashlib.sha256((self.fingerprint + json.dumps(active)).encode()).hexdigest()

    def values(self, finding, field):
        if field == "asset_kind":
            return [
                "container"
                if self.classification.container(finding.asset_type, finding.asset_name)
                else "other"
            ]
        if field == "cve":
            return list(finding.cve_ids or ([finding.cve_id] if finding.cve_id else []))
        value = getattr(finding, COLUMNS[field], None)
        return [str(value)] if value is not None else []

    def matching_rules(self, finding, now=None, *, raw_only=False):
        now = now or utcnow()
        if not self.enabled:
            return []
        matches = []
        for rule in self.rules:
            if not rule.active(now):
                continue
            conditions = rule.match.all + rule.match.any
            if raw_only and any(c.field in ENRICHMENT_FIELDS for c in conditions):
                continue  # Scoped rules need tag/CSV enrichment.

            def test(condition):
                return condition.matches(self.values(finding, condition.field))

            if all(test(c) for c in rule.match.all) and (
                not rule.match.any or any(test(c) for c in rule.match.any)
            ):
                matches.append(rule)
        return matches

    def _condition_sql(self, condition, model, dialect):
        if condition.field == "asset_kind":
            from sqlalchemy import case

            return condition.sql(
                case((self.classification.container_sql(model), "container"), else_="other"),
                dialect,
            )
        if condition.field != "cve":
            return condition.sql(getattr(model, COLUMNS[condition.field]), dialect)
        # Older records may only have cve_id.
        if dialect == "postgresql":
            elements = (
                func.json_array_elements_text(model.cve_ids).table_valued("value").render_derived()
            )
        elif dialect == "sqlite":
            elements = func.json_each(model.cve_ids).table_valued("value")
        else:
            raise ValueError("CVE exclusions require PostgreSQL or SQLite")
        array_match = (
            select(literal(1))
            .select_from(elements)
            .where(condition.sql(elements.c.value, dialect))
            .correlate(model)
            .exists()
        )
        return or_(condition.sql(model.cve_id, dialect), array_match)

    def sql(self, model, dialect="postgresql", now=None):
        now = now or utcnow()
        if not self.enabled:
            return false()
        expressions = []
        for rule in self.rules:
            if not rule.active(now):
                continue
            parts = [self._condition_sql(c, model, dialect) for c in rule.match.all]
            if rule.match.any:
                parts.append(or_(*[self._condition_sql(c, model, dialect) for c in rule.match.any]))
            expressions.append(and_(*parts))
        return or_(false(), *expressions)

    def active_sql(self, model, dialect="postgresql", now=None):
        return and_(not_(self.sql(model, dialect, now)), model.processing_status != "PAUSED")


def load_policy(config_dir, legacy_patterns=(), container_patterns=None):
    root = Path(config_dir)
    path = root / "exclusions.yaml"
    data = yaml.load(path.read_text(), Loader=UniqueKeyLoader) if path.exists() else {}
    if not isinstance(data, dict) or set(data) - {"exclusions"}:
        raise ValueError("exclusions.yaml must contain only an exclusions mapping")
    if not isinstance(data.get("exclusions", {}), dict):
        raise ValueError("exclusions must be a mapping")
    settings = dict(data.get("exclusions", {}))
    declared_rules = settings.pop("rules", [])
    if not isinstance(declared_rules, list):
        raise ValueError("rules must be a list")
    rules = list(declared_rules)
    for path in sorted((root / "exclusions.d").glob("*")):
        if path.suffix not in (".yaml", ".yml"):
            continue
        document = yaml.load(path.read_text(), Loader=UniqueKeyLoader)
        if (
            not isinstance(document, dict)
            or set(document) != {"rules"}
            or not isinstance(document["rules"], list)
        ):
            raise ValueError(f"{path.name} must contain a rules list")
        rules.extend(document["rules"])
    if not isinstance(settings.get("classification", {}), dict):
        raise ValueError("classification must be a mapping")
    classification = dict(settings.get("classification", {}))
    if container_patterns is not None:
        classification.setdefault("container_name_patterns", container_patterns)
    settings["classification"] = classification
    for pattern in sorted(set(legacy_patterns)):
        rules.append(
            {
                "id": "legacy-asset-" + hashlib.sha256(pattern.encode()).hexdigest()[:12],
                "owner": "legacy-tenable-config",
                "reason": f"Legacy asset name exclusion: {pattern}",
                "match": {
                    "all": [
                        {
                            "field": "asset_name",
                            "operator": "contains",
                            "value": pattern,
                            "case_sensitive": False,
                        }
                    ]
                },
            }
        )
    return ExclusionPolicy.model_validate({**settings, "rules": rules})
