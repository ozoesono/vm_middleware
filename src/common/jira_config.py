"""Validated Jira connections and team rules. YAML contains secret names, never values."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

RiskRating = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
MatchField = Literal["service_owner_team", "portfolio", "service", "environment"]


def normalized(value: str | None) -> str:
    return (value or "").strip().casefold()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def json_fields(value):
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("Jira field values must be JSON; quote YAML dates and avoid NaN") from exc
    return value


class JiraAuth(StrictModel):
    type: Literal["basic", "bearer"] = "basic"
    email_env: str | None = None
    token_env: str

    @field_validator("email_env", "token_env")
    @classmethod
    def env_name(cls, value):
        if value is not None and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
            raise ValueError("credentials must reference environment variable names")
        return value

    @model_validator(mode="after")
    def basic_needs_email(self):
        if self.type == "basic" and not self.email_env:
            raise ValueError("basic auth requires email_env")
        return self


class JiraInstance(StrictModel):
    deployment: Literal["cloud", "data_center"] = "cloud"
    base_url: str
    # For scoped Cloud tokens, base_url can be the api.atlassian.com/ex/jira/{cloudId}
    # gateway; browse links still use the site URL.
    browse_url: str | None = None
    auth: JiraAuth
    timeout_seconds: int = Field(default=30, ge=1, le=120)

    @field_validator("base_url", "browse_url")
    @classmethod
    def validate_url(cls, value):
        if value is None:
            return value
        parts = urlsplit(value)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username
            or parts.password
            or parts.query
            or parts.fragment
        ):
            raise ValueError("Jira URLs must be HTTPS without credentials, query or fragment")
        return value.rstrip("/")

    @model_validator(mode="after")
    def gateway_needs_browse_url(self):
        if urlsplit(self.base_url).hostname == "api.atlassian.com" and not self.browse_url:
            raise ValueError(
                "Atlassian API gateway connections require browse_url for ticket links"
            )
        return self


class JiraTransitions(StrictModel):
    close: str = "Done"
    reopen: str = "To Do"
    # Required transition-screen fields, such as resolution, differ by workflow.
    close_fields: dict[str, Any] = Field(default_factory=dict)
    reopen_fields: dict[str, Any] = Field(default_factory=dict)

    _json_fields = field_validator("close_fields", "reopen_fields")(json_fields)


class JiraDestination(StrictModel):
    instance: str
    project: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]*$")
    issue_type: str = Field(default="Task", min_length=1)
    labels: list[str] = Field(default_factory=lambda: ["vm-middleware"])
    priority_mapping: dict[RiskRating, str] = Field(
        default_factory=lambda: {
            "CRITICAL": "Highest",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
        }
    )
    # Cloud uses accountId; Data Center uses name. These are literal API values.
    assignee: dict[str, str] | None = None
    components: list[str] = Field(default_factory=list)
    custom_fields: dict[str, Any] = Field(default_factory=dict)
    transitions: JiraTransitions = Field(default_factory=JiraTransitions)

    @field_validator("custom_fields")
    @classmethod
    def custom_field_ids(cls, value):
        if any(not re.fullmatch(r"customfield_[0-9]+", key) for key in value):
            raise ValueError("custom_fields keys must be Jira customfield_<number> IDs")
        return json_fields(value)

    @field_validator("labels")
    @classmethod
    def labels_without_spaces(cls, value):
        if any(not label or any(c.isspace() for c in label) for label in value):
            raise ValueError("Jira labels must be nonempty and contain no whitespace")
        return value


class TeamTicketing(StrictModel):
    risk_ratings: list[RiskRating] = Field(default_factory=lambda: ["CRITICAL", "HIGH"])
    max_creates_per_run: int = Field(default=20, ge=0)


class JiraTeam(StrictModel):
    team_id: str = Field(pattern=r"^[a-z][a-z0-9_-]*$", max_length=100)
    enabled: bool = False
    match: dict[MatchField, list[str]]
    jira: JiraDestination
    ticketing: TeamTicketing = Field(default_factory=TeamTicketing)

    @field_validator("match")
    @classmethod
    def nonempty_match(cls, value):
        if not value or any(
            not values or any(not normalized(v) for v in values) for values in value.values()
        ):
            raise ValueError("team rules require nonempty selectors and values")
        return value


class JiraConfig(StrictModel):
    enabled: bool = False
    instances: dict[str, JiraInstance] = Field(default_factory=dict)
    teams: dict[str, JiraTeam] = Field(default_factory=dict)
    batch_size: int = Field(default=100, ge=1, le=1000)
    refresh_seconds: int = Field(default=3600, ge=60)
    retry_base_seconds: int = Field(default=60, ge=1)
    max_attempts: int = Field(default=5, ge=1)

    @model_validator(mode="after")
    def validate_routes(self):
        if any(not re.fullmatch(r"[a-z][a-z0-9_-]{0,99}", key) for key in self.instances):
            raise ValueError("instance IDs must be lowercase slugs up to 100 characters")
        teams = list(self.teams.values())
        for key, team in self.teams.items():
            if key != team.team_id:
                raise ValueError(f"team key {key!r} does not match team_id")
            if team.jira.instance not in self.instances:
                raise ValueError(f"team {key!r} references unknown instance {team.jira.instance!r}")
        for i, left in enumerate(teams):
            for right in teams[i + 1 :]:
                # AND across selectors, OR within each selector. Reject overlapping
                # predicates rather than silently depending on file order.
                shared = left.match.keys() & right.match.keys()
                disjoint = any(
                    not (
                        {normalized(v) for v in left.match[k]}
                        & {normalized(v) for v in right.match[k]}
                    )
                    for k in shared
                )
                if not disjoint:
                    raise ValueError(f"overlapping team rules: {left.team_id}, {right.team_id}")
        return self


class UniqueKeyLoader(yaml.SafeLoader):
    """Reject duplicate keys instead of silently discarding an earlier rule."""


def _unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def load_jira_config(config_dir: str) -> JiraConfig:
    root = Path(config_dir)
    path = root / "jira.yaml"
    data = yaml.load(path.read_text(), Loader=UniqueKeyLoader) if path.exists() else {}
    if not isinstance(data, dict) or set(data) - {"jira"}:
        raise ValueError("jira.yaml must contain only a jira mapping")
    jira = dict(data.get("jira") or {})
    teams = dict(jira.get("teams") or {})
    for path in sorted((root / "teams").glob("*")):
        if path.suffix not in (".yaml", ".yml"):
            continue
        team = JiraTeam.model_validate(yaml.load(path.read_text(), Loader=UniqueKeyLoader))
        if team.team_id in teams:
            raise ValueError(f"duplicate team_id: {team.team_id}")
        teams[team.team_id] = team
    jira["teams"] = teams
    return JiraConfig.model_validate(jira)
