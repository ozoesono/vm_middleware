"""Configuration loader — reads YAML files and merges with environment variable overrides."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


# ---------------------------------------------------------------------------
# Pydantic settings models
# ---------------------------------------------------------------------------


class CustomScoringConfig(BaseModel):
    vpr_weight: float = 0.50
    acs_weight: float = 0.50
    thresholds: dict[str, float] = Field(
        default_factory=lambda: {"critical": 0.75, "high": 0.50, "medium": 0.30}
    )


class LuminScoringConfig(BaseModel):
    ces_thresholds: dict[str, int] = Field(
        default_factory=lambda: {"critical": 800, "high": 600, "medium": 400}
    )


class ScoringConfig(BaseModel):
    active_model: str = "custom"  # "custom" | "lumin_ces"
    custom: CustomScoringConfig = Field(default_factory=CustomScoringConfig)
    lumin: LuminScoringConfig = Field(default_factory=LuminScoringConfig)


class SLAConfig(BaseModel):
    critical: int = 10
    high: int = 30
    medium: int = 45
    low: int = 90
    use_business_days: bool = False
    approaching_warning_days: int = 5

    def days_for_rating(self, risk_rating: str) -> int:
        """Return SLA days for a given risk rating."""
        mapping = {
            "CRITICAL": self.critical,
            "HIGH": self.high,
            "MEDIUM": self.medium,
            "LOW": self.low,
        }
        return mapping.get(risk_rating.upper(), self.low)


class RolloutPhaseConfig(BaseModel):
    severity_filter: list[str] = Field(default_factory=lambda: ["CRITICAL", "HIGH"])
    team_filter: list[str] = Field(default_factory=list)
    max_tickets_per_run: int = 50


class RolloutConfig(BaseModel):
    phase: str = "pilot"
    phases: dict[str, RolloutPhaseConfig] = Field(default_factory=dict)

    @property
    def active_phase(self) -> RolloutPhaseConfig:
        return self.phases.get(self.phase, RolloutPhaseConfig())


class ScheduleConfig(BaseModel):
    cron: str = "0 6 * * *"
    timezone: str = "UTC"
    enabled: bool = True


class TenableConfig(BaseModel):
    base_url: str = "https://cloud.tenable.com"
    # Synchronous search endpoint
    findings_endpoint: str = "/api/v1/t1/inventory/findings/search"
    # Async export endpoint
    export_endpoint: str = "/api/v1/t1/inventory/export/findings"
    # Which mode to use: "search" (synchronous paginated) or "export" (async bulk)
    retrieval_mode: str = "search"  # "search" | "export"
    page_size: int = 10000
    extra_properties: str = (
        "finding_vpr_score,finding_cvss3_base_score,finding_cves,finding_solution,"
        "finding_detection_id,asset_name,asset_class,sensor_type,"
        "first_observed_at,last_observed_at,last_updated,tag_names,tag_ids,"
        "ipv4_addresses,product"
    )
    severity_filter: list[str] | None = None
    stale_threshold_days: int = 7
    request_timeout_seconds: int = 120
    max_retries: int = 3
    export_poll_interval: int = 10  # seconds between status polls
    export_max_wait: int = 600  # max seconds to wait for export


class JiraConfig(BaseModel):
    base_url: str = "https://org.atlassian.net"
    default_project: str = "VULN"
    issue_type: str = "Task"
    labels: list[str] = Field(default_factory=lambda: ["vm-middleware"])
    priority_mapping: dict[str, str] = Field(
        default_factory=lambda: {
            "CRITICAL": "Highest",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
        }
    )
    portfolio_project_mapping: dict[str, str] = Field(default_factory=dict)
    close_transition: str = "Done"
    reopen_transition: str = "To Do"


class AppSettings(BaseSettings):
    """Top-level application settings, sourced from env vars."""

    database_url: str = "postgresql://vm_user:vm_local_pass@localhost:5432/vm_middleware"
    tenable_access_key: str = ""
    tenable_secret_key: str = ""
    jira_api_token: str = ""
    jira_user_email: str = ""
    config_dir: str = "config"
    log_level: str = "INFO"

    model_config = {"env_prefix": "", "case_sensitive": False}


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------


def _load_yaml(config_dir: str, filename: str) -> dict[str, Any]:
    """Load a YAML config file, returning empty dict if not found."""
    path = Path(config_dir) / filename
    if not path.exists():
        return {}
    with open(path) as f:
        data = yaml.safe_load(f)
    return data if data else {}


# ---------------------------------------------------------------------------
# Assembled configuration
# ---------------------------------------------------------------------------


class AppConfig:
    """Assembled application configuration from env vars + YAML files."""

    def __init__(self, settings: AppSettings | None = None):
        self.settings = settings or AppSettings()
        config_dir = self.settings.config_dir

        scoring_data = _load_yaml(config_dir, "scoring.yaml").get("scoring", {})
        self.scoring = ScoringConfig(**scoring_data)

        sla_data = _load_yaml(config_dir, "sla_policy.yaml").get("sla", {})
        self.sla = SLAConfig(**sla_data)

        rollout_data = _load_yaml(config_dir, "rollout.yaml").get("rollout", {})
        self.rollout = RolloutConfig(**rollout_data)

        schedule_data = _load_yaml(config_dir, "schedule.yaml").get("schedule", {})
        self.schedule = ScheduleConfig(**schedule_data)

        tenable_data = _load_yaml(config_dir, "tenable.yaml").get("tenable", {})
        self.tenable = TenableConfig(**tenable_data)

        jira_data = _load_yaml(config_dir, "jira.yaml").get("jira", {})
        self.jira = JiraConfig(**jira_data)


@lru_cache()
def get_config() -> AppConfig:
    """Return a cached singleton AppConfig instance."""
    return AppConfig()
