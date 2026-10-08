#!/usr/bin/env python3
"""Validate team configuration, preview routing and run Jira delivery."""

import argparse
import json
import sys
import uuid
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.common.config import AppConfig, AppSettings
from src.common.db import get_engine, get_session, init_db
from src.common.models import Finding
from src.integration.jira_client import JiraClient, JiraError
from src.integration.jira_sync import adopt_issue, retry_finding, sync_jira
from src.integration.payloads import issue_fields
from src.integration.preview import preview_routes
from src.integration.routing import validate_rollout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", default=None)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate", help="validate YAML locally; no database or Jira access")
    preview = commands.add_parser(
        "preview", help="read findings and show proposed routing/payloads"
    )
    preview.add_argument("--team")
    preview.add_argument("--limit", type=int, default=100)
    check = commands.add_parser(
        "check", help="read Jira metadata and validate one team's create fields"
    )
    check.add_argument("--team", required=True)
    commands.add_parser("sync", help="deliver one batch; requires jira.enabled: true")
    retry = commands.add_parser("retry", help="retry a failed finding")
    retry.add_argument("--finding-id", type=uuid.UUID, required=True)
    retry.add_argument(
        "--clear-uncertain-create",
        action="store_true",
        help="allow a new CREATE only after manually confirming no Jira ticket exists",
    )
    adopt = commands.add_parser("adopt", help="bind an explicitly selected existing ticket")
    adopt.add_argument("--finding-id", type=uuid.UUID, required=True)
    adopt.add_argument("--team", required=True)
    adopt.add_argument("--issue-key", required=True)
    args = parser.parse_args()
    try:
        settings = AppSettings(**({"config_dir": args.config_dir} if args.config_dir else {}))
        config = AppConfig(settings)
        validate_rollout(config)
        if args.command == "validate":
            result = {
                "valid": True,
                "enabled": config.jira.enabled,
                "instances": sorted(config.jira.instances),
                "teams": sorted(config.jira.teams),
            }
        elif args.command == "check":
            team = config.jira.teams[args.team]
            instance = config.jira.instances[team.jira.instance]
            finding = Finding(
                id=uuid.uuid4(),
                tenable_finding_id="validation-only",
                title="Configuration validation",
                severity="HIGH",
                risk_rating="HIGH",
                risk_score=0.5,
                sla_due_date=date.today(),
                sla_status="WITHIN_SLA",
                state="OPEN",
                tenable_state="ACTIVE",
                recurrence_count=0,
            )
            with JiraClient(instance) as client:
                for rating in team.ticketing.risk_ratings:
                    finding.risk_rating = rating
                    client.validate_fields(team.jira, issue_fields(finding, team.jira, instance))
            result = {
                "valid": True,
                "team": team.team_id,
                "project": team.jira.project,
                "checked": "create metadata; transitions are checked against each live issue",
            }
        elif args.command == "sync" and not config.jira.enabled:
            result = {"skipped": True, "reason": "Jira delivery is disabled"}
        else:
            init_db(settings.database_url)
            if args.command == "preview":
                if not 1 <= args.limit <= 10000:
                    raise ValueError("limit must be between 1 and 10000")
                with get_session() as session:
                    result = preview_routes(session, config, team_id=args.team, limit=args.limit)
            elif args.command == "sync":
                result = sync_jira(get_engine(), config)
            elif args.command == "retry":
                retry_finding(
                    get_engine(), args.finding_id, clear_uncertain=args.clear_uncertain_create
                )
                result = {"retry_scheduled": str(args.finding_id)}
            elif args.command == "adopt":
                adopt_issue(get_engine(), config, args.finding_id, args.team, args.issue_key)
                result = {"adopted": args.issue_key, "finding_id": str(args.finding_id)}
        print(json.dumps(result, indent=2))
    except (ValueError, KeyError, JiraError) as exc:
        parser.exit(2, f"Jira command failed: {exc}\n")


if __name__ == "__main__":
    main()
