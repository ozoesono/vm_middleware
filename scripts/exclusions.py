#!/usr/bin/env python3
"""Validate, preview and apply middleware exclusions. Never writes to Tenable or Jira."""

import argparse
import json
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import not_, or_

from src.common.config import AppConfig, AppSettings
from src.common.db import get_session, init_db
from src.common.models import ExclusionAudit, Finding, PipelineRun
from src.exclusions.policy import utcnow
from src.exclusions.service import refresh_exclusions


def preview(session, config, *, rule_id=None, limit=20):
    policy = config.exclusions
    now = utcnow()
    predicate = policy.sql(Finding, session.get_bind().dialect.name, now)
    query = session.query(Finding)
    result = {
        "policy_hash": policy.fingerprint,
        "excluded_by_current_config": query.filter(predicate).count(),
        "waiting_to_resume": query.filter(
            not_(predicate), Finding.processing_status == "PAUSED"
        ).count(),
    }
    if rule_id:
        rule = next((r for r in policy.rules if r.id == rule_id), None)
        if rule is None:
            raise ValueError(f"unknown rule: {rule_id}")
        # A disabled example can be assessed before enabling it in the live file.
        proposed = policy.model_copy(
            update={
                "enabled": True,
                "rules": [
                    rule.model_copy(update={"enabled": True, "expires_at": None}),
                ],
            }
        )
        selection = proposed.sql(Finding, session.get_bind().dialect.name, now)
        result["rule"] = {
            "id": rule.id,
            "active": policy.enabled and rule.active(now),
            "matching_stored_findings": query.filter(selection).count(),
            "preview_ignores_enabled_and_expiry": True,
        }
    else:
        selection = or_(predicate, Finding.processing_status == "PAUSED")
    samples = []
    for finding in query.filter(selection).order_by(Finding.id).limit(limit):
        rules = policy.matching_rules(finding, now)
        samples.append(
            {
                "finding_id": str(finding.id),
                "tenable_finding_id": finding.tenable_finding_id,
                "title": finding.title,
                "detection_id": finding.plugin_id,
                "cves": policy.values(finding, "cve"),
                "asset_name": finding.asset_name,
                "asset_type": finding.asset_type,
                "owner_team": finding.service_owner_team,
                "source_state": finding.state,
                "processing_status": finding.processing_status,
                "matched_rules": [r.id for r in rules],
                "effect": "PAUSE"
                if rules
                else "RESUME"
                if finding.processing_status == "PAUSED"
                else "UNCHANGED",
                "jira_ticket_key": finding.jira_ticket_key,
            }
        )
    result["samples"] = samples
    latest = session.query(PipelineRun).order_by(PipelineRun.started_at.desc()).first()
    result["last_run_untracked_findings_excluded"] = latest.findings_excluded if latest else 0
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate", help="validate configuration without a database connection")
    p = commands.add_parser("preview", help="read-only match counts and samples")
    p.add_argument("--rule", help="also test a rule's predicates even if it is disabled or expired")
    p.add_argument("--limit", type=int, default=20)
    apply = commands.add_parser(
        "apply", help="update local pause state and rescore released findings"
    )
    apply.add_argument(
        "--all", action="store_true", help="continue until every affected stored finding is checked"
    )
    history = commands.add_parser("history", help="show pause/resume decision history")
    history.add_argument("--finding-id", type=uuid.UUID, required=True)
    history.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()
    try:
        settings = AppSettings(**({"config_dir": args.config_dir} if args.config_dir else {}))
        config = AppConfig(settings)
        if hasattr(args, "limit") and not 1 <= args.limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        if args.command == "validate":
            now = utcnow()
            result = {
                "valid": True,
                "enabled": config.exclusions.enabled,
                "rules": [
                    {
                        "id": r.id,
                        "active": config.exclusions.enabled and r.active(now),
                        "owner": r.owner,
                        "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                    }
                    for r in config.exclusions.rules
                ],
            }
        else:
            init_db(settings.database_url)
            if args.command == "apply":
                result = {"checked": 0, "paused": 0, "resumed": 0}
                while True:
                    with get_session() as session:
                        batch = refresh_exclusions(session, config)
                    for key in result:
                        result[key] += batch[key]
                    if not args.all or batch["checked"] == 0:
                        break
            elif args.command == "preview":
                with get_session() as session:
                    result = preview(session, config, rule_id=args.rule, limit=args.limit)
            else:
                with get_session() as session:
                    result = [
                        {
                            "action": event.action,
                            "at": event.evaluated_at.isoformat(),
                            "rules": event.rules,
                            "policy_hash": event.policy_hash,
                        }
                        for event in session.query(ExclusionAudit)
                        .filter_by(finding_id=args.finding_id)
                        .order_by(ExclusionAudit.evaluated_at.desc())
                        .limit(args.limit)
                    ]
        print(json.dumps(result, indent=2))
    except (ValueError, KeyError) as exc:
        parser.exit(2, f"Exclusion command failed: {exc}\n")


if __name__ == "__main__":
    main()
