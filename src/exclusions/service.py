"""Persist middleware pause decisions while continuing to observe Tenable state."""

from __future__ import annotations

from sqlalchemy import and_, not_, or_

from src.common.models import ExclusionAudit, Finding
from src.exclusions.policy import aware, utcnow
from src.scoring.engine import score_record


def apply_policy(session, finding, config, *, now=None, rescore_on_release=True):
    """Return True when paused. Never alter source state, dates, or Jira identity."""
    now = aware(now or utcnow())
    naive_now = now.replace(tzinfo=None)
    rules = config.exclusions.matching_rules(finding, now)
    ids = sorted(rule.id for rule in rules)
    old_ids = finding.exclusion_rule_ids or []
    old_status = finding.processing_status or "ACTIVE"
    reason = "; ".join(f"{r.id}: {r.reason}" for r in rules) if rules else None
    until = (
        max(r.expires_at for r in rules).replace(tzinfo=None)
        if rules and all(r.expires_at for r in rules)
        else None
    )
    changed = (
        old_status != ("PAUSED" if rules else "ACTIVE")
        or old_ids != ids
        or finding.exclusion_reason != reason
        or finding.exclusion_until != until
    )
    finding.processing_status = "PAUSED" if rules else "ACTIVE"
    finding.exclusion_rule_ids = ids or None
    finding.exclusion_reason = reason
    finding.exclusion_until = until
    finding.exclusion_evaluated_at = naive_now
    finding.exclusion_policy_hash = config.exclusions.fingerprint
    if rules:
        finding.jira_sync_status = "PAUSED"
        if finding.risk_rating is None:
            finding.risk_rating, finding.risk_model = "UNSCORED", "not_scored"
            finding.risk_score, finding.sla_days, finding.sla_status = 0, 0, "NOT_SCORED"
    elif old_status == "PAUSED":
        if rescore_on_release:
            score_record(finding, config)
        finding.jira_sync_status = "PENDING"
        finding.jira_sync_error = None
        finding.jira_attempts = 0
        finding.jira_next_sync_at = None
    if changed:
        session.add(
            ExclusionAudit(
                finding_id=finding.id,
                tenable_finding_id=finding.tenable_finding_id,
                action="PAUSED"
                if rules and old_status != "PAUSED"
                else "UPDATED"
                if rules
                else "RESUMED",
                rules=[r.model_dump(mode="json") for r in rules],
                policy_hash=config.exclusions.fingerprint,
                evaluated_at=naive_now,
            )
        )
    return bool(rules)


def refresh_exclusions(session, config, *, now=None, limit=None):
    """Re-evaluate changed/expired rules in bounded, restartable batches."""
    now = aware(now or utcnow())
    policy = config.exclusions
    matching = policy.sql(Finding, session.get_bind().dialect.name, now)
    passed_expiries = [
        r.expires_at for r in policy.rules if r.enabled and r.expires_at and r.expires_at <= now
    ]
    latest_expiry = max(passed_expiries).replace(tzinfo=None) if passed_expiries else None
    candidates = (
        session.query(Finding)
        .filter(
            or_(
                and_(
                    matching,
                    or_(
                        Finding.processing_status != "PAUSED",
                        Finding.exclusion_policy_hash.is_(None),
                        Finding.exclusion_policy_hash != policy.fingerprint,
                    ),
                ),
                and_(not_(matching), Finding.processing_status == "PAUSED"),
                # Expiring one of several matches changes the recorded rule list/expiry.
                and_(
                    Finding.processing_status == "PAUSED",
                    Finding.exclusion_until <= now.replace(tzinfo=None),
                ),
                and_(
                    Finding.processing_status == "PAUSED",
                    Finding.exclusion_evaluated_at < latest_expiry,
                )
                if latest_expiry
                else False,
            )
        )
        .order_by(Finding.id)
        .with_for_update(skip_locked=True)
        .limit(limit or policy.refresh_batch_size)
        .all()
    )
    result = {"checked": len(candidates), "paused": 0, "resumed": 0}
    for finding in candidates:
        old = finding.processing_status
        paused = apply_policy(session, finding, config, now=now)
        result["paused"] += int(paused and old != "PAUSED")
        result["resumed"] += int(not paused and old == "PAUSED")
    session.flush()
    return result


def filter_untracked_findings(session, run_id, raw_findings, config, *, now=None):
    """Skip new out-of-scope findings early; retain all updates to tracked findings.

    Team-scoped rules wait for enrichment. Existing findings (including every
    linked Jira ticket) continue through ingestion even while paused.
    """
    from src.common.logging import get_logger
    from src.ingestion.tenable_ingestion import normalise_finding

    now = now or utcnow()
    matches = {}
    for index, raw in enumerate(raw_findings):
        try:
            staged = normalise_finding(raw, run_id)
            rules = config.exclusions.matching_rules(staged, now, raw_only=True)
            if rules:
                matches[index] = (staged.tenable_finding_id, [rule.id for rule in rules])
        except (ValueError, TypeError, AttributeError):
            pass  # Ingestion reports malformed records.
    if not matches:
        return raw_findings, 0
    tracked = {
        row[0]
        for row in session.query(Finding.tenable_finding_id)
        .filter(Finding.tenable_finding_id.in_([value[0] for value in matches.values()]))
        .all()
    }
    excluded = {index: value for index, value in matches.items() if value[0] not in tracked}
    counts = {}
    for _, rule_ids in excluded.values():
        for rule_id in rule_ids:
            counts[rule_id] = counts.get(rule_id, 0) + 1
    if excluded:
        get_logger("exclusions").info(
            "untracked_findings_excluded",
            run_id=str(run_id),
            excluded=len(excluded),
            rule_counts=counts,
        )
    return [raw for i, raw in enumerate(raw_findings) if i not in excluded], len(excluded)
