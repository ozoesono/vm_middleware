"""Pure routing and eligibility decisions shared by previews and delivery."""

from dataclasses import dataclass

from src.common.config import AppConfig
from src.common.jira_config import JiraDestination, JiraInstance, JiraTeam, normalized
from src.common.models import Finding


@dataclass
class Route:
    status: str
    reason: str
    team_id: str | None = None
    destination: JiraDestination | None = None
    instance: JiraInstance | None = None
    team: JiraTeam | None = None


def resolve_route(finding: Finding, config: AppConfig, *, now=None) -> Route:
    route = _resolve_base_route(finding, config)
    rules = config.exclusions.matching_rules(finding, now)
    if rules:
        route.status = "PAUSED"
        route.reason = "; ".join(f"{r.id}: {r.reason}" for r in rules)
    elif finding.processing_status == "PAUSED":
        route.status = "RESUME_PENDING"
        route.reason = "policy refresh will resume from the latest observation"
    return route


def _resolve_base_route(finding: Finding, config: AppConfig) -> Route:
    if finding.jira_binding:
        binding = finding.jira_binding
        destination = JiraDestination.model_validate(binding["destination"])
        original = JiraInstance.model_validate(binding["instance"])
        instance = config.jira.instances.get(destination.instance)
        if instance is None or (instance.base_url, instance.deployment) != (
            original.base_url,
            original.deployment,
        ):
            return Route(
                "BLOCKED",
                "bound Jira instance was removed or its address changed",
                finding.jira_team_id,
            )
        team = config.jira.teams.get(finding.jira_team_id)
        # Workflow/field edits apply to an existing destination. Routing changes
        # apply only to unbound findings; existing tickets keep their destination.
        if team and (team.jira.instance, team.jira.project) == (
            destination.instance,
            destination.project,
        ):
            destination = team.jira
        return Route(
            "BOUND", "existing Jira destination", finding.jira_team_id, destination, instance, team
        )
    if finding.jira_ticket_key or finding.jira_issue_id:
        return Route("BLOCKED", "existing ticket has no instance binding; adopt it explicitly")
    matches = [
        team
        for team in config.jira.teams.values()
        if all(
            normalized(getattr(finding, key)) in {normalized(v) for v in values}
            for key, values in team.match.items()
        )
    ]
    if len(matches) > 1:
        return Route("BLOCKED", "multiple team rules matched")
    if not matches:
        return Route("UNROUTED", "no team rule matched ownership fields")
    team = matches[0]
    route = Route(
        "ELIGIBLE",
        "eligible for ticket creation",
        team.team_id,
        team.jira,
        config.jira.instances[team.jira.instance],
        team,
    )
    reason = None
    phase = config.rollout.active_phase
    if finding.state != "OPEN" or (finding.tenable_state or "").upper() == "FIXED":
        reason = "only current OPEN findings can create tickets"
    elif not team.enabled:
        reason = "team is disabled for new tickets"
    elif finding.risk_rating not in team.ticketing.risk_ratings:
        reason = "risk rating is outside team ticketing policy"
    elif phase.severity_filter and finding.risk_rating not in phase.severity_filter:
        reason = "risk rating is outside rollout policy"
    elif phase.team_filter and team.team_id not in phase.team_filter:
        reason = "team is outside rollout policy"
    if reason:
        route.status, route.reason = "INELIGIBLE", reason
    return route


def validate_rollout(config: AppConfig) -> None:
    if config.rollout.phase not in config.rollout.phases:
        raise ValueError(f"unknown rollout phase: {config.rollout.phase}")
    phase = config.rollout.active_phase
    if phase.max_tickets_per_run < 0:
        raise ValueError("rollout max_tickets_per_run cannot be negative")
    if set(phase.severity_filter) - {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        raise ValueError("rollout severity_filter must contain scored risk ratings")
