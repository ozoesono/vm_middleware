"""Pure routing and eligibility decisions shared by previews and delivery."""

from dataclasses import dataclass

from src.common.config import AppConfig
from src.common.jira_config import JiraDestination, JiraInstance, JiraTeam, normalized
from src.common.models import Finding
from src.common.ownership import services_for


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


def _matches_scope(team, finding, *, service=None):
    for key, wanted in team.match.items():
        if key == "service_owner_team" and "service" in team.match:
            continue
        if key == "service":
            actual = [service] if service is not None else services_for(finding)
        else:
            actual = [getattr(finding, key)]
        if not {normalized(v) for v in actual} & {normalized(v) for v in wanted}:
            return False
    return True


def _accountable_team(finding, config):
    """Rank service teams, falling back to the first observed service's team."""
    services = services_for(finding)
    teams = list(config.jira.teams.values())
    service_teams = [team for team in teams if "service" in team.match]
    if services and service_teams:
        by_service = [
            [team for team in service_teams if _matches_scope(team, finding, service=name)]
            for name in services
        ]
        candidates = {team.team_id: team for matches in by_service for team in matches}
        for team_id in config.jira.remediation_team_priority:
            if team_id in candidates:
                return [candidates[team_id]], f"highest-ranked matching service team: {team_id}", "UNROUTED"
        # Do not silently skip an unmapped first service to assign another one.
        if not by_service[0]:
            return [], f"first service {services[0]!r} has no matching team configuration or scope", "UNROUTED"
        return by_service[0], f"first service in Tenable tag order: {services[0]}", "UNROUTED"
    # Keep existing non-service configurations working without a priority list.
    matches = [team for team in teams if _matches_scope(team, finding)]
    return matches, "eligible for ticket creation" if matches else "no team rule matched ownership fields", "UNROUTED"


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
        # Routing changes must not move existing tickets to another destination.
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
    matches, reason, missing_status = _accountable_team(finding, config)
    if len(matches) > 1:
        return Route("BLOCKED", "multiple team rules matched; configure one accountable team")
    if not matches:
        return Route(missing_status, reason)
    team = matches[0]
    route = Route(
        "ELIGIBLE",
        reason,
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
