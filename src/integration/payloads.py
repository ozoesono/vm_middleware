"""Ticket content and a stable correlation label for recovering uncertain creates."""

import hashlib
import json

from src.common.jira_config import JiraDestination, JiraInstance
from src.common.models import CveDetails, Finding
from src.reporting.csv_reports import _format_description, _format_solution


def correlation_label(finding: Finding) -> str:
    return f"vmf-{finding.id.hex}"


def issue_fields(
    finding: Finding,
    destination: JiraDestination,
    instance: JiraInstance,
    cve: CveDetails | None = None,
) -> dict:
    description = "\n\n".join(
        filter(
            None,
            [
                _format_description(finding, cve),
                _format_solution(finding, cve),
                f"Finding ID: {finding.tenable_finding_id}\n"
                f"Owner team: {finding.service_owner_team or 'Unassigned'}\n"
                f"Portfolio: {finding.portfolio or 'Unknown'}\n"
                f"Service: {finding.service or 'Unknown'}\n"
                f"Environment: {finding.environment or 'Unknown'}\n"
                f"Risk: {finding.risk_rating} ({finding.risk_score})\n"
                f"SLA: {finding.sla_status}; due {finding.sla_due_date}\n"
                f"Tenable state: {finding.tenable_state}\n"
                f"Recurrences: {finding.recurrence_count}",
            ],
        )
    )
    if instance.deployment == "cloud":
        description = {
            "type": "doc",
            "version": 1,
            "content": [
                {"type": "paragraph", "content": [{"type": "text", "text": line}]}
                for line in description.splitlines()
                if line
            ],
        }
    fields = {
        "project": {"key": destination.project},
        "issuetype": {
            "id" if destination.issue_type.isdecimal() else "name": destination.issue_type
        },
        "summary": f"[{finding.risk_rating}] {finding.title} - {finding.asset_name or 'asset'}"[
            :255
        ],
        "description": description,
        "labels": sorted(set(destination.labels + [correlation_label(finding)])),
        "duedate": finding.sla_due_date.isoformat() if finding.sla_due_date else None,
        **destination.custom_fields,
    }
    if priority := destination.priority_mapping.get(finding.risk_rating):
        fields["priority"] = {"name": priority}
    if destination.assignee is not None:
        fields["assignee"] = destination.assignee
    if destination.components:
        fields["components"] = [{"name": name} for name in destination.components]
    return fields


def fields_hash(fields: dict) -> str:
    return hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()
