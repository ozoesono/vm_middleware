"""Shared fixtures for exercising delivery against real HTTP request shapes."""

import json
import uuid
from datetime import datetime

import httpx

from src.common.config import AppConfig, AppSettings
from src.common.jira_config import JiraConfig
from src.common.models import Finding, PipelineRun
from src.integration.jira_client import JiraClient

NOW = datetime(2026, 10, 8, 12)


def config_for_teams():
    config = AppConfig(AppSettings(config_dir="config", database_url="sqlite:///:memory:"))
    config.jira = JiraConfig.model_validate(
        {
            "enabled": True,
            "refresh_seconds": 60,
            "instances": {
                name: {
                    "base_url": f"https://{name}.example.test",
                    "deployment": deployment,
                    "auth": {"type": "bearer", "token_env": "TEST_JIRA_TOKEN"},
                }
                for name, deployment in (("one", "cloud"), ("two", "data_center"))
            },
            "teams": {
                name: {
                    "team_id": name,
                    "enabled": True,
                    "match": {"service_owner_team": [name]},
                    "jira": {"instance": instance, "project": project},
                }
                for name, instance, project in (
                    ("team-platform", "one", "PLAT"),
                    ("team-api", "two", "API"),
                )
            },
        }
    )
    return config


def seed_run(session):
    run = PipelineRun(id=uuid.uuid4(), status="SUCCESS", started_at=NOW, completed_at=NOW)
    session.add(run)
    session.commit()
    return run.id


def seed_finding(session, run_id, team="team-platform", **kwargs):
    values = dict(
        id=uuid.uuid4(),
        tenable_finding_id=str(uuid.uuid4()),
        title="Patch vulnerable lib",
        severity="HIGH",
        risk_rating="HIGH",
        risk_score=0.8,
        state="OPEN",
        tenable_state="ACTIVE",
        service_owner_team=team,
        last_run_id=run_id,
        sla_status="WITHIN_SLA",
        sla_due_date=NOW.date(),
        first_seen=NOW,
        last_seen=NOW,
    )
    values.update(kwargs)
    finding = Finding(**values)
    session.add(finding)
    session.commit()
    return finding.id


class JiraServer:
    """Mock transport for two Jira instances, with programmable failures."""

    def __init__(self):
        self.issues = {}
        self.requests = []
        self.fail_host = None
        self.fail_status = 503
        self.lose_create_response = False
        self.fail_before_create = False
        self.hide_search = False
        self.metadata_extra = []

    def factory(self, instance):
        return JiraClient(instance, transport=httpx.MockTransport(self.handle))

    def handle(self, request):
        self.requests.append(request)
        host = request.url.host
        path = request.url.path
        body = json.loads(request.content) if request.content else {}
        if host == self.fail_host:
            return httpx.Response(self.fail_status, headers={"Retry-After": "120"})
        if "/createmeta/" in path:
            if path.endswith("/issuetypes"):
                return httpx.Response(
                    200, json={"issueTypes": [{"id": "10001", "name": "Task"}], "total": 1}
                )
            fields = [
                "summary",
                "description",
                "labels",
                "duedate",
                "priority",
                "project",
                "issuetype",
                "assignee",
                "components",
            ]
            return httpx.Response(
                200,
                json={
                    "fields": [{"fieldId": f} for f in fields] + self.metadata_extra,
                    "total": len(fields) + len(self.metadata_extra),
                },
            )
        if "/search" in path:
            matches = (
                []
                if self.hide_search
                else [
                    i
                    for (h, _), i in self.issues.items()
                    if h == host
                    and any(label in request.url.params["jql"] for label in i["fields"]["labels"])
                ]
            )
            return httpx.Response(200, json={"issues": matches})
        if path.endswith("/issue") and request.method == "POST":
            if self.fail_before_create:
                raise httpx.ConnectError("connection dropped", request=request)
            # Issue IDs are instance-local; both instances can return ID 1.
            ident = str(sum(1 for h, _ in self.issues if h == host) + 1)
            key = f"{body['fields']['project']['key']}-{ident}"
            issue = {
                "id": ident,
                "key": key,
                "fields": {
                    **body["fields"],
                    "status": {"name": "To Do", "statusCategory": {"key": "new"}},
                },
            }
            self.issues[(host, ident)] = issue
            if self.lose_create_response:
                raise httpx.ReadTimeout("server accepted but reply was lost", request=request)
            return httpx.Response(201, json={"id": ident, "key": key})
        ident = path.split("/issue/", 1)[-1].split("/")[0]
        issue = self.issues.get((host, ident)) or next(
            (i for (h, _), i in self.issues.items() if h == host and i["key"] == ident), None
        )
        if issue is None:
            return httpx.Response(404)
        if path.endswith("/transitions"):
            if request.method == "GET":
                done = issue["fields"]["status"]["statusCategory"]["key"] == "done"
                return httpx.Response(
                    200,
                    json={
                        "transitions": [
                            {
                                "id": "11" if done else "31",
                                "name": "To Do" if done else "Done",
                                "fields": {},
                            },
                        ]
                    },
                )
            done = body["transition"]["id"] == "31"
            issue["fields"]["status"] = {
                "name": "Done" if done else "To Do",
                "statusCategory": {"key": "done" if done else "new"},
            }
            return httpx.Response(204)
        if request.method == "PUT":
            if issue["fields"]["status"]["statusCategory"]["key"] == "done":
                return httpx.Response(
                    400, json={"errorMessages": ["Resolved issues are not editable"]}
                )
            issue["fields"].update(body["fields"])
            for change in body.get("update", {}).get("labels", []):
                issue["fields"]["labels"].append(change["add"])
            return httpx.Response(204)
        return httpx.Response(200, json=issue)

    @property
    def creates(self):
        return [r for r in self.requests if r.method == "POST" and r.url.path.endswith("/issue")]
