"""Small Jira Cloud v3 / Data Center v2 adapter. Retries belong to the durable worker."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import quote

import httpx

from src.common.jira_config import JiraDestination, JiraInstance


class JiraError(Exception):
    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        retryable: bool = False,
        uncertain: bool = False,
        retry_after: int = 0,
    ):
        super().__init__(message)
        self.status = status
        self.retryable = retryable
        self.uncertain = uncertain
        self.retry_after = retry_after


def _retry_after(value: str | None) -> int:
    if not value:
        return 0
    try:
        return max(0, int(value))
    except ValueError:
        try:
            dt = parsedate_to_datetime(value)
            return max(0, int((dt - datetime.now(timezone.utc)).total_seconds()) + 1)
        except (ValueError, TypeError, OverflowError):
            return 0


class JiraClient:
    def __init__(self, instance: JiraInstance, *, transport=None, observer=None):
        self.instance = instance
        self.observer = observer
        token = os.environ.get(instance.auth.token_env, "")
        email = os.environ.get(instance.auth.email_env or "", "")
        if not token or (instance.auth.type == "basic" and not email):
            raise JiraError("missing Jira credentials referenced by environment variable names")
        headers = {"Accept": "application/json", "User-Agent": "vm-middleware/0.1"}
        auth = None
        if instance.auth.type == "basic":
            auth = httpx.BasicAuth(email, token)
        else:
            headers["Authorization"] = f"Bearer {token}"
        version = "3" if instance.deployment == "cloud" else "2"
        self.http = httpx.Client(
            base_url=f"{instance.base_url}/rest/api/{version}/",
            auth=auth,
            headers=headers,
            timeout=instance.timeout_seconds,
            follow_redirects=False,
            transport=transport,
        )
        self._metadata = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.http.close()

    def _request(self, method, path, **kwargs):
        status = None
        try:
            response = self.http.request(method, path, **kwargs)
            status = response.status_code
        except httpx.TransportError as exc:
            self._observe(method, path, status, False)
            # Transport errors can contain credentials; store only a generic message.
            raise JiraError(
                "Jira transport failure", retryable=True, uncertain=method != "GET"
            ) from exc
        if not 200 <= status < 300:
            self._observe(method, path, status, False)
            raise JiraError(
                f"Jira returned HTTP {status}",
                status=status,
                retryable=status == 429 or status >= 500,
                uncertain=method != "GET" and (status >= 500 or 300 <= status < 400),
                retry_after=_retry_after(response.headers.get("Retry-After")),
            )
        try:
            data = response.json() if response.content else {}
            if not isinstance(data, dict):
                raise ValueError("expected object")
        except ValueError as exc:
            self._observe(method, path, status, False)
            raise JiraError(
                "invalid Jira JSON response",
                status=status,
                retryable=True,
                uncertain=method != "GET",
            ) from exc
        self._observe(method, path, status, True)
        return data

    def _observe(self, method, path, status, success):
        if self.observer:
            self.observer(method, path, status, success)

    def _pages(self, path, key):
        offset = 0
        while True:
            page = self._request("GET", path, params={"startAt": offset, "maxResults": 100})
            rows = page.get(key, page.get("values", []))
            if not isinstance(rows, list):
                raise JiraError("invalid Jira metadata page")
            yield from rows
            offset += len(rows)
            if page.get("isLast") or offset >= page.get("total", offset):
                return
            if not rows:
                raise JiraError("Jira metadata pagination made no progress")

    def create_metadata(self, destination: JiraDestination) -> dict:
        key = (destination.project, destination.issue_type)
        if key not in self._metadata:
            path = f"issue/createmeta/{quote(destination.project, safe='')}/issuetypes"
            types = list(self._pages(path, "issueTypes"))
            matches = [
                t
                for t in types
                if t.get("name") == destination.issue_type
                or str(t.get("id")) == destination.issue_type
            ]
            if len(matches) != 1 or matches[0].get("subtask"):
                raise JiraError("issue type is unavailable, ambiguous or requires a parent")
            fields = list(self._pages(f"{path}/{quote(str(matches[0]['id']), safe='')}", "fields"))
            self._metadata[key] = {f.get("fieldId", f.get("key")): f for f in fields}
        return self._metadata[key]

    def validate_fields(self, destination: JiraDestination, fields: dict) -> None:
        metadata = self.create_metadata(destination)
        missing = [
            key
            for key, spec in metadata.items()
            if spec.get("required")
            and not spec.get("hasDefaultValue")
            and fields.get(key) in (None, "", [])
        ]
        unknown = set(fields) - set(metadata) - {"project", "issuetype"}
        if missing or unknown:
            raise JiraError(
                f"invalid create fields; missing={sorted(missing)}, "
                f"not on create screen={sorted(unknown)}"
            )
        for key, value in fields.items():
            allowed = metadata.get(key, {}).get("allowedValues")
            if not allowed or value is None:
                continue
            for item in value if isinstance(value, list) else [value]:
                if isinstance(item, dict):
                    identifiers = set(item) & {"id", "name", "value", "accountId"}
                    if identifiers and not any(
                        all(str(option.get(k)) == str(item[k]) for k in identifiers)
                        for option in allowed
                    ):
                        raise JiraError(f"value for {key} is not available in this project")

    def find_correlated(self, project: str, label: str) -> list[dict]:
        path = "search/jql" if self.instance.deployment == "cloud" else "search"
        data = self._request(
            "GET",
            path,
            params={
                "jql": f'project = "{project}" AND labels = "{label}"',
                "maxResults": 2,
                "fields": "status,labels,project",
            },
        )
        if not isinstance(data.get("issues"), list):
            raise JiraError("Jira search response has no issues list", retryable=True)
        return data["issues"]

    def get_issue(self, issue_id: str) -> dict:
        data = self._request(
            "GET",
            f"issue/{quote(str(issue_id), safe='')}",
            params={"fields": "status,labels,project"},
        )
        if not data.get("id") or not data.get("key") or not data.get("fields", {}).get("status"):
            raise JiraError("incomplete Jira issue response", retryable=True)
        return data

    def create_issue(self, fields: dict) -> dict:
        data = self._request("POST", "issue", json={"fields": fields})
        if not data.get("id") or not data.get("key"):
            raise JiraError("create response has no issue identity", uncertain=True)
        return data

    def update_issue(self, issue_id: str, fields: dict, existing_labels: list[str]) -> None:
        # Keep assignment and issue type chosen by the team after creation.
        fields = {k: v for k, v in fields.items() if k not in ("project", "issuetype", "assignee")}
        labels = fields.pop("labels", [])
        update = {"labels": [{"add": label} for label in labels if label not in existing_labels]}
        self._request(
            "PUT",
            f"issue/{quote(str(issue_id), safe='')}",
            json={"fields": fields, "update": update},
        )

    def transition(self, issue_id: str, name: str, fields: dict) -> None:
        path = f"issue/{quote(str(issue_id), safe='')}/transitions"
        data = self._request("GET", path, params={"expand": "transitions.fields"})
        matches = [
            t
            for t in data.get("transitions", [])
            if t.get("name") == name or str(t.get("id")) == name
        ]
        if len(matches) != 1:
            raise JiraError(f"configured transition {name!r} is unavailable or ambiguous")
        transition = matches[0]
        missing = [
            key
            for key, spec in transition.get("fields", {}).items()
            if spec.get("required")
            and not spec.get("hasDefaultValue")
            and fields.get(key) in (None, "", [])
        ]
        if missing:
            raise JiraError(f"transition requires fields: {sorted(missing)}")
        self._request("POST", path, json={"transition": {"id": transition["id"]}, "fields": fields})
