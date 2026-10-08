import json

import httpx
import pytest

from src.common.jira_config import JiraDestination, JiraInstance
from src.integration.jira_client import JiraClient, JiraError


def instance(**kwargs):
    return JiraInstance(
        base_url="https://jira.example.test/context",
        auth={
            "type": "bearer",
            "token_env": "TEST_JIRA_TOKEN",
        },
        **kwargs,
    )


@pytest.fixture(autouse=True)
def credentials(monkeypatch):
    monkeypatch.setenv("TEST_JIRA_TOKEN", "sensitive-token")


@pytest.mark.parametrize("deployment,version", [("cloud", "3"), ("data_center", "2")])
def test_metadata_pagination_preserves_context_path(deployment, version):
    requests = []

    def handler(request):
        requests.append(request)
        assert request.url.path.startswith(f"/context/rest/api/{version}/")
        if request.url.path.endswith("/issuetypes"):
            start = int(request.url.params["startAt"])
            return httpx.Response(
                200,
                json={
                    "issueTypes": [{"id": str(start), "name": "Task" if start else "Bug"}],
                    "total": 2,
                },
            )
        return httpx.Response(
            200, json={"fields": [{"fieldId": "summary", "required": True}], "total": 1}
        )

    with JiraClient(
        instance(deployment=deployment), transport=httpx.MockTransport(handler)
    ) as client:
        client.validate_fields(JiraDestination(instance="x", project="PROJ"), {"summary": "test"})
    assert len(requests) == 3


def test_redirect_does_not_forward_credentials_and_create_is_uncertain():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(302, headers={"Location": "https://untrusted.example.test/"})

    with JiraClient(instance(), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(JiraError) as error:
            client.create_issue({})
    assert len(requests) == 1
    assert error.value.uncertain
    assert "sensitive-token" not in str(error.value)


def test_429_is_definite_rejection_and_retains_retry_after():
    with JiraClient(
        instance(),
        transport=httpx.MockTransport(
            lambda r: httpx.Response(429, headers={"Retry-After": "120"})
        ),
    ) as client:
        with pytest.raises(JiraError) as error:
            client.create_issue({})
    assert error.value.retryable
    assert not error.value.uncertain
    assert error.value.retry_after == 120


def test_malformed_successful_create_is_uncertain():
    with JiraClient(
        instance(),
        transport=httpx.MockTransport(lambda r: httpx.Response(201, json={"key": "PROJ-1"})),
    ) as client:
        with pytest.raises(JiraError) as error:
            client.create_issue({})
    assert error.value.uncertain


def test_transition_resolves_id_and_checks_required_fields():
    posts = []

    def handler(request):
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "transitions": [
                        {
                            "id": "91",
                            "name": "Resolve",
                            "fields": {"resolution": {"required": True}},
                        }
                    ]
                },
            )
        posts.append(json.loads(request.content))
        return httpx.Response(204)

    with JiraClient(instance(), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(JiraError, match="requires fields"):
            client.transition("1", "Resolve", {})
        client.transition("1", "Resolve", {"resolution": {"name": "Fixed"}})
    assert posts == [{"transition": {"id": "91"}, "fields": {"resolution": {"name": "Fixed"}}}]


def test_unavailable_transition_does_not_post():
    with JiraClient(
        instance(),
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"transitions": []})),
    ) as client:
        with pytest.raises(JiraError, match="unavailable"):
            client.transition("1", "Done", {})
