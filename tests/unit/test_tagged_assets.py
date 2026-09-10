"""Regression coverage for exact tag filtering without numbered expansion."""

import json

import httpx
import pytest
import respx

from src.common.config import TenableConfig
from src.ingestion.tagged_assets import TaggedAssetsError, fetch_tagged_assets_with_tags


@pytest.mark.parametrize("has_assets", [False, True])
@respx.mock
def test_plain_tag_does_not_probe_numbered_tags(has_assets):
    config = TenableConfig()
    tags = ["Portfolio-Data-Services", "Criticality-High"]
    rows = [{"id": "a1", "extra_properties": {"tag_names": tags}}] if has_assets else []
    route = respx.post(f"{config.base_url}/api/v1/t1/inventory/assets/search").mock(
        return_value=httpx.Response(200, json={"pagination": {"total": len(rows)}, "data": rows})
    )

    result = fetch_tagged_assets_with_tags(config, "ak", "sk", [tags[0]])

    assert result == ({"a1": tags} if has_assets else {})
    assert route.call_count == 1
    assert json.loads(route.calls[0].request.content)["query"]["text"] == (
        'Assets HAS tag_names = "Portfolio-Data-Services"'
    )


@respx.mock
def test_multiple_tags_use_one_or_query_across_pages():
    config = TenableConfig()
    route = respx.post(f"{config.base_url}/api/v1/t1/inventory/assets/search").mock(
        side_effect=[
            httpx.Response(200, json={
                "pagination": {"total": 2},
                "data": [{"id": asset, "extra_properties": {"tag_names": [tag]}}],
            })
            for asset, tag in [("a1", "Portfolio-A"), ("a2", "Portfolio-B")]
        ]
    )

    result = fetch_tagged_assets_with_tags(
        config, "ak", "sk", ["Portfolio-A", "Portfolio-B"], page_size=1
    )

    assert result == {"a1": ["Portfolio-A"], "a2": ["Portfolio-B"]}
    assert route.call_count == 2
    for offset, call in enumerate(route.calls):
        assert call.request.url.params["offset"] == str(offset)
        assert json.loads(call.request.content)["query"]["text"] == (
            '(Assets HAS tag_names = "Portfolio-A") OR (Assets HAS tag_names = "Portfolio-B")'
        )


@pytest.mark.parametrize("status", [400, 404, 401, 403, 500])
@respx.mock
def test_query_errors_propagate(status):
    config = TenableConfig()
    route = respx.post(f"{config.base_url}/api/v1/t1/inventory/assets/search").mock(
        return_value=httpx.Response(status, text="Query failed")
    )

    with pytest.raises(TaggedAssetsError, match=str(status)):
        fetch_tagged_assets_with_tags(config, "ak", "sk", ["Portfolio-A"])
    assert route.call_count == 1
