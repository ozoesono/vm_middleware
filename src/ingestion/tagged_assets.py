"""Fetch the set of asset IDs that are tagged with the configured tag(s).

Uses the assets/search endpoint with an advanced query, which DOES support
tag-based filtering (unlike the findings endpoint).

The resulting set of asset_ids is then used to filter findings client-side
in the streaming pipeline.

Working query format (verified):
    POST /api/v1/t1/inventory/assets/search
    body: {
        "query": {
            "mode": "advanced",
            "text": 'Assets HAS tag_names = "Portfolio-Business-Growth"'
        }
    }
    params: extra_properties=asset_id,tag_names
"""

from __future__ import annotations

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from src.common.config import TenableConfig
from src.common.logging import get_logger

logger = get_logger("tagged_assets")


class TaggedAssetsError(Exception):
    """Raised when the assets/search call fails."""


class _RateLimit(Exception):
    """Internal trigger for tenacity retry on 429."""


def _build_advanced_query(tag_names: list[str]) -> str:
    """Build an advanced query string for one or more tag names (OR logic)."""
    parts = [f'Assets HAS tag_names = "{t}"' for t in tag_names]
    if len(parts) == 1:
        return parts[0]
    return " OR ".join(f"({p})" for p in parts)


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=2, min=4, max=60),
    retry=retry_if_exception_type(_RateLimit),
)
def _fetch_assets_page(
    client: httpx.Client,
    config: TenableConfig,
    text_query: str,
    offset: int,
    limit: int,
) -> dict:
    """Fetch one page of assets matching the advanced query."""
    response = client.post(
        "/api/v1/t1/inventory/assets/search",
        params={
            "offset": offset,
            "limit": limit,
            "extra_properties": "asset_id,asset_name,tag_names",
        },
        json={"query": {"mode": "advanced", "text": text_query}},
    )
    if response.status_code == 429:
        raise _RateLimit()
    if response.status_code >= 400:
        raise TaggedAssetsError(
            f"assets/search returned {response.status_code}: {response.text[:300]}"
        )
    return response.json()


def fetch_tagged_asset_ids(
    config: TenableConfig,
    access_key: str,
    secret_key: str,
    tag_names: list[str],
    page_size: int = 1000,
) -> set[str]:
    """Fetch the set of asset_ids that have any of the supplied tag names.

    Args:
        config: TenableConfig (used for base_url, timeout)
        access_key/secret_key: Tenable API credentials
        tag_names: list of tag names like ["Portfolio-Business-Growth"]
        page_size: assets per page (default 1000)

    Returns:
        Set of asset_id strings.
    """
    if not tag_names:
        return set()

    text_query = _build_advanced_query(tag_names)
    logger.info("tagged_assets_fetch_start", tags=tag_names, query=text_query)

    asset_ids: set[str] = set()
    offset = 0
    total: int | None = None

    with httpx.Client(
        base_url=config.base_url,
        headers={
            "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        timeout=config.request_timeout_seconds,
    ) as client:
        while True:
            data = _fetch_assets_page(client, config, text_query, offset, page_size)

            if total is None:
                total = data.get("pagination", {}).get("total", 0)
                logger.info("tagged_assets_total", total=total)

            page = data.get("data", [])
            for a in page:
                aid = a.get("id") or a.get("asset_id")
                if not aid:
                    extra = a.get("extra_properties", {}) or {}
                    aid = extra.get("asset_id")
                if aid:
                    asset_ids.add(aid)

            logger.info(
                "tagged_assets_page",
                offset=offset,
                fetched=len(page),
                cumulative=len(asset_ids),
                total=total,
            )

            offset += page_size
            if offset >= (total or 0) or len(page) == 0:
                break

    logger.info("tagged_assets_fetch_complete", asset_count=len(asset_ids))
    return asset_ids
