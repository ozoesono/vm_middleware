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

Account-split tag variants:
    Tenable caps a tag at 5 AWS accounts. A logical tag that spans more accounts
    is stored as several variants — Tag-Name-1, Tag-Name-2, … — each holding up
    to 5 accounts; a tag within the limit stays unsuffixed as Tag-Name. The
    caller still passes the logical name (--tag Tag-Name); this module expands it
    by probing the base then Tag-Name-1, -2, … and unions their assets, stopping
    at the first numbered variant that returns nothing.
"""

from __future__ import annotations

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from src.common.config import TenableConfig
from src.common.logging import get_logger

logger = get_logger("tagged_assets")

# Safety bound on the numbered-variant probe (up to 5 accounts each, so 50
# variants ≈ 250 accounts). A misbehaving query can't loop unbounded.
TAG_VARIANT_CAP = 50


class TaggedAssetsError(Exception):
    """Raised when the assets/search call fails. Carries the HTTP status so
    callers can distinguish a nonexistent tag (4xx) from a real fault."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


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
            f"assets/search returned {response.status_code}: {response.text[:300]}",
            status_code=response.status_code,
        )
    return response.json()


def _extract_asset(a: dict) -> tuple[str | None, list[str]]:
    """Pull (asset_id, tag_names) out of one assets/search result row."""
    extra = a.get("extra_properties", {}) or {}
    aid = a.get("id") or a.get("asset_id") or extra.get("asset_id")
    tag_list = extra.get("tag_names") or []
    if not isinstance(tag_list, list):
        tag_list = []
    return aid, tag_list


def _accumulate_tag_assets(
    client: httpx.Client,
    config: TenableConfig,
    tag: str,
    asset_tags: dict[str, list[str]],
    page_size: int,
) -> int:
    """Fetch every asset carrying one EXACT tag, merging asset_id → tag_names
    into asset_tags. Returns the number of assets seen for this tag (0 if the
    tag has no assets or does not exist).
    """
    text_query = _build_advanced_query([tag])
    seen = 0
    offset = 0
    total: int | None = None

    while True:
        try:
            data = _fetch_assets_page(client, config, text_query, offset, page_size)
        except TaggedAssetsError as e:
            # A nonexistent tag may surface as a client error rather than an
            # empty result set. Treat 4xx (bad / unknown tag) as "no data" so the
            # variant probe can stop cleanly; auth (401/403) and server (5xx)
            # errors are real faults and must not be swallowed.
            if e.status_code in (400, 404):
                logger.info("tag_absent_or_unqueryable", tag=tag, status=e.status_code)
                return 0
            raise

        if total is None:
            total = data.get("pagination", {}).get("total", 0)

        page = data.get("data", [])
        for a in page:
            aid, tag_list = _extract_asset(a)
            if aid:
                asset_tags[aid] = tag_list
                seen += 1

        offset += page_size
        if offset >= (total or 0) or len(page) == 0:
            break

    return seen


def _fetch_tag_with_variants(
    client: httpx.Client,
    config: TenableConfig,
    logical: str,
    asset_tags: dict[str, list[str]],
    page_size: int,
    max_variants: int,
) -> None:
    """Expand one logical tag into its account-split variants and merge all of
    their assets into asset_tags.

    Probe the unsuffixed base first (present when the tag is within Tenable's
    5-account limit), then the numbered variants logical-1, logical-2, …,
    stopping at the first numbered variant that returns no data. An empty base
    is NOT a stop signal — a heavily split tag has no unsuffixed form, only
    numbered variants.
    """
    base_seen = _accumulate_tag_assets(client, config, logical, asset_tags, page_size)
    logger.info("tag_base_probed", tag=logical, assets=base_seen)

    n = 1
    while n <= max_variants:
        variant = f"{logical}-{n}"
        seen = _accumulate_tag_assets(client, config, variant, asset_tags, page_size)
        if seen == 0:
            break
        logger.info("tag_variant_probed", tag=variant, assets=seen)
        n += 1

    if n > max_variants:
        logger.warning("tag_variant_cap_reached", logical=logical, cap=max_variants)
    if base_seen == 0 and n == 1:
        logger.warning("tag_yielded_no_assets", tag=logical)


def fetch_tagged_assets_with_tags(
    config: TenableConfig,
    access_key: str,
    secret_key: str,
    tag_names: list[str],
    page_size: int = 1000,
    max_variants: int = TAG_VARIANT_CAP,
) -> dict[str, list[str]]:
    """Fetch tagged assets and return a dict mapping asset_id → ALL tag_names.

    Each requested tag is expanded across its account-split variants (see the
    module docstring): the base plus Tag-Name-1, -2, … are probed and their
    assets unioned. Even though the filter is for one logical tag, every tag
    attached to each matching asset (Criticality-X, Environment-Y, …) is
    captured so the middleware can enrich findings with full business context.

    Args:
        config: TenableConfig (used for base_url, timeout)
        access_key/secret_key: Tenable API credentials
        tag_names: logical filter tag names like ["Portfolio-Business-Growth"]
        page_size: assets per page (default 1000)
        max_variants: cap on the numbered-variant probe per logical tag

    Returns:
        dict[asset_id, list[tag_name]]
    """
    if not tag_names:
        return {}

    logger.info("tagged_assets_fetch_start", tags=tag_names)
    asset_tags: dict[str, list[str]] = {}

    with httpx.Client(
        base_url=config.base_url,
        headers={
            "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        timeout=config.request_timeout_seconds,
    ) as client:
        for logical in tag_names:
            _fetch_tag_with_variants(client, config, logical, asset_tags, page_size, max_variants)

    logger.info("tagged_assets_fetch_complete", tags=tag_names, asset_count=len(asset_tags))
    return asset_tags


def fetch_tagged_asset_ids(
    config: TenableConfig,
    access_key: str,
    secret_key: str,
    tag_names: list[str],
    page_size: int = 1000,
) -> set[str]:
    """Backward-compatible wrapper that returns just the set of asset_ids."""
    return set(
        fetch_tagged_assets_with_tags(config, access_key, secret_key, tag_names, page_size).keys()
    )
