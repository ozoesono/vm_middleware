#!/usr/bin/env python3
"""Test script to explore tag-based filtering in the Tenable Inventory API.

This script:
1. Fetches findings WITH tag_names/tag_ids to see what tags exist
2. Tries filtering findings by a specific tag
3. Shows the filter syntax that works

Usage:
    .venv/bin/python3 scripts/test_tenable_tags.py
    .venv/bin/python3 scripts/test_tenable_tags.py --tag "Portfolio:payments"
"""

import os
import sys
import json
from pathlib import Path
from collections import Counter

# Load .env file
env_path = Path(__file__).parent.parent / ".env"
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())

import httpx

BASE_URL = os.environ.get("TENABLE_BASE_URL", "https://cloud.tenable.com")
ACCESS_KEY = os.environ.get("TENABLE_ACCESS_KEY", "")
SECRET_KEY = os.environ.get("TENABLE_SECRET_KEY", "")

if not ACCESS_KEY or not SECRET_KEY:
    print("ERROR: Set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY in .env or environment")
    sys.exit(1)

SEARCH_ENDPOINT = "/api/v1/t1/inventory/findings/search"
EXTRA_PROPS = "finding_vpr_score,finding_cvss3_base_score,finding_cves,asset_name,asset_class,sensor_type,first_observed_at,last_observed_at,tag_names,tag_ids"

client = httpx.Client(
    base_url=BASE_URL,
    headers={
        "X-ApiKeys": f"accessKey={ACCESS_KEY};secretKey={SECRET_KEY}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    },
    timeout=120,
)


def fetch(params, body=None, label=""):
    """Helper to fetch and handle errors."""
    print(f"\n  [{label}]")
    print(f"  Params: {params}")
    if body:
        print(f"  Body: {json.dumps(body, indent=2)}")
    response = client.post(SEARCH_ENDPOINT, params=params, json=body or {})
    if response.status_code != 200:
        print(f"  ERROR {response.status_code}: {response.text[:300]}")
        return None
    data = response.json()
    total = data.get("pagination", {}).get("total", 0)
    findings = data.get("data", [])
    print(f"  Total: {total:,} | Fetched: {len(findings)}")
    return data


# =====================================================================
# STEP 1: Fetch findings and see what tags look like
# =====================================================================
print("=" * 70)
print("  STEP 1: Fetching findings to see tag structure")
print("=" * 70)

data = fetch(
    params={"offset": 0, "limit": 20, "extra_properties": EXTRA_PROPS},
    label="Fetch with tags"
)

if data:
    findings = data.get("data", [])
    tag_counter = Counter()
    findings_with_tags = 0
    findings_without_tags = 0

    for f in findings:
        extra = f.get("extra_properties", {}) or {}
        tag_names = extra.get("tag_names", [])
        tag_ids = extra.get("tag_ids", [])

        if tag_names:
            findings_with_tags += 1
            for tag in tag_names:
                tag_counter[tag] += 1
        else:
            findings_without_tags += 1

    print(f"\n  Findings with tags: {findings_with_tags}/{len(findings)}")
    print(f"  Findings without tags: {findings_without_tags}/{len(findings)}")

    if tag_counter:
        print(f"\n  --- Tags found (across {len(findings)} findings) ---")
        for tag, count in tag_counter.most_common(30):
            print(f"    {tag}: {count}")
    else:
        print("\n  No tags found in these findings.")
        print("  This could mean:")
        print("    - Assets are not tagged in Tenable yet")
        print("    - Tags are not returned as extra_properties")
        print("    - Tags use a different field name")

    # Show raw tag data from first finding that has tags
    for f in findings:
        extra = f.get("extra_properties", {}) or {}
        if extra.get("tag_names") or extra.get("tag_ids"):
            print(f"\n  --- Sample finding with tags ---")
            print(f"  Finding: {f.get('name')}")
            print(f"  Asset: {extra.get('asset_name')}")
            print(f"  tag_names: {extra.get('tag_names')}")
            print(f"  tag_ids: {extra.get('tag_ids')}")
            break

# =====================================================================
# STEP 2: Try different filter syntaxes for tag-based queries
# =====================================================================
print()
print("=" * 70)
print("  STEP 2: Testing tag filter syntaxes")
print("=" * 70)

# Parse --tag argument if provided
tag_filter = None
for i, arg in enumerate(sys.argv):
    if arg == "--tag" and i + 1 < len(sys.argv):
        tag_filter = sys.argv[i + 1]

if not tag_filter:
    # Try to use a tag we discovered
    if tag_counter:
        tag_filter = tag_counter.most_common(1)[0][0]
        print(f"\n  Using most common tag: '{tag_filter}'")
    else:
        print("\n  No tags discovered and no --tag argument provided.")
        print("  Trying common filter patterns anyway...")
        tag_filter = "Portfolio"

# Try various filter syntaxes the API might accept
filter_attempts = [
    {
        "label": "Filter by tag_names contains",
        "body": {"filters": [{"property": "tag_names", "operator": "contains", "value": [tag_filter]}]},
    },
    {
        "label": "Filter by tag_names eq",
        "body": {"filters": [{"property": "tag_names", "operator": "eq", "value": [tag_filter]}]},
    },
    {
        "label": "Filter by tag_names in",
        "body": {"filters": [{"property": "tag_names", "operator": "in", "value": [tag_filter]}]},
    },
    {
        "label": "Filter by tag_names match",
        "body": {"filters": [{"property": "tag_names", "operator": "match", "value": tag_filter}]},
    },
    {
        "label": "Filter via query text",
        "body": {"query": {"mode": "simple", "text": tag_filter}},
    },
]

working_filters = []

for attempt in filter_attempts:
    data = fetch(
        params={"offset": 0, "limit": 5, "extra_properties": EXTRA_PROPS},
        body=attempt["body"],
        label=attempt["label"],
    )
    if data and data.get("pagination", {}).get("total", 0) > 0:
        working_filters.append(attempt)
        # Show a sample
        findings = data.get("data", [])
        if findings:
            f = findings[0]
            extra = f.get("extra_properties", {}) or {}
            print(f"    Sample: {f.get('name')} | Asset: {extra.get('asset_name', 'N/A')}")
            print(f"    Tags: {extra.get('tag_names', [])}")

# =====================================================================
# STEP 3: Summary
# =====================================================================
print()
print("=" * 70)
print("  SUMMARY")
print("=" * 70)

if working_filters:
    print(f"\n  Working filter syntax ({len(working_filters)} found):")
    for wf in working_filters:
        print(f"    {wf['label']}")
        print(f"    Body: {json.dumps(wf['body'])}")
else:
    print("\n  No tag filter syntax worked.")
    print("  You may need to:")
    print("    1. Ensure assets are tagged in Tenable Exposure Management")
    print("    2. Check if tags use Category:Value format (e.g., 'Portfolio:payments')")
    print("    3. Try the Tenable tags search endpoint: POST /api/v1/t1/tags/search")

# Also try the tags search endpoint to see what tags exist
print()
print("=" * 70)
print("  BONUS: Checking available tags via /api/v1/t1/tags/search")
print("=" * 70)

response = client.post("/api/v1/t1/tags/search", params={"limit": 50}, json={})
if response.status_code == 200:
    tags_data = response.json()
    tags = tags_data.get("data", [])
    print(f"  Found {len(tags)} tags")
    for t in tags[:20]:
        if isinstance(t, dict):
            cat = t.get("category", t.get("name", ""))
            val = t.get("value", "")
            tag_id = t.get("id", "")
            print(f"    {cat}:{val}  (id: {tag_id})")
        else:
            print(f"    {t}")
else:
    print(f"  Tags endpoint returned {response.status_code}: {response.text[:200]}")

client.close()
