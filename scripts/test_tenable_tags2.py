#!/usr/bin/env python3
"""Find a Tenable tag by name and filter findings by its tag_id.

Usage:
    .venv/bin/python3 scripts/test_tenable_tags2.py --name Prod
"""

import os
import sys
import json
from pathlib import Path

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
    print("ERROR: Set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY in .env")
    sys.exit(1)

EXTRA_PROPS = "finding_vpr_score,finding_cves,asset_name,sensor_type,tag_names,tag_ids"

client = httpx.Client(
    base_url=BASE_URL,
    headers={
        "X-ApiKeys": f"accessKey={ACCESS_KEY};secretKey={SECRET_KEY}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    },
    timeout=120,
)

# Parse --name
target_name = None
for i, arg in enumerate(sys.argv):
    if arg == "--name" and i + 1 < len(sys.argv):
        target_name = sys.argv[i + 1]

if not target_name:
    print("Usage: test_tenable_tags2.py --name <tag_name>")
    print("Example: test_tenable_tags2.py --name Prod")
    sys.exit(1)

# =====================================================================
# STEP 1: Find the tag ID by name
# =====================================================================
print("=" * 70)
print(f"  STEP 1: Looking up tag by name='{target_name}'")
print("=" * 70)

response = client.post("/api/v1/t1/tags/search", params={"limit": 500}, json={})
if response.status_code != 200:
    print(f"  ERROR {response.status_code}: {response.text[:300]}")
    sys.exit(1)

tags = response.json().get("data", [])
print(f"  Got {len(tags)} total tags")

# Find exact and partial matches
exact_matches = []
partial_matches = []
for t in tags:
    if not isinstance(t, dict):
        continue
    tag_name = t.get("name", "")
    if tag_name.lower() == target_name.lower():
        exact_matches.append(t)
    elif target_name.lower() in tag_name.lower():
        partial_matches.append(t)

print(f"\n  Exact matches for '{target_name}': {len(exact_matches)}")
for t in exact_matches:
    print(f"    - name: '{t.get('name')}'  id: {t.get('id')}  asset_count: {t.get('asset_count')}  total_weaknesses: {t.get('total_weakness_count')}")

if partial_matches:
    print(f"\n  Partial matches: {len(partial_matches)}")
    for t in partial_matches[:10]:
        print(f"    - name: '{t.get('name')}'  id: {t.get('id')}")

if not exact_matches:
    print("\n  No exact match. Check the name — it's case-sensitive in the API.")
    sys.exit(1)

# Use the first exact match
target_tag = exact_matches[0]
target_tag_id = target_tag.get("id")
asset_count = target_tag.get("asset_count", 0)
weakness_count = target_tag.get("total_weakness_count", 0)

print(f"\n  Using tag ID: {target_tag_id}")
print(f"  This tag is linked to {asset_count} assets with {weakness_count} total weaknesses")

# =====================================================================
# STEP 2: Filter findings by tag_id
# =====================================================================
print()
print("=" * 70)
print(f"  STEP 2: Filtering findings where tag_ids contains '{target_tag_id}'")
print("=" * 70)

attempts = [
    ("tag_ids contains [id]", {"filters": [{"property": "tag_ids", "operator": "contains", "value": [target_tag_id]}]}),
    ("tag_ids has [id]", {"filters": [{"property": "tag_ids", "operator": "has", "value": [target_tag_id]}]}),
    ("tag_ids eq id", {"filters": [{"property": "tag_ids", "operator": "eq", "value": target_tag_id}]}),
    ("tag_ids in [id]", {"filters": [{"property": "tag_ids", "operator": "in", "value": [target_tag_id]}]}),
]

working = None
for label, body in attempts:
    print(f"\n  [{label}]")
    response = client.post(
        "/api/v1/t1/inventory/findings/search",
        params={"offset": 0, "limit": 5, "extra_properties": EXTRA_PROPS},
        json=body,
    )
    if response.status_code != 200:
        print(f"    ERROR {response.status_code}: {response.text[:200]}")
        continue

    data = response.json()
    total = data.get("pagination", {}).get("total", 0)
    findings = data.get("data", [])
    print(f"    Total matching: {total:,} | Returned: {len(findings)}")

    if total > 0 and findings:
        working = (label, body)
        print(f"    >>> THIS SYNTAX WORKS <<<")
        for f in findings[:3]:
            extra = f.get("extra_properties", {}) or {}
            print(f"    - {f.get('name')} | {extra.get('asset_name', 'N/A')[:60]}")
            print(f"      tag_names: {extra.get('tag_names', [])}")
            print(f"      tag_ids: {extra.get('tag_ids', [])}")
        break

# =====================================================================
# STEP 3: If nothing worked, try via the assets endpoint
# =====================================================================
if not working:
    print()
    print("=" * 70)
    print(f"  STEP 3: Findings filter didn't work — trying assets endpoint")
    print("=" * 70)

    response = client.post(
        "/api/v1/t1/inventory/assets/search",
        params={"offset": 0, "limit": 5},
        json={"filters": [{"property": "tag_ids", "operator": "contains", "value": [target_tag_id]}]},
    )
    if response.status_code != 200:
        print(f"  ERROR {response.status_code}: {response.text[:300]}")
    else:
        data = response.json()
        total = data.get("pagination", {}).get("total", 0)
        assets = data.get("data", [])
        print(f"  Assets with this tag: {total:,}")
        for a in assets[:3]:
            print(f"    - id: {a.get('id')}  name: {a.get('name', 'N/A')}")
        if assets:
            print()
            print("  >>> Assets endpoint works! We can:")
            print("  >>> 1. Get asset IDs that have the tag")
            print("  >>> 2. Then filter findings by asset_id")

print()
print("=" * 70)

client.close()
