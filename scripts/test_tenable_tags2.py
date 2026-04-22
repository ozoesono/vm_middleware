#!/usr/bin/env python3
"""Explore Tenable tags in detail and find the right way to filter findings.

Usage:
    .venv/bin/python3 scripts/test_tenable_tags2.py
    .venv/bin/python3 scripts/test_tenable_tags2.py --category Environment --value Prod
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

# Parse args
target_category = None
target_value = None
for i, arg in enumerate(sys.argv):
    if arg == "--category" and i + 1 < len(sys.argv):
        target_category = sys.argv[i + 1]
    if arg == "--value" and i + 1 < len(sys.argv):
        target_value = sys.argv[i + 1]


# =====================================================================
# STEP 1: Get ALL tags with their raw structure
# =====================================================================
print("=" * 70)
print("  STEP 1: Dumping raw tag structure from /api/v1/t1/tags/search")
print("=" * 70)

response = client.post("/api/v1/t1/tags/search", params={"limit": 200}, json={})
if response.status_code != 200:
    print(f"  ERROR {response.status_code}: {response.text[:300]}")
    sys.exit(1)

tags_data = response.json()
tags = tags_data.get("data", [])
print(f"  Found {len(tags)} tags")
print()

# Show the structure of the first tag raw
if tags:
    print("  --- Raw tag #1 (all fields) ---")
    print(json.dumps(tags[0], indent=2))
    print()

# Save all tags to file
tags_file = Path(__file__).parent.parent / "tenable_tags_dump.json"
with open(tags_file, "w") as f:
    json.dump(tags, f, indent=2, default=str)
print(f"  All tags saved to: {tags_file}")
print()

# Show all tags grouped by category
print("  --- All tags grouped ---")
by_category = {}
for t in tags:
    if not isinstance(t, dict):
        continue
    cat = t.get("category") or t.get("category_name") or t.get("name") or "?"
    val = t.get("value") or t.get("value_name") or "?"
    tag_id = t.get("id") or t.get("tag_id") or "?"
    by_category.setdefault(cat, []).append((val, tag_id))

for cat, values in sorted(by_category.items()):
    print(f"\n  {cat}:")
    for val, tag_id in sorted(values):
        print(f"    - {val}  (id: {tag_id})")


# =====================================================================
# STEP 2: Find target tag ID if user specified category/value
# =====================================================================
target_tag_id = None
target_tag_name = None

if target_category and target_value:
    print()
    print("=" * 70)
    print(f"  STEP 2: Looking for tag '{target_category}:{target_value}'")
    print("=" * 70)

    for t in tags:
        if not isinstance(t, dict):
            continue
        cat = t.get("category") or t.get("category_name") or t.get("name") or ""
        val = t.get("value") or t.get("value_name") or ""
        if cat.lower() == target_category.lower() and val.lower() == target_value.lower():
            target_tag_id = t.get("id") or t.get("tag_id")
            target_tag_name = f"{cat}:{val}"
            break

    if target_tag_id:
        print(f"  Found! Tag ID: {target_tag_id}")
    else:
        print(f"  Tag not found with category='{target_category}' value='{target_value}'")
        print(f"  Check the list above for the exact spelling.")


# =====================================================================
# STEP 3: Try filtering findings by tag_ids (not tag_names)
# =====================================================================
if target_tag_id:
    print()
    print("=" * 70)
    print(f"  STEP 3: Filtering findings by tag_id = {target_tag_id}")
    print("=" * 70)

    attempts = [
        {
            "label": "filter tag_ids contains [id]",
            "body": {"filters": [{"property": "tag_ids", "operator": "contains", "value": [target_tag_id]}]},
        },
        {
            "label": "filter tag_ids eq [id]",
            "body": {"filters": [{"property": "tag_ids", "operator": "eq", "value": [target_tag_id]}]},
        },
        {
            "label": "filter tag_ids = id (string)",
            "body": {"filters": [{"property": "tag_ids", "operator": "contains", "value": target_tag_id}]},
        },
        {
            "label": f"filter tag_names contains [{target_tag_name}]",
            "body": {"filters": [{"property": "tag_names", "operator": "contains", "value": [target_tag_name]}]},
        },
        {
            "label": f"filter tag_names contains [{target_value}]",
            "body": {"filters": [{"property": "tag_names", "operator": "contains", "value": [target_value]}]},
        },
    ]

    for attempt in attempts:
        print(f"\n  [{attempt['label']}]")
        response = client.post(
            "/api/v1/t1/inventory/findings/search",
            params={"offset": 0, "limit": 5, "extra_properties": EXTRA_PROPS},
            json=attempt["body"],
        )
        if response.status_code != 200:
            print(f"    ERROR {response.status_code}: {response.text[:200]}")
            continue

        data = response.json()
        total = data.get("pagination", {}).get("total", 0)
        findings = data.get("data", [])
        print(f"    Total matching: {total:,} | Returned: {len(findings)}")

        if findings:
            # Show if the returned findings actually have this tag
            for f in findings[:2]:
                extra = f.get("extra_properties", {}) or {}
                print(f"    - {f.get('name')} | asset: {extra.get('asset_name', 'N/A')[:60]}")
                print(f"      tag_names: {extra.get('tag_names', [])}")
                print(f"      tag_ids: {extra.get('tag_ids', [])}")
            if total > 0:
                print(f"    >>> THIS SYNTAX WORKS <<<")
                print(f"    >>> Use: {json.dumps(attempt['body'])}")


# =====================================================================
# STEP 4: Alternative — try assets search to find assets with this tag
# =====================================================================
if target_tag_id:
    print()
    print("=" * 70)
    print(f"  STEP 4: Try the ASSETS endpoint filtered by tag_id")
    print("=" * 70)
    print("  (maybe findings don't carry tags, but assets do)")

    response = client.post(
        "/api/v1/t1/inventory/assets/search",
        params={"offset": 0, "limit": 5},
        json={"filters": [{"property": "tag_ids", "operator": "contains", "value": [target_tag_id]}]},
    )
    if response.status_code != 200:
        print(f"  ERROR {response.status_code}: {response.text[:200]}")
    else:
        data = response.json()
        total = data.get("pagination", {}).get("total", 0)
        assets = data.get("data", [])
        print(f"  Assets with this tag: {total:,}")
        for a in assets[:3]:
            print(f"    - {a.get('name', a.get('id'))}")

client.close()
print()
print("=" * 70)
print("  Done. Share the output — we need to see the tag structure and")
print("  which filter syntax returns findings.")
print("=" * 70)
