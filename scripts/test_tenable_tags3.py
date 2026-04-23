#!/usr/bin/env python3
"""Explore Tenable tags across all products (VM, Exposure Management, etc).

Tenable has two tag systems:
  1. VM module tags (product: TENABLE_IO) — flat name-only tags
  2. Exposure Management tags — Category:Value format, created in T1 UI

This script tries to find both.

Usage:
    .venv/bin/python3 scripts/test_tenable_tags3.py
"""

import os
import sys
import json
from collections import Counter
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

client = httpx.Client(
    base_url=BASE_URL,
    headers={
        "X-ApiKeys": f"accessKey={ACCESS_KEY};secretKey={SECRET_KEY}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    },
    timeout=120,
)


def try_get(url, label):
    """Try a GET request and show the response."""
    print(f"\n  [GET {url}]  — {label}")
    try:
        r = client.get(url, params={"limit": 5})
        print(f"    Status: {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, dict):
                items = data.get("data", data.get("categories", data.get("tags", [])))
                print(f"    Keys: {list(data.keys())}")
                if items:
                    print(f"    Items: {len(items)}")
                    print(f"    First item: {json.dumps(items[0], indent=6)[:500]}")
            elif isinstance(data, list):
                print(f"    Items: {len(data)}")
                if data:
                    print(f"    First item: {json.dumps(data[0], indent=6)[:500]}")
        else:
            print(f"    {r.text[:200]}")
    except Exception as e:
        print(f"    Exception: {e}")


def try_post(url, label, body=None):
    """Try a POST request and show the response."""
    print(f"\n  [POST {url}]  — {label}")
    try:
        r = client.post(url, params={"limit": 5}, json=body or {})
        print(f"    Status: {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, dict):
                items = data.get("data", data.get("categories", data.get("tags", [])))
                print(f"    Keys: {list(data.keys())}")
                if items:
                    print(f"    Items: {len(items)}")
                    print(f"    First item: {json.dumps(items[0], indent=6)[:600]}")
            elif isinstance(data, list):
                print(f"    Items: {len(data)}")
                if data:
                    print(f"    First item: {json.dumps(data[0], indent=6)[:600]}")
        else:
            print(f"    {r.text[:200]}")
    except Exception as e:
        print(f"    Exception: {e}")


# =====================================================================
# PART 1: Inspect existing /tags/search response — group by product
# =====================================================================
print("=" * 70)
print("  PART 1: Tags grouped by 'product' field")
print("=" * 70)

response = client.post("/api/v1/t1/tags/search", params={"limit": 500}, json={})
if response.status_code == 200:
    tags = response.json().get("data", [])
    print(f"  Total tags: {len(tags)}")

    products = Counter()
    all_keys = set()
    for t in tags:
        if isinstance(t, dict):
            products[t.get("product", "UNKNOWN")] += 1
            all_keys.update(t.keys())

    print(f"\n  --- Tags per product ---")
    for prod, count in products.most_common():
        print(f"    {prod}: {count}")

    print(f"\n  --- All fields seen across tags ---")
    for key in sorted(all_keys):
        print(f"    {key}")

    # Show one sample per product
    print(f"\n  --- Sample tag per product ---")
    seen = set()
    for t in tags:
        if isinstance(t, dict):
            prod = t.get("product", "UNKNOWN")
            if prod not in seen:
                seen.add(prod)
                print(f"\n  Product '{prod}':")
                print(json.dumps(t, indent=4))
else:
    print(f"  ERROR: {response.status_code}")


# =====================================================================
# PART 2: Try tag properties endpoint
# =====================================================================
print()
print("=" * 70)
print("  PART 2: Tag properties endpoint")
print("=" * 70)
try_get("/api/v1/t1/tags/properties", "List filterable tag properties")


# =====================================================================
# PART 3: Try alternative tag endpoints for Exposure Management
# =====================================================================
print()
print("=" * 70)
print("  PART 3: Try alternative endpoints that might have EM-native tags")
print("=" * 70)

try_get("/api/v1/t1/tag-categories", "Tag categories (hypothetical)")
try_post("/api/v1/t1/tag-categories/search", "Tag categories search (hypothetical)")
try_get("/api/v1/tags", "Legacy VM tags")
try_get("/tags/values", "Legacy tag values")
try_post("/tags/values/filter", "Legacy tag filter", {})
try_get("/api/v1/t1/inventory/tags/search", "Inventory-scoped tags")


# =====================================================================
# PART 4: Filter tags search by product field
# =====================================================================
print()
print("=" * 70)
print("  PART 4: Search tags with product filter")
print("=" * 70)

for prod_value in ["TENABLE_ONE", "T1", "EXPOSURE_MANAGEMENT", "TENABLE_EM", "INVENTORY"]:
    try_post(
        "/api/v1/t1/tags/search",
        f"filter product={prod_value}",
        {"filters": [{"property": "product", "operator": "eq", "value": prod_value}]},
    )


# =====================================================================
# PART 5: Look at findings to see if any have Environment-like tag_names
# =====================================================================
print()
print("=" * 70)
print("  PART 5: Scan findings for 'Prod', 'Dev', 'Environment' tag_names")
print("=" * 70)

response = client.post(
    "/api/v1/t1/inventory/findings/search",
    params={"offset": 0, "limit": 500, "extra_properties": "tag_names,tag_ids,asset_name"},
    json={},
)

if response.status_code == 200:
    findings = response.json().get("data", [])
    tag_names_counter = Counter()
    for f in findings:
        extra = f.get("extra_properties", {}) or {}
        for tn in extra.get("tag_names", []) or []:
            tag_names_counter[tn] += 1

    print(f"  Scanned {len(findings)} findings")
    print(f"  Unique tag_names seen: {len(tag_names_counter)}")
    if tag_names_counter:
        print(f"\n  --- Top tag names on findings ---")
        for name, count in tag_names_counter.most_common(30):
            print(f"    '{name}': {count}")
    else:
        print("  No tag_names populated on any findings.")
        print("  This means the 500 findings we fetched are on assets that")
        print("  have NO tags. Either:")
        print("    - No assets have tags")
        print("    - OR tagged assets have fewer findings and fell outside first 500")
        print("    - OR tags aren't surfaced through this field in findings")

print()
print("=" * 70)
client.close()
