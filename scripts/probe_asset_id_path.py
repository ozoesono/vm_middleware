#!/usr/bin/env python3
"""Test if we can filter findings by asset_id, and if there's an endpoint
to list assets for a given tag.

Usage:
    .venv/bin/python3 scripts/probe_asset_id_path.py --tag Portfolio-Business-Growth
"""

import os, sys, json
from pathlib import Path

env_path = Path(__file__).parent.parent / ".env"
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

import httpx

BASE_URL = os.environ.get("TENABLE_BASE_URL", "https://cloud.tenable.com")
ACCESS_KEY = os.environ.get("TENABLE_ACCESS_KEY", "")
SECRET_KEY = os.environ.get("TENABLE_SECRET_KEY", "")

target = "Portfolio-Business-Growth"
for i, a in enumerate(sys.argv):
    if a == "--tag" and i + 1 < len(sys.argv):
        target = sys.argv[i + 1]

c = httpx.Client(
    base_url=BASE_URL,
    headers={
        "X-ApiKeys": f"accessKey={ACCESS_KEY};secretKey={SECRET_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    },
    timeout=120,
)

# Get tag id
r = c.post("/api/v1/t1/tags/search", params={"limit": 500}, json={})
tags = r.json().get("data", [])
match = [t for t in tags if t.get("name", "").lower() == target.lower()]
if not match:
    print(f"Tag '{target}' not found.")
    sys.exit(1)
tag = match[0]
tag_id = tag.get("id")
expected_assets = tag.get("asset_count", "?")
expected_findings = tag.get("total_weakness_count", "?")
print(f"Tag: {tag.get('name')}")
print(f"  id: {tag_id}")
print(f"  expected asset_count: {expected_assets}")
print(f"  expected weakness/finding count: {expected_findings}")
print()

# =====================================================================
# PART 1: Try to find tagged assets via various tag-related endpoints
# =====================================================================
print("=" * 70)
print("  PART 1: Find tagged assets via dedicated endpoints")
print("=" * 70)

candidate_endpoints = [
    ("GET",  f"/api/v1/t1/tags/{tag_id}/assets"),
    ("GET",  f"/api/v1/t1/tags/{tag_id}"),
    ("POST", f"/api/v1/t1/tags/{tag_id}/assets/search"),
    ("POST", f"/api/v1/t1/inventory/assets/search?tag_id={tag_id}"),
    ("GET",  f"/api/v1/t1/inventory/tags/{tag_id}/assets"),
]

asset_ids = []
for method, path in candidate_endpoints:
    if method == "GET":
        r = c.get(path)
    else:
        r = c.post(path, params={"offset": 0, "limit": 100}, json={})
    print(f"  {method} {path}  →  {r.status_code}")
    if r.status_code == 200:
        try:
            data = r.json()
            print(f"    Response keys: {list(data.keys()) if isinstance(data, dict) else 'list'}")
            if isinstance(data, dict):
                if "data" in data:
                    items = data["data"]
                    if items and isinstance(items[0], dict):
                        ids = [i.get("id") or i.get("asset_id") for i in items if i.get("id") or i.get("asset_id")]
                        if ids and not asset_ids:
                            asset_ids = ids
                            print(f"    >>> Got {len(ids)} asset IDs from this endpoint")
                            print(f"    >>> Sample: {ids[:3]}")
        except Exception as e:
            print(f"    Parse error: {e}")
    elif r.status_code in (400, 404):
        msg = r.text[:120].replace("\n", " ")
        print(f"    {msg}")

# =====================================================================
# PART 2: Test if findings/search accepts asset_id filter
# =====================================================================
print()
print("=" * 70)
print("  PART 2: Test asset_id filter on findings endpoint")
print("=" * 70)

# Get baseline
r = c.post("/api/v1/t1/inventory/findings/search", params={"offset": 0, "limit": 1}, json={})
baseline = r.json().get("pagination", {}).get("total", 0)
print(f"  Findings baseline: {baseline:,}")

# Get a sample asset_id from the findings endpoint
r = c.post(
    "/api/v1/t1/inventory/findings/search",
    params={"offset": 0, "limit": 1, "extra_properties": "asset_name"},
    json={},
)
sample = r.json().get("data", [])
if not sample:
    print("  No findings to sample asset_id from")
    sys.exit(1)

sample_aid = sample[0].get("asset_id")
print(f"  Sample asset_id: {sample_aid}")
print()

# Try filter shapes for asset_id
shapes = [
    ("filters[]: asset_id eq",
     {"filters": [{"property": "asset_id", "operator": "eq", "value": sample_aid}]}),
    ("filters[]: asset_id in [id]",
     {"filters": [{"property": "asset_id", "operator": "in", "value": [sample_aid]}]}),
    ("filters[]: asset_id has [id]",
     {"filters": [{"property": "asset_id", "operator": "has", "value": [sample_aid]}]}),
    ("filters[]: asset_id contains [id]",
     {"filters": [{"property": "asset_id", "operator": "contains", "value": [sample_aid]}]}),
    ("filters[]: asset_id contains str",
     {"filters": [{"property": "asset_id", "operator": "contains", "value": sample_aid}]}),
    ("query.text mode=Advanced",
     {"query": {"text": f"asset_id = {sample_aid}", "mode": "Advanced"}}),
    ("query.text mode=simple",
     {"query": {"text": sample_aid, "mode": "simple"}}),
]

for label, body in shapes:
    r = c.post(
        "/api/v1/t1/inventory/findings/search",
        params={"offset": 0, "limit": 1},
        json=body,
    )
    if r.status_code != 200:
        msg = r.text[:120].replace("\n", " ")
        print(f"  {r.status_code:>3}  {label}")
        print(f"        {msg}")
        continue
    total = r.json().get("pagination", {}).get("total", 0)
    if total == baseline:
        print(f"  {total:>10,}  (IGNORED)  {label}")
    elif total == 0:
        print(f"  {total:>10,}  (0 match)  {label}")
    else:
        print(f"  {total:>10,}  GENUINE   {label}")
        print(f"            Body: {json.dumps(body)}")

c.close()
