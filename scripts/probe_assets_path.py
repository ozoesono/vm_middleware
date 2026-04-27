#!/usr/bin/env python3
"""Try the two-step approach: filter assets by tag, then findings by asset_id.

Usage:
    .venv/bin/python3 scripts/probe_assets_path.py --tag Portfolio-Business-Growth
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

target = None
for i, a in enumerate(sys.argv):
    if a == "--tag" and i + 1 < len(sys.argv):
        target = sys.argv[i + 1]
if not target:
    print("Usage: --tag <Tag-Name>")
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

# Tag id
r = client.post("/api/v1/t1/tags/search", params={"limit": 500}, json={})
tags = r.json().get("data", [])
match = [t for t in tags if t.get("name", "").lower() == target.lower()]
tag_id = match[0]["id"] if match else None
tag_name = match[0]["name"] if match else target
print(f"Tag: {tag_name}  id={tag_id}")
print()

# =====================================================================
# 1. Discover available asset properties
# =====================================================================
print("=" * 70)
print("  Available asset filter properties")
print("=" * 70)
r = client.get("/api/v1/t1/inventory/assets/properties")
if r.status_code == 200:
    props_data = r.json()
    props = props_data if isinstance(props_data, list) else props_data.get("data", [])
    names = []
    for p in props:
        if isinstance(p, str):
            names.append(p)
        elif isinstance(p, dict):
            names.append(p.get("key") or p.get("name") or str(p))
    tag_related = [n for n in names if "tag" in n.lower()]
    print(f"  Total: {len(names)}")
    print(f"  Tag-related: {tag_related}")
    Path("tenable_asset_properties.json").write_text(json.dumps(names, indent=2))
    print(f"  Saved all to tenable_asset_properties.json")
else:
    print(f"  {r.status_code}: {r.text[:200]}")

# =====================================================================
# 2. Try asset filter shapes
# =====================================================================
print()
print("=" * 70)
print("  Probing asset filter shapes")
print("=" * 70)

# Baseline
r = client.post(
    "/api/v1/t1/inventory/assets/search",
    params={"offset": 0, "limit": 1},
    json={},
)
baseline_assets = r.json().get("pagination", {}).get("total", 0) if r.status_code == 200 else "?"
print(f"  Unfiltered assets total: {baseline_assets}")
print()

shapes = [
    ("tag_names eq",
     {"filters": [{"property": "tag_names", "operator": "eq", "value": tag_name}]}),
    ("tag_names has",
     {"filters": [{"property": "tag_names", "operator": "has", "value": tag_name}]}),
    ("tag_names contains",
     {"filters": [{"property": "tag_names", "operator": "contains", "value": tag_name}]}),
    ("tag_ids eq str",
     {"filters": [{"property": "tag_ids", "operator": "eq", "value": tag_id}]}),
    ("tag_ids has [id]",
     {"filters": [{"property": "tag_ids", "operator": "has", "value": [tag_id]}]}),
    ("tag_ids contains [id]",
     {"filters": [{"property": "tag_ids", "operator": "contains", "value": [tag_id]}]}),
    ("tag_ids in [id]",
     {"filters": [{"property": "tag_ids", "operator": "in", "value": [tag_id]}]}),
]

asset_ids_with_tag = []
for label, body in shapes:
    r = client.post(
        "/api/v1/t1/inventory/assets/search",
        params={"offset": 0, "limit": 5},
        json=body,
    )
    if r.status_code != 200:
        print(f"  {r.status_code}  {label}: {r.text[:150]}")
        continue
    total = r.json().get("pagination", {}).get("total", 0)
    if total == baseline_assets:
        print(f"  {total:>10,}  (IGNORED)  {label}")
    elif total == 0:
        print(f"  {total:>10,}  (0 match)  {label}")
    else:
        print(f"  {total:>10,}  GENUINE   {label}")
        if not asset_ids_with_tag:
            asset_ids_with_tag = [a.get("id") for a in r.json().get("data", []) if a.get("id")]
            print(f"            Sample asset IDs: {asset_ids_with_tag[:3]}")
            print(f"            Working body: {json.dumps(body)}")

# =====================================================================
# 3. If we got asset IDs, try filtering findings by asset_id
# =====================================================================
if asset_ids_with_tag:
    print()
    print("=" * 70)
    print(f"  Found {len(asset_ids_with_tag)} sample tagged assets")
    print(f"  Now trying to filter findings by asset_id...")
    print("=" * 70)

    finding_filter_attempts = [
        ("asset_id eq",
         {"filters": [{"property": "asset_id", "operator": "eq", "value": asset_ids_with_tag[0]}]}),
        ("asset_id in [ids]",
         {"filters": [{"property": "asset_id", "operator": "in", "value": asset_ids_with_tag}]}),
        ("asset_id has [ids]",
         {"filters": [{"property": "asset_id", "operator": "has", "value": asset_ids_with_tag}]}),
    ]

    for label, body in finding_filter_attempts:
        r = client.post(
            "/api/v1/t1/inventory/findings/search",
            params={"offset": 0, "limit": 5, "extra_properties": "asset_name,tag_names"},
            json=body,
        )
        if r.status_code != 200:
            print(f"  {r.status_code}  {label}: {r.text[:150]}")
            continue
        total = r.json().get("pagination", {}).get("total", 0)
        print(f"  {total:>10,}  {label}")
        if total > 0:
            f = r.json().get("data", [])[0] if r.json().get("data") else None
            if f:
                extra = f.get("extra_properties", {}) or {}
                print(f"            Sample: {f.get('name')} on {extra.get('asset_name')}")
                print(f"            Tags: {extra.get('tag_names')}")
                print(f"            >>> WORKING: {json.dumps(body)}")

client.close()
