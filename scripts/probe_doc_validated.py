#!/usr/bin/env python3
"""Re-probe filters using ONLY property names returned by the
findings/properties endpoint (the documented source of truth).

Also tests with the always-send-JSON-body fix, in case our earlier
ignored 200s were actually 415s being silently transformed.
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

c = httpx.Client(
    base_url=BASE_URL,
    headers={
        "X-ApiKeys": f"accessKey={ACCESS_KEY};secretKey={SECRET_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    },
    timeout=120,
)

# 1. Get the documented properties list with full schema (operators, types)
print("=" * 70)
print("  STEP 1: Fetch the documented findings properties + their schemas")
print("=" * 70)
r = c.get("/api/v1/t1/inventory/findings/properties")
props_data = r.json()
all_props = props_data if isinstance(props_data, list) else props_data.get("data", [])

# Print full schema for asset_id and tag_name properties
target_names = {"asset_id", "tag_name", "tag_names", "tag_ids", "asset_name"}
relevant = []
for p in all_props:
    if isinstance(p, dict):
        name = p.get("key") or p.get("name")
        if name in target_names:
            relevant.append(p)
            print(f"\n  Property '{name}':")
            print(json.dumps(p, indent=4, default=str))

if not relevant:
    # Fallback: print first 5 properties to see the schema shape
    print("\n  Couldn't find target properties — showing first 5 to see schema:")
    for p in all_props[:5]:
        print(json.dumps(p, indent=4, default=str))

# 2. Get a real asset_id and tag value
print()
print("=" * 70)
print("  STEP 2: Sample a real asset_id and observed tag from findings")
print("=" * 70)
r = c.post(
    "/api/v1/t1/inventory/findings/search",
    params={"offset": 0, "limit": 50, "extra_properties": "asset_name,tag_names,tag_ids"},
    json={},
)
findings = r.json().get("data", [])
baseline = r.json().get("pagination", {}).get("total", 0)
print(f"  Baseline: {baseline:,}")

# Find one with tags
sample_with_tag = None
for f in findings:
    extra = f.get("extra_properties", {}) or {}
    if extra.get("tag_names"):
        sample_with_tag = f
        break

sample_aid = sample_with_tag.get("asset_id") if sample_with_tag else findings[0].get("asset_id")
sample_tag = (sample_with_tag.get("extra_properties", {}) or {}).get("tag_names", [None])[0] if sample_with_tag else None
sample_tag_id = (sample_with_tag.get("extra_properties", {}) or {}).get("tag_ids", [None])[0] if sample_with_tag else None
print(f"  Sample asset_id: {sample_aid}")
print(f"  Sample tag_name: {sample_tag}")
print(f"  Sample tag_id:   {sample_tag_id}")

# 3. Try filters with documented property names
print()
print("=" * 70)
print("  STEP 3: Filter findings using documented property names")
print("=" * 70)

shapes = [
    # asset_id (singular — this is the documented property name)
    ("asset_id eq str",          {"filters": [{"property": "asset_id", "operator": "eq", "value": sample_aid}]}),
    ("asset_id equal str",       {"filters": [{"property": "asset_id", "operator": "equal", "value": sample_aid}]}),
    ("asset_id =",               {"filters": [{"property": "asset_id", "operator": "=", "value": sample_aid}]}),
    ("asset_id is str",          {"filters": [{"property": "asset_id", "operator": "is", "value": sample_aid}]}),
    ("asset_id in [str]",        {"filters": [{"property": "asset_id", "operator": "in", "value": [sample_aid]}]}),
    ("asset_id is_one_of [str]", {"filters": [{"property": "asset_id", "operator": "is_one_of", "value": [sample_aid]}]}),
]

if sample_tag:
    shapes.extend([
        ("tag_name eq str (singular)", {"filters": [{"property": "tag_name", "operator": "eq", "value": sample_tag}]}),
        ("tag_name = str",             {"filters": [{"property": "tag_name", "operator": "=", "value": sample_tag}]}),
        ("tag_name is str",            {"filters": [{"property": "tag_name", "operator": "is", "value": sample_tag}]}),
        ("tag_name in [str]",          {"filters": [{"property": "tag_name", "operator": "in", "value": [sample_tag]}]}),
    ])

if sample_tag_id:
    shapes.extend([
        ("tag_ids eq str",         {"filters": [{"property": "tag_ids", "operator": "eq", "value": sample_tag_id}]}),
        ("tag_ids in [str]",       {"filters": [{"property": "tag_ids", "operator": "in", "value": [sample_tag_id]}]}),
    ])

for label, body in shapes:
    r = c.post(
        "/api/v1/t1/inventory/findings/search",
        params={"offset": 0, "limit": 1},
        json=body,
    )
    if r.status_code == 200:
        total = r.json().get("pagination", {}).get("total", 0)
        if total == baseline:
            tag = "(IGNORED)"
        elif total == 0:
            tag = "(0 match)"
        else:
            tag = "GENUINE!"
        print(f"  200  total={total:>10,}  {tag:<10}  {label}")
    else:
        msg = r.text[:120].replace("\n", " ")
        print(f"  {r.status_code}  {label}: {msg}")

c.close()
