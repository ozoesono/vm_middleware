#!/usr/bin/env python3
"""Try every plausible filter shape for asset_id on findings/search."""

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

# Get a real asset_id from a real finding
print("Sampling a real asset_id from a finding...")
r = c.post(
    "/api/v1/t1/inventory/findings/search",
    params={"offset": 0, "limit": 1, "extra_properties": "asset_name"},
    json={},
)
sample_aid = r.json().get("data", [{}])[0].get("asset_id")
print(f"  Sample asset_id: {sample_aid}\n")

baseline = r.json().get("pagination", {}).get("total", 0)
print(f"Baseline: {baseline:,}\n")

# Many shape variations
shapes = [
    # Standard filter shapes with different operators
    ("filters[]: asset_id eq str",         {"filters": [{"property": "asset_id", "operator": "eq", "value": sample_aid}]}),
    ("filters[]: asset_id = str",          {"filters": [{"property": "asset_id", "operator": "=", "value": sample_aid}]}),
    ("filters[]: asset_id equals str",     {"filters": [{"property": "asset_id", "operator": "equals", "value": sample_aid}]}),
    ("filters[]: asset_id is str",         {"filters": [{"property": "asset_id", "operator": "is", "value": sample_aid}]}),
    ("filters[]: asset_id has str",        {"filters": [{"property": "asset_id", "operator": "has", "value": sample_aid}]}),
    ("filters[]: asset_id has [str]",      {"filters": [{"property": "asset_id", "operator": "has", "value": [sample_aid]}]}),
    ("filters[]: asset_id contains str",   {"filters": [{"property": "asset_id", "operator": "contains", "value": sample_aid}]}),
    ("filters[]: asset_id contains [str]", {"filters": [{"property": "asset_id", "operator": "contains", "value": [sample_aid]}]}),
    ("filters[]: asset_id in [str]",       {"filters": [{"property": "asset_id", "operator": "in", "value": [sample_aid]}]}),
    ("filters[]: asset_id in str",         {"filters": [{"property": "asset_id", "operator": "in", "value": sample_aid}]}),
    ("filters[]: asset_id eq [str]",       {"filters": [{"property": "asset_id", "operator": "eq", "value": [sample_aid]}]}),
    ("filters[]: asset_id is_one_of [str]",{"filters": [{"property": "asset_id", "operator": "is_one_of", "value": [sample_aid]}]}),
    ("filters[]: asset_id one_of [str]",   {"filters": [{"property": "asset_id", "operator": "one_of", "value": [sample_aid]}]}),
    ("filters[]: asset_id any [str]",      {"filters": [{"property": "asset_id", "operator": "any", "value": [sample_aid]}]}),
    # Query string approach
    ("query.text=asset_id eq, mode=Advanced", {"query": {"text": f"asset_id = {sample_aid}", "mode": "Advanced"}}),
    ("query.text=asset_id is, mode=Advanced", {"query": {"text": f"asset_id is {sample_aid}", "mode": "Advanced"}}),
]

print("Trying shapes:")
print("-" * 70)
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
        print(f"  200  total={total:>10,}  {tag}  {label}")
    else:
        msg = r.text[:120].replace("\n", " ")
        print(f"  {r.status_code:>3}  {label}")
        print(f"        {msg}")

c.close()
