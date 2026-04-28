#!/usr/bin/env python3
"""Test if findings/search with mode=simple can filter server-side
by asset_id (or anything useful).

The user observed:
  - findings/search ONLY supports query.mode=simple (advanced fails)
  - We need to test what query.text values actually filter

Tries:
  1. text = '<asset_id>' literally
  2. text = blank with extra_properties=asset_id (just to see)
  3. text = 'asset_id:<id>' format
  4. various other text shapes
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

# Get baseline & a real asset_id
print("Fetching baseline + sample asset_id...")
r = c.post(
    "/api/v1/t1/inventory/findings/search",
    params={"offset": 0, "limit": 1, "extra_properties": "asset_name"},
    json={},
)
baseline = r.json().get("pagination", {}).get("total", 0)
sample = r.json().get("data", [{}])[0]
sample_aid = sample.get("asset_id")
print(f"  Baseline findings: {baseline:,}")
print(f"  Sample asset_id:   {sample_aid}")
print()

EXTRA = "asset_name,asset_id"

shapes = [
    ("Empty body (control)",                {}),
    ("query mode=simple, no text",          {"query": {"mode": "simple"}}),
    ("query mode=simple, text=''",          {"query": {"mode": "simple", "text": ""}}),
    ("query mode=simple, text=<asset_id>",  {"query": {"mode": "simple", "text": sample_aid}}),
    ("query mode=simple, text='asset_id:<id>'", {"query": {"mode": "simple", "text": f"asset_id:{sample_aid}"}}),
    ("query mode=simple, text='asset_id = <id>'", {"query": {"mode": "simple", "text": f'asset_id = "{sample_aid}"'}}),
    ("query mode=simple, text='asset_id:\"<id>\"'", {"query": {"mode": "simple", "text": f'asset_id:"{sample_aid}"'}}),
    ("query mode=simple, text=Findings...",  {"query": {"mode": "simple", "text": f'Findings HAS asset_id = "{sample_aid}"'}}),
    ("filters[]: property/operator/value (with body)",
     {"filters": [{"property": "asset_id", "operator": "eq", "value": sample_aid}],
      "query": {"mode": "simple"}}),
    ("filters[] only, no query",
     {"filters": [{"property": "asset_id", "operator": "eq", "value": sample_aid}]}),
]

print("Probing simple mode shapes:")
print("=" * 70)
genuine = []
for label, body in shapes:
    r = c.post(
        "/api/v1/t1/inventory/findings/search",
        params={"offset": 0, "limit": 3, "extra_properties": EXTRA},
        json=body,
    )
    if r.status_code != 200:
        msg = r.text[:150].replace("\n", " ")
        print(f"  {r.status_code}  {label}")
        print(f"        {msg}")
        continue
    data = r.json()
    total = data.get("pagination", {}).get("total", 0)
    items = data.get("data", [])

    # Check if all returned findings actually have the target asset_id
    if items and all(f.get("asset_id") == sample_aid for f in items):
        verdict = "ALL MATCH ASSET_ID"
    elif items:
        match_count = sum(1 for f in items if f.get("asset_id") == sample_aid)
        verdict = f"{match_count}/{len(items)} match"
    else:
        verdict = "no items"

    if total == baseline:
        tag = "(IGNORED — baseline)"
    elif total == 0:
        tag = "(0 match)"
    elif total < baseline:
        tag = f"GENUINE — {verdict}"
        genuine.append((label, body, total))
    else:
        tag = f"unexpected ({verdict})"

    print(f"  200  total={total:>10,}  {tag}")
    print(f"       label: {label}")

print()
print("=" * 70)
if genuine:
    print(f"WORKING SHAPES ({len(genuine)}):")
    for label, body, total in genuine:
        print(f"\n  {label}  →  {total:,} findings")
        print(f"  Body: {json.dumps(body)}")
else:
    print("No server-side asset_id filtering on findings/search.")
    print("Confirms we need client-side filtering by asset_id set.")
print("=" * 70)

c.close()
