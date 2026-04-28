#!/usr/bin/env python3
"""Verify the user's discovery: query.mode=simple + query.text works.

Tests:
  1. assets/search with text=<tag_name> — should return ~33K tagged assets
  2. assets/search with text=<asset_id> — should return 1 asset
  3. findings/search with text=<tag_name> — does it work too?
  4. findings/search with text=<asset_id> — does it filter findings by asset?
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

target_tag = "Portfolio-Business-Growth"
for i, a in enumerate(sys.argv):
    if a == "--tag" and i + 1 < len(sys.argv):
        target_tag = sys.argv[i + 1]

c = httpx.Client(
    base_url=BASE_URL,
    headers={
        "X-ApiKeys": f"accessKey={ACCESS_KEY};secretKey={SECRET_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    },
    timeout=120,
)

# Baselines
r = c.post("/api/v1/t1/inventory/assets/search", params={"offset": 0, "limit": 1}, json={})
baseline_assets = r.json().get("pagination", {}).get("total", 0) if r.status_code == 200 else 0
r = c.post("/api/v1/t1/inventory/findings/search", params={"offset": 0, "limit": 1}, json={})
baseline_findings = r.json().get("pagination", {}).get("total", 0) if r.status_code == 200 else 0
print(f"Baselines  →  assets={baseline_assets:,}  findings={baseline_findings:,}")
print()

# 1. assets/search with tag name as simple text
print("=" * 70)
print("  TEST 1: assets/search with query.text = '<tag>'")
print("=" * 70)
body = {"query": {"mode": "simple", "text": target_tag}}
r = c.post(
    "/api/v1/t1/inventory/assets/search",
    params={"offset": 0, "limit": 5, "extra_properties": "asset_id,asset_name,tag_names"},
    json=body,
)
if r.status_code == 200:
    data = r.json()
    total = data.get("pagination", {}).get("total", 0)
    print(f"  Total: {total:,} (baseline {baseline_assets:,})")
    if total > 0 and total != baseline_assets:
        print(f"  GENUINE filter — got {total} tagged assets")
    elif total == baseline_assets:
        print(f"  IGNORED")
    else:
        print(f"  0 match — text search didn't find anything")
    sample = data.get("data", [])
    sample_aid = None
    for s in sample[:3]:
        extra = s.get("extra_properties", {}) or {}
        print(f"    - id={s.get('id')}  tags={extra.get('tag_names')}")
        if not sample_aid:
            sample_aid = s.get("id") or s.get("asset_id")
else:
    print(f"  {r.status_code}: {r.text[:200]}")
    sample_aid = None

# 2. assets/search with asset_id as simple text
if sample_aid:
    print()
    print("=" * 70)
    print(f"  TEST 2: assets/search with query.text = '<asset_id={sample_aid[:20]}...>'")
    print("=" * 70)
    body = {"query": {"mode": "simple", "text": sample_aid}}
    r = c.post(
        "/api/v1/t1/inventory/assets/search",
        params={"offset": 0, "limit": 3, "extra_properties": "asset_id,asset_name"},
        json=body,
    )
    if r.status_code == 200:
        data = r.json()
        total = data.get("pagination", {}).get("total", 0)
        print(f"  Total: {total:,}")
        if total == 1:
            print(f"  GENUINE — exactly 1 asset matched")
        elif total > 0 and total != baseline_assets:
            print(f"  filtered to {total}")
        elif total == baseline_assets:
            print(f"  IGNORED")
    else:
        print(f"  {r.status_code}: {r.text[:200]}")

# 3. findings/search with tag name as simple text
print()
print("=" * 70)
print(f"  TEST 3: findings/search with query.text = '{target_tag}'")
print("=" * 70)
body = {"query": {"mode": "simple", "text": target_tag}}
r = c.post(
    "/api/v1/t1/inventory/findings/search",
    params={"offset": 0, "limit": 3, "extra_properties": "asset_name,tag_names"},
    json=body,
)
if r.status_code == 200:
    data = r.json()
    total = data.get("pagination", {}).get("total", 0)
    print(f"  Total: {total:,} (baseline {baseline_findings:,})")
    if total > 0 and total != baseline_findings:
        print(f"  GENUINE!  This is the cleanest path forward.")
    elif total == baseline_findings:
        print(f"  IGNORED — text search didn't filter findings")
    else:
        print(f"  0 match")
else:
    print(f"  {r.status_code}: {r.text[:200]}")

# 4. findings/search with asset_id as simple text
if sample_aid:
    print()
    print("=" * 70)
    print(f"  TEST 4: findings/search with query.text = '<asset_id>'")
    print("=" * 70)
    body = {"query": {"mode": "simple", "text": sample_aid}}
    r = c.post(
        "/api/v1/t1/inventory/findings/search",
        params={"offset": 0, "limit": 3, "extra_properties": "asset_name"},
        json=body,
    )
    if r.status_code == 200:
        data = r.json()
        total = data.get("pagination", {}).get("total", 0)
        print(f"  Total: {total:,} (baseline {baseline_findings:,})")
        if total > 0 and total != baseline_findings:
            print(f"  GENUINE — got {total} findings for this asset")
        elif total == baseline_findings:
            print(f"  IGNORED")
        else:
            print(f"  0 match")
    else:
        print(f"  {r.status_code}: {r.text[:200]}")

c.close()
