#!/usr/bin/env python3
"""Test passing tag_id (and other tag identifiers) as query parameters
on the findings/search endpoint."""

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
tag = match[0] if match else None
if not tag:
    print(f"Tag {target} not found")
    sys.exit(1)
tag_id = tag.get("id")
expected_assets = tag.get("asset_count", "?")
expected_findings = tag.get("total_weakness_count", "?")
print(f"Tag: {target}  id={tag_id}")
print(f"Expected asset_count: {expected_assets}")
print(f"Expected weakness_count: {expected_findings}")
print()

# Baselines
r = c.post("/api/v1/t1/inventory/assets/search", params={"offset": 0, "limit": 1}, json={})
asset_baseline = r.json().get("pagination", {}).get("total", 0)
r = c.post("/api/v1/t1/inventory/findings/search", params={"offset": 0, "limit": 1}, json={})
finding_baseline = r.json().get("pagination", {}).get("total", 0)
print(f"Asset baseline:   {asset_baseline:,}")
print(f"Finding baseline: {finding_baseline:,}")
print()

# =====================================================================
# PART 1: Confirm assets/search?tag_id=... actually filters
# =====================================================================
print("=" * 70)
print("  PART 1: Confirm assets/search?tag_id=X is a real filter")
print("=" * 70)

r = c.post(
    "/api/v1/t1/inventory/assets/search",
    params={"offset": 0, "limit": 5, "tag_id": tag_id},
    json={},
)
if r.status_code == 200:
    data = r.json()
    total = data.get("pagination", {}).get("total", 0)
    items = data.get("data", [])
    print(f"  status: 200")
    print(f"  total: {total:,}  (baseline {asset_baseline:,}, expected {expected_assets})")
    if items:
        print(f"  sample asset:")
        print(f"    {json.dumps(items[0], default=str)[:400]}")
    if total != asset_baseline and total > 0:
        print(f"  >>> GENUINE filter — returns ~{total} tagged assets")
    elif total == asset_baseline:
        print(f"  IGNORED — same as baseline")
else:
    print(f"  status: {r.status_code}: {r.text[:300]}")

# =====================================================================
# PART 2: Try various query-param forms on findings/search
# =====================================================================
print()
print("=" * 70)
print("  PART 2: Try query-param tag filters on findings/search")
print("=" * 70)

param_attempts = [
    {"tag_id": tag_id},
    {"tag_ids": tag_id},
    {"tag_name": target},
    {"tag_names": target},
    {"tags": tag_id},
    {"tag": tag_id},
    {"filter[tag_id]": tag_id},
    {"asset.tag_id": tag_id},
]

for params in param_attempts:
    p = {"offset": 0, "limit": 1, **params}
    r = c.post("/api/v1/t1/inventory/findings/search", params=p, json={})
    if r.status_code != 200:
        msg = r.text[:120].replace("\n", " ")
        print(f"  {r.status_code:>3}  params={params}")
        print(f"        {msg}")
        continue
    total = r.json().get("pagination", {}).get("total", 0)
    if total == finding_baseline:
        print(f"  {total:>10,}  (IGNORED)   params={params}")
    elif total == 0:
        print(f"  {total:>10,}  (0 match)   params={params}")
    else:
        print(f"  {total:>10,}  GENUINE     params={params}")

c.close()
