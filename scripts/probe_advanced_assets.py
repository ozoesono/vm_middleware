#!/usr/bin/env python3
"""Verify that assets/search with mode=advanced + 'Assets HAS tag_names = "X"'
genuinely filters assets to those with the tag.
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

# Baseline
r = c.post("/api/v1/t1/inventory/assets/search", params={"offset": 0, "limit": 1}, json={})
baseline = r.json().get("pagination", {}).get("total", 0)
print(f"Assets baseline: {baseline:,}\n")

queries = [
    f'Assets HAS tag_names = "{target}"',
    f"Assets HAS tag_names = '{target}'",
    f'Assets HAS tag_names:"{target}"',
    f"Assets HAS tag_names:'{target}'",
    f'AS Asset HAS tag_names = "{target}"',
    f'HAS tag_names = "{target}"',
    f'tag_names = "{target}"',
    f"tag_names:'{target}'",
]

print("=" * 70)
print(f"  Trying advanced queries to filter assets by tag '{target}'")
print("=" * 70)
working = None
for q in queries:
    body = {"query": {"mode": "advanced", "text": q}}
    r = c.post(
        "/api/v1/t1/inventory/assets/search",
        params={"offset": 0, "limit": 5, "extra_properties": "asset_id,asset_name,tag_names"},
        json=body,
    )
    if r.status_code != 200:
        msg = r.text[:120].replace("\n", " ")
        print(f"  {r.status_code}  {q!r}")
        print(f"        {msg}")
        continue
    data = r.json()
    total = data.get("pagination", {}).get("total", 0)
    if total == baseline:
        print(f"  200  total={total:>10,}  (IGNORED)  {q!r}")
    elif total == 0:
        print(f"  200  total={total:>10,}  (0 match)  {q!r}")
    else:
        print(f"  200  total={total:>10,}  GENUINE!   {q!r}")
        # Show sample
        for a in data.get("data", [])[:3]:
            extra = a.get("extra_properties", {}) or {}
            print(f"            id={a.get('id')}  name={extra.get('asset_name')}")
            print(f"            tags={extra.get('tag_names')}")
        if not working:
            working = q

print()
print("=" * 70)
if working:
    print(f"  WINNER: {working!r}")
    print()
    print("  Use this on assets/search to get the tagged asset IDs,")
    print("  then in our middleware we can build a set and filter findings")
    print("  client-side by asset_id IN <set>.")
else:
    print("  No working query found. The advanced query syntax may differ.")
print("=" * 70)

c.close()
