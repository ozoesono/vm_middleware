#!/usr/bin/env python3
"""Test the 'query.text' / 'mode' approach using Tenable Query Language.

The UI shows: textQuery = "tag_names has Portfolio-Business-Growth", mode = Advanced
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
    target = "Portfolio-Business-Growth"

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
r = c.post("/api/v1/t1/inventory/findings/search", params={"offset": 0, "limit": 1}, json={})
baseline = r.json().get("pagination", {}).get("total", 0)
print(f"Baseline (unfiltered): {baseline:,}")
print()

shapes = [
    ("query.text + mode=Advanced",
     {"query": {"text": f"tag_names has {target}", "mode": "Advanced"}}),
    ("query.text + mode=advanced (lowercase)",
     {"query": {"text": f"tag_names has {target}", "mode": "advanced"}}),
    ("query.text + mode=Simple",
     {"query": {"text": target, "mode": "Simple"}}),
    ("query.textQuery + mode",
     {"query": {"textQuery": f"tag_names has {target}", "mode": "Advanced"}}),
    ("textQuery + mode at top level",
     {"textQuery": f"tag_names has {target}", "mode": "Advanced"}),
    ("query.text quoted value",
     {"query": {"text": f'tag_names has "{target}"', "mode": "Advanced"}}),
    ("query.text equals operator",
     {"query": {"text": f"tag_names = {target}", "mode": "Advanced"}}),
    ("query.text eq operator",
     {"query": {"text": f"tag_names eq {target}", "mode": "Advanced"}}),
    ("with Findings prefix",
     {"query": {"text": f"Findings has tag_names {target}", "mode": "Advanced"}}),
]

print(f"Trying with tag = '{target}'")
print("-" * 70)
for label, body in shapes:
    r = c.post(
        "/api/v1/t1/inventory/findings/search",
        params={"offset": 0, "limit": 3, "extra_properties": "asset_name,tag_names"},
        json=body,
    )
    if r.status_code != 200:
        msg = r.text[:150].replace("\n", " ")
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
        # Sample
        for f in r.json().get("data", [])[:2]:
            extra = f.get("extra_properties", {}) or {}
            print(f"            - {f.get('name')} | {extra.get('asset_name')} | tags={extra.get('tag_names')}")

c.close()
