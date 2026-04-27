#!/usr/bin/env python3
"""Compare filtered vs unfiltered totals to detect silently-ignored filters.

Usage:
    .venv/bin/python3 scripts/probe_compare.py --tag Portfolio-Business-Growth
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
if not match:
    print(f"Tag {target} not found")
    sys.exit(1)
tag = match[0]
tag_id = tag.get("id")
tag_name = tag.get("name")
expected = tag.get("total_weakness_count", "?")
print(f"Tag: {tag_name}  id={tag_id}")
print(f"Tag-API reports total_weakness_count = {expected:,}")
print(f"(In the UI you see ~163,000 for this tag)")
print()

# Get unfiltered baseline
print("Baseline (no filter)...")
r = client.post(
    "/api/v1/t1/inventory/findings/search",
    params={"offset": 0, "limit": 1, "extra_properties": "tag_names"},
    json={},
)
baseline = r.json().get("pagination", {}).get("total", 0)
print(f"  Unfiltered total = {baseline:,}")
print()

# Run each candidate shape and compare to baseline
shapes = [
    ("filters[]: property/operator/value (string)",
     {"filters": [{"property": "tag_names", "operator": "eq", "value": tag_name}]}),

    ("filter object with bool combinator",
     {"filter": {"and": [{"tag_names": {"eq": tag_name}}]}}),

    ("search.filters[]",
     {"search": {"filters": [{"property": "tag_names", "operator": "eq", "value": tag_name}]}}),

    ("filter.condition",
     {"filter": {"condition": [{"property": "tag_names", "operator": "eq", "value": tag_name}]}}),

    # Try operators other than eq
    ("filters[]: tag_names/has/string",
     {"filters": [{"property": "tag_names", "operator": "has", "value": tag_name}]}),

    ("filters[]: tag_names/contains/string",
     {"filters": [{"property": "tag_names", "operator": "contains", "value": tag_name}]}),

    ("filters[]: tag_names/in/array",
     {"filters": [{"property": "tag_names", "operator": "in", "value": [tag_name]}]}),

    ("filters[]: tag_names/exists/true",
     {"filters": [{"property": "tag_names", "operator": "exists", "value": True}]}),

    # Try tag_ids variants
    ("filters[]: tag_ids/eq/string",
     {"filters": [{"property": "tag_ids", "operator": "eq", "value": tag_id}]}),

    ("filters[]: tag_ids/in/array",
     {"filters": [{"property": "tag_ids", "operator": "in", "value": [tag_id]}]}),
]

print("Comparing filter results to baseline:")
print("-" * 70)
genuine_matches = []
for label, body in shapes:
    r = client.post(
        "/api/v1/t1/inventory/findings/search",
        params={"offset": 0, "limit": 1, "extra_properties": "tag_names"},
        json=body,
    )
    if r.status_code != 200:
        print(f"  {r.status_code}  {label}")
        continue
    total = r.json().get("pagination", {}).get("total", 0)
    if total == baseline:
        marker = "(IGNORED — same as baseline)"
    elif total == 0:
        marker = "(applied but 0 matches)"
    else:
        marker = "<<< GENUINE FILTER"
        genuine_matches.append((label, body, total))
    print(f"  {total:>12,}  {marker}  — {label}")

print()
print("=" * 70)
if genuine_matches:
    print(f"GENUINE WORKING FILTERS ({len(genuine_matches)}):")
    for label, body, total in genuine_matches:
        print(f"\n  {label}  →  {total:,} findings")
        print(f"  Body: {json.dumps(body)}")
else:
    print("No genuine filter found.")
    print("Either the filter property name is different, or filtering at this")
    print("endpoint isn't supported. May need to filter via Assets endpoint then")
    print("look up findings by asset_id.")
print("=" * 70)

client.close()
