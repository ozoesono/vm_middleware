#!/usr/bin/env python3
"""Probe many different filter shapes to find what Tenable accepts.

Usage:
    .venv/bin/python3 scripts/probe_filter_shapes.py --tag Portfolio-Business-Growth
"""

import os
import sys
import json
from pathlib import Path

env_path = Path(__file__).parent.parent / ".env"
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())

import httpx

BASE_URL = os.environ.get("TENABLE_BASE_URL", "https://cloud.tenable.com")
ACCESS_KEY = os.environ.get("TENABLE_ACCESS_KEY", "")
SECRET_KEY = os.environ.get("TENABLE_SECRET_KEY", "")

target = None
for i, arg in enumerate(sys.argv):
    if arg == "--tag" and i + 1 < len(sys.argv):
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

# Lookup tag id
r = client.post("/api/v1/t1/tags/search", params={"limit": 500}, json={})
tags = r.json().get("data", [])
match = [t for t in tags if isinstance(t, dict) and t.get("name", "").lower() == target.lower()]
if not match:
    print(f"Tag '{target}' not found.")
    sys.exit(1)
tag_id = match[0].get("id")
tag_name = match[0].get("name")
print(f"Tag: {tag_name}  id={tag_id}")
print()

# A wide variety of filter shapes
shapes = [
    # Original style
    ("filters[]: property/operator/value (string)",
     {"filters": [{"property": "tag_names", "operator": "eq", "value": tag_name}]}),

    # Different field name for value
    ("filters[]: property/operator/values (plural array)",
     {"filters": [{"property": "tag_names", "operator": "eq", "values": [tag_name]}]}),

    # filter (singular) instead of filters
    ("filter (singular): property/operator/value",
     {"filter": {"property": "tag_names", "operator": "eq", "value": tag_name}}),

    # query wrapper
    ("query.filters: property/operator/value",
     {"query": {"filters": [{"property": "tag_names", "operator": "eq", "value": tag_name}]}}),

    # field/op/value naming
    ("filters[]: field/op/value",
     {"filters": [{"field": "tag_names", "op": "eq", "value": tag_name}]}),

    # name/operator/value
    ("filters[]: name/operator/value",
     {"filters": [{"name": "tag_names", "operator": "eq", "value": tag_name}]}),

    # Logical AND wrapper
    ("filters.and[]",
     {"filters": {"and": [{"property": "tag_names", "operator": "eq", "value": tag_name}]}}),

    # Object value
    ("filters[]: value as object",
     {"filters": [{"property": "tag_names", "operator": "eq", "value": {"text": tag_name}}]}),

    # Simple key/value style
    ("filters[]: just {property: value}",
     {"filters": [{"tag_names": tag_name}]}),

    # Boolean shape (some APIs use this)
    ("filter object with bool combinator",
     {"filter": {"and": [{"tag_names": {"eq": tag_name}}]}}),

    # Search field shape
    ("search.filters[]",
     {"search": {"filters": [{"property": "tag_names", "operator": "eq", "value": tag_name}]}}),

    # Nested condition
    ("filter.condition",
     {"filter": {"condition": [{"property": "tag_names", "operator": "eq", "value": tag_name}]}}),

    # Free-text query
    ("query.text",
     {"query": {"mode": "simple", "text": tag_name}}),

    # Try by tag_ids with same shapes
    ("filters[]: tag_ids/eq/string id",
     {"filters": [{"property": "tag_ids", "operator": "eq", "value": tag_id}]}),

    ("filters[]: tag_ids/eq/array",
     {"filters": [{"property": "tag_ids", "operator": "eq", "value": [tag_id]}]}),
]

EXTRA = "asset_name,tag_names,tag_ids"
url = "/api/v1/t1/inventory/findings/search"

print("Probing...")
print("-" * 70)
working = []
for label, body in shapes:
    r = client.post(
        url,
        params={"offset": 0, "limit": 1, "extra_properties": EXTRA},
        json=body,
    )
    code = r.status_code
    if code == 200:
        total = r.json().get("pagination", {}).get("total", 0)
        marker = " <<< MATCHES" if total > 0 else ""
        print(f"  200  total={total:>10,}  {label}{marker}")
        if total > 0:
            working.append((label, body, total))
    elif code == 400:
        msg = r.text[:120].replace("\n", " ")
        print(f"  400  {label}")
        print(f"       {msg}")
    else:
        print(f"  {code}  {label}")

print()
print("=" * 70)
if working:
    print(f"  WORKING SHAPES ({len(working)}):")
    for label, body, total in working:
        print(f"\n  [{label}] — {total:,} findings")
        print(f"  Body: {json.dumps(body)}")
else:
    print("  No shape returned matching findings.")
    print("  All 200-OK shapes returned 0 results — they are likely")
    print("  ignored, not applied. Need a different approach.")
print("=" * 70)

client.close()
