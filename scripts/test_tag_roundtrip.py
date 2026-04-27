#!/usr/bin/env python3
"""Verify the tag taxonomy round-trip with a real Tenable tag.

This script:
1. Looks up a tag in Tenable by name (e.g., "Environment-Prod")
2. Confirms the API returns the full taxonomic name
3. Fetches findings linked to assets with that tag
4. Parses the tag through our middleware parser
5. Reports what enrichment fields would be populated

Usage:
    .venv/bin/python3 scripts/test_tag_roundtrip.py --tag Environment-Prod
"""

import os
import sys
from pathlib import Path

# Load .env
env_path = Path(__file__).parent.parent / ".env"
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())

# Make src importable
sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx
from src.common.tag_parser import parse_tag, parse_tags, CATEGORY_TO_FIELD

BASE_URL = os.environ.get("TENABLE_BASE_URL", "https://cloud.tenable.com")
ACCESS_KEY = os.environ.get("TENABLE_ACCESS_KEY", "")
SECRET_KEY = os.environ.get("TENABLE_SECRET_KEY", "")

if not ACCESS_KEY or not SECRET_KEY:
    print("ERROR: Set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY in .env")
    sys.exit(1)

target_tag = None
for i, arg in enumerate(sys.argv):
    if arg == "--tag" and i + 1 < len(sys.argv):
        target_tag = sys.argv[i + 1]

if not target_tag:
    print("Usage: test_tag_roundtrip.py --tag <Tag-Name>")
    print("Example: test_tag_roundtrip.py --tag Environment-Prod")
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

# =====================================================================
# STEP 1: Confirm the tag exists in Tenable
# =====================================================================
print("=" * 70)
print(f"  STEP 1: Looking up tag '{target_tag}' in Tenable")
print("=" * 70)

response = client.post("/api/v1/t1/tags/search", params={"limit": 500}, json={})
if response.status_code != 200:
    print(f"  ERROR {response.status_code}: {response.text[:300]}")
    sys.exit(1)

tags = response.json().get("data", [])
matches = [t for t in tags if isinstance(t, dict) and t.get("name", "").lower() == target_tag.lower()]

if not matches:
    print(f"  Tag '{target_tag}' NOT found in Tenable.")
    print(f"  Make sure you've created it with the Value field set to '{target_tag}'.")
    sys.exit(1)

tag = matches[0]
tag_id = tag.get("id")
tag_name = tag.get("name")
asset_count = tag.get("asset_count", 0)
weakness_count = tag.get("total_weakness_count", 0)

print(f"  Tag found")
print(f"    name (from API):    '{tag_name}'")
print(f"    id:                 {tag_id}")
print(f"    assets tagged:      {asset_count}")
print(f"    total weaknesses:   {weakness_count}")

# Verify API returns the full taxonomic name (this is the round-trip check)
if tag_name == target_tag:
    print(f"  Round-trip OK — the API returns the full name as expected.")
else:
    print(f"  WARNING — API returned '{tag_name}' but you asked for '{target_tag}'")

# =====================================================================
# STEP 2: Parse the tag through the middleware parser
# =====================================================================
print()
print("=" * 70)
print(f"  STEP 2: Parsing '{tag_name}' through the middleware parser")
print("=" * 70)

parsed = parse_tag(tag_name)
print(f"  Raw tag:        '{parsed.raw}'")
print(f"  Category:       '{parsed.category}'")
print(f"  Value:          '{parsed.value}'")
print(f"  Valid?          {parsed.is_valid}")
if parsed.warning:
    print(f"  Warning:        {parsed.warning}")

if parsed.is_valid:
    field = CATEGORY_TO_FIELD.get(parsed.category, "<not mapped to a field>")
    print(f"  Maps to field:  {field}")

# =====================================================================
# STEP 3: Fetch findings on assets with this tag
# =====================================================================
print()
print("=" * 70)
print(f"  STEP 3: Fetching findings on tagged assets")
print("=" * 70)

# Try filtering findings by tag_ids contains [tag_id]
EXTRA_PROPS = "asset_name,sensor_type,tag_names,tag_ids,finding_vpr_score,finding_cves"
response = client.post(
    "/api/v1/t1/inventory/findings/search",
    params={"offset": 0, "limit": 5, "extra_properties": EXTRA_PROPS},
    json={"filters": [{"property": "tag_ids", "operator": "contains", "value": [tag_id]}]},
)

if response.status_code != 200:
    print(f"  Filter on findings endpoint failed: {response.status_code}")
    print(f"  {response.text[:300]}")
    print()
    print("  Falling back: fetching unfiltered findings to find tagged ones...")
    response = client.post(
        "/api/v1/t1/inventory/findings/search",
        params={"offset": 0, "limit": 50, "extra_properties": EXTRA_PROPS},
        json={},
    )

if response.status_code == 200:
    data = response.json()
    findings = data.get("data", [])
    total = data.get("pagination", {}).get("total", 0)
    print(f"  Total findings: {total:,}")

    # Find findings whose tag_names contains our target
    tagged_findings = []
    for f in findings:
        extra = f.get("extra_properties", {}) or {}
        tag_names_list = extra.get("tag_names") or []
        if target_tag.lower() in [t.lower() for t in tag_names_list]:
            tagged_findings.append(f)

    print(f"  Findings showing this tag in tag_names: {len(tagged_findings)}")

    if tagged_findings:
        print()
        print("  --- Sample finding ---")
        f = tagged_findings[0]
        extra = f.get("extra_properties", {}) or {}
        print(f"    Finding:    {f.get('name')}")
        print(f"    Asset:      {extra.get('asset_name', 'N/A')}")
        print(f"    Tag names:  {extra.get('tag_names', [])}")
        print()
        print("  --- Middleware enrichment for this finding ---")
        parsed_dict, all_parsed = parse_tags(extra.get("tag_names", []))
        if parsed_dict:
            for cat, val in parsed_dict.items():
                field = CATEGORY_TO_FIELD.get(cat, "?")
                print(f"    {field:<25}: {val}")
        else:
            print(f"    (no taxonomic tags found on this finding)")

        invalid = [p for p in all_parsed if not p.is_valid]
        if invalid:
            print()
            print("  --- Invalid tags (would be warnings in middleware) ---")
            for p in invalid:
                print(f"    '{p.raw}' — {p.warning}")
    else:
        print()
        print("  Findings exist but none in this sample show the tag.")
        print("  This is normal if tags aren't applied to many assets yet.")

print()
print("=" * 70)
print("  Round-trip test complete.")
print("=" * 70)

client.close()
