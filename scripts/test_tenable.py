#!/usr/bin/env python3
"""Quick test script to discover available properties and pull findings from Tenable.

Usage:
    .venv/bin/python3 scripts/test_tenable.py              # discover properties + fetch findings
    .venv/bin/python3 scripts/test_tenable.py --props-only  # just list available properties
"""

import os
import sys
import json
from pathlib import Path
from collections import Counter

# Load .env file
env_path = Path(__file__).parent.parent / ".env"
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())

import httpx

# Config
BASE_URL = os.environ.get("TENABLE_BASE_URL", "https://cloud.tenable.com")
ACCESS_KEY = os.environ.get("TENABLE_ACCESS_KEY", "")
SECRET_KEY = os.environ.get("TENABLE_SECRET_KEY", "")

if not ACCESS_KEY or not SECRET_KEY:
    print("ERROR: Set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY in .env or environment")
    sys.exit(1)

PROPS_ENDPOINT = "/api/v1/t1/inventory/findings/properties"
SEARCH_ENDPOINT = "/api/v1/t1/inventory/findings/search"

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
# STEP 1: Discover available properties
# =====================================================================
print("=" * 70)
print("  STEP 1: Discovering available finding properties...")
print("=" * 70)

response = client.get(PROPS_ENDPOINT)
if response.status_code != 200:
    print(f"  ERROR: Properties endpoint returned {response.status_code}")
    print(f"  {response.text[:500]}")
    print()
    print("  Skipping property discovery, will try search without extra_properties...")
    available_props = []
else:
    props_data = response.json()

    # The response could be a list or dict with a data key
    if isinstance(props_data, list):
        available_props = props_data
    elif isinstance(props_data, dict):
        available_props = props_data.get("data", props_data.get("properties", []))
    else:
        available_props = []

    print(f"  Found {len(available_props)} properties")
    print()

    # Print all properties — we need to see what's available
    # Properties might be strings or dicts with name/key fields
    prop_names = []
    for p in available_props:
        if isinstance(p, str):
            prop_names.append(p)
        elif isinstance(p, dict):
            name = p.get("key") or p.get("name") or p.get("property") or str(p)
            prop_names.append(name)

    # Look for properties we care about
    keywords = ["vpr", "cvss", "cve", "severity", "source", "acr", "aes",
                "epss", "exploit", "tag", "first", "last", "seen", "asset",
                "solution", "plugin", "owner", "critical", "score", "risk",
                "portfolio", "service", "environment", "sensitivity"]

    print("  --- Properties matching our needs ---")
    matched = []
    for name in sorted(prop_names):
        name_lower = name.lower()
        if any(kw in name_lower for kw in keywords):
            matched.append(name)
            print(f"    {name}")

    print()
    print(f"  --- ALL available properties ({len(prop_names)} total) ---")
    for name in sorted(prop_names):
        marker = " <-- " if name in matched else ""
        print(f"    {name}{marker}")

    # Save to file for reference
    props_file = Path(__file__).parent.parent / "tenable_properties.json"
    with open(props_file, "w") as f:
        json.dump({"properties": prop_names, "raw": available_props}, f, indent=2, default=str)
    print()
    print(f"  Full properties saved to: {props_file}")

if "--props-only" in sys.argv:
    client.close()
    sys.exit(0)

# =====================================================================
# STEP 2: Fetch findings with discovered properties
# =====================================================================
print()
print("=" * 70)
print("  STEP 2: Fetching findings...")
print("=" * 70)

# Build extra_properties from discovered props — request the ones we need
desired_props = []
if prop_names:
    for name in prop_names:
        name_lower = name.lower()
        # Include properties relevant to our middleware
        if any(kw in name_lower for kw in [
            "vpr", "cvss", "cve", "source", "acr", "aes", "epss", "exploit",
            "tag", "first_seen", "last_seen", "asset_name", "solution",
            "plugin", "score", "risk",
        ]):
            desired_props.append(name)

params = {"offset": 0, "limit": 10}
if desired_props:
    params["extra_properties"] = ",".join(desired_props)
    print(f"  Requesting extra properties: {', '.join(desired_props)}")
    print()

response = client.post(SEARCH_ENDPOINT, params=params, json={})

if response.status_code != 200:
    print(f"  ERROR with extra_properties: {response.status_code}")
    print(f"  {response.text[:300]}")
    print()
    print("  Retrying without extra_properties...")
    response = client.post(SEARCH_ENDPOINT, params={"offset": 0, "limit": 10}, json={})

if response.status_code != 200:
    print(f"  ERROR: API returned {response.status_code}")
    print(f"  {response.text[:500]}")
    client.close()
    sys.exit(1)

data = response.json()
findings = data.get("data", [])
total = data.get("pagination", {}).get("total", 0)

print(f"  Total findings available: {total:,}")
print(f"  Fetched: {len(findings)}")
print()

if not findings:
    print("  No findings returned.")
    client.close()
    sys.exit(0)

# =====================================================================
# STEP 3: Analyse and display
# =====================================================================
print("=" * 70)
print("  STEP 3: Analysis")
print("=" * 70)

severities = Counter()
states = Counter()
sources = Counter()

for f in findings:
    severities[f.get("severity", "Unknown")] += 1
    states[f.get("state", "Unknown")] += 1
    extra = f.get("extra_properties", {}) or {}
    # Try common source field names
    source = extra.get("source") or extra.get("sources") or extra.get("application") or "Unknown"
    if isinstance(source, list):
        source = source[0] if source else "Unknown"
    sources[str(source)] += 1

print()
print(f"  --- Severity breakdown ---")
for sev, count in severities.most_common():
    bar = "#" * min(count, 40)
    print(f"  {sev:>10}: {count:>4}  {bar}")

print()
print(f"  --- State breakdown ---")
for state, count in states.most_common():
    print(f"  {state:>12}: {count}")

print()
print(f"  --- Source breakdown ---")
for source, count in sources.most_common():
    print(f"  {source:>25}: {count}")

# Print first 3 findings in full detail
print()
print("=" * 70)
print("  SAMPLE FINDINGS (first 3)")
print("=" * 70)
for i, f in enumerate(findings[:3]):
    print(f"\n  --- Finding {i+1} ---")
    for key, value in f.items():
        if key == "extra_properties" and isinstance(value, dict):
            print(f"  {key}:")
            for ek, ev in sorted(value.items()):
                val_str = str(ev)[:120]
                print(f"    {ek}: {val_str}")
        else:
            val_str = str(value)[:120]
            print(f"  {key}: {val_str}")

print()
print("=" * 70)

# Save full sample to file for reference
sample_file = Path(__file__).parent.parent / "tenable_sample_findings.json"
with open(sample_file, "w") as f:
    json.dump(findings[:5], f, indent=2, default=str)
print(f"  First 5 findings saved to: {sample_file}")
print("=" * 70)

client.close()
