#!/usr/bin/env python3
"""Quick test script to pull findings from Tenable and print a summary.

Usage:
    # With .env file in project root:
    python scripts/test_tenable.py

    # Or with env vars:
    TENABLE_ACCESS_KEY=xxx TENABLE_SECRET_KEY=yyy python scripts/test_tenable.py
"""

import os
import sys
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

ENDPOINT = "/api/v1/t1/inventory/findings/search"
EXTRA_PROPS = "asset_name,vpr_score,cve,source,severity,acr,aes,epss_score,exploit_maturity,first_seen,last_seen"

print(f"Connecting to {BASE_URL}{ENDPOINT} ...")
print()

client = httpx.Client(
    base_url=BASE_URL,
    headers={
        "X-ApiKeys": f"accessKey={ACCESS_KEY};secretKey={SECRET_KEY}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    },
    timeout=120,
)

# Fetch first page to get total count
response = client.post(
    ENDPOINT,
    params={"offset": 0, "limit": 50, "extra_properties": EXTRA_PROPS, "sort": "severity:desc"},
    json={},
)

if response.status_code != 200:
    print(f"ERROR: API returned {response.status_code}")
    print(response.text[:500])
    sys.exit(1)

data = response.json()
findings = data.get("data", [])
total = data.get("pagination", {}).get("total", 0)

print("=" * 60)
print(f"  TENABLE INVENTORY API - CONNECTION SUCCESSFUL")
print("=" * 60)
print(f"  Total findings available: {total:,}")
print(f"  Fetched first page:      {len(findings)}")
print()

if not findings:
    print("  No findings returned. Check your Tenable configuration.")
    sys.exit(0)

# Analyse the findings
severities = Counter()
states = Counter()
sources = Counter()
has_vpr = 0
has_cve = 0

for f in findings:
    severities[f.get("severity", "Unknown")] += 1
    states[f.get("state", "Unknown")] += 1

    extra = f.get("extra_properties", {}) or {}
    source = extra.get("source", "Unknown")
    sources[source] += 1

    if extra.get("vpr_score"):
        has_vpr += 1
    if extra.get("cve"):
        has_cve += 1

print(f"  --- Severity breakdown (first {len(findings)} findings) ---")
for sev in ["Critical", "High", "Medium", "Low", "Info"]:
    count = severities.get(sev, 0)
    if count:
        bar = "#" * min(count, 40)
        print(f"  {sev:>10}: {count:>4}  {bar}")

print()
print(f"  --- State breakdown ---")
for state, count in states.most_common():
    print(f"  {state:>12}: {count}")

print()
print(f"  --- Source breakdown ---")
for source, count in sources.most_common():
    print(f"  {source:>20}: {count}")

print()
print(f"  --- Data quality ---")
print(f"  Findings with VPR score: {has_vpr}/{len(findings)}")
print(f"  Findings with CVE ID:    {has_cve}/{len(findings)}")

print()
print(f"  --- Sample finding ---")
f = findings[0]
extra = f.get("extra_properties", {}) or {}
print(f"  ID:         {f.get('id', 'N/A')}")
print(f"  Name:       {f.get('name', 'N/A')}")
print(f"  Severity:   {f.get('severity', 'N/A')}")
print(f"  State:      {f.get('state', 'N/A')}")
print(f"  Asset:      {extra.get('asset_name', 'N/A')}")
print(f"  CVE:        {extra.get('cve', 'N/A')}")
print(f"  VPR:        {extra.get('vpr_score', 'N/A')}")
print(f"  Source:     {extra.get('source', 'N/A')}")
print(f"  First seen: {extra.get('first_seen', 'N/A')}")
print("=" * 60)

client.close()
