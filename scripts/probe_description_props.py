#!/usr/bin/env python3
"""Find Tenable finding properties related to description / synopsis /
output / details. Pulls a real finding and prints the values of each
candidate so we can pick the best ones for the report.
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

BASE = os.environ.get("TENABLE_BASE_URL", "https://cloud.tenable.com")
AK = os.environ.get("TENABLE_ACCESS_KEY", "")
SK = os.environ.get("TENABLE_SECRET_KEY", "")

c = httpx.Client(
    base_url=BASE,
    headers={
        "X-ApiKeys": f"accessKey={AK};secretKey={SK}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    },
    timeout=120,
)

# 1. List all finding properties
print("=" * 70)
print("  Finding properties matching description-like keywords")
print("=" * 70)

r = c.get("/api/v1/t1/inventory/findings/properties")
props = r.json() if isinstance(r.json(), list) else r.json().get("data", [])

keywords = ["desc", "synopsis", "output", "detail", "info", "summary",
            "explanation", "evidence", "see_also", "reference", "remediat",
            "solut", "patch", "fix", "workaround", "impact", "risk_factor"]

candidates = []
for p in props:
    if not isinstance(p, dict):
        continue
    name = (p.get("key") or p.get("name") or "").lower()
    full = p.get("key") or p.get("name")
    if any(k in name for k in keywords):
        candidates.append(full)
        print(f"  {full}")

if not candidates:
    print("  (none found; showing all properties for review)")
    for p in props:
        if isinstance(p, dict):
            print(f"  {p.get('key') or p.get('name')}")

# 2. Request a sample finding with all candidates + solution
print()
print("=" * 70)
print("  Sample values for each candidate property")
print("=" * 70)

# Always include solution as a baseline for comparison
request_props = sorted(set(candidates) | {"finding_solution"})
print(f"\nRequesting: {','.join(request_props)}")
print()

r = c.post(
    "/api/v1/t1/inventory/findings/search",
    params={"offset": 0, "limit": 3, "extra_properties": ",".join(request_props)},
    json={},
)
if r.status_code != 200:
    print(f"  ERROR {r.status_code}: {r.text[:300]}")
    sys.exit(1)

findings = r.json().get("data", [])
if not findings:
    print("  No findings returned")
    sys.exit(0)

# For each candidate property, count how many of the 3 samples have values
for prop in request_props:
    print(f"\n--- {prop} ---")
    for i, f in enumerate(findings, 1):
        extra = f.get("extra_properties", {}) or {}
        val = extra.get(prop)
        if val is None:
            print(f"  [{i}] (null)")
        elif isinstance(val, str):
            print(f"  [{i}] {val[:200]}{'...' if len(val) > 200 else ''}")
        else:
            print(f"  [{i}] {val}")

c.close()
print()
print("=" * 70)
print("  Once you see which ones have rich content, add them to:")
print("    config/tenable.yaml → extra_properties")
print("    src/ingestion/tenable_ingestion.py → normalise_finding()")
print("=" * 70)
