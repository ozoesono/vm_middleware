#!/usr/bin/env python3
"""Dump every extra_property Tenable will return for a Cloud Security finding,
so we can see if remediation/solution data lives in a field we're not using
(e.g. finding_attributes, custom_attributes).
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

c = httpx.Client(
    base_url=os.environ.get("TENABLE_BASE_URL", "https://cloud.tenable.com"),
    headers={
        "X-ApiKeys": f"accessKey={os.environ['TENABLE_ACCESS_KEY']};secretKey={os.environ['TENABLE_SECRET_KEY']}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    },
    timeout=120,
)

# Get every available finding property and request it all
r = c.get("/api/v1/t1/inventory/findings/properties")
props = r.json() if isinstance(r.json(), list) else r.json().get("data", [])
prop_names = []
for p in props:
    if isinstance(p, dict):
        name = p.get("key") or p.get("name")
        if name:
            prop_names.append(name)

print(f"Found {len(prop_names)} available properties.\n")
print("Requesting ALL of them...\n")

r = c.post(
    "/api/v1/t1/inventory/findings/search",
    params={
        "offset": 0,
        "limit": 5,
        "extra_properties": ",".join(prop_names),
    },
    json={},
)
if r.status_code != 200:
    print(f"  ERROR {r.status_code}: {r.text[:500]}")
    sys.exit(1)

findings = r.json().get("data", [])
print(f"Got {len(findings)} sample findings\n")

# For each finding, dump the full structure
for i, f in enumerate(findings[:3], 1):
    print("=" * 70)
    print(f"  FINDING #{i}: {f.get('name')} (source: {(f.get('extra_properties', {}) or {}).get('sensor_type')})")
    print("=" * 70)
    extra = f.get("extra_properties", {}) or {}
    populated = []
    empty = []
    for key in sorted(extra.keys()):
        val = extra[key]
        if val is None or val == "" or val == [] or val == {}:
            empty.append(key)
        else:
            populated.append((key, val))

    print(f"\n  POPULATED fields ({len(populated)}):")
    for key, val in populated:
        s = str(val)
        if len(s) > 400:
            s = s[:400] + "..."
        print(f"\n    {key}:")
        print(f"      {s}")

    print(f"\n  EMPTY fields ({len(empty)}):")
    print(f"    {', '.join(empty)}")
    print()

c.close()
