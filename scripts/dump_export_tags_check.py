#!/usr/bin/env python3
"""Check if the export endpoint returns tags at all by sampling many findings
and trying alternate property names.
"""

import os, sys, json, time
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

c = httpx.Client(
    base_url=BASE_URL,
    headers={
        "X-ApiKeys": f"accessKey={ACCESS_KEY};secretKey={SECRET_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    },
    timeout=180,
)

# Try requesting EVERY tag-related property variant
PROPS = "asset_name,asset_id,tag_names,tag_ids,tag_name,tag_id,tags,asset_tags,asset_tag_names"

# Initiate
print("Initiating export with maximum tag properties...")
r = c.post(
    "/api/v1/t1/inventory/export/findings",
    params={"properties": PROPS, "file_format": "JSON"},
    json={},
)
print(f"  status: {r.status_code}")
if r.status_code != 200:
    print(r.text[:500])
    sys.exit(1)
eid = r.json().get("export_id")
print(f"  export_id: {eid}\n")

# Poll
print("Polling...")
for i in range(120):
    time.sleep(5)
    r = c.get(f"/api/v1/t1/inventory/export/{eid}/status")
    sd = r.json()
    print(f"  [{i*5}s] {sd.get('status')}")
    if sd.get("status") == "FINISHED":
        break

chunks = sd.get("chunks") or sd.get("chunks_available") or [0]
print(f"\nChunks: {len(chunks) if isinstance(chunks, list) else chunks}\n")

# Download first chunk
print("Downloading first chunk...")
chunk_id = chunks[0] if chunks else 0
r = c.get(f"/api/v1/t1/inventory/export/{eid}/download/{chunk_id}")
data = r.json()
findings = data if isinstance(data, list) else data.get("data", data.get("findings", []))
print(f"Got {len(findings)} findings in chunk 0\n")

if not findings:
    sys.exit(1)

# Show the FULL structure of the first finding
print("=" * 70)
print("First finding (FULL):")
print("=" * 70)
print(json.dumps(findings[0], indent=2, default=str))
print()

# Show top-level keys observed across the first 100 findings
print("=" * 70)
print(f"Field analysis across first {min(100, len(findings))} findings:")
print("=" * 70)

all_keys = set()
extra_keys = set()
tag_field_counts = {}

for f in findings[:100]:
    if isinstance(f, dict):
        all_keys.update(f.keys())
        extra = f.get("extra_properties", {}) or {}
        if isinstance(extra, dict):
            extra_keys.update(extra.keys())
        # Count which tag-related fields are NON-NULL
        for fld in ["tag_names", "tag_ids", "tag_name", "tag_id", "tags", "asset_tags", "asset_tag_names"]:
            val = f.get(fld) or (extra.get(fld) if isinstance(extra, dict) else None)
            if val:
                tag_field_counts[fld] = tag_field_counts.get(fld, 0) + 1

print(f"\nTop-level keys: {sorted(all_keys)}")
print(f"\nextra_properties keys: {sorted(extra_keys)}")
print(f"\nTag fields populated (out of {min(100, len(findings))} sampled):")
for fld, count in sorted(tag_field_counts.items()):
    print(f"  {fld}: {count}")

if not tag_field_counts:
    print("  NONE — export endpoint does NOT return tag data at all")

c.close()
