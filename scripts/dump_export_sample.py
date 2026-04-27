#!/usr/bin/env python3
"""Initiate a small export and dump the raw chunk shape so we can see
what fields are returned (vs the search endpoint).
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

PROPS = "finding_vpr_score,finding_cves,asset_name,sensor_type,tag_names,tag_ids"

# Initiate export
print("Initiating export...")
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
print(f"  export_id: {eid}")

# Poll
print("Polling for completion...")
for i in range(60):
    time.sleep(5)
    r = c.get(f"/api/v1/t1/inventory/export/{eid}/status")
    if r.status_code != 200:
        print(f"  poll error: {r.status_code}: {r.text[:200]}")
        sys.exit(1)
    status_data = r.json()
    status = status_data.get("status")
    print(f"  [{i*5}s] status={status}")
    if status == "FINISHED":
        break

print()
print("Status response:")
print(json.dumps(status_data, indent=2, default=str)[:2000])
print()

# Get chunk list
chunks = status_data.get("chunks") or status_data.get("chunks_available") or [0]
print(f"Chunks: {chunks}")

# Download first chunk
if chunks:
    chunk_id = chunks[0]
    print(f"\nDownloading chunk {chunk_id}...")
    r = c.get(f"/api/v1/t1/inventory/export/{eid}/download/{chunk_id}")
    print(f"  status: {r.status_code}")
    if r.status_code != 200:
        print(r.text[:300])
        sys.exit(1)

    chunk_data = r.json()
    print(f"  chunk type: {type(chunk_data).__name__}")

    # If list, show first item
    if isinstance(chunk_data, list):
        print(f"  chunk size: {len(chunk_data)}")
        if chunk_data:
            sample = chunk_data[0]
            print(f"\nFirst finding (raw):")
            print(json.dumps(sample, indent=2, default=str)[:2000])
            print(f"\nTop-level keys: {list(sample.keys())}")
            extra = sample.get("extra_properties", {})
            if extra:
                print(f"extra_properties keys: {list(extra.keys()) if isinstance(extra, dict) else type(extra)}")

    # If dict, dump structure
    elif isinstance(chunk_data, dict):
        print(f"  chunk keys: {list(chunk_data.keys())}")
        items = chunk_data.get("data") or chunk_data.get("findings") or []
        print(f"  items: {len(items)}")
        if items:
            print(f"\nFirst finding (raw):")
            print(json.dumps(items[0], indent=2, default=str)[:2000])

    # Save to file
    Path("export_sample.json").write_text(json.dumps(chunk_data[:5] if isinstance(chunk_data, list) else chunk_data, indent=2, default=str))
    print(f"\nSaved first 5 to export_sample.json")

c.close()
