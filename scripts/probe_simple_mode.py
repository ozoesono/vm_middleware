#!/usr/bin/env python3
"""Try simple mode with many text variations + show ALL errors verbosely."""

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

target = "Portfolio-Business-Growth"
for i, a in enumerate(sys.argv):
    if a == "--tag" and i + 1 < len(sys.argv):
        target = sys.argv[i + 1]

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
print(f"Baseline: {baseline:,}\n")

# PART A — exhaustively test mode values, show every response
print("PART A: Try every mode value, verbose errors")
print("=" * 70)
modes = ["Advanced", "advanced", "ADVANCED", "Simple", "simple", "SIMPLE",
         "Auto", "auto", "Default", "default", "Quick", "Text", "Custom",
         "Basic", "Query", "Filter", "Smart", "Manual", "TQL", "tql"]

for m in modes:
    body = {"query": {"text": f"tag_names has {target}", "mode": m}}
    r = c.post("/api/v1/t1/inventory/findings/search",
               params={"offset": 0, "limit": 1}, json=body)
    if r.status_code == 200:
        t = r.json().get("pagination", {}).get("total", 0)
        marker = "GENUINE" if (t > 0 and t != baseline) else ("0_match" if t == 0 else "ignored")
        print(f"  mode={m:<10}  200  total={t:>10,}  {marker}")
    else:
        msg = r.text[:200].replace("\n", " ")
        print(f"  mode={m:<10}  {r.status_code}  {msg[:150]}")

# PART B — with each accepted (200) mode, try different text formats
print()
print("PART B: Trying text variations with mode='simple'")
print("=" * 70)
texts = [
    target,                                     # raw value
    f'"{target}"',                              # quoted
    f"tag_names:{target}",                      # field:value
    f"tag_names:'{target}'",                    # field:'value'
    f"tag_names:\"{target}\"",                  # field:"value"
    f"tag_names = {target}",
    f"tag_names = '{target}'",
    f"tag_names eq {target}",
    f"tag_names equals {target}",
    f"tag_names contains {target}",
    f"tag_names has '{target}'",
    f"tag_names HAS '{target}'",
    f"AS Finding HAS tag_names:'{target}'",
    f"AS device HAS tag_names:'{target}'",
    f"HAS tag_names:'{target}'",
    f"HAS tag_names = '{target}'",
    "tag_names exists",                          # any tagged finding
]

for txt in texts:
    body = {"query": {"text": txt, "mode": "simple"}}
    r = c.post("/api/v1/t1/inventory/findings/search",
               params={"offset": 0, "limit": 1}, json=body)
    if r.status_code == 200:
        t = r.json().get("pagination", {}).get("total", 0)
        marker = "GENUINE" if (t > 0 and t != baseline) else ("0_match" if t == 0 else "ignored")
        print(f"  text={txt!r}")
        print(f"      200  total={t:>10,}  {marker}")
    else:
        msg = r.text[:200].replace("\n", " ")
        print(f"  text={txt!r}")
        print(f"      {r.status_code}  {msg[:150]}")

c.close()
