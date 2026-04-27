#!/usr/bin/env python3
"""Try every plausible value for query.mode."""

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
baseline = r.json().get("pagination", {}).get("total", 0) if r.status_code == 200 else 0
print(f"Baseline: {baseline:,}")
print()

mode_values = [
    "Advanced", "advanced", "ADVANCED",
    "Simple", "simple", "SIMPLE",
    "Auto", "auto", "AUTO",
    "Default", "default",
    "Quick", "quick",
    "Text", "text",
    "Custom", "custom",
    "Builder", "builder",
    "Basic", "basic",
    "Query", "query",
    "Filter", "filter",
    "All", "all",
]

text_values = [
    f"tag_names has {target}",
    f"tag_names = {target}",
    f"tag_names equals {target}",
    f"tag_names:{target}",
    f"tag_names:'{target}'",
    f"tag_names:\"{target}\"",
    target,  # just the value
    f"AS device HAS tag_names:'{target}'",
    f"HAS tag_names:'{target}'",
]

print("Probing query.mode values with text='tag_names has <target>'")
print("-" * 70)
working = []
for mode in mode_values:
    body = {"query": {"text": f"tag_names has {target}", "mode": mode}}
    r = c.post("/api/v1/t1/inventory/findings/search",
               params={"offset": 0, "limit": 1}, json=body)
    if r.status_code == 200:
        total = r.json().get("pagination", {}).get("total", 0)
        if total != baseline and total > 0:
            print(f"  {total:>10,}  GENUINE   mode='{mode}'")
            working.append((mode, body))
        elif total == 0:
            print(f"  {total:>10,}  (0 match) mode='{mode}'")
        # silent ignore: skip to keep output short
    elif r.status_code == 400:
        msg = r.text[:120].replace("\n", " ")
        # Only print non-mode errors
        if "query.mode" not in msg.lower() and "mode" not in msg.lower():
            print(f"  400 mode='{mode}': {msg}")

print()
if working:
    print("Now trying different text formats with the working mode(s)...")
    print("-" * 70)
    for mode, _ in working:
        for txt in text_values:
            body = {"query": {"text": txt, "mode": mode}}
            r = c.post("/api/v1/t1/inventory/findings/search",
                       params={"offset": 0, "limit": 1}, json=body)
            if r.status_code != 200:
                continue
            total = r.json().get("pagination", {}).get("total", 0)
            if total != baseline and total > 0:
                print(f"  {total:>10,}  mode='{mode}'  text='{txt}'")

c.close()
