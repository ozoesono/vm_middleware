#!/usr/bin/env python3
"""Final attempt: try Advanced mode with several text formats.

Advanced mode previously returned 500 — the API tried to parse but failed.
This script tries different text query formats to find one that doesn't
crash the parser.

Usage:
    .venv/bin/python3 scripts/probe_advanced_text.py
    .venv/bin/python3 scripts/probe_advanced_text.py --tag Portfolio-Business-Growth
"""

import os
import sys
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

text_variations = [
    f"Findings has tag_names {target}",
    f"Findings has tag_names = {target}",
    f"Findings has tag_names:'{target}'",
    f"Findings has tag_names = '{target}'",
    f"Findings has tag_names is '{target}'",
    f"AS Finding HAS tag_names:'{target}'",
    f"AS Finding HAS tag_names = '{target}'",
    f"tag_names = {target}",
    f"tag_names = '{target}'",
    f"tag_names is {target}",
    f"tag_names is '{target}'",
    f"tag_names:'{target}'",
    f"tag_names:{target}",
    f"tag_names contains '{target}'",
    f"tag_names contains {target}",
    f"tag_names equals {target}",
    f"tag_name = '{target}'",        # singular
    f"tag_name:'{target}'",
]

print("Trying each text format with mode=Advanced")
print("=" * 70)
for txt in text_variations:
    body = {"query": {"text": txt, "mode": "Advanced"}}
    r = c.post(
        "/api/v1/t1/inventory/findings/search",
        params={"offset": 0, "limit": 1},
        json=body,
    )

    if r.status_code == 200:
        total = r.json().get("pagination", {}).get("total", 0)
        if total > 0 and total != baseline:
            tag = "GENUINE"
        elif total == 0:
            tag = "0_match"
        else:
            tag = "ignored"
        print(f"  200  total={total:>10,}  {tag:<8}  {txt!r}")
    else:
        msg = r.text[:200].replace("\n", " ")
        print(f"  {r.status_code}  {txt!r}")
        print(f"      {msg[:180]}")

c.close()
