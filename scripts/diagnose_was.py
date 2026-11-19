#!/usr/bin/env python3
"""Read-only WAS API diagnostic. No database or Jira access.

Loads the project .env automatically (exported variables take precedence).
Samples Inventory and WAS independently, then probes possible cross-API IDs.
Output contains identifiers, field availability and lengths, not raw evidence.
"""

import argparse
import json
import os
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import yaml
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = "/api/v1/t1/inventory/findings"
WAS = "/was/v2"


def identifier(value, numeric=False):
    if value is None or isinstance(value, bool):
        return None
    value = str(value)
    if numeric:
        return value if value.isascii() and value.isdecimal() else None
    try:
        return str(uuid.UUID(value))
    except ValueError:
        return None


def shape(value, depth=0):
    """Describe available fields without exposing evidence or target URLs."""
    if isinstance(value, dict):
        if depth >= 3:
            return {"type": "object", "keys": sorted(value)}
        return {key: shape(item, depth + 1) for key, item in value.items()}
    if isinstance(value, list):
        return {"type": "list", "count": len(value),
                "first_item": shape(value[0], depth + 1) if value else None}
    if isinstance(value, str):
        return {"type": "string", "characters": len(value)}
    return {"type": type(value).__name__, "present": value is not None}


def identity_fields(value, prefix=""):
    """Keep only UUID/numeric IDs, including nested source-specific identifiers."""
    result = {}
    if not isinstance(value, dict):
        return result
    for key, item in value.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(item, dict):
            result.update(identity_fields(item, path))
        elif key == "id" or key.endswith(("_id", "_uuid")):
            safe_id = identifier(item) or identifier(item, numeric=True)
            if safe_id:
                result[path] = safe_id
    return result


class Probe:
    def __init__(self, client):
        self.client = client
        self.calls = []
        self.rate_limited = False
        self.cache = {}

    def request(self, method, path, **kwargs):
        if self.rate_limited:
            return None
        if method == "GET" and path in self.cache:
            return self.cache[path]
        entry = {"method": method, "path": path}
        self.calls.append(entry)
        print(f"Checking {method} {path}", file=sys.stderr, flush=True)
        try:
            response = self.client.request(method, path, **kwargs)
            entry["http_status"] = response.status_code
            if response.status_code == 429:
                self.rate_limited = True
                entry["note"] = "Rate limited; stopped further requests. Rerun later."
            if not response.is_success:
                # Error bodies may contain request data. Never include them.
                return None
            data = response.json()
            if not isinstance(data, dict):
                entry["error"] = "Expected a JSON object"
                return None
            entry["response_keys"] = sorted(data)
            if method == "GET":
                self.cache[path] = data
            return data
        except (httpx.HTTPError, ValueError) as exc:
            entry["error"] = type(exc).__name__  # No URLs, headers or raw responses.
            return None


def diagnose(client, limit=3, inventory_id=None, was_id=None):
    probe = Probe(client)
    report = {"note": "Bounded samples; no match does not prove no mapping exists.",
              "requests": probe.calls, "inventory_samples": [], "was_samples": [],
              "id_probes": [], "plugins": {}}
    catalog = probe.request("GET", f"{INVENTORY}/properties") or {}
    properties = [p for p in catalog.get("data", []) if isinstance(p, dict)]
    relevant = [p for p in properties if any(
        term in p.get("key", "").lower()
        for term in ("was", "plugin", "detection", "source", "sensor", "product", "description", "solution")
    )]
    report["inventory_property_names"] = [p.get("key") for p in relevant]
    filters = [{"property": "sensor_type", "operator": "=", "value": ["WAS"]}]
    if inventory_id:
        filters.append({"property": "finding_id", "operator": "=", "value": [inventory_id]})
    extra = {"finding_detection_id", "sensor_type", "product", "asset_name", "asset_class",
             "finding_solution"}
    extra.update(p["key"] for p in relevant)
    inventory = probe.request("POST", f"{INVENTORY}/search",
                              params={"limit": limit, "offset": 0,
                                      "extra_properties": ",".join(sorted(extra))},
                              json={"filters": filters}) or {}
    report["inventory_total"] = inventory.get("pagination", {}).get("total")
    inventory_rows = [r for r in inventory.get("data", []) if isinstance(r, dict)][:limit]
    for row in inventory_rows:
        report["inventory_samples"].append({"ids": identity_fields(row), "fields": shape(row)})

    if was_id:
        native = [{"vuln_id": was_id}]
    else:
        search = probe.request("POST", f"{WAS}/vulnerabilities/search",
                               params={"limit": limit, "offset": 0}, json={}) or {}
        report["was_total"] = search.get("pagination", {}).get("total")
        native = [r for r in search.get("items", []) if isinstance(r, dict)][:limit]

    plugin_ids = set()
    for row in native:
        vuln_id = identifier(row.get("vuln_id"))
        detail = probe.request("GET", f"{WAS}/vulnerabilities/{vuln_id}") if vuln_id else None
        result = detail or row
        report["was_samples"].append({"ids": identity_fields(result), "fields": shape(result)})
        plugin_id = identifier(result.get("plugin_id"), numeric=True)
        if plugin_id:
            plugin_ids.add(plugin_id)

    # Test equality explicitly; never treat a title/URL/plugin match as an instance match.
    for row in inventory_rows:
        extra = row.get("extra_properties") or {}
        candidates = {"inventory_id": row.get("id"),
                      "finding_detection_id": extra.get("finding_detection_id")}
        for field, candidate in candidates.items():
            vuln_id = identifier(candidate)
            if not vuln_id:
                continue
            detail = probe.request("GET", f"{WAS}/vulnerabilities/{vuln_id}")
            matched = bool(detail and identifier(detail.get("vuln_id")) == vuln_id)
            report["id_probes"].append({"inventory_id": identifier(row.get("id")),
                                        "candidate_field": field, "candidate": vuln_id,
                                        "was_instance_id_confirmed": matched,
                                        "detail_fields": shape(detail) if detail else None})
            if detail:
                plugin_id = identifier(detail.get("plugin_id"), numeric=True)
                if plugin_id:
                    plugin_ids.add(plugin_id)
        plugin_id = identifier(extra.get("finding_detection_id"), numeric=True)
        if plugin_id:
            plugin_ids.add(plugin_id)
            report["id_probes"].append({"inventory_id": identifier(row.get("id")),
                                        "possible_plugin_id": plugin_id,
                                        "note": "Plugin lookup only; does not identify a WAS occurrence."})

    for plugin_id in sorted(plugin_ids):
        plugin = probe.request("GET", f"{WAS}/plugins/{plugin_id}")
        report["plugins"][plugin_id] = {
            "id_confirmed": bool(plugin and str(plugin.get("plugin_id")) == plugin_id),
            "fields": shape(plugin) if plugin else None,
        }
    report["rate_limited"] = probe.rate_limited
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=3, help="Sample size per API (1–10)")
    parser.add_argument("--inventory-finding-id", type=uuid.UUID)
    parser.add_argument("--was-vuln-id", type=uuid.UUID)
    parser.add_argument("--env-file", type=Path, default=ROOT / ".env")
    parser.add_argument("--base-url", help="Override Tenable API base URL")
    parser.add_argument("--out", type=Path, help="Also save the diagnostic JSON here")
    args = parser.parse_args()
    if not 1 <= args.limit <= 10:
        parser.error("--limit must be between 1 and 10")
    load_dotenv(args.env_file, override=False)
    access, secret = os.getenv("TENABLE_ACCESS_KEY"), os.getenv("TENABLE_SECRET_KEY")
    if not access or not secret:
        parser.error("Set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY in .env or the environment")
    config_dir = Path(os.getenv("CONFIG_DIR", str(ROOT / "config")))
    if not config_dir.is_absolute():
        config_dir = ROOT / config_dir
    config_file = config_dir / "tenable.yaml"
    try:
        config = yaml.safe_load(config_file.read_text()) if config_file.exists() else {}
        base_url = args.base_url or os.getenv("TENABLE_BASE_URL") or (
            (config or {}).get("tenable", {}).get("base_url", "https://cloud.tenable.com"))
        url = urlsplit(base_url)
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
            parser.error("Base URL must be HTTPS without credentials, query or fragment")
        with httpx.Client(base_url=base_url.rstrip("/"), timeout=30, follow_redirects=False,
                          headers={"X-ApiKeys": f"accessKey={access};secretKey={secret}",
                                   "Accept": "application/json"}) as client:
            report = diagnose(client, args.limit,
                              str(args.inventory_finding_id) if args.inventory_finding_id else None,
                              str(args.was_vuln_id) if args.was_vuln_id else None)
        output = json.dumps(report, indent=2)
        print(f"Inventory WAS findings: total={report.get('inventory_total')}, "
              f"sampled={len(report['inventory_samples'])}")
        print(f"Native WAS vulnerabilities: total={report.get('was_total')}, "
              f"sampled={len(report['was_samples'])}")
        for call in report["requests"]:
            print(f"  {call['method']} {call['path']}: "
                  f"{call.get('http_status', call.get('error', 'unknown'))}")
        for candidate in report["id_probes"]:
            print("ID probe:", json.dumps({k: v for k, v in candidate.items()
                                           if k != "detail_fields"}))
        for plugin_id, plugin in report["plugins"].items():
            fields = plugin["fields"] or {}
            lengths = {key: fields.get(key, {}).get("characters", 0)
                       for key in ("synopsis", "description", "solution", "impact")}
            print(f"Plugin {plugin_id}: id_confirmed={plugin['id_confirmed']}; "
                  f"text lengths={lengths}")
        print(report["note"])
        if args.out:
            args.out.write_text(output + "\n")
            print(f"Saved diagnostic: {args.out.resolve()}", file=sys.stderr)
        else:
            print("Use --out to save the detailed field-availability report.")
    except (OSError, ValueError, TypeError, AttributeError, yaml.YAMLError) as exc:
        parser.exit(1, f"Diagnostic failed: {type(exc).__name__}; check configuration/output path.\n")


if __name__ == "__main__":
    main()
