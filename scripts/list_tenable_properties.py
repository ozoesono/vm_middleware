#!/usr/bin/env python3
"""List the properties the Tenable Inventory API exposes for findings/assets.

The Inventory API is in beta and its property catalogue isn't reliably
documented, so this helper queries the live catalogue directly. Use it to
discover the real field name for something before wiring it into the ingester
(e.g. a container in-use/deployed flag, a fixed-version field, a description),
or to re-validate the contract after a Tenable platform change.

Reads Tenable credentials from .env (TENABLE_ACCESS_KEY / TENABLE_SECRET_KEY)
and the base URL from config/tenable.yaml.

Usage:
    # everything (findings + assets)
    .venv/bin/python3 scripts/list_tenable_properties.py

    # only property names matching a pattern (case-insensitive regex)
    .venv/bin/python3 scripts/list_tenable_properties.py --grep 'use|deploy|running|image'

    # just the findings catalogue, and save the raw JSON for closer inspection
    .venv/bin/python3 scripts/list_tenable_properties.py --kind findings --dump ./out
"""

import argparse
import json
import re
import sys
from pathlib import Path

import httpx

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.common.config import AppConfig, AppSettings

# Field names a property record might use for its identifier and its description.
_NAME_KEYS = ("key", "name", "property", "property_name", "id", "field", "fqn")
_DESC_KEYS = ("description", "label", "title", "display_name", "desc")
_IDENT = re.compile(r"^[A-Za-z][A-Za-z0-9_.]{1,80}$")


def _property_records(data) -> list[tuple[str, str]]:
    """Pull (name, description) pairs from any property-definition objects,
    wherever they sit in the response shape."""
    records: list[tuple[str, str]] = []

    def walk(obj):
        if isinstance(obj, dict):
            name = next((obj[k] for k in _NAME_KEYS if isinstance(obj.get(k), str)), None)
            if name:
                desc = next((obj[k] for k in _DESC_KEYS if isinstance(obj.get(k), str)), "")
                records.append((name, desc))
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(data)
    return records


def _ident_tokens(data) -> set[str]:
    """Fallback: every identifier-like string in the response (used only when no
    structured property list is found)."""
    out: set[str] = set()

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(k, str):
                    out.add(k)
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)
        elif isinstance(obj, str):
            out.add(obj)

    walk(data)
    return {t for t in out if _IDENT.match(t)}


def main():
    parser = argparse.ArgumentParser(description="List Tenable Inventory API properties.")
    parser.add_argument("--kind", choices=["findings", "assets", "both"], default="both",
                        help="Which property catalogue to list (default: both).")
    parser.add_argument("--grep", default=None,
                        help="Case-insensitive regex to filter property names.")
    parser.add_argument("--dump", default=None,
                        help="Directory to save each catalogue's raw JSON into.")
    parser.add_argument("--names-only", action="store_true",
                        help="Print just property names, one per line (compact, screenshot-friendly).")
    args = parser.parse_args()

    settings = AppSettings()
    config = AppConfig(settings=settings)
    access_key = settings.tenable_access_key.get_secret_value()
    secret_key = settings.tenable_secret_key.get_secret_value()
    if not access_key or not secret_key:
        sys.exit("TENABLE_ACCESS_KEY / TENABLE_SECRET_KEY not set (check .env).")

    pattern = re.compile(args.grep, re.I) if args.grep else None
    kinds = ["assets", "findings"] if args.kind == "both" else [args.kind]

    with httpx.Client(
        base_url=config.tenable.base_url,
        headers={
            "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
            "Accept": "application/json",
        },
        timeout=config.tenable.request_timeout_seconds,
    ) as client:
        for kind in kinds:
            path = f"/api/v1/t1/inventory/{kind}/properties"
            try:
                response = client.get(path)
                response.raise_for_status()
                data = response.json()
            except Exception as e:
                print(f"\n[{kind}] request failed: {str(e)[:200]}")
                continue

            if args.dump:
                out_path = Path(args.dump) / f"{kind}_properties.json"
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(json.dumps(data, indent=2))

            names: dict[str, str] = {}
            for name, desc in _property_records(data):
                names.setdefault(name, desc)

            display = sorted(names)
            if not display:
                # unexpected shape — fall back to raw identifier tokens
                display = sorted(_ident_tokens(data))
                names = {t: "" for t in display}

            if pattern:
                display = [n for n in display if pattern.search(n)]

            suffix = f" matching /{args.grep}/" if pattern else ""
            print(f"\n=== {kind}: {len(display)} propert{'y' if len(display) == 1 else 'ies'}{suffix} ===")
            if args.dump and not args.names_only:
                print(f"    (raw JSON saved to {Path(args.dump) / f'{kind}_properties.json'})")
            for name in display:
                if args.names_only:
                    print(name)
                else:
                    desc = names.get(name, "")
                    print(f"  {name}" + (f"  —  {desc[:100]}" if desc else ""))


if __name__ == "__main__":
    main()
