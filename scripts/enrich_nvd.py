#!/usr/bin/env python3
"""Standalone NVD enrichment — backfill CVE descriptions/references.

Decoupled from the main pipeline so it never blocks findings ingestion or
scoring. Fully resumable: the cve_details cache accumulates, so re-running
picks up where it left off. Bound the work per run with --max for Lambda /
scheduled use.

Usage:
    # Backfill everything (slow without an API key — set NVD_API_KEY in .env)
    .venv/bin/python3 scripts/enrich_nvd.py

    # Fetch only the next 500 uncached CVEs, then exit (good for a cron job)
    .venv/bin/python3 scripts/enrich_nvd.py --max 500

    # Just show how many CVEs still need fetching, don't fetch
    .venv/bin/python3 scripts/enrich_nvd.py --status

Strongly recommended: get a free NVD API key (10x faster) and put it in .env:
    NVD_API_KEY=...
    -> https://nvd.nist.gov/developers/request-an-api-key
"""

import argparse
import os
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.common.config import AppConfig, AppSettings
from src.common.db import get_session, init_db
from src.common.logging import setup_logging
from src.common.models import CveDetails
from src.ingestion.nvd_enrichment import (
    _filter_to_fetch,
    distinct_finding_cves,
    enrich_cves_from_findings,
)


def main():
    parser = argparse.ArgumentParser(description="Backfill CVE descriptions from NVD")
    parser.add_argument("--max", type=int, default=None,
                        help="Max CVEs to fetch this run (default: all). Use for cron/Lambda.")
    parser.add_argument("--ttl-days", type=int, default=None,
                        help="Refresh cached entries older than this (default: config nvd.ttl_days)")
    parser.add_argument("--status", action="store_true",
                        help="Just report how many CVEs still need fetching, then exit.")
    parser.add_argument("--scope", choices=["all", "non-container"], default="all",
                        help="'non-container' fetches only host/VM CVE descriptions, "
                             "skipping the huge set of container-image CVEs.")
    args = parser.parse_args()

    settings = AppSettings()
    config = AppConfig(settings=settings)
    setup_logging(settings.log_level)
    init_db(settings.database_url)

    ttl_days = args.ttl_days if args.ttl_days is not None else config.nvd.ttl_days
    exclude_container = args.scope == "non-container"
    patterns = config.tenable.container_registry_patterns

    with get_session() as session:
        # How much is left (within scope)?
        unique = distinct_finding_cves(session, exclude_container, patterns)
        to_fetch = _filter_to_fetch(session, unique, ttl_days)
        cached_total = session.query(CveDetails).count()

        print("=" * 60)
        print("  NVD ENRICHMENT STATUS")
        print("=" * 60)
        print(f"  Scope:                       {args.scope}")
        print(f"  Distinct CVEs in scope:      {len(unique):,}")
        print(f"  Already cached (fresh):      {len(unique) - len(to_fetch):,}")
        print(f"  Still to fetch:              {len(to_fetch):,}")
        print(f"  Total rows in cve_details:   {cached_total:,}")
        api_key = os.environ.get("NVD_API_KEY")
        rate = "50 req / 30s (with key)" if api_key else "5 req / 30s (NO KEY — slow!)"
        print(f"  Rate limit:                  {rate}")
        if not api_key:
            est_hours = len(to_fetch) * 6 / 3600
            print(f"  Est. time for full backfill: ~{est_hours:.1f} hours")
            print(f"  >>> Get a free key for 10x: https://nvd.nist.gov/developers/request-an-api-key")
        print("=" * 60)

        if args.status:
            return

        if not to_fetch:
            print("\n  Nothing to fetch. Cache is up to date.\n")
            return

        target = args.max if args.max else len(to_fetch)
        print(f"\n  Fetching up to {target:,} CVEs now...\n")

        cached = enrich_cves_from_findings(
            session,
            ttl_days=ttl_days,
            api_key=api_key,
            max_fetch=args.max,
            exclude_container=exclude_container,
            container_patterns=patterns,
        )

        remaining = len(to_fetch) - cached
        print(f"\n  Done. Cached {cached:,} CVEs this run. {remaining:,} still remaining.")
        if remaining > 0:
            print(f"  Run again to continue (resumable).\n")


if __name__ == "__main__":
    main()
