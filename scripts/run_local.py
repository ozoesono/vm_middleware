#!/usr/bin/env python3
"""Local pipeline runner entry point.

Usage:
    python scripts/run_local.py                                  # auto-resume or fresh
    python scripts/run_local.py --start-fresh                    # force new run
    python scripts/run_local.py --mock                           # mock fixture data
    python scripts/run_local.py --tag Portfolio-Business-Growth  # filter by tag
    python scripts/run_local.py --tag Portfolio-A --tag Portfolio-B
    python scripts/run_local.py --mode export --tag Portfolio-X

Resilience:
    By DEFAULT, the runner AUTO-RESUMES any incomplete run whose tag_filter
    matches the current request. Pass --start-fresh to force a new run.
    Per-record and per-page failures are tolerated (logged + counted on
    pipeline_runs.findings_skipped / pages_failed); the pipeline continues.

Tag filter:
    --tag X (repeatable). Pre-flight assets/search advanced query fetches
    the asset_ids carrying the tag, then findings/search is server-side
    filtered. Tags accumulate (OR logic).

Retrieval mode:
    --mode search (default) — synchronous paginated
    --mode export — async bulk export (cannot be combined with --tag)

Severity filter:
    --severity Critical --severity High (repeatable)
"""

import argparse
import os
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.common.config import AppConfig, AppSettings
from src.common.db import init_db
from src.pipeline import run_pipeline


def main():
    parser = argparse.ArgumentParser(description="Run the VM Middleware pipeline locally")
    parser.add_argument("--mock", action="store_true", help="Use mock Tenable data from fixtures")
    parser.add_argument(
        "--fixture",
        default="tests/fixtures/sample_tenable_findings.json",
        help="Path to mock fixture file (default: tests/fixtures/sample_tenable_findings.json)",
    )
    parser.add_argument(
        "--enrichment",
        default="tests/fixtures/sample_enrichment.csv",
        help="Path to enrichment CSV (default: tests/fixtures/sample_enrichment.csv)",
    )
    parser.add_argument(
        "--config-dir",
        default="config",
        help="Path to config directory (default: config)",
    )
    parser.add_argument(
        "--tag",
        action="append",
        default=None,
        help="Client-side tag filter (repeatable). e.g. --tag Portfolio-Business-Growth",
    )
    parser.add_argument(
        "--mode",
        choices=["search", "export"],
        default=None,
        help="Tenable retrieval mode: search (sync) or export (async bulk)",
    )
    parser.add_argument(
        "--severity",
        action="append",
        default=None,
        help="Severity filter (repeatable). e.g. --severity Critical --severity High",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="(legacy alias) Auto-resume is now the default; this flag is a no-op.",
    )
    parser.add_argument(
        "--start-fresh",
        action="store_true",
        help="Force a brand new pipeline run, ignoring any incomplete one.",
    )
    args = parser.parse_args()

    # Load config
    os.environ.setdefault("CONFIG_DIR", args.config_dir)
    settings = AppSettings(config_dir=args.config_dir)
    config = AppConfig(settings=settings)

    # Apply CLI overrides
    if args.tag:
        config.tenable.tag_filter = args.tag
        print(f">>> tag_filter override: {args.tag}")
    if args.mode:
        config.tenable.retrieval_mode = args.mode
        print(f">>> retrieval_mode override: {args.mode}")

    # Warn on incompatible combos
    if args.tag and (args.mode == "export" or config.tenable.retrieval_mode == "export"):
        print()
        print("!!! WARNING: --mode export does NOT return tag data from Tenable.")
        print("!!! Tag filter will drop ALL findings.")
        print("!!! Use --mode search (default) or omit --mode when filtering by tag.")
        print()
    if args.severity:
        config.tenable.severity_filter = args.severity
        print(f">>> severity_filter override: {args.severity}")

    # Initialise DB
    init_db(settings.database_url)

    # Run pipeline
    mock_path = str(project_root / args.fixture) if args.mock else None
    enrichment_path = str(project_root / args.enrichment) if args.enrichment else None

    run_pipeline(
        config=config,
        mock_fixture_path=mock_path,
        enrichment_csv_path=enrichment_path,
        start_fresh=args.start_fresh,
    )


if __name__ == "__main__":
    main()
