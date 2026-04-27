#!/usr/bin/env python3
"""Local pipeline runner entry point.

Usage:
    python scripts/run_local.py
    python scripts/run_local.py --mock
    python scripts/run_local.py --tag Portfolio-Business-Growth
    python scripts/run_local.py --tag Portfolio-Business-Growth --tag Portfolio-Payments
    python scripts/run_local.py --mode export --tag Portfolio-Business-Growth

Tag filter:
    --tag X (repeatable). Only findings whose tag_names contain at least
    one of the supplied tags will be kept. Filtering is client-side
    because the Tenable Inventory API doesn't support server-side tag
    filters reliably.

Retrieval mode:
    --mode search (default) — synchronous paginated, good for small datasets
    --mode export — async bulk export, recommended for >50k findings

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
    )


if __name__ == "__main__":
    main()
