#!/usr/bin/env python3
"""Local pipeline runner entry point.

Usage:
    python scripts/run_local.py              # Run with real Tenable API
    python scripts/run_local.py --mock       # Run with mock fixture data
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
    args = parser.parse_args()

    # Load config
    os.environ.setdefault("CONFIG_DIR", args.config_dir)
    settings = AppSettings(config_dir=args.config_dir)
    config = AppConfig(settings=settings)

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
