#!/usr/bin/env python3
"""Generate a CSV report from the scored findings in PostgreSQL.

Usage:
    .venv/bin/python3 scripts/generate_report.py --report findings
    .venv/bin/python3 scripts/generate_report.py --report risk-summary --out risk.csv
    .venv/bin/python3 scripts/generate_report.py --report findings \\
        --portfolio Business-Growth --risk-rating CRITICAL --risk-rating HIGH
    .venv/bin/python3 scripts/generate_report.py --list

Reports:
    findings            Full findings export (all fields)
    risk-summary        Counts by risk_rating x portfolio x criticality
    sla-breaches        Findings past their SLA
    sla-approaching     Findings near their SLA deadline
    recurrence          Findings that resurfaced after remediation
    portfolio-summary   Per-portfolio rollup

Filters (repeatable, AND across keys, OR within a key):
    --portfolio --service --environment --asset-criticality
    --risk-rating --severity --state --sla-status --source
"""

import argparse
import os
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.common.config import AppConfig, AppSettings
from src.common.db import get_session, init_db
from src.reporting import csv_reports


def main():
    parser = argparse.ArgumentParser(description="Generate a CSV report")
    parser.add_argument("--report", help="Report name (see --list)")
    parser.add_argument("--out", help="Output file path (default: stdout)")
    parser.add_argument("--list", action="store_true", help="List available reports")

    # Filters
    parser.add_argument("--portfolio", action="append")
    parser.add_argument("--service", action="append")
    parser.add_argument("--environment", action="append")
    parser.add_argument("--asset-criticality", action="append", dest="asset_criticality")
    parser.add_argument("--risk-rating", action="append", dest="risk_rating")
    parser.add_argument("--severity", action="append")
    parser.add_argument("--state", action="append")
    parser.add_argument("--sla-status", action="append", dest="sla_status")
    parser.add_argument("--source", action="append")

    args = parser.parse_args()

    if args.list:
        print("Available reports:")
        for name in sorted(csv_reports.REPORTS):
            print(f"  {name}")
        return

    if not args.report:
        parser.error("--report is required (or use --list)")

    # Build filter dict from provided args
    filters = {}
    for key in (
        "portfolio", "service", "environment", "asset_criticality",
        "risk_rating", "severity", "state", "sla_status", "source",
    ):
        val = getattr(args, key)
        if val:
            filters[key] = val

    settings = AppSettings()
    config = AppConfig(settings=settings)
    init_db(settings.database_url)

    with get_session() as session:
        try:
            output = csv_reports.generate(
                session, args.report, filters or None,
                container_patterns=config.tenable.container_registry_patterns,
            )
        except ValueError as e:
            parser.error(str(e))

    if args.out:
        Path(args.out).write_text(output)
        line_count = output.count("\n") - 1  # minus header
        print(f"Wrote {max(line_count, 0)} rows to {args.out}")
    else:
        print(output)


if __name__ == "__main__":
    main()
