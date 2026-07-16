#!/usr/bin/env python3
"""Housekeeping CLI — reap abandoned runs, prune aged STALE findings.

Both actions are DRY-RUN by default: they report what they would do and change
nothing. Pass --apply to commit. Thresholds come from config/maintenance.yaml
unless overridden on the command line.

Usage:
    # Preview which RUNNING runs would be reaped (nothing changes)
    .venv/bin/python3 scripts/maintenance.py --reap-runs

    # Actually reap them
    .venv/bin/python3 scripts/maintenance.py --reap-runs --apply

    # Override the abandonment threshold
    .venv/bin/python3 scripts/maintenance.py --reap-runs --timeout-hours 12 --apply

Note: the pipeline auto-reaps abandoned runs on every start, so a manual reap is
only needed to clean up between pipeline runs.
"""

import argparse
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.common.config import AppConfig, AppSettings
from src.common.db import get_session, init_db
from src.common.logging import setup_logging
from src.maintenance.retention import reap_stale_runs


def _do_reap(session, timeout_hours: int, apply: bool) -> None:
    reaped = reap_stale_runs(session, timeout_hours, dry_run=not apply)
    verb = "Reaped" if apply else "Would reap"
    print("=" * 60)
    print(f"  REAP ABANDONED RUNS  (timeout {timeout_hours}h)")
    print("=" * 60)
    if not reaped:
        print("  No abandoned RUNNING runs found.")
    else:
        print(f"  {verb} {len(reaped)} run(s):")
        for r in reaped:
            dur = f"{r['duration_hours']}h" if r["duration_hours"] is not None else "?"
            print(f"    - {r['id']}  started {r['started_at']}  last progress {r['last_progress_at']}  (ran ~{dur})")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="VM Middleware maintenance tasks")
    parser.add_argument("--reap-runs", action="store_true",
                        help="Reap RUNNING runs abandoned past the timeout.")
    parser.add_argument("--timeout-hours", type=int, default=None,
                        help="Override maintenance.run_timeout_hours for --reap-runs.")
    parser.add_argument("--apply", action="store_true",
                        help="Commit changes. Without this, actions are dry-run only.")
    parser.add_argument("--config-dir", default="config", help="Config directory.")
    args = parser.parse_args()

    if not args.reap_runs:
        parser.error("nothing to do — pass --reap-runs")

    settings = AppSettings(config_dir=args.config_dir)
    config = AppConfig(settings=settings)
    setup_logging(settings.log_level)
    init_db(settings.database_url)

    timeout_hours = args.timeout_hours if args.timeout_hours is not None else config.maintenance.run_timeout_hours

    with get_session() as session:
        if args.reap_runs:
            _do_reap(session, timeout_hours, args.apply)
        if args.apply:
            session.commit()
        else:
            session.rollback()
            print("\n  (dry run — nothing changed. Re-run with --apply to commit.)\n")


if __name__ == "__main__":
    main()
