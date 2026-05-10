"""Management CLI for manual purge execution.

Usage:
    python -m contextify_cloud.cli.purge [--dry-run] [--batch-limit N]

    Or via the installed entry point:
    contextify-purge [--dry-run] [--batch-limit N]
"""

import argparse
import asyncio
import logging
import sys

from contextify_cloud.services.purge import run_purge_once

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


def main() -> None:
    """Run a single purge sweep and print results."""
    parser = argparse.ArgumentParser(description="Run a single purge sweep")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report candidates without mutating any data",
    )
    parser.add_argument(
        "--batch-limit",
        type=int,
        default=None,
        help="Max tenants to process (default: from config)",
    )
    args = parser.parse_args()

    result = asyncio.run(
        run_purge_once(dry_run=args.dry_run, batch_limit=args.batch_limit)
    )

    print(f"Dry run:           {result.dry_run}")
    print(f"Candidates:        {result.candidates}")
    print(f"Purged:            {result.purged}")
    print(f"Skipped (locked):  {result.skipped_locked}")
    print(f"Tombstones expired: {result.tombstones_expired}")
    if result.errors:
        print(f"Errors:            {len(result.errors)}")
        for err in result.errors:
            print(f"  - {err}")
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
