#!/usr/bin/env python3
"""Capture post-change device state and diff it against the precheck.

Run this AFTER the change is complete. Collects the same evidence as
the precheck, zips it under reports/<TICKET>/Postcheck/, then
immediately writes a plain-text comparison against the latest precheck
so you know before leaving the window whether anything unexpected
changed. Run scripts/compare.py afterwards for the full HTML report.

Usage:
    python3 scripts/postcheck.py                # fully interactive
    python3 scripts/postcheck.py --ticket NET-123 --username admin
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console

from modules import collect, inventory, layout, textcompare
from modules.cli import parse_args


def main():
    args = parse_args("Capture post-change device state and diff against the precheck.")
    console = Console()

    platforms = inventory.load_inventory(args.inventory)
    username, password = inventory.prompt_credentials(args.username)
    jobs = inventory.build_jobs(platforms, username, password)

    dirs = layout.ticket_dirs(args.ticket)
    run_timestamp = layout.timestamp()

    os.makedirs(dirs["postcheck"], exist_ok=True)

    _folder_name, zip_name = collect.run_collection(
        jobs, "postcheck", dirs["postcheck"], run_timestamp, console
    )

    textcompare.write_compare_report(args.ticket, dirs, run_timestamp, console)

    console.print()
    console.print("[bold green]SUCCESS[/bold green]")
    console.print(f"Postcheck ZIP created: {zip_name}")


if __name__ == "__main__":
    main()
