#!/usr/bin/env python3
"""Capture pre-change device state.

Run this BEFORE the maintenance window starts. Collects every command
in the inventory from every device in parallel and zips the evidence
under reports/<TICKET>/Precheck/.

Usage:
    python3 scripts/precheck.py                 # fully interactive
    python3 scripts/precheck.py --ticket NET-123 --username admin
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console

from modules import collect, inventory, layout
from modules.cli import parse_args


def main():
    args = parse_args("Capture pre-change device state.")
    console = Console()

    platforms = inventory.load_inventory(args.inventory)
    username, password = inventory.prompt_credentials(args.username)
    jobs = inventory.build_jobs(platforms, username, password)

    dirs = layout.ticket_dirs(args.ticket)
    run_timestamp = layout.timestamp()

    os.makedirs(dirs["precheck"], exist_ok=True)

    _folder_name, zip_name = collect.run_collection(
        jobs, "precheck", dirs["precheck"], run_timestamp, console
    )

    console.print()
    console.print("[bold green]SUCCESS[/bold green]")
    console.print(f"Precheck ZIP created: {zip_name}")


if __name__ == "__main__":
    main()
