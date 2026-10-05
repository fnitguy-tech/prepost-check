#!/usr/bin/env python3
"""Capture pre-change device state.

Run this BEFORE the maintenance window starts. Collects every command
in the inventory from every device in parallel and zips the evidence
under reports/<TICKET>/Precheck/.

Usage:
    python3 scripts/precheck.py                 # fully interactive
    python3 scripts/precheck.py --ticket NET-123 --username admin
    python3 scripts/precheck.py --redact-secrets   # no passwords/hashes in the capture

Exit code: 0 when every device was captured, 1 when some weren't, 2 when
none were. The last lines printed say which, for example:

    7 of 8 captured; 1 failed: 10.0.0.5 (authentication failed)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console

from modules import collect, inventory, layout
from modules.cli import host_keys_from, parse_args


def main():
    args = parse_args("Capture pre-change device state.")
    console = Console()

    platforms = inventory.load_inventory(args.inventory)
    username, password = inventory.prompt_credentials(args.username)
    jobs = inventory.build_jobs(platforms, username, password)

    dirs = layout.ticket_dirs(args.ticket)
    run_timestamp = layout.timestamp()

    os.makedirs(dirs["precheck"], exist_ok=True)

    host_keys = host_keys_from(args)

    if host_keys is None:
        console.print("[yellow]SSH host keys are not being checked (--insecure-accept-any-host-key).[/yellow]")

    result = collect.run_collection(
        jobs, "precheck", dirs["precheck"], run_timestamp, console,
        redact_secrets=args.redact_secrets, host_keys=host_keys,
    )

    return collect.report_run(result, "precheck", console)


if __name__ == "__main__":
    sys.exit(main())
