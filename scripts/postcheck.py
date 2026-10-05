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
    python3 scripts/postcheck.py --redact-secrets  # no passwords/hashes in the capture

Exit code: 0 when every device was captured, 1 when some weren't, 2 when
none were. The last lines printed say which, for example:

    7 of 8 captured; 1 failed: 10.0.0.5 (authentication failed)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console

from modules import collect, inventory, layout, textcompare
from modules.cli import host_keys_from, parse_args


def main():
    args = parse_args("Capture post-change device state and diff against the precheck.")
    console = Console()

    platforms = inventory.load_inventory(args.inventory)
    username, password = inventory.prompt_credentials(args.username)
    jobs = inventory.build_jobs(platforms, username, password)

    dirs = layout.ticket_dirs(args.ticket)
    run_timestamp = layout.timestamp()

    os.makedirs(dirs["postcheck"], exist_ok=True)

    host_keys = host_keys_from(args)

    if host_keys is None:
        console.print("[yellow]SSH host keys are not being checked (--insecure-accept-any-host-key).[/yellow]")

    result = collect.run_collection(
        jobs, "postcheck", dirs["postcheck"], run_timestamp, console,
        redact_secrets=args.redact_secrets, host_keys=host_keys,
    )

    # Written even when devices failed: the diff of the ones that did
    # answer is still worth reading, and it lists the ones that didn't.
    textcompare.write_compare_report(args.ticket, dirs, run_timestamp, console)

    return collect.report_run(result, "postcheck", console)


if __name__ == "__main__":
    sys.exit(main())
