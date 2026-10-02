#!/usr/bin/env python3
"""Build the interpreted HTML maintenance report.

Diffs the latest precheck against the latest postcheck for a ticket and
writes a self-contained HTML dashboard (findings, impact scores,
charts, collapsible raw evidence) to reports/<TICKET>/Compare/. Needs
no device access - it only reads files already captured by
scripts/precheck.py and scripts/postcheck.py.

Usage:
    python3 scripts/compare.py                  # prompts for ticket
    python3 scripts/compare.py --ticket NET-123
    python3 scripts/compare.py --ticket NET-123 --inventory inventory/net-123-prepost.yml

The inventory is optional here and is read only for its "pairs:" list;
pairs whose hostnames differ only by a trailing number (SW-1 / SW-2)
are inferred from the captures without it.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console

from modules import htmlreport, inventory, layout
from modules.cli import parse_args


def main():
    args = parse_args("Build the interpreted HTML maintenance report.", needs_inventory=False)
    console = Console()

    dirs = layout.ticket_dirs(args.ticket)
    run_timestamp = layout.timestamp()
    pairs = inventory.load_pairs(args.inventory)

    htmlreport.build_html_report(args.ticket, dirs, run_timestamp, console, pairs=pairs)


if __name__ == "__main__":
    main()
