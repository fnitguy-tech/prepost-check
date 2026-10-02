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
    python3 scripts/compare.py --ticket NET-123 --notes reports/NET-123/notes.md

The inventory is optional here and is read only for its "pairs:" list;
pairs whose hostnames differ only by a trailing number (SW-1 / SW-2)
are inferred from the captures without it.

The notes file (default reports/<TICKET>/notes.md) is your own account
of the window. Whatever you write there is rendered above the machine
findings, so the ticket carries both.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console

from modules import htmlreport, inventory, layout, notes
from modules.cli import parse_args


def main():
    args = parse_args("Build the interpreted HTML maintenance report.", needs_inventory=False)
    console = Console()

    dirs = layout.ticket_dirs(args.ticket)
    run_timestamp = layout.timestamp()
    pairs = inventory.load_pairs(args.inventory)

    notes_path = args.notes or dirs["notes"]
    notes_text = notes.load(notes_path)

    if notes_text is None:
        console.print(
            f"No maintenance notes at {layout.display_path(notes_path)}. "
            "Run scripts/notes.py to start one."
        )
    elif notes.render_html(notes_text):
        open_items = notes.open_task_count(notes_text)
        suffix = f", {open_items} item(s) still open" if open_items else ""
        console.print(f"Notes: {layout.display_path(notes_path)}{suffix}")
    else:
        # A template nobody filled in must not read as a finished
        # write-up, so say so rather than rendering empty headings.
        console.print(f"Notes: {layout.display_path(notes_path)} is still a blank template; leaving it out.")

    htmlreport.build_html_report(
        args.ticket, dirs, run_timestamp, console,
        pairs=pairs, notes_text=notes_text,
    )


if __name__ == "__main__":
    main()
