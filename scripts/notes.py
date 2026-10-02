#!/usr/bin/env python3
"""Start the maintenance notes for a ticket.

Writes reports/<TICKET>/notes.md, seeded with what the captures already
know - the ticket, the window times, the devices - and a heading per
question worth answering after a window. Fill it in with any editor;
scripts/compare.py renders it above the machine findings, so the report
on the ticket carries your account as well as the parser's.

Nothing here touches a device. It only reads the capture folders.

Usage:
    python3 scripts/notes.py                  # prompts for ticket
    python3 scripts/notes.py --ticket NET-123
    python3 scripts/notes.py --ticket NET-123 --notes /tmp/my-notes.md

An existing file is never overwritten: a half-written account is worth
more than a fresh skeleton.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console

from modules import layout, notes
from modules.cli import parse_args


def captured_hostnames(folder):
    """The hostnames in a capture folder, newest run, without .txt."""
    if folder is None:
        return []

    return sorted(
        name[: -len(".txt")]
        for name in os.listdir(folder)
        if name.endswith(".txt") and not name.endswith("_FAILED.txt")
    )


def main():
    args = parse_args("Start the maintenance notes for a ticket.", needs_inventory=False)
    console = Console()

    dirs = layout.ticket_dirs(args.ticket)
    precheck_folder = layout.find_latest_folder(dirs["precheck"], "precheck_")
    postcheck_folder = layout.find_latest_folder(dirs["postcheck"], "postcheck_")
    notes_path = args.notes or dirs["notes"]

    hostnames = captured_hostnames(postcheck_folder) or captured_hostnames(precheck_folder)

    written = notes.write_template(
        notes_path,
        args.ticket,
        layout.display_path(precheck_folder) if precheck_folder else "not captured yet",
        layout.display_path(postcheck_folder) if postcheck_folder else "not captured yet",
        hostnames,
    )

    if not written:
        console.print(f"Notes already exist: {layout.display_path(notes_path)} (left as they are)")
        return

    console.print(f"Notes template created: {layout.display_path(notes_path)}")
    console.print(f"Seeded with {len(hostnames)} device(s). Fill it in, then run scripts/compare.py.")


if __name__ == "__main__":
    main()
