"""Shared command-line handling for the three entry-point scripts.

Everything can run fully interactive (just answer the prompts, matching
how the tool is used mid-maintenance-window) or scripted via flags.
The password is always prompted - never accepted as an argument, so it
can't land in shell history or process listings.
"""

import argparse


def parse_args(description, needs_inventory=True):
    """needs_inventory=True adds the collection flags (inventory, username,
    redaction). The compare script passes False and gets only an optional
    --inventory, read for its pairs: list and nothing else."""
    parser = argparse.ArgumentParser(description=description)

    parser.add_argument(
        "--ticket",
        help="Change/Jira ticket number (prompted if omitted)",
    )

    if not needs_inventory:
        parser.add_argument(
            "--inventory",
            help=(
                "Inventory YAML whose 'pairs:' list names redundant pairs to compare "
                "(default: inventory/devices.yml if present; pairs whose hostnames differ "
                "only by a trailing number are inferred anyway)"
            ),
        )
        parser.add_argument(
            "--notes",
            help=(
                "Markdown file of your notes on the window "
                "(default: reports/<TICKET>/notes.md if present). Whatever you write there is "
                "rendered above the findings. scripts/notes.py starts one for you."
            ),
        )
        parser.add_argument(
            "--expectations",
            help=(
                "YAML file of the BGP prefix deltas you expect, per device and peer "
                "(default: reports/<TICKET>/expectations.yml if present). A delta that matches "
                "your plan is rated Stable; one that doesn't, or that no entry covers, is Attention."
            ),
        )

    if needs_inventory:
        parser.add_argument(
            "--inventory",
            help="Path to inventory YAML (default: inventory/devices.yml)",
        )
        parser.add_argument(
            "--username",
            help="SSH username (prompted if omitted)",
        )
        parser.add_argument(
            "--redact-secrets",
            action="store_true",
            help=(
                "Replace passwords, password hashes, SNMP communities, "
                "TACACS/RADIUS/BGP/OSPF keys, and PAN-OS encrypted values "
                "with <REDACTED> before anything is written to disk"
            ),
        )

    args = parser.parse_args()

    if not args.ticket:
        args.ticket = input("Ticket: ")

    # Normalized so reports/<TICKET>/ is the same folder no matter how
    # the ticket was typed.
    args.ticket = args.ticket.strip().upper()

    return args
