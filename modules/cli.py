"""Shared command-line handling for the three entry-point scripts.

Everything can run fully interactive (just answer the prompts, matching
how the tool is used mid-maintenance-window) or scripted via flags.
The password is always prompted - never accepted as an argument, so it
can't land in shell history or process listings.
"""

import argparse


def parse_args(description, needs_inventory=True):
    parser = argparse.ArgumentParser(description=description)

    parser.add_argument(
        "--ticket",
        help="Change/Jira ticket number (prompted if omitted)",
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

    args = parser.parse_args()

    if not args.ticket:
        args.ticket = input("Ticket: ")

    # Normalized so reports/<TICKET>/ is the same folder no matter how
    # the ticket was typed.
    args.ticket = args.ticket.strip().upper()

    return args
