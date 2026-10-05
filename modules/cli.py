"""Shared command-line handling for the three entry-point scripts.

Everything can run fully interactive (just answer the prompts, matching
how the tool is used mid-maintenance-window) or scripted via flags.
The password is always prompted - never accepted as an argument, so it
can't land in shell history or process listings.
"""

import argparse

from modules import hostkeys
from modules.layout import TicketError, check_ticket


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
        parser.add_argument(
            "--known-hosts",
            metavar="FILE",
            help=(
                "File of SSH host keys to check each device against. A new device's key is "
                "recorded on first connect; a changed key is refused. "
                f"(default: {hostkeys.default_path()}, or ${hostkeys.ENV_VAR} if set)"
            ),
        )
        parser.add_argument(
            "--insecure-accept-any-host-key",
            action="store_true",
            help=(
                "Skip the SSH host-key check and accept whatever key each device offers. "
                "Your password is then sent to anything that answers at the device's address, "
                "so use it only on a lab you trust."
            ),
        )

    args = parser.parse_args()

    if not args.ticket:
        args.ticket = input("Ticket: ")

    # Normalized so reports/<TICKET>/ is the same folder no matter how
    # the ticket was typed. Checked, because it becomes a folder name: a
    # ticket of "../.." would write outside reports/.
    try:
        args.ticket = check_ticket(args.ticket.strip().upper())
    except TicketError as error:
        parser.error(str(error))

    return args


def host_keys_from(args):
    """The host-key store the capture flags ask for, or None for
    --insecure-accept-any-host-key (accept any key, check nothing)."""
    if args.insecure_accept_any_host_key:
        return None

    return hostkeys.HostKeyStore(args.known_hosts)
