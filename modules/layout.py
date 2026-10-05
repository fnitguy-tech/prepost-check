"""On-disk layout for check output.

Everything a maintenance window produces lands under reports/, keyed by
ticket number, so evidence for one change never mixes with another:

    reports/
      <TICKET>/
        Precheck/precheck_<timestamp>/<hostname>.txt   (+ .zip)
        Postcheck/postcheck_<timestamp>/<hostname>.txt (+ .zip)
        Compare/compare_<timestamp>.txt / .html
        notes.md           (optional: the engineer's account of the window)

Every name that reaches the disk goes through safe_name() or
check_ticket() first. A device reports its own hostname and a person
types the ticket, so neither is trusted to be a safe file name.

Paths are anchored to the repo root (not the current working directory)
so the scripts behave the same no matter where they are invoked from.
"""

import os
import re
from datetime import datetime

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(REPO_ROOT, "reports")


# The longest device or ticket name we'll put on disk. Windows caps a
# whole path near 260 characters, and reports/<TICKET>/Precheck/
# precheck_<stamp>/<name>_<host>_FAILED.txt has to fit inside that.
MAX_NAME_LENGTH = 64

# Names Windows reserves in every folder, with or without an extension.
# "NUL.txt" can't be created there, so a device called NUL needs a nudge.
WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"{port}{n}" for port in ("COM", "LPT") for n in range(1, 10)}


class TicketError(ValueError):
    """Raised when a ticket ID can't be used as a folder name."""


def _clean_name(value):
    """safe_name() without the fallback: may come back empty."""
    name = re.sub(r"[^A-Za-z0-9._-]", "_", str(value or "").strip())
    # A leading dot hides the file on Linux and macOS, and "." / ".." are
    # folders. Windows drops a trailing dot without telling you.
    name = name.lstrip(".")[:MAX_NAME_LENGTH].rstrip(".")

    if name.split(".")[0].upper() in WINDOWS_RESERVED:
        name = f"_{name}"[:MAX_NAME_LENGTH]

    return name


def safe_name(value, fallback="device"):
    """Turn any text into a file name that's safe on Linux, macOS, and Windows.

    You get back only letters, digits, dot, underscore, and hyphen. It's
    never empty, never starts with a dot, and is never longer than
    MAX_NAME_LENGTH. That matters because the text comes from the device
    itself: a hostname of "../../x" must not write outside the run folder.

    Examples:
        "SITE-A-SW-1"   -> "SITE-A-SW-1"   (already safe, unchanged)
        "../../x"       -> "_.._x"
        "2001:db8::1"   -> "2001_db8__1"   (":" isn't allowed on Windows)
        ""              -> the fallback, cleaned the same way
    """
    return _clean_name(value) or _clean_name(fallback) or "device"


def check_ticket(ticket):
    """Return the ticket ID, or raise TicketError if it can't name a folder.

    The ticket becomes reports/<TICKET>/, so it has to be a plain name.
    We refuse a bad one instead of quietly changing it: you'd go looking
    for reports/NET-123/ and never find the folder we made up.

    Examples:
        "NET-123"  -> "NET-123"
        "../.."    -> TicketError (it would write outside reports/)
        ""         -> TicketError
    """
    ticket = str(ticket or "").strip()

    if not ticket or ticket != _clean_name(ticket):
        raise TicketError(
            f"Ticket {ticket!r} can't be used as a folder name. "
            f"Use 1 to {MAX_NAME_LENGTH} letters, digits, dots, underscores, or hyphens, "
            "starting with a letter or digit. Example: NET-123."
        )

    return ticket


def ticket_dirs(ticket):
    """Return the per-ticket directory paths (without creating them)."""
    ticket = check_ticket(ticket)
    base = os.path.join(REPORTS_DIR, ticket)

    return {
        "base": base,
        "precheck": os.path.join(base, "Precheck"),
        "postcheck": os.path.join(base, "Postcheck"),
        "compare": os.path.join(base, "Compare"),
        "notes": os.path.join(base, "notes.md"),
    }


def display_path(path):
    """Repo-relative form of a path for console output and report headers."""
    return os.path.relpath(path, REPO_ROOT)


def timestamp():
    """One timestamp format everywhere, sortable as a plain string.

    It goes down to the second. Two runs in the same minute used to get
    the same folder name, and the second run's files landed on top of
    the first. Older folders end at the minute (precheck_2026-04-14_08-48);
    they still sort correctly next to the new ones, because a name sorts
    before any longer name that starts with it.
    """
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def find_latest_folder(parent_dir, prefix):
    """Newest run folder under parent_dir matching prefix, or None.

    Relies on the timestamp format above sorting lexicographically.
    """
    if not os.path.exists(parent_dir):
        return None

    folders = sorted([
        folder for folder in os.listdir(parent_dir)
        if folder.startswith(prefix)
        and os.path.isdir(os.path.join(parent_dir, folder))
    ])

    if not folders:
        return None

    return os.path.join(parent_dir, folders[-1])
