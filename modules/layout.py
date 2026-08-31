"""On-disk layout for check output.

Everything a maintenance window produces lands under reports/, keyed by
ticket number, so evidence for one change never mixes with another:

    reports/
      <TICKET>/
        Precheck/precheck_<timestamp>/<hostname>.txt   (+ .zip)
        Postcheck/postcheck_<timestamp>/<hostname>.txt (+ .zip)
        Compare/compare_<timestamp>.txt / .html

Paths are anchored to the repo root (not the current working directory)
so the scripts behave the same no matter where they are invoked from.
"""

import os
from datetime import datetime

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(REPO_ROOT, "reports")


def ticket_dirs(ticket):
    """Return the per-ticket directory paths (without creating them)."""
    base = os.path.join(REPORTS_DIR, ticket)

    return {
        "base": base,
        "precheck": os.path.join(base, "Precheck"),
        "postcheck": os.path.join(base, "Postcheck"),
        "compare": os.path.join(base, "Compare"),
    }


def timestamp():
    """One timestamp format everywhere, sortable as a plain string."""
    return datetime.now().strftime("%Y-%m-%d_%H-%M")


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
