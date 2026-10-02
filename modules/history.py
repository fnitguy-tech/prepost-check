"""Every window you have run, and comparisons across them.

`reports/` already keeps each window forever - captures, zips and reports,
timestamped under a ticket. What was missing is a way to look across them.

Two things live here. `scan()` walks the tree into a list of tickets, each
with its capture runs and the reports built from them, newest first. That
is what the history view reads.

`compare_runs()` is the more useful half: it runs the same analysis on any
two capture folders, from any two tickets. That answers a question the
per-window report cannot. "Is the prefix-list entry I fixed in NET-1 still
there two months later?" is a diff between NET-1's postcheck and today's
precheck, and the engine for it already exists.

Nothing here touches a device. It only reads folders.
"""

import os
import re
from datetime import datetime

from modules.layout import REPORTS_DIR, display_path, timestamp

# Where a cross-window comparison lands. It belongs to no single ticket, so
# it sits beside them rather than inside one.
COMPARISONS_DIRNAME = "Comparisons"

RUN_FOLDER = re.compile(r"^(precheck|postcheck)_(\d{4}-\d{2}-\d{2}_\d{2}-\d{2})$")
REPORT_FILE = re.compile(r"^compare_(.+)\.(html|txt)$")


def parse_run_timestamp(stamp):
    """The run folder's timestamp as a datetime, or None if it is not one."""
    try:
        return datetime.strptime(stamp, "%Y-%m-%d_%H-%M")
    except ValueError:
        return None


def captured_devices(folder):
    """(captured, failed) hostnames in one run folder."""
    captured = []
    failed = []

    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return [], []

    for name in names:
        if not name.endswith(".txt"):
            continue

        stem = name[: -len(".txt")]

        if stem.endswith("_FAILED"):
            failed.append(stem[: -len("_FAILED")])
        else:
            captured.append(stem)

    return captured, failed


def runs_for(ticket_dir):
    """Every capture run under one ticket, newest first.

    A run is a folder named `precheck_<ts>` or `postcheck_<ts>`. A bare zip
    beside it is the same run packaged, so it is not listed again.
    """
    found = []

    for phase, phase_dirname in (("precheck", "Precheck"), ("postcheck", "Postcheck")):
        phase_dir = os.path.join(ticket_dir, phase_dirname)

        if not os.path.isdir(phase_dir):
            continue

        for name in sorted(os.listdir(phase_dir)):
            match = RUN_FOLDER.match(name)
            path = os.path.join(phase_dir, name)

            if not match or not os.path.isdir(path):
                continue

            captured, failed = captured_devices(path)
            when = parse_run_timestamp(match.group(2))
            found.append({
                "phase": phase,
                "stamp": match.group(2),
                "when": when,
                # The same moment as a string, because `when` is a datetime
                # for the ordering and the direction check and the UI needs
                # something it can serialise.
                "when_text": when.strftime("%d %b %Y, %H:%M") if when else match.group(2),
                "path": path,
                "label": display_path(path),
                "devices": captured,
                "failed": failed,
                "zip": os.path.exists(f"{path}.zip"),
            })

    found.sort(key=lambda run: (run["stamp"], run["phase"]), reverse=True)

    return found


def reports_for(ticket_dir):
    """Every report built under one ticket, newest first."""
    compare_dir = os.path.join(ticket_dir, "Compare")
    found = []

    if not os.path.isdir(compare_dir):
        return found

    for name in sorted(os.listdir(compare_dir)):
        match = REPORT_FILE.match(name)

        if not match:
            continue

        path = os.path.join(compare_dir, name)
        found.append({
            "stamp": match.group(1),
            "kind": match.group(2),
            "path": path,
            "label": display_path(path),
            "size": os.path.getsize(path),
        })

    found.sort(key=lambda report: report["stamp"], reverse=True)

    return found


def scan(reports_dir=None):
    """Every ticket under reports/, newest activity first.

    The Comparisons folder is not a ticket, so it is left out; read it with
    `comparisons()` instead.
    """
    reports_dir = reports_dir or REPORTS_DIR
    tickets = []

    if not os.path.isdir(reports_dir):
        return tickets

    for name in sorted(os.listdir(reports_dir)):
        ticket_dir = os.path.join(reports_dir, name)

        if not os.path.isdir(ticket_dir) or name == COMPARISONS_DIRNAME:
            continue

        runs = runs_for(ticket_dir)
        reports = reports_for(ticket_dir)
        notes_path = os.path.join(ticket_dir, "notes.md")

        tickets.append({
            "ticket": name,
            "path": ticket_dir,
            "runs": runs,
            "reports": reports,
            "has_notes": os.path.exists(notes_path),
            "notes_path": notes_path,
            # What the history list sorts and summarises on.
            "latest": runs[0]["stamp"] if runs else "",
            "device_count": len(runs[0]["devices"]) if runs else 0,
        })

    tickets.sort(key=lambda entry: entry["latest"], reverse=True)

    return tickets


def comparisons(reports_dir=None):
    """Every cross-window comparison written so far, newest first."""
    reports_dir = reports_dir or REPORTS_DIR
    compare_dir = os.path.join(reports_dir, COMPARISONS_DIRNAME)
    found = []

    if not os.path.isdir(compare_dir):
        return found

    for name in sorted(os.listdir(compare_dir), reverse=True):
        if not name.endswith(".html"):
            continue

        path = os.path.join(compare_dir, name)
        found.append({
            "name": name,
            "path": path,
            "label": display_path(path),
            "size": os.path.getsize(path),
        })

    return found


def all_runs(reports_dir=None):
    """Every capture run across every ticket, newest first.

    This is what a cross-window comparison picks its two sides from, so the
    ticket is carried along with each run.
    """
    found = []

    for entry in scan(reports_dir):
        for run in entry["runs"]:
            found.append({**run, "ticket": entry["ticket"]})

    found.sort(key=lambda run: run["stamp"], reverse=True)

    return found


def find_run(reports_dir, ticket, phase, stamp):
    """One run by ticket, phase and timestamp, or None.

    The GUI posts back these three fields rather than a path, so a request
    can never name a folder outside reports/.
    """
    for run in all_runs(reports_dir):
        if run["ticket"] == ticket and run["phase"] == phase and run["stamp"] == stamp:
            return run

    return None


def comparison_name(before, after, stamp=None):
    """The filename for one cross-window comparison."""
    stamp = stamp or timestamp()
    left = f"{before['ticket']}-{before['phase']}-{before['stamp']}"
    right = f"{after['ticket']}-{after['phase']}-{after['stamp']}"

    return f"compare_{stamp}__{left}__vs__{right}.html"


class ReversedRuns(Exception):
    """Raised when the second run was captured before the first."""


class NoSharedDevices(Exception):
    """Raised when two runs have no device in common."""


def shared_devices(before, after):
    """Hostnames captured in both runs."""
    return sorted(set(before["devices"]) & set(after["devices"]))


def in_order(before, after):
    """True when `after` was captured at or after `before`.

    This is not fussiness. The interpreted layer reads the BGP Up/Down
    timer on the rule that the postcheck is always the later capture, so a
    session that reset shows a *smaller* uptime. Hand it the two runs
    backwards and every healthy long-lived session looks like it reset
    during the window, which is a page full of findings that are all wrong.
    """
    if before["when"] is None or after["when"] is None:
        return True

    return after["when"] >= before["when"]


def compare_runs(before, after, reports_dir=None, stamp=None, notes_text=None, allow_reversed=False):
    """Build a report from any two capture runs and return its path.

    `before` and `after` are run dicts from `all_runs()`. They can be from
    different tickets: comparing one window's postcheck against a later
    window's precheck is how you find out whether a fix held.

    Raises `ReversedRuns` when `after` is the earlier capture, unless you
    pass `allow_reversed`. See `in_order()` for why that matters.

    Raises `NoSharedDevices` when the two runs captured different fleets.
    The analysis works device by device on files present in both, so two
    unrelated windows produce a report with nothing in it - which reads as
    "nothing changed" rather than "these have nothing to compare".
    """
    from modules import htmlreport

    shared = shared_devices(before, after)

    if not shared:
        raise NoSharedDevices(
            f"{before['ticket']} {before['phase']} and {after['ticket']} {after['phase']} have no "
            f"device in common ({len(before['devices'])} and {len(after['devices'])} captured). "
            "There would be nothing to compare."
        )

    if not allow_reversed and not in_order(before, after):
        raise ReversedRuns(
            f"{after['ticket']} {after['phase']} ({after['stamp']}) was captured before "
            f"{before['ticket']} {before['phase']} ({before['stamp']}). Swap them, or the "
            "uptime checks will read every healthy session as a reset."
        )

    reports_dir = reports_dir or REPORTS_DIR
    out_dir = os.path.join(reports_dir, COMPARISONS_DIRNAME)
    os.makedirs(out_dir, exist_ok=True)

    out_path = os.path.join(out_dir, comparison_name(before, after, stamp))
    analysis = htmlreport.analyze(before["path"], after["path"])
    ticket = (
        before["ticket"]
        if before["ticket"] == after["ticket"]
        else f"{before['ticket']} vs {after['ticket']}"
    )
    page = htmlreport.render_html(ticket, before["path"], after["path"], analysis, notes_text=notes_text)

    with open(out_path, "w", encoding="utf-8") as file:
        file.write(page)

    return out_path
