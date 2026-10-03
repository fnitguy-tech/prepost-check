"""What the window is allowed to ask for.

Every action is a function here, and every one of them is something the CLI
already does. The window is a second front door onto the same code, not a
second implementation: `before` and `after` call `collect.run_collection`,
`report` calls `htmlreport.build_html_report`, and the notes form reads and
writes the same `notes.md` that `scripts/notes.py` seeds.

Two rules shape this file.

Nothing here takes a path from the page. A report is named by ticket and
file name, a capture run by ticket, phase and timestamp, and both are looked
up in `reports/`. A request cannot name a folder outside the tree, so there
is no path to escape from.

The SSH password arrives, goes to the job, and is never stored, logged or
returned. See `modules/ui/jobs.py`.
"""

import os
import webbrowser

from rich.console import Console

from modules import collect, history, htmlreport, inventory, layout, notes, textcompare
from modules.ui.jobs import ProgressSink


class ApiError(Exception):
    """Something the page asked for that cannot be done, with the reason."""


def _quiet_console():
    """A rich console that writes nowhere; jobs report through the sink."""
    return Console(file=open(os.devnull, "w", encoding="utf-8"), quiet=True)


def inventories():
    """The inventory files on disk, the default one first."""
    found = []
    inventory_dir = os.path.join(layout.REPO_ROOT, "inventory")

    if os.path.isdir(inventory_dir):
        for name in sorted(os.listdir(inventory_dir)):
            if name.endswith((".yml", ".yaml")) and not name.endswith(".example.yml"):
                found.append(layout.display_path(os.path.join(inventory_dir, name)))

    default = layout.display_path(os.path.join(inventory_dir, "devices.yml"))

    if default in found:
        found.remove(default)
        found.insert(0, default)

    return found


def plan(inventory_path=None):
    """What a capture would do: the devices and the commands, before you run it.

    The window shows this next to the buttons. A read-only sweep is still a
    sweep of production, and you should be able to see its shape first.
    """
    try:
        platforms = inventory.load_inventory(inventory_path or None)
    except Exception as error:  # noqa: BLE001 - surfaced to the page
        return {"ok": False, "error": str(error), "devices": [], "commands": 0}

    devices = []
    commands = 0

    for platform in platforms:
        for host in platform["hosts"]:
            devices.append({
                "host": str(host),
                "platform": platform.get("name", platform["device_type"]),
                "commands": len(platform["commands"]),
            })
            commands += len(platform["commands"])

    return {
        "ok": True,
        "error": None,
        "devices": devices,
        "commands": commands,
        # Stated so the window can say it next to the buttons. Every command
        # the inventory can carry is a show; collect.py sends nothing else.
        "read_only": True,
    }


def _jsonable(value):
    """Strip the datetimes history carries for its own ordering."""
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items() if key != "when"}

    if isinstance(value, list):
        return [_jsonable(item) for item in value]

    return value


def state(current_ticket=None):
    """Everything the page draws on load: tickets, runs, reports, notes."""
    tickets = _jsonable(history.scan())
    ticket = current_ticket or (tickets[0]["ticket"] if tickets else "")

    return {
        "tickets": tickets,
        "comparisons": history.comparisons(),
        "runs": _jsonable(history.all_runs()),
        "inventories": inventories(),
        "ticket": ticket,
        "notes": notes_for(ticket) if ticket else {"text": "", "exists": False, "open_items": 0},
    }


def notes_for(ticket):
    """One ticket's notes, and whether a file exists yet."""
    path = layout.ticket_dirs(ticket)["notes"]
    text = notes.load(path)

    return {
        "path": layout.display_path(path),
        "text": text or "",
        "exists": text is not None,
        "open_items": notes.open_task_count(text) if text else 0,
        "rendered": bool(text and notes.render_html(text)),
        "sections": [heading for heading, _prompt in notes.TEMPLATE_SECTIONS],
    }


def save_notes(ticket, text):
    """Write the notes for a ticket, creating the folder if needed."""
    if not ticket:
        raise ApiError("A ticket is needed before notes can be saved.")

    path = layout.ticket_dirs(ticket)["notes"]
    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w", encoding="utf-8") as file:
        file.write(text if text.endswith("\n") else f"{text}\n")

    return notes_for(ticket)


def seed_notes(ticket):
    """Seed the template from the captures, without overwriting notes."""
    if not ticket:
        raise ApiError("A ticket is needed before notes can be seeded.")

    dirs = layout.ticket_dirs(ticket)
    precheck = layout.find_latest_folder(dirs["precheck"], "precheck_")
    postcheck = layout.find_latest_folder(dirs["postcheck"], "postcheck_")
    hostnames, _failed = history.captured_devices(postcheck or precheck or "")

    notes.write_template(
        dirs["notes"],
        ticket,
        layout.display_path(precheck) if precheck else "not captured yet",
        layout.display_path(postcheck) if postcheck else "not captured yet",
        hostnames,
    )

    return notes_for(ticket)


def capture(runner, phase, ticket, username, password, inventory_path=None, redact=False):
    """Start a precheck or postcheck. The job does the SSH, not this call."""
    if phase not in ("precheck", "postcheck"):
        raise ApiError(f"Unknown phase {phase!r}.")

    if not ticket:
        raise ApiError("A ticket number is needed.")

    if not username or not password:
        raise ApiError("An SSH username and password are needed.")

    platforms = inventory.load_inventory(inventory_path or None)
    jobs = inventory.build_jobs(platforms, username, password)

    if not jobs:
        raise ApiError("The inventory has no devices in it.")

    dirs = layout.ticket_dirs(ticket)
    phase_dir = dirs[phase]
    run_timestamp = layout.timestamp()

    def work(job):
        os.makedirs(phase_dir, exist_ok=True)
        job.add_line(f"{phase} {ticket}: {len(jobs)} device(s)" + (", secrets redacted" if redact else ""))

        folder, zip_name = collect.run_collection(
            jobs, phase, phase_dir, run_timestamp, _quiet_console(),
            redact_secrets=redact, progress=ProgressSink(job),
        )

        captured, failed = history.captured_devices(folder)
        job.add_line(f"captured {len(captured)}, failed {len(failed)}")

        # `scripts/postcheck.py` writes the plain-text compare here, so the
        # window does too. Same ticket, same two files either way.
        if phase == "postcheck":
            # Returns None when there is no precheck to diff against. It
            # says so rather than raising, so check the path it hands back.
            compare_path = textcompare.write_compare_report(
                ticket, dirs, run_timestamp, _quiet_console()
            )
            job.add_line(
                f"wrote {layout.display_path(compare_path)}" if compare_path
                else "no precheck to compare against; text compare skipped"
            )

        return {
            "folder": layout.display_path(folder),
            "zip": layout.display_path(zip_name),
            "captured": captured,
            "failed": failed,
        }

    return runner.start(phase, ticket, work, password=password)


def build_report(runner, ticket):
    """Start the report. Reads files only - no device is touched."""
    if not ticket:
        raise ApiError("A ticket number is needed.")

    dirs = layout.ticket_dirs(ticket)

    def work(job):
        notes_text = notes.load(dirs["notes"])

        if notes_text is None:
            job.add_line("no notes.md yet; the report will carry findings only")
        elif notes.render_html(notes_text):
            job.add_line(f"notes: {notes.open_task_count(notes_text)} item(s) still open")
        else:
            job.add_line("notes.md is still a blank template; leaving it out")

        job.set_progress(0, 1, "analysing")
        path = htmlreport.build_html_report(
            ticket, dirs, layout.timestamp(), _quiet_console(),
            pairs=inventory.load_pairs(None), notes_text=notes_text,
        )

        if path is None:
            raise ApiError("Both a precheck and a postcheck are needed before a report.")

        job.set_progress(1, 1, "written")

        return {"report": layout.display_path(path), "ticket": ticket}

    return runner.start("report", ticket, work)


def compare_runs(runner, before, after, allow_reversed=False):
    """Start a comparison of two capture runs, named not pathed.

    `before` and `after` are {ticket, phase, stamp}. They are looked up in
    reports/, so the page cannot name a folder outside it.
    """
    left = history.find_run(None, before.get("ticket"), before.get("phase"), before.get("stamp"))
    right = history.find_run(None, after.get("ticket"), after.get("phase"), after.get("stamp"))

    if left is None or right is None:
        raise ApiError("One of those capture runs is no longer there. Reload the history.")

    def work(job):
        job.set_progress(0, 1, f"{left['ticket']} {left['phase']} -> {right['ticket']} {right['phase']}")

        try:
            path = history.compare_runs(left, right, allow_reversed=allow_reversed)
        except (history.ReversedRuns, history.NoSharedDevices) as error:
            raise ApiError(str(error)) from error

        job.set_progress(1, 1, "written")

        return {"report": layout.display_path(path), "ticket": f"{left['ticket']} vs {right['ticket']}"}

    label = (
        left["ticket"]
        if left["ticket"] == right["ticket"]
        else f"{left['ticket']} vs {right['ticket']}"
    )

    return runner.start("comparison", label, work)


def open_report(name):
    """Hand a report to the machine's default browser.

    The window has no tabs, so a report link cannot open one. This opens
    the file itself rather than the server's URL: no token in the address
    bar, and the page keeps working after the app is closed.
    """
    path = resolve_report(name)

    if path is None:
        raise ApiError("That report is not under reports/.")

    webbrowser.open(f"file://{path}")

    return {"opened": layout.display_path(path)}


def resolve_report(name):
    """An absolute path for a report the page asked to open, or None.

    The page passes the repo-relative label the API gave it. It is resolved
    against reports/ and checked to still be inside it, so a crafted name
    cannot reach another part of the filesystem.
    """
    if not name:
        return None

    candidate = os.path.realpath(os.path.join(layout.REPO_ROOT, name))
    root = os.path.realpath(layout.REPORTS_DIR)

    if not candidate.startswith(root + os.sep) or not os.path.isfile(candidate):
        return None

    if not candidate.endswith((".html", ".txt", ".md")):
        return None

    return candidate
