"""What's in a capture folder, and whether it can be trusted.

Both reports read capture folders through this module, so they agree on
four things:

1. Where one command's output ends and the next begins.
2. Which files are devices, and which devices are missing or failed.
3. Whether the run that wrote a folder got to the end.
4. Whether the "before" folder really is older than the "after" folder.

A capture file looks like this. The collector writes the two-line
marker; the device writes everything under it:

    ### show ip bgp summary ###
    --------------------------------------------------------------------------------
    BGP summary information for VRF default
"""

import json
import os
import re
from datetime import datetime

from modules.layout import safe_name

# The dash rule the collector writes under every section header. A
# header only counts when this exact line follows it.
SECTION_RULE = "-" * 80

# A device the collector couldn't capture gets this file instead of
# <hostname>.txt. The first line says what happened; the rest is the
# error text.
FAILED_SUFFIX = "_FAILED.txt"
FAILED_FIRST_LINE = "FAILED TO CONNECT TO"
NOT_ATTEMPTED_FIRST_LINE = "NOT ATTEMPTED:"

# Written into the run folder as the last step of a capture. A folder
# without it was interrupted partway (Ctrl-C, a crash, a closed laptop),
# so it's missing devices and isn't a full baseline.
COMPLETE_MARKER = "capture-complete.json"

NEWER_BASELINE_WARNING = "The before capture is newer than the after capture. Did you run before again by mistake?"

_RUN_STAMP = re.compile(r"_(\d{4}-\d{2}-\d{2}_\d{2}-\d{2})(-\d{2})?$")


def section_header(command):
    """The two-line marker the collector writes above a command's output."""
    return f"### {command} ###\n{SECTION_RULE}\n"


def read_sections(file_path):
    """Split a capture file into {command: [raw lines]}.

    A section starts only at the exact marker the collector writes: a
    "### command ###" line with the 80-dash rule right under it. Device
    output can't fake that by accident. A login banner inside
    `show running-config` like

        ### AUTHORIZED USE ONLY ###

    used to start a new section and cut the config in two. Now it's just
    another config line, because no dash rule follows it.

    Lines above the first header land under "HEADER". The dash rule
    stays in the section as its first line, the way it always has, so
    old and new captures compare the same.
    """
    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        lines = [line.rstrip("\n") for line in file]

    current_command = "HEADER"
    sections = {current_command: []}

    for index, line in enumerate(lines):
        is_header = (
            line.startswith("### ")
            and line.endswith(" ###")
            and index + 1 < len(lines)
            and lines[index + 1] == SECTION_RULE
        )

        if is_header:
            current_command = line.replace("###", "").strip()
            sections[current_command] = []
        else:
            sections[current_command].append(line)

    return sections


def capture_files(folder):
    """The device files in a run folder, sorted. Only .txt files count,
    so the completion marker is never mistaken for a device."""
    return sorted(name for name in os.listdir(folder) if name.endswith(".txt"))


def is_failed(file_name):
    return file_name.endswith(FAILED_SUFFIX)


def write_failed(folder, host, first_line, error_text):
    """Record a device we couldn't capture; returns the file path."""
    path = os.path.join(folder, f"{safe_name(host, 'device')}{FAILED_SUFFIX}")

    with open(path, "w", encoding="utf-8") as file:
        file.write(f"{first_line} {host}\n")
        file.write(error_text)

    return path


def _read_failed(path):
    """(was it attempted, [error lines]) from a _FAILED.txt file."""
    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        lines = [line.rstrip() for line in file.read().splitlines()]

    attempted = not (lines and lines[0].startswith(NOT_ATTEMPTED_FIRST_LINE))

    return attempted, [line for line in lines[1:] if line.strip()]


def _capture_address(path):
    """The "IP Address:" a capture file was taken from, or ""."""
    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        for _ in range(5):
            line = file.readline()

            if line.startswith("IP Address:"):
                return line.split(":", 1)[1].strip()

    return ""


def _problem(file_name, name, address, title, before, after, summary, evidence, detail):
    return {
        "file_name": file_name,
        "name": name,
        "address": address,
        "title": title,
        "before": before,
        "after": after,
        "summary": summary,
        "evidence": evidence,
        "detail": detail,
    }


def device_problems(precheck_folder, postcheck_folder):
    """Sort two run folders into devices to compare and devices to flag.

    Returns (common_files, problems). common_files are captured in both
    runs and safe to diff. problems is one dict for every device that
    isn't: unreachable, never attempted, missing, or new. Each of those
    means "we can't say this device is fine", so the reports list them
    first and rate them Action Required.

    Example. The before folder holds SW-1.txt, taken from 10.0.0.5. The
    after folder holds 10.0.0.5_FAILED.txt. The two are matched on the
    address and come back as one problem:

        SW-1 (10.0.0.5): Device unreachable after the change

    with the connect error from the FAILED file as its detail.
    """
    pre_files = capture_files(precheck_folder)
    post_files = capture_files(postcheck_folder)
    pre_ok = [name for name in pre_files if not is_failed(name)]
    post_ok = [name for name in post_files if not is_failed(name)]
    # Keyed the way write_failed() names the file, so a capture's
    # "IP Address:" line can be matched to it.
    pre_failed = {name[: -len(FAILED_SUFFIX)]: name for name in pre_files if is_failed(name)}
    post_failed = {name[: -len(FAILED_SUFFIX)]: name for name in post_files if is_failed(name)}

    def failure(folder, failed_file, label):
        attempted, detail = _read_failed(os.path.join(folder, failed_file))
        state = "Failed" if attempted else "Not attempted"
        what = "unreachable" if attempted else "not attempted"
        return state, what, f"{failed_file} in the {label} folder", detail

    common_files = sorted(set(pre_ok) & set(post_ok))
    problems = []

    for file_name in sorted(set(pre_ok) - set(post_ok)):
        name = file_name[: -len(".txt")]
        address = _capture_address(os.path.join(precheck_folder, file_name))
        failed_file = post_failed.pop(safe_name(address, ""), None) if address else None

        if failed_file:
            state, what, evidence, detail = failure(postcheck_folder, failed_file, "postcheck")
            problems.append(
                _problem(
                    file_name,
                    name,
                    address,
                    f"Device {what} after the change",
                    "Captured",
                    state,
                    "This device answered before the change and didn't after. Nothing about its state after the "
                    "change is known. Check that it's up and reachable, then run the postcheck again.",
                    evidence,
                    detail,
                )
            )
        else:
            problems.append(
                _problem(
                    file_name,
                    name,
                    address,
                    "Device missing after the change",
                    "Captured",
                    "Not captured",
                    "This device was captured before the change, and the after capture has no file for it at all. "
                    "Check that it's still in the inventory, then run the postcheck again.",
                    f"{file_name} is in the precheck folder only",
                    [],
                )
            )

    for file_name in sorted(set(post_ok) - set(pre_ok)):
        name = file_name[: -len(".txt")]
        address = _capture_address(os.path.join(postcheck_folder, file_name))
        failed_file = pre_failed.pop(safe_name(address, ""), None) if address else None

        if failed_file:
            state, what, evidence, detail = failure(precheck_folder, failed_file, "precheck")
            problems.append(
                _problem(
                    file_name,
                    name,
                    address,
                    f"Device {what} before the change",
                    state,
                    "Captured",
                    "This device has no before capture, so there's nothing to compare its after state against. "
                    "Check it by hand.",
                    evidence,
                    detail,
                )
            )
        else:
            problems.append(
                _problem(
                    file_name,
                    name,
                    address,
                    "Device only in the after capture",
                    "Not captured",
                    "Captured",
                    "This device has no before capture, so there's nothing to compare its after state against. "
                    "If it was renamed during the window, its old name is listed here as missing.",
                    f"{file_name} is in the postcheck folder only",
                    [],
                )
            )

    for host, failed_file in sorted(post_failed.items()):
        state, what, evidence, detail = failure(postcheck_folder, failed_file, "postcheck")
        before_file = pre_failed.pop(host, None)

        if before_file:
            before_state, _what, before_evidence, _detail = failure(precheck_folder, before_file, "precheck")
            problems.append(
                _problem(
                    failed_file,
                    host,
                    host,
                    f"Device {what} before and after the change",
                    before_state,
                    state,
                    "This device was never captured, so nothing about it is known. Check it by hand.",
                    f"{before_evidence}, and {evidence}",
                    detail,
                )
            )
        else:
            problems.append(
                _problem(
                    failed_file,
                    host,
                    host,
                    f"Device {what} after the change",
                    "Not captured",
                    state,
                    "Nothing about this device's state after the change is known. Check that it's up and "
                    "reachable, then run the postcheck again.",
                    evidence,
                    detail,
                )
            )

    for host, failed_file in sorted(pre_failed.items()):
        state, what, evidence, detail = failure(precheck_folder, failed_file, "precheck")
        problems.append(
            _problem(
                failed_file,
                host,
                host,
                f"Device {what} before the change",
                state,
                "Not captured",
                "This device has no capture before or after the change, so nothing about it is known. "
                "Check it by hand.",
                evidence,
                detail,
            )
        )

    return common_files, problems


def write_complete_marker(folder, phase, counts):
    """Mark a run folder as finished. Called once, after the last device.

    counts is a small dict of totals (devices, captured, failed, ...),
    kept in the marker so a reader can see what "finished" meant:

        {"phase": "precheck", "finished": "2026-04-14 08:49:31",
         "devices": 8, "captured": 7, "failed": 1}
    """
    record = {"phase": phase, "finished": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), **counts}

    with open(os.path.join(folder, COMPLETE_MARKER), "w", encoding="utf-8") as file:
        json.dump(record, file, indent=2)
        file.write("\n")


def run_stamp(folder):
    """A run folder's timestamp to the second, as a sortable string, or
    None when the name carries none. Older folders stop at the minute;
    they're read as second 00."""
    match = _RUN_STAMP.search(os.path.basename(os.path.normpath(folder)))

    if not match:
        return None

    return match.group(1) + (match.group(2) or "-00")


def baseline_warnings(precheck_folder, postcheck_folder):
    """Reasons not to trust this pair of folders: (warnings, notes).

    warnings go at the top of both reports and on the console. notes go
    on the console only.

    1. The before folder is newer than the after folder. Say you ran
       precheck.py at 08:48, made the change, then ran precheck.py again
       at 10:40 by mistake, and postcheck.py at 10:42. The comparison is
       now "after against after" and shows no change at all. Here the
       stamps are compared, and a before stamp later than the after
       stamp is called out.

    2. A folder has no completion marker. If its name carries seconds
       (precheck_2026-04-14_08-48-05), this version wrote it, and the
       only way it lacks a marker is that the run was cut short. That's
       a warning. If its name stops at the minute, an older version
       wrote it and never wrote markers, so there's no way to tell. That
       gets a note, and the comparison still runs.
    """
    warnings = []
    notes = []
    pre_stamp = run_stamp(precheck_folder)
    post_stamp = run_stamp(postcheck_folder)

    if pre_stamp and post_stamp and pre_stamp > post_stamp:
        warnings.append(NEWER_BASELINE_WARNING)

    for label, folder in (("before", precheck_folder), ("after", postcheck_folder)):
        if os.path.exists(os.path.join(folder, COMPLETE_MARKER)):
            continue

        name = os.path.basename(os.path.normpath(folder))

        if _RUN_STAMP.search(name) and _RUN_STAMP.search(name).group(2):
            warnings.append(
                f"The {label} capture ({name}) didn't finish. It was interrupted partway, "
                "so devices may be missing from it. Run it again before you trust this comparison."
            )
        else:
            notes.append(
                f"The {label} capture ({name}) has no completion marker. An older version wrote it, "
                "so there's no way to tell whether it finished."
            )

    return warnings, notes
