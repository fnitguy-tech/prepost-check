"""Quick plain-text pre/post comparison.

This is the fast on-call view written at the end of a postcheck run:
one .txt report diffing the latest precheck against the latest
postcheck, command by command, with expected churn filtered out. The
HTML report (modules/htmlreport.py) is the richer, shareable artifact.

Normalization is the heart of it: counters, uptimes, ARP/MAC age
timers, BGP message counts and content-version lines change on every
capture and would bury real findings, so they are stripped or collapsed
before diffing. Each command's rule keeps the operationally meaningful
columns (e.g. a BGP peer's state and prefix counts survive; its
up/down timer does not).
"""

import difflib
import os
import re

from modules.layout import find_latest_folder

# Commands whose output is captured for evidence but is too volatile to
# ever diff meaningfully (per-lane optics readings drift constantly).
SKIP_COMPARE_COMMANDS = [
    "show interfaces transceiver",
]

# Lines that change on every capture regardless of command.
NOISY_STARTS = [
    "Generated:",
    "Uptime:",
    "Free memory:",
    "Last table change time",
    "Number of table inserts",
    "Number of table deletes",
    "time:",
    "uptime:",
    "url-filtering-version:",
    "Last update age:",
    "Update messages:",
    "Total messages:",
    "Flap counts:",
    "lifetime remain:",
]


def normalize_line(command, line):
    """Return the comparable form of a line, or None to drop it."""
    line = line.rstrip("\n")

    if command in SKIP_COMPARE_COMMANDS:
        return None

    # Config output is compared verbatim - every character matters.
    if command in ["show running-config", "show config running"]:
        return line

    if any(line.strip().startswith(item) for item in NOISY_STARTS):
        return None

    # Strip trailing "x:y:z ago" / "N days, ... ago" age columns.
    line = re.sub(r"\s+\d+:\d+:\d+ ago$", "", line)
    line = re.sub(r"\s+\d+ days?,.*ago$", "", line)

    if command == "show ip bgp summary":
        # Keep peer identity + state/prefixes, drop the Up/Down timer
        # and message counters between them.
        parts = line.split()

        if "Estab" in parts:
            estab_index = parts.index("Estab")
            return " ".join(parts[0:3] + parts[estab_index:])

        if "Idle(Admin)" in parts:
            idle_index = parts.index("Idle(Admin)")
            return " ".join(parts[0:3] + parts[idle_index:])

        return line

    if command == "show ip ospf neighbor":
        # Column 5 is the dead-timer countdown - always different.
        parts = line.split()

        if len(parts) >= 8:
            return " ".join(parts[0:5] + parts[6:])

        return line

    if command == "show ip arp":
        # Column 1 is the entry age.
        parts = line.split()

        if len(parts) >= 4 and re.match(r"\d+:\d+:\d+", parts[1]):
            return " ".join([parts[0]] + parts[2:])

        return line

    if command == "show mac address-table":
        line = re.sub(r"\s+\d+:\d+:\d+ ago$", "", line)
        line = re.sub(r"\s+\d+ days?,.*ago$", "", line)
        return line

    if command == "show routing route":
        # PAN-OS route age is a bare integer column; drop all-digit
        # tokens so only destination/nexthop/flags are compared.
        parts = line.split()

        if len(parts) >= 5:
            return " ".join([p for p in parts if not p.isdigit()])

        return line

    if command == "show routing protocol bgp peer":
        stripped = line.strip()

        bgp_noise = [
            "Peer status:",
            "Update messages:",
            "Total messages:",
            "Last update age:",
            "Flap counts:",
        ]

        if any(stripped.startswith(item) for item in bgp_noise):
            # "Peer status: Established, for 123456 secs" - keep the
            # state, drop the ever-growing duration.
            if stripped.startswith("Peer status:"):
                if "," in stripped:
                    return stripped.split(",")[0]
                return stripped

            return None

        return line

    if command == "show routing protocol ospf neighbor":
        if line.strip().startswith("lifetime remain:"):
            return None

        return line

    if command == "show system info":
        stripped = line.strip()

        # Content/AV/threat package versions auto-update on their own
        # schedule - not maintenance-window findings.
        system_noise = [
            "time:",
            "uptime:",
            "url-filtering-version:",
            "global-protect-client-package-version:",
            "global-protect-clientless-vpn-version:",
            "app-version:",
            "av-version:",
            "threat-version:",
            "wildfire-version:",
        ]

        if any(stripped.startswith(item) for item in system_noise):
            return None

        return line

    return line


def parse_sections(file_path):
    """Split a capture file into {command: [normalized lines]}."""
    sections = {}
    current_command = "HEADER"
    sections[current_command] = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            clean_line = line.rstrip("\n")

            if clean_line.startswith("### ") and clean_line.endswith(" ###"):
                current_command = clean_line.replace("###", "").strip()
                sections[current_command] = []
            else:
                normalized = normalize_line(current_command, clean_line)

                if normalized is None:
                    continue

                sections[current_command].append(normalized)

    return sections


def write_compare_report(ticket, dirs, run_timestamp, console):
    """Diff latest precheck vs latest postcheck into a .txt report."""
    precheck_folder = find_latest_folder(dirs["precheck"], "precheck_")
    postcheck_folder = find_latest_folder(dirs["postcheck"], "postcheck_")

    if precheck_folder is None:
        console.print("No precheck folder found. Skipping compare.")
        return None

    if postcheck_folder is None:
        console.print("No postcheck folder found. Skipping compare.")
        return None

    os.makedirs(dirs["compare"], exist_ok=True)
    compare_file = os.path.join(dirs["compare"], f"compare_{run_timestamp}.txt")

    pre_files = sorted(os.listdir(precheck_folder))
    post_files = sorted(os.listdir(postcheck_folder))

    common_files = sorted(set(pre_files) & set(post_files))
    missing_post = sorted(set(pre_files) - set(post_files))
    new_post = sorted(set(post_files) - set(pre_files))

    with open(compare_file, "w", encoding="utf-8") as report:
        report.write("Pre/Post Maintenance Comparison Report\n")
        report.write("=" * 80 + "\n\n")
        report.write(f"Ticket:           {ticket}\n")
        report.write(f"Precheck Folder:  {precheck_folder}\n")
        report.write(f"Postcheck Folder: {postcheck_folder}\n\n")

        report.write("File Summary\n")
        report.write("-" * 80 + "\n")
        report.write(f"Common files: {len(common_files)}\n")
        report.write(f"Missing in postcheck: {len(missing_post)}\n")
        report.write(f"New in postcheck: {len(new_post)}\n\n")

        if missing_post:
            report.write("Missing in Postcheck:\n")
            report.writelines(f"- {file_name}\n" for file_name in missing_post)
            report.write("\n")

        if new_post:
            report.write("New in Postcheck:\n")
            report.writelines(f"+ {file_name}\n" for file_name in new_post)
            report.write("\n")

        for file_name in common_files:
            pre_path = os.path.join(precheck_folder, file_name)
            post_path = os.path.join(postcheck_folder, file_name)

            pre_sections = parse_sections(pre_path)
            post_sections = parse_sections(post_path)

            all_commands = sorted(set(pre_sections.keys()) | set(post_sections.keys()))

            report.write("\n")
            report.write("=" * 80 + "\n")
            report.write(f"Device/File: {file_name}\n")
            report.write("=" * 80 + "\n")

            device_changed = False

            for command in all_commands:
                pre_lines = pre_sections.get(command, [])
                post_lines = post_sections.get(command, [])

                if pre_lines == post_lines:
                    continue

                device_changed = True

                report.write("\n")
                report.write("-" * 80 + "\n")
                report.write(f"Command: {command}\n")
                report.write("-" * 80 + "\n")
                report.write("Differences detected.\n\n")

                diff = difflib.ndiff(pre_lines, post_lines)

                for line in diff:
                    if line.startswith("- "):
                        report.write(f"- {line[2:]}\n")
                    elif line.startswith("+ "):
                        report.write(f"+ {line[2:]}\n")

            if not device_changed:
                report.write("\nNo meaningful changes detected.\n")

    console.print(f"Compare report created: {compare_file}")

    return compare_file
