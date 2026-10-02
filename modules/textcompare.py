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
up/down timer does not). That is the right call for a diff, where the
timer differs on every capture; the interpreted HTML report reads the
same column, because an uptime that went backwards is the
only trace a session that reset and recovered leaves in that table.
"""

import os
import re

from modules import difftrim
from modules.layout import display_path, find_latest_folder

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
    "Bytes received",
    "Bytes sent",
    "Packets received",
    "Packets sent",
]

# PAN-OS IPsec / IKE / LSVPN status commands. Their rows carry tunnel
# identity (gateway name, peer address, tunnel interface, state) next to
# values that move on every rekey or capture: SPIs, lifetimes, message
# IDs, established/expiry timestamps, satellite login times.
VPN_SA_COMMANDS = [
    "show vpn ike-sa",
    "show vpn ipsec-sa",
]

VPN_SATELLITE_COMMANDS = [
    "show global-protect-gateway current-satellite",
    "show global-protect-satellite current-gateway",
]

# LSVPN per-tunnel flow table on a hub: each row names the tunnel and the
# satellite, then carries byte/packet counters that move every second.
# Same shape as an SA row, so the SA rule handles it: keep the identity
# column, drop the numeric ones.
# Hub gateway list. The built state (tunnel, pool, access routes,
# certificate) is what a maintenance changes; the per-gateway satellite
# counter moves whenever an aircraft powers up or leaves, which is
# normal operation, not a change we made.
VPN_GATEWAY_COMMANDS = [
    "show global-protect-gateway gateway",
]

VPN_GATEWAY_COUNT_FIELDS = (
    "number of satellites",
    "current satellites",
    "satellites connected",
    "active satellites",
)

VPN_FLOW_COMMANDS = [
    "show global-protect-gateway flow-site-to-site",
    "show global-protect-gateway flow",
]

# Tokens in an SA table row that change without the tunnel changing.
VPN_CHURN_TOKENS = [
    re.compile(r"^(0x)?[0-9a-fA-F]{8,}$"),                  # SPI (hex, with or without 0x)
    re.compile(r"^[A-Z][a-z]{2}\.\d{1,2}$"),                # date: Aug.31
    re.compile(r"^\d{1,2}:\d{2}(:\d{2})?$"),               # time: 10:11:12
    re.compile(r"^\d+(\.\d+)?(/\d+(\.\d+)?)?[A-Za-z]{0,2}$"),  # counters, 3450/28800, 1.2GB
    re.compile(r"^\d+[hms](\d+[ms])*$"),                     # 1h10m rekey countdown
]

# key: value lines in the LSVPN satellite/gateway output that only
# record when the session started, not whether it is up.
VPN_SATELLITE_NOISE = (
    "login time",
    "logout time",
    "connect time",
    "uptime",
    "established",
    "expiration",
)


def normalize_vpn_line(command, line):
    """Shared IPsec/IKE/LSVPN churn rule; returns the line unchanged for
    every other command so callers can apply it unconditionally."""
    if command in VPN_SA_COMMANDS or command in VPN_FLOW_COMMANDS:
        # "Total 1 gateways found. 1 ike sa found." is the SA count -
        # keep it whole so an SA vanishing is a visible diff.
        if "found" in line:
            return line

        parts = line.split()

        if len(parts) < 2:
            return line

        # Never drop the first token: it is the gateway ID / gateway
        # name that identifies the row. IPv4 addresses never match the
        # counter pattern (three dots) so peers survive.
        kept = [parts[0]] + [
            p for p in parts[1:]
            if not any(pattern.match(p) for pattern in VPN_CHURN_TOKENS)
        ]
        return " ".join(kept)

    if command in VPN_SATELLITE_COMMANDS:
        if line.strip().lower().startswith(VPN_SATELLITE_NOISE):
            return None

        return line

    if command in VPN_GATEWAY_COMMANDS:
        if line.strip().lower().startswith(VPN_GATEWAY_COUNT_FIELDS):
            return None

        return line

    return line


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

    if (command in VPN_SA_COMMANDS or command in VPN_SATELLITE_COMMANDS
            or command in VPN_FLOW_COMMANDS or command in VPN_GATEWAY_COMMANDS):
        return normalize_vpn_line(command, line)

    # EOS route-map / prefix-list listings carry per-entry hit counters;
    # the entries themselves are the point, so drop the counter line.
    if command in ["show route-map", "show ip prefix-list"]:
        if re.match(r"^\s*(Match|Set)?\s*clauses? hit", line.strip(), re.I):
            return None

        return re.sub(r"\s*\(\s*\d+\s+(matches|hits)\s*\)$", "", line)

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
        report.write(f"Precheck Folder:  {display_path(precheck_folder)}\n")
        report.write(f"Postcheck Folder: {display_path(postcheck_folder)}\n\n")

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

                diff = difftrim.ndiff(pre_lines, post_lines)

                for line in diff:
                    if line.startswith("- "):
                        report.write(f"- {line[2:]}\n")
                    elif line.startswith("+ "):
                        report.write(f"+ {line[2:]}\n")

            if not device_changed:
                report.write("\nNo meaningful changes detected.\n")

    console.print(f"Compare report created: {display_path(compare_file)}")

    return compare_file
