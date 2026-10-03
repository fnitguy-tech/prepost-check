"""Interpreted HTML maintenance report.

Where the text compare answers "what changed", this report answers "does
it matter": it parses BGP summaries into per-peer state, correlates
peer changes with config diffs, parses prefix-lists entry by entry,
classifies every changed command into a category (Configuration /
Protocol / Routing / Interface / ...), scores each device's operational
impact, and renders a self-contained dark dashboard (Chart.js from CDN
is its only external asset) that can be attached to a change ticket
as-is.

Impact levels, most to least severe:
    Action Required > Attention > Changed > Stable

Every interpreted finding, whatever parsed it, is one dict with the same
keys so it rolls into the health verdict, the attention list, the
per-device impact score and the charts through one path:

    classification  chart category (Protocol / Routing / Interface ...)
    category        short group label ("BGP state", "Prefix-list")
    impact          Stable / Changed / Attention / Action Required
    title           one-line headline
    subject         identity spans shown after the title (peer, list name)
    fields          [(label, before, after)] rendered as the state grid
    summary         plain-English interpretation
    evidence        which capture sections back it up
    detail          optional [(kind, text)] raw lines shown under it

Normalization here is looser than modules/textcompare.py:
this report keeps more context lines so the collapsible raw-diff
evidence sections read naturally.
"""

import html
import json
import os
import re
from datetime import datetime

from modules import difftrim, notes
from modules.layout import display_path, find_latest_folder
from modules.textcompare import (
    VPN_FLOW_COMMANDS,
    VPN_GATEWAY_COMMANDS,
    VPN_SA_COMMANDS,
    VPN_SATELLITE_COMMANDS,
    normalize_vpn_line,
)


def safe_id(value):
    """Make a string usable as an HTML anchor id."""
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-")


def parse_sections(file_path):
    """Split a capture file into {command: [raw lines]} (no filtering)."""
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
                sections[current_command].append(clean_line)

    return sections


def clean_line_for_compare(command, line):
    """Normalize a line for diffing, or None to drop it as noise."""
    line = line.rstrip("\n")

    if command in [
        "show interfaces transceiver",
        "show logging last 200",
        "show log system direction equal backward",
        "show log traffic direction equal backward",
    ]:
        return None

    if command in ["show running-config", "show config running"]:
        return line

    noisy_starts = [
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

    if any(line.strip().startswith(item) for item in noisy_starts):
        return None

    # IPsec/IKE/LSVPN churn (SPIs, rekey timers, login times) - one
    # rule shared with textcompare so the two reports agree.
    if (command in VPN_SA_COMMANDS or command in VPN_SATELLITE_COMMANDS
            or command in VPN_FLOW_COMMANDS or command in VPN_GATEWAY_COMMANDS):
        return normalize_vpn_line(command, line)

    if command == "show ip bgp summary":
        parts = line.split()

        if len(parts) >= 10:
            peer_ip_index = None

            for index, part in enumerate(parts):
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", part):
                    peer_ip_index = index
                    break

            if peer_ip_index is not None and peer_ip_index >= 1:
                peer_name = " ".join(parts[:peer_ip_index])
                peer_ip = parts[peer_ip_index]
                peer_as = parts[peer_ip_index + 2] if len(parts) > peer_ip_index + 2 else "UNKNOWN"

                if "Estab" in parts:
                    state_index = parts.index("Estab")
                    prefixes = " ".join(parts[state_index + 1:])
                    return f"{peer_name} {peer_ip} AS{peer_as} Estab {prefixes}"

                if "Idle(Admin)" in parts:
                    return f"{peer_name} {peer_ip} AS{peer_as} Idle(Admin)"

                return f"{peer_name} {peer_ip} AS{peer_as} {parts[-1]}"

        return line

    if command == "show ip ospf neighbor":
        parts = line.split()
        if len(parts) >= 8:
            return " ".join(parts[0:5] + parts[6:])
        return line

    if command == "show ip arp":
        parts = line.split()
        if len(parts) >= 4 and re.match(r"^\d+:\d+:\d+$", parts[1]):
            return " ".join([parts[0]] + parts[2:])
        return line

    if command in ["show ip route", "show ip route ospf"]:
        parts = line.split()
        if len(parts) >= 6 and parts[-2].isdigit():
            return " ".join(parts[:-2] + [parts[-1]])
        return line

    if command == "show mac address-table":
        line = re.sub(r"\s+\d+:\d+:\d+ ago$", "", line)
        line = re.sub(r"\s+\d+ days?,.*ago$", "", line)
        return line

    line = re.sub(r"\s+\d+:\d+:\d+ ago$", "", line)
    line = re.sub(r"\s+\d+ days?,.*ago$", "", line)

    return line


def normalized_section(command, lines):
    if command in PANOS_ROUTE_COMMANDS:
        lines = blank_panos_route_age(lines)

    cleaned = []

    for line in lines:
        new_line = clean_line_for_compare(command, line)

        if new_line is not None:
            cleaned.append(new_line)

    return cleaned


# PAN-OS prints 'show routing route' as fixed-width columns under a header
# that names them:
#
#   destination      nexthop      metric flags      age   interface   next-AS
#   10.61.82.7/32    10.2.1.1            A?B        2724             4280000001
#
# The age ticks every second, so a capture pair two minutes apart reports
# every BGP route as changed - 224 of 224 lines on one firewall here, with
# an identical route set. The header gives us the column map, so read the
# age span off it rather than guessing a field index: 'interface' and
# 'next-AS' are both optionally blank, which makes counting from the right
# unreliable.
PANOS_ROUTE_COMMANDS = ("show routing route",)

PANOS_ROUTE_HEADER = re.compile(r"^destination\s+nexthop\s+.*\bage\b")

PANOS_ROUTE_AGE = re.compile(r"^(\s*)(\d+)")


def blank_panos_route_age(lines):
    """Blank the age column of a PAN-OS routing table, tracking the header.

    A wide age overruns the header's own column width - 'age' is 6 columns
    but a 2666471-second route needs 7 - so match the number that starts in
    the age column rather than slicing a fixed span. Requiring it to start
    before the next column keeps a blank age from swallowing next-AS, which
    is also numeric. One capture holds a header per virtual router, so the
    columns are re-read each time rather than fixed once."""
    blanked = []
    age_start = None
    next_start = None

    for line in lines:
        if PANOS_ROUTE_HEADER.match(line):
            age_start = line.index("age")
            rest = line[age_start + len("age"):]
            gap = len(rest) - len(rest.lstrip())
            next_start = age_start + len("age") + gap if rest.strip() else len(line)
            blanked.append(line)
            continue

        if age_start is None or len(line) <= age_start:
            blanked.append(line)
            continue

        match = PANOS_ROUTE_AGE.match(line[age_start:])

        if match and age_start + len(match.group(1)) < next_start:
            age = match.group(2)
            cut = age_start + len(match.group(1))
            blanked.append(line[:cut] + " " * len(age) + line[cut + len(age):])
            continue

        blanked.append(line)

    return blanked


# EOS "Up/Down" column formats. The timer rolls over to a coarser unit as
# the session ages: 00:52:40 under a day, 1d02h under a week, 2w3d after
# that (and 1y2w eventually). "never" means the session has never come up.
UPTIME_CLOCK = re.compile(r"^(\d+):(\d{2}):(\d{2})$")
UPTIME_UNITS = re.compile(r"^(?:\d+[ywdhms])+$")
UPTIME_UNIT_SECONDS = {"y": 365 * 86400, "w": 7 * 86400, "d": 86400, "h": 3600, "m": 60, "s": 1}


def parse_uptime(token):
    """Seconds in an Up/Down value plus its granularity, or None.

    Granularity is the smallest unit the format shows (1s for a clock,
    1h for "1d02h", 1d for "2w3d"): the true value lies anywhere in
    [seconds, seconds + granularity), which the reset check honours so a
    coarse timer is never read as having gone backwards when it has not.
    Anything unparsable (including "never") is None, never a guess.
    """
    if token is None:
        return None

    token = token.strip()
    clock = UPTIME_CLOCK.match(token)

    if clock:
        hours, minutes, seconds = (int(part) for part in clock.groups())
        return hours * 3600 + minutes * 60 + seconds, 1

    if UPTIME_UNITS.match(token.lower()):
        total = 0
        granularity = None

        for amount, unit in re.findall(r"(\d+)([ywdhms])", token.lower()):
            total += int(amount) * UPTIME_UNIT_SECONDS[unit]
            granularity = UPTIME_UNIT_SECONDS[unit]

        return total, granularity

    # PAN-OS: "Peer status: Established, for 123456 secs".
    secs = re.match(r"^(\d+)\s*secs?$", token.lower())

    if secs:
        return int(secs.group(1)), 1

    return None


def session_reset(before, after):
    """True only when the post uptime is unambiguously smaller than the pre.

    The postcheck is always taken after the precheck, so a session that
    stayed up can only show an equal (coarse format) or larger value. A
    smaller one means the session was torn down and came back in between,
    which the state column alone (Estab -> Estab) can never show.
    """
    pre = parse_uptime(before.get("updown"))
    post = parse_uptime(after.get("updown"))

    if pre is None or post is None:
        return False

    post_seconds, post_granularity = post
    pre_seconds, _pre_granularity = pre

    return post_seconds + post_granularity <= pre_seconds


def parse_bgp_summary(lines):
    """Parse 'show ip bgp summary' rows into per-peer dicts.

    The Up/Down column is kept (as "updown") even though the raw-diff
    normalizers strip it: it is churn in a diff but the highest-signal
    field in the interpreted layer, because uptime going backwards is the
    only trace a reset-and-recovered session leaves in this table.
    """
    peers = {}

    for line in lines:
        clean = line.strip()

        if not clean:
            continue

        if clean.startswith(("Neighbor", "VRF", "Router", "BGP", "Pfx")):
            continue

        parts = clean.split()

        peer_ip_index = None

        for index, part in enumerate(parts):
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", part):
                peer_ip_index = index
                break

        if peer_ip_index is None:
            continue

        peer_name = " ".join(parts[:peer_ip_index])
        peer_ip = parts[peer_ip_index]
        peer_as = parts[peer_ip_index + 2] if len(parts) > peer_ip_index + 2 else "UNKNOWN"

        state = parts[-1]
        state_index = len(parts) - 1
        prefixes_received = "0"
        prefixes_accepted = "0"

        if "Estab" in parts:
            state = "Estab"
            state_index = parts.index("Estab")

            if len(parts) > state_index + 2:
                prefixes_received = parts[state_index + 1]
                prefixes_accepted = parts[state_index + 2]

        elif "Idle(Admin)" in parts:
            state = "Idle(Admin)"
            state_index = parts.index("Idle(Admin)")

        # Up/Down sits immediately before State. Only trust it when it
        # lies after the AS column, so a short or odd row yields None.
        updown = parts[state_index - 1] if state_index - 1 > peer_ip_index + 2 else None

        key = f"{peer_name} {peer_ip}"

        peers[key] = {
            "name": peer_name,
            "ip": peer_ip,
            "as": peer_as,
            "state": state,
            "prefixes_received": prefixes_received,
            "prefixes_accepted": prefixes_accepted,
            "updown": updown,
            "raw": clean,
        }

    return peers


# PAN-OS "show routing protocol bgp peer" is one indented block per peer
# rather than a table. These are the lines that carry the same facts the
# EOS summary row does; everything else in the block is ignored.
PANOS_PEER_START = re.compile(r"^\s*Peer:\s*(\S+)", re.IGNORECASE)
PANOS_PEER_FIELDS = {
    "address": re.compile(r"^\s*Peer address:\s*(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE),
    "as": re.compile(r"^\s*Remote AS:\s*(\d+)", re.IGNORECASE),
    "status": re.compile(r"^\s*Peer status:\s*([A-Za-z]+)(?:,\s*for\s+(\d+)\s*secs?)?", re.IGNORECASE),
    "incoming": re.compile(r"^\s*Incoming total:\s*(\d+),\s*accepted:\s*(\d+)", re.IGNORECASE),
}


def parse_panos_bgp_peers(lines):
    """Parse PAN-OS 'show routing protocol bgp peer' blocks into the same
    per-peer dicts parse_bgp_summary() produces, so the BGP findings
    treat a firewall peer exactly like a switch peer.

    "Established" is stored as "Estab" so the state transitions and the
    uptime reset check share one vocabulary; other PAN-OS states (Idle,
    Active, Connect, OpenSent) are kept as written.
    """
    peers = {}
    current = None

    for line in lines:
        start = PANOS_PEER_START.match(line)

        if start:
            current = {
                "name": start.group(1),
                "ip": "",
                "as": "UNKNOWN",
                "state": "UNKNOWN",
                "prefixes_received": "0",
                "prefixes_accepted": "0",
                "updown": None,
                "raw": line.strip(),
            }
            continue

        if current is None:
            continue

        address = PANOS_PEER_FIELDS["address"].match(line)
        remote_as = PANOS_PEER_FIELDS["as"].match(line)
        status = PANOS_PEER_FIELDS["status"].match(line)
        incoming = PANOS_PEER_FIELDS["incoming"].match(line)

        if address:
            current["ip"] = address.group(1)
            peers[f"{current['name']} {current['ip']}"] = current
        elif remote_as:
            current["as"] = remote_as.group(1)
        elif status:
            state = status.group(1)
            current["state"] = "Estab" if state.lower() == "established" else state

            if status.group(2) is not None:
                current["updown"] = f"{status.group(2)} secs"
        elif incoming and current["prefixes_received"] == "0":
            # First AFI/SAFI block only (ipv4 unicast comes first).
            current["prefixes_received"] = incoming.group(1)
            current["prefixes_accepted"] = incoming.group(2)

    return peers


def parse_bgp_peers(sections):
    """All BGP peers in one capture, whichever platform produced it."""
    peers = parse_bgp_summary(sections.get("show ip bgp summary", []))
    peers.update(parse_panos_bgp_peers(sections.get("show routing protocol bgp peer", [])))
    return peers


# Substrings that make a changed running-config line BGP-relevant. The
# list covers the policy objects a peer's behaviour is built from, not
# just the "router bgp" block: on EOS a prefix-list, access-list,
# peer-group, redistribution, BFD or link-state edit changes what a peer
# sends or accepts without touching a "neighbor" line, and on PAN-OS
# "valid-networks" and "used-by" (under "protocol bgp") are how routes
# are filtered and policies attached. Lowercased before matching.
BGP_CONFIG_KEYWORDS = [
    "router bgp",
    "protocol bgp",
    "neighbor",
    "peer-group",
    "peer group",
    "route-map",
    "prefix-list",
    "access-list",
    "access-group",
    "community",
    "send-community",
    "set community",
    "match community",
    "redist",
    "aggregate-address",
    "valid-networks",
    "auth-profile",
    "used-by",
    "bfd",
    "link-state",
    "shutdown",
    "no shutdown",
]


def bgp_config_changes(pre_sections, post_sections):
    """BGP-relevant lines that changed in the running config.

    Returns ndiff-style lines: "- " removed, "+ " added, and "  " context
    for the block header ("ip prefix-list ISP-OUT", "router bgp 64500")
    an indented change sits under. The header is what makes an indented
    "seq 40 permit ..." line BGP-relevant, and what makes it readable.
    """
    keywords = BGP_CONFIG_KEYWORDS

    pre_lines = pre_sections.get("show running-config", []) + pre_sections.get("show config running", [])
    post_lines = post_sections.get("show running-config", []) + post_sections.get("show config running", [])

    if pre_lines == post_lines:
        return []

    diff = difftrim.ndiff(pre_lines, post_lines)
    important = []
    # ndiff interleaves the two sides, so each side keeps its own notion
    # of "the block this line is under": a removed line belongs to the
    # precheck's last header, an added line to the postcheck's.
    headers = {"- ": "", "+ ": ""}
    emitted_header = None

    for line in diff:
        if line.startswith("? "):
            continue

        text = line[2:]
        sides = ["- ", "+ "] if line.startswith("  ") else [line[:2]]

        if text.strip() and not text[0].isspace():
            for side in sides:
                headers[side] = text

        if not line.startswith(("- ", "+ ")):
            continue

        content = text.strip().lower()
        indented = text[:1].isspace()
        block_header = headers[line[:2]]
        in_relevant_block = indented and any(keyword in block_header.lower() for keyword in keywords)

        if any(keyword in content for keyword in keywords) or in_relevant_block:
            if indented and block_header != emitted_header:
                important.append(f"  {block_header}")
                emitted_header = block_header
            elif not indented:
                # A changed header line is its own context for what follows.
                emitted_header = text

            important.append(line)

    return important


def count_config_changes(config_changes):
    """Added/removed lines only; block-header context lines do not count."""
    return sum(1 for line in config_changes if line.startswith(("- ", "+ ")))


def bgp_finding(classification, category, impact, title, peer, before, after, summary, evidence):
    """One BGP peer finding in the shared finding shape.

    The peer dicts are kept (before / after / peer) because tests and the
    summary text read them; subject and fields are what the renderer uses,
    so a BGP finding and a prefix-list finding draw the same way.
    """
    state_before = before["state"] if before else "Not Present"
    state_after = after["state"] if after else "Not Present"
    rx_before = before["prefixes_received"] if before else "0"
    rx_after = after["prefixes_received"] if after else "0"
    acc_before = before["prefixes_accepted"] if before else "0"
    acc_after = after["prefixes_accepted"] if after else "0"
    updown_before = (before.get("updown") or "n/a") if before else "Not Present"
    updown_after = (after.get("updown") or "n/a") if after else "Not Present"

    return {
        "classification": classification,
        "category": category,
        "impact": impact,
        "title": title,
        "peer": peer,
        "before": before,
        "after": after,
        "subject": [peer["name"], peer["ip"], f"AS{peer['as']}"],
        "fields": [
            ("State", state_before, state_after),
            ("Prefixes Received", rx_before, rx_after),
            ("Prefixes Accepted", acc_before, acc_after),
            ("Up/Down", updown_before, updown_after),
        ],
        "summary": summary,
        "evidence": evidence,
    }


# The caveat every prefix delta carries. A count that moved is worth
# showing; whether it was meant to is something only the engineer knows,
# and the notes are where that goes.
PREFIX_DELTA_HEDGE = (
    "That's normal if this window touched routing policy, communities, failover, or advertised routes."
)


def prefix_delta_finding(peer, before, after, delta, evidence):
    """One prefix-count change, rated Changed with the generic caveat."""
    return bgp_finding(
        "Routing", "BGP prefixes", "Changed", "BGP Prefix Count Changed", peer, before, after,
        f"Prefix count changed by {delta:+d}. {PREFIX_DELTA_HEDGE}",
        evidence,
    )


def bgp_neighbor_findings(pre_sections, post_sections, config_changes):
    """Interpret per-peer BGP changes into impact-rated findings."""
    pre_bgp = parse_bgp_peers(pre_sections)
    post_bgp = parse_bgp_peers(post_sections)

    findings = []
    config_text = "\n".join(config_changes).lower()

    for peer in sorted(set(pre_bgp) - set(post_bgp)):
        before = pre_bgp[peer]

        findings.append(bgp_finding(
            "Protocol", "BGP state", "Attention", "BGP Peer Removed From Summary",
            before, before, None,
            "This peer is in the precheck and gone from the postcheck. Either the neighbor was removed "
            "from the config, or the session never came back.",
            "show ip bgp summary",
        ))

    for peer in sorted(set(post_bgp) - set(pre_bgp)):
        after = post_bgp[peer]

        findings.append(bgp_finding(
            "Protocol", "BGP state", "Stable", "BGP Peer Added",
            after, None, after,
            "This peer isn't in the precheck and shows up in the postcheck. It's new since the window "
            "started.",
            "show ip bgp summary",
        ))

    for peer in sorted(set(pre_bgp) & set(post_bgp)):
        before = pre_bgp[peer]
        after = post_bgp[peer]

        detected_evidence = "show ip bgp summary"

        if after["ip"].lower() in config_text and "shutdown" in config_text:
            detected_evidence = "show ip bgp summary + related BGP shutdown/no shutdown config"
        elif "prefix-list" in config_text or "valid-networks" in config_text:
            detected_evidence = "show ip bgp summary + BGP prefix-list/valid-networks config"
        elif "community" in config_text or "route-map" in config_text:
            detected_evidence = "show ip bgp summary + BGP route-map/community config"

        if before["state"] != after["state"]:
            if before["state"] == "Idle(Admin)" and after["state"] == "Estab":
                title = "BGP Peer Activated"
                impact = "Stable"
                summary = "Someone un-shut this peer during the window and it came up."
            elif before["state"] == "Estab" and after["state"] == "Idle(Admin)":
                title = "BGP Peer Shut Down"
                impact = "Attention"
                summary = "Someone shut this peer down during the window. It's idle on purpose, not broken."
            else:
                title = "BGP Peer State Changed"
                impact = "Attention"
                summary = "This peer isn't in the state it started the window in."

            findings.append(bgp_finding(
                "Protocol", "BGP state", impact, title, after, before, after, summary, detected_evidence,
            ))

        elif after["state"] == "Estab" and session_reset(before, after):
            # Estab -> Estab looks healthy; a smaller uptime is the only
            # trace of a session that dropped and came straight back.
            before_received = int(before["prefixes_received"]) if before["prefixes_received"].isdigit() else 0
            after_received = int(after["prefixes_received"]) if after["prefixes_received"].isdigit() else 0
            delta = after_received - before_received
            prefix_note = (
                "Prefix counts came back the same." if delta == 0 and before["prefixes_accepted"] == after["prefixes_accepted"]
                else f"Prefix count also changed by {delta:+d} across the reset."
            )

            findings.append(bgp_finding(
                "Protocol", "BGP state", "Attention", "BGP Session Reset", after, before, after,
                f"This session dropped and came back during the window. It reads Established in both "
                f"captures, so nothing else gives it away - but uptime went from {before['updown']} to "
                f"{after['updown']}, and a session that never dropped can only count up. {prefix_note}",
                detected_evidence,
            ))

        elif (
            before["prefixes_received"] != after["prefixes_received"]
            or before["prefixes_accepted"] != after["prefixes_accepted"]
        ):
            before_received = int(before["prefixes_received"]) if before["prefixes_received"].isdigit() else 0
            after_received = int(after["prefixes_received"]) if after["prefixes_received"].isdigit() else 0
            delta = after_received - before_received

            findings.append(prefix_delta_finding(after, before, after, delta, detected_evidence))

    return findings


# "ip prefix-list NAME" opens a list in both the EOS show output and the
# running config; the one-line config form carries the entry on the same
# line ("ip prefix-list NAME seq 10 permit 10.0.0.0/8"). A Cisco-style
# header ("ip prefix-list NAME: 3 entries") leaves a colon on the name.
PREFIX_LIST_HEADER = re.compile(r"^\s*(?:ip|ipv6)\s+prefix-list\s+(\S+)(.*)$", re.IGNORECASE)
PREFIX_LIST_ENTRY = re.compile(r"^\s*seq\s+(\d+)\s+(.+?)\s*$", re.IGNORECASE)
# Per-entry hit counters tick on their own; the entry is the point.
PREFIX_LIST_HITS = re.compile(r"\s*\(\s*\d+\s+(?:matches|hits)\s*\)\s*$", re.IGNORECASE)


def parse_prefix_lists(lines):
    """Parse prefix-list listings into {list_name: {seq: rule}}.

    rule is the entry text after the sequence number with hit counters and
    extra whitespace removed, e.g. "permit 198.51.100.0/24 le 32", so two
    captures of an untouched list compare equal.
    """
    lists = {}
    current = None

    for line in lines:
        header = PREFIX_LIST_HEADER.match(line)

        if header:
            current = header.group(1).rstrip(":")
            lists.setdefault(current, {})
            rest = header.group(2)
        elif current is not None:
            rest = line
        else:
            continue

        entry = PREFIX_LIST_ENTRY.match(rest)

        if entry:
            rule = " ".join(PREFIX_LIST_HITS.sub("", entry.group(2)).split())
            lists[current][int(entry.group(1))] = rule
        elif current is not None and header is None and rest.strip() and not rest.startswith((" ", "\t")):
            # A non-indented line that is not a header ends the block
            # (config "!" separators, the next command's output).
            current = None

    return lists


def prefix_lists_from(sections, other_sections=None):
    """Prefix-lists for one capture, plus which command they came from.

    "show ip prefix-list" is preferred because it shows the list as the
    device holds it; inventories that do not capture it still carry the
    same entries in the running config. Both captures of a pair must use
    the same source so a list is never compared against itself.
    """
    other_sections = other_sections if other_sections is not None else sections

    if "show ip prefix-list" in sections and "show ip prefix-list" in other_sections:
        return parse_prefix_lists(sections["show ip prefix-list"]), "show ip prefix-list"

    config_lines = sections.get("show running-config", [])
    return parse_prefix_lists(config_lines), "show running-config"


def prefix_list_finding(impact, title, name, seq_label, fields, summary, evidence):
    """One prefix-list finding in the shared finding shape."""
    return {
        "classification": "Routing",
        "category": "Prefix-list",
        "impact": impact,
        "title": title,
        "subject": [name] + ([seq_label] if seq_label else []),
        "fields": fields,
        "summary": summary,
        "evidence": evidence,
    }


def entry_fields(seq_before, seq_after, rule_before, rule_after):
    """Sequence + entry columns for a single-entry prefix-list finding."""
    return [
        ("Sequence", str(seq_before) if seq_before is not None else "Not Present",
         str(seq_after) if seq_after is not None else "Not Present"),
        ("Entry", rule_before or "Not Present", rule_after or "Not Present"),
    ]


def prefix_list_findings(pre_sections, post_sections):
    """Interpret prefix-list changes entry by entry into impact-rated findings.

    A permit that disappears is a withdrawn advertisement (or a route no
    longer accepted, if the list is applied inbound), so it is rated
    Attention, as is a sequence whose entry changed in place: on EOS,
    configuring an existing sequence number silently replaces that entry,
    which is the easiest way to drop a prefix without meaning to. An
    entry that merely moved to a new sequence is Changed; a new sequence
    is Stable. A whole list appearing or vanishing is reported once.
    """
    pre_lists, evidence = prefix_lists_from(pre_sections, post_sections)
    post_lists, _ = prefix_lists_from(post_sections, pre_sections)

    findings = []

    for name in sorted(set(pre_lists) | set(post_lists)):
        before = pre_lists.get(name)
        after = post_lists.get(name)

        if after is None:
            finding = prefix_list_finding(
                "Attention", "Prefix-List Removed", name, None,
                [("Entries", str(len(before)), "Not Present")],
                f"Anything that still points at this list now matches nothing. All {len(before)} entries are "
                "gone from the postcheck, so every route the list used to permit falls through.",
                evidence,
            )
            finding["detail"] = [("removed", f"seq {seq} {rule}") for seq, rule in sorted(before.items())]
            findings.append(finding)
            continue

        if before is None:
            finding = prefix_list_finding(
                "Stable", "Prefix-List Added", name, None,
                [("Entries", "Not Present", str(len(after)))],
                f"Nothing changes yet. The postcheck has a new list of {len(after)} entries, and it does nothing "
                "until a route-map or neighbor points at it.",
                evidence,
            )
            finding["detail"] = [("added", f"seq {seq} {rule}") for seq, rule in sorted(after.items())]
            findings.append(finding)
            continue

        before_rules = set(before.values())
        after_rules = set(after.values())

        for seq in sorted(set(before) | set(after)):
            rule_before = before.get(seq)
            rule_after = after.get(seq)

            if rule_before is not None and rule_after is not None:
                if rule_before == rule_after:
                    continue

                if rule_before in after_rules:
                    moved_to = next(s for s, r in sorted(after.items()) if r == rule_before)
                    fate = f"The previous entry still appears at seq {moved_to}."
                else:
                    fate = "The previous entry no longer appears anywhere in the list."

                findings.append(prefix_list_finding(
                    "Attention", "Prefix-List Entry Replaced", name, f"seq {seq}",
                    entry_fields(seq, seq, rule_before, rule_after),
                    f"seq {seq} now holds '{rule_after}' instead of '{rule_before}'. Reusing a sequence number "
                    f"replaces that entry instead of adding one, so the old line is gone. {fate}",
                    evidence,
                ))

            elif rule_after is None:
                if rule_before in after_rules:
                    moved_to = next(s for s, r in sorted(after.items()) if r == rule_before)
                    findings.append(prefix_list_finding(
                        "Changed", "Prefix-List Entry Moved", name, f"seq {seq}",
                        entry_fields(seq, moved_to, rule_before, rule_before),
                        f"The same entry moved from seq {seq} to seq {moved_to}. The list still matches the same "
                        "routes, unless this moved it past a deny.",
                        evidence,
                    ))
                else:
                    action = rule_before.split()[0].lower() if rule_before else "permit"
                    effect = (
                        "Applied outbound, this route isn't advertised any more. Applied inbound, it isn't "
                        "accepted."
                        if action == "permit"
                        else "Routes this deny used to stop now get through."
                    )
                    findings.append(prefix_list_finding(
                        "Attention", "Prefix-List Entry Removed", name, f"seq {seq}",
                        entry_fields(seq, None, rule_before, None),
                        f"'{rule_before}' at seq {seq} is gone, and it doesn't come back at another sequence. "
                        f"{effect}",
                        evidence,
                    ))

            elif rule_after not in before_rules:
                # An entry that was already in the list at another seq is
                # reported once, as the resequence or overwrite above.
                findings.append(prefix_list_finding(
                    "Stable", "Prefix-List Entry Added", name, f"seq {seq}",
                    entry_fields(None, seq, None, rule_after),
                    f"'{rule_after}' was added at seq {seq}; existing entries are untouched.",
                    evidence,
                ))

    return findings


# ---------------------------------------------------------------------------
# Pair symmetry
#
# A redundant pair (SW-1 / SW-2, FW-1 / FW-2) is supposed to carry the same
# policy. The per-device findings cannot see "SW-1 and SW-2 now disagree",
# which is the real signature of a change applied to one member only, so
# the two postcheck captures are compared against each other as well.
# ---------------------------------------------------------------------------

PAIR_SUFFIX = re.compile(r"^(.*?)(\d+)$")
IPV4_NAME = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


def infer_pairs(hostnames):
    """Pairs of hostnames that differ only by a trailing number.

    SITE-A-SW-1 / SITE-A-SW-2 pair up; SITE-B-SW-1 alone does not; a
    group of three or more (LEAF-1/2/3) is not a pair and is left alone
    rather than guessed at. A capture named after a bare management IP
    (the collector's fallback for platforms it cannot ask for a hostname)
    is never paired: 192.0.2.11 and 192.0.2.12 share a stem by accident.
    """
    groups = {}

    for hostname in hostnames:
        match = PAIR_SUFFIX.match(hostname)

        if match and not IPV4_NAME.match(hostname):
            groups.setdefault(match.group(1).lower(), []).append(hostname)

    return [tuple(sorted(members)) for _stem, members in sorted(groups.items()) if len(members) == 2]


def resolve_pairs(hostnames, explicit=None):
    """Explicit inventory pairs (where both members were captured) plus
    inferred pairs for the devices the explicit list does not mention."""
    by_lower = {hostname.lower(): hostname for hostname in hostnames}
    pairs = []
    claimed = set()

    for pair in explicit or []:
        members = [by_lower.get(str(host).lower()) for host in pair]

        if all(members) and members[0] != members[1]:
            pairs.append(tuple(sorted(members)))
            claimed.update(members)

    for pair in infer_pairs([host for host in hostnames if host not in claimed]):
        pairs.append(pair)

    return pairs


ROUTE_MAP_HEADER = re.compile(r"^\s*route-map\s+(\S+?),?(\s+.*)?$", re.IGNORECASE)
ROUTE_MAP_HIT_LINES = re.compile(r"^\s*(Match|Set)?\s*clauses?\s+hit", re.IGNORECASE)


def parse_route_maps(lines):
    """Parse 'show route-map' (or the config's route-map blocks) into
    {name: [normalized lines]}, hit counters dropped, whitespace collapsed,
    so two captures of the same policy compare equal line for line."""
    maps = {}
    current = None

    for line in lines:
        header = ROUTE_MAP_HEADER.match(line)

        if header:
            current = header.group(1)
            rest = " ".join((header.group(2) or "").replace(",", " ").split())
            maps.setdefault(current, []).append(f"route-map {rest}".strip())
            continue

        if current is None:
            continue

        if not line.strip():
            continue

        if not line.startswith((" ", "\t")):
            # Non-indented, not a header: the block (or the section) ended.
            current = None
            continue

        if ROUTE_MAP_HIT_LINES.match(line):
            continue

        maps[current].append(" ".join(PREFIX_LIST_HITS.sub("", line).split()))

    return maps


def route_maps_from(sections, other_sections):
    """Route-maps for one capture, from the same source as its partner."""
    if "show route-map" in sections and "show route-map" in other_sections:
        return parse_route_maps(sections["show route-map"]), "show route-map"

    return parse_route_maps(sections.get("show running-config", [])), "show running-config"


# PAN-OS "show high-availability state" keys that differ between the two
# members of a healthy pair by design (one is active, one passive; each
# has its own addresses, serial and timers). Everything else - mode,
# software and content versions, sync state, encryption, cookies - is
# expected to match, and a mismatch is what a half-applied change
# looks like.
# A PAN-OS HA group header, with or without the group's local label.
HA_GROUP_HEADER = re.compile(r"^Group\s+\d+$", re.IGNORECASE)

HA_ROLE_KEYS = (
    "state",
    "priority",
    "address",
    "mac",
    "serial",
    "hostname",
    "last ",
    "duration",
    "time",
    "connection",
    "preempt hold",
    "uptime",
)


def parse_ha_state(lines):
    """Local-side key/value lines of 'show high-availability state' as
    {"Block/Key": value}, stopping at the Peer Information block (which
    describes the other member and is compared from its own capture)."""
    values = {}
    stack = []

    for line in lines:
        stripped = line.strip()

        if not stripped or ":" not in stripped:
            continue

        indent = len(line) - len(line.lstrip())
        key, _sep, value = stripped.partition(":")
        key = key.strip()
        value = value.strip()

        while stack and stack[-1][0] >= indent:
            stack.pop()

        if key.lower().startswith("peer information"):
            break

        # "Group 1:" on one member and "Group 1: MMP-E-HA" on the other are
        # the same block, but only the bare form looks like a block header to
        # the rule below, so one member's leaves land under "Group 1/Local
        # Information/Mode" and the other's under "Local Information/Mode".
        # Every key then differs and a healthy pair reads as 26 mismatches.
        # The label is a local name an operator typed, not synchronized
        # state - these four firewalls carry "", "MMP-E-HA", "MMP-W-FW1" and
        # "MMP-W-BU" - so treat the line as a header and drop the label.
        if HA_GROUP_HEADER.match(key):
            stack.append((indent, key))
            continue

        if not value:
            stack.append((indent, key))
            continue

        if any(role_key in key.lower() for role_key in HA_ROLE_KEYS):
            continue

        path = "/".join([name for _indent, name in stack] + [key])
        values[path] = value

    return values


# Route-map lines that bias which member is preferred, rather than deciding
# which routes match or where they go. A redundant pair is deliberately
# asymmetric in exactly these, so they are dropped before the two members
# are compared.
#
# Their *absence* is a setting too: the preferred member of this pair has no
# prepend line at all where the backup has "set as-path prepend 4280000001",
# so masking the value is not enough - the line has to go. Clause 30 of
# EACN-OUT is that case, and it was 22 lines against 23.
#
# What stays is everything that decides reachability: the clause headers and
# their permit/deny, every match line, set ip next-hop, set origin. Those
# must agree, because a peer that lands on either member has to be offered
# and accept the same routes.
ROUTE_MAP_TUNING = re.compile(
    r"""^(
          description
        | set \s+ as-path \s+ prepend
        | set \s+ local-preference
        | set \s+ metric
        | set \s+ (ext)?community
        | set \s+ weight
    )\b""",
    re.IGNORECASE | re.VERBOSE,
)


def canonical_route_map(body):
    """A route-map body with the per-member preference tuning dropped."""
    return [
        line.strip() for line in body
        if not ROUTE_MAP_TUNING.match(line.strip())
    ]


PAIR_SYMMETRY_CATEGORY = "Pair symmetry"


def pair_finding(classification, title, pair, subject, fields, summary, evidence, detail=None):
    """One pair-symmetry finding: Attention, attributed to both members."""
    finding = {
        "classification": classification,
        "category": PAIR_SYMMETRY_CATEGORY,
        "impact": "Attention",
        "title": title,
        "subject": [f"{pair[0]} vs {pair[1]}"] + subject,
        "fields": fields,
        "arrow": "vs",
        "summary": summary,
        "evidence": evidence,
        "devices": list(pair),
    }

    if detail:
        finding["detail"] = detail

    return finding


def pair_findings(pair, post_a, post_b, pre_a=None, pre_b=None):
    """Compare the two postcheck captures of a pair.

    Only commands present in both captures are compared. Same-named
    prefix-lists and route-maps must match entry for entry; a list that
    both members had in the precheck but only one has now is reported
    too, since that is what a list deleted on one side looks like.
    """
    a, b = pair
    findings = []
    pre_a = pre_a if pre_a is not None else {}
    pre_b = pre_b if pre_b is not None else {}

    lists_a, source = prefix_lists_from(post_a, post_b)
    lists_b, _ = prefix_lists_from(post_b, post_a)
    pre_lists_a, _ = prefix_lists_from(pre_a, pre_b)
    pre_lists_b, _ = prefix_lists_from(pre_b, pre_a)

    for name in sorted(set(lists_a) | set(lists_b)):
        entries_a = lists_a.get(name)
        entries_b = lists_b.get(name)

        if entries_a is None or entries_b is None:
            if name in pre_lists_a and name in pre_lists_b:
                missing_on = a if entries_a is None else b
                findings.append(pair_finding(
                    "Routing", "Pair Prefix-List Missing On One Device", pair, [name],
                    [("Entries", str(len(entries_a)) if entries_a else "Not Present",
                      str(len(entries_b)) if entries_b else "Not Present")],
                    f"{missing_on} lost prefix-list {name} during this window. Both members had it in the "
                    "precheck.",
                    source,
                ))
            continue

        differing = sorted(seq for seq in set(entries_a) | set(entries_b) if entries_a.get(seq) != entries_b.get(seq))

        if differing:
            fields = [
                (f"seq {seq}", entries_a.get(seq, "Not Present"), entries_b.get(seq, "Not Present"))
                for seq in differing
            ]
            findings.append(pair_finding(
                "Routing", "Pair Prefix-Lists Differ", pair, [name], fields,
                f"A peer gets different routes depending on which member it lands on. Prefix-list {name} "
                f"differs at {len(differing)} sequence(s), and a redundant pair is supposed to carry the same "
                "policy. Either one side was edited alone, or a sequence got overwritten on one side.",
                source,
            ))

    maps_a, map_source = route_maps_from(post_a, post_b)
    maps_b, _ = route_maps_from(post_b, post_a)
    pre_maps_a, _ = route_maps_from(pre_a, pre_b)
    pre_maps_b, _ = route_maps_from(pre_b, pre_a)

    for name in sorted(set(maps_a) | set(maps_b)):
        body_a = maps_a.get(name)
        body_b = maps_b.get(name)

        if body_a is None or body_b is None:
            if name in pre_maps_a and name in pre_maps_b:
                missing_on = a if body_a is None else b
                findings.append(pair_finding(
                    "Routing", "Pair Route-Map Missing On One Device", pair, [name],
                    [("Lines", str(len(body_a)) if body_a else "Not Present",
                      str(len(body_b)) if body_b else "Not Present")],
                    f"{missing_on} lost route-map {name} during this window. Both members had it in the "
                    "precheck.",
                    map_source,
                ))
            continue

        if body_a == body_b:
            continue

        # A redundant pair is deliberately asymmetric: you make one member
        # preferred by prepending your own AS more times on it, or by setting
        # a lower local-preference, and you label the result "Path 1".. "Path
        # 4". Those differences are the design, not a defect, and on this
        # fleet they accounted for 24 of 28 route-map findings - enough noise
        # to bury the four real ones. So compare the bodies with the tunable
        # values canonicalized: if the two sides match once the knob settings
        # are set aside, the only difference is tuning and there is nothing to
        # report. Anything that changes which routes match or where they go
        # still differs, and still fires.
        if canonical_route_map(body_a) == canonical_route_map(body_b):
            continue

        detail = []

        for line in difftrim.ndiff(body_a, body_b):
            if line.startswith("- "):
                detail.append(("removed", f"{a}: {line[2:]}"))
            elif line.startswith("+ "):
                detail.append(("added", f"{b}: {line[2:]}"))

        findings.append(pair_finding(
            "Routing", "Pair Route-Maps Differ", pair, [name],
            [("Lines", str(len(body_a)), str(len(body_b))),
             ("Differing lines", str(sum(1 for kind, _ in detail if kind == "removed")),
              str(sum(1 for kind, _ in detail if kind == "added")))],
            f"Route-map {name} differs between the two members in a way that isn't preference tuning. "
            f"Lines only on {a} are red, lines only on {b} are green. This skips prepend depth, "
            "local-preference, metric, and community, because a pair is meant to differ in those.",
            map_source,
            detail,
        ))

    ha_command = "show high-availability state"

    if ha_command in post_a and ha_command in post_b:
        ha_a = parse_ha_state(post_a[ha_command])
        ha_b = parse_ha_state(post_b[ha_command])
        differing = sorted(key for key in set(ha_a) | set(ha_b) if ha_a.get(key) != ha_b.get(key))

        if differing:
            fields = [(key, ha_a.get(key, "Not Present"), ha_b.get(key, "Not Present")) for key in differing]
            findings.append(pair_finding(
                "Protocol", "Pair HA State Differs", pair, ["high-availability"], fields,
                f"These two members disagree on {len(differing)} HA value(s) that a healthy pair keeps in sync. "
                "Values that depend on which member is active - state, priority, and addresses - don't count. "
                "A version, sync, or cookie mismatch means one member didn't get what the other did.",
                ha_command,
            ))

        # The firewall grades its own content versions against its peer's and
        # reports the verdict. Both members print the same verdict, so a
        # Mismatch reads as agreement to the key-by-key compare above and
        # slips through it - it needs asking for directly.
        mismatched = sorted(
            key for key in set(ha_a) | set(ha_b)
            if "compatibility" in key.lower()
            and "mismatch" in (ha_a.get(key, "") + ha_b.get(key, "")).lower()
        )

        if mismatched:
            fields = [(key.rsplit("/", 1)[-1], ha_a.get(key, "Not Present"), ha_b.get(key, "Not Present"))
                      for key in mismatched]
            findings.append(pair_finding(
                "Protocol", "Pair HA Content Version Mismatch", pair, ["high-availability"], fields,
                f"This pair disagrees with itself: {len(mismatched)} content version(s) read Mismatch. Both "
                "members print the same verdict, so comparing the two captures can't catch it. Policy that "
                "leans on that content - an application, a threat signature, an IoT device profile - can "
                "decide differently after a failover than before it. Run 'show system info' on both members "
                "to see which file is behind, then push that update to the stale one.",
                ha_command,
            ))

    return findings


# ---------------------------------------------------------------------------
# Interface addresses
#
# An interface that gained an IP address during the window and is up in
# the postcheck is the change working; one that gained an address and is
# still down means the step configured cleanly and does not work.
# ---------------------------------------------------------------------------

IPV4_PREFIX = re.compile(r"^\d+\.\d+\.\d+\.\d+/\d+$")
# EOS abbreviates names in "show interfaces status" (Et50/1) but spells
# them out in "show ip interface brief" and the config (Ethernet50/1).
EOS_SHORT_NAMES = {"Et": "Ethernet", "Po": "Port-Channel", "Ma": "Management", "Vl": "Vlan", "Lo": "Loopback"}
EOS_CONFIG_INTERFACE = re.compile(r"^interface\s+(\S+)\s*$", re.IGNORECASE)
EOS_CONFIG_ADDRESS = re.compile(r"^\s+ip address\s+(\d+\.\d+\.\d+\.\d+/\d+)", re.IGNORECASE)
# "set network interface ethernet ethernet1/1 layer3 ip A/B" names the
# port directly; sub-interfaces, loopbacks, tunnels and VLAN interfaces
# are "... units <name> ip A/B".
PANOS_CONFIG_ADDRESS = re.compile(
    r"^set network interface (\S+) (.+?)\s+ip\s+(\d+\.\d+\.\d+\.\d+/\d+)\s*$",
    re.IGNORECASE,
)


def expand_eos_name(name):
    for short, full in EOS_SHORT_NAMES.items():
        if name.startswith(short) and name[len(short):len(short) + 1].isdigit():
            return full + name[len(short):]
    return name


def parse_ip_interface_brief(lines):
    """EOS 'show ip interface brief' -> {name: {"address", "status"}}.

    Status is "up" only when both the Status and Protocol columns say so;
    otherwise the columns are kept verbatim ("down down", "admin down
    down") so the finding can show them.
    """
    interfaces = {}

    for line in lines:
        parts = line.split()

        if len(parts) < 4 or parts[0].lower() in ("interface", "address") or parts[0].startswith("-"):
            continue

        address = parts[1] if IPV4_PREFIX.match(parts[1]) else None

        if address is None and parts[1].lower() != "unassigned":
            continue

        status_tokens = []

        for token in parts[2:]:
            if token.isdigit():
                break
            status_tokens.append(token.lower())

        if not status_tokens:
            continue

        status = "up" if status_tokens == ["up", "up"] else " ".join(status_tokens)
        interfaces[parts[0]] = {"address": address, "status": status}

    return interfaces


def parse_interfaces_status(lines):
    """EOS 'show interfaces status' -> {full name: "up" | "<status>"}."""
    statuses = {}

    for line in lines:
        parts = line.split()

        if len(parts) < 3 or parts[0].lower() == "port" or not parts[0][:1].isalpha():
            continue

        for token in parts[1:]:
            if token.lower() in ("connected", "notconnect", "disabled", "errdisabled", "inactive"):
                statuses[expand_eos_name(parts[0])] = "up" if token.lower() == "connected" else token.lower()
                break

    return statuses


def parse_interface_all(lines):
    """PAN-OS 'show interface all' -> {name: {"address", "status"}}.

    The hardware table ("name id speed/duplex/state mac") gives link
    state per physical port; the logical table ("name id vsys zone
    forwarding tag address") gives addresses. A sub-interface takes its
    parent's link state; tunnel and loopback interfaces have none, so
    their status stays None and is never rated.
    """
    hardware = {}
    logical = {}

    for line in lines:
        parts = line.split()

        if len(parts) < 3 or not parts[1].isdigit():
            continue

        speed_duplex_state = parts[2].split("/")

        if len(speed_duplex_state) == 3 and not IPV4_PREFIX.match(parts[2]):
            hardware[parts[0]] = speed_duplex_state[2].lower()
        else:
            logical[parts[0]] = parts[-1] if IPV4_PREFIX.match(parts[-1]) else None

    interfaces = {}

    for name, address in logical.items():
        state = hardware.get(name, hardware.get(name.split(".")[0]))
        interfaces[name] = {"address": address, "status": state}

    for name, state in hardware.items():
        interfaces.setdefault(name, {"address": None, "status": state})

    return interfaces


def parse_config_addresses(lines):
    """Interface addresses from an EOS or PAN-OS (set format) config."""
    addresses = {}
    current = None

    for line in lines:
        panos = PANOS_CONFIG_ADDRESS.match(line)

        if panos:
            _kind, middle, address = panos.groups()
            tokens = middle.split()
            name = tokens[tokens.index("units") + 1] if "units" in tokens[:-1] else tokens[0]
            addresses[name] = address
            continue

        header = EOS_CONFIG_INTERFACE.match(line)

        if header:
            current = header.group(1)
            continue

        if current is None:
            continue

        if not line[:1].isspace():
            current = None
            continue

        address = EOS_CONFIG_ADDRESS.match(line)

        if address:
            addresses[current] = address.group(1)

    return addresses


def parse_interfaces(sections):
    """Address + link status per interface from whatever one capture has.

    Addresses come from the show tables first and the config second;
    status only ever comes from a show table, so an interface the capture
    cannot say is up or down gets None and no finding.
    """
    interfaces = {}
    sources = []

    if "show ip interface brief" in sections:
        interfaces.update(parse_ip_interface_brief(sections["show ip interface brief"]))
        sources.append("show ip interface brief")

    if "show interface all" in sections:
        interfaces.update(parse_interface_all(sections["show interface all"]))
        sources.append("show interface all")

    config_lines = sections.get("show running-config", []) + sections.get("show config running", [])

    for name, address in parse_config_addresses(config_lines).items():
        entry = interfaces.setdefault(name, {"address": None, "status": None})

        if entry["address"] is None:
            entry["address"] = address
            if "running config" not in sources:
                sources.append("running config")

    if "show interfaces status" in sections:
        statuses = parse_interfaces_status(sections["show interfaces status"])

        for name, entry in interfaces.items():
            if entry["status"] is None and name in statuses:
                entry["status"] = statuses[name]
                if "show interfaces status" not in sources:
                    sources.append("show interfaces status")

    return interfaces, sources


def interface_findings(pre_sections, post_sections):
    """Interfaces that gained an address during the window, rated by
    whether they are up in the postcheck. Never rated when the postcheck
    cannot say (no status column for that interface)."""
    pre, _pre_sources = parse_interfaces(pre_sections)
    post, sources = parse_interfaces(post_sections)
    findings = []

    for name in sorted(post):
        after = post[name]
        before = pre.get(name, {"address": None, "status": None})

        if after["address"] is None or before["address"] is not None or after["status"] is None:
            continue

        status_before = before["status"] or "Not Present"
        fields = [
            ("Address", "Not Present" if name not in pre else "unassigned", after["address"]),
            ("Status", status_before, after["status"]),
        ]
        evidence = " + ".join(sources)

        if after["status"] == "up":
            findings.append({
                "classification": "Interface",
                "category": "Interface address",
                "impact": "Stable",
                "title": "New Address, Interface Up",
                "subject": [name, after["address"]],
                "fields": fields,
                "summary": f"{name} gained {after['address']} during the window and is up in the postcheck.",
                "evidence": evidence,
            })
        else:
            findings.append({
                "classification": "Interface",
                "category": "Interface address",
                "impact": "Attention",
                "title": "New Address, Interface Still Down",
                "subject": [name, after["address"]],
                "fields": fields,
                "summary": (
                    f"The config is fine and the link isn't. {name} gained {after['address']} during the "
                    f"window but reads '{after['status']}' in the postcheck. Check the admin state, the cable, "
                    "or the far end before you close the window."
                ),
                "evidence": evidence,
            })

    return findings


def raw_diffs(pre_sections, post_sections):
    """Normalized added/removed lines per command."""
    all_commands = sorted(set(pre_sections.keys()) | set(post_sections.keys()))
    diffs = {}

    for command in all_commands:
        pre_lines = normalized_section(command, pre_sections.get(command, []))
        post_lines = normalized_section(command, post_sections.get(command, []))

        if pre_lines == post_lines:
            continue

        diff_lines = []

        for line in difftrim.ndiff(pre_lines, post_lines):
            if line.startswith("- "):
                diff_lines.append(("removed", line[2:]))
            elif line.startswith("+ "):
                diff_lines.append(("added", line[2:]))

        if diff_lines:
            diffs[command] = diff_lines

    return diffs


def classify_raw_diff_commands(diffs):
    """Count changed commands by operational category."""
    categories = {
        "Configuration": 0,
        "Protocol": 0,
        "Routing": 0,
        "Interface": 0,
        "Layer 2": 0,
        "Firewall": 0,
        "System": 0,
        "Evidence only": 0,
    }

    for command in diffs:
        if command in ["show running-config", "show config running"]:
            categories["Configuration"] += 1
        elif command in [
            "show ip bgp summary",
            "show ip ospf neighbor",
            "show high-availability state",
            "show mlag",
            "show vpn flow",
            *VPN_SA_COMMANDS,
            *VPN_SATELLITE_COMMANDS,
            *VPN_FLOW_COMMANDS,
            *VPN_GATEWAY_COMMANDS,
            "show global-protect-portal satellite-cookie-expiration",
        ]:
            categories["Protocol"] += 1
        elif command in [
            "show route-map",
            "show ip prefix-list",
            "show ip route",
            "show ip route ospf",
            "show ip bgp",
            "show routing route",
        ]:
            categories["Routing"] += 1
        # Both port-channel spellings: "summary" is Cisco's, "dense" is
        # EOS's, and a capture from either should land in this category.
        elif command in ["show interfaces status", "show interfaces trunk", "show port-channel summary", "show port-channel dense", "show interfaces counters errors", "show interfaces description"]:
            categories["Interface"] += 1
        elif command in ["show mac address-table", "show vlan brief", "show lldp neighbors"]:
            categories["Layer 2"] += 1
        elif command in ["show session info", "show counter global filter severity drop", "show jobs all"]:
            categories["Firewall"] += 1
        elif command in ["show system info", "show version", "show system resources"]:
            categories["System"] += 1
        else:
            categories["Evidence only"] += 1

    return categories


def render_diff_line(kind, text):
    css, sign = {"added": ("added", "+"), "removed": ("removed", "-")}.get(kind, ("context", " "))
    return f'<div class="{css}">{sign} {html.escape(text)}</div>'


def render_finding(finding):
    """Render one finding of any kind: badge, title, subject spans, the
    before/after grid built from its fields, summary, evidence, and any
    raw detail lines."""
    impact = finding["impact"]
    arrow = finding.get("arrow", "→")

    badge_class = {
        "Stable": "badge-stable",
        "Changed": "badge-changed",
        "Attention": "badge-attention",
        "Action Required": "badge-action",
    }.get(impact, "badge-changed")

    subject_html = ""

    for index, span in enumerate(finding.get("subject", [])):
        css = "peer-name" if index == 0 else "peer-ip"
        subject_html += f'<span class="{css}">{html.escape(str(span))}</span>\n            '

    fields_html = ""

    for label, before, after in finding.get("fields", []):
        fields_html += f"""
            <div>
                <div class="mini-label">{html.escape(label)}</div>
                <div class="state-flow"><span>{html.escape(str(before))}</span><span class="arrow">{html.escape(arrow)}</span><span>{html.escape(str(after))}</span></div>
            </div>"""

    detail_html = ""

    if finding.get("detail"):
        detail_html = '<div class="diff-box finding-detail">' + "".join(
            render_diff_line(kind, text) for kind, text in finding["detail"]
        ) + "</div>"

    return f"""
    <div class="finding {impact.lower().replace(" ", "-")}">
        <div class="finding-title">
            <span class="badge {badge_class}">{html.escape(impact)}</span>
            <span class="finding-heading">{html.escape(finding["title"])}</span>
            {subject_html}
        </div>

        <div class="finding-grid">{fields_html}
        </div>

        <div class="explanation">{html.escape(finding["summary"])}</div>
        <div class="evidence">Evidence: {html.escape(finding["evidence"])}</div>
        {detail_html}
    </div>
    """


# Titles produced by prefix_delta_finding() / the unmet check, so the
def analyze(precheck_folder, postcheck_folder, pairs=None):
    """Diff every common device file and roll up findings + totals.

    pairs: optional explicit [[host, host], ...] from the inventory; pairs
    whose hostnames differ only by a trailing number are inferred anyway.
    """
    pre_files = sorted(os.listdir(precheck_folder))
    post_files = sorted(os.listdir(postcheck_folder))
    common_files = sorted(set(pre_files) & set(post_files))

    total_findings_by_classification = {
        "Configuration": 0,
        "Protocol": 0,
        "Routing": 0,
        "Interface": 0,
        "Layer 2": 0,
        "Firewall": 0,
        "System": 0,
        "Evidence only": 0,
    }

    impact_totals = {
        "Stable": 0,
        "Changed": 0,
        "Attention": 0,
        "Action Required": 0,
    }

    # impact_totals split by where the finding came from: window_totals from
    # comparing pre against post, symmetry_totals from comparing the two
    # members of a pair against each other.
    window_totals = dict.fromkeys(impact_totals, 0)
    symmetry_totals = dict.fromkeys(impact_totals, 0)

    # Pass 1: per-device parsing and findings.
    devices = {}

    for file_name in common_files:
        pre_sections = parse_sections(os.path.join(precheck_folder, file_name))
        post_sections = parse_sections(os.path.join(postcheck_folder, file_name))

        hostname = file_name.replace(".txt", "")
        config_changes = bgp_config_changes(pre_sections, post_sections)
        findings = (
            bgp_neighbor_findings(pre_sections, post_sections, config_changes)
            + prefix_list_findings(pre_sections, post_sections)
            + interface_findings(pre_sections, post_sections)
        )
        diffs = raw_diffs(pre_sections, post_sections)

        devices[hostname] = {
            "file_name": file_name,
            "pre": pre_sections,
            "post": post_sections,
            "config_changes": config_changes,
            "findings": findings,
            "diffs": diffs,
            "raw_categories": classify_raw_diff_commands(diffs),
        }

    # Pass 2: pair symmetry. Each pair finding is attributed to both
    # members (it raises both devices' attention count and impact score)
    # but counted once in the network-wide totals.
    resolved_pairs = resolve_pairs(list(devices), pairs)
    all_pair_findings = []

    for pair in resolved_pairs:
        a, b = pair
        found = pair_findings(pair, devices[a]["post"], devices[b]["post"], devices[a]["pre"], devices[b]["pre"])
        all_pair_findings.extend(found)
        devices[a]["findings"].extend(found)
        devices[b]["findings"].extend(found)

    # Pass 3: counts, scores and totals.
    device_reports = []
    devices_with_findings = 0

    for hostname, device in devices.items():
        findings = device["findings"]
        config_changes = device["config_changes"]
        raw_categories = device["raw_categories"]

        config_change_count = count_config_changes(config_changes)
        findings_count = len(findings) + config_change_count

        if findings_count > 0:
            devices_with_findings += 1

        for finding in findings:
            if "devices" in finding and finding["devices"][0] != hostname:
                continue  # counted once, on the pair's first member

            total_findings_by_classification[finding["classification"]] += 1
            impact_totals[finding["impact"]] += 1

            # The health verdict answers "did this window change anything".
            # A pair-symmetry finding is a standing condition that was just
            # as true before the window as after, so it is counted on its
            # own and kept out of that verdict - otherwise a maintenance
            # that changed nothing reads as 30 problems it did not cause.
            if finding["category"] == PAIR_SYMMETRY_CATEGORY:
                symmetry_totals[finding["impact"]] += 1
            else:
                window_totals[finding["impact"]] += 1

        if config_change_count:
            total_findings_by_classification["Configuration"] += config_change_count
            impact_totals["Changed"] += config_change_count
            window_totals["Changed"] += config_change_count

        for category, count in raw_categories.items():
            if count:
                total_findings_by_classification[category] += count

        device_attention_count = sum(1 for f in findings if f["impact"] == "Attention")
        device_action_count = sum(1 for f in findings if f["impact"] == "Action Required")
        device_changed_count = sum(1 for f in findings if f["impact"] == "Changed")
        device_stable_count = sum(1 for f in findings if f["impact"] == "Stable")

        # Weighted so one action-required finding outranks any pile of
        # cosmetic churn; interface diffs weigh more than L2 noise.
        device_impact_score = (
            device_action_count * 10
            + device_attention_count * 5
            + device_changed_count * 2
            + config_change_count * 2
            + raw_categories["Interface"] * 4
            + device_stable_count
        )

        device_reports.append({
            "file_name": device["file_name"],
            "device_id": safe_id(hostname),
            "findings": findings,
            "config_changes": config_changes,
            "diffs": device["diffs"],
            "raw_categories": raw_categories,
            "findings_count": findings_count,
            "attention_count": device_attention_count,
            "action_count": device_action_count,
            "changed_count": device_changed_count,
            "stable_count": device_stable_count,
            "impact_score": device_impact_score,
        })

    device_reports = sorted(
        device_reports,
        key=lambda item: (
            item["action_count"],
            item["attention_count"],
            item["findings_count"],
            item["impact_score"],
        ),
        reverse=True,
    )

    return {
        "common_files": common_files,
        "device_reports": device_reports,
        "pairs": resolved_pairs,
        "pair_findings": all_pair_findings,
        "total_findings_by_classification": total_findings_by_classification,
        "impact_totals": impact_totals,
        "window_totals": window_totals,
        "symmetry_totals": symmetry_totals,
        "devices_with_findings": devices_with_findings,
    }


def render_html(ticket, precheck_folder, postcheck_folder, analysis, notes_text=None):
    """Render the analysis into a single self-contained HTML page."""
    common_files = analysis["common_files"]
    device_reports = analysis["device_reports"]
    total_findings_by_classification = analysis["total_findings_by_classification"]
    impact_totals = analysis["impact_totals"]
    devices_with_findings = analysis["devices_with_findings"]

    window_totals = analysis.get("window_totals", impact_totals)
    symmetry_totals = analysis.get("symmetry_totals", dict.fromkeys(impact_totals, 0))
    symmetry_count = sum(symmetry_totals.values())

    # Graded on the window alone. A pair-symmetry finding is a standing
    # condition the window did not create, so it gets its own sentence
    # instead of turning a clean verification red.
    if window_totals["Action Required"] > 0:
        overall_health = "Action Required"
    elif window_totals["Attention"] > 0:
        overall_health = "Attention"
    elif window_totals["Changed"] > 0:
        overall_health = "Changed"
    else:
        overall_health = "Stable"

    if overall_health == "Stable":
        assessment_text = "Nothing changed between the precheck and the postcheck beyond expected churn."
    elif overall_health == "Changed":
        assessment_text = "Something changed, but nothing needs your attention."
    elif overall_health == "Attention":
        assessment_text = "Something changed that you should look at. Click Attention to jump to it."
    else:
        assessment_text = "Something here may need fixing. Click Action Required to jump to it."

    if symmetry_count:
        assessment_text += (
            f" Separately, {symmetry_count} pair-symmetry finding(s) say how the two members of a redundant "
            "pair differ from each other right now. This window didn't cause them - they were just as true in "
            "the precheck - so they're listed on their own under Pair Symmetry."
        )

    summary_items = []

    for classification, count in total_findings_by_classification.items():
        if count:
            summary_items.append(f"{count} {classification.lower()} item(s).")

    if not summary_items:
        summary_items.append("Nothing worth reporting.")

    attention_devices = [
        report for report in device_reports
        if report["attention_count"] > 0 or report["action_count"] > 0
    ]

    chart_classification_labels = list(total_findings_by_classification.keys())
    chart_classification_values = list(total_findings_by_classification.values())

    chart_impact_labels = list(impact_totals.keys())
    chart_impact_values = list(impact_totals.values())

    chart_device_labels = [report["file_name"].replace(".txt", "") for report in device_reports]
    chart_device_impact = [report["impact_score"] for report in device_reports]

    html_parts = []

    html_parts.append(f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{ticket} Maintenance Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root {{
    --panel: rgba(15, 23, 42, 0.92);
    --text: #e5edf8;
    --muted: #94a3b8;
    --line: rgba(148, 163, 184, 0.22);
    --green: #22c55e;
    --blue: #38bdf8;
    --yellow: #f59e0b;
    --orange: #fb923c;
    --red: #ef4444;
    --purple: #a78bfa;
}}

* {{ box-sizing: border-box; }}

html {{
    scroll-behavior: smooth;
}}

body {{
    margin: 0;
    min-height: 100vh;
    font-family: "Segoe UI", Arial, sans-serif;
    background:
        radial-gradient(circle at top left, rgba(56, 189, 248, 0.16), transparent 32%),
        radial-gradient(circle at top right, rgba(167, 139, 250, 0.14), transparent 34%),
        linear-gradient(135deg, #020617 0%, #07111f 48%, #111827 100%);
    color: var(--text);
}}

a {{
    color: inherit;
    text-decoration: none;
}}

.header {{
    padding: 34px 44px;
    border-bottom: 1px solid var(--line);
    background: rgba(2, 6, 23, 0.72);
}}

.brand {{
    display: flex;
    align-items: center;
    gap: 14px;
}}

.logo {{
    width: 46px;
    height: 46px;
    border-radius: 14px;
    background: linear-gradient(135deg, var(--blue), var(--purple));
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 900;
    color: #020617;
}}

.header h1 {{
    margin: 0;
    font-size: 34px;
    letter-spacing: -0.04em;
}}

.subtitle, .muted {{ color: var(--muted); }}

.header-meta {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 10px;
    margin-top: 20px;
    color: var(--muted);
    font-size: 13px;
}}

.meta-pill {{
    border: 1px solid var(--line);
    background: rgba(15, 23, 42, 0.65);
    border-radius: 999px;
    padding: 9px 12px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}}

.container {{ padding: 26px 44px 44px 44px; }}

.cards {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 16px;
    margin-bottom: 28px;
}}

.card, .chart-card, .device, .outcome-card, .attention-card, .notes-card {{
    border: 1px solid var(--line);
    background: var(--panel);
    border-radius: 18px;
    box-shadow: 0 18px 50px rgba(0,0,0,0.28);
}}

.card {{
    padding: 18px;
    transition: transform 0.15s ease, border-color 0.15s ease;
}}

.card.clickable:hover {{
    transform: translateY(-2px);
    border-color: rgba(56, 189, 248, 0.65);
}}

.label {{
    color: var(--muted);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
}}

.value {{
    font-size: 30px;
    font-weight: 800;
    margin-top: 8px;
}}

.health-stable {{ color: var(--green); }}
.health-changed {{ color: var(--blue); }}
.health-attention {{ color: var(--yellow); }}
.health-action-required {{ color: var(--red); }}

.outcome-card {{
    padding: 22px;
    margin-bottom: 28px;
}}

.outcome-grid {{
    display: grid;
    grid-template-columns: 1.2fr 2fr;
    gap: 18px;
}}

.outcome-pill {{
    border: 1px solid var(--line);
    background: rgba(2, 6, 23, 0.38);
    border-radius: 14px;
    padding: 14px;
}}

.outcome-list {{
    margin: 0;
    padding-left: 20px;
    color: #dbeafe;
}}

.attention-card {{
    padding: 18px;
    margin-bottom: 28px;
    border-left: 4px solid var(--yellow);
}}

.notes-card {{
    padding: 22px;
    margin-bottom: 28px;
    border-left: 4px solid var(--blue);
}}

.notes-card h3 {{
    margin: 18px 0 8px;
    font-size: 15px;
    color: var(--blue);
}}

.notes-card h3:first-of-type {{ margin-top: 6px; }}

.notes-card p {{
    margin: 0 0 10px;
    line-height: 1.6;
    color: #dbeafe;
}}

.notes-list {{
    margin: 0 0 10px;
    padding-left: 20px;
    line-height: 1.6;
    color: #dbeafe;
}}

.notes-list .notes-task {{
    list-style: none;
    margin-left: -20px;
}}

.notes-box {{
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
    color: var(--yellow);
}}

.notes-done .notes-box {{ color: var(--green); }}
.notes-done {{ color: var(--muted); }}

.pair-card {{
    border: 1px solid var(--line);
    background: var(--panel);
    border-radius: 18px;
    box-shadow: 0 18px 50px rgba(0,0,0,0.28);
    padding: 18px;
    margin-bottom: 28px;
    border-left: 4px solid var(--purple);
}}

.attention-list {{
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
    margin-top: 12px;
}}

.attention-link {{
    display: block;
    border: 1px solid var(--line);
    background: rgba(245, 158, 11, 0.10);
    border-radius: 12px;
    padding: 12px;
}}

.attention-link:hover {{
    border-color: rgba(245, 158, 11, 0.65);
}}

.charts {{
    display: grid;
    grid-template-columns: 1fr 1fr 1.4fr;
    gap: 16px;
    margin-bottom: 30px;
}}

.chart-card {{ padding: 20px; }}

.chart-card h3 {{ margin: 0 0 6px 0; }}

.chart-note {{
    color: var(--muted);
    font-size: 12px;
    margin-bottom: 10px;
}}

.chart-wrap {{
    position: relative;
    height: 300px;
}}

.section-title {{
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 30px 0 14px 0;
}}

.section-dot {{
    width: 10px;
    height: 10px;
    border-radius: 99px;
    background: var(--blue);
    box-shadow: 0 0 18px var(--blue);
}}

.device {{
    margin-bottom: 20px;
    overflow: hidden;
    scroll-margin-top: 24px;
}}

.device-header {{
    padding: 18px 22px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: linear-gradient(90deg, rgba(56, 189, 248, 0.14), rgba(167, 139, 250, 0.08));
    border-bottom: 1px solid var(--line);
}}

.device-name {{
    font-size: 19px;
    font-weight: 800;
}}

.device-summary {{
    color: var(--muted);
    font-size: 13px;
}}

.section {{
    padding: 20px 22px;
    border-bottom: 1px solid var(--line);
}}

.section:last-child {{ border-bottom: none; }}

.finding {{
    border: 1px solid var(--line);
    border-radius: 16px;
    padding: 16px;
    margin-bottom: 12px;
    background: rgba(15, 23, 42, 0.62);
}}

.finding.stable {{
    border-left: 4px solid var(--green);
    background: rgba(34, 197, 94, 0.14);
}}

.finding.changed {{
    border-left: 4px solid var(--blue);
    background: rgba(56, 189, 248, 0.12);
}}

.finding.attention {{
    border-left: 4px solid var(--yellow);
    background: rgba(245, 158, 11, 0.14);
}}

.finding.action-required {{
    border-left: 4px solid var(--red);
    background: rgba(239, 68, 68, 0.14);
}}

.finding-title {{
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 12px;
}}

.badge {{
    display: inline-flex;
    border-radius: 999px;
    padding: 5px 10px;
    font-size: 11px;
    font-weight: 800;
    text-transform: uppercase;
}}

.badge-stable {{
    background: rgba(34, 197, 94, 0.18);
    color: #86efac;
    border: 1px solid rgba(34, 197, 94, 0.42);
}}

.badge-changed {{
    background: rgba(56, 189, 248, 0.18);
    color: #bae6fd;
    border: 1px solid rgba(56, 189, 248, 0.42);
}}

.badge-attention {{
    background: rgba(245, 158, 11, 0.18);
    color: #fcd34d;
    border: 1px solid rgba(245, 158, 11, 0.42);
}}

.badge-action {{
    background: rgba(239, 68, 68, 0.18);
    color: #fca5a5;
    border: 1px solid rgba(239, 68, 68, 0.42);
}}

.finding-heading, .peer-name {{ font-weight: 800; }}

.peer-ip, .peer-as {{
    color: var(--muted);
    font-family: Consolas, monospace;
}}

.finding-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
    margin-bottom: 12px;
}}

.finding-detail {{
    margin-top: 10px;
}}

.mini-label {{
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 6px;
}}

.state-flow {{
    display: flex;
    align-items: center;
    gap: 8px;
    font-family: Consolas, monospace;
    font-size: 14px;
}}

.arrow {{ color: var(--blue); }}

.explanation {{
    color: #dbeafe;
    line-height: 1.45;
}}

.evidence {{
    margin-top: 8px;
    color: #bfdbfe;
    font-size: 13px;
}}

.diff-box {{
    background: rgba(2, 6, 23, 0.72);
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 12px;
    overflow-x: auto;
}}

.added {{
    color: #86efac;
    font-family: Consolas, monospace;
    white-space: pre-wrap;
}}

.removed {{
    color: #fca5a5;
    font-family: Consolas, monospace;
    white-space: pre-wrap;
}}

.context {{
    color: var(--muted);
    font-family: Consolas, monospace;
    white-space: pre-wrap;
}}

details {{
    margin-top: 10px;
    border: 1px solid var(--line);
    border-radius: 14px;
    background: rgba(15, 23, 42, 0.54);
    overflow: hidden;
}}

summary {{
    cursor: pointer;
    padding: 12px 14px;
    color: #bae6fd;
    font-weight: 800;
}}

details .diff-box {{
    border: none;
    border-top: 1px solid var(--line);
    border-radius: 0;
}}

.empty {{
    color: var(--muted);
    font-style: italic;
}}

.footer {{
    color: var(--muted);
    text-align: center;
    padding: 24px;
    font-size: 12px;
}}

@media (max-width: 1200px) {{
    .cards, .charts, .outcome-grid, .pair-card {{
    border: 1px solid var(--line);
    background: var(--panel);
    border-radius: 18px;
    box-shadow: 0 18px 50px rgba(0,0,0,0.28);
    padding: 18px;
    margin-bottom: 28px;
    border-left: 4px solid var(--purple);
}}

.attention-list {{
        grid-template-columns: 1fr;
    }}

    .header-meta, .finding-grid {{
        grid-template-columns: 1fr;
    }}
}}
</style>
</head>
<body>
<div class="header">
    <div class="brand">
        <div class="logo">M</div>
        <div>
            <h1>Maintenance Report</h1>
            <div class="subtitle">Automated pre/post comparison, interpreted findings, visual summary, and raw evidence package</div>
        </div>
    </div>

    <div class="header-meta">
        <div class="meta-pill">Ticket: {html.escape(ticket)}</div>
        <div class="meta-pill">Precheck: {html.escape(display_path(precheck_folder))}</div>
        <div class="meta-pill">Postcheck: {html.escape(display_path(postcheck_folder))}</div>
    </div>
</div>

<div class="container">
    <div class="cards">
        <a class="card clickable" href="#device-findings"><div class="label">Network Health</div><div class="value health-{overall_health.lower().replace(" ", "-")}">{html.escape(overall_health)}</div></a>
        <a class="card clickable" href="#device-findings"><div class="label">Devices Checked</div><div class="value">{len(common_files)}</div></a>
        <a class="card clickable" href="#device-findings"><div class="label">Devices With Findings</div><div class="value">{devices_with_findings}</div></a>
        <a class="card clickable" href="#device-findings"><div class="label">Changed</div><div class="value">{window_totals["Changed"]}</div></a>
        <a class="card clickable" href="#attention-items"><div class="label">Attention</div><div class="value health-attention">{window_totals["Attention"]}</div></a>
        <a class="card clickable" href="#attention-items"><div class="label">Pair Symmetry</div><div class="value">{symmetry_count}</div></a>
    </div>

    <div class="outcome-card">
        <h2>Maintenance Outcome Summary</h2>
        <div class="outcome-grid">
            <div class="outcome-pill">
                <strong>Assessment</strong>
                <p>{html.escape(assessment_text)}</p>
            </div>
            <div class="outcome-pill">
                <strong>Detected Categories</strong>
                <ul class="outcome-list">
""")

    for item in summary_items:
        html_parts.append(f"<li>{html.escape(item)}</li>")

    html_parts.append("""
                </ul>
            </div>
        </div>
    </div>
""")

    # The engineer's account comes before the machine's, because a
    # reader opening this on a ticket wants to know what a person
    # concluded before they read what a parser noticed.
    notes_html = notes.render_html(notes_text) if notes_text else ""

    if notes_html:
        html_parts.append("\n    " + notes_html + "\n")

    html_parts.append("""
    <div id="attention-items" class="attention-card">
        <h2>Items Needing Attention</h2>
""")

    if attention_devices:
        html_parts.append('<div class="attention-list">')
        for report in attention_devices:
            html_parts.append(f"""
        <a class="attention-link" href="#device-{html.escape(report["device_id"])}">
            <strong>{html.escape(report["file_name"])}</strong><br>
            <span class="muted">Attention: {report["attention_count"]} | Action Required: {report["action_count"]} | Impact Score: {report["impact_score"]}</span>
        </a>
        """)
        html_parts.append("</div>")
    else:
        html_parts.append('<p class="empty">Nothing needs your attention.</p>')

    html_parts.append("""
    </div>

    <div id="pair-symmetry" class="pair-card">
        <h2>Pair Symmetry</h2>
""")

    pairs = analysis.get("pairs", [])
    pair_findings_list = analysis.get("pair_findings", [])

    if not pairs:
        html_parts.append(
            '<p class="empty">No redundant pairs to compare: no two captured hostnames differ only by a '
            'trailing number, and the inventory lists no pairs.</p>'
        )
    else:
        pair_labels = ", ".join(f"{a} / {b}" for a, b in pairs)
        html_parts.append(
            f'<p class="muted">{len(pairs)} pair(s) compared from the postcheck captures: '
            f'{html.escape(pair_labels)}. Same-named prefix-lists and route-maps, and PAN-OS HA state, '
            f'are checked entry for entry.</p>'
        )

        if pair_findings_list:
            for finding in pair_findings_list:
                html_parts.append(render_finding(finding))
        else:
            html_parts.append('<p class="empty">Both members of every pair agree.</p>')

    html_parts.append("""
    </div>

    <div class="charts">
        <div class="chart-card">
            <h3>Operational Health</h3>
            <div class="chart-note">Stable, changed, attention, and action-required classifications.</div>
            <div class="chart-wrap"><canvas id="healthChart"></canvas></div>
        </div>
        <div class="chart-card">
            <h3>Findings by Category</h3>
            <div class="chart-note">Generic categories that remain useful across maintenance types.</div>
            <div class="chart-wrap"><canvas id="categoryChart"></canvas></div>
        </div>
        <div class="chart-card">
            <h3>Device Impact</h3>
            <div class="chart-note">Ranks devices by interpreted operational impact, not raw diff volume.</div>
            <div class="chart-wrap"><canvas id="deviceImpactChart"></canvas></div>
        </div>
    </div>

    <div id="device-findings" class="section-title">
        <div class="section-dot"></div>
        <h2>Device Findings</h2>
    </div>
""")

    for report in device_reports:
        file_name = report["file_name"]
        findings = report["findings"]
        config_changes = report["config_changes"]
        diffs = report["diffs"]

        html_parts.append(f"""
    <div id="device-{html.escape(report["device_id"])}" class="device">
        <div class="device-header">
            <div class="device-name">{html.escape(file_name)}</div>
            <div class="device-summary">Findings: {report["findings_count"]} | Impact Score: {report["impact_score"]} | Evidence Sections: {len(diffs)}</div>
        </div>

        <div class="section">
            <h3>Protocol / Routing Interpretation</h3>
    """)

        if findings:
            for finding in findings:
                html_parts.append(render_finding(finding))
        else:
            html_parts.append(
                '<p class="empty">No meaningful BGP neighbor, prefix, prefix-list, or interface address '
                'changes detected.</p>'
            )

        html_parts.append("""
        </div>

        <div class="section">
            <h3>Configuration / Policy Changes</h3>
            <div class="diff-box">
    """)

        if config_changes:
            for line in config_changes:
                if line.startswith("+ "):
                    html_parts.append(render_diff_line("added", line[2:]))
                elif line.startswith("- "):
                    html_parts.append(render_diff_line("removed", line[2:]))
                else:
                    html_parts.append(render_diff_line("context", line[2:]))
        else:
            html_parts.append('<p class="empty">No BGP-related config changes detected.</p>')

        html_parts.append("""
            </div>
        </div>

        <div class="section">
            <h3>Evidence Only - Collapsible Raw Diffs</h3>
    """)

        if diffs:
            for command, diff_lines in diffs.items():
                label = command
                if command in ["show ip bgp", "show ip route", "show routing route"]:
                    label = f"{command} - Large routing evidence"

                html_parts.append(f"""
            <details>
                <summary>{html.escape(label)}</summary>
                <div class="diff-box">
""")
                for kind, text in diff_lines:
                    html_parts.append(render_diff_line(kind, text))

                html_parts.append("""
                </div>
            </details>
""")
        else:
            html_parts.append('<p class="empty">No raw differences detected.</p>')

        html_parts.append("""
        </div>
    </div>
    """)

    html_parts.append(f"""
</div>

<div class="footer">
    Generated {html.escape(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))} | Maintenance Report
</div>

<script>
const healthLabels = {json.dumps(chart_impact_labels)};
const healthValues = {json.dumps(chart_impact_values)};

const categoryLabels = {json.dumps(chart_classification_labels)};
const categoryValues = {json.dumps(chart_classification_values)};

const deviceLabels = {json.dumps(chart_device_labels)};
const deviceImpact = {json.dumps(chart_device_impact)};

Chart.defaults.color = "#cbd5e1";
Chart.defaults.borderColor = "rgba(148, 163, 184, 0.18)";
Chart.defaults.font.family = "Segoe UI, Arial, sans-serif";

new Chart(document.getElementById("healthChart"), {{
    type: "doughnut",
    data: {{
        labels: healthLabels,
        datasets: [{{
            data: healthValues,
            backgroundColor: [
                "rgba(34, 197, 94, 0.78)",
                "rgba(56, 189, 248, 0.78)",
                "rgba(245, 158, 11, 0.78)",
                "rgba(239, 68, 68, 0.78)"
            ],
            borderColor: "rgba(15, 23, 42, 0.92)",
            borderWidth: 3
        }}]
    }},
    options: {{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{
            legend: {{ position: "bottom" }}
        }},
        cutout: "68%"
    }}
}});

new Chart(document.getElementById("categoryChart"), {{
    type: "bar",
    data: {{
        labels: categoryLabels,
        datasets: [{{
            label: "Findings / evidence items",
            data: categoryValues,
            backgroundColor: "rgba(56, 189, 248, 0.72)",
            borderRadius: 8
        }}]
    }},
    options: {{
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        scales: {{
            x: {{
                beginAtZero: true,
                ticks: {{ precision: 0 }}
            }}
        }},
        plugins: {{
            legend: {{ display: false }}
        }}
    }}
}});

new Chart(document.getElementById("deviceImpactChart"), {{
    type: "bar",
    data: {{
        labels: deviceLabels,
        datasets: [{{
            label: "Impact score",
            data: deviceImpact,
            backgroundColor: "rgba(167, 139, 250, 0.72)",
            borderRadius: 8
        }}]
    }},
    options: {{
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        scales: {{
            x: {{
                beginAtZero: true,
                ticks: {{ precision: 0 }}
            }}
        }},
        plugins: {{
            legend: {{ position: "bottom" }}
        }}
    }}
}});
</script>

</body>
</html>
""")

    return "\n".join(html_parts)


def build_html_report(ticket, dirs, run_timestamp, console, pairs=None, notes_text=None):
    """Find the latest pre/post runs and write the HTML report.

    pairs: optional explicit pair list from the inventory (see analyze).
    notes_text: the notes.md contents, or None; rendered above the
    findings (see modules/notes.py).
    """
    precheck_folder = find_latest_folder(dirs["precheck"], "precheck_")
    postcheck_folder = find_latest_folder(dirs["postcheck"], "postcheck_")

    if precheck_folder is None:
        console.print("No precheck folder found.")
        return None

    if postcheck_folder is None:
        console.print("No postcheck folder found.")
        return None

    os.makedirs(dirs["compare"], exist_ok=True)
    html_report = os.path.join(dirs["compare"], f"compare_{run_timestamp}.html")

    analysis = analyze(precheck_folder, postcheck_folder, pairs=pairs)
    page = render_html(ticket, precheck_folder, postcheck_folder, analysis, notes_text=notes_text)

    with open(html_report, "w", encoding="utf-8") as file:
        file.write(page)

    console.print("HTML comparison report created.")
    console.print(f"Created: {display_path(html_report)}")

    return html_report
