"""Interpreted HTML maintenance report.

Where the text compare answers "what changed", this report answers "does
it matter": it parses BGP summaries into per-peer state, correlates
peer changes with config diffs, classifies every changed command into a
category (Configuration / Protocol / Routing / Interface / ...), scores
each device's operational impact, and renders a self-contained dark
dashboard (Chart.js from CDN is its only external asset) that can be
attached to a change ticket as-is.

Impact levels, most to least severe:
    Action Required > Attention > Changed > Stable

Normalization here is looser than modules/textcompare.py on purpose:
this report keeps more context lines so the collapsible raw-diff
evidence sections read naturally.
"""

import difflib
import html
import json
import os
import re
from datetime import datetime

from modules.layout import find_latest_folder


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
    cleaned = []

    for line in lines:
        new_line = clean_line_for_compare(command, line)

        if new_line is not None:
            cleaned.append(new_line)

    return cleaned


def parse_bgp_summary(lines):
    """Parse 'show ip bgp summary' rows into per-peer dicts."""
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

        key = f"{peer_name} {peer_ip}"

        peers[key] = {
            "name": peer_name,
            "ip": peer_ip,
            "as": peer_as,
            "state": state,
            "prefixes_received": prefixes_received,
            "prefixes_accepted": prefixes_accepted,
            "raw": clean,
        }

    return peers


def bgp_config_changes(pre_sections, post_sections):
    """BGP-relevant lines that changed in the running config."""
    keywords = [
        "router bgp",
        "neighbor",
        "route-map",
        "community",
        "send-community",
        "set community",
        "match community",
        "shutdown",
        "no shutdown",
    ]

    pre_lines = pre_sections.get("show running-config", []) + pre_sections.get("show config running", [])
    post_lines = post_sections.get("show running-config", []) + post_sections.get("show config running", [])

    diff = difflib.ndiff(pre_lines, post_lines)
    important = []

    for line in diff:
        if not line.startswith(("- ", "+ ")):
            continue

        content = line[2:].strip().lower()

        if any(keyword in content for keyword in keywords):
            important.append(line)

    return important


def bgp_neighbor_findings(pre_sections, post_sections, config_changes):
    """Interpret per-peer BGP changes into impact-rated findings."""
    pre_bgp = parse_bgp_summary(pre_sections.get("show ip bgp summary", []))
    post_bgp = parse_bgp_summary(post_sections.get("show ip bgp summary", []))

    findings = []
    config_text = "\n".join(config_changes).lower()

    for peer in sorted(set(pre_bgp) - set(post_bgp)):
        before = pre_bgp[peer]

        findings.append({
            "classification": "Protocol",
            "category": "BGP state",
            "impact": "Attention",
            "title": "BGP Peer Removed From Summary",
            "peer": before,
            "before": before,
            "after": None,
            "summary": "This peer appeared in the precheck but was not present in the postcheck BGP summary.",
            "evidence": "show ip bgp summary",
        })

    for peer in sorted(set(post_bgp) - set(pre_bgp)):
        after = post_bgp[peer]

        findings.append({
            "classification": "Protocol",
            "category": "BGP state",
            "impact": "Stable",
            "title": "BGP Peer Added",
            "peer": after,
            "before": None,
            "after": after,
            "summary": "This peer was not present in the precheck but appeared in the postcheck BGP summary.",
            "evidence": "show ip bgp summary",
        })

    for peer in sorted(set(pre_bgp) & set(post_bgp)):
        before = pre_bgp[peer]
        after = post_bgp[peer]

        detected_evidence = "show ip bgp summary"

        if after["ip"].lower() in config_text and "shutdown" in config_text:
            detected_evidence = "show ip bgp summary + related BGP shutdown/no shutdown config"
        elif "community" in config_text or "route-map" in config_text:
            detected_evidence = "show ip bgp summary + BGP route-map/community config"

        if before["state"] != after["state"]:
            if before["state"] == "Idle(Admin)" and after["state"] == "Estab":
                title = "BGP Peer Activated"
                impact = "Stable"
                summary = "The peer transitioned from administratively idle to established."
            elif before["state"] == "Estab" and after["state"] == "Idle(Admin)":
                title = "BGP Peer Administratively Disabled"
                impact = "Attention"
                summary = "The peer transitioned from established to administratively idle."
            else:
                title = "BGP Peer State Changed"
                impact = "Attention"
                summary = "The peer state changed between precheck and postcheck."

            findings.append({
                "classification": "Protocol",
                "category": "BGP state",
                "impact": impact,
                "title": title,
                "peer": after,
                "before": before,
                "after": after,
                "summary": summary,
                "evidence": detected_evidence,
            })

        elif (
            before["prefixes_received"] != after["prefixes_received"]
            or before["prefixes_accepted"] != after["prefixes_accepted"]
        ):
            before_received = int(before["prefixes_received"]) if before["prefixes_received"].isdigit() else 0
            after_received = int(after["prefixes_received"]) if after["prefixes_received"].isdigit() else 0
            delta = after_received - before_received

            findings.append({
                "classification": "Routing",
                "category": "BGP prefixes",
                "impact": "Changed",
                "title": "BGP Prefix Count Changed",
                "peer": after,
                "before": before,
                "after": after,
                "summary": f"Prefix count changed by {delta}. This may be expected when routing policy, communities, failover, or advertised routes change.",
                "evidence": detected_evidence,
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

        for line in difflib.ndiff(pre_lines, post_lines):
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
        elif command in ["show ip bgp summary", "show ip ospf neighbor", "show high-availability state", "show mlag"]:
            categories["Protocol"] += 1
        elif command in ["show ip route", "show ip route ospf", "show ip bgp", "show routing route"]:
            categories["Routing"] += 1
        elif command in ["show interfaces status", "show interfaces trunk", "show port-channel summary", "show interfaces counters errors", "show interfaces description"]:
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
    css = "added" if kind == "added" else "removed"
    sign = "+" if kind == "added" else "-"
    return f'<div class="{css}">{sign} {html.escape(text)}</div>'


def render_bgp_finding(finding):
    impact = finding["impact"]
    title = finding["title"]
    before = finding["before"]
    after = finding["after"]
    peer = finding["peer"]

    badge_class = {
        "Stable": "badge-stable",
        "Changed": "badge-changed",
        "Attention": "badge-attention",
        "Action Required": "badge-action",
    }.get(impact, "badge-changed")

    state_before = before["state"] if before else "Not Present"
    state_after = after["state"] if after else "Not Present"

    rx_before = before["prefixes_received"] if before else "0"
    rx_after = after["prefixes_received"] if after else "0"

    acc_before = before["prefixes_accepted"] if before else "0"
    acc_after = after["prefixes_accepted"] if after else "0"

    return f"""
    <div class="finding {impact.lower().replace(" ", "-")}">
        <div class="finding-title">
            <span class="badge {badge_class}">{html.escape(impact)}</span>
            <span class="finding-heading">{html.escape(title)}</span>
            <span class="peer-name">{html.escape(peer["name"])}</span>
            <span class="peer-ip">{html.escape(peer["ip"])}</span>
            <span class="peer-as">AS{html.escape(peer["as"])}</span>
        </div>

        <div class="finding-grid">
            <div>
                <div class="mini-label">State</div>
                <div class="state-flow"><span>{html.escape(state_before)}</span><span class="arrow">→</span><span>{html.escape(state_after)}</span></div>
            </div>
            <div>
                <div class="mini-label">Prefixes Received</div>
                <div class="state-flow"><span>{html.escape(rx_before)}</span><span class="arrow">→</span><span>{html.escape(rx_after)}</span></div>
            </div>
            <div>
                <div class="mini-label">Prefixes Accepted</div>
                <div class="state-flow"><span>{html.escape(acc_before)}</span><span class="arrow">→</span><span>{html.escape(acc_after)}</span></div>
            </div>
        </div>

        <div class="explanation">{html.escape(finding["summary"])}</div>
        <div class="evidence">Evidence: {html.escape(finding["evidence"])}</div>
    </div>
    """


def analyze(precheck_folder, postcheck_folder):
    """Diff every common device file and roll up findings + totals."""
    pre_files = sorted(os.listdir(precheck_folder))
    post_files = sorted(os.listdir(postcheck_folder))
    common_files = sorted(set(pre_files) & set(post_files))

    device_reports = []

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

    devices_with_findings = 0

    for file_name in common_files:
        pre_path = os.path.join(precheck_folder, file_name)
        post_path = os.path.join(postcheck_folder, file_name)

        pre_sections = parse_sections(pre_path)
        post_sections = parse_sections(post_path)

        config_changes = bgp_config_changes(pre_sections, post_sections)
        bgp_findings = bgp_neighbor_findings(pre_sections, post_sections, config_changes)
        diffs = raw_diffs(pre_sections, post_sections)
        raw_categories = classify_raw_diff_commands(diffs)

        findings_count = len(bgp_findings) + len(config_changes)

        if findings_count > 0:
            devices_with_findings += 1

        for finding in bgp_findings:
            total_findings_by_classification[finding["classification"]] += 1
            impact_totals[finding["impact"]] += 1

        if config_changes:
            total_findings_by_classification["Configuration"] += len(config_changes)
            impact_totals["Changed"] += len(config_changes)

        for category, count in raw_categories.items():
            if count:
                total_findings_by_classification[category] += count

        device_attention_count = sum(1 for f in bgp_findings if f["impact"] == "Attention")
        device_action_count = sum(1 for f in bgp_findings if f["impact"] == "Action Required")
        device_changed_count = sum(1 for f in bgp_findings if f["impact"] == "Changed")
        device_stable_count = sum(1 for f in bgp_findings if f["impact"] == "Stable")

        # Weighted so one action-required finding outranks any pile of
        # cosmetic churn; interface diffs weigh more than L2 noise.
        device_impact_score = (
            device_action_count * 10
            + device_attention_count * 5
            + device_changed_count * 2
            + len(config_changes) * 2
            + raw_categories["Interface"] * 4
            + device_stable_count
        )

        device_reports.append({
            "file_name": file_name,
            "device_id": safe_id(file_name.replace(".txt", "")),
            "bgp_findings": bgp_findings,
            "config_changes": config_changes,
            "diffs": diffs,
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
        "total_findings_by_classification": total_findings_by_classification,
        "impact_totals": impact_totals,
        "devices_with_findings": devices_with_findings,
    }


def render_html(ticket, precheck_folder, postcheck_folder, analysis):
    """Render the analysis into a single self-contained HTML page."""
    common_files = analysis["common_files"]
    device_reports = analysis["device_reports"]
    total_findings_by_classification = analysis["total_findings_by_classification"]
    impact_totals = analysis["impact_totals"]
    devices_with_findings = analysis["devices_with_findings"]

    if impact_totals["Action Required"] > 0:
        overall_health = "Action Required"
    elif impact_totals["Attention"] > 0:
        overall_health = "Attention"
    elif impact_totals["Changed"] > 0:
        overall_health = "Changed"
    else:
        overall_health = "Stable"

    if overall_health == "Stable":
        assessment_text = "No attention-level operational changes were detected. Review changed items and raw evidence as needed."
    elif overall_health == "Changed":
        assessment_text = "Meaningful changes were detected, but no immediate attention markers were identified."
    elif overall_health == "Attention":
        assessment_text = "Operational changes were detected that should be reviewed. Click the Attention card to jump to items requiring review."
    else:
        assessment_text = "One or more findings may require action. Click Action Required to jump to the highest-priority items."

    summary_items = []

    for classification, count in total_findings_by_classification.items():
        if count:
            summary_items.append(f"{count} {classification.lower()} finding/evidence item(s) detected.")

    if not summary_items:
        summary_items.append("No meaningful findings detected.")

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
    grid-template-columns: repeat(3, minmax(0, 1fr));
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

.card, .chart-card, .device, .outcome-card, .attention-card {{
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
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
    margin-bottom: 12px;
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
    .cards, .charts, .outcome-grid, .attention-list {{
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
        <div class="meta-pill">Precheck: {html.escape(precheck_folder)}</div>
        <div class="meta-pill">Postcheck: {html.escape(postcheck_folder)}</div>
    </div>
</div>

<div class="container">
    <div class="cards">
        <a class="card clickable" href="#device-findings"><div class="label">Network Health</div><div class="value health-{overall_health.lower().replace(" ", "-")}">{html.escape(overall_health)}</div></a>
        <a class="card clickable" href="#device-findings"><div class="label">Devices Checked</div><div class="value">{len(common_files)}</div></a>
        <a class="card clickable" href="#device-findings"><div class="label">Devices With Findings</div><div class="value">{devices_with_findings}</div></a>
        <a class="card clickable" href="#device-findings"><div class="label">Changed</div><div class="value">{impact_totals["Changed"]}</div></a>
        <a class="card clickable" href="#attention-items"><div class="label">Attention</div><div class="value health-attention">{impact_totals["Attention"]}</div></a>
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
        html_parts.append('<p class="empty">No attention-level findings detected.</p>')

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
        bgp_findings = report["bgp_findings"]
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

        if bgp_findings:
            for finding in bgp_findings:
                html_parts.append(render_bgp_finding(finding))
        else:
            html_parts.append('<p class="empty">No meaningful BGP neighbor or prefix changes detected.</p>')

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


def build_html_report(ticket, dirs, run_timestamp, console):
    """Find the latest pre/post runs and write the HTML report."""
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

    analysis = analyze(precheck_folder, postcheck_folder)
    page = render_html(ticket, precheck_folder, postcheck_folder, analysis)

    with open(html_report, "w", encoding="utf-8") as file:
        file.write(page)

    console.print("HTML comparison report created.")
    console.print(f"Created: {html_report}")

    return html_report
