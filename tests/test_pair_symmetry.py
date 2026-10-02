"""Pair symmetry.

The real signature of a change applied to one member of a redundant
pair is not "a line vanished" but "SW-1 and SW-2 now disagree". A
per-device report cannot see that, so the two postcheck captures of a
pair are compared against each other: same-named prefix-lists and
route-maps entry for entry, and the parts of PAN-OS HA state that do
not depend on which member is active.
"""

import io

from rich.console import Console

from modules.htmlreport import (
    analyze,
    build_html_report,
    infer_pairs,
    pair_findings,
    parse_ha_state,
    parse_route_maps,
    resolve_pairs,
)

PREFIX_LIST = [
    "ip prefix-list ISP-OUT",
    "   seq 10 permit 203.0.113.0/24",
    "   seq 20 permit 198.51.100.0/24",
    "   seq 40 permit 198.51.100.243/32",
]

ROUTE_MAP = [
    "route-map ISP-OUT permit 10",
    "  Description:",
    "  Match clauses:",
    "    match ip address prefix-list ISP-OUT",
    "  Match clauses hit: 4211",
    "  Set clauses:",
    "    set community 64500:100",
    "route-map ISP-OUT deny 20",
    "  Match clauses:",
    "  Set clauses:",
]

HA_STATE = """\
Mode: Active-Passive
Local Information:
        Version: 1
        Mode: Active-Passive
        State: {state} (last 61 days)
        Device Information:
                Management IPv4 Address: {mgmt}/24
        HA1 Control Links Joint Configuration:
                Encryption Enabled: no
        Election Option Information:
                Priority: {priority}
                Preemptive: no
        Version Information:
                Build Release: {build}
                Application Content: Match
        Session Synchronization Cookie: {cookie}
Peer Information:
        Connection status: up
        State: {peer_state}
"""


def _capture(prefix_lines=None, route_map_lines=None, ha=None):
    sections = {"show running-config": ["hostname x"]}
    if prefix_lines is not None:
        sections["show ip prefix-list"] = prefix_lines
    if route_map_lines is not None:
        sections["show route-map"] = route_map_lines
    if ha is not None:
        sections["show high-availability state"] = ha.splitlines()
    return sections


def test_infer_pairs_by_trailing_number():
    hosts = ["SITE-A-SW-1", "SITE-A-SW-2", "SITE-B-SW-1", "SITE-A-FW-1", "SITE-A-FW-2", "LEAF-1", "LEAF-2", "LEAF-3"]

    assert infer_pairs(hosts) == [("SITE-A-FW-1", "SITE-A-FW-2"), ("SITE-A-SW-1", "SITE-A-SW-2")]


def test_bare_ip_captures_are_never_paired():
    assert infer_pairs(["192.0.2.11", "192.0.2.12"]) == []


def test_explicit_pairs_take_precedence_and_inference_covers_the_rest():
    hosts = ["CORE-EAST", "CORE-WEST", "SITE-A-SW-1", "SITE-A-SW-2", "EDGE-1"]

    pairs = resolve_pairs(hosts, [["core-east", "CORE-WEST"], ["EDGE-1", "EDGE-2"]])

    # EDGE-2 was not captured, so that explicit pair is skipped.
    assert pairs == [("CORE-EAST", "CORE-WEST"), ("SITE-A-SW-1", "SITE-A-SW-2")]


def test_parse_route_maps_drops_hit_counters():
    maps = parse_route_maps(ROUTE_MAP)

    assert list(maps) == ["ISP-OUT"]
    assert "Match clauses hit: 4211" not in " ".join(maps["ISP-OUT"])
    assert "match ip address prefix-list ISP-OUT" in maps["ISP-OUT"]
    assert maps["ISP-OUT"][0] == "route-map permit 10"


def test_parse_ha_state_ignores_role_dependent_keys():
    values = parse_ha_state(HA_STATE.format(
        state="active", mgmt="10.1.1.1", priority=100, build="11.1.4-h7", cookie="0x5", peer_state="passive",
    ).splitlines())

    assert "Local Information/State" not in values
    assert "Local Information/Election Option Information/Priority" not in values
    assert "Local Information/Device Information/Management IPv4 Address" not in values
    assert values["Local Information/Version Information/Build Release"] == "11.1.4-h7"
    assert values["Local Information/Session Synchronization Cookie"] == "0x5"
    # Peer Information describes the other box and is not part of the local view.
    assert not any(key.startswith("Peer") for key in values)


def test_prefix_list_divergence_is_attention_on_both_devices():
    pair = ("SITE-A-SW-1", "SITE-A-SW-2")
    sw1 = _capture(prefix_lines=PREFIX_LIST)
    sw2 = _capture(prefix_lines=[line for line in PREFIX_LIST if "seq 40" not in line])

    findings = pair_findings(pair, sw1, sw2)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["title"] == "Pair Prefix-List Divergence"
    assert finding["impact"] == "Attention"
    assert finding["devices"] == ["SITE-A-SW-1", "SITE-A-SW-2"]
    assert finding["subject"] == ["SITE-A-SW-1 vs SITE-A-SW-2", "ISP-OUT"]
    assert finding["fields"] == [("seq 40", "permit 198.51.100.243/32", "Not Present")]
    assert finding["arrow"] == "vs"


def test_identical_members_produce_nothing():
    pair = ("SITE-A-SW-1", "SITE-A-SW-2")
    sw = _capture(prefix_lines=PREFIX_LIST, route_map_lines=ROUTE_MAP)

    assert pair_findings(pair, sw, dict(sw)) == []


def test_lists_present_on_one_member_only_are_not_compared_unless_both_had_them():
    pair = ("SITE-A-SW-1", "SITE-A-SW-2")
    sw1 = _capture(prefix_lines=PREFIX_LIST)
    sw2 = _capture(prefix_lines=[])

    # Different roles, different lists: nothing to say without a precheck.
    assert pair_findings(pair, sw1, sw2) == []

    # Both had it before the window and one lost it: that is a finding.
    findings = pair_findings(pair, sw1, sw2, pre_a=sw1, pre_b=sw1)
    assert [f["title"] for f in findings] == ["Pair Prefix-List Missing On One Device"]
    assert "SITE-A-SW-2 no longer has it" in findings[0]["summary"]


def test_route_map_divergence_lists_the_differing_lines():
    pair = ("SITE-A-SW-1", "SITE-A-SW-2")
    sw1 = _capture(route_map_lines=ROUTE_MAP)
    sw2 = _capture(route_map_lines=[line.replace("64500:100", "64500:200") for line in ROUTE_MAP])

    findings = pair_findings(pair, sw1, sw2)

    assert [f["title"] for f in findings] == ["Pair Route-Map Divergence"]
    assert findings[0]["impact"] == "Attention"
    assert ("removed", "SITE-A-SW-1: set community 64500:100") in findings[0]["detail"]
    assert ("added", "SITE-A-SW-2: set community 64500:200") in findings[0]["detail"]


def test_ha_cookie_split_is_attention_but_active_passive_is_not():
    pair = ("SITE-A-FW-1", "SITE-A-FW-2")
    fw1 = _capture(ha=HA_STATE.format(
        state="active", mgmt="10.1.1.1", priority=100, build="11.1.4-h7", cookie="0x5", peer_state="passive",
    ))
    fw2_in_sync = _capture(ha=HA_STATE.format(
        state="passive", mgmt="10.1.1.2", priority=110, build="11.1.4-h7", cookie="0x5", peer_state="active",
    ))
    fw2_split = _capture(ha=HA_STATE.format(
        state="passive", mgmt="10.1.1.2", priority=110, build="11.1.4-h7", cookie="0x0", peer_state="active",
    ))

    assert pair_findings(pair, fw1, fw2_in_sync) == []

    findings = pair_findings(pair, fw1, fw2_split)
    assert [f["title"] for f in findings] == ["Pair HA State Divergence"]
    assert findings[0]["classification"] == "Protocol"
    assert findings[0]["fields"] == [("Local Information/Session Synchronization Cookie", "0x5", "0x0")]


def _write(folder, hostname, prefix_lines):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{hostname}.txt").write_text(
        f"Hostname: {hostname}\n"
        "### show ip prefix-list ###\n" + "\n".join(prefix_lines) + "\n"
        "### show running-config ###\n"
        f"hostname {hostname}\n"
    )


def test_pair_finding_counts_on_both_devices_and_once_in_totals(tmp_path):
    pre_run = tmp_path / "Precheck" / "precheck_2026-01-01_00-00"
    post_run = tmp_path / "Postcheck" / "postcheck_2026-01-01_02-00"
    for folder in (pre_run, post_run):
        _write(folder, "SITE-A-SW-1", PREFIX_LIST)
        _write(folder, "SITE-B-SW-1", PREFIX_LIST)
    _write(pre_run, "SITE-A-SW-2", PREFIX_LIST)
    _write(post_run, "SITE-A-SW-2", [line.replace("seq 40 permit 198.51.100.243/32", "seq 40 permit 198.51.100.244/32") for line in PREFIX_LIST])

    analysis = analyze(str(pre_run), str(post_run))

    assert analysis["pairs"] == [("SITE-A-SW-1", "SITE-A-SW-2")]
    assert [f["title"] for f in analysis["pair_findings"]] == ["Pair Prefix-List Divergence"]

    by_name = {report["file_name"]: report for report in analysis["device_reports"]}
    # SW-2 also has its own per-device overwrite finding; SW-1 only the pair one.
    assert by_name["SITE-A-SW-1.txt"]["attention_count"] == 1
    assert by_name["SITE-A-SW-2.txt"]["attention_count"] == 2
    assert by_name["SITE-B-SW-1.txt"]["attention_count"] == 0
    assert by_name["SITE-A-SW-1.txt"]["impact_score"] >= 5
    # Network-wide: one overwrite + one pair divergence, not three.
    assert analysis["impact_totals"]["Attention"] == 2

    dirs = {
        "precheck": str(tmp_path / "Precheck"),
        "postcheck": str(tmp_path / "Postcheck"),
        "compare": str(tmp_path / "Compare"),
    }
    report_path = build_html_report("NET-4", dirs, "2026-01-01_02-05", Console(file=io.StringIO()))

    with open(report_path, encoding="utf-8") as report:
        content = report.read()

    assert "Pair Symmetry" in content
    assert content.index("Pair Symmetry") < content.index("Device Findings")
    assert "Pair Prefix-List Divergence" in content
    assert "SITE-A-SW-1 vs SITE-A-SW-2" in content
    # Both members land in the attention list.
    assert 'href="#device-site-a-sw-1"' in content
    assert 'href="#device-site-a-sw-2"' in content


def test_explicit_pairs_reach_analyze(tmp_path):
    pre_run = tmp_path / "Precheck" / "precheck_2026-01-01_00-00"
    post_run = tmp_path / "Postcheck" / "postcheck_2026-01-01_02-00"
    for folder in (pre_run, post_run):
        _write(folder, "CORE-EAST", PREFIX_LIST)
    _write(pre_run, "CORE-WEST", PREFIX_LIST)
    _write(post_run, "CORE-WEST", PREFIX_LIST[:2])

    assert analyze(str(pre_run), str(post_run))["pairs"] == []

    analysis = analyze(str(pre_run), str(post_run), pairs=[["CORE-EAST", "CORE-WEST"]])
    assert analysis["pairs"] == [("CORE-EAST", "CORE-WEST")]
    assert [f["title"] for f in analysis["pair_findings"]] == ["Pair Prefix-List Divergence"]
