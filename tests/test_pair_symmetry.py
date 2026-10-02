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
    """A match line that differs changes which routes the member acts on."""
    pair = ("SITE-A-SW-1", "SITE-A-SW-2")
    sw1 = _capture(route_map_lines=ROUTE_MAP)
    sw2 = _capture(route_map_lines=[line.replace("prefix-list ISP-OUT", "prefix-list ISP-Out") for line in ROUTE_MAP])

    findings = pair_findings(pair, sw1, sw2)

    assert [f["title"] for f in findings] == ["Pair Route-Map Divergence"]
    assert findings[0]["impact"] == "Attention"
    assert ("removed", "SITE-A-SW-1: match ip address prefix-list ISP-OUT") in findings[0]["detail"]
    assert ("added", "SITE-A-SW-2: match ip address prefix-list ISP-Out") in findings[0]["detail"]


def test_route_map_preference_tuning_is_not_a_divergence():
    """How a pair biases traffic toward one member is the design, not a defect.

    SW-2 is the backup: it prepends its own AS twice where SW-1 does not
    prepend at all, sets a lower local-preference, and labels its clauses
    "Path 2". Comparing the two members line by line reports every one of
    those as a divergence, which on a real MLAG pair buries the findings
    that matter under two dozen that do not."""
    pair = ("SITE-A-SW-1", "SITE-A-SW-2")
    sw1 = _capture(route_map_lines=ROUTE_MAP)
    sw2 = _capture(route_map_lines=[
        "route-map ISP-OUT permit 10",
        "  Description:",
        "    description transit out - Path 2",
        "  Match clauses:",
        "    match ip address prefix-list ISP-OUT",
        "  Match clauses hit: 51",
        "  Set clauses:",
        "    set community 64500:200",
        "    set as-path prepend 64500 64500",
        "    set local-preference 150",
        "route-map ISP-OUT deny 20",
        "  Match clauses:",
        "  Set clauses:",
    ])

    assert pair_findings(pair, sw1, sw2) == []


def test_route_map_next_hop_still_diverges_despite_tuning():
    """Tuning is set aside; where the traffic goes is not."""
    pair = ("SITE-A-SW-1", "SITE-A-SW-2")
    sw1 = _capture(route_map_lines=ROUTE_MAP)
    sw2 = _capture(route_map_lines=[
        line.replace("    set community 64500:100", "    set ip next-hop 192.0.2.9")
        for line in ROUTE_MAP
    ])

    findings = pair_findings(pair, sw1, sw2)

    assert [f["title"] for f in findings] == ["Pair Route-Map Divergence"]
    assert ("added", "SITE-A-SW-2: set ip next-hop 192.0.2.9") in findings[0]["detail"]


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


def test_ha_group_label_does_not_desynchronize_every_key():
    """A PAN-OS HA group header carries an optional local label.

    One member prints "Group 1:" and the other "Group 1: MMP-E-HA" - the
    label is a name an operator typed, not synchronized state. Only the
    bare form looks like a block header, so without normalizing it one
    member's leaves land under "Group 1/Local Information/Mode" and the
    other's under "Local Information/Mode". Every key then differs, and a
    healthy pair reports a wall of "Not Present" mismatches."""
    body = """\
  Mode: Active-Passive
  Local Information:
    Version: 1
    Mode: Active-Passive
    State: {state} (last 30 days)
    Version Compatibility:
      Application Content Compatibility: Match
      IOT Content Compatibility: {iot}
"""
    unlabelled = parse_ha_state(("Group 1: \n" + body.format(state="active", iot="Match")).splitlines())
    labelled = parse_ha_state(("Group 1: MMP-E-HA\n" + body.format(state="passive", iot="Match")).splitlines())

    assert unlabelled == labelled
    assert "Group 1/Local Information/Mode" in unlabelled


def test_ha_content_mismatch_is_reported_even_when_both_members_agree():
    """The pair can disagree with itself while both captures agree.

    The firewall grades its own content versions against its peer's, so a
    stale file makes BOTH members print "Mismatch". That reads as agreement
    to a key-by-key compare and slips through it."""
    pair = ("SITE-A-FW-1", "SITE-A-FW-2")
    body = """\
Group 1: {label}
  Mode: Active-Passive
  Local Information:
    Mode: Active-Passive
    State: {state} (last 30 days)
    Version Compatibility:
      Application Content Compatibility: Match
      IOT Content Compatibility: {iot}
"""
    fw1 = _capture(ha=body.format(label="", state="active", iot="Mismatch"))
    fw2 = _capture(ha=body.format(label="SITE-A-HA", state="passive", iot="Mismatch"))

    findings = pair_findings(pair, fw1, fw2)

    assert [f["title"] for f in findings] == ["Pair HA Content Version Mismatch"]
    assert findings[0]["fields"] == [("IOT Content Compatibility", "Mismatch", "Mismatch")]
    assert "show system info" in findings[0]["summary"]

    in_sync = _capture(ha=body.format(label="SITE-A-HA", state="passive", iot="Match"))
    assert pair_findings(pair, _capture(ha=body.format(label="", state="active", iot="Match")), in_sync) == []


def test_health_verdict_ignores_pair_symmetry(tmp_path):
    """A window that changed nothing must not read red.

    Pair-symmetry findings describe how two members differ from each other
    right now - they were as true in the precheck as in the postcheck. Rolling
    them into the health verdict made a clean verification window report
    "Attention" next to "Changed: 0", which reads backwards."""
    pre_run = tmp_path / "Precheck" / "precheck_2026-01-01_00-00"
    post_run = tmp_path / "Postcheck" / "postcheck_2026-01-01_02-00"

    # Identical pre and post on both members, but the pair disagrees with
    # itself: SW-2 is missing a sequence SW-1 has, in both captures.
    for folder in (pre_run, post_run):
        _write(folder, "SITE-A-SW-1", PREFIX_LIST)
        _write(folder, "SITE-A-SW-2", PREFIX_LIST[:-1])

    analysis = analyze(str(pre_run), str(post_run))

    assert [f["title"] for f in analysis["pair_findings"]] == ["Pair Prefix-List Divergence"]
    assert analysis["symmetry_totals"]["Attention"] == 1
    assert analysis["window_totals"] == {"Stable": 0, "Changed": 0, "Attention": 0, "Action Required": 0}

    dirs = {
        "precheck": str(tmp_path / "Precheck"),
        "postcheck": str(tmp_path / "Postcheck"),
        "compare": str(tmp_path / "Compare"),
    }
    report = build_html_report("NET-5", dirs, "2026-01-01_02-05", Console(file=io.StringIO()))
    with open(report, encoding="utf-8") as handle:
        page = handle.read()

    assert "health-stable" in page
    assert "Nothing changed between the precheck and the postcheck" in page
    assert "Pair Symmetry" in page
    assert "1 pair-symmetry finding(s)" in page
