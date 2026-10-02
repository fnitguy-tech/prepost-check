"""Prefix-list findings.

A prefix-list entry that vanishes between the captures is a route that
stopped being advertised (or accepted), and an entry replaced in place
at the same sequence number is the EOS overwrite that a careful change
plan is written to avoid. Both must surface as Attention findings, not
as one grey line in the raw config diff.
"""

import io

from rich.console import Console

from modules.htmlreport import (
    analyze,
    build_html_report,
    parse_prefix_lists,
    prefix_list_findings,
)

SHOW_PRE = [
    "ip prefix-list ISP-OUT",
    "   seq 10 permit 203.0.113.0/24 ( 812 matches )",
    "   seq 20 permit 198.51.100.0/24",
    "   seq 30 permit 198.51.100.240/28 le 32",
    "   seq 40 permit 198.51.100.243/32",
    "ip prefix-list ISP-IN",
    "   seq 10 deny 0.0.0.0/0",
    "   seq 20 permit 0.0.0.0/0 le 24",
]


def _sections(lines, config=None):
    sections = {"show ip prefix-list": lines}
    if config is not None:
        sections["show running-config"] = config
    return sections


def test_parse_show_output_drops_hit_counters():
    lists = parse_prefix_lists(SHOW_PRE)

    assert sorted(lists) == ["ISP-IN", "ISP-OUT"]
    assert lists["ISP-OUT"][10] == "permit 203.0.113.0/24"
    assert lists["ISP-OUT"][30] == "permit 198.51.100.240/28 le 32"
    assert lists["ISP-IN"] == {10: "deny 0.0.0.0/0", 20: "permit 0.0.0.0/0 le 24"}


def test_parse_running_config_block_and_one_line_forms():
    config = [
        "ip prefix-list ISP-OUT",
        "   seq 10 permit 203.0.113.0/24",
        "!",
        "ip prefix-list LOOPBACKS seq 5 permit 192.0.2.0/24 ge 32",
        "ip prefix-list LOOPBACKS seq 10 permit 192.0.2.0/24",
        "!",
        "router bgp 64500",
        "   neighbor 10.0.0.2 remote-as 64500",
    ]

    lists = parse_prefix_lists(config)

    assert lists == {
        "ISP-OUT": {10: "permit 203.0.113.0/24"},
        "LOOPBACKS": {5: "permit 192.0.2.0/24 ge 32", 10: "permit 192.0.2.0/24"},
    }


def test_untouched_lists_produce_no_findings():
    # Only the hit counter moved.
    post = [line.replace("812 matches", "944 matches") for line in SHOW_PRE]

    assert prefix_list_findings(_sections(SHOW_PRE), _sections(post)) == []


def test_removed_entry_is_attention():
    post = [line for line in SHOW_PRE if "seq 40" not in line]

    findings = prefix_list_findings(_sections(SHOW_PRE), _sections(post))

    assert len(findings) == 1
    finding = findings[0]
    assert finding["title"] == "Prefix-List Entry Removed"
    assert finding["impact"] == "Attention"
    assert finding["classification"] == "Routing"
    assert finding["subject"] == ["ISP-OUT", "seq 40"]
    assert ("Entry", "permit 198.51.100.243/32", "Not Present") in finding["fields"]
    assert finding["evidence"] == "show ip prefix-list"
    assert "isn't advertised any more" in finding["summary"]


def test_same_seq_different_prefix_is_attention():
    # The replace-by-sequence overwrite: seq 40 was meant to be a new
    # entry but it already existed, so the old prefix is gone.
    post = [line.replace("seq 40 permit 198.51.100.243/32", "seq 40 permit 198.51.100.244/32") for line in SHOW_PRE]

    findings = prefix_list_findings(_sections(SHOW_PRE), _sections(post))

    assert len(findings) == 1
    finding = findings[0]
    assert finding["title"] == "Prefix-List Entry Replaced"
    assert finding["impact"] == "Attention"
    assert ("Entry", "permit 198.51.100.243/32", "permit 198.51.100.244/32") in finding["fields"]
    assert "no longer appears anywhere" in finding["summary"]


def test_new_seq_is_stable():
    post = SHOW_PRE[:5] + ["   seq 50 permit 198.51.100.244/32"] + SHOW_PRE[5:]

    findings = prefix_list_findings(_sections(SHOW_PRE), _sections(post))

    assert len(findings) == 1
    assert findings[0]["title"] == "Prefix-List Entry Added"
    assert findings[0]["impact"] == "Stable"
    assert findings[0]["subject"] == ["ISP-OUT", "seq 50"]


def test_resequenced_entry_is_changed_not_withdrawn():
    post = [line.replace("seq 40 permit", "seq 45 permit") for line in SHOW_PRE]

    findings = prefix_list_findings(_sections(SHOW_PRE), _sections(post))

    assert len(findings) == 1
    assert findings[0]["title"] == "Prefix-List Entry Moved"
    assert findings[0]["impact"] == "Changed"
    assert ("Sequence", "40", "45") in findings[0]["fields"]


def test_whole_list_removed_is_one_attention_finding_with_detail():
    post = SHOW_PRE[5:]

    findings = prefix_list_findings(_sections(SHOW_PRE), _sections(post))

    assert len(findings) == 1
    assert findings[0]["title"] == "Prefix-List Removed"
    assert findings[0]["impact"] == "Attention"
    assert findings[0]["subject"] == ["ISP-OUT"]
    assert ("removed", "seq 40 permit 198.51.100.243/32") in findings[0]["detail"]


def test_falls_back_to_running_config_when_show_is_not_captured():
    pre = {"show running-config": ["ip prefix-list ISP-OUT", "   seq 10 permit 203.0.113.0/24", "!"]}
    post = {"show running-config": ["ip prefix-list ISP-OUT", "!"]}

    findings = prefix_list_findings(pre, post)

    assert len(findings) == 1
    assert findings[0]["title"] == "Prefix-List Entry Removed"
    assert findings[0]["evidence"] == "show running-config"


def _write_capture(folder, prefix_lines):
    folder.mkdir(parents=True)
    (folder / "SITE-A-SW-1.txt").write_text(
        "Hostname: SITE-A-SW-1\n"
        "### show ip bgp summary ###\n"
        "  ISP-B  198.51.100.9  4 64497  213  201  0  0  00:52:40  Estab  815  815\n"
        "### show ip prefix-list ###\n" + "\n".join(prefix_lines) + "\n"
        "### show running-config ###\n"
        "router bgp 64500\n"
        "   neighbor 198.51.100.9 remote-as 64497\n"
    )


def test_prefix_list_removal_reaches_verdict_attention_list_and_score(tmp_path):
    pre_run = tmp_path / "Precheck" / "precheck_2026-01-01_00-00"
    post_run = tmp_path / "Postcheck" / "postcheck_2026-01-01_02-00"
    _write_capture(pre_run, SHOW_PRE)
    _write_capture(post_run, [line for line in SHOW_PRE if "seq 40" not in line])

    analysis = analyze(str(pre_run), str(post_run))

    assert analysis["impact_totals"]["Attention"] == 1
    assert analysis["total_findings_by_classification"]["Routing"] >= 1
    device = analysis["device_reports"][0]
    assert device["attention_count"] == 1
    assert device["impact_score"] >= 5

    dirs = {
        "precheck": str(tmp_path / "Precheck"),
        "postcheck": str(tmp_path / "Postcheck"),
        "compare": str(tmp_path / "Compare"),
    }
    report_path = build_html_report("NET-2", dirs, "2026-01-01_02-05", Console(file=io.StringIO()))

    with open(report_path, encoding="utf-8") as report:
        content = report.read()

    assert "Prefix-List Entry Removed" in content
    assert 'health-attention">Attention' in content
    assert "permit 198.51.100.243/32" in content
    assert "<canvas" in content
