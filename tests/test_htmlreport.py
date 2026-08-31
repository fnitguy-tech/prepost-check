import io

from rich.console import Console

from modules.htmlreport import (
    bgp_neighbor_findings,
    build_html_report,
    classify_raw_diff_commands,
    clean_line_for_compare,
    parse_bgp_summary,
    safe_id,
)

BGP_ESTAB = "SPINE1 203.0.113.1 4 65001 12345 12340 0 0 5d02h Estab 100 98"
BGP_IDLE = "SPINE1 203.0.113.1 4 65001 12345 12340 0 0 5d02h Idle(Admin)"


def test_safe_id():
    assert safe_id("Switch-1 (Core).txt") == "switch-1-core-txt"


def test_parse_bgp_summary():
    peers = parse_bgp_summary(["Neighbor V AS MsgRcvd", BGP_ESTAB])

    assert list(peers) == ["SPINE1 203.0.113.1"]
    peer = peers["SPINE1 203.0.113.1"]
    assert peer["as"] == "65001"
    assert peer["state"] == "Estab"
    assert peer["prefixes_received"] == "100"
    assert peer["prefixes_accepted"] == "98"


def test_clean_line_collapses_bgp_summary():
    assert clean_line_for_compare("show ip bgp summary", BGP_ESTAB) == (
        "SPINE1 203.0.113.1 AS65001 Estab 100 98"
    )


def test_peer_removed_is_attention():
    pre = {"show ip bgp summary": [BGP_ESTAB]}
    post = {"show ip bgp summary": []}

    findings = bgp_neighbor_findings(pre, post, [])

    assert len(findings) == 1
    assert findings[0]["title"] == "BGP Peer Removed From Summary"
    assert findings[0]["impact"] == "Attention"


def test_admin_shutdown_is_attention():
    pre = {"show ip bgp summary": [BGP_ESTAB]}
    post = {"show ip bgp summary": [BGP_IDLE]}

    findings = bgp_neighbor_findings(pre, post, [])

    assert len(findings) == 1
    assert findings[0]["title"] == "BGP Peer Administratively Disabled"
    assert findings[0]["impact"] == "Attention"


def test_classify_raw_diff_commands():
    diffs = {
        "show running-config": [],
        "show ip bgp summary": [],
        "show interfaces status": [],
        "show hobbies": [],
    }

    categories = classify_raw_diff_commands(diffs)

    assert categories["Configuration"] == 1
    assert categories["Protocol"] == 1
    assert categories["Interface"] == 1
    assert categories["Evidence only"] == 1


def test_build_html_report_end_to_end(tmp_path):
    pre_run = tmp_path / "Precheck" / "precheck_2026-01-01_00-00"
    post_run = tmp_path / "Postcheck" / "postcheck_2026-01-01_02-00"
    pre_run.mkdir(parents=True)
    post_run.mkdir(parents=True)

    pre_capture = (
        "Hostname: switch1\n"
        "### show ip bgp summary ###\n"
        f"{BGP_ESTAB}\n"
        "### show running-config ###\n"
        "router bgp 65001\n"
        "   neighbor 203.0.113.1 remote-as 65001\n"
    )
    post_capture = (
        "Hostname: switch1\n"
        "### show ip bgp summary ###\n"
        f"{BGP_IDLE}\n"
        "### show running-config ###\n"
        "router bgp 65001\n"
        "   neighbor 203.0.113.1 remote-as 65001\n"
        "   neighbor 203.0.113.1 shutdown\n"
    )

    (pre_run / "switch1.txt").write_text(pre_capture)
    (post_run / "switch1.txt").write_text(post_capture)

    dirs = {
        "precheck": str(tmp_path / "Precheck"),
        "postcheck": str(tmp_path / "Postcheck"),
        "compare": str(tmp_path / "Compare"),
    }

    console = Console(file=io.StringIO())
    report_path = build_html_report("NET-1", dirs, "2026-01-01_02-05", console)

    assert report_path is not None
    with open(report_path, encoding="utf-8") as report:
        content = report.read()

    assert "NET-1" in content
    assert "switch1.txt" in content
    assert "BGP Peer Administratively Disabled" in content
    assert "neighbor 203.0.113.1 shutdown" in content
    assert content.count("<canvas") == 3
