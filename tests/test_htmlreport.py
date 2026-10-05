import io
import json

from rich.console import Console

from modules.htmlreport import (
    bgp_neighbor_findings,
    build_html_report,
    classify_raw_diff_commands,
    clean_line_for_compare,
    parse_bgp_summary,
    safe_id,
    script_json,
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
    assert findings[0]["title"] == "BGP Peer Shut Down"
    assert findings[0]["impact"] == "Attention"


def test_classify_raw_diff_commands():
    diffs = {
        "show running-config": [],
        "show ip bgp summary": [],
        "show interfaces status": [],
        "show vpn flow": [],
        "show vpn ipsec-sa": [],
        "show hobbies": [],
    }

    categories = classify_raw_diff_commands(diffs)

    assert categories["Configuration"] == 1
    assert categories["Protocol"] == 3
    assert categories["Interface"] == 1
    assert categories["Evidence only"] == 1


def test_build_html_report_end_to_end(tmp_path):
    pre_run = tmp_path / "Precheck" / "precheck_2026-01-01_00-00"
    post_run = tmp_path / "Postcheck" / "postcheck_2026-01-01_02-00"
    pre_run.mkdir(parents=True)
    post_run.mkdir(parents=True)

    pre_capture = (
        "Hostname: switch1\n"
        "### show ip bgp summary ###\n--------------------------------------------------------------------------------\n"
        f"{BGP_ESTAB}\n"
        "### show running-config ###\n--------------------------------------------------------------------------------\n"
        "router bgp 65001\n"
        "   neighbor 203.0.113.1 remote-as 65001\n"
    )
    post_capture = (
        "Hostname: switch1\n"
        "### show ip bgp summary ###\n--------------------------------------------------------------------------------\n"
        f"{BGP_IDLE}\n"
        "### show running-config ###\n--------------------------------------------------------------------------------\n"
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
    assert "BGP Peer Shut Down" in content
    assert "neighbor 203.0.113.1 shutdown" in content
    assert content.count("<canvas") == 3


def test_clean_line_applies_shared_vpn_rule():
    pre = "gw-siteA  1  tunnel-siteA  ESP/A256/SHA256  0x1a2b3c4d  CAFEF00D  1234"
    post = "gw-siteA  1  tunnel-siteA  ESP/A256/SHA256  0x9f8e7d6c  DEADBEEF  1301"
    assert clean_line_for_compare("show vpn ike-sa", pre) == clean_line_for_compare("show vpn ike-sa", post)
    assert clean_line_for_compare("show global-protect-gateway current-satellite", "  Login Time : x") is None


# --- report hardening -------------------------------------------------


def test_script_json_cannot_close_the_script_block():
    hostile = '</script><script>alert("x")</script> & <!--'
    encoded = script_json([hostile])

    assert "<" not in encoded and ">" not in encoded and "&" not in encoded
    assert encoded == (
        '["\\u003c/script\\u003e\\u003cscript\\u003ealert(\\"x\\")\\u003c/script\\u003e \\u0026 \\u003c!--"]'
    )
    # JavaScript and JSON both read the escapes back as the same text.
    assert json.loads(encoded) == [hostile]
    # Ordinary values are written exactly as json.dumps writes them.
    assert script_json(["SITE-A-SW-1", 22]) == json.dumps(["SITE-A-SW-1", 22])


def _report_for(tmp_path, file_name):
    pre_run = tmp_path / "Precheck" / "precheck_2026-01-01_00-00"
    post_run = tmp_path / "Postcheck" / "postcheck_2026-01-01_02-00"
    pre_run.mkdir(parents=True)
    post_run.mkdir(parents=True)
    (pre_run / file_name).write_text("Hostname: x\n")
    (post_run / file_name).write_text("Hostname: x\n")
    dirs = {
        "precheck": str(tmp_path / "Precheck"),
        "postcheck": str(tmp_path / "Postcheck"),
        "compare": str(tmp_path / "Compare"),
    }

    with open(build_html_report("NET-1", dirs, "2026-01-01_02-05-00", Console(file=io.StringIO())), encoding="utf-8") as report:
        return report.read()


def test_a_hostile_device_name_stays_inside_its_script_string(tmp_path):
    # Linux allows "<" and ">" in a file name; "/" is the one thing it
    # can't hold, so the classic "</script>" needs no slash to be tested:
    # any "<" reaching the script block raw is the bug.
    page = _report_for(tmp_path, "<script>alert(1)<.txt")
    script = page[page.rindex("<script>"):]

    assert 'const deviceLabels = ["\\u003cscript\\u003ealert(1)\\u003c"];' in script
    assert "<script>alert(1)" not in script[len("<script>"):]


def test_chart_js_is_pinned_and_hash_checked(tmp_path):
    page = _report_for(tmp_path, "switch1.txt")

    assert (
        '<script src="https://cdn.jsdelivr.net/npm/chart.js@4.5.1/dist/chart.umd.min.js" '
        'integrity="sha384-jb8JQMbMoBUzgWatfe6COACi2ljcDdZQ2OxczGA3bGNeWe+6DChMTBJemed7ZnvJ" '
        'crossorigin="anonymous"></script>'
    ) in page
    assert page.count("<script") == 2


def test_the_report_says_so_when_the_charts_cannot_load(tmp_path):
    page = _report_for(tmp_path, "switch1.txt")
    script = page[page.rindex("<script>"):]

    # Every use of Chart sits behind the check, so a blocked CDN can't
    # stop the script with a ReferenceError.
    guard = script.index('if (typeof Chart === "undefined") {')
    assert guard < script.index("Chart.defaults.color")
    assert guard < script.index("new Chart(")
    assert "Charts are not shown because Chart.js could not be loaded from the CDN." in script
    assert script.count("{") == script.count("}")
