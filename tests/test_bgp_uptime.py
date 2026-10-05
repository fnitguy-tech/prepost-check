"""BGP session uptime.

The raw diff strips the Up/Down column because it moves on every
capture. The interpreted layer reads it: a peer that reset
and came straight back is Estab in both captures with the same prefix
counts, and a smaller uptime in the postcheck is the only trace it
leaves. These tests pin both the formats and the rule that a reset is
only ever flagged when the post value is unambiguously smaller.
"""

import io

from rich.console import Console

from modules.htmlreport import (
    bgp_neighbor_findings,
    build_html_report,
    parse_bgp_summary,
    parse_panos_bgp_peers,
    parse_uptime,
)

ROW = "  ISP-B  198.51.100.9  4 64497  213  201  0  0  {updown}  Estab  815  815"
PANOS_BLOCK = """\
Peer: EACN-PEER-1 (id 1)
  virtual router: default
  Peer router id: 10.40.0.1
  Remote AS: 64510, peer group: EACN
  Peer status: Established, for {secs} secs
  Peer address: 10.40.0.1:179
  Local address: 10.40.0.2:179
  Prefix counter for AFI/SAFI: ipv4 unicast
    Incoming total: 5, accepted: 5, rejected: 0
    Outgoing total: 3
"""


def _summary(updown):
    return {"show ip bgp summary": [ROW.format(updown=updown)]}


def test_parse_uptime_formats():
    assert parse_uptime("01:02:03") == (3723, 1)
    assert parse_uptime("00:12:33") == (753, 1)
    assert parse_uptime("1d02h") == (26 * 3600, 3600)
    assert parse_uptime("2w3d") == (17 * 86400, 86400)
    assert parse_uptime("5d02h") == (5 * 86400 + 2 * 3600, 3600)
    assert parse_uptime("123456 secs") == (123456, 1)


def test_parse_uptime_refuses_to_guess():
    assert parse_uptime("never") is None
    assert parse_uptime("Estab") is None
    assert parse_uptime("") is None
    assert parse_uptime(None) is None


def test_summary_keeps_updown_column():
    peers = parse_bgp_summary([ROW.format(updown="5d02h")])

    assert peers["ISP-B 198.51.100.9"]["updown"] == "5d02h"
    assert peers["ISP-B 198.51.100.9"]["state"] == "Estab"

    idle = parse_bgp_summary(["  ISP-A  198.51.100.1  4 64496  48377  48102  0  0  00:01:12  Idle(Admin)"])
    assert idle["ISP-A 198.51.100.1"]["updown"] == "00:01:12"

    never = parse_bgp_summary(["  NEW  198.51.100.17  4 64498  0  0  0  0  never  Active"])
    assert never["NEW 198.51.100.17"]["updown"] == "never"
    assert never["NEW 198.51.100.17"]["state"] == "Active"


def test_uptime_going_backwards_is_a_reset():
    findings = bgp_neighbor_findings(_summary("5d02h"), _summary("00:12:33"), [])

    assert len(findings) == 1
    finding = findings[0]
    assert finding["title"] == "BGP Session Reset"
    assert finding["impact"] == "Attention"
    assert finding["classification"] == "Protocol"
    assert ("Up/Down", "5d02h", "00:12:33") in finding["fields"]
    assert "dropped and came back during the window" in finding["summary"]
    assert "Prefix counts came back the same." in finding["summary"]


def test_uptime_growing_is_not_a_finding():
    assert bgp_neighbor_findings(_summary("5d02h"), _summary("5d04h"), []) == []
    assert bgp_neighbor_findings(_summary("23:59:10"), _summary("1d02h"), []) == []
    assert bgp_neighbor_findings(_summary("6d23h"), _summary("1w0d"), []) == []


def test_equal_coarse_uptime_is_not_a_reset():
    # 34d11h in both captures: the true values differ by two hours but the
    # format cannot show it, and equal is not smaller.
    assert bgp_neighbor_findings(_summary("34d11h"), _summary("34d11h"), []) == []


def test_boundary_of_coarse_format_is_not_a_reset():
    # 1d02h means [26h, 27h); a post value of 1d02h can never be shown to
    # be below a pre value of 1d02h, only 1d01h can.
    assert bgp_neighbor_findings(_summary("1d02h"), _summary("1d02h"), []) == []
    findings = bgp_neighbor_findings(_summary("1d02h"), _summary("1d01h"), [])
    assert [f["title"] for f in findings] == ["BGP Session Reset"]


def test_unparsable_uptime_never_flags():
    assert bgp_neighbor_findings(_summary("never"), _summary("00:10:00"), []) == []
    assert bgp_neighbor_findings(_summary("5d02h"), _summary("never"), []) == []


def test_reset_with_prefix_change_is_one_attention_finding():
    post = {"show ip bgp summary": [ROW.format(updown="00:12:33").replace("815  815", "812  812")]}

    findings = bgp_neighbor_findings(_summary("5d02h"), post, [])

    assert len(findings) == 1
    assert findings[0]["title"] == "BGP Session Reset"
    assert findings[0]["impact"] == "Attention"
    assert "changed by -3 across the reset" in findings[0]["summary"]
    assert ("Prefixes Received", "815", "812") in findings[0]["fields"]


def test_panos_peer_block_parses_like_a_summary_row():
    peers = parse_panos_bgp_peers(PANOS_BLOCK.format(secs=123456).splitlines())

    assert list(peers) == ["EACN-PEER-1 10.40.0.1"]
    peer = peers["EACN-PEER-1 10.40.0.1"]
    assert peer["as"] == "64510"
    assert peer["state"] == "Estab"
    assert peer["updown"] == "123456 secs"
    assert peer["prefixes_received"] == "5"
    assert peer["prefixes_accepted"] == "5"


def test_panos_peer_reset_is_attention():
    pre = {"show routing protocol bgp peer": PANOS_BLOCK.format(secs=123456).splitlines()}
    post = {"show routing protocol bgp peer": PANOS_BLOCK.format(secs=310).splitlines()}

    findings = bgp_neighbor_findings(pre, post, [])

    assert [f["title"] for f in findings] == ["BGP Session Reset"]
    assert findings[0]["subject"] == ["EACN-PEER-1", "10.40.0.1", "AS64510"]

    # Same peer, uptime grew: nothing to report.
    later = {"show routing protocol bgp peer": PANOS_BLOCK.format(secs=130000).splitlines()}
    assert bgp_neighbor_findings(pre, later, []) == []


def test_reset_reaches_the_report(tmp_path):
    pre_run = tmp_path / "Precheck" / "precheck_2026-01-01_00-00"
    post_run = tmp_path / "Postcheck" / "postcheck_2026-01-01_02-00"
    pre_run.mkdir(parents=True)
    post_run.mkdir(parents=True)

    capture = "Hostname: SITE-A-SW-1\n### show ip bgp summary ###\n--------------------------------------------------------------------------------\n{row}\n"
    (pre_run / "SITE-A-SW-1.txt").write_text(capture.format(row=ROW.format(updown="5d02h")))
    (post_run / "SITE-A-SW-1.txt").write_text(capture.format(row=ROW.format(updown="00:12:33")))

    dirs = {
        "precheck": str(tmp_path / "Precheck"),
        "postcheck": str(tmp_path / "Postcheck"),
        "compare": str(tmp_path / "Compare"),
    }
    report_path = build_html_report("NET-3", dirs, "2026-01-01_02-05", Console(file=io.StringIO()))

    with open(report_path, encoding="utf-8") as report:
        content = report.read()

    assert "BGP Session Reset" in content
    assert 'health-attention">Attention' in content
    assert "Up/Down" in content
