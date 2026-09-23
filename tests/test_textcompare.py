import io

from rich.console import Console

from modules.textcompare import normalize_line, parse_sections, write_compare_report


def test_noisy_lines_dropped():
    assert normalize_line("show version", "Uptime: 5 days") is None
    assert normalize_line("HEADER", "Generated: 2026-01-01 00:00:00") is None
    assert normalize_line("show interfaces transceiver", "anything at all") is None


def test_running_config_kept_verbatim():
    # Config diffs must be exact - even lines that look "noisy"
    # elsewhere survive untouched.
    line = "   uptime: banner text"
    assert normalize_line("show running-config", line) == line


def test_bgp_summary_drops_timers_keeps_state():
    line = "SPINE1 203.0.113.1 4 65001 12345 12340 0 0 5d02h Estab 100 98"
    assert normalize_line("show ip bgp summary", line) == "SPINE1 203.0.113.1 4 Estab 100 98"

    line = "SPINE1 203.0.113.1 4 65001 12345 12340 0 0 5d02h Idle(Admin)"
    assert normalize_line("show ip bgp summary", line) == "SPINE1 203.0.113.1 4 Idle(Admin)"


def test_ospf_neighbor_drops_dead_timer():
    # Column 6 (index 5) is the dead-timer countdown; everything else
    # must survive so real neighbor changes still show up.
    line = "203.0.113.2 default 1 FULL 198.51.100.2 00:00:31 Ethernet49/1 0"
    result = normalize_line("show ip ospf neighbor", line)
    assert result == "203.0.113.2 default 1 FULL 198.51.100.2 Ethernet49/1 0"


def test_panos_route_age_dropped():
    pre = "198.51.100.0/24 198.51.100.9 10 3600 A B ethernet1/1"
    post = "198.51.100.0/24 198.51.100.9 10 7200 A B ethernet1/1"
    assert normalize_line("show routing route", pre) == normalize_line("show routing route", post)


def test_panos_peer_status_keeps_state_only():
    line = "  Peer status: Established, for 123456 secs"
    assert normalize_line("show routing protocol bgp peer", line) == "Peer status: Established"
    assert normalize_line("show routing protocol bgp peer", "  Flap counts: 3") is None


def test_parse_sections_and_compare_report(tmp_path):
    pre_run = tmp_path / "Precheck" / "precheck_2026-01-01_00-00"
    post_run = tmp_path / "Postcheck" / "postcheck_2026-01-01_02-00"
    pre_run.mkdir(parents=True)
    post_run.mkdir(parents=True)

    capture = (
        "Hostname: switch1\n"
        "### show vlan brief ###\n"
        "10  users  active\n"
        "{extra}"
    )

    (pre_run / "switch1.txt").write_text(capture.format(extra=""))
    (post_run / "switch1.txt").write_text(capture.format(extra="20  voice  active\n"))

    sections = parse_sections(str(pre_run / "switch1.txt"))
    assert sections["show vlan brief"] == ["10  users  active"]

    dirs = {
        "precheck": str(tmp_path / "Precheck"),
        "postcheck": str(tmp_path / "Postcheck"),
        "compare": str(tmp_path / "Compare"),
    }

    console = Console(file=io.StringIO())
    report_path = write_compare_report("NET-1", dirs, "2026-01-01_02-05", console)

    assert report_path is not None
    with open(report_path, encoding="utf-8") as report:
        content = report.read()
    assert "Device/File: switch1.txt" in content
    assert "Command: show vlan brief" in content
    assert "+ 20  voice  active" in content


def test_compare_report_skips_without_precheck(tmp_path):
    dirs = {
        "precheck": str(tmp_path / "Precheck"),
        "postcheck": str(tmp_path / "Postcheck"),
        "compare": str(tmp_path / "Compare"),
    }

    console = Console(file=io.StringIO())
    assert write_compare_report("NET-1", dirs, "2026-01-01_00-00", console) is None


def test_vpn_ike_sa_drops_rekey_churn_keeps_identity():
    # IKEv2 SA row: gateway ID, peer, name, role and algorithm survive;
    # the established/expiration timestamps and child count do not.
    pre = "1  198.51.100.7  gw-siteA  Init  PSK/ DH14/A256/SHA256  Aug.31 10:11:12  Sep.01 10:11:12  1"
    post = "1  198.51.100.7  gw-siteA  Init  PSK/ DH14/A256/SHA256  Sep.01 10:11:12  Sep.02 10:11:12  2"
    assert normalize_line("show vpn ike-sa", pre) == normalize_line("show vpn ike-sa", post)
    assert normalize_line("show vpn ike-sa", pre) == "1 198.51.100.7 gw-siteA Init PSK/ DH14/A256/SHA256"

    # Child SA row: SPIs (with and without 0x) and the message ID churn.
    pre = "gw-siteA  1  tunnel-siteA  ESP/A256/SHA256  0x1a2b3c4d  CAFEF00D  1234"
    post = "gw-siteA  1  tunnel-siteA  ESP/A256/SHA256  0x9f8e7d6c  DEADBEEF  1301"
    assert normalize_line("show vpn ike-sa", pre) == normalize_line("show vpn ike-sa", post)
    assert normalize_line("show vpn ike-sa", pre) == "gw-siteA tunnel-siteA ESP/A256/SHA256"


def test_vpn_ike_sa_count_line_kept():
    line = "Show IKEv2 IKE SA: Total 1 gateways found. 1 ike sa found."
    assert normalize_line("show vpn ike-sa", line) == line


def test_vpn_ipsec_sa_state_change_survives():
    pre = "1  1  198.51.100.7  tunnel-siteA(gw-siteA)  ethernet1/1  Active  4  3450/28800  1.2GB"
    post = "1  1  198.51.100.7  tunnel-siteA(gw-siteA)  ethernet1/1  Init  0  0/28800  0KB"
    assert normalize_line("show vpn ipsec-sa", pre) == "1 198.51.100.7 tunnel-siteA(gw-siteA) ethernet1/1 Active"
    assert normalize_line("show vpn ipsec-sa", pre) != normalize_line("show vpn ipsec-sa", post)


def test_vpn_flow_kept_verbatim():
    line = "1  tunnel-siteA  active  off  203.0.113.1  198.51.100.7  tunnel.1"
    assert normalize_line("show vpn flow", line) == line


def test_lsvpn_satellite_login_time_dropped():
    cmd = "show global-protect-gateway current-satellite"
    assert normalize_line(cmd, "        Login Time    : Aug.31 10:11:12") is None
    assert normalize_line(cmd, "    Satellite         : sat-siteA") == "    Satellite         : sat-siteA"

    cmd = "show global-protect-satellite current-gateway"
    assert normalize_line(cmd, "  Status : Active") == "  Status : Active"
