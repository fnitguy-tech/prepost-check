"""LSVPN and routing-policy normalization.

A maintenance on an LSVPN hub changes what is built: gateways, tunnels,
pools, certificates, the portal cookie lifetime, and the route-maps or
prefix-lists that decide what a peer is sent. Everything else in those
outputs moves on its own - traffic counters climb, aircraft connect and
disconnect, hit counters tick - and would bury the real finding.

These tests pin that split: the identity of a thing survives, the
numbers that move without anyone touching the device do not.
"""

from modules.htmlreport import classify_raw_diff_commands, clean_line_for_compare
from modules.textcompare import normalize_line

FLOW = "show global-protect-gateway flow-site-to-site"
GATEWAY = "show global-protect-gateway gateway"
SATELLITE = "show global-protect-gateway current-satellite"
COOKIE = "show global-protect-portal satellite-cookie-expiration"


def test_flow_counters_drop_but_tunnel_survives():
    before = normalize_line(FLOW, "SIL-HCX-FW1 tunnel.511 active 10.2.0.9 148293 20481")
    after = normalize_line(FLOW, "SIL-HCX-FW1 tunnel.511 active 10.2.0.9 992104 88123")

    assert before == after
    assert "SIL-HCX-FW1" in before
    assert "tunnel.511" in before


def test_flow_state_change_is_visible():
    up = normalize_line(FLOW, "SIL-HCX-FW1 tunnel.511 active 10.2.0.9 148293 20481")
    down = normalize_line(FLOW, "SIL-HCX-FW1 tunnel.511 init 10.2.0.9 148293 20481")

    assert up != down


def test_gateway_satellite_count_is_not_a_change():
    assert normalize_line(GATEWAY, "  Number of satellites connected: 4") is None
    assert normalize_line(GATEWAY, "  Current satellites : 2") is None


def test_gateway_build_survives():
    line = "  Tunnel Interface: tunnel.511"

    assert normalize_line(GATEWAY, line) == line


def test_satellite_login_time_is_not_a_change():
    assert normalize_line(SATELLITE, "Login time: Sep.28 04:15:11") is None


def test_cookie_lifetime_is_compared_verbatim():
    line = "Satellite cookie expiration: 5"

    assert normalize_line(COOKIE, line) == line


def test_route_map_hit_counters_drop():
    assert normalize_line("show route-map", "  Match clauses hit: 4211") is None
    assert (
        normalize_line("show route-map", "route-map VIASAT-OUT-P0 permit 10 ( 812 matches )")
        == "route-map VIASAT-OUT-P0 permit 10"
    )


def test_prefix_list_entry_survives():
    line = "   seq 40 permit 198.51.100.243/32"

    assert normalize_line("show ip prefix-list", line) == line


def test_html_report_applies_the_same_rules():
    before = clean_line_for_compare(FLOW, "SIL-HCX-FW1 tunnel.511 active 10.2.0.9 148293 20481")
    after = clean_line_for_compare(FLOW, "SIL-HCX-FW1 tunnel.511 active 10.2.0.9 992104 88123")

    assert before == after
    assert clean_line_for_compare(GATEWAY, "  Number of satellites connected: 4") is None


def test_new_commands_are_categorised():
    categories = classify_raw_diff_commands([FLOW, GATEWAY, COOKIE, "show route-map"])

    assert categories["Protocol"] == 3
    assert categories["Routing"] == 1
    assert categories["Evidence only"] == 0
