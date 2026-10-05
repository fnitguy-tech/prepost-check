"""Newly addressed interfaces.

An interface that gained an IP address during the window and is up is
the change working; one that gained an address and is still down means
the step configured cleanly and does not work, which deserves
Attention. Status only ever comes from a show table: an interface the
capture cannot say is up or down is never rated.
"""

import io

from rich.console import Console

from modules.htmlreport import (
    build_html_report,
    interface_findings,
    parse_config_addresses,
    parse_interface_all,
    parse_interfaces_status,
    parse_ip_interface_brief,
)

EOS_BRIEF = """\
                                                                              Address
Interface         IP Address           Status       Protocol           MTU    Owner
----------------- -------------------- ------------ -------------- ---------- -------
Ethernet49/1      198.51.100.2/30      up           up                 1500
Ethernet50/1      198.51.100.10/30     {status}
Loopback0         192.0.2.1/32         up           up                65535
Vlan240           unassigned           admin down   down               1500
"""

PANOS_ALL = """\
total configured hardware interfaces: 3
name                    id    speed/duplex/state    mac address
--------------------------------------------------------------------------------
ethernet1/1             16    1000/full/up          00:1b:17:00:00:11
ethernet1/2             17    1000/full/down        00:1b:17:00:00:12
ethernet1/3             18    ukn/ukn/{state}       00:1b:17:00:00:13
aggregation groups: 0
total configured logical interfaces: 5
name                id    vsys zone             forwarding               tag    address
------------------- ----- ---- ---------------- ------------------------ ------ ------------------
ethernet1/1         16    1    outside          vr:default               0      10.10.200.254/24
ethernet1/2         17    1    inside           vr:default               0      10.20.0.1/16
ethernet1/3         18    1    dmz              vr:default               0      {address}
ethernet1/3.100     260   1    dmz-100          vr:default               100    10.30.100.1/24
tunnel.1            256   1    vpn              vr:default               0      10.99.0.1/30
"""


def test_parse_eos_ip_interface_brief():
    interfaces = parse_ip_interface_brief(EOS_BRIEF.format(status="down         down               1500").splitlines())

    assert interfaces["Ethernet49/1"] == {"address": "198.51.100.2/30", "status": "up"}
    assert interfaces["Ethernet50/1"] == {"address": "198.51.100.10/30", "status": "down down"}
    assert interfaces["Vlan240"] == {"address": None, "status": "admin down down"}
    assert "Interface" not in interfaces


def test_parse_eos_interfaces_status_expands_names():
    statuses = parse_interfaces_status([
        "Port       Name               Status       Vlan     Duplex Speed  Type         Flags Encapsulation",
        "Et50/1     ISP-B uplink       notconnect   routed   full   10G    10GBASE-LR",
        "Et49/1     ISP-A uplink       connected    routed   full   10G    10GBASE-LR",
        "Po1        to SERVER-AGG      connected    trunk    full   20G    N/A",
    ])

    assert statuses == {"Ethernet50/1": "notconnect", "Ethernet49/1": "up", "Port-Channel1": "up"}


def test_parse_panos_interface_all():
    interfaces = parse_interface_all(PANOS_ALL.format(state="down", address="10.30.0.1/24").splitlines())

    assert interfaces["ethernet1/1"] == {"address": "10.10.200.254/24", "status": "up"}
    assert interfaces["ethernet1/3"] == {"address": "10.30.0.1/24", "status": "down"}
    # Sub-interface takes the parent port's link state; a tunnel has none.
    assert interfaces["ethernet1/3.100"] == {"address": "10.30.100.1/24", "status": "down"}
    assert interfaces["tunnel.1"] == {"address": "10.99.0.1/30", "status": None}


def test_parse_config_addresses_eos_and_panos():
    eos = [
        "interface Ethernet50/1",
        "   description ISP-B uplink",
        "   ip address 198.51.100.10/30",
        "!",
        "interface Vlan240",
        "   no autostate",
        "!",
        "router bgp 64500",
        "   neighbor 10.0.0.2 remote-as 64500",
    ]
    panos = [
        "set network interface ethernet ethernet1/1 layer3 ip 10.10.200.254/24",
        "set network interface ethernet ethernet1/3 layer3 units ethernet1/3.100 ip 10.30.100.1/24",
        "set network interface loopback units loopback.1 ip 192.0.2.99/32",
        "set network interface ethernet ethernet1/2 layer3 mtu 1500",
    ]

    assert parse_config_addresses(eos) == {"Ethernet50/1": "198.51.100.10/30"}
    assert parse_config_addresses(panos) == {
        "ethernet1/1": "10.10.200.254/24",
        "ethernet1/3.100": "10.30.100.1/24",
        "loopback.1": "192.0.2.99/32",
    }


def _eos(brief_status, with_vlan240_address=False):
    brief = EOS_BRIEF.format(status=brief_status)
    if with_vlan240_address:
        brief = brief.replace("Vlan240           unassigned           admin down   down", "Vlan240           10.24.0.1/24         up           up  ")
    return {"show ip interface brief": brief.splitlines()}


def test_newly_addressed_interface_that_is_down_is_attention():
    pre = {"show ip interface brief": [
        "Interface         IP Address           Status       Protocol           MTU    Owner",
        "Ethernet49/1      198.51.100.2/30      up           up                 1500",
        "Loopback0         192.0.2.1/32         up           up                65535",
    ]}
    post = _eos("down         down               1500")

    findings = interface_findings(pre, post)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["title"] == "New Address, Interface Still Down"
    assert finding["impact"] == "Attention"
    assert finding["classification"] == "Interface"
    assert finding["subject"] == ["Ethernet50/1", "198.51.100.10/30"]
    assert ("Address", "Not Present", "198.51.100.10/30") in finding["fields"]
    assert ("Status", "Not Present", "down down") in finding["fields"]
    assert finding["evidence"] == "show ip interface brief"


def test_newly_addressed_interface_that_is_up_is_stable():
    pre = _eos("down         down               1500")
    post = _eos("down         down               1500", with_vlan240_address=True)

    findings = interface_findings(pre, post)

    assert [(f["title"], f["impact"]) for f in findings] == [("New Address, Interface Up", "Stable")]
    assert ("Address", "unassigned", "10.24.0.1/24") in findings[0]["fields"]
    assert ("Status", "admin down down", "up") in findings[0]["fields"]


def test_interface_that_already_had_its_address_is_not_a_finding():
    # Ethernet50/1 was addressed but down before the window and is still
    # down: nothing gained, nothing to say here (the raw diff is empty too).
    pre = _eos("down         down               1500")
    post = _eos("down         down               1500")

    assert interface_findings(pre, post) == []


def test_panos_newly_addressed_port_down_is_attention_and_tunnel_is_never_rated():
    pre = {"show interface all": PANOS_ALL.format(state="down", address="N/A").splitlines()}
    post = {"show interface all": PANOS_ALL.format(state="down", address="10.30.0.1/24").splitlines()}

    findings = interface_findings(pre, post)

    assert [f["subject"][0] for f in findings] == ["ethernet1/3"]
    assert findings[0]["title"] == "New Address, Interface Still Down"

    # tunnel.1 appears with an address only in the postcheck but has no
    # link state: no status, no rating.
    pre_without_tunnel = {"show interface all": [
        line for line in PANOS_ALL.format(state="down", address="10.30.0.1/24").splitlines()
        if not line.startswith("tunnel.1")
    ]}
    assert interface_findings(pre_without_tunnel, post) == []


def test_config_address_with_interfaces_status_fallback():
    # Inventory without "show ip interface brief": the address comes from
    # the config and the link state from "show interfaces status".
    status = [
        "Port       Name               Status       Vlan     Duplex Speed  Type         Flags Encapsulation",
        "Et50/1     ISP-B uplink       {state}   routed   full   10G    10GBASE-LR",
    ]
    pre = {
        "show running-config": ["interface Ethernet50/1", "   description ISP-B uplink", "!"],
        "show interfaces status": [line.format(state="notconnect") for line in status],
    }
    post = {
        "show running-config": ["interface Ethernet50/1", "   ip address 198.51.100.10/30", "!"],
        "show interfaces status": [line.format(state="notconnect") for line in status],
    }

    findings = interface_findings(pre, post)

    assert [f["title"] for f in findings] == ["New Address, Interface Still Down"]
    assert findings[0]["evidence"] == "running config + show interfaces status"

    # Same config change, nothing that reports link state: never rated.
    assert interface_findings({"show running-config": pre["show running-config"]},
                              {"show running-config": post["show running-config"]}) == []


def test_down_interface_reaches_the_report(tmp_path):
    pre_run = tmp_path / "Precheck" / "precheck_2026-01-01_00-00"
    post_run = tmp_path / "Postcheck" / "postcheck_2026-01-01_02-00"
    pre_run.mkdir(parents=True)
    post_run.mkdir(parents=True)

    (pre_run / "SITE-A-SW-1.txt").write_text(
        "Hostname: SITE-A-SW-1\n### show ip interface brief ###\n--------------------------------------------------------------------------------\n"
        "Loopback0         192.0.2.1/32         up           up                65535\n"
    )
    (post_run / "SITE-A-SW-1.txt").write_text(
        "Hostname: SITE-A-SW-1\n### show ip interface brief ###\n--------------------------------------------------------------------------------\n"
        "Ethernet50/1      198.51.100.10/30     down         down               1500\n"
        "Loopback0         192.0.2.1/32         up           up                65535\n"
    )

    dirs = {
        "precheck": str(tmp_path / "Precheck"),
        "postcheck": str(tmp_path / "Postcheck"),
        "compare": str(tmp_path / "Compare"),
    }
    report_path = build_html_report("NET-6", dirs, "2026-01-01_02-05", Console(file=io.StringIO()))

    with open(report_path, encoding="utf-8") as report:
        content = report.read()

    assert "New Address, Interface Still Down" in content
    assert 'health-attention">Attention' in content
    assert "198.51.100.10/30" in content
