"""BGP-relevant config lines.

bgp_config_changes() decides which changed running-config lines are
shown next to the BGP findings. It used to match only the "router bgp"
block itself (neighbor, route-map, community, shutdown), so a
prefix-list, peer-group, redistribution or PAN-OS valid-networks edit -
the things that actually change what a peer is sent - never reached
that context.
"""

from modules.htmlreport import bgp_config_changes, bgp_neighbor_findings

EOS_PRE = [
    "ip prefix-list ISP-OUT",
    "   seq 10 permit 203.0.113.0/24",
    "   seq 40 permit 198.51.100.243/32",
    "!",
    "router bgp 64500",
    "   neighbor ISP peer group",
    "   neighbor ISP route-map ISP-OUT out",
    "   neighbor 198.51.100.1 peer group ISP",
    "   redistribute connected route-map CONN",
    "   bfd interval 300 min-rx 300 multiplier 3",
    "   link-state bandwidth 10g",
]

PANOS_PRE = [
    "set network virtual-router default protocol bgp peer-group EACN peer EACN-1 peer-address ip 10.40.0.1",
    "set network virtual-router default protocol bgp policy export rules EACN-OUT used-by EACN",
    "set network virtual-router default protocol bgp policy export rules EACN-OUT match address-prefix 10.20.0.0/16 exact yes",
    "set network virtual-router default protocol bgp redist-rules 10.20.0.0/16 enable yes",
    "set network virtual-router default protocol bgp auth-profile EACN-AUTH secret <REDACTED>",
    "set network virtual-router default protocol bgp valid-networks 10.20.0.0/16",
]


def _changes(pre, post, command="show running-config"):
    return bgp_config_changes({command: pre}, {command: post})


def test_prefix_list_edit_reaches_bgp_context():
    post = [line for line in EOS_PRE if "seq 40" not in line]

    assert _changes(EOS_PRE, post) == ["  ip prefix-list ISP-OUT", "-    seq 40 permit 198.51.100.243/32"]


def test_eos_policy_keywords_are_bgp_relevant():
    post = [
        line for line in EOS_PRE
        if "peer group ISP" not in line and "redistribute" not in line and "bfd" not in line and "link-state" not in line
    ]
    post.append("ip access-list BGP-PEERS")
    post.append("   10 permit ip 198.51.100.0/24 any")
    post.append("   ip access-group BGP-PEERS in")

    changes = _changes(EOS_PRE, post)
    removed_or_added = sorted(line[2:].strip() for line in changes if line.startswith(("- ", "+ ")))
    assert "  router bgp 64500" in changes

    assert "neighbor 198.51.100.1 peer group ISP" in removed_or_added
    assert "redistribute connected route-map CONN" in removed_or_added
    assert "bfd interval 300 min-rx 300 multiplier 3" in removed_or_added
    assert "link-state bandwidth 10g" in removed_or_added
    assert "ip access-list BGP-PEERS" in removed_or_added
    assert "ip access-group BGP-PEERS in" in removed_or_added


def test_panos_valid_networks_and_used_by_register():
    post = [
        line.replace("valid-networks 10.20.0.0/16", "valid-networks 10.20.0.0/17")
        if "valid-networks" in line else line
        for line in PANOS_PRE
        if "used-by" not in line
    ]

    changes = _changes(PANOS_PRE, post, command="show config running")
    text = "\n".join(changes)

    assert "used-by EACN" in text
    assert "valid-networks 10.20.0.0/16" in text
    assert "valid-networks 10.20.0.0/17" in text

    # Everything PAN-OS says under "protocol bgp" is BGP context, even
    # lines with none of the EOS keywords.
    auth_only = _changes(PANOS_PRE, [line for line in PANOS_PRE if "auth-profile" not in line], "show config running")
    assert len(auth_only) == 1 and "auth-profile" in auth_only[0]


def test_unrelated_config_lines_stay_out():
    pre = ["interface Ethernet1", "   description users", "vlan 240", "   name ISP-B-TRANSIT"]
    post = pre + ["interface Vlan240", "   ip address 10.24.0.1/24"]

    assert _changes(pre, post) == []


def test_prefix_list_change_is_cited_as_evidence_for_a_prefix_delta():
    row = "  ISP-B  198.51.100.9  4 64497  213  201  0  0  5d02h  Estab  {count}  {count}"
    pre = {"show ip bgp summary": [row.format(count=815)], "show running-config": EOS_PRE}
    post = {
        "show ip bgp summary": [row.format(count=814)],
        "show running-config": [line for line in EOS_PRE if "seq 40" not in line],
    }

    findings = bgp_neighbor_findings(pre, post, bgp_config_changes(pre, post))

    assert [f["title"] for f in findings] == ["BGP Prefix Count Changed"]
    assert findings[0]["evidence"] == "show ip bgp summary + BGP prefix-list/valid-networks config"
