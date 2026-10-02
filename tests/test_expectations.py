"""Expected BGP prefix deltas.

Every prefix-count change used to carry the same "this may be expected
when ..." hedge, and a caveat on everything is a caveat on nothing. With
an expectations file in play a matching delta is Stable ("as planned"),
a delta that differs from or has no expectation is Attention, and an
expected change that did not happen is Attention too. Without a file,
the old behaviour (Changed + hedge) is kept.
"""

import io
import os

import pytest
from rich.console import Console

from modules.expectations import (
    EXAMPLE_EXPECTATIONS,
    ExpectationsError,
    for_device,
    load_expectations,
)
from modules.htmlreport import PREFIX_DELTA_HEDGE, analyze, bgp_neighbor_findings, build_html_report
from modules.layout import REPO_ROOT, ticket_dirs

ROW = "  {name}  {ip}  4 64497  213  201  0  0  5d02h  Estab  {count}  {count}"
DEMO = os.path.join(REPO_ROOT, "docs", "demo", "NET-DEMO")


def _sections(count, name="ISP-B", ip="198.51.100.9"):
    return {"show ip bgp summary": [ROW.format(name=name, ip=ip, count=count)]}


def _entry(peer, **expected):
    return {"device": "SITE-A-SW-1", "peer": peer, "note": "", **expected}


def test_load_expectations_example_file():
    entries = load_expectations(EXAMPLE_EXPECTATIONS, "NET-DEMO")

    assert entries == [{
        "device": "SITE-A-SW-2",
        "peer": "10.0.0.1",
        "expected_delta": 3,
        "note": "SITE-A-SW-1 re-advertises the three ISP-B transit prefixes over iBGP",
    }]


def test_load_expectations_accepts_quoted_delta_and_absolute_count(tmp_path):
    path = tmp_path / "expectations.yml"
    path.write_text(
        "expectations:\n"
        "  - device: sw-1\n    peer: ISP-B\n    expected_delta: '+3'\n"
        "  - device: sw-1\n    peer: 10.0.0.1\n    expected_prefixes: 815\n"
    )

    entries = load_expectations(str(path))

    assert entries[0]["expected_delta"] == 3
    assert entries[1]["expected_prefixes"] == 815
    assert entries[1]["note"] == ""


@pytest.mark.parametrize("body", [
    "expectations: nope\n",
    "expectations:\n  - peer: ISP-B\n    expected_delta: 3\n",
    "expectations:\n  - device: sw-1\n    expected_delta: 3\n",
    "expectations:\n  - device: sw-1\n    peer: ISP-B\n",
    "expectations:\n  - device: sw-1\n    peer: ISP-B\n    expected_delta: 3\n    expected_prefixes: 5\n",
    "expectations:\n  - device: sw-1\n    peer: ISP-B\n    expected_delta: three\n",
])
def test_malformed_expectations_rejected(tmp_path, body):
    path = tmp_path / "expectations.yml"
    path.write_text(body)

    with pytest.raises(ExpectationsError):
        load_expectations(str(path))


def test_wrong_ticket_and_missing_file_rejected(tmp_path):
    path = tmp_path / "expectations.yml"
    path.write_text("ticket: NET-1\nexpectations: []\n")

    with pytest.raises(ExpectationsError):
        load_expectations(str(path), "NET-2")
    assert load_expectations(str(path), "net-1") == []

    with pytest.raises(ExpectationsError):
        load_expectations(str(tmp_path / "missing.yml"))


def test_for_device_is_case_insensitive_and_none_without_a_file():
    entries = [{"device": "SITE-A-SW-1", "peer": "x", "expected_delta": 1, "note": ""}]

    assert for_device(entries, "site-a-sw-1") == entries
    assert for_device(entries, "SITE-A-SW-2") == []
    assert for_device(None, "SITE-A-SW-1") is None


def test_no_file_keeps_the_hedge():
    findings = bgp_neighbor_findings(_sections(815), _sections(812), [])

    assert [(f["title"], f["impact"]) for f in findings] == [("BGP Prefix Count Changed", "Changed")]
    assert PREFIX_DELTA_HEDGE in findings[0]["summary"]


def test_matching_delta_is_stable_as_planned():
    findings = bgp_neighbor_findings(_sections(812), _sections(815), [], expectations=[_entry("ISP-B", expected_delta=3)])

    assert [(f["title"], f["impact"]) for f in findings] == [("BGP Prefix Count Changed As Planned", "Stable")]
    assert "+3" in findings[0]["summary"]
    assert PREFIX_DELTA_HEDGE not in findings[0]["summary"]


def test_matching_absolute_count_by_ip_is_stable_with_note():
    entry = _entry("198.51.100.9", expected_prefixes=815)
    entry["note"] = "full table minus bogons"

    findings = bgp_neighbor_findings(_sections(812), _sections(815), [], expectations=[entry])

    assert findings[0]["title"] == "BGP Prefix Count Changed As Planned"
    assert "Note: full table minus bogons" in findings[0]["summary"]


def test_delta_that_differs_from_plan_is_attention():
    findings = bgp_neighbor_findings(_sections(812), _sections(814), [], expectations=[_entry("ISP-B", expected_delta=3)])

    assert [(f["title"], f["impact"]) for f in findings] == [("BGP Prefix Count Differs From Expectation", "Attention")]
    assert "changed by +2, but you planned for a change of +3" in findings[0]["summary"]


def test_delta_with_no_entry_is_unexplained_attention():
    # A file exists but covers a different peer: this delta is unexplained.
    findings = bgp_neighbor_findings(_sections(812), _sections(815), [], expectations=[_entry("ISP-A", expected_delta=3)])

    assert [(f["title"], f["impact"]) for f in findings] == [("BGP Prefix Count Changed Unexpectedly", "Attention")]
    assert PREFIX_DELTA_HEDGE not in findings[0]["summary"]

    # An empty list (file present, nothing for this device) is the same.
    assert bgp_neighbor_findings(_sections(812), _sections(815), [], expectations=[])[0]["impact"] == "Attention"


def test_expected_change_that_did_not_happen_is_attention():
    findings = bgp_neighbor_findings(_sections(812), _sections(812), [], expectations=[_entry("ISP-B", expected_delta=3)])

    assert [(f["title"], f["impact"]) for f in findings] == [("Expected BGP Prefix Change Did Not Happen", "Attention")]

    # An expectation of "no change" or of the count it already has is met.
    assert bgp_neighbor_findings(_sections(812), _sections(812), [], expectations=[_entry("ISP-B", expected_delta=0)]) == []
    assert bgp_neighbor_findings(_sections(812), _sections(812), [], expectations=[_entry("ISP-B", expected_prefixes=812)]) == []


def test_state_change_outranks_the_expectation():
    idle = {"show ip bgp summary": ["  ISP-B  198.51.100.9  4 64497  213  201  0  0  00:01:12  Idle(Admin)"]}

    findings = bgp_neighbor_findings(_sections(812), idle, [], expectations=[_entry("ISP-B", expected_delta=3)])

    assert [f["title"] for f in findings] == ["BGP Peer Shut Down"]


def test_demo_captures_match_the_demo_expectations():
    pre = os.path.join(DEMO, "Precheck", "precheck_2026-04-14_08-48")
    post = os.path.join(DEMO, "Postcheck", "postcheck_2026-04-14_10-42")

    hedged = analyze(pre, post)
    planned = analyze(pre, post, expectations=load_expectations(EXAMPLE_EXPECTATIONS, "NET-DEMO"))

    sw2_hedged = next(r for r in hedged["device_reports"] if r["file_name"] == "SITE-A-SW-2.txt")
    sw2_planned = next(r for r in planned["device_reports"] if r["file_name"] == "SITE-A-SW-2.txt")

    assert [f["title"] for f in sw2_hedged["findings"]] == ["BGP Prefix Count Changed"]
    assert [f["title"] for f in sw2_planned["findings"]] == ["BGP Prefix Count Changed As Planned"]
    assert hedged["expectations_in_play"] is False
    assert planned["expectations_in_play"] is True
    assert planned["expectation_totals"] == {"as_planned": 1, "differs": 0, "unexplained": 0, "not_met": 0}
    # The planned delta no longer counts as Changed.
    assert planned["impact_totals"]["Changed"] == hedged["impact_totals"]["Changed"] - 1


def test_expectations_reach_the_report_header_and_summary(tmp_path):
    pre_run = tmp_path / "Precheck" / "precheck_2026-01-01_00-00"
    post_run = tmp_path / "Postcheck" / "postcheck_2026-01-01_02-00"
    pre_run.mkdir(parents=True)
    post_run.mkdir(parents=True)

    capture = "Hostname: SITE-A-SW-1\n### show ip bgp summary ###\n{a}\n{b}\n"
    (pre_run / "SITE-A-SW-1.txt").write_text(capture.format(
        a=ROW.format(name="ISP-B", ip="198.51.100.9", count=812),
        b=ROW.format(name="ISP-A", ip="198.51.100.1", count=100),
    ))
    (post_run / "SITE-A-SW-1.txt").write_text(capture.format(
        a=ROW.format(name="ISP-B", ip="198.51.100.9", count=815),
        b=ROW.format(name="ISP-A", ip="198.51.100.1", count=99),
    ))

    dirs = {
        "precheck": str(tmp_path / "Precheck"),
        "postcheck": str(tmp_path / "Postcheck"),
        "compare": str(tmp_path / "Compare"),
    }
    report_path = build_html_report(
        "NET-5", dirs, "2026-01-01_02-05", Console(file=io.StringIO()),
        expectations=[_entry("ISP-B", expected_delta=3)], expectations_label="reports/NET-5/expectations.yml",
    )

    with open(report_path, encoding="utf-8") as report:
        content = report.read()

    assert "Expectations: reports/NET-5/expectations.yml" in content
    assert "1 as planned, 0 different from plan, 1 unexplained" in content
    assert "BGP Prefix Count Changed As Planned" in content
    assert "BGP Prefix Count Changed Unexpectedly" in content
    assert 'health-attention">Attention' in content


def test_ticket_dirs_name_the_expectations_file():
    assert ticket_dirs("NET-5")["expectations"].endswith(os.path.join("reports", "NET-5", "expectations.yml"))
