"""History across windows.

reports/ already keeps every window forever. What was missing is a way to
look across them: list what you have run, and compare any two capture runs
even when they belong to different tickets.

The behaviour worth protecting is the direction check. The interpreted
layer reads the BGP Up/Down timer on the rule that the postcheck is the
later capture, so handing it two runs backwards turns every healthy
long-lived session into a reset.
"""

import pytest

from modules import history

CAPTURE = """\
Hostname: {host}
### show ip bgp summary ###
  Description              Neighbor      V AS           MsgRcvd   MsgSent  InQ OutQ  Up/Down State   PfxRcd PfxAcc
  ISP-A                    10.0.0.1      4 64500          10        10       0    0   {updown} Estab   {pfx}      {pfx}
### show running-config ###
hostname {host}
"""


def write_run(reports_dir, ticket, phase, stamp, hosts, updown="30d20h", pfx="100", failed=()):
    folder = reports_dir / ticket / phase.capitalize() / f"{phase}_{stamp}"
    folder.mkdir(parents=True, exist_ok=True)

    for host in hosts:
        (folder / f"{host}.txt").write_text(
            CAPTURE.format(host=host, updown=updown, pfx=pfx), encoding="utf-8"
        )

    for host in failed:
        (folder / f"{host}_FAILED.txt").write_text(f"FAILED TO CONNECT TO {host}\n", encoding="utf-8")

    return folder


def test_scan_lists_tickets_newest_first(tmp_path):
    write_run(tmp_path, "NET-1", "precheck", "2026-01-01_00-00", ["SW-1"])
    write_run(tmp_path, "NET-1", "postcheck", "2026-01-01_02-00", ["SW-1"])
    write_run(tmp_path, "NET-9", "precheck", "2026-03-01_00-00", ["SW-1", "SW-2"])

    tickets = history.scan(str(tmp_path))

    assert [entry["ticket"] for entry in tickets] == ["NET-9", "NET-1"]
    assert tickets[0]["device_count"] == 2
    assert tickets[1]["latest"] == "2026-01-01_02-00"
    assert [run["phase"] for run in tickets[1]["runs"]] == ["postcheck", "precheck"]


def test_a_failed_device_is_listed_as_failed_not_captured(tmp_path):
    """An unreachable device is evidence, but it isn't a device you captured."""
    write_run(tmp_path, "NET-1", "precheck", "2026-01-01_00-00", ["SW-1"], failed=["10.0.0.9"])

    run = history.scan(str(tmp_path))[0]["runs"][0]

    assert run["devices"] == ["SW-1"]
    assert run["failed"] == ["10.0.0.9"]


def test_a_zip_beside_a_run_is_not_a_second_run(tmp_path):
    folder = write_run(tmp_path, "NET-1", "precheck", "2026-01-01_00-00", ["SW-1"])
    (folder.parent / "precheck_2026-01-01_00-00.zip").write_bytes(b"")
    (folder.parent / "not-a-run").mkdir()

    runs = history.scan(str(tmp_path))[0]["runs"]

    assert len(runs) == 1
    assert runs[0]["zip"] is True


def test_all_runs_spans_tickets_for_the_pick_list(tmp_path):
    write_run(tmp_path, "NET-1", "postcheck", "2026-01-01_02-00", ["SW-1"])
    write_run(tmp_path, "NET-9", "precheck", "2026-03-01_00-00", ["SW-1"])

    runs = history.all_runs(str(tmp_path))

    assert [(run["ticket"], run["phase"]) for run in runs] == [
        ("NET-9", "precheck"),
        ("NET-1", "postcheck"),
    ]
    assert history.find_run(str(tmp_path), "NET-1", "postcheck", "2026-01-01_02-00") is not None
    assert history.find_run(str(tmp_path), "NET-1", "postcheck", "nope") is None


def test_comparing_two_runs_backwards_is_refused(tmp_path):
    """The uptime rule assumes the second capture is the later one.

    Reversed, a session that never dropped reads as one that reset, and the
    report fills with findings that are all wrong. Better to refuse and say
    which way round it goes.
    """
    write_run(tmp_path, "NET-1", "postcheck", "2026-03-01_02-00", ["SW-1"])
    write_run(tmp_path, "NET-9", "precheck", "2026-01-01_00-00", ["SW-1"])

    later = history.find_run(str(tmp_path), "NET-1", "postcheck", "2026-03-01_02-00")
    earlier = history.find_run(str(tmp_path), "NET-9", "precheck", "2026-01-01_00-00")

    assert history.in_order(earlier, later) is True
    assert history.in_order(later, earlier) is False

    with pytest.raises(history.ReversedRuns) as raised:
        history.compare_runs(later, earlier, reports_dir=str(tmp_path))

    assert "Swap them" in str(raised.value)

    # Explicit override still works, for the case you really meant it.
    assert history.compare_runs(later, earlier, reports_dir=str(tmp_path), allow_reversed=True)


def test_comparing_across_tickets_writes_a_report(tmp_path):
    """The question the per-window report cannot answer: did the fix hold?

    NET-1 left the peer at 100 prefixes. Two months later NET-9's precheck
    finds 53, so something undid it between windows - which is only visible
    by comparing one window's postcheck against another window's precheck.
    """
    write_run(tmp_path, "NET-1", "postcheck", "2026-01-01_02-00", ["SW-1"], pfx="100")
    write_run(tmp_path, "NET-9", "precheck", "2026-03-01_00-00", ["SW-1"], pfx="53")

    before = history.find_run(str(tmp_path), "NET-1", "postcheck", "2026-01-01_02-00")
    after = history.find_run(str(tmp_path), "NET-9", "precheck", "2026-03-01_00-00")

    path = history.compare_runs(before, after, reports_dir=str(tmp_path), stamp="2026-03-01_00-05")
    with open(path, encoding="utf-8") as handle:
        page = handle.read()

    assert history.COMPARISONS_DIRNAME in path
    assert "NET-1-postcheck-2026-01-01_02-00__vs__NET-9-precheck-2026-03-01_00-00" in path
    # Both tickets are named, because this comparison belongs to neither.
    assert "NET-1 vs NET-9" in page
    assert "Prefix Count Changed" in page
    assert "-47" in page

    listed = history.comparisons(str(tmp_path))
    assert len(listed) == 1
    assert listed[0]["path"] == path


def test_the_comparisons_folder_is_not_a_ticket(tmp_path):
    write_run(tmp_path, "NET-1", "precheck", "2026-01-01_00-00", ["SW-1"])
    (tmp_path / history.COMPARISONS_DIRNAME).mkdir()

    assert [entry["ticket"] for entry in history.scan(str(tmp_path))] == ["NET-1"]


def test_an_empty_or_absent_reports_tree_is_not_an_error(tmp_path):
    assert history.scan(str(tmp_path / "absent")) == []
    assert history.all_runs(str(tmp_path)) == []
    assert history.comparisons(str(tmp_path)) == []


def test_a_malformed_run_timestamp_does_not_crash_the_scan(tmp_path):
    write_run(tmp_path, "NET-1", "precheck", "2026-01-01_00-00", ["SW-1"])
    (tmp_path / "NET-1" / "Precheck" / "precheck_not-a-date").mkdir()

    runs = history.scan(str(tmp_path))[0]["runs"]

    assert len(runs) == 1
    assert history.parse_run_timestamp("not-a-date") is None
