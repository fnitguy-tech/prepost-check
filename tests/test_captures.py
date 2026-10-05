"""Capture folders: section headers, failed and missing devices, and
the checks on whether a pair of folders can be trusted."""

import io
import os

from rich.console import Console

from modules import captures, htmlreport, textcompare
from modules.captures import SECTION_RULE, section_header

BGP_ROW = "SPINE1 203.0.113.1 4 65001 12345 12340 0 0 5d02h Estab 100 98"


def capture(hostname, address, config_lines=("hostname x",)):
    return (
        f"Hostname: {hostname}\nIP Address: {address}\nGenerated: 2026-01-01 00:00:00\n" + "=" * 80 + "\n"
        "\n\n" + section_header("show ip bgp summary") + BGP_ROW + "\n"
        "\n\n" + section_header("show running-config") + "\n".join(config_lines) + "\n"
    )


def folders(tmp_path, pre="precheck_2026-01-01_00-00", post="postcheck_2026-01-01_02-00", complete=True):
    pre_run = tmp_path / "Precheck" / pre
    post_run = tmp_path / "Postcheck" / post
    pre_run.mkdir(parents=True)
    post_run.mkdir(parents=True)

    if complete:
        captures.write_complete_marker(str(pre_run), "precheck", {"devices": 1})
        captures.write_complete_marker(str(post_run), "postcheck", {"devices": 1})

    dirs = {
        "precheck": str(tmp_path / "Precheck"),
        "postcheck": str(tmp_path / "Postcheck"),
        "compare": str(tmp_path / "Compare"),
    }

    return pre_run, post_run, dirs


def build_both(dirs):
    """Both reports and what each printed: (text, text console, html, html console)."""
    text_console = Console(file=io.StringIO(), width=300)
    html_console = Console(file=io.StringIO(), width=300)
    text_path = textcompare.write_compare_report("NET-1", dirs, "2026-01-01_02-05-00", text_console)
    html_path = htmlreport.build_html_report("NET-1", dirs, "2026-01-01_02-05-00", html_console)

    with open(text_path, encoding="utf-8") as file:
        text = file.read()

    with open(html_path, encoding="utf-8") as file:
        page = file.read()

    return text, text_console.file.getvalue(), page, html_console.file.getvalue()


# --- fix 6: section headers -------------------------------------------


def test_a_banner_line_inside_a_config_does_not_start_a_section(tmp_path):
    config = ["hostname SW-1", "banner login", "### AUTHORIZED USE ONLY ###", "EOF", "router bgp 65001"]
    path = tmp_path / "SW-1.txt"
    path.write_text(capture("SW-1", "10.0.0.1", config))

    for parse in (captures.read_sections, htmlreport.parse_sections, textcompare.parse_sections):
        sections = parse(str(path))

        assert list(sections) == ["HEADER", "show ip bgp summary", "show running-config"], parse
        assert sections["show running-config"][0] == SECTION_RULE
        assert "### AUTHORIZED USE ONLY ###" in sections["show running-config"]
        assert "router bgp 65001" in sections["show running-config"]


def test_a_header_needs_the_dash_rule_right_under_it(tmp_path):
    path = tmp_path / "x.txt"
    path.write_text("### show a ###\n" + SECTION_RULE + "\nA\n### show b ###\nnot a rule\n### show c ###")

    sections = captures.read_sections(str(path))

    assert list(sections) == ["HEADER", "show a"]
    assert sections["show a"] == [SECTION_RULE, "A", "### show b ###", "not a rule", "### show c ###"]


# --- fix 1: failed and missing devices --------------------------------


def test_a_device_unreachable_after_the_change_is_loud_in_both_reports(tmp_path):
    pre_run, post_run, dirs = folders(tmp_path)
    (pre_run / "SW-1.txt").write_text(capture("SW-1", "10.0.0.5"))
    (pre_run / "SW-2.txt").write_text(capture("SW-2", "10.0.0.6"))
    (post_run / "SW-2.txt").write_text(capture("SW-2", "10.0.0.6"))
    captures.write_failed(
        str(post_run),
        "10.0.0.5",
        captures.FAILED_FIRST_LINE,
        "TCP connection to device failed.\n\nDevice settings: arista_eos 10.0.0.5:22\n",
    )

    analysis = htmlreport.analyze(str(pre_run), str(post_run))
    text, text_console, page, html_console = build_both(dirs)

    # Without the fix: SW-2 is unchanged, SW-1 vanishes, verdict "Stable".
    assert analysis["window_totals"]["Action Required"] == 1
    assert analysis["common_files"] == ["SW-2.txt"]
    assert analysis["device_reports"][0]["file_name"] == "SW-1.txt"

    assert '<div class="value health-action-required">Action Required</div>' in page
    assert '<div class="label">Devices Checked</div><div class="value">2</div>' in page
    assert "Devices Not Verified" in page
    assert "Device unreachable after the change" in page
    assert "TCP connection to device failed." in page
    assert "Device settings: arista_eos 10.0.0.5:22" in page
    assert "1 device(s) couldn&#x27;t be verified" in page
    # At the top: before the summary cards.
    assert page.index('id="device-problems"') < page.index('<div class="cards">')

    assert "ACTION REQUIRED: 1 device(s) could not be verified" in text
    assert "! SW-1 (10.0.0.5): Device unreachable after the change" in text
    assert "    | TCP connection to device failed." in text
    assert text.index("ACTION REQUIRED") < text.index("Device/File: SW-2.txt")

    for printed in (text_console, html_console):
        assert "ACTION REQUIRED: 1 device(s) could not be verified: SW-1" in printed


def test_every_kind_of_missing_or_failed_device_is_reported(tmp_path):
    pre_run, post_run, _dirs = folders(tmp_path)
    (pre_run / "GONE.txt").write_text(capture("GONE", "10.0.0.1"))
    (post_run / "NEW.txt").write_text(capture("NEW", "10.0.0.2"))
    (post_run / "LATE.txt").write_text(capture("LATE", "10.0.0.3"))
    captures.write_failed(str(pre_run), "10.0.0.3", captures.FAILED_FIRST_LINE, "timed out\n")
    captures.write_failed(str(pre_run), "10.0.0.4", captures.FAILED_FIRST_LINE, "timed out\n")
    captures.write_failed(str(post_run), "10.0.0.4", captures.FAILED_FIRST_LINE, "timed out again\n")
    captures.write_failed(str(post_run), "10.0.0.9", captures.NOT_ATTEMPTED_FIRST_LINE, "Not tried.\n")

    common, problems = captures.device_problems(str(pre_run), str(post_run))
    titles = {problem["name"]: problem["title"] for problem in problems}

    assert common == []
    assert titles == {
        "GONE": "Device missing after the change",
        "NEW": "Device only in the after capture",
        "LATE": "Device unreachable before the change",
        "10.0.0.4": "Device unreachable before and after the change",
        "10.0.0.9": "Device not attempted after the change",
    }

    analysis = htmlreport.analyze(str(pre_run), str(post_run))

    assert analysis["window_totals"]["Action Required"] == 5
    assert all(finding["impact"] == "Action Required" for finding in analysis["device_problems"])


def test_with_no_problem_devices_nothing_is_added(tmp_path):
    pre_run, post_run, dirs = folders(tmp_path)
    (pre_run / "SW-1.txt").write_text(capture("SW-1", "10.0.0.5"))
    (post_run / "SW-1.txt").write_text(capture("SW-1", "10.0.0.5"))

    text, text_console, page, html_console = build_both(dirs)

    assert "Devices Not Verified" not in page
    assert "ACTION REQUIRED" not in text + text_console + html_console
    assert "WARNING" not in text + text_console + html_console
    assert "Warning</h2>" not in page
    assert '<div class="value health-stable">Stable</div>' in page


# --- fix 8: baseline sanity -------------------------------------------


def test_a_before_capture_newer_than_the_after_capture_is_called_out(tmp_path):
    pre_run, post_run, dirs = folders(
        tmp_path, pre="precheck_2026-01-01_10-40-00", post="postcheck_2026-01-01_08-50-00"
    )
    (pre_run / "SW-1.txt").write_text(capture("SW-1", "10.0.0.5"))
    (post_run / "SW-1.txt").write_text(capture("SW-1", "10.0.0.5"))

    text, text_console, page, html_console = build_both(dirs)
    warning = "The before capture is newer than the after capture. Did you run before again by mistake?"

    assert f"WARNING: {warning}" in text
    assert text.index("WARNING") < text.index("File Summary")
    assert f"<h2>Warning</h2><p>{warning}</p>" in page
    assert page.index("<h2>Warning</h2>") < page.index('<div class="cards">')
    assert f"WARNING: {warning}" in text_console
    assert f"WARNING: {warning}" in html_console


def test_run_stamps_compare_across_the_old_and_new_formats():
    assert captures.run_stamp("/x/precheck_2026-04-14_08-48") == "2026-04-14_08-48-00"
    assert captures.run_stamp("/x/precheck_2026-04-14_08-48-05/") == "2026-04-14_08-48-05"
    assert captures.run_stamp("/x/precheck_custom") is None
    # Same minute, old and new format: not "newer".
    warnings, _notes = captures.baseline_warnings("/x/precheck_2026-04-14_08-48", "/x/postcheck_2026-04-14_08-48-30")
    assert captures.NEWER_BASELINE_WARNING not in warnings


def test_a_run_without_its_marker_is_an_interrupted_baseline(tmp_path):
    pre_run, post_run, dirs = folders(tmp_path, pre="precheck_2026-01-01_00-00-07", complete=False)
    captures.write_complete_marker(str(post_run), "postcheck", {"devices": 1})
    (pre_run / "SW-1.txt").write_text(capture("SW-1", "10.0.0.5"))
    (post_run / "SW-1.txt").write_text(capture("SW-1", "10.0.0.5"))

    text, text_console, page, html_console = build_both(dirs)
    warning = "The before capture (precheck_2026-01-01_00-00-07) didn&#x27;t finish."

    assert warning in page
    assert warning.replace("&#x27;", "'") in text
    assert "didn't finish" in text_console and "didn't finish" in html_console
    # The marker is not a device.
    assert '<div class="label">Devices Checked</div><div class="value">1</div>' in page
    assert "Common files: 1" in text


def test_an_older_folder_without_a_marker_still_compares_with_only_a_note(tmp_path):
    # Minute-resolution names are what older versions (and the bundled
    # demo captures) use; they never had markers.
    pre_run, post_run, dirs = folders(tmp_path, complete=False)
    (pre_run / "SW-1.txt").write_text(capture("SW-1", "10.0.0.5"))
    (post_run / "SW-1.txt").write_text(capture("SW-1", "10.0.0.5"))

    text, text_console, page, html_console = build_both(dirs)

    assert "WARNING" not in text and "Warning</h2>" not in page
    assert "Note: The before capture (precheck_2026-01-01_00-00) has no completion marker." in text_console
    assert "Note: The after capture (postcheck_2026-01-01_02-00) has no completion marker." in html_console
    assert os.path.exists(os.path.join(dirs["compare"], "compare_2026-01-01_02-05-00.html"))
