"""Maintenance notes.

The report says what changed; it cannot say what you meant to do, what
surprised you, or what you only noticed afterwards. The notes file is
that account, written by hand in Markdown and rendered above the
machine findings.

Two behaviours matter more than the formatting. A template nobody filled
in must not pass for a finished write-up, and an existing file must never
be overwritten by a fresh skeleton.
"""

import pytest

from modules import notes

FILLED = """\
# NET-9 - Maintenance Notes

- Precheck: reports/NET-9/Precheck/precheck_2026-01-01_00-00

## What we set out to do

Add the second uplink.

## What we missed

- `seq 60` never landed on SW-2 - the inverse of the gap
  the step existed to close.
- The tool rated it **Stable**.

## Still open

- [ ] chase the cabling
- [x] re-add the entry
"""


def test_an_unfilled_template_renders_nothing():
    """Six empty headings would look like a write-up."""
    template = notes.template("NET-9", "pre", "post", ["SW-1", "SW-2"])

    assert notes.parse(template) != []          # the headings are there
    assert all(not body for _head, body in notes.parse(template))
    assert notes.render_html(template) == ""
    assert notes.open_task_count(template) == 0


def test_the_template_names_the_devices_and_the_runs():
    template = notes.template("NET-9", "pre/run-a", "post/run-b", ["SW-2", "SW-1"])

    assert "# NET-9 - Maintenance Notes" in template
    assert "- Precheck: pre/run-a" in template
    assert "- Postcheck: post/run-b" in template
    # Sorted, and counted, so a missing device is obvious at a glance.
    assert "- Devices (2): SW-1, SW-2" in template
    for heading, _prompt in notes.TEMPLATE_SECTIONS:
        assert f"## {heading}" in template


def test_write_template_never_overwrites_existing_notes(tmp_path):
    """Half-finished notes are more use than a fresh skeleton."""
    path = tmp_path / "notes.md"

    assert notes.write_template(str(path), "NET-9", "pre", "post", ["SW-1"]) is True
    path.write_text("# mine\n\n## What we missed\n\nthe cable.\n", encoding="utf-8")

    assert notes.write_template(str(path), "NET-9", "pre", "post", ["SW-1"]) is False
    assert path.read_text(encoding="utf-8") == "# mine\n\n## What we missed\n\nthe cable.\n"


def test_load_returns_none_when_there_is_no_file(tmp_path):
    assert notes.load(str(tmp_path / "absent.md")) is None
    assert notes.load(None) is None


def test_only_sections_with_content_are_rendered():
    html = notes.render_html(FILLED)

    assert "<h3>What we set out to do</h3>" in html
    assert "<h3>What we missed</h3>" in html
    assert "<h3>Still open</h3>" in html
    # "What actually happened" is not in FILLED at all.
    assert "What actually happened" not in html
    # The seeded header is dropped: the report shows the runs in its own pills.
    assert "Precheck: reports/NET-9" not in html


def test_a_wrapped_bullet_stays_one_bullet():
    """Markdown writers wrap. Without continuation lines, a wrapped bullet
    came out as a bullet plus a stray paragraph holding the rest of its
    sentence."""
    html = notes.render_html(FILLED)

    assert "the inverse of the gap the step existed to close." in html
    assert html.count("<li>") == 2        # two bullets under "What we missed"
    assert "<p>the step existed to close" not in html


def test_checkboxes_carry_their_state_and_are_counted():
    html = notes.render_html(FILLED)

    assert '<span class="notes-box">[ ]</span> chase the cabling' in html
    assert '<span class="notes-box">[x]</span> re-add the entry' in html
    assert "notes-open" in html and "notes-done" in html
    assert notes.open_task_count(FILLED) == 1


def test_inline_code_and_bold_survive_escaping():
    html = notes.render_html(FILLED)

    assert "<code>seq 60</code>" in html
    assert "<strong>Stable</strong>" in html


@pytest.mark.parametrize("hostile", [
    "- <img src=x onerror=alert(1)>",
    "- [ ] <b>not bold</b> & raw",
    "<script>alert(1)</script>",
])
def test_notes_are_escaped(hostile):
    """The notes are a file on disk, but they still end up in a page that
    gets attached to a ticket and opened in a browser.

    The payloads survive as visible text, which is the point - every
    angle bracket is escaped, so nothing in them is markup any more.
    """
    html = notes.render_html(f"## Heading\n\n{hostile}\n")

    for tag in ("<script", "<img", "<b>"):
        assert tag not in html

    assert "&lt;" in html


def test_a_heading_with_no_body_is_dropped_entirely():
    """A hostile heading cannot reach the page on its own: a section with
    nothing under it is left out, heading and all."""
    assert notes.render_html("## <script>alert(1)</script>\n") == ""


def test_prompts_and_comments_are_dropped():
    html = notes.render_html(
        "## What we missed\n\n<!-- found after the fact -->\nthe cable.\n"
    )

    assert "found after the fact" not in html
    assert "<p>the cable.</p>" in html


def test_a_line_ending_in_an_arrow_is_text_not_a_comment():
    html = notes.render_html(
        "## What actually happened\n\nEt49/1 went down --> traffic moved to Et50/1\n- [ ] ops - recheck A --> B\n"
    )

    assert "<p>Et49/1 went down --&gt; traffic moved to Et50/1</p>" in html
    assert "recheck A --&gt; B" in html
    assert notes.open_task_count("## Still open\n\n- [ ] ops - recheck A --> B\n") == 1


def test_a_comment_spanning_lines_is_dropped_whole():
    html = notes.render_html(
        "## What we missed\n\n<!-- note to self:\n     ask about the\n     spare optic -->\nthe cable.\n"
    )

    assert "note to self" not in html
    assert "ask about" not in html
    assert "spare optic" not in html
    assert "<p>the cable.</p>" in html


def test_the_template_still_renders_nothing_until_it_is_filled_in():
    # Its own two-line prompt comment ends in "-->" on the second line.
    assert notes.render_html(notes.template("NET-1", "pre", "post", ["SW-1"])) == ""


def test_a_notes_file_that_cannot_be_read_says_so(tmp_path):
    unreadable = tmp_path / "notes.md"
    unreadable.write_bytes(b"## What we missed\n\n\xff\xfe not utf-8\n")

    with pytest.raises(notes.NotesError) as excinfo:
        notes.load(str(unreadable))

    assert "exists but couldn't be read" in str(excinfo.value)

    # A folder where the file should be: also "can't read", not "no notes".
    (tmp_path / "dir.md").mkdir()

    with pytest.raises(notes.NotesError):
        notes.load(str(tmp_path / "dir.md"))
