"""Maintenance notes: the engineer's account of the window.

The report says what changed. It cannot say why you changed it, what
surprised you, or what you only noticed afterwards - and that is the
part a reader needs most when they pick the ticket up a month later.

So the notes are written by hand, in Markdown, and rendered into the
top of the HTML report above the machine findings. One file, two uses:
attached to the ticket inside the report, and shareable on its own.

    reports/<TICKET>/notes.md     (scripts/notes.py writes the template)

The template is seeded with what the tool already knows: the ticket, the
window times, and the devices it captured. That leaves only the
judgement to type. An empty section renders as nothing, and a template
with nothing filled in renders no notes block at all - the console says
so, so a blank skeleton can't pass for a finished write-up.

The Markdown subset is tiny, because the Rust port has to produce
byte-identical HTML from the same file:

    ## Heading          a section heading
    - item              a bullet
    - [ ] item          an open checkbox
    - [x] item          a ticked checkbox
    `code`              inline code
    **bold**            inline bold
    <!-- comment -->    dropped (the template's own prompts); a comment
                        may run over several lines, and has to start
                        its line

Anything else is a paragraph. There is no nesting, no tables, and no
links; a line that looks like one of those is shown as written.
"""

import html
import os
import re

# The questions worth answering after a window, in the order a reader
# wants them: what you meant to do, what happened, what you missed,
# what is still open, what you would change.
TEMPLATE_SECTIONS = [
    ("What we set out to do", "the change in one or two sentences, and why"),
    ("What actually happened", "deviations from the plan, surprises, anything re-run"),
    ("What we missed", "found after the fact - what it was, and how it got past the checks"),
    ("Still open", "one '- [ ] owner - item' per line"),
    ("Would do differently", "what to change in the MOP or the checks next time"),
]

HEADING = re.compile(r"^##\s+(.*\S)\s*$")
TASK = re.compile(r"^-\s+\[([ xX])\]\s+(.*\S)\s*$")
BULLET = re.compile(r"^-\s+(.*\S)\s*$")
COMMENT_OPEN = "<!--"
COMMENT_CLOSE = "-->"
CODE_SPAN = re.compile(r"`([^`]+)`")
BOLD_SPAN = re.compile(r"\*\*([^*]+)\*\*")


def template(ticket, precheck_label, postcheck_label, hostnames):
    """The seeded notes template for one ticket, as Markdown text."""
    devices = ", ".join(sorted(hostnames)) if hostnames else "none captured yet"
    lines = [
        f"# {ticket} - Maintenance Notes",
        "",
        f"- Precheck: {precheck_label}",
        f"- Postcheck: {postcheck_label}",
        f"- Devices ({len(hostnames)}): {devices}",
        "",
        "<!-- Written by hand. Delete the prompts as you answer them; a section",
        "     left empty is left out of the report. -->",
        "",
    ]

    for heading, prompt in TEMPLATE_SECTIONS:
        lines += [f"## {heading}", "", f"<!-- {prompt} -->", ""]

    return "\n".join(lines).rstrip("\n") + "\n"


def write_template(path, ticket, precheck_label, postcheck_label, hostnames):
    """Write the template, refusing to overwrite notes that already exist.

    Returns True when it wrote the file, False when one was already
    there. It never overwrites: half-finished notes are more use than a
    fresh skeleton.
    """
    if os.path.exists(path):
        return False

    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w", encoding="utf-8") as file:
        file.write(template(ticket, precheck_label, postcheck_label, hostnames))

    return True


class NotesError(Exception):
    """Raised when a notes file exists but can't be read."""


def load(path):
    """The notes file's text, or None when there is no file to read.

    A file that's there but can't be read raises NotesError. "No notes"
    and "your notes couldn't be opened" call for different fixes, so
    they must not print the same message. Example: a notes.md saved by
    another user with no read permission for you.
    """
    if not path or not os.path.exists(path):
        return None

    try:
        with open(path, "r", encoding="utf-8") as file:
            return file.read()
    except (OSError, UnicodeDecodeError) as error:
        reason = error.strerror if isinstance(error, OSError) and error.strerror else "it isn't UTF-8 text"
        raise NotesError(f"The notes file {path} exists but couldn't be read ({reason}).") from error


def parse(text):
    """Split notes Markdown into [(heading, [block, ...])], prompts dropped.

    Content before the first '## ' heading is the seeded header, which
    the report already shows in its own meta pills, so it is dropped.
    A heading whose body is only prompts comes back with no blocks.
    """
    sections = []
    heading = None
    blocks = []
    paragraph = []
    items = []

    def close_paragraph():
        if paragraph:
            blocks.append(("p", [" ".join(paragraph)]))
            paragraph.clear()

    def close_items():
        if items:
            blocks.append(("ul", list(items)))
            items.clear()

    def close_heading():
        close_paragraph()
        close_items()

        if heading is not None:
            sections.append((heading, list(blocks)))

        blocks.clear()

    # True while inside a comment that opened on an earlier line.
    in_comment = False

    for raw in text.splitlines():
        line = raw.rstrip()

        # A comment is dropped only when it really is one: it starts its
        # line with "<!--" and runs to the next "-->", on that line or a
        # later one. The template's own prompt spans two lines, so the
        # state is carried across lines. A line that merely ends in "-->"
        # is the writer's text ("Et49/1 down --> failover") and is kept;
        # it used to vanish from the report without a word.
        if in_comment or line.lstrip().startswith(COMMENT_OPEN):
            body = line if in_comment else line.lstrip()[len(COMMENT_OPEN):]
            in_comment = COMMENT_CLOSE not in body
            continue

        match = HEADING.match(line)

        if match:
            close_heading()
            heading = match.group(1)
            continue

        if not line.strip():
            close_paragraph()
            close_items()
            continue

        task = TASK.match(line)

        if task:
            close_paragraph()
            items.append(("task", task.group(1).lower() == "x", task.group(2)))
            continue

        bullet = BULLET.match(line)

        if bullet:
            close_paragraph()
            items.append(("plain", False, bullet.group(1)))
            continue

        # An indented line under a list item continues it. Markdown
        # writers wrap, and without this a wrapped bullet came out as a
        # bullet plus a stray paragraph holding the rest of its sentence.
        if items and line[:1].isspace():
            kind, done, text = items[-1]
            items[-1] = (kind, done, f"{text} {line.strip()}")
            continue

        close_items()
        paragraph.append(line.strip())

    close_heading()

    return [(head, body) for head, body in sections]


def inline_html(text):
    """Escape one line, then re-apply the two inline spans we support."""
    escaped = html.escape(text)
    escaped = CODE_SPAN.sub(lambda m: f"<code>{m.group(1)}</code>", escaped)

    return BOLD_SPAN.sub(lambda m: f"<strong>{m.group(1)}</strong>", escaped)


def render_html(text):
    """The notes as an HTML block, or "" when nothing has been filled in."""
    sections = [(head, body) for head, body in parse(text) if body]

    if not sections:
        return ""

    parts = ['<div id="maintenance-notes" class="notes-card">', "        <h2>Maintenance Notes</h2>"]

    for heading, blocks in sections:
        parts.append(f"        <h3>{inline_html(heading)}</h3>")

        for kind, body in blocks:
            if kind == "p":
                parts.append(f"        <p>{inline_html(body[0])}</p>")
                continue

            parts.append('        <ul class="notes-list">')

            for item_kind, done, item_text in body:
                if item_kind == "task":
                    box = "[x]" if done else "[ ]"
                    state = "done" if done else "open"
                    parts.append(
                        f'            <li class="notes-task notes-{state}">'
                        f'<span class="notes-box">{box}</span> {inline_html(item_text)}</li>'
                    )
                else:
                    parts.append(f"            <li>{inline_html(item_text)}</li>")

            parts.append("        </ul>")

    parts.append("    </div>")

    return "\n".join(parts)


def open_task_count(text):
    """How many '- [ ]' items are still open, for the report's summary."""
    return sum(
        1
        for _heading, blocks in parse(text)
        for kind, body in blocks
        if kind == "ul"
        for item_kind, done, _item in body
        if item_kind == "task" and not done
    )
