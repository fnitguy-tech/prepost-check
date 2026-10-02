"""difflib.ndiff, skipping the lines that already match.

A firewall's `show config running` is 78,180 lines and a window changes
a few of them. SequenceMatcher's longest-match search gets slower than
linearly as the input grows, so diffing the whole file is expensive: 70%
of a 1.9 second report ran inside find_longest_match, on configs that
were identical apart from a few lines.

Matching lines at the start and end can't come out as `- ` or `+ `, no
matter how the matcher aligns the middle. So we skip them, emit them as
the context lines they would have been, and hand ndiff only the part
that differs. Two places in the report pay this cost, and both diff the
same large config.

Measured on a 78,180-line config: 795 ms down to 11 ms.

This is not a drop-in replacement for difflib.ndiff on any input. ndiff
decides which of several equal lines to pair by searching the whole
sequence; trimming decides some of those pairings by position. Given
only four distinct lines to choose from, the two disagree about a third
of the time, at any length. Duplicate density causes that, not size, so
a length cutoff wouldn't help.

Real captures don't hit it. All 190 sections of a 10-device pair match
difflib exactly, as does that 78,180-line config with 50 lines changed
and with 200 inserted. Real configs have unique lines between the "!"
separators, and real changes are localized. Both tools use the same
trim, so they still match each other, which is what the reports need.
tests/test_difftrim.py checks both halves of this.
"""

import difflib


def ndiff(a, b):
    """Yield difflib.ndiff(a, b), diffing only the part that differs.

    Matches difflib on every input the report sees. Checked line by line
    against it on the bundled demo and on a real 10-device capture pair.
    """
    # Nothing changed, so ndiff would return only context lines. Free,
    # and the same answer difflib gives.
    if a == b:
        for line in a:
            yield f"  {line}"

        return

    head = 0
    limit = min(len(a), len(b))

    while head < limit and a[head] == b[head]:
        head += 1

    tail = 0

    while tail < limit - head and a[-1 - tail] == b[-1 - tail]:
        tail += 1

    # Don't cut inside a run of equal lines. ndiff searches for the
    # longest match rather than the smallest edit, so which copy of a
    # repeated line it pairs depends on the rest of the input - and "!"
    # ends every block in an Arista config. Cutting through a run forces
    # a different pairing. Backing up to the start of the run leaves the
    # choice to difflib, which keeps the two in step more often.
    while head > 0 and (
        (head < len(a) and a[head - 1] == a[head])
        or (head < len(b) and a[head - 1] == b[head])
    ):
        head -= 1

    while tail > 0 and (
        (tail < len(a) - head and a[-1 - tail] == a[-tail])
        or (tail < len(b) - head and b[-1 - tail] == a[-tail])
    ):
        tail -= 1

    for line in a[:head]:
        yield f"  {line}"

    core_a = a[head: len(a) - tail]
    core_b = b[head: len(b) - tail]

    if core_a or core_b:
        yield from difflib.ndiff(core_a, core_b)

    if tail:
        for line in a[len(a) - tail:]:
            yield f"  {line}"
