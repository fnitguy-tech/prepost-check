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

Real captures do hit it, rarely and cosmetically. On the bundled demo a
`+ !` line moved two places among the other additions in a config diff.
Nothing was added or removed that wasn't before; only where a repeated
line sits among its siblings changed. The 190 sections of a 10-device
pair all matched difflib exactly, but those configs were identical
pre/post, so the trim short-circuited and never reached the ambiguous
path - that run proved less than it looked like it did.

Both tools run the same trim and produce the same 48 diff lines in the
same order, which is the parity the reports rest on.
tests/test_difftrim.py checks both halves of this.

One more guard: a size cap on difflib's "fancy replace". When a block of
lines is replaced by another block, difflib scores every old line
against every new line to find the closest pair, lines up on it, then
does the same again on each side. A block of 5,000 changed lines is 25
million scores for the first pass alone, and the run takes minutes (or
ends in a RecursionError). See FANCY_REPLACE_MAX_PAIRS below.
"""

import difflib

# The most line pairs difflib may score for one replaced block:
# (old lines in the block) x (new lines in the block). Above it, the
# block is written the plain way: every "-" line, then every "+" line
# (the shorter side goes first, which is difflib's own rule).
#
# Worked example: 200 old lines replaced by 200 new ones is 40,000
# pairs, which is at the cap and still gets the fancy treatment. 200
# replaced by 201 is 40,200 pairs and is written plain.
#
# Why 40,000: the largest replaced block in the bundled demo is 4 pairs,
# so the demo report comes out byte-for-byte the same. A block at the
# cap (200 x 200 similar config lines) takes about 0.8 seconds on
# Python 3.12; 300 x 300 already takes over 2.
#
# Nothing is lost above the cap. Both reports keep only the "-" and "+"
# lines, so the same lines appear either way; only their order within
# the block changes, from interleaved pairs to removed-then-added.
FANCY_REPLACE_MAX_PAIRS = 40_000


class _CappedDiffer(difflib.Differ):
    """difflib.Differ with the size cap above on its fancy replace.

    difflib offers no public switch for this, so the cap hooks the two
    methods Differ.compare() itself calls for a replaced block. Both
    have had the same signature since Python 3.0;
    tests/test_difftrim.py fails loudly if a future Python renames them.
    """

    def _fancy_replace(self, a, alo, ahi, b, blo, bhi):
        if (ahi - alo) * (bhi - blo) > FANCY_REPLACE_MAX_PAIRS:
            yield from self._plain_replace(a, alo, ahi, b, blo, bhi)
        else:
            yield from super()._fancy_replace(a, alo, ahi, b, blo, bhi)


def _capped_ndiff(a, b):
    """difflib.ndiff(a, b) with the fancy-replace cap. Same defaults as
    ndiff: no line junk, IS_CHARACTER_JUNK for the in-line hints."""
    return _CappedDiffer(None, difflib.IS_CHARACTER_JUNK).compare(a, b)


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
        yield from _capped_ndiff(core_a, core_b)

    if tail:
        for line in a[len(a) - tail:]:
            yield f"  {line}"
