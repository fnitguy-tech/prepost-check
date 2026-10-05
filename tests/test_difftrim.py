"""Trimming the diff.

A firewall's `show config running` is 78,180 lines and a window changes a
handful of them, but SequenceMatcher's longest-match recursion is
superlinear in its input: 70% of a real report's 1.9 s ran inside
find_longest_match, over configs that were identical apart from a few
lines.

The lines at the start and end that already match cannot become a `- ` or
a `+ `, so they are skipped and re-emitted as the context lines they
would have been. These tests exist to hold the one property that makes
that safe: the stream a caller sees is the stream difflib would have
produced.
"""

import difflib
import random
import time

import pytest

from modules import difftrim

CONFIG = [
    "router bgp 64500",
    "   router-id 10.0.0.1",
    "   neighbor 10.0.0.2 peer group ISP",
    "   neighbor 10.0.0.2 maximum-routes 12000",
    "!",
    "ip prefix-list ISP-OUT",
    "   seq 10 permit 203.0.113.0/24",
    "   seq 20 permit 198.51.100.0/24",
    "!",
    "interface Ethernet1",
    "   description uplink",
]


def assert_same_as_difflib(a, b):
    assert list(difftrim.ndiff(a, b)) == list(difflib.ndiff(a, b))


@pytest.mark.parametrize("a, b", [
    ([], []),
    ([], ["only in b"]),
    (["only in a"], []),
    (["same"], ["same"]),
    (CONFIG, CONFIG),                                          # nothing changed
    (CONFIG, CONFIG[:6] + ["   seq 15 permit 10.0.0.0/8"] + CONFIG[6:]),   # insert
    (CONFIG, CONFIG[:3] + CONFIG[4:]),                         # delete
    (CONFIG[:-1], CONFIG[:-1] + ["   mtu 9214"]),              # append at the tail
    (["x"] + CONFIG, CONFIG),                                  # change at the head
    (CONFIG, list(reversed(CONFIG))),                          # nothing in common order
    (["a", "b", "a", "b"], ["b", "a", "b", "a"]),              # repeats
])
def test_matches_difflib_exactly(a, b):
    assert_same_as_difflib(a, b)


def test_matches_difflib_on_a_large_config_with_one_changed_line():
    """The case this exists for: a big file, one line different."""
    big = [f"   seq {n} permit 10.{n // 256}.{n % 256}.0/24" for n in range(4000)]
    pre = ["ip prefix-list BIG"] + big + ["!"]
    post = ["ip prefix-list BIG"] + big[:2000] + ["   seq 9999 permit 0.0.0.0/0"] + big[2001:] + ["!"]

    assert_same_as_difflib(pre, post)


def test_matches_difflib_on_config_shaped_edits():
    """Fuzz the shapes a real capture actually has: mostly-unique lines,
    a handful of localised edits."""
    rng = random.Random(20261002)

    for _ in range(200):
        size = rng.randint(0, 60)
        a = [f"        setting-{rng.randint(0, 400)} value-{rng.randint(0, 400)};" for _ in range(size)]
        b = list(a)

        for _ in range(rng.randint(0, 4)):
            action = rng.choice(["insert", "delete", "replace"])

            if action == "insert" or not b:
                b.insert(rng.randint(0, len(b)), f"        new-{rng.randint(0, 99)} yes;")
            elif action == "delete":
                del b[rng.randint(0, len(b) - 1)]
            else:
                b[rng.randint(0, len(b) - 1)] = f"        changed-{rng.randint(0, 99)} no;"

        assert_same_as_difflib(a, b)


def test_the_known_divergence_is_recorded_not_hidden():
    """Where this differs from difflib.

    ndiff decides which of several equal lines to pair by searching the
    whole sequence; trimming decides some of those pairings by position.
    Given only four distinct lines to choose from, the two disagree about
    a third of the time, at any length. Duplicate density causes that,
    not size, so a length cutoff wouldn't help.

    Real captures do hit it, rarely and cosmetically. On the bundled
    demo a "+ !" line moved two places among the other additions in a
    config diff - same lines added and removed, different order among
    siblings. The 190 sections of a 10-device pair all matched difflib,
    but those configs were identical pre/post, so the trim
    short-circuited and never reached the ambiguous path.

    Both tools run the same trim and produce the same 48 diff lines in
    the same order, which is the parity the reports rest on.
    """
    rng = random.Random(7)
    vocabulary = ["!", "   exit", "  seq 10 permit x", "router bgp 1"]
    disagreements = 0

    for _ in range(200):
        a = [rng.choice(vocabulary) for _ in range(rng.randint(2, 40))]
        b = list(a)

        for _ in range(rng.randint(1, 6)):
            b.insert(rng.randint(0, len(b)), rng.choice(vocabulary))

        if list(difftrim.ndiff(a, b)) != list(difflib.ndiff(a, b)):
            disagreements += 1

    # A range, so the test fails if this moves in either direction
    # instead of going stale.
    assert 10 < disagreements < 190


def test_a_mostly_identical_config_is_far_cheaper_than_difflib():
    """The point of the module, asserted as a property rather than a time.

    difflib is given the whole file; difftrim is given only the part that
    differs. The margin on a 6,000-line config is large enough that a
    loose bound still catches a regression that reintroduces the full
    diff, without making the suite flaky on a busy machine.
    """
    big = [f"   seq {n} permit 10.{n // 256}.{n % 256}.0/24" for n in range(6000)]
    pre = ["ip prefix-list BIG"] + big
    post = ["ip prefix-list BIG"] + big[:3000] + ["   seq 9999 permit 0.0.0.0/0"] + big[3000:]

    start = time.perf_counter()
    list(difflib.ndiff(pre, post))
    baseline = time.perf_counter() - start

    start = time.perf_counter()
    trimmed = list(difftrim.ndiff(pre, post))
    cost = time.perf_counter() - start

    assert trimmed == list(difflib.ndiff(pre, post))
    assert cost < baseline / 2


def test_the_trimmed_head_and_tail_come_back_as_context():
    """Callers read the context lines - the report tracks which config
    block an indented change sits under from them - so they have to be
    in the stream, not dropped."""
    pre = ["router bgp 64500", "   neighbor 10.0.0.2 shutdown", "!"]
    post = ["router bgp 64500", "   neighbor 10.0.0.2 maximum-routes 100", "!"]

    stream = list(difftrim.ndiff(pre, post))

    assert stream[0] == "  router bgp 64500"
    assert stream[-1] == "  !"
    assert any(line.startswith("- ") for line in stream)
    assert any(line.startswith("+ ") for line in stream)


# --- the fancy-replace size cap ---------------------------------------


def _config_lines(count, tag):
    rng = random.Random(tag)
    return [f"   neighbor 10.{i // 250}.{i % 250}.{rng.randint(1, 250)} description {tag}-{rng.randint(0, 10**6)}" for i in range(count)]


def test_a_five_thousand_line_changed_block_finishes_fast():
    a = ["router bgp 65001"] + _config_lines(5000, "old") + ["end"]
    b = ["router bgp 65001"] + _config_lines(5000, "new") + ["end"]

    started = time.perf_counter()
    out = list(difftrim.ndiff(a, b))
    elapsed = time.perf_counter() - started

    # Uncapped, difflib scores 25 million line pairs here and runs for minutes.
    assert elapsed < 2.0, f"{elapsed:.1f}s"
    # Nothing lost: every old line removed, every new line added, in order.
    assert [line[2:] for line in out if line.startswith("- ")] == a[1:-1]
    assert [line[2:] for line in out if line.startswith("+ ")] == b[1:-1]
    assert out[0] == "  router bgp 65001" and out[-1] == "  end"


def test_the_cap_rule_is_old_lines_times_new_lines():
    assert difftrim.FANCY_REPLACE_MAX_PAIRS == 40_000

    def interleaved(old_count, new_count):
        # Line i of each side differs by one character, so the fancy
        # path pairs them up ("- old", "+ new", "- old", ...). The plain
        # path writes one block, then the other.
        a = [f"interface Ethernet{i} description uplink-to-core-old" for i in range(old_count)]
        b = [f"interface Ethernet{i} description uplink-to-core-new" for i in range(new_count)]
        signs = [line[0] for line in difftrim.ndiff(a, b) if line[0] in "-+"]

        return signs[:2] == ["-", "+"]

    assert interleaved(200, 200)  # 40,000 pairs: at the cap, still fancy
    assert not interleaved(200, 201)  # 40,200 pairs: plain


def test_above_the_cap_the_shorter_side_is_written_first():
    a = [f"old line {i}" for i in range(300)]
    b = [f"new line {i}" for i in range(200)]

    out = [line for line in difftrim.ndiff(a, b) if line[0] in "-+"]

    # difflib's own plain-replace rule: fewer "+" lines than "-", so "+" first.
    assert out == [f"+ {line}" for line in b] + [f"- {line}" for line in a]


def test_under_the_cap_the_output_is_still_exactly_difflib():
    a = _config_lines(150, "old")
    b = a[:40] + _config_lines(60, "new") + a[100:]

    assert list(difftrim.ndiff(a, b)) == list(difflib.ndiff(a, b))


def test_the_difflib_hooks_the_cap_relies_on_still_exist():
    # The cap overrides one private Differ method and calls another. If a
    # future Python renames either, fail here with a clear message
    # instead of silently losing the cap.
    assert callable(getattr(difflib.Differ, "_fancy_replace", None))
    assert callable(getattr(difflib.Differ, "_plain_replace", None))
