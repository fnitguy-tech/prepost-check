"""PAN-OS routing-table age.

'show routing route' prints a fixed-width table whose age column ticks
every second. Two captures taken two minutes apart therefore disagree on
every BGP route while the route set is identical - 224 of 224 lines on
one firewall in a real window, which is enough evidence noise to hide a
route that actually moved.
"""

from modules.htmlreport import blank_panos_route_age, normalized_section

HEADER = (
    "destination                                 nexthop                                 "
    "metric flags      age   interface          next-AS    "
)

# A connected route (no age, no next-AS), a BGP route whose age fits the
# column, and one whose seven-digit age overruns it.
CONNECTED = (
    "10.11.16.0/24                               10.11.16.1                              "
    "0      A C              tunnel.511                    "
)
BGP_NARROW = (
    "10.61.82.7/32                               10.2.1.1                                "
    "       A?B        {age}                     4280000001 "
)
BGP_WIDE = (
    "10.100.2.251/32                             10.2.1.1                                "
    "       A?B        {age}                  4280000001 "
)


def _section(age_narrow, age_wide):
    return [
        "VIRTUAL ROUTER: default (id 1)",
        "  ==========",
        HEADER,
        CONNECTED,
        BGP_NARROW.format(age=age_narrow),
        BGP_WIDE.format(age=age_wide),
        "total routes shown: 3",
    ]


def test_age_column_is_blanked_so_a_static_table_compares_equal():
    pre = normalized_section("show routing route", _section("2724", "2666471"))
    post = normalized_section("show routing route", _section("2849", "2666596"))

    assert pre == post


def test_a_wide_age_does_not_leave_its_last_digits_behind():
    """A 7-digit age overruns the header's 6-column 'age' span, so slicing a
    fixed width leaves a digit behind and the line still differs."""
    blanked = blank_panos_route_age(_section("2724", "2666471"))

    assert "2666471" not in "\n".join(blanked)
    assert "2724" not in "\n".join(blanked)


def test_next_as_survives_a_blank_age():
    """next-AS is numeric too. On a route with no age, the blanker must not
    reach past the age column and erase it."""
    blanked = blank_panos_route_age([
        "VIRTUAL ROUTER: default (id 1)",
        HEADER,
        "10.0.0.0/8                                  10.2.1.1                                "
        "       A?B                                 4280000001 ",
    ])

    assert "4280000001" in blanked[-1]


def test_a_route_that_really_moved_still_shows():
    moved = _section("2724", "2666471")
    moved[4] = moved[4].replace("10.2.1.1", "10.2.1.5")

    pre = normalized_section("show routing route", _section("2724", "2666471"))
    post = normalized_section("show routing route", moved)

    assert pre != post
    assert any("10.2.1.5" in line for line in post)


def test_lines_before_any_header_are_untouched():
    lines = ["flags: A:active, ?:loose, C:connect", "  ", "VIRTUAL ROUTER: management (id 4)"]

    assert blank_panos_route_age(lines) == lines
