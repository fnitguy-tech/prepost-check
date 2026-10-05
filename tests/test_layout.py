import os
import re

import pytest

from modules.layout import (
    MAX_NAME_LENGTH,
    TicketError,
    check_ticket,
    find_latest_folder,
    safe_name,
    ticket_dirs,
    timestamp,
)


def test_ticket_dirs_shape():
    dirs = ticket_dirs("NET-123")

    assert dirs["base"].endswith(os.path.join("reports", "NET-123"))
    assert dirs["precheck"].endswith("Precheck")
    assert dirs["postcheck"].endswith("Postcheck")
    assert dirs["compare"].endswith("Compare")


def test_find_latest_folder_picks_newest(tmp_path):
    (tmp_path / "precheck_2026-01-01_09-00").mkdir()
    (tmp_path / "precheck_2026-01-02_08-00").mkdir()
    (tmp_path / "unrelated_folder").mkdir()
    (tmp_path / "precheck_not_a_dir.txt").write_text("file, not a run folder")

    latest = find_latest_folder(str(tmp_path), "precheck_")

    assert latest is not None
    assert latest.endswith("precheck_2026-01-02_08-00")


def test_find_latest_folder_handles_missing():
    assert find_latest_folder("/does/not/exist", "precheck_") is None


@pytest.mark.parametrize(
    "value, expected",
    [
        ("SITE-A-SW-1", "SITE-A-SW-1"),
        ("localhost", "localhost"),
        ("../../x", "_.._x"),
        ("2001:db8::1", "2001_db8__1"),
        (".hidden", "hidden"),
        ("NUL", "_NUL"),
        ("", "192.0.2.1"),
        ("...", "192.0.2.1"),
    ],
)
def test_safe_name(value, expected):
    assert safe_name(value, "192.0.2.1") == expected


def test_safe_name_is_never_empty_dotted_or_too_long():
    for value in ["", ".", "..", "/", "a" * 500, "x" * 63 + ".txt", None]:
        name = safe_name(value, "")

        assert name
        assert not name.startswith(".")
        assert len(name) <= MAX_NAME_LENGTH
        assert re.fullmatch(r"[A-Za-z0-9._-]+", name)


@pytest.mark.parametrize("ticket", ["../..", "..", "", "a/b", "a\\b", ".hidden", "NET 123", "x" * 65])
def test_a_ticket_that_cannot_name_a_folder_is_rejected(ticket):
    with pytest.raises(TicketError):
        check_ticket(ticket)

    with pytest.raises(TicketError):
        ticket_dirs(ticket)


def test_an_ordinary_ticket_is_unchanged():
    assert check_ticket("NET-123") == "NET-123"
    assert check_ticket("CHG0012345_v2.1") == "CHG0012345_v2.1"


def test_timestamp_has_seconds_and_sorts_after_the_old_minute_format(tmp_path):
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}", timestamp())

    # An old minute-resolution folder and two new runs in that same minute.
    for name in ["precheck_2026-04-14_08-48", "precheck_2026-04-14_08-48-05", "precheck_2026-04-14_08-48-41"]:
        (tmp_path / name).mkdir()

    assert find_latest_folder(str(tmp_path), "precheck_").endswith("precheck_2026-04-14_08-48-41")
