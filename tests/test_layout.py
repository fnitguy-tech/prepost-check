import os

from modules.layout import find_latest_folder, ticket_dirs


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
