"""Command-line handling, and the exit codes the capture scripts leave with."""

import importlib.util
import io
import os

import pytest
from rich.console import Console

from modules import cli, collect, hostkeys, layout
from modules.collect import DeviceOutcome, RunResult

SCRIPTS = os.path.join(layout.REPO_ROOT, "scripts")


def parse(monkeypatch, *argv, needs_inventory=True):
    monkeypatch.setattr("sys.argv", ["prog", *argv])
    return cli.parse_args("test", needs_inventory=needs_inventory)


def test_a_ticket_that_would_escape_reports_is_rejected(monkeypatch, capsys):
    with pytest.raises(SystemExit) as excinfo:
        parse(monkeypatch, "--ticket", "../..")

    assert excinfo.value.code == 2
    assert "can't be used as a folder name" in capsys.readouterr().err


def test_a_normal_ticket_is_upper_cased_as_before(monkeypatch):
    assert parse(monkeypatch, "--ticket", " net-123 ").ticket == "NET-123"


def test_host_keys_are_checked_unless_you_opt_out(monkeypatch, tmp_path):
    monkeypatch.setenv(hostkeys.ENV_VAR, str(tmp_path / "from-env"))

    default = cli.host_keys_from(parse(monkeypatch, "--ticket", "NET-1"))
    assert default.path == str(tmp_path / "from-env")

    chosen = cli.host_keys_from(parse(monkeypatch, "--ticket", "NET-1", "--known-hosts", str(tmp_path / "flag")))
    assert chosen.path == str(tmp_path / "flag")

    assert cli.host_keys_from(parse(monkeypatch, "--ticket", "NET-1", "--insecure-accept-any-host-key")) is None


def load_script(name):
    spec = importlib.util.spec_from_file_location(f"script_{name}", os.path.join(SCRIPTS, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


@pytest.mark.parametrize("script", ["precheck", "postcheck"])
@pytest.mark.parametrize(
    "statuses, exit_code, summary",
    [
        (["captured", "captured"], 0, "2 of 2 captured."),
        (["captured", "failed"], 1, "1 of 2 captured; 1 failed: 10.0.0.2 (authentication failed)"),
        (
            ["failed", "failed"],
            2,
            "0 of 2 captured; 2 failed: 10.0.0.1 (authentication failed), 10.0.0.2 (authentication failed)",
        ),
    ],
)
def test_the_scripts_exit_code_and_last_lines_match_the_run(
    monkeypatch, tmp_path, script, statuses, exit_code, summary
):
    module = load_script(script)
    output = io.StringIO()
    outcomes = [
        DeviceOutcome(f"10.0.0.{n}", status, reason="" if status == "captured" else "authentication failed")
        for n, status in enumerate(statuses, start=1)
    ]

    monkeypatch.setattr(
        "sys.argv", [script, "--ticket", "NET-1", "--username", "admin", "--known-hosts", str(tmp_path / "kh")]
    )
    monkeypatch.setattr(module, "Console", lambda: Console(file=output, width=300))
    monkeypatch.setattr(layout, "REPORTS_DIR", str(tmp_path))
    monkeypatch.setattr(module.inventory, "load_inventory", lambda _path: [])
    monkeypatch.setattr(module.inventory, "prompt_credentials", lambda username: (username, "not-a-real-password"))
    monkeypatch.setattr(
        collect,
        "run_collection",
        lambda *_args, **_kwargs: RunResult(str(tmp_path / "run"), str(tmp_path / "run.zip"), outcomes),
    )

    assert module.main() == exit_code

    printed = output.getvalue()
    assert summary in printed
    assert ("SUCCESS" in printed) == (exit_code == 0)
