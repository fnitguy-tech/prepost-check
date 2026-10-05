"""The collector, driven by fake connections. No SSH happens here."""

import io
import json
import os
import threading

import pytest
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException, ReadTimeout
from rich.console import Console

from modules import captures, collect
from modules.captures import read_sections

COMMANDS = ["show version", "show ip bgp", "show running-config"]


class FakeDevice:
    """One pretend device: its hostname, and how it misbehaves."""

    def __init__(self, hostname="SW", connect_error=None, slow_command=None, disconnect_error=None):
        self.hostname = hostname
        self.connect_error = connect_error
        self.slow_command = slow_command
        self.disconnect_error = disconnect_error
        self.commands_sent = []
        # Output the device is still sending when netmiko gives up
        # waiting. The next read on the same connection would get it.
        self.late_output = None

    def send_command(self, command, **_kwargs):
        self.commands_sent.append(command)

        if command == "show hostname":
            return f"Hostname: {self.hostname}"

        if self.late_output is not None:
            late, self.late_output = self.late_output, None
            return late

        if command == self.slow_command:
            self.late_output = f"late output of {command}"
            raise ReadTimeout(f"Pattern not detected in output of {command}")

        return f"output of {command}"

    def disconnect(self):
        if self.disconnect_error:
            raise self.disconnect_error


class FakeNetwork:
    """Stands in for collect.ConnectHandler; records every attempt."""

    def __init__(self, devices):
        self.devices = devices
        self.attempts = []
        self._lock = threading.Lock()

    def __call__(self, **params):
        with self._lock:
            self.attempts.append(params["host"])

        fake = self.devices[params["host"]]

        if fake.connect_error:
            raise fake.connect_error

        return fake


class RecordingProgress:
    """rich's Progress interface, counting how far the bar moved."""

    def __init__(self):
        self.console = Console(file=io.StringIO(), width=200)
        self.advanced = 0
        self.total = 0

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def add_task(self, _description, total):
        self.total = total
        return 1

    def update(self, _task, **_kwargs):
        pass

    def advance(self, _task, amount):
        self.advanced += amount

    @property
    def log(self):
        return self.console.file.getvalue()


def run(tmp_path, monkeypatch, devices, commands=COMMANDS, **kwargs):
    network = FakeNetwork(devices)
    monkeypatch.setattr(collect, "ConnectHandler", network)
    jobs = [
        {
            "device": {"device_type": "arista_eos", "host": host, "username": "admin", "password": "pass-under-test"},
            "commands": commands,
        }
        for host in devices
    ]
    progress = RecordingProgress()
    result = collect.run_collection(
        jobs,
        "precheck",
        str(tmp_path),
        "2026-01-01_00-00-00",
        progress.console,
        progress=progress,
        host_keys=None,
        **kwargs,
    )

    return result, network, progress


def hosts(count):
    return [f"10.0.0.{n}" for n in range(1, count + 1)]


# --- fix 2: honest exit codes and the failure summary -----------------


def test_all_captured_is_success_and_exit_zero(tmp_path, monkeypatch):
    result, _network, progress = run(tmp_path, monkeypatch, {h: FakeDevice(f"SW-{h[-1]}") for h in hosts(3)})
    console = Console(file=io.StringIO(), width=200)

    assert result.summary_line() == "3 of 3 captured."
    assert collect.report_run(result, "precheck", console) == collect.EXIT_OK == 0
    assert "SUCCESS" in console.file.getvalue()
    assert progress.advanced == progress.total == 9


def test_one_unreachable_device_is_counted_named_and_exit_one(tmp_path, monkeypatch):
    devices = {h: FakeDevice(f"SW-{h[-1]}") for h in hosts(8)}
    devices["10.0.0.5"].connect_error = NetmikoTimeoutException("TCP connection to device failed.")
    result, _network, progress = run(tmp_path, monkeypatch, devices)
    console = Console(file=io.StringIO(), width=200)

    assert result.summary_line() == "7 of 8 captured; 1 failed: 10.0.0.5 (unreachable)"
    assert collect.report_run(result, "precheck", console) == collect.EXIT_SOME_FAILED == 1

    printed = console.file.getvalue()
    assert "SUCCESS" not in printed
    assert "7 of 8 captured; 1 failed: 10.0.0.5 (unreachable)" in printed
    assert os.path.exists(tmp_path / "precheck_2026-01-01_00-00-00" / "10.0.0.5_FAILED.txt")
    assert progress.advanced == progress.total


def test_every_device_failing_is_exit_two(tmp_path, monkeypatch):
    devices = {
        h: FakeDevice(connect_error=NetmikoTimeoutException("TCP connection to device failed.")) for h in hosts(2)
    }
    result, _network, _progress = run(tmp_path, monkeypatch, devices)

    assert result.exit_code == collect.EXIT_ALL_FAILED == 2
    assert result.summary_line().startswith("0 of 2 captured; 2 failed: ")


def test_first_authentication_failure_stops_the_run(tmp_path, monkeypatch):
    devices = {
        h: FakeDevice(connect_error=NetmikoAuthenticationException("Authentication to device failed."))
        for h in hosts(8)
    }
    result, network, progress = run(tmp_path, monkeypatch, devices)

    # A wrong password is tried on exactly one device, not all eight.
    assert len(network.attempts) == 1
    rejected_by = network.attempts[0]

    assert result.exit_code == collect.EXIT_ALL_FAILED
    assert result.summary_line() == f"0 of 8 captured; 1 failed: {rejected_by} (authentication failed); 7 not attempted"
    assert f"{rejected_by} rejected the username or password" in progress.log

    console = Console(file=io.StringIO(), width=200)
    collect.report_run(result, "precheck", console)
    assert f"Stopped early: {rejected_by} rejected the username or password." in console.file.getvalue()

    # Each device that wasn't tried still leaves a record for the compare.
    folder = tmp_path / "precheck_2026-01-01_00-00-00"
    skipped = sorted(set(hosts(8)) - {rejected_by})[0]
    assert (folder / f"{skipped}_FAILED.txt").read_text().startswith(f"NOT ATTEMPTED: {skipped}\n")
    assert progress.advanced == progress.total


def test_an_unreachable_first_device_does_not_count_as_a_bad_password(tmp_path, monkeypatch):
    devices = {h: FakeDevice(f"SW-{h[-1]}") for h in hosts(4)}
    devices["10.0.0.1"].connect_error = NetmikoTimeoutException("TCP connection to device failed.")
    result, network, _progress = run(tmp_path, monkeypatch, devices)

    assert sorted(network.attempts) == hosts(4)
    assert result.summary_line() == "3 of 4 captured; 1 failed: 10.0.0.1 (unreachable)"


def test_the_password_never_reaches_a_failed_file_or_the_log(tmp_path, monkeypatch):
    devices = {"10.0.0.1": FakeDevice(connect_error=RuntimeError("login as admin/pass-under-test refused"))}
    _result, _network, progress = run(tmp_path, monkeypatch, devices)

    failed = (tmp_path / "precheck_2026-01-01_00-00-00" / "10.0.0.1_FAILED.txt").read_text()

    assert "pass-under-test" not in failed
    assert "pass-under-test" not in progress.log
    assert "login as admin/<hidden> refused" in failed


# --- fix 4: a slow command must not shift later answers ---------------


def test_commands_after_a_timeout_are_skipped_not_misfiled(tmp_path, monkeypatch):
    device = FakeDevice("SW-1", slow_command="show ip bgp")
    result, _network, progress = run(tmp_path, monkeypatch, {"10.0.0.1": device})

    sections = read_sections(str(tmp_path / "precheck_2026-01-01_00-00-00" / "SW-1.txt"))

    assert sections["show version"][1] == "output of show version"
    assert sections["show ip bgp"][1] == "COMMAND FAILED:"
    assert sections["show running-config"][1] == "SKIPPED after timeout on show ip bgp"
    # The late BGP output was never read, so it can't sit under the config.
    assert "show running-config" not in device.commands_sent
    assert "late output of show ip bgp" not in "\n".join(sections["show running-config"])

    assert result.summary_line() == "0 of 1 captured; 1 incomplete: SW-1 (timeout on show ip bgp)"
    assert result.exit_code == collect.EXIT_SOME_FAILED
    assert progress.advanced == progress.total


# --- fix 7: file names ------------------------------------------------


def test_two_devices_with_the_same_hostname_keep_separate_files(tmp_path, monkeypatch):
    devices = {"192.0.2.1": FakeDevice("localhost"), "192.0.2.2": FakeDevice("localhost")}
    result, _network, _progress = run(tmp_path, monkeypatch, devices)

    folder = tmp_path / "precheck_2026-01-01_00-00-00"

    assert captures.capture_files(str(folder)) == ["localhost_192.0.2.1.txt", "localhost_192.0.2.2.txt"]
    assert "IP Address: 192.0.2.1\n" in (folder / "localhost_192.0.2.1.txt").read_text()
    assert "IP Address: 192.0.2.2\n" in (folder / "localhost_192.0.2.2.txt").read_text()
    assert sorted(os.path.basename(outcome.file_path) for outcome in result.outcomes) == [
        "localhost_192.0.2.1.txt",
        "localhost_192.0.2.2.txt",
    ]


@pytest.mark.parametrize(
    "hostname, host, expected",
    [
        ("../../x", "192.0.2.1", "_.._x.txt"),
        ("", "192.0.2.1", "192.0.2.1.txt"),
        ("", "2001:db8::1", "2001_db8__1.txt"),
        ("core sw/1", "192.0.2.1", "core_sw_1.txt"),
    ],
)
def test_a_hostile_or_empty_hostname_stays_inside_the_run_folder(tmp_path, monkeypatch, hostname, host, expected):
    run(tmp_path, monkeypatch, {host: FakeDevice(hostname)})

    folder = tmp_path / "precheck_2026-01-01_00-00-00"

    assert captures.capture_files(str(folder)) == [expected]
    # Nothing was written above the run folder.
    assert sorted(os.listdir(tmp_path)) == ["precheck_2026-01-01_00-00-00", "precheck_2026-01-01_00-00-00.zip"]


def test_an_unreachable_ipv6_host_gets_a_windows_safe_failed_file(tmp_path, monkeypatch):
    devices = {"2001:db8::5": FakeDevice(connect_error=NetmikoTimeoutException("TCP connection to device failed."))}
    run(tmp_path, monkeypatch, devices)

    assert captures.capture_files(str(tmp_path / "precheck_2026-01-01_00-00-00")) == ["2001_db8__5_FAILED.txt"]


# --- fix 8: completion marker -----------------------------------------


def test_a_finished_run_writes_the_completion_marker(tmp_path, monkeypatch):
    devices = {h: FakeDevice(f"SW-{h[-1]}") for h in hosts(2)}
    devices["10.0.0.2"].connect_error = NetmikoTimeoutException("TCP connection to device failed.")
    run(tmp_path, monkeypatch, devices)

    with open(tmp_path / "precheck_2026-01-01_00-00-00" / captures.COMPLETE_MARKER, encoding="utf-8") as file:
        marker = json.load(file)

    assert marker["phase"] == "precheck"
    assert (marker["devices"], marker["captured"], marker["failed"]) == (2, 1, 1)


def test_an_interrupted_run_leaves_no_marker(tmp_path, monkeypatch):
    monkeypatch.setattr(collect, "collect_device", lambda job, run: (_ for _ in ()).throw(KeyboardInterrupt()))

    with pytest.raises(KeyboardInterrupt):
        run(tmp_path, monkeypatch, {"10.0.0.1": FakeDevice()})

    assert not os.path.exists(tmp_path / "precheck_2026-01-01_00-00-00" / captures.COMPLETE_MARKER)


# --- fix 9: disconnect errors -----------------------------------------


def test_a_disconnect_error_after_a_full_capture_is_only_a_warning(tmp_path, monkeypatch):
    device = FakeDevice("SW-1", disconnect_error=OSError("Socket is closed"))
    result, _network, progress = run(tmp_path, monkeypatch, {"10.0.0.1": device})

    folder = tmp_path / "precheck_2026-01-01_00-00-00"

    assert captures.capture_files(str(folder)) == ["SW-1.txt"]
    assert result.summary_line() == "1 of 1 captured."
    assert "WARNING: SW-1: error while disconnecting, ignored (Socket is closed)" in progress.log
    # The bar moved once per command, not twice.
    assert progress.advanced == progress.total == len(COMMANDS)


def test_older_callers_can_still_unpack_folder_and_zip(tmp_path, monkeypatch):
    result, _network, _progress = run(tmp_path, monkeypatch, {"10.0.0.1": FakeDevice("SW-1")})
    folder_name, zip_name = result

    assert folder_name.endswith("precheck_2026-01-01_00-00-00")
    assert zip_name.endswith("precheck_2026-01-01_00-00-00.zip")
