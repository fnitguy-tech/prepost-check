"""State collection over SSH.

Connects to every device in parallel (netmiko), runs that platform's
command list, and writes one timestamped text file per device. A device
that cannot be reached gets a <host>_FAILED.txt marker instead of
killing the run - during a maintenance window an unreachable device is
itself a finding, not a reason to abort evidence collection.

Output files use "### <command> ###" section headers with a dash rule
under each; the compare modules parse that two-line marker to diff
command-by-command (see modules/captures.py).

The run is honest about how it went. run_collection() returns a
RunResult that knows how many devices were captured, which failed and
why, the one-line summary to print, and the exit code to leave with.
"""

import os
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException, ReadTimeout
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from modules import captures, redact
from modules.hostkeys import HostKeyStore
from modules.layout import safe_name

# How to ask each platform for its own hostname, so output files are
# named after the device and not its management IP. Unknown platforms
# fall back to the IP.
HOSTNAME_LOOKUPS = {
    "arista_eos": ("show hostname", "Hostname:"),
    "paloalto_panos": ("show system info | match hostname", "hostname:"),
}

MAX_WORKERS = 5
COMMAND_READ_TIMEOUT = 180  # seconds; "show ip bgp" on a full table is slow

# Exit codes for precheck.py and postcheck.py. Three values, so a
# wrapper script can tell "look at one device" from "nothing worked".
EXIT_OK = 0  # every device fully captured
EXIT_SOME_FAILED = 1  # at least one device failed, was cut short, or wasn't tried
EXIT_ALL_FAILED = 2  # no device was captured at all

# Pass as host_keys to check SSH host keys against the default
# known-hosts file. It's the default, so a caller has to opt out of
# checking on purpose (host_keys=None), not opt in.
DEFAULT_HOST_KEYS = object()


@dataclass
class DeviceOutcome:
    """How one device's capture went.

    status is one of:
        captured     every command ran
        incomplete   connected, but a command timed out and the rest were skipped
        failed       couldn't connect, or the capture broke
        skipped      never tried, because another device rejected the password
    """

    host: str
    status: str
    name: str = ""
    reason: str = ""
    file_path: str = ""

    @property
    def label(self):
        return self.name or self.host


@dataclass
class RunResult:
    """What one precheck or postcheck run produced, and how it went."""

    folder_name: str
    zip_name: str
    outcomes: list = field(default_factory=list)

    def __iter__(self):
        # Older callers unpack two values: folder, zip = run_collection(...).
        return iter((self.folder_name, self.zip_name))

    def _with(self, status):
        return [outcome for outcome in self.outcomes if outcome.status == status]

    @property
    def ok(self):
        return self.exit_code == EXIT_OK

    @property
    def exit_code(self):
        captured = len(self._with("captured"))
        usable = captured + len(self._with("incomplete"))

        if captured == len(self.outcomes):
            return EXIT_OK

        return EXIT_SOME_FAILED if usable else EXIT_ALL_FAILED

    def summary_line(self):
        """The whole run in one line.

        Examples:
            8 of 8 captured.
            7 of 8 captured; 1 failed: 10.0.0.5 (authentication failed)
            1 of 8 captured; 1 failed: 10.0.0.5 (authentication failed); 6 not attempted
            7 of 8 captured; 1 incomplete: SITE-A-SW-1 (timeout on show ip bgp)
        """
        parts = [f"{len(self._with('captured'))} of {len(self.outcomes)} captured"]

        for status, word in (("failed", "failed"), ("incomplete", "incomplete")):
            found = self._with(status)

            if found:
                listed = ", ".join(f"{outcome.label} ({outcome.reason})" for outcome in found)
                parts.append(f"{len(found)} {word}: {listed}")

        if self._with("skipped"):
            parts.append(f"{len(self._with('skipped'))} not attempted")

        return "; ".join(parts) + ("." if len(parts) == 1 else "")


class _NotAttempted(Exception):
    """Raised instead of connecting, once a device has rejected the password."""

    def __init__(self, rejected_by):
        super().__init__(rejected_by)
        self.rejected_by = rejected_by


class _CredentialGate:
    """Stops a mistyped password from being tried on every device.

    Most networks check logins against one central server, and that
    server locks an account after a few bad tries. Five devices at a
    time, a typo would use up those tries in the first second.

    So the first connections go one at a time. As soon as one device
    accepts the password, it's known to be right and the rest connect in
    parallel. The first device that rejects it ends the run for every
    device that hasn't started yet: at most one bad try with an unproven
    password. Once it's proven, connections overlap, so a rejection can
    still be followed by the few that were already in flight.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.proven = threading.Event()
        self.rejected_by = None

    def connect(self, device, host_keys):
        if not self.proven.is_set():
            with self.lock:
                # Checked again: the password may have been proven while
                # this connection waited its turn.
                if not self.proven.is_set():
                    conn = self._attempt(device, host_keys)
                    self.proven.set()

                    return conn

        return self._attempt(device, host_keys)

    def _attempt(self, device, host_keys):
        if self.rejected_by is not None:
            raise _NotAttempted(self.rejected_by)

        try:
            return open_connection(device, host_keys)
        except NetmikoAuthenticationException:
            self.rejected_by = self.rejected_by or device["host"]
            raise


class _Run:
    """What the worker threads share for one run."""

    def __init__(self, folder_name, progress, overall_task, redact_secrets, host_keys):
        self.folder_name = folder_name
        self.progress = progress
        self.overall_task = overall_task
        # Scrub output before it is written so no password, hash or key ever
        # reaches disk; off by default because it hides a rotated password
        # from the diff (see modules/redact.py).
        self.clean = redact.scrub if redact_secrets else (lambda text: text)
        self.redact_secrets = redact_secrets
        self.host_keys = host_keys
        self._lock = threading.Lock()
        self._gates = {}
        self._claims = {}

    def log(self, message):
        self.progress.console.log(message)

    def connect(self, device):
        # One gate per credential, so a rejected password only stops the
        # devices that would have been sent the same one.
        credential = (device.get("username"), device.get("password"))

        with self._lock:
            gate = self._gates.setdefault(credential, _CredentialGate())

        return gate.connect(device, self.host_keys)

    def claim_file(self, hostname, host):
        """Pick the capture file path for a device; never one already taken.

        The name comes from the device, so it's cleaned first. Two
        devices can also report the same name (two lab boxes both called
        "localhost"). The second one to arrive gets the host added:
        localhost_192.0.2.2.txt. settle_names() then renames the first
        to match, so neither depends on which connected first.
        """
        stem = safe_name(hostname, host)

        with self._lock:
            claims = self._claims.setdefault(stem.lower(), [])
            taken = {path for claimed in self._claims.values() for _host, path in claimed}
            path = os.path.join(self.folder_name, f"{stem}.txt")

            if claims or path in taken:
                path = os.path.join(self.folder_name, f"{stem}_{safe_name(host)}.txt")

            claims.append((host, path))

        return path

    def settle_names(self, outcomes):
        """After the last device: give every device that shared a name
        the same <name>_<host>.txt form."""
        for claims in self._claims.values():
            if len(claims) < 2:
                continue

            host, path = claims[0]
            stem = os.path.basename(path)[: -len(".txt")]
            new_path = os.path.join(self.folder_name, f"{stem}_{safe_name(host)}.txt")

            if os.path.exists(path) and not os.path.exists(new_path):
                os.replace(path, new_path)

                for outcome in outcomes:
                    if outcome.file_path == path:
                        outcome.file_path = new_path


def open_connection(device, host_keys):
    """Connect to one device, checking its SSH host key first.

    host_keys is a HostKeyStore, or None to accept any key the way
    netmiko does by default (see modules/hostkeys.py for both).
    """
    if host_keys is None:
        return ConnectHandler(**device)

    conn = ConnectHandler(**device, **host_keys.connect_options(), auto_connect=False)
    conn.key_policy = host_keys.policy()
    conn._open()

    return conn


def get_hostname(conn, device_type, fallback):
    lookup = HOSTNAME_LOOKUPS.get(device_type)

    if lookup is None:
        return fallback

    command, prefix = lookup
    output = conn.send_command(command)

    for line in output.splitlines():
        if line.strip().startswith(prefix):
            return line.split(":", 1)[1].strip()

    return fallback


def _hide_password(text, device):
    """Error text with the login password blanked out, in case a library
    ever echoes it back. Very short passwords are left alone: blanking
    every "a" would wreck the message and hide nothing."""
    password = device.get("password") or ""

    return text.replace(password, "<hidden>") if len(password) >= 4 else text


def _failure_reason(error):
    """A few plain words for the summary line; the full error goes in the file."""
    if isinstance(error, NetmikoAuthenticationException):
        return "authentication failed"

    if isinstance(error, NetmikoTimeoutException):
        text = str(error)

        if "DNS failure" in text:
            return "name not found"

        if "TCP connection to device failed" in text:
            return "unreachable"

        return "SSH connection failed"

    return "capture failed"


def _capture(conn, device, commands, hostname, file_path, run, done):
    """Run every command and write the capture file.

    Each command is added to `done` as its section is written, so the
    caller knows how far the progress bar has moved even if this raises.
    Returns (the command that cut it short or None, "timeout" or "error").

    If a command times out, the rest are skipped, not run. A timeout
    means netmiko stopped waiting; the device didn't stop answering. The
    late output is still on its way down the same connection, and the
    next command would read it as its own answer. Every answer after
    that would be filed under the wrong command.

    Reconnecting would fix that, but it also resets the session. PAN-OS
    needs `set cli config-output-format set` to hold for the whole
    capture, so a fresh session would print the config in another format
    and the diff would light up from top to bottom. Skipping is the
    safe choice. The capture says so in plain words:

        ### show running-config ###
        ----------------------------------------------------------------
        SKIPPED after timeout on show ip bgp
    """
    stopped_on = None
    stopped_why = ""

    with open(file_path, "w", encoding="utf-8") as file:
        file.write(f"Hostname: {hostname}\n")
        file.write(f"IP Address: {device['host']}\n")
        file.write(f"Generated: {datetime.now()}\n")
        if run.redact_secrets:
            file.write("Secrets: redacted\n")
        file.write("=" * 80 + "\n")

        for command in commands:
            run.progress.update(run.overall_task, description=f"{hostname}")

            if stopped_on is not None:
                output = f"SKIPPED after {stopped_why} on {stopped_on}"
            else:
                try:
                    output = conn.send_command(command, read_timeout=COMMAND_READ_TIMEOUT)
                except Exception as cmd_error:
                    output = f"COMMAND FAILED:\n{_hide_password(str(cmd_error), device)}"
                    stopped_on = command
                    stopped_why = "timeout" if isinstance(cmd_error, ReadTimeout) else "error"
                    run.log(f"{hostname}: {stopped_why} on '{command}'. Skipping the rest of its commands.")

            file.write("\n\n" + captures.section_header(command))
            file.write(run.clean(output))
            file.write("\n")

            run.progress.advance(run.overall_task, 1)
            done.append(command)

    return stopped_on, stopped_why


def collect_device(job, run):
    """Capture one device and return its DeviceOutcome. Never raises."""
    device = job["device"]
    commands = job["commands"]
    host = device["host"]
    done = []
    conn = None
    file_path = ""
    hostname = ""

    try:
        run.log(f"Connecting to {host}...")

        conn = run.connect(device)

        hostname = get_hostname(conn, device["device_type"], host)
        run.log(f"Connected to {hostname}")

        file_path = run.claim_file(hostname, host)
        stopped_on, stopped_why = _capture(conn, device, commands, hostname, file_path, run, done)

        if stopped_on is None:
            outcome = DeviceOutcome(host, "captured", hostname, file_path=file_path)
        else:
            outcome = DeviceOutcome(host, "incomplete", hostname, f"{stopped_why} on {stopped_on}", file_path)

    except _NotAttempted as skip:
        run.log(f"NOT ATTEMPTED: {host}")
        reason = f"{skip.rejected_by} rejected the username or password"
        failed_file = captures.write_failed(
            run.folder_name, host, captures.NOT_ATTEMPTED_FIRST_LINE,
            f"Not tried, because {reason}. Trying it on more devices could lock the account.\n",
        )
        outcome = DeviceOutcome(host, "skipped", reason=reason, file_path=failed_file)

    except Exception as error:
        changed_key = run.host_keys.find_changed_key(error) if run.host_keys else None
        text = _hide_password(str(changed_key or error), device)
        reason = "host key changed" if changed_key else _failure_reason(error)

        run.log(f"FAILED: {host}")
        run.log(text)

        if isinstance(error, NetmikoAuthenticationException):
            run.log(
                f"{host} rejected the username or password. No more devices will be tried, "
                "so a mistyped password can't lock the account."
            )

        # A capture that broke partway isn't evidence. Left in place, the
        # compare would read the half file as the device's whole state.
        if file_path and os.path.exists(file_path):
            os.remove(file_path)

        failed_file = captures.write_failed(run.folder_name, host, captures.FAILED_FIRST_LINE, run.clean(text))
        outcome = DeviceOutcome(host, "failed", hostname, reason, failed_file)

    # Advance the bar for the commands this device didn't get to run.
    # Counted, so a device that fails late doesn't move the bar twice.
    run.progress.advance(run.overall_task, len(commands) - len(done))

    if conn is not None:
        # Closing can fail on its own (the device hangs up first). By now
        # the capture is on disk and complete, so it's worth a warning
        # and nothing more: not a FAILED file next to a good capture.
        try:
            conn.disconnect()
        except Exception as error:
            run.log(f"WARNING: {outcome.label}: error while disconnecting, ignored ({error})")

    return outcome


def create_zip(folder_name, zip_name):
    with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for file_name in os.listdir(folder_name):
            file_path = os.path.join(folder_name, file_name)
            zip_file.write(file_path, arcname=file_name)


def run_collection(
    jobs, phase, phase_dir, run_timestamp, console,
    redact_secrets=False, progress=None, host_keys=DEFAULT_HOST_KEYS,
):
    """Collect all devices for one phase ('precheck' or 'postcheck').

    With redact_secrets, every command's output is passed through
    modules.redact.scrub() before it is written, so passwords, hashes
    and keys never land in the capture files or the zip.

    progress: somewhere to report to instead of a terminal bar. Anything
    with rich's Progress interface works - add_task, update, advance, and
    a console with log() - which is how the desktop window watches a run
    without this module knowing a window exists.

    host_keys: a modules.hostkeys.HostKeyStore to check SSH host keys
    against. Left alone, the default known-hosts file is used. Pass None
    to accept any key (the --insecure-accept-any-host-key flag).

    Returns a RunResult. It unpacks as (folder_name, zip_name) of the run
    that was just written, and also carries each device's outcome, the
    summary line, and the exit code.
    """
    if host_keys is DEFAULT_HOST_KEYS:
        host_keys = HostKeyStore()

    folder_name = os.path.join(phase_dir, f"{phase}_{run_timestamp}")
    zip_name = os.path.join(phase_dir, f"{phase}_{run_timestamp}.zip")

    os.makedirs(folder_name, exist_ok=True)

    total_commands = sum(len(job["commands"]) for job in jobs)
    outcomes = []

    with (
        progress
        or Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
        )
    ) as progress:

        overall_task = progress.add_task(
            f"{phase.capitalize()} Progress",
            total=total_commands,
        )
        run = _Run(folder_name, progress, overall_task, redact_secrets, host_keys)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(collect_device, job, run): job for job in jobs}

            for future in as_completed(futures):
                try:
                    outcomes.append(future.result())
                except Exception as error:
                    host = futures[future]["device"]["host"]
                    progress.console.log(f"Thread failed: {host}: {error}")
                    outcomes.append(DeviceOutcome(host, "failed", reason="capture failed"))

        run.settle_names(outcomes)

    result = RunResult(folder_name, zip_name, sorted(outcomes, key=lambda outcome: outcome.label))

    # Last, and only if we got this far: a run stopped by Ctrl-C or a
    # crash never writes the marker, so the compare can tell its folder
    # isn't a full baseline.
    captures.write_complete_marker(folder_name, phase, {
        "devices": len(outcomes),
        "captured": len(result._with("captured")),
        "incomplete": len(result._with("incomplete")),
        "failed": len(result._with("failed")),
        "not_attempted": len(result._with("skipped")),
    })

    create_zip(folder_name, zip_name)

    return result


def report_run(result, phase, console):
    """Print how the run went and return the exit code to leave with.

    SUCCESS is printed only when every device was fully captured.
    Anything less gets the summary line and a non-zero exit code, so
    neither a person nor a wrapper script reads a partial capture as a
    clean one.
    """
    console.print()

    if result.ok:
        console.print("[bold green]SUCCESS[/bold green]")
    else:
        console.print("[bold red]INCOMPLETE[/bold red]")

    console.print(result.summary_line(), highlight=False)

    skipped = result._with("skipped")

    if skipped:
        console.print(
            f"Stopped early: {skipped[0].reason}. Check the password, then run again.",
            highlight=False,
        )

    console.print(f"{phase.capitalize()} ZIP created: {result.zip_name}", highlight=False)

    return result.exit_code
