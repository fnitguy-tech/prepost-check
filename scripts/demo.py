#!/usr/bin/env python3
"""Run the whole prepost-check workflow on the bundled fictional dataset.

No devices, no SSH. netmiko's ConnectHandler is swapped for a stub that
answers each show command from the captures in docs/demo/NET-DEMO/ (a
made-up uplink migration at SITE-A; see SCENARIO.md there). Everything
else is the real code path: the parallel collector with its progress
bar, the zip packaging, the quick text diff, and the HTML report land in
reports/NET-DEMO/ exactly as they would after a real window.

Usage:
    python3 scripts/demo.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console

from modules import collect, htmlreport, layout, textcompare
from modules.htmlreport import parse_sections

TICKET = "NET-DEMO"
DEMO_SRC = os.path.join(layout.REPO_ROOT, "docs", "demo", TICKET)
# Capture timestamps from the fictional window; reused so the replayed run
# lands in folders with the same names as the source captures.
STAMPS = {"precheck": "2026-04-14_08-48", "postcheck": "2026-04-14_10-42"}
PHASES = {
    phase: os.path.join(DEMO_SRC, phase.capitalize(), f"{phase}_{stamp}")
    for phase, stamp in STAMPS.items()
}
# Pretend each show command takes this long, so the progress bar is visible.
COMMAND_DELAY = 0.12

# Which capture belongs to which "management IP" and platform.
DEVICES = [
    ("arista_eos", "192.0.2.1", "SITE-A-SW-1"),
    ("arista_eos", "192.0.2.2", "SITE-A-SW-2"),
    ("arista_eos", "192.0.2.11", "SITE-B-SW-1"),
    ("paloalto_panos", "10.10.200.254", "SITE-A-FW-1"),
]


class FakeConnection:
    """Stands in for a netmiko connection; replays one device's capture."""

    def __init__(self, capture_path, hostname):
        self.sections = parse_sections(capture_path)
        self.hostname = hostname

    def send_command(self, command, **_kwargs):
        time.sleep(COMMAND_DELAY)
        if command in ("show hostname", "show system info | match hostname"):
            return f"Hostname: {self.hostname}\nhostname: {self.hostname}"
        # Real captures store the command output under a "### cmd ###"
        # header, preceded by a dashed rule; return just the output.
        lines = self.sections.get(command, [])
        return "\n".join(line for line in lines if not line.startswith("-" * 80)).rstrip("\n")

    def disconnect(self):
        pass


def fake_connect_handler_for(phase):
    folder = PHASES[phase]

    def connect(**device):
        host = device["host"]
        hostname = next(name for _, ip, name in DEVICES if ip == host)
        return FakeConnection(os.path.join(folder, f"{hostname}.txt"), hostname)

    return connect


def demo_jobs():
    """Same shape inventory.build_jobs() produces, without credentials."""
    commands_by_type = {}
    for device_type, _ip, hostname in DEVICES:
        capture = os.path.join(PHASES["precheck"], f"{hostname}.txt")
        commands_by_type.setdefault(
            device_type,
            [cmd for cmd in parse_sections(capture) if cmd != "HEADER"],
        )
    return [
        {
            "device": {"device_type": device_type, "host": ip, "username": "demo", "password": "demo"},
            "commands": commands_by_type[device_type],
        }
        for device_type, ip, _hostname in DEVICES
    ]


def main(console=None):
    console = console or Console(highlight=False)
    dirs = layout.ticket_dirs(TICKET)
    jobs = demo_jobs()

    console.print(
        f"[bold]{TICKET}[/bold]: fictional SITE-A uplink migration, "
        f"{len(jobs)} devices replayed from docs/demo/ (no SSH)"
    )
    console.print()

    for phase in ("precheck", "postcheck"):
        collect.ConnectHandler = fake_connect_handler_for(phase)
        os.makedirs(dirs[phase], exist_ok=True)
        _folder, zip_name = collect.run_collection(jobs, phase, dirs[phase], STAMPS[phase], console)
        console.print(f"{phase.capitalize()} ZIP created: {layout.display_path(zip_name)}")
        console.print()

    run_timestamp = layout.timestamp()
    textcompare.write_compare_report(TICKET, dirs, run_timestamp, console)
    htmlreport.build_html_report(TICKET, dirs, run_timestamp, console)


if __name__ == "__main__":
    main()
