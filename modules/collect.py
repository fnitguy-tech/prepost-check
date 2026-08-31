"""State collection over SSH.

Connects to every device in parallel (netmiko), runs that platform's
command list, and writes one timestamped text file per device. A device
that cannot be reached gets a <host>_FAILED.txt marker instead of
killing the run - during a maintenance window an unreachable device is
itself a finding, not a reason to abort evidence collection.

Output files use "### <command> ###" section headers; the compare
modules parse those headers to diff command-by-command.
"""

import os
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from netmiko import ConnectHandler
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

# How to ask each platform for its own hostname, so output files are
# named after the device and not its management IP. Unknown platforms
# fall back to the IP.
HOSTNAME_LOOKUPS = {
    "arista_eos": ("show hostname", "Hostname:"),
    "paloalto_panos": ("show system info | match hostname", "hostname:"),
}

MAX_WORKERS = 5
COMMAND_READ_TIMEOUT = 180  # seconds; "show ip bgp" on a full table is slow


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


def collect_device(job, folder_name, progress, overall_task):
    device = job["device"]
    commands = job["commands"]

    try:
        progress.console.log(f"Connecting to {device['host']}...")

        conn = ConnectHandler(**device)

        hostname = get_hostname(conn, device["device_type"], device["host"])
        progress.console.log(f"Connected to {hostname}")

        file_path = os.path.join(folder_name, f"{hostname}.txt")

        with open(file_path, "w", encoding="utf-8") as file:
            file.write(f"Hostname: {hostname}\n")
            file.write(f"IP Address: {device['host']}\n")
            file.write(f"Generated: {datetime.now()}\n")
            file.write("=" * 80 + "\n")

            for command in commands:
                progress.update(overall_task, description=f"{hostname}")

                try:
                    output = conn.send_command(command, read_timeout=COMMAND_READ_TIMEOUT)
                except Exception as cmd_error:
                    output = f"COMMAND FAILED:\n{cmd_error}"

                file.write(f"\n\n### {command} ###\n")
                file.write("-" * 80 + "\n")
                file.write(output)
                file.write("\n")

                progress.advance(overall_task, 1)

        conn.disconnect()

    except Exception as error:
        progress.console.log(f"FAILED: {device['host']}")
        progress.console.log(str(error))

        failed_file = os.path.join(folder_name, f"{device['host']}_FAILED.txt")

        with open(failed_file, "w", encoding="utf-8") as file:
            file.write(f"FAILED TO CONNECT TO {device['host']}\n")
            file.write(str(error))

        # Still advance the bar for the commands this device would have run.
        progress.advance(overall_task, len(commands))


def create_zip(folder_name, zip_name):
    with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for file_name in os.listdir(folder_name):
            file_path = os.path.join(folder_name, file_name)
            zip_file.write(file_path, arcname=file_name)


def run_collection(jobs, phase, phase_dir, run_timestamp, console):
    """Collect all devices for one phase ('precheck' or 'postcheck').

    Returns (folder_name, zip_name) of the run that was just written.
    """
    folder_name = os.path.join(phase_dir, f"{phase}_{run_timestamp}")
    zip_name = os.path.join(phase_dir, f"{phase}_{run_timestamp}.zip")

    os.makedirs(folder_name, exist_ok=True)

    total_commands = sum(len(job["commands"]) for job in jobs)

    with Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:

        overall_task = progress.add_task(
            f"{phase.capitalize()} Progress",
            total=total_commands,
        )

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [
                executor.submit(collect_device, job, folder_name, progress, overall_task)
                for job in jobs
            ]

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as error:
                    progress.console.log(f"Thread failed: {error}")

    create_zip(folder_name, zip_name)

    return folder_name, zip_name
