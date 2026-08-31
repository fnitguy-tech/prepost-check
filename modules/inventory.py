"""Device inventory loading.

Devices live in inventory/devices.yml (gitignored - it names real
hosts). Copy inventory/devices.example.yml and edit. The file groups
devices by platform; each platform carries the netmiko device_type and
the list of show commands to capture for that platform, so adding a
device or a command never means touching Python.
"""

import getpass
import os

import yaml

from modules.layout import REPO_ROOT

DEFAULT_INVENTORY = os.path.join(REPO_ROOT, "inventory", "devices.yml")
EXAMPLE_INVENTORY = os.path.join(REPO_ROOT, "inventory", "devices.example.yml")


class InventoryError(Exception):
    """Raised when the inventory file is missing or malformed."""


def load_inventory(path=None):
    """Parse and validate the inventory; return the platform list."""
    path = path or DEFAULT_INVENTORY

    if not os.path.exists(path):
        raise InventoryError(
            f"Inventory not found: {path}\n"
            f"Copy {EXAMPLE_INVENTORY} to {DEFAULT_INVENTORY} "
            "and fill in your devices."
        )

    with open(path, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if not isinstance(data, dict) or not isinstance(data.get("platforms"), list):
        raise InventoryError(f"{path}: expected a top-level 'platforms' list.")

    platforms = data["platforms"]

    for index, platform in enumerate(platforms):
        label = platform.get("name", f"platforms[{index}]")

        for key in ("name", "device_type", "hosts", "commands"):
            if not platform.get(key):
                raise InventoryError(f"{path}: platform '{label}' is missing '{key}'.")

        if not isinstance(platform["hosts"], list) or not isinstance(platform["commands"], list):
            raise InventoryError(f"{path}: platform '{label}': 'hosts' and 'commands' must be lists.")

    return platforms


def build_jobs(platforms, username, password):
    """Flatten platforms into one collection job per device."""
    jobs = []

    for platform in platforms:
        for host in platform["hosts"]:
            jobs.append({
                "device": {
                    "device_type": platform["device_type"],
                    "host": host,
                    "username": username,
                    "password": password,
                },
                "commands": platform["commands"],
            })

    return jobs


def prompt_credentials(username=None):
    """Ask for SSH credentials; password is never echoed or stored."""
    if not username:
        username = input("Username: ")

    password = getpass.getpass("Password: ")

    return username, password
