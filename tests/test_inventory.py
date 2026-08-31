import os

import pytest

from modules.inventory import (
    EXAMPLE_INVENTORY,
    InventoryError,
    build_jobs,
    load_inventory,
)


def test_example_inventory_loads():
    platforms = load_inventory(EXAMPLE_INVENTORY)

    assert [p["name"] for p in platforms] == ["arista", "paloalto"]
    assert platforms[0]["device_type"] == "arista_eos"
    assert "show running-config" in platforms[0]["commands"]
    assert "show config running" in platforms[1]["commands"]


def test_build_jobs_one_per_host():
    platforms = load_inventory(EXAMPLE_INVENTORY)
    jobs = build_jobs(platforms, "admin", "secret")

    total_hosts = sum(len(p["hosts"]) for p in platforms)
    assert len(jobs) == total_hosts

    first = jobs[0]
    assert first["device"]["username"] == "admin"
    assert first["device"]["password"] == "secret"
    assert first["device"]["device_type"] == "arista_eos"
    assert first["commands"] == platforms[0]["commands"]


def test_missing_inventory_points_at_example(tmp_path):
    missing = os.path.join(str(tmp_path), "nope.yml")

    with pytest.raises(InventoryError) as excinfo:
        load_inventory(missing)

    assert "devices.example.yml" in str(excinfo.value)


def test_malformed_inventory_rejected(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("platforms:\n  - name: arista\n    hosts: [192.0.2.1]\n")

    with pytest.raises(InventoryError):
        load_inventory(str(bad))
