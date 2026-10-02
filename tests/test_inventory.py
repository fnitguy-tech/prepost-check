import os

import pytest

from modules.inventory import (
    EXAMPLE_INVENTORY,
    InventoryError,
    build_jobs,
    load_inventory,
    load_pairs,
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


def test_load_pairs_is_optional(tmp_path):
    assert load_pairs(os.path.join(str(tmp_path), "missing.yml")) == []

    plain = tmp_path / "plain.yml"
    plain.write_text("platforms:\n  - name: arista\n    device_type: arista_eos\n    hosts: [a]\n    commands: [show version]\n")
    assert load_pairs(str(plain)) == []


def test_load_pairs_reads_and_validates(tmp_path):
    good = tmp_path / "good.yml"
    good.write_text("pairs:\n  - [CORE-EAST, CORE-WEST]\n  - [FW-A, FW-B]\n")
    assert load_pairs(str(good)) == [["CORE-EAST", "CORE-WEST"], ["FW-A", "FW-B"]]

    bad = tmp_path / "bad.yml"
    bad.write_text("pairs:\n  - [ONLY-ONE]\n")
    with pytest.raises(InventoryError):
        load_pairs(str(bad))

    # load_inventory applies the same check so a typo fails before collection.
    bad_inventory = tmp_path / "bad_inventory.yml"
    bad_inventory.write_text(
        "pairs: CORE-EAST\nplatforms:\n  - name: arista\n    device_type: arista_eos\n"
        "    hosts: [a]\n    commands: [show version]\n"
    )
    with pytest.raises(InventoryError):
        load_inventory(str(bad_inventory))
