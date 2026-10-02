"""Expected BGP prefix deltas for one change.

Every prefix-count change used to carry the same hedge ("this may be
expected when routing policy ... change"), and a caveat on everything
is a caveat on nothing. An expectations file states, per device and
peer, what the change was supposed to do to the prefix count; the HTML
report then rates a matching delta Stable ("as planned"), a delta that
differs from or has no expectation Attention, and an expected change
that did not happen Attention too. The hedge text survives only when
no expectations file is in play at all.

File: reports/<TICKET>/expectations.yml by default, or --expectations
on scripts/compare.py. Schema:

    ticket: NET-123                 # optional; must match when present
    expectations:
      - device: SITE-A-SW-2         # capture hostname, case-insensitive
        peer: 10.0.0.1              # neighbor IP or description column
        expected_delta: +3          # change in prefixes received, or
      - device: SITE-A-SW-1
        peer: ISP-B
        expected_prefixes: 815      # absolute prefixes received after
        note: full table minus bogons   # optional, shown in the finding
"""

import os

import yaml

from modules.layout import REPO_ROOT

EXAMPLE_EXPECTATIONS = os.path.join(REPO_ROOT, "docs", "demo", "NET-DEMO", "expectations.yml")


class ExpectationsError(Exception):
    """Raised when the expectations file is missing or malformed."""


def load_expectations(path, ticket=None):
    """Parse and validate an expectations file; return its entry list."""
    if not os.path.exists(path):
        raise ExpectationsError(f"Expectations file not found: {path}\nSee {EXAMPLE_EXPECTATIONS} for the format.")

    with open(path, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if not isinstance(data, dict) or not isinstance(data.get("expectations"), list):
        raise ExpectationsError(f"{path}: expected a top-level 'expectations' list.")

    file_ticket = data.get("ticket")

    if ticket and file_ticket and str(file_ticket).strip().upper() != ticket.strip().upper():
        raise ExpectationsError(f"{path}: file is for ticket {file_ticket}, this report is for {ticket}.")

    entries = []

    for index, entry in enumerate(data["expectations"]):
        label = f"expectations[{index}]"

        if not isinstance(entry, dict):
            raise ExpectationsError(f"{path}: {label} must be a mapping.")

        for key in ("device", "peer"):
            if not isinstance(entry.get(key), str) or not entry[key].strip():
                raise ExpectationsError(f"{path}: {label} is missing '{key}'.")

        has_delta = "expected_delta" in entry
        has_total = "expected_prefixes" in entry

        if has_delta == has_total:
            raise ExpectationsError(
                f"{path}: {label} needs exactly one of 'expected_delta' or 'expected_prefixes'."
            )

        value_key = "expected_delta" if has_delta else "expected_prefixes"
        value = entry[value_key]

        # YAML reads "+3" as the int 3, "3" as 3; a quoted "+3" arrives
        # as a string and is accepted too.
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise ExpectationsError(f"{path}: {label}: '{value_key}' must be an integer.")

        try:
            value = int(str(value).strip())
        except ValueError as error:
            raise ExpectationsError(f"{path}: {label}: '{value_key}' must be an integer.") from error

        note = entry.get("note")

        entries.append({
            "device": entry["device"].strip(),
            "peer": entry["peer"].strip(),
            value_key: value,
            "note": str(note).strip() if note is not None else "",
        })

    return entries


def for_device(expectations, hostname):
    """The entries for one capture hostname, or None when no file is in play."""
    if expectations is None:
        return None

    return [entry for entry in expectations if entry["device"].lower() == hostname.lower()]


def match_peer(expectations, peer):
    """The first entry naming this peer by description or IP, or None."""
    for entry in expectations or []:
        if entry["peer"].lower() in (peer["name"].lower(), peer["ip"].lower()):
            return entry

    return None


def describe(entry):
    """Human form of what an entry expects: '+3' or '815 prefixes'."""
    if "expected_delta" in entry:
        return f"a change of {entry['expected_delta']:+d}"

    return f"{entry['expected_prefixes']} prefixes received"
