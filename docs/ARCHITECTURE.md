# prepost-check - Architecture

## Overview

The tool is a three-stage pipeline, one entry point per stage
(`scripts/precheck.py`, `scripts/postcheck.py`, `scripts/compare.py`),
all sharing the same modules:

```
inventory/devices.yml
        |
        v
  modules/inventory.py     load + validate platforms, hosts, command lists
        |
        v
  modules/collect.py       parallel SSH capture (netmiko), one text file
        |                  per device, zipped per run
        v
  reports/<TICKET>/...     modules/layout.py owns the directory scheme
        |
        +--> modules/textcompare.py   quick .txt diff (on-call view)
        +--> modules/htmlreport.py    interpreted HTML dashboard
```

Capture files use `### <command> ###` section headers; both compare
modules parse those headers to diff command-by-command rather than
whole-file.

## Design decisions worth recording

- **Normalization is per-command, not global.** Raw `show` output can
  never be diffed as-is: uptimes, ARP/MAC age timers, and BGP message
  counters change between any two captures. Each command has its own
  rule that strips the expected churn while keeping the operationally
  meaningful columns (a BGP peer's state and prefix counts survive;
  its up/down timer does not). The rules live next to the diff code in
  `modules/textcompare.py` and `modules/htmlreport.py`, each commented
  with what it strips and why. Commands too volatile to ever diff
  usefully (per-lane optics readings) are still captured as evidence
  but listed in a skip-compare list.

- **Two reports, deliberately different.** The .txt compare is the
  fast on-call answer to "what changed" - tight normalization, minimal
  context. The HTML report answers "does it matter": it parses BGP
  summaries into per-peer state, correlates peer changes with config
  diffs, classifies every change into a category, and scores
  per-device impact. Its normalization is looser on purpose so the
  collapsible raw-diff evidence sections read naturally.

- **An unreachable device is a finding, not an abort.** During a
  maintenance window, a device that stopped answering SSH is exactly
  the kind of thing the evidence should show. Collection records it as
  `<host>_FAILED.txt` and carries on with the rest of the fleet.

- **Read-only by design.** Everything sent to a device is a `show`
  command. The one exception, PAN-OS
  `set cli config-output-format set`, only changes how the config is
  displayed for the capture session (set-format output diffs
  line-by-line; the default XML tree does not) - it modifies nothing
  on the device.

- **No stored credentials.** The scripts prompt for SSH credentials at
  run time (username can be a flag; the password never is). This is a
  portable tool meant to run against arbitrary environments, so it
  deliberately keeps no secrets store, no credential files, and
  nothing to leak - stricter than a gitignored credentials file.

- **Evidence is keyed by ticket.** `modules/layout.py` anchors all
  output to `reports/<TICKET>/` at the repo root (not the current
  working directory), so one change's evidence never mixes with
  another's and the scripts behave the same wherever they are invoked
  from.

- **The HTML report is one self-contained file** so it can be attached
  to a change ticket as-is. Chart.js from a CDN is its only external
  asset; everything else (styles, data, raw diffs) is inlined.

- **Tests run fully offline.** The suite exercises the normalization
  rules, BGP parsing, finding classification, and both report
  generators against synthetic capture files, so parser changes are
  validated without touching a live network.
