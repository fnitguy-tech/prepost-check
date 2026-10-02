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
        |                  per device, zipped per run; --redact-secrets
        |                  passes output through modules/redact.py first
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
  `modules/textcompare.py` and `modules/htmlreport.py` (the IPsec/IKE/LSVPN
  rule lives once in `textcompare.py` and is imported by the HTML report), each commented
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

- **One finding shape, many parsers.** Every interpreted finding is a
  dict with the same keys (classification, category, impact, title,
  subject, fields, summary, evidence, optional detail lines). The
  renderer, the health verdict, the attention list, the per-device
  impact score and the charts only ever see that shape, so adding a new
  interpretation (prefix-lists were the first after BGP) means writing
  a parser and a rating function, never a new rendering path.

- **Prefix-lists are rated per entry, not per line.** `show ip
  prefix-list` (or the running config, when the command is not in the
  inventory) is parsed into `{list: {seq: rule}}` with hit counters
  stripped. An entry that vanished and was not re-added elsewhere is a
  withdrawn advertisement (Attention); a sequence whose entry changed in
  place is the EOS replace-by-sequence overwrite (Attention); a moved
  entry is Changed; a new sequence is Stable. The raw config diff cannot
  tell those four apart.

- **The BGP Up/Down timer is churn in the diff and signal in the
  report.** Both diff normalizers strip it, correctly: it differs on
  every capture. The interpreted layer keeps it, because a session that
  reset and recovered reads `Estab -> Estab` with identical prefix
  counts and a smaller uptime is the only trace it leaves. The reset
  rule accounts for the coarse EOS formats (`1d02h` is anywhere in
  [26h, 27h)) by requiring post + its granularity <= pre, and treats an
  unparsable value (`never`) as no evidence rather than a guess. PAN-OS
  `show routing protocol bgp peer` blocks are parsed into the same
  per-peer dicts so firewall peers get the same findings.

- **Pairs are compared against each other, not just against their own
  precheck.** A change applied to one member of a redundant pair leaves
  "SW-1 and SW-2 now disagree" as its real signature, which a strictly
  per-device report cannot see. `analyze()` therefore runs in passes:
  per-device findings first, then pair symmetry on the two postcheck
  captures (same-named prefix-lists and route-maps entry for entry,
  PAN-OS HA state minus role-dependent keys), then counts. A pair
  finding is appended to both members (both devices' attention counts
  and impact scores rise) but counted once in the network totals. Pairs
  are inferred from hostnames differing only by a trailing number;
  bare-IP capture names and groups of three or more are never paired;
  the inventory's optional `pairs:` list covers the rest, and compare.py
  reads the inventory for that list only, so it still works without one.

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

- **Secrets in captures are the user's call, off by default.** A
  running-config capture is evidence precisely because it is verbatim,
  and it carries every password hash, BGP/OSPF key, SNMP community and
  PAN-OS encrypted value on the device. `--redact-secrets` replaces
  those values with `<REDACTED>` in `modules/collect.py` before the
  file is written, so nothing downstream (zip, text diff, HTML report)
  ever sees them. Redaction keeps the keyword and type marker and drops
  only the value: an added or removed credential still diffs; a rotated
  one does not. Rules in `modules/redact.py` are per-pattern and
  commented like the normalization rules, with two keyword-free
  catch-alls (crypt-style hashes, PAN-OS `-AQ==` blobs) as a backstop.

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
