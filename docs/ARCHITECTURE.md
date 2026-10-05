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
                   ^
  reports/<TICKET>/notes.md           modules/notes.py: your account of
                                      the window, rendered above the
                                      findings (optional, by hand)
```

Capture files use `### <command> ###` section headers with an 80-dash
rule under each. Both compare modules read them through
`modules/captures.py`, and diff command-by-command rather than
whole-file. A header only counts when the dash rule follows it, so a
banner line like `### AUTHORIZED USE ONLY ###` inside a config stays
part of the config.

## Design decisions worth recording

- **Normalization is per-command, not global.** Raw `show` output can
  never be diffed as-is: uptimes, ARP/MAC age timers, and BGP message
  counters change between any two captures. Each command has its own
  rule. It strips the expected churn and keeps the columns that matter.
  A BGP peer's state and prefix counts survive; its up/down timer does
  not.

  The rules sit next to the diff code, in `modules/textcompare.py` and
  `modules/htmlreport.py`, each commented with what it strips and why.
  The IPsec/IKE/LSVPN rule lives once in `textcompare.py` and the HTML
  report imports it. A command too volatile to diff usefully, like
  per-lane optics readings, is still captured as evidence but named in a
  skip-compare list.

- **Two reports that answer different questions.** The .txt compare is
  the fast on-call answer to "what changed" - tight normalization,
  minimal context.

  The HTML report answers "does it matter". It parses BGP summaries into
  per-peer state, ties peer changes to config diffs, sorts changes into
  categories, and scores each device's impact. Its normalization is
  looser, so the collapsible raw-diff evidence reads naturally.

- **One finding shape, many parsers.** Every interpreted finding is a
  dict with the same keys (classification, category, impact, title,
  subject, fields, summary, evidence, optional detail lines). The
  renderer, the health verdict, the attention list, the impact score and
  the charts only ever see that shape. So a new interpretation means
  writing a parser and a rating function, never a new rendering path.
  Prefix-lists were the first one added after BGP.

- **Prefix-lists are rated per entry, not per line.** `show ip
  prefix-list` (or the running config, when the command is not in the
  inventory) is parsed into `{list: {seq: rule}}` with hit counters
  stripped. Four outcomes, four ratings. An entry that vanished and did
  not come back elsewhere is Removed (Attention). A sequence whose entry
  changed in place is Replaced (Attention), the EOS
  replace-by-sequence trap. A moved entry is Changed. A new sequence is
  Stable. The raw config diff cannot tell those four apart.

- **The BGP Up/Down timer is churn in the diff and signal in the
  report.** Both diff normalizers strip it, correctly: it differs on
  every capture. The interpreted layer keeps it, because a session that
  reset and recovered reads `Estab -> Estab` with identical prefix
  counts. A smaller uptime is the only trace it leaves.

  The reset rule handles the coarse EOS formats, where `1d02h` is
  anywhere in [26h, 27h), by requiring post plus its granularity <= pre.
  An unparsable value like `never` counts as no evidence rather than a
  guess. PAN-OS
  `show routing protocol bgp peer` blocks are parsed into the same
  per-peer dicts so firewall peers get the same findings.

- **Pairs are compared against each other, not just against their own
  precheck.** Change one member of a redundant pair and the real
  signature is "SW-1 and SW-2 now disagree". A per-device report cannot
  see that. So `analyze()` runs in passes:
  per-device findings first, then pair symmetry on the two postcheck
  captures, then counts. Symmetry covers same-named prefix-lists and
  route-maps entry for entry, plus PAN-OS HA state minus the
  role-dependent keys.

  A pair finding goes on both members, so both devices' attention counts
  and impact scores rise, but it counts once in the network totals.

  Pairs come from hostnames differing only by a trailing number. Bare-IP
  capture names and groups of three or more are never paired. The
  inventory's optional `pairs:` list covers the rest, and compare.py
  reads the inventory for that list alone, so it still works without
  one.

- **"BGP-relevant" config means the policy objects, not just the
  `router bgp` block.** `BGP_CONFIG_KEYWORDS` in `htmlreport.py` names
  them (prefix-list, access-list/-group, peer-group, redistribution,
  bfd, link-state, PAN-OS `protocol bgp`, `valid-networks`,
  `auth-profile`, `used-by`, ...).

  EOS puts the keyword on the block header and the change on an indented
  line under it. So the diff walk tracks the enclosing header per side of
  the ndiff and emits it as a context line. That way "- seq 40 permit
  ..." arrives under "ip prefix-list ISP-OUT", where it means something.
  Context lines don't count as changes.

- **A new address on a down interface is rated; an unknown link state
  is not.** `interface_findings()` joins addresses (EOS `show ip
  interface brief`, PAN-OS `show interface all`, then the config) with
  link state (the same tables, then `show interfaces status`, with EOS
  short names expanded). Gained an address and up is Stable, gained an
  address and down is Attention. Status only ever comes from a show
  table, so a PAN-OS tunnel or a config-only address yields no finding
  rather than a guess.

- **The tool rates what it can see; you write down what it can't.** A
  prefix count that moved is `Changed` with the caveat that routing
  policy, communities, failover, and advertised routes all move it
  legitimately. Whether this move was meant to happen is a judgement, and
  the captures do not hold it. That belongs in the notes
  (`modules/notes.py`, `reports/<TICKET>/notes.md`), not in a rating.

  An earlier version took expected deltas as a YAML file and rated
  against them. There was no way to enter one short of hand-writing the
  schema mid-window. Worse, a file that parsed but held no entries turned
  every delta into Attention. The notes answer the same question without
  asking you to encode a judgement as data.

- **Don't diff the lines that already match.** A firewall's
  `show config running` is 78,180 lines and a window changes a few of
  them. But `SequenceMatcher`'s longest-match search gets slower than
  linearly as the input grows, and 70% of a 1.9 second report ran inside
  `find_longest_match`.

  `modules/difftrim.py` skips the matching lines at each end and emits
  them as the context lines they would have been. ndiff only ever sees
  the part that differs. That took the config from 795 ms to 11 ms, and
  the whole report from 1.9 s to about 0.5 s.

  It is not a drop-in for `difflib.ndiff` on any input. ndiff picks which
  of several equal lines to pair by searching the whole sequence.
  Trimming decides some of those by position, so a `+ !` can land
  somewhere else among sibling additions. The same lines are added and
  removed either way, and both tools run the same trim.
  `tests/test_difftrim.py` pins the agreement on config-shaped input and
  the known divergence.

- **An unreachable device is a finding, not an abort.** During a
  maintenance window, a device that stopped answering SSH is exactly
  the kind of thing the evidence should show. Collection records it as
  `<host>_FAILED.txt` and carries on with the rest of the fleet.

  The reports then treat "we couldn't check it" as the most serious
  result, not as nothing. `modules/captures.py` matches a FAILED file to
  the device's other capture by address, and both reports list it first
  as `Action Required`. The run itself ends with a summary line and a
  non-zero exit code (`1` some failed, `2` all failed).

- **One rejected password stops the run.** Central login servers lock an
  account after a few bad tries, and five parallel connections would use
  those up in a second. The first connection goes alone; the rest go in
  parallel only after a device has accepted the password.

- **A timeout ends that device's capture.** After a `ReadTimeout` the
  late output is still coming down the same connection, and the next
  command would read it as its own. The remaining commands are written
  as `SKIPPED after timeout on <command>`. Reconnecting was ruled out:
  it resets session settings such as PAN-OS
  `set cli config-output-format set`, and the config would come back in
  another format.

- **SSH host keys are trust-on-first-use.** netmiko's default accepts
  any key and remembers none. `modules/hostkeys.py` keeps the tool's own
  known-hosts file and refuses a changed key before the password is
  sent. It uses netmiko's supported options (`alt_host_keys`,
  `alt_key_file`, and a `key_policy` set on a connection built with
  `auto_connect=False`). New keys are appended one line at a time under
  a lock, because paramiko's own save rewrites the whole file and five
  connections at once could drop each other's lines.

- **A capture folder says whether it finished.** The last step of a run
  writes `capture-complete.json`. A folder stamped to the second without
  one was interrupted, and both reports warn. Folders stamped to the
  minute come from older versions that wrote no marker; they compare
  with a console note. The reports also warn when the before folder is
  newer than the after folder.

- **Read-only by design.** Everything sent to a device is a `show`
  command. There is one exception: PAN-OS
  `set cli config-output-format set`. That only changes how the config is
  printed for the capture session, because set-format output diffs line
  by line and the default XML tree does not. It modifies nothing on the
  device.

- **No stored credentials.** The scripts prompt for SSH credentials at
  run time. The username can be a flag; the password never is. This tool
  is meant to run against whatever environment you point it at, so it
  keeps no secrets store and no credential files. There is nothing to
  leak, which is stricter than a gitignored credentials file.

- **Secrets in captures are the user's call, off by default.** A
  running-config capture is evidence because it is verbatim. That means
  it carries every password hash, BGP/OSPF key, SNMP community, and
  PAN-OS encrypted value on the box.

  `--redact-secrets` replaces those values with `<REDACTED>` in
  `modules/collect.py` before the file is written. Nothing downstream
  sees them: not the zip, not the text diff, not the HTML report.

  It keeps the keyword and type marker and drops only the value, so an
  added or removed credential still diffs. A rotated one does not. Rules in `modules/redact.py` are per-pattern and
  commented like the normalization rules, with keyword-free
  catch-alls (crypt-style hashes, `$9$` values, PAN-OS `-AQ==` blobs) as
  a backstop. PEM private keys and the IOS-XE `radius server` /
  `tacacs server` block form span lines, so `scrub()` handles those
  before the per-line rules.

- **Evidence is keyed by ticket.** `modules/layout.py` anchors all
  output to `reports/<TICKET>/` at the repo root, not the current working
  directory. One change's evidence never mixes with another's, and the
  scripts behave the same wherever you run them from.

- **The HTML report is one self-contained file** so it can be attached
  to a change ticket as-is. Chart.js from a CDN is its only external
  asset; everything else (styles, data, raw diffs) is inlined. The
  script tag pins one Chart.js release and carries its SHA-384 hash, so
  the browser refuses a changed file. Without Chart.js the charts are
  replaced by a note and the rest of the report still reads. Values
  written into the script block have `<`, `>`, and `&` escaped, so a
  device name can't end the block.

- **Tests run fully offline.** Every test runs against synthetic capture
  files, so you can change a parser without touching a live network. They
  cover the normalization rules, BGP parsing, how findings get
  classified, and both report generators.
