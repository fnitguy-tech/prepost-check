#!/usr/bin/env python3
"""Run the compare pipeline on the bundled fictional dataset - no devices needed.

Copies docs/demo/NET-DEMO/ (pre + post captures from a made-up uplink
migration at SITE-A; see SCENARIO.md there) into reports/NET-DEMO/, then
writes the quick text diff and the interpreted HTML report exactly as
scripts/postcheck.py and scripts/compare.py would after a real window.

Usage:
    python3 scripts/demo.py
"""

import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console

from modules import htmlreport, layout, textcompare

TICKET = "NET-DEMO"
DEMO_SRC = os.path.join(layout.REPO_ROOT, "docs", "demo", TICKET)


def main(console=None):
    console = console or Console(highlight=False)
    dirs = layout.ticket_dirs(TICKET)

    # Stage the captures where the real scripts would have written them.
    for phase, key in (("Precheck", "precheck"), ("Postcheck", "postcheck")):
        shutil.copytree(os.path.join(DEMO_SRC, phase), dirs[key], dirs_exist_ok=True)

    console.print(f"[bold]{TICKET}[/bold]: fictional SITE-A uplink migration, 4 devices, captures staged from docs/demo/")
    console.print()

    run_timestamp = layout.timestamp()
    textcompare.write_compare_report(TICKET, dirs, run_timestamp, console)
    htmlreport.build_html_report(TICKET, dirs, run_timestamp, console)


if __name__ == "__main__":
    main()
