#!/usr/bin/env python3
"""The desktop window.

Same work as the CLI, same code underneath - `precheck.py`, `postcheck.py`,
`compare.py` and `notes.py` all still do their jobs, and nothing here
replaces them. This is a second front door for people who would rather click
than remember four commands.

    python3 scripts/gui.py            # a native window
    python3 scripts/gui.py --serve    # print a URL for your browser instead

The window is a webview over a local server, so the interface is HTML and
CSS and every decision stays in Python. `--serve` is the same server without
the window, which is the fallback when the webview packages are missing.

The server binds 127.0.0.1 and nothing else, and every request carries a
token minted at startup, so another account on this machine cannot drive it.
The SSH password is held for one run and never written to disk, logged, or
sent back to the page.

The window needs pywebview:

    pip install -r requirements-gui.txt

and, on Linux, the system WebKitGTK and PyGObject packages. See that file.
`--serve` needs nothing beyond the normal requirements.
"""

import argparse
import os
import sys
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.ui.server import AppServer

WINDOW_TITLE = "Maintenance Window"


def parse_args():
    parser = argparse.ArgumentParser(
        description="The desktop window for pre/post maintenance checks.",
        epilog="The CLI scripts keep working either way; this changes nothing about them.",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="print a URL for your browser instead of opening a window",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="with --serve, open your default browser at that URL",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="port to bind on 127.0.0.1 (default: let the OS pick a free one)",
    )

    return parser.parse_args()


def serve(app, open_browser):
    """Hold the server open and print how to reach it.

    Every print in this script is flushed. The URL carries the token and is
    the only way in; piped into a file or a log, a buffered print leaves you
    with a server you cannot reach and no idea why.
    """
    print(f"Serving on {app.url}", flush=True)
    print("  Loopback only, and the token in that URL is required.", flush=True)
    print("  Every device command is a read-only show.", flush=True)
    print("  Ctrl-C to stop.", flush=True)

    if open_browser:
        webbrowser.open(app.url)

    try:
        app.httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.", flush=True)


def window(app):
    """Open the native window, or explain what is missing and fall back."""
    try:
        import webview
    except ImportError:
        print("The window needs pywebview, which is not installed:", flush=True)
        print("    pip install -r requirements-gui.txt", flush=True)
        print("\nServing in your browser instead.\n", flush=True)
        serve(app, open_browser=True)
        return

    app.serve_forever_in_background()
    webview.create_window(WINDOW_TITLE, app.url, width=1220, height=880, min_size=(900, 640))

    try:
        webview.start()
    except Exception as error:  # noqa: BLE001 - a missing GTK/WebKit backend
        print(f"The window could not open: {error}", flush=True)
        print("\nServing in your browser instead.\n", flush=True)
        serve(app, open_browser=True)


def main():
    args = parse_args()

    try:
        app = AppServer(port=args.port, native=not args.serve)
    except OSError as error:
        print(f"Could not start the local server: {error}", flush=True)
        return 1

    if args.serve:
        app.serve_forever_in_background()
        serve(app, open_browser=args.open)
    else:
        window(app)

    return 0


if __name__ == "__main__":
    sys.exit(main())
