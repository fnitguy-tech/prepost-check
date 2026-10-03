"""The local server behind the window.

The window is a webview pointed at this, so the UI is HTML and CSS and the
logic stays in Python. The same server answers a browser, which is the
fallback when the webview packages are not installed.

It is deliberately hard to reach from anywhere else:

* it binds 127.0.0.1 and refuses to start on any other address;
* every request that reads or changes anything needs a token generated at
  startup, so another account on the same machine cannot drive it. The
  three static assets are exempt, because a relative <link> loses the
  query string and because an HTML shell, a stylesheet and a script that
  can do nothing without a token are not worth guarding;
* no request names a path. Reports are named by their repo-relative label
  and re-resolved under reports/; capture runs are named by ticket, phase
  and timestamp. There is no path to traverse out of.

It holds no state that outlives the process. Close the window and the
token, the job history and the password are gone with it.
"""

import json
import mimetypes
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from modules.ui import api
from modules.ui.jobs import JobRunner

ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")

# Big enough that guessing is not a strategy, short enough to live in a URL.
TOKEN_BYTES = 24


class AppServer:
    """The HTTP server, its job runner and its token."""

    def __init__(self, host="127.0.0.1", port=0, native=False):
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError(
                f"refusing to bind {host}: this serves SSH credentials and a job runner, "
                "so it is loopback only"
            )

        self.token = secrets.token_urlsafe(TOKEN_BYTES)
        # The page needs to know, because a report link that opens a tab in
        # a browser does nothing at all in a webview. See /api/open.
        self.native = native
        self.runner = JobRunner()
        self.httpd = ThreadingHTTPServer((host, port), _make_handler(self))
        self.httpd.daemon_threads = True

    @property
    def port(self):
        return self.httpd.server_address[1]

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}/?t={self.token}"

    def serve_forever_in_background(self):
        thread = threading.Thread(target=self.httpd.serve_forever, daemon=True, name="ui-server")
        thread.start()

        return thread

    def shutdown(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _make_handler(app):
    # The inert shell. Everything else needs the token.
    PUBLIC_PATHS = frozenset({"/", "/index.html", "/app.css", "/app.js"})

    class Handler(BaseHTTPRequestHandler):
        server_version = "prepost-check-ui"

        # The page is the log. A request line per poll would bury it.
        def log_message(self, *_args):
            return

        # -- plumbing -------------------------------------------------
        def _send(self, status, body, content_type="application/json"):
            payload = body if isinstance(body, bytes) else str(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            # The page loads only its own assets, talks only to this origin,
            # and is never framed.
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'self'; "
                "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
            )
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()

            if self.command != "HEAD":
                self.wfile.write(payload)

        def _json(self, status, payload):
            self._send(status, json.dumps(payload))

        def _authorised(self, query):
            supplied = (query.get("t") or [None])[0] or self.headers.get("X-Auth-Token")

            return bool(supplied) and secrets.compare_digest(supplied, app.token)

        def _body(self):
            length = int(self.headers.get("Content-Length") or 0)

            if not length:
                return {}

            try:
                return json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError as error:
                raise api.ApiError(f"malformed request body: {error}") from error

        # -- routing --------------------------------------------------
        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's name
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)

            if parsed.path not in PUBLIC_PATHS and not self._authorised(query):
                self._json(403, {"error": "bad or missing token"})
                return

            try:
                self._route_get(parsed.path, query)
            except api.ApiError as error:
                self._json(400, {"error": str(error)})
            except Exception as error:  # noqa: BLE001 - the page shows it
                self._json(500, {"error": f"{type(error).__name__}: {error}"})

        def do_POST(self):  # noqa: N802
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)

            if not self._authorised(query):
                self._json(403, {"error": "bad or missing token"})
                return

            try:
                self._route_post(parsed.path, self._body())
            except api.ApiError as error:
                self._json(400, {"error": str(error)})
            except RuntimeError as error:
                self._json(409, {"error": str(error)})
            except Exception as error:  # noqa: BLE001 - the page shows it
                self._json(500, {"error": f"{type(error).__name__}: {error}"})

        def _route_get(self, path, query):
            if path in ("/", "/index.html"):
                self._asset("index.html")
                return

            if path in ("/app.css", "/app.js"):
                self._asset(path.lstrip("/"))
                return

            if path == "/api/state":
                ticket = (query.get("ticket") or [None])[0]
                self._json(200, {**api.state(ticket), "token": app.token, "native": app.native})
                return

            if path == "/api/plan":
                self._json(200, api.plan((query.get("inventory") or [None])[0]))
                return

            if path == "/api/notes":
                self._json(200, api.notes_for((query.get("ticket") or [""])[0]))
                return

            if path == "/api/jobs":
                self._json(200, {"jobs": app.runner.recent()})
                return

            if path == "/api/job":
                job = app.runner.get(int((query.get("id") or [0])[0]))
                self._json(200, job.state() if job else {"error": "no such job"})
                return

            if path == "/report":
                self._report((query.get("name") or [""])[0])
                return

            self._json(404, {"error": f"no route for {path}"})

        def _route_post(self, path, body):
            if path == "/api/notes":
                self._json(200, api.save_notes(body.get("ticket", ""), body.get("text", "")))
                return

            if path == "/api/open":
                self._json(200, api.open_report(body.get("name", "")))
                return

            if path == "/api/notes/seed":
                self._json(200, api.seed_notes(body.get("ticket", "")))
                return

            if path == "/api/capture":
                job = api.capture(
                    app.runner,
                    body.get("phase", ""),
                    body.get("ticket", ""),
                    body.get("username", ""),
                    body.get("password", ""),
                    inventory_path=body.get("inventory") or None,
                    redact=bool(body.get("redact")),
                )
                self._json(202, job.state())
                return

            if path == "/api/report":
                self._json(202, api.build_report(app.runner, body.get("ticket", "")).state())
                return

            if path == "/api/compare-runs":
                job = api.compare_runs(
                    app.runner,
                    body.get("before") or {},
                    body.get("after") or {},
                    allow_reversed=bool(body.get("allow_reversed")),
                )
                self._json(202, job.state())
                return

            self._json(404, {"error": f"no route for {path}"})

        # -- files ----------------------------------------------------
        def _asset(self, name):
            path = os.path.join(ASSETS_DIR, name)

            if not os.path.isfile(path):
                self._json(404, {"error": f"missing asset {name}"})
                return

            with open(path, "rb") as file:
                body = file.read()

            kind = mimetypes.guess_type(name)[0] or "application/octet-stream"
            self._send(200, body, f"{kind}; charset=utf-8" if kind.startswith("text") else kind)

        def _report(self, name):
            path = api.resolve_report(name)

            if path is None:
                self._json(404, {"error": "that report is not under reports/"})
                return

            with open(path, "rb") as file:
                body = file.read()

            kind = "text/html" if path.endswith(".html") else "text/plain"
            # A generated report inlines its own styles and loads Chart.js
            # from a CDN, so it gets a policy of its own rather than the
            # app's, which allows neither.
            self.send_response(200)
            self.send_header("Content-Type", f"{kind}; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

    return Handler
