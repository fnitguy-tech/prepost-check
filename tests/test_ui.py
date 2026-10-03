"""The desktop window's server, jobs and API.

The window is a second front door onto the same code the CLI runs, so what
needs testing here is not the interpretation - that is covered elsewhere -
but the boundary. Four properties matter:

* it binds loopback and refuses anything else;
* a request that reads or changes something needs the token, and the inert
  assets do not;
* no request names a path, so there is nothing to traverse out of;
* the SSH password reaches the job and never comes back.
"""

import json
import os
import urllib.error
import urllib.request

import pytest

from modules.ui import api
from modules.ui.jobs import JobRunner, ProgressSink
from modules.ui.server import AppServer


@pytest.fixture
def server():
    app = AppServer()
    app.serve_forever_in_background()
    yield app
    app.shutdown()


def fetch(app, path, body=None, token=None):
    token = app.token if token is None else token
    joiner = "&" if "?" in path else "?"
    url = f"http://127.0.0.1:{app.port}{path}{joiner}t={token}"
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"} if data else {}
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def fetch_json(app, path, body=None, token=None):
    status, raw = fetch(app, path, body, token)

    return status, json.loads(raw)


# -- the boundary ------------------------------------------------------

def test_it_refuses_to_bind_anything_but_loopback():
    """It serves SSH credentials and a job runner. Loopback or nothing."""
    for address in ("0.0.0.0", "192.168.1.10", ""):
        with pytest.raises(ValueError, match="loopback only"):
            AppServer(host=address)


def test_the_api_needs_the_token_and_the_assets_do_not(server):
    """A relative <link> loses the query string, so the shell is exempt.

    It is an HTML file, a stylesheet and a script that can do nothing
    without a token, and the things worth guarding stay guarded.
    """
    for path in ("/", "/app.css", "/app.js"):
        status, _ = fetch(server, path, token="wrong")
        assert status == 200, path

    for path in ("/api/state", "/api/plan", "/api/jobs", "/report?name=x"):
        status, body = fetch_json(server, path, token="wrong")
        assert status == 403, path
        assert body["error"] == "bad or missing token"

    status, _ = fetch_json(server, "/api/notes", {"ticket": "X", "text": "y"}, token="")
    assert status == 403


def test_no_request_can_name_a_path_outside_reports(server):
    for name in (
        "../../../etc/passwd",
        "/etc/passwd",
        "reports/../../etc/passwd",
        "reports/../.gitignore",
        "",
    ):
        status, body = fetch_json(server, f"/report?name={urllib.parse.quote(name)}")
        assert status == 404, name
        assert "under reports/" in body["error"]


def test_only_report_shaped_files_are_served(tmp_path, monkeypatch):
    """Even inside reports/, it serves reports - not whatever is there."""
    monkeypatch.setattr("modules.layout.REPORTS_DIR", str(tmp_path))
    monkeypatch.setattr("modules.layout.REPO_ROOT", str(tmp_path.parent))

    (tmp_path / "fine.html").write_text("<p>ok</p>", encoding="utf-8")
    (tmp_path / "secrets.yml").write_text("password: hunter2", encoding="utf-8")

    assert api.resolve_report(f"{tmp_path.name}/fine.html") is not None
    assert api.resolve_report(f"{tmp_path.name}/secrets.yml") is None
    assert api.resolve_report(f"{tmp_path.name}/absent.html") is None


def test_an_unknown_route_is_a_404_not_a_traceback(server):
    status, body = fetch_json(server, "/api/nope")
    assert status == 404
    assert "no route" in body["error"]


# -- the password ------------------------------------------------------

def test_a_jobs_public_state_cannot_carry_the_password():
    runner = JobRunner()
    job = runner.start("precheck", "NET-1", lambda j: {"ok": True}, password="hunter2")

    for _ in range(50):
        if job.status != "running":
            break
        import time

        time.sleep(0.02)

    assert "hunter2" not in json.dumps(job.state())
    # Cleared the moment the run ends, not merely left out of state().
    assert job._password is None


def test_a_capture_without_credentials_is_refused_before_any_ssh():
    runner = JobRunner()

    with pytest.raises(api.ApiError, match="username and password"):
        api.capture(runner, "precheck", "NET-1", "", "", inventory_path=None)

    with pytest.raises(api.ApiError, match="Unknown phase"):
        api.capture(runner, "sideways", "NET-1", "user", "pass")

    with pytest.raises(api.ApiError, match="ticket number"):
        api.capture(runner, "precheck", "", "user", "pass")

    assert runner.current() is None


# -- jobs --------------------------------------------------------------

def test_one_job_at_a_time():
    """Two captures of one ticket would race for the same run folder, and
    two SSH sweeps of a fleet is not something to start by accident."""
    import threading

    gate = threading.Event()
    runner = JobRunner()
    runner.start("precheck", "NET-1", lambda job: gate.wait(5))

    with pytest.raises(RuntimeError, match="still running"):
        runner.start("postcheck", "NET-1", lambda job: None)

    gate.set()


def test_a_job_that_raises_is_recorded_not_lost():
    runner = JobRunner()

    def explode(job):
        raise ValueError("the device said no")

    job = runner.start("report", "NET-1", explode)

    for _ in range(50):
        if job.status != "running":
            break
        import time

        time.sleep(0.02)

    assert job.status == "failed"
    assert "the device said no" in job.error
    assert job.state()["percent"] == 0


def test_the_progress_sink_speaks_rich_progress():
    """collect.py reports through whatever it is handed. This stands in for
    a terminal bar so a capture can report into a window."""
    runner = JobRunner()
    job = runner.start("precheck", "NET-1", lambda j: None)
    sink = ProgressSink(job)

    with sink as context:
        assert context is sink
        context.add_task("Precheck Progress", total=4)
        context.console.log("Connecting to 10.0.0.1...")
        context.advance(0, 2)
        context.update(0, description="SW-1")

    state = job.state()
    assert state["total"] == 4
    assert state["done"] == 2
    assert state["percent"] == 50
    assert state["detail"] == "SW-1"
    assert "Connecting to 10.0.0.1..." in state["lines"]


def test_the_log_is_bounded_so_a_stuck_run_cannot_grow_without_limit():
    runner = JobRunner()
    job = runner.start("precheck", "NET-1", lambda j: None)

    for index in range(900):
        job.add_line(f"line {index}")

    assert len(job.lines) == 400
    assert job.lines[-1] == "line 899"
    # The page is shown a window onto the tail, not the whole buffer.
    assert len(job.state()["lines"]) == 60


# -- the plan ----------------------------------------------------------

def test_the_plan_reports_a_missing_inventory_instead_of_raising(server):
    status, plan = fetch_json(server, "/api/plan?inventory=/nope/absent.yml")

    assert status == 200
    assert plan["ok"] is False
    assert "not found" in plan["error"]
    assert plan["devices"] == []


def test_the_plan_counts_what_a_capture_would_run():
    """Shown next to the buttons: a read-only sweep is still a sweep."""
    plan = api.plan("inventory/devices.example.yml")

    assert plan["ok"] is True
    assert plan["read_only"] is True
    assert len(plan["devices"]) == 5
    assert plan["commands"] == sum(device["commands"] for device in plan["devices"])


# -- parity with the CLI -----------------------------------------------

def _write(path, version):
    with open(path, "w", encoding="utf-8") as file:
        file.write(f"### show version ###\n{version}\n")


def test_a_postcheck_from_the_window_writes_the_text_compare(tmp_path, monkeypatch):
    """`scripts/postcheck.py` writes compare_<stamp>.txt the moment it
    finishes. A postcheck started from the window has to leave the same two
    files behind, or the front door you chose changes what you get."""
    import time

    from modules import collect, inventory, layout

    monkeypatch.setattr(layout, "REPORTS_DIR", str(tmp_path))
    monkeypatch.setattr(layout, "REPO_ROOT", str(tmp_path.parent))

    dirs = layout.ticket_dirs("NET-1")
    pre = f"{dirs['precheck']}/precheck_2026-01-01_00-00"
    os.makedirs(pre)
    _write(f"{pre}/sw-1.txt", "4.35.4M")

    def fake_collection(jobs, phase, phase_dir, stamp, console, **kwargs):
        folder = os.path.join(phase_dir, f"{phase}_{stamp}")
        os.makedirs(folder, exist_ok=True)
        _write(f"{folder}/sw-1.txt", "4.35.5M")

        return folder, f"{folder}.zip"

    monkeypatch.setattr(collect, "run_collection", fake_collection)
    monkeypatch.setattr(
        inventory, "load_inventory",
        lambda path: [{"name": "a", "device_type": "arista_eos",
                       "hosts": ["10.0.0.1"], "commands": ["show version"]}],
    )

    runner = JobRunner()
    job = api.capture(runner, "postcheck", "NET-1", "user", "pass")

    for _ in range(100):
        if job.status != "running":
            break
        time.sleep(0.02)

    assert job.status == "done", job.error
    written = os.listdir(dirs["compare"])
    assert [name for name in written if name.endswith(".txt")], written
    assert any("wrote" in line for line in job.lines), job.lines


# -- the assets ---------------------------------------------------------

def test_the_assets_match_their_recorded_hashes():
    """The Rust port serves these same three files from its own copy.

    Two repositories, one page. There is no build step to tie them
    together, so the hashes are recorded in both and checked in both: edit
    the CSS here without carrying it over and this fails, which is the
    only warning either side gets.
    """
    import hashlib

    from modules.ui.server import ASSETS_DIR

    recorded = os.path.join(ASSETS_DIR, "ASSET_SHA256")

    with open(recorded, encoding="utf-8") as file:
        lines = [line.split() for line in file if line.strip()]

    assert len(lines) == 3, "index.html, app.css and app.js"

    for digest, name in lines:
        with open(os.path.join(ASSETS_DIR, name), "rb") as asset:
            actual = hashlib.sha256(asset.read()).hexdigest()

        assert actual == digest, (
            f"{name} changed. Update modules/ui/assets/ASSET_SHA256 and copy the "
            "file to netshell's crates/mw-check/assets/ as well."
        )


# -- opening a report ---------------------------------------------------

def test_the_window_hands_a_report_to_the_real_browser(tmp_path, monkeypatch):
    """A report link is target="_blank". A browser opens a tab; a webview
    has no tabs, so the click does nothing. In the window the page posts
    here instead, and the file goes to the machine's browser."""
    opened = []

    monkeypatch.setattr("modules.layout.REPORTS_DIR", str(tmp_path))
    monkeypatch.setattr("modules.layout.REPO_ROOT", str(tmp_path.parent))
    monkeypatch.setattr("webbrowser.open", lambda url: opened.append(url))

    report = tmp_path / "NET-1" / "Compare" / "compare_x.html"
    report.parent.mkdir(parents=True)
    report.write_text("<p>ok</p>", encoding="utf-8")

    label = os.path.join(tmp_path.name, "NET-1", "Compare", "compare_x.html")
    assert api.open_report(label)["opened"] == label
    # The file itself, not the server's URL: no token in the address bar,
    # and it still works once the app is closed.
    assert opened == [f"file://{report}"]

    for refused in ("", "../../../etc/passwd", os.path.join(tmp_path.name, "NET-1", "notes.md.x")):
        with pytest.raises(api.ApiError, match="under reports/"):
            api.open_report(refused)

    assert len(opened) == 1


def test_the_page_is_told_which_front_door_it_came_through(server):
    """`--serve` means a browser, which handles target="_blank" itself."""
    _status, state = fetch_json(server, "/api/state")
    assert state["native"] is False

    native = AppServer(native=True)
    try:
        native.serve_forever_in_background()
        _status, state = fetch_json(native, "/api/state")
        assert state["native"] is True
    finally:
        native.shutdown()
