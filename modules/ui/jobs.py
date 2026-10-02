"""One run of work, watched from the window.

A capture takes a minute against ten devices, so the window cannot wait for
it. Each action becomes a Job: it runs on its own thread, records what it is
doing as it goes, and the page asks for that record a few times a second.

The SSH password lives here and nowhere else. It is held on the job for as
long as the run needs it, cleared the moment the run ends, and never
written to disk, never logged, and never sent back to the page. A job's
public form - what `state()` returns - has no field that could carry it.
"""

import threading
import traceback
from datetime import datetime


class ProgressSink:
    """rich.Progress's interface, recording instead of drawing.

    `modules/collect.py` reports through whatever it is handed: add_task,
    update, advance, and a console with log(). Standing in for it here is
    what lets a capture report into a window without collect.py knowing a
    window exists.
    """

    def __init__(self, job):
        self.job = job
        self.console = self
        self.total = 0
        self.done = 0

    # -- the console half ---------------------------------------------
    def log(self, message, *_args, **_kwargs):
        self.job.add_line(str(message))

    # -- the progress half --------------------------------------------
    def add_task(self, description, total=0, **_kwargs):
        self.total = total or 0
        self.job.set_progress(self.done, self.total, description)
        return 0

    def update(self, _task, description=None, **_kwargs):
        if description:
            self.job.set_progress(self.done, self.total, description)

    def advance(self, _task, amount=1):
        self.done += amount
        self.job.set_progress(self.done, self.total)

    # -- used as a context manager by run_collection ------------------
    def __enter__(self):
        return self

    def __exit__(self, *_exception):
        return False


class Job:
    """One action: its lines, its progress, and how it ended."""

    def __init__(self, job_id, kind, ticket):
        self.id = job_id
        self.kind = kind
        self.ticket = ticket
        self.started = datetime.now()
        self.finished = None
        self.status = "running"
        self.error = None
        self.result = None
        self.detail = ""
        self.done = 0
        self.total = 0
        self.lines = []
        self._lock = threading.Lock()
        # Held only while the run needs it. See the module docstring.
        self._password = None

    def add_line(self, text):
        with self._lock:
            # A long capture logs per device and per failure; keeping the
            # last 400 lines is more than the page shows and bounds the
            # memory a stuck run can take.
            self.lines.append(text)
            del self.lines[:-400]

    def set_progress(self, done, total, detail=None):
        with self._lock:
            self.done = done
            self.total = total

            if detail is not None:
                self.detail = detail

    def finish(self, result=None):
        with self._lock:
            self.status = "done"
            self.result = result
            self.finished = datetime.now()
            self._password = None

    def fail(self, error):
        with self._lock:
            self.status = "failed"
            self.error = str(error)
            self.finished = datetime.now()
            self._password = None

    def state(self):
        """The job as the page sees it. No field here can hold a secret."""
        with self._lock:
            elapsed = (self.finished or datetime.now()) - self.started

            return {
                "id": self.id,
                "kind": self.kind,
                "ticket": self.ticket,
                "status": self.status,
                "error": self.error,
                "result": self.result,
                "detail": self.detail,
                "done": self.done,
                "total": self.total,
                "percent": round(100 * self.done / self.total) if self.total else 0,
                "seconds": round(elapsed.total_seconds()),
                "lines": list(self.lines[-60:]),
            }


class JobRunner:
    """Starts jobs, keeps the last few, and refuses to run two at once.

    Two captures of the same ticket at the same moment would race for the
    same run folder, and two SSH sweeps of one fleet is not something to do
    by accident, so one job runs at a time.
    """

    def __init__(self, keep=12):
        self.keep = keep
        self.jobs = {}
        self.order = []
        self._lock = threading.Lock()
        self._next_id = 1

    def current(self):
        """The running job, or None."""
        with self._lock:
            for job_id in reversed(self.order):
                if self.jobs[job_id].status == "running":
                    return self.jobs[job_id]

        return None

    def get(self, job_id):
        with self._lock:
            return self.jobs.get(job_id)

    def recent(self):
        with self._lock:
            return [self.jobs[job_id].state() for job_id in reversed(self.order)]

    def start(self, kind, ticket, work, password=None):
        """Run `work(job)` on a thread and return the job.

        `work` is handed the job so it can log and report progress through
        it. Raise from `work` and the job records the failure; the page
        shows it rather than the window dying.
        """
        busy = self.current()

        if busy is not None:
            raise RuntimeError(
                f"{busy.kind} for {busy.ticket} is still running. One job at a time, "
                "so two captures can't race for the same run folder."
            )

        with self._lock:
            job_id = self._next_id
            self._next_id += 1
            job = Job(job_id, kind, ticket)
            job._password = password
            self.jobs[job_id] = job
            self.order.append(job_id)

            for stale in self.order[: -self.keep]:
                self.jobs.pop(stale, None)

            del self.order[: -self.keep]

        def run():
            try:
                job.finish(work(job))
            except Exception as error:  # noqa: BLE001 - the page reports it
                job.add_line(traceback.format_exc(limit=3).strip().splitlines()[-1])
                job.fail(error)

        threading.Thread(target=run, daemon=True, name=f"job-{job_id}-{kind}").start()

        return job
