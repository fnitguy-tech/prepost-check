/* The view layer, and only that.
 *
 * Every decision is Python's: what a capture would run, whether a pair of
 * runs is the right way round, whether notes are still a blank template.
 * This file reads fields, posts them, and draws what comes back. Keeping it
 * that way is what lets the Rust port reuse these assets unchanged.
 *
 * No framework, no build step, no dependencies. */

const token = new URLSearchParams(location.search).get("t") || "";
const $ = (id) => document.getElementById(id);

let state = { tickets: [], runs: [], comparisons: [], inventories: [], notes: {} };
let watching = null;

/* ── talking to Python ───────────────────────────────────────────── */

async function call(path, body) {
  const url = path + (path.includes("?") ? "&" : "?") + "t=" + encodeURIComponent(token);
  const options = body
    ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
    : {};
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({ error: response.statusText }));

  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

function toast(message, ok = false) {
  const node = $("toast");
  node.textContent = message;
  node.className = ok ? "toast ok" : "toast";
  node.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { node.hidden = true; }, ok ? 3200 : 7000);
}

const escape = (text) =>
  String(text ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;" }[c]));

const kb = (bytes) => (bytes / 1024).toFixed(1) + " KB";

/* ── tabs ────────────────────────────────────────────────────────── */

document.querySelectorAll(".tab").forEach((tab) => {
  tab.onclick = () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("is-active", t === tab));
    document.querySelectorAll(".view").forEach((view) =>
      view.classList.toggle("is-active", view.id === "view-" + tab.dataset.view));
  };
});

/* ── the window view ─────────────────────────────────────────────── */

async function refreshPlan() {
  const plan = await call("/api/plan?inventory=" + encodeURIComponent($("inventory").value || ""));

  if (!plan.ok) {
    $("plan-summary").innerHTML = "";
    $("plan-devices").innerHTML = `<p class="empty">${escape(plan.error)}</p>`;
    return;
  }

  $("plan-summary").innerHTML = `
    <div class="stat"><b>${plan.devices.length}</b><span>devices</span></div>
    <div class="stat"><b>${plan.commands}</b><span>show commands</span></div>`;
  $("plan-devices").innerHTML = plan.devices.map((device) => `
    <div class="device-row">
      <code>${escape(device.host)}</code>
      <span class="platform">${escape(device.platform)} &middot; ${device.commands} commands</span>
    </div>`).join("");
}

function setBusy(busy) {
  ["run-before", "run-after", "run-report", "cmp-run"].forEach((id) => { $(id).disabled = busy; });
}

async function startCapture(phase) {
  const body = {
    phase,
    ticket: $("ticket").value.trim(),
    username: $("username").value.trim(),
    password: $("password").value,
    inventory: $("inventory").value,
    redact: $("redact").checked,
  };

  try {
    watch(await call("/api/capture", body));
  } catch (error) {
    toast(error.message);
  }
}

$("run-before").onclick = () => startCapture("precheck");
$("run-after").onclick = () => startCapture("postcheck");

$("run-report").onclick = async () => {
  try {
    watch(await call("/api/report", { ticket: $("ticket").value.trim() }));
  } catch (error) {
    toast(error.message);
  }
};

/* ── watching a job ──────────────────────────────────────────────── */

function watch(job) {
  $("job-panel").hidden = false;
  setBusy(true);
  draw(job);
  clearInterval(watching);
  watching = setInterval(async () => {
    try {
      const next = await call("/api/job?id=" + job.id);
      draw(next);

      if (next.status !== "running") {
        clearInterval(watching);
        setBusy(false);
        await load($("ticket").value.trim());
      }
    } catch (error) {
      clearInterval(watching);
      setBusy(false);
      toast(error.message);
    }
  }, 700);
}

function draw(job) {
  const titles = { precheck: "Capturing before", postcheck: "Capturing after",
                   report: "Building the report", comparison: "Comparing runs" };
  $("job-title").textContent = (titles[job.kind] || job.kind) + " · " + job.ticket;
  $("job-elapsed").textContent = job.seconds + "s";
  $("job-detail").textContent = job.detail || "";
  $("job-log").textContent = (job.lines || []).join("\n");
  $("job-log").scrollTop = $("job-log").scrollHeight;

  const bar = $("job-bar");
  bar.style.width = (job.status === "done" ? 100 : job.percent) + "%";
  bar.className = "bar-fill" + (job.status === "done" ? " is-done" : job.status === "failed" ? " is-failed" : "");

  const result = $("job-result");

  if (job.status === "failed") {
    result.innerHTML = `<div class="result-bad">${escape(job.error)}</div>`;
  } else if (job.status === "done" && job.result) {
    result.innerHTML = reportLink(job.result) || summarise(job.result);
  } else {
    result.innerHTML = "";
  }
}

function reportLink(result) {
  if (!result.report) return "";
  return `<div class="result-ok">Report written.
    <a href="/report?name=${encodeURIComponent(result.report)}&t=${encodeURIComponent(token)}"
       target="_blank" rel="noopener">Open ${escape(result.report)}</a></div>`;
}

function summarise(result) {
  if (!result.captured) return "";
  const failed = result.failed && result.failed.length
    ? ` ${result.failed.length} failed: ${escape(result.failed.join(", "))}.`
    : "";
  return `<div class="${failed ? "result-bad" : "result-ok"}">Captured
    ${result.captured.length} device(s) to <code>${escape(result.folder)}</code>.${failed}</div>`;
}

/* ── notes ───────────────────────────────────────────────────────── */

function drawNotes(notes) {
  $("notes-path").textContent = notes.path || "";
  const bodies = splitSections(notes.text, notes.sections);
  $("notes-form").innerHTML = notes.sections.map((heading, index) => `
    <div class="notes-section">
      <label for="notes-${index}">${escape(heading)}</label>
      <textarea id="notes-${index}" data-heading="${escape(heading)}"
        rows="${index === 3 ? 5 : 3}">${escape(bodies[heading] || "")}</textarea>
    </div>`).join("");
}

/* Pull each "## heading" body out of the Markdown so the form round-trips a
   file someone may have edited by hand. Prompts are comments, so they go. */
function splitSections(text, headings) {
  const bodies = {};
  let current = null;

  for (const raw of (text || "").split("\n")) {
    const match = raw.match(/^##\s+(.*\S)\s*$/);

    if (match) { current = match[1]; bodies[current] = []; continue; }
    if (current === null) continue;
    if (/^\s*<!--/.test(raw) || /-->\s*$/.test(raw)) continue;

    bodies[current].push(raw);
  }

  for (const heading of Object.keys(bodies)) {
    bodies[heading] = bodies[heading].join("\n").trim();
  }

  return bodies;
}

function notesMarkdown(ticket) {
  const parts = [`# ${ticket} - Maintenance Notes`, ""];

  document.querySelectorAll("#notes-form textarea").forEach((box) => {
    parts.push(`## ${box.dataset.heading}`, "");
    if (box.value.trim()) parts.push(box.value.trim(), "");
  });

  return parts.join("\n").trimEnd() + "\n";
}

$("notes-save").onclick = async () => {
  const ticket = $("ticket").value.trim();

  if (!ticket) return toast("A ticket is needed before notes can be saved.");

  try {
    state.notes = await call("/api/notes", { ticket, text: notesMarkdown(ticket) });
    drawNotes(state.notes);
    const open = state.notes.open_items;
    $("notes-saved").textContent = "Saved" + (open ? ` · ${open} item(s) still open` : "");
    setTimeout(() => { $("notes-saved").textContent = ""; }, 3200);
  } catch (error) {
    toast(error.message);
  }
};

$("notes-seed").onclick = async () => {
  const ticket = $("ticket").value.trim();

  if (!ticket) return toast("A ticket is needed before notes can be seeded.");

  try {
    state.notes = await call("/api/notes/seed", { ticket });
    drawNotes(state.notes);
    toast("Template seeded from the captures. Existing notes were left alone.", true);
  } catch (error) {
    toast(error.message);
  }
};

/* ── history ─────────────────────────────────────────────────────── */

function runLabel(run) {
  return `${run.ticket} · ${run.phase} · ${run.when_text} · ${run.devices.length} devices`;
}

function drawHistory() {
  const options = state.runs.map((run, index) =>
    `<option value="${index}">${escape(runLabel(run))}</option>`).join("");
  $("cmp-before").innerHTML = options;
  $("cmp-after").innerHTML = options;

  // Default to the newest window's own pre and post. Any two runs can be
  // compared, but the pair you almost always want is one window's own, and
  // picking across unrelated fleets gives a report with nothing in it.
  const newest = state.runs[0];
  const sameTicket = state.runs
    .map((run, index) => ({ run, index }))
    .filter((entry) => newest && entry.run.ticket === newest.ticket);
  const pre = sameTicket.find((entry) => entry.run.phase === "precheck");
  const post = sameTicket.find((entry) => entry.run.phase === "postcheck");

  if (pre && post) {
    $("cmp-before").value = String(pre.index);
    $("cmp-after").value = String(post.index);
  } else if (state.runs.length > 1) {
    $("cmp-before").value = String(state.runs.length - 1);
    $("cmp-after").value = "0";
  }

  describePair();

  $("ticket-list").innerHTML = state.tickets.length
    ? state.tickets.map(ticketCard).join("")
    : `<p class="empty">No windows yet. Capture one and it will show up here.</p>`;

  $("comparisons-panel").hidden = state.comparisons.length === 0;
  $("comparison-list").innerHTML = state.comparisons.map(link).join("");

  document.querySelectorAll("[data-use-ticket]").forEach((node) => {
    node.onclick = (event) => {
      event.preventDefault();
      $("ticket").value = node.dataset.useTicket;
      load(node.dataset.useTicket);
      document.querySelector('.tab[data-view="window"]').click();
    };
  });
}

function ticketCard(entry) {
  const runs = entry.runs.map((run) =>
    `<span class="chip ${run.phase === "precheck" ? "pre" : "post"}">${run.phase} ${escape(run.stamp)}</span>`).join("");
  const notes = entry.has_notes ? `<span class="chip notes">notes</span>` : "";

  return `<div class="ticket">
    <div class="ticket-head">
      <span class="ticket-name"><a href="#" data-use-ticket="${escape(entry.ticket)}">${escape(entry.ticket)}</a></span>
      <span class="ticket-meta">${entry.device_count} devices · ${entry.reports.length} report(s)</span>
    </div>
    <div class="chips">${runs}${notes}</div>
    <div class="report-list">${entry.reports.slice(0, 5).map(link).join("")}</div>
  </div>`;
}

function link(report) {
  const name = report.label || report.name;
  return `<a class="report-link" target="_blank" rel="noopener"
    href="/report?name=${encodeURIComponent(name)}&t=${encodeURIComponent(token)}">
    <span>${escape(name)}</span><span class="size">${kb(report.size)}</span></a>`;
}

/* Say what the pair has in common before the button is pressed, because
   two unrelated fleets share no devices and would compare to nothing. */
function describePair() {
  const before = state.runs[Number($("cmp-before").value)];
  const after = state.runs[Number($("cmp-after").value)];
  const note = $("cmp-note");

  if (!before || !after) { note.textContent = ""; return; }

  const shared = before.devices.filter((name) => after.devices.includes(name));
  const backwards = before.stamp > after.stamp;

  if (!shared.length) {
    note.textContent = "No device in common - there would be nothing to compare.";
  } else if (backwards) {
    note.textContent = "The later run is on the left. Swap them, or uptime reads as resets.";
  } else {
    note.textContent = `${shared.length} device(s) in common.`;
  }
}

$("cmp-before").onchange = describePair;
$("cmp-after").onchange = describePair;

$("cmp-run").onclick = async () => {
  const before = state.runs[Number($("cmp-before").value)];
  const after = state.runs[Number($("cmp-after").value)];

  if (!before || !after) return toast("Pick two capture runs.");

  const pick = (run) => ({ ticket: run.ticket, phase: run.phase, stamp: run.stamp });

  try {
    watch(await call("/api/compare-runs", { before: pick(before), after: pick(after) }));
    document.querySelector('.tab[data-view="window"]').click();
  } catch (error) {
    toast(error.message);
  }
};

/* ── load ────────────────────────────────────────────────────────── */

async function load(ticket) {
  state = await call("/api/state" + (ticket ? "?ticket=" + encodeURIComponent(ticket) : ""));

  const select = $("inventory");
  const chosen = select.value;
  select.innerHTML = state.inventories.map((path) =>
    `<option value="${escape(path)}">${escape(path)}</option>`).join("")
    || `<option value="">inventory/devices.yml (not found)</option>`;
  if (chosen) select.value = chosen;

  if (!$("ticket").value) $("ticket").value = state.ticket || "";

  drawNotes(state.notes);
  drawHistory();
  await refreshPlan();
}

/* ── opening a report ────────────────────────────────────────────────
 *
 * In a browser these links are ordinary target="_blank" anchors and a new
 * tab is exactly right. A webview has no tabs, so the click does nothing
 * at all - which is what a report link in the native window used to do.
 *
 * So when the page knows it is inside the window, it hands the file to the
 * real browser instead. That is also the better place for it: a report is a
 * document you keep, print and send to someone, and it outlives the app. */

document.addEventListener("click", (event) => {
  const anchor = event.target.closest('a[href^="/report"]');

  if (!anchor || !state.native) return;

  event.preventDefault();
  const name = new URL(anchor.href, location.origin).searchParams.get("name");

  call("/api/open", { name })
    .then((result) => toast("Opened " + result.opened + " in your browser.", true))
    .catch((error) => toast("Could not open it: " + error.message));
});

$("inventory").onchange = refreshPlan;
$("ticket").onchange = () => load($("ticket").value.trim());

load().catch((error) => toast("Could not load: " + error.message));
