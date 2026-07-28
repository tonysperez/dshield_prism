"use strict";

/* Pipeline-health page. Panels:
 *   - Data freshness — per-index doc count + max(@timestamp).
 *   - Clustering performance — cluster/outlier counts per type. The sole home
 *     for those numbers; the unit panel deliberately does not repeat them.
 *   - Pipeline & schedule — one row per systemd unit (what it does, cadence,
 *     last run, running?), expanding to the verbs that ran under it.
 *   - Command-grounding coverage — stat bar read from the single
 *     precomputed report doc (spec-grounding-precompute), O(1); the full
 *     worklist + block/unblock live under Tune.
 */

// Stale thresholds (hours). Rows older than this flag amber. Tuned for
// a corpus that runs the backward cycle every 60 min; tune per deploy.
const STALE_HOURS = {
  default: 24,                  // fallback for any index not listed below
  sessions_raw: 2,              // forward pipeline — should be very fresh
  commands: 2,
  sessions_rollup: 2,
  ips_rollup: 2,
  command_clusters: 36,
  session_clusters: 36,
  ip_clusters: 36,
  findings: 36,
  campaigns: 36,
  intel_ip: 168,                // 7d — intel refresh has long TTLs
  intel_url: 336,               // 14d
  intel_domain: 336,
  intel_hash: 720,              // 30d
};

function el(tag, attrs, children) {
  const e = document.createElement(tag);
  if (attrs) for (const k in attrs) {
    if (k === "class") e.className = attrs[k];
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), attrs[k]);
    else e.setAttribute(k, attrs[k]);
  }
  if (children) for (const c of children) {
    if (c == null) continue;
    e.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return e;
}

function fmtNum(n) {
  if (n == null) return "—";
  return Number(n).toLocaleString();
}

function fmtRelTs(iso) {
  if (!iso) return {text: "never", cls: "missing"};
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return {text: iso, cls: ""};
  const sec = Math.max(0, Math.round((Date.now() - then) / 1000));
  let text;
  if (sec < 60)       text = `${sec}s ago`;
  else if (sec < 3600)   text = `${Math.round(sec / 60)}m ago`;
  else if (sec < 86_400) text = `${Math.round(sec / 3600)}h ago`;
  else                   text = `${Math.round(sec / 86_400)}d ago`;
  return {text, cls: "", hours: sec / 3600};
}

function tsCell(iso, indexName) {
  const f = fmtRelTs(iso);
  let cls = "ts";
  if (f.cls === "missing") cls += " missing";
  else {
    const threshold = STALE_HOURS[indexName] ?? STALE_HOURS.default;
    if (typeof f.hours === "number" && f.hours > threshold) cls += " stale";
  }
  const td = el("td", {class: cls}, [f.text]);
  if (iso) td.setAttribute("data-tooltip", iso);
  return td;
}

async function loadOverview() {
  const body = document.getElementById("overview-stats");
  if (!body) return;
  let data;
  try {
    const r = await fetch("/api/health/overview");
    data = await r.json();
  } catch (e) {
    body.innerHTML = "";
    body.appendChild(el("div", {class: "h-error"}, [`fetch failed: ${e.message}`]));
    return;
  }
  if (data.error) {
    body.innerHTML = "";
    body.appendChild(el("div", {class: "h-error"}, [data.error]));
    return;
  }
  body.innerHTML = "";
  const stats = [
    ["Total IPs", data.total_ips],
    ["Sessions",  data.total_sessions],
    ["Commands",  data.total_commands],
    ["Playbooks", data.active_playbooks],
    ["Clusters",  data.total_clusters],
    ["Outliers",  data.total_outliers],
  ];
  for (const [label, value] of stats) {
    body.appendChild(el("div", {class: "stat-card"}, [
      el("div", {class: "s-label"}, [label]),
      el("div", {class: "s-value"}, [fmtNum(value)]),
    ]));
  }
}

// Intel-coverage table — rendered from the intel_* rows already returned by
// /api/health/freshness (no extra request). Filters on the `intel_` name
// prefix `queries.health_freshness` uses for each intel index.
function renderIntelCoverage(rows) {
  const body = document.getElementById("intel-coverage-body");
  if (!body) return;
  // `health_freshness` probes all four intel indices unconditionally, so a
  // disabled-intel deploy still yields intel_* rows — but with doc_count null
  // (the index doesn't exist). Treat only rows whose index actually exists as
  // "deployed"; if none are, show the not-deployed empty state rather than four
  // permanent "never" rows.
  const intel = (rows || []).filter(
    (r) => r.name && r.name.startsWith("intel_") && r.doc_count != null);
  body.innerHTML = "";
  if (!intel.length) {
    body.appendChild(el("em", {class: "h-empty"},
      ["no intel indices — enable intel enrichment to populate this"]));
    return;
  }
  const table = el("table", {class: "h-table"});
  table.appendChild(el("thead", null, [el("tr", null, [
    el("th", null, ["Kind"]),
    el("th", {class: "num"}, ["Docs"]),
    el("th", null, ["Last refresh"]),
  ])]));
  const tbody = el("tbody");
  for (const r of intel) {
    const tr = el("tr");
    tr.appendChild(el("td", {class: "name"}, [r.name.replace(/^intel_/, "")]));
    tr.appendChild(el("td", {class: "num"}, [fmtNum(r.doc_count)]));
    tr.appendChild(tsCell(r.last_ts, r.name));
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  body.appendChild(table);
}

async function loadFreshness() {
  const body = document.getElementById("freshness-body");
  const intelBody = document.getElementById("intel-coverage-body");
  const showErr = (msg) => {
    for (const b of [body, intelBody]) {
      if (!b) continue;
      b.innerHTML = "";
      b.appendChild(el("div", {class: "h-error"}, [msg]));
    }
  };
  let data;
  try {
    const r = await fetch("/api/health/freshness");
    data = await r.json();
  } catch (e) {
    showErr(`fetch failed: ${e.message}`);
    return;
  }
  if (data.error) {
    showErr(data.error);
    return;
  }
  body.innerHTML = "";
  const table = el("table", {class: "h-table"});
  table.appendChild(el("thead", null, [el("tr", null, [
    el("th", null, ["Name"]),
    el("th", null, ["Index"]),
    el("th", {class: "num"}, ["Docs"]),
    el("th", null, ["Freshest"]),
  ])]));
  const tbody = el("tbody");
  for (const r of (data.rows || [])) {
    const tr = el("tr");
    tr.appendChild(el("td", {class: "name"}, [r.name]));
    tr.appendChild(el("td", {class: "idx"}, [r.idx || "—"]));
    tr.appendChild(el("td", {class: "num"}, [fmtNum(r.doc_count)]));
    tr.appendChild(tsCell(r.last_ts, r.name));
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  body.appendChild(table);
  // Same rows drive the intel-coverage block — no second fetch.
  renderIntelCoverage(data.rows);
}

async function loadPressure() {
  const body = document.getElementById("pressure-tile");
  if (!body) return;
  let data;
  try {
    const r = await fetch("/api/health/pressure");
    data = await r.json();
  } catch (e) {
    body.className = "press-tile state-unknown";
    body.innerHTML = "";
    body.appendChild(el("div", {class: "p-label"}, ["ES pressure"]));
    body.appendChild(el("div", {class: "p-value"}, ["unknown"]));
    body.appendChild(el("div", {class: "p-detail"}, [`fetch failed: ${e.message}`]));
    return;
  }
  const state = data.state || "unknown";
  body.className = "press-tile state-" + state;
  body.innerHTML = "";
  body.appendChild(el("div", {class: "p-label"}, ["ES pressure"]));
  const pct = (typeof data.ratio === "number")
    ? `${(data.ratio * 100).toFixed(0)}%` : "unknown";
  body.appendChild(el("div", {class: "p-value"}, [pct]));
  body.appendChild(el("div", {class: "p-detail"}, [data.detail || ""]));
}

async function loadSensors() {
  const body = document.getElementById("sensors-body");
  if (!body) return;
  let data;
  try {
    const r = await fetch("/api/health/sensors");
    data = await r.json();
  } catch (e) {
    body.innerHTML = "";
    body.appendChild(el("div", {class: "h-error"}, [`fetch failed: ${e.message}`]));
    return;
  }
  if (data.error) {
    body.innerHTML = "";
    body.appendChild(el("div", {class: "h-error"}, [data.error]));
    return;
  }
  body.innerHTML = "";
  const rows = data.rows || [];
  if (!rows.length) {
    body.appendChild(el("em", {class: "h-empty"}, ["no sensor data yet"]));
    return;
  }
  const table = el("table", {class: "h-table"});
  table.appendChild(el("thead", null, [el("tr", null, [
    el("th", null, ["Sensor"]),
    el("th", null, ["Last data"]),
  ])]));
  const tbody = el("tbody");
  for (const r of rows) {
    const tr = el("tr");
    tr.appendChild(el("td", {class: "name"}, [
      el("span", {class: "st-dot state-" + (r.state || "ok")}),
      r.sensor || "—",
    ]));
    // Server state is the source of truth for stale (amber), not the client's
    // per-index STALE_HOURS heuristic — build the ts cell directly.
    const f = fmtRelTs(r.last_ts);
    const tsc = el("td", {class: "ts" + (r.state === "stale" ? " stale" : "")}, [f.text]);
    if (r.last_ts) tsc.setAttribute("data-tooltip", r.last_ts);
    tr.appendChild(tsc);
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  body.appendChild(table);
}

// verb → the type label shown in the Clustering-performance grid.
const CLUSTER_TYPE_LABEL = {
  "cluster ips":      "IP",
  "cluster sessions": "Session",
  "cluster commands": "Command",
};
// Fixed grid order (IP / session / command), independent of the row order the
// API returns.
const CLUSTER_TYPE_ORDER = ["cluster ips", "cluster sessions", "cluster commands"];

// Render the 3-up Clustering-performance grid from the same run_summary rows the
// Recent-runs table uses (no extra fetch). Each card shows a type's cluster and
// outlier counts plus its outlier share (outliers / input docs), guarded so a
// zero-doc idle run or a never-run type shows `—`, never `NaN%`.
function renderClustering(rows) {
  const body = document.getElementById("clustering-stats");
  if (!body) return;
  body.innerHTML = "";
  const byVerb = {};
  for (const r of (rows || [])) byVerb[r.verb] = r;

  for (const verb of CLUSTER_TYPE_ORDER) {
    const r = byVerb[verb] || {};
    const ran = r.run_id != null;         // a type with no run_summary never ran
    const nClusters = r.n_clusters;
    const nOutliers = r.n_outliers;
    const totalDocs = r.total_docs;

    // Outlier share: guard div-by-zero (idle run, total_docs == 0) AND a
    // never-run / missing type — both render `—`, never NaN%.
    let share = "—";
    if (ran && typeof nOutliers === "number"
        && typeof totalDocs === "number" && totalDocs > 0) {
      share = `${((nOutliers / totalDocs) * 100).toFixed(1)}%`;
    }

    const card = el("div", {class: "cl-card" + (ran ? "" : " never")}, [
      el("div", {class: "cl-type"}, [CLUSTER_TYPE_LABEL[verb] || verb]),
      el("div", {class: "cl-nums"}, [
        el("div", {class: "cl-metric"}, [
          el("div", {class: "cl-label"}, ["Clusters"]),
          el("div", {class: "cl-value"}, [ran ? fmtNum(nClusters) : "—"]),
        ]),
        el("div", {class: "cl-metric"}, [
          el("div", {class: "cl-label"}, ["Outliers"]),
          el("div", {class: "cl-value"}, [ran ? fmtNum(nOutliers) : "—"]),
        ]),
      ]),
      el("div", {class: "cl-share"}, [`outlier share ${share}`]),
    ]);
    body.appendChild(card);
  }
}

/* `/api/health/runs` now feeds only the Clustering-performance panel. The
 * former "Recent pipeline runs" table rendered these same rows a second time,
 * and their verbs a third time under "Pipeline activity" — run/status facts now
 * live once, in "Pipeline & schedule". */
async function loadRuns() {
  const clustering = document.getElementById("clustering-stats");
  if (!clustering) return;
  const fail = (msg) => {
    clustering.innerHTML = "";
    clustering.appendChild(el("div", {class: "h-error"}, [msg]));
  };
  let data;
  try {
    const r = await fetch("/api/health/runs");
    data = await r.json();
  } catch (e) {
    fail(`fetch failed: ${e.message}`);
    return;
  }
  if (data.error) {
    fail(data.error);
    return;
  }
  renderClustering(data.rows);
}

async function loadOpsRuns() {
  const body = document.getElementById("ops-runs-body");
  if (!body) return;
  let data;
  try {
    const r = await fetch("/api/health/ops-runs");
    data = await r.json();
  } catch (e) {
    body.innerHTML = "";
    body.appendChild(el("div", {class: "h-error"}, [`fetch failed: ${e.message}`]));
    return;
  }
  if (data.error) {
    body.innerHTML = "";
    body.appendChild(el("div", {class: "h-error"}, [data.error]));
    return;
  }
  body.innerHTML = "";

  const running = data.running || [];
  if (running.length) {
    const names = running.map((r) => r.verb).join(", ");
    body.appendChild(el("div", {class: "h-action-status success",
      style: "margin-bottom:8px;"},
      [`in progress: ${names}`]));
  }

  const units = data.units || [];
  if (!units.length) {
    body.appendChild(el("em", {class: "h-empty"},
      ["no run telemetry yet — enable with `init-indexes --source ops`"]));
    return;
  }

  const UNIT_STATE_TEXT = {
    running: "running", failed: "failed", ok: "ok", never: "no runs recorded",
  };

  const table = el("table", {class: "h-table"});
  table.appendChild(el("thead", null, [el("tr", null, [
    el("th", null, ["Unit"]),
    el("th", null, ["State"]),
    el("th", null, ["Last run"]),
    el("th", null, ["Cadence"]),
    el("th", {class: "num"}, ["Duration"]),
    el("th", null, ["Host"]),
  ])]));
  const tbody = el("tbody");

  const fmtDur = (s) => (s == null ? "—" : `${Number(s).toLocaleString()}s`);

  for (const u of units) {
    const kids = [];
    const hasKids = !!(u.verbs && u.verbs.length);
    const nameCell = el("td", {class: "name"}, [
      el("span", {class: "u-caret"}, [hasKids ? "▸" : " "]),
      u.unit,
    ]);
    // The tooltip is what the unit does — the ask this panel exists to answer.
    // Native `title`, so it needs no JS and reads out to assistive tech.
    if (u.description) nameCell.setAttribute("title", u.description);
    // `verb` is top-level only, so a unit can fail in a step whose bucket was
    // overwritten by a later sibling's success. Name those verbs explicitly —
    // otherwise the child rows all read "ok" under a red unit.
    if (u.failed_verbs && u.failed_verbs.length) {
      nameCell.appendChild(el("span", {class: "u-desc"},
        [`failed in window: ${u.failed_verbs.join(", ")}`]));
    }

    const tr = el("tr", {
      class: `unit-row${u.state === "failed" ? " run-failed" : ""}`,
      // Keyboard-operable: the row is the disclosure control, so it needs to be
      // focusable and announce its expanded state.
      ...(hasKids ? {tabindex: "0", role: "button", "aria-expanded": "false"} : {}),
    });
    tr.appendChild(nameCell);
    tr.appendChild(el("td", null, [
      el("span", {class: `u-state state-${u.state}`},
        [UNIT_STATE_TEXT[u.state] || u.state]),
    ]));
    tr.appendChild(tsCell(u.last_run, "__ops__"));
    tr.appendChild(el("td", null, [el("span", {class: "u-cadence"}, [u.cadence || "—"])]));
    tr.appendChild(el("td", {class: "num"}, [fmtDur(u.duration_s)]));
    tr.appendChild(el("td", {class: "idx"}, [u.host || "—"]));
    tbody.appendChild(tr);

    for (const v of (u.verbs || [])) {
      const vtr = el("tr", {class: "verb-row", hidden: "hidden"});
      vtr.appendChild(el("td", {class: "name"}, [v.verb || "—"]));
      let statusText;
      if (v.state === "running") statusText = "running";
      else if (v.state === "failed") {
        statusText = (v.rc != null) ? `failed (rc ${v.rc})` : "failed";
      } else statusText = v.status || "—";
      vtr.appendChild(el("td", null, [
        el("span", {class: `u-state state-${v.state}`}, [statusText]),
      ]));
      vtr.appendChild(tsCell(v.started_at, "__ops__"));
      // Cadence is a unit-level property; a step inside it has none.
      vtr.appendChild(el("td", null, [""]));
      vtr.appendChild(el("td", {class: "num"}, [fmtDur(v.duration_s)]));
      vtr.appendChild(el("td", {class: "idx"}, [v.host || "—"]));
      tbody.appendChild(vtr);
      kids.push(vtr);
    }

    if (kids.length) {
      const caret = nameCell.querySelector(".u-caret");
      const toggle = () => {
        const open = kids[0].hasAttribute("hidden");
        for (const k of kids) {
          if (open) k.removeAttribute("hidden"); else k.setAttribute("hidden", "hidden");
        }
        caret.textContent = open ? "▾" : "▸";
        tr.setAttribute("aria-expanded", open ? "true" : "false");
      };
      tr.addEventListener("click", toggle);
      tr.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(); }
      });
      // Units needing attention open on load — the operator shouldn't have to
      // hunt for which step inside the unit broke, or what is in flight.
      if (u.state === "failed" || u.state === "running") toggle();
    }
  }
  table.appendChild(tbody);
  body.appendChild(table);
}

async function loadGroundingCoverage() {
  const body = document.getElementById("grounding-stats");
  if (!body) return;
  let data;
  try {
    const r = await fetch("/api/health/grounding-coverage");
    data = await r.json();
  } catch (e) {
    body.innerHTML = "";
    body.appendChild(el("div", {class: "h-error"}, [`fetch failed: ${e.message}`]));
    return;
  }
  if (data.error) {
    body.innerHTML = "";
    body.appendChild(el("div", {class: "h-error"}, [data.error]));
    return;
  }
  body.innerHTML = "";
  if (!data.available) {
    body.appendChild(el("em", {class: "h-empty"},
      ["pending first run — the track grounding-coverage pipeline job hasn't written a report yet"]));
    return;
  }
  const stats = data.stats || {};
  const cards = [
    ["unique commands", stats.total_unique_cmds],
    ["curated", stats.curated],
    ["tldr only", stats.tldr_only],
    ["needs definition", stats.needs_def],
    ["denied", stats.denied],
    ["total occurrences", stats.total_corpus_occurrences],
  ];
  for (const [label, value] of cards) {
    body.appendChild(el("div", {class: "stat-card"}, [
      el("div", {class: "s-label"}, [label]),
      el("div", {class: "s-value"}, [fmtNum(value)]),
    ]));
  }
}

async function purgeCache() {
  const btn = document.getElementById("cfg-purge-cache");
  const status = document.getElementById("cfg-purge-status");
  if (!btn || !status) return;
  btn.disabled = true;
  status.className = "h-action-status";
  status.textContent = "purging…";
  try {
    const r = await fetch("/api/cache/purge", { method: "POST" });
    if (r.ok) {
      const data = await r.json();
      const layers = (data.cleared || []).join(", ") || "ok";
      status.className = "h-action-status success";
      status.textContent = `purged: ${layers}`;
      setTimeout(() => {
        if (status.textContent.startsWith("purged")) {
          status.textContent = "";
          status.className = "h-action-status";
        }
      }, 4000);
    } else {
      status.className = "h-action-status error";
      status.textContent = `failed: HTTP ${r.status}`;
    }
  } catch (exc) {
    status.className = "h-action-status error";
    status.textContent = `error: ${exc}`;
  } finally {
    btn.disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  loadPressure();
  loadSensors();
  loadOverview();
  loadFreshness();
  loadRuns();
  loadOpsRuns();
  loadGroundingCoverage();
  const purgeBtn = document.getElementById("cfg-purge-cache");
  if (purgeBtn) purgeBtn.addEventListener("click", purgeCache);
});
