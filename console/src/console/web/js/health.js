"use strict";

/* Pipeline-health page. Two panels:
 *   - Data freshness — per-index doc count + max(@timestamp).
 *   - Recent pipeline runs — latest run_summary per cluster index.
 *
 * LLM-grounding curation moved to /curation under ROADMAP #17.10.
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

async function loadFreshness() {
  const body = document.getElementById("freshness-body");
  let data;
  try {
    const r = await fetch("/api/health/freshness");
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

async function loadRuns() {
  const body = document.getElementById("runs-body");
  const clustering = document.getElementById("clustering-stats");
  let data;
  try {
    const r = await fetch("/api/health/runs");
    data = await r.json();
  } catch (e) {
    body.innerHTML = "";
    body.appendChild(el("div", {class: "h-error"}, [`fetch failed: ${e.message}`]));
    if (clustering) {
      clustering.innerHTML = "";
      clustering.appendChild(el("div", {class: "h-error"}, [`fetch failed: ${e.message}`]));
    }
    return;
  }
  if (data.error) {
    body.innerHTML = "";
    body.appendChild(el("div", {class: "h-error"}, [data.error]));
    if (clustering) {
      clustering.innerHTML = "";
      clustering.appendChild(el("div", {class: "h-error"}, [data.error]));
    }
    return;
  }
  renderClustering(data.rows);
  body.innerHTML = "";
  const table = el("table", {class: "h-table"});
  table.appendChild(el("thead", null, [el("tr", null, [
    el("th", null, ["Verb"]),
    el("th", null, ["Last run"]),
    el("th", {class: "num"}, ["Input docs"]),
    el("th", {class: "num"}, ["Clusters"]),
    el("th", {class: "num"}, ["Outliers"]),
    el("th", null, ["Run id"]),
  ])]));
  const tbody = el("tbody");
  for (const r of (data.rows || [])) {
    const tr = el("tr");
    tr.appendChild(el("td", {class: "name"}, [r.verb]));
    tr.appendChild(tsCell(r.ts, r.verb.replace(/^cluster /, "") + "_clusters"));
    tr.appendChild(el("td", {class: "num"}, [fmtNum(r.total_docs)]));
    tr.appendChild(el("td", {class: "num"}, [fmtNum(r.n_clusters)]));
    tr.appendChild(el("td", {class: "num"}, [fmtNum(r.n_outliers)]));
    tr.appendChild(el("td", {class: "idx"}, [r.run_id || "—"]));
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  body.appendChild(table);
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

  const rows = data.rows || [];
  if (!rows.length) {
    body.appendChild(el("em", {class: "h-empty"},
      ["no run telemetry yet — enable with `init-indexes --source ops`"]));
    return;
  }

  const table = el("table", {class: "h-table"});
  table.appendChild(el("thead", null, [el("tr", null, [
    el("th", null, ["Verb"]),
    el("th", null, ["Status"]),
    el("th", null, ["Last run"]),
    el("th", {class: "num"}, ["Duration"]),
    el("th", null, ["Host"]),
  ])]));
  const tbody = el("tbody");
  const runningVerbs = new Set(running.map((r) => r.verb));
  for (const r of rows) {
    const tr = el("tr");
    tr.appendChild(el("td", {class: "name"}, [r.verb]));
    // started (in-flight) > failed (amber) > finished.
    const inFlight = r.status === "started" || runningVerbs.has(r.verb);
    const statusCell = el("td", null, [inFlight ? "running" : (r.status || "—")]);
    if (inFlight) statusCell.style.color = "#34d399";
    else if (r.status === "failed" || (r.rc != null && r.rc !== 0)) statusCell.style.color = "#fbbf24";
    tr.appendChild(statusCell);
    tr.appendChild(tsCell(r.started_at, "__ops__"));
    tr.appendChild(el("td", {class: "num"},
      [r.duration_s == null ? "—" : `${Number(r.duration_s).toLocaleString()}s`]));
    tr.appendChild(el("td", {class: "idx"}, [r.host || "—"]));
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  body.appendChild(table);
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
  loadOverview();
  loadFreshness();
  loadRuns();
  loadOpsRuns();
  const purgeBtn = document.getElementById("cfg-purge-cache");
  if (purgeBtn) purgeBtn.addEventListener("click", purgeCache);
});
