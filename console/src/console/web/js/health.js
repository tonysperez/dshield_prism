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

async function loadRuns() {
  const body = document.getElementById("runs-body");
  let data;
  try {
    const r = await fetch("/api/health/runs");
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

document.addEventListener("DOMContentLoaded", () => {
  loadFreshness();
  loadRuns();
});
