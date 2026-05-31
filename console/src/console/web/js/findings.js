"use strict";

/* Findings inbox — single ranked list + slide-in drawer.
 *
 * One fetch to /api/findings drives the inbox rows and the rail (status
 * chips + category chips + dynamic facet groups). Each row is clickable;
 * clicking opens the detail drawer at /api/finding/{id}/detail. The
 * status select stays inside the row so the analyst can triage without
 * opening the drawer. The backend still groups findings into three
 * streams (drift/discovery/coverage); the UI surfaces them as a single
 * "Category" facet (Changed / New / Confirm).
 *
 * URL state: ?status=new&stream=drift&sort=score survives reloads.
 */

const STATUSES = ["new", "ack", "confirmed", "rejected"];

// ────────────────────────────────────────────────────────────────────────────
// Next-action templates (ROADMAP #17.14 — the spine of the overhaul).
//
// A finding without a suggested next step is a notification, not a triage
// row. Deterministic per-kind templates are intentionally first — they
// close ~80% of the value before any LLM rescue. Each entry has:
//   verb: confirm | investigate | ack | auto_confirm | reject
//   text: one-line explanation rendered as the chip tooltip + drawer body
// `intel_verdict_flip` is direction-dependent and computed in nextAction().
// Confirmed/rejected rows return null — the decision is already made.
// ────────────────────────────────────────────────────────────────────────────
const ACTION_TEMPLATES = {
  // Drift kinds — confirm to keep tracking, investigate for the high-signal ones
  playbook_command_drift:  {verb: "confirm",     text: "Drift in tracked playbook commands — confirm to keep watching, or reject if it's known noise"},
  playbook_artifact_drift: {verb: "confirm",     text: "New artifacts appeared on a tracked playbook — confirm to keep watching"},
  playbook_geo_drift:      {verb: "confirm",     text: "Geo distribution shifted on this playbook — confirm to keep tracking"},
  playbook_size_drift:     {verb: "confirm",     text: "Playbook size moved beyond its baseline — confirm to keep tracking"},
  playbook_resurgence:     {verb: "investigate", text: "Playbook is back after a silent period — investigate the new sessions"},
  playbook_sequence_drift: {verb: "confirm",     text: "Command sequence shifted on this playbook — confirm to keep tracking"},
  campaign_growth:         {verb: "investigate", text: "Campaign added members since its baseline — investigate the new IPs"},

  // Coverage kinds — analyst-pinnable artifacts. Confirming arms drift watch.
  playbook: {verb: "confirm", text: "Confirm to start drift-watching this playbook"},
  campaign: {verb: "confirm", text: "Confirm to start drift-watching this campaign"},

  // Discovery kinds — first appearances + anomalies
  new_playbook:           {verb: "confirm",     text: "Confirm if this is a real new TTP, reject if it's a one-off"},
  outlier_burst:          {verb: "investigate", text: "Burst activity on a single IP — investigate before it spreads"},
  novel_edge_session:     {verb: "investigate", text: "Session is structurally unusual — investigate the command sequence"},
  unattributed_active_ip: {verb: "investigate", text: "Orphan IP with no known cluster home — investigate its session history"},
  campaign_convergence:   {verb: "confirm",     text: "Multiple playbooks converging on shared infrastructure — confirm to track"},
  ip_behavior_shift:      {verb: "investigate", text: "IP's behaviour changed from its previous pattern — investigate the shift"},
  // intel_verdict_flip handled in nextAction() — direction matters
};

const ACTION_VERB_LABEL = {
  confirm:      "Confirm",
  investigate:  "Investigate",
  ack:          "Ack",
  auto_confirm: "Auto-confirm",
  reject:       "Reject",
};

function nextAction(row) {
  if (!row || !row.kind) return null;
  // Confirmed/rejected already decided — no action chip in the row.
  if (row.status === "confirmed" || row.status === "rejected") return null;

  if (row.kind === "intel_verdict_flip") {
    const v = ((row.evidence || {}).verdict_curr || "").toLowerCase();
    if (v === "malicious") return {verb: "auto_confirm", text: "Intel verdict flipped to malicious — auto-confirm candidate"};
    if (v === "clean")     return {verb: "ack",          text: "Intel verdict flipped to clean — consider ack"};
    return {verb: "investigate", text: "Intel verdict changed — investigate the new evidence"};
  }
  return ACTION_TEMPLATES[row.kind] || null;
}
// Display labels for the three backend streams (the API contract still
// uses drift/discovery/coverage; the UI surfaces them as a Category facet).
const STREAM_LABEL = {
  drift: "Changed",
  discovery: "New",
  coverage: "Confirm",
};
// Triage state machine. Tooltip text per status — surfaced on the
// facet-rail chips so an analyst doesn't need to read docs to know
// what each state means.
const STATUS_TOOLTIP = {
  all:       "Show findings in every state",
  new:       "Untriaged — the default for fresh findings",
  ack:       "Saw it, haven't decided yet",
  confirmed: "Real signal — arms drift watch on the artifact",
  rejected:  "Noise — suppress similar in future",
};
// Score is intentionally absent — banding an uncalibrated number adds
// fake precision and triage decisions hang on intent / intel_verdict /
// recency instead. (ROADMAP #17.12 amended)
const FACET_DIMS = ["age_band", "ip_band", "intent", "intel_verdict"];
const FACET_LABEL = {
  age_band:      "Age",
  ip_band:       "IP count",
  intent:        "Intent",
  intel_verdict: "Intel verdict",
};

// Tooltip text for the category facet — mirrors the per-section hints
// the three-accordion layout used to surface.
const STREAM_TOOLTIP = {
  all:       "Show every category",
  drift:     "Changed — playbooks/campaigns that shifted from baseline",
  discovery: "New — first appearances and intel verdict flips",
  coverage:  "Confirm — confirm a row to start tracking drift on the artifact",
};

const state = {
  status: "new",     // single status (chip click), or "all"
  stream: "",        // "" = all categories; or "drift" | "discovery" | "coverage"
  sort: "last_seen", // reverse-chronological by default — score is uncalibrated
  facets: {},        // {dim: bucket_key} — one active bucket per dim
  selectedIds: new Set(), // multi-select for bulk status (ROADMAP #17.4)
  lastRows: [],           // most recent render, indexed by selection ops
  focusIdx: -1,           // keyboard-focused row index into lastRows (#16)
  since: "",              // ISO timestamp filter — "show only what's new since X" (#17)
  referenceTs: null,      // session-stable anchor for the since-strip
};

function parseQuery() {
  const q = new URLSearchParams(location.search);
  if (q.has("status")) state.status = q.get("status");
  if (q.has("stream")) state.stream = q.get("stream");
  if (q.has("sort")) state.sort = q.get("sort");
  if (q.has("since")) state.since = q.get("since");
  for (const dim of FACET_DIMS) {
    if (q.has(dim)) state.facets[dim] = q.get(dim);
  }
}

function pushQuery() {
  const q = new URLSearchParams();
  q.set("status", state.status);
  if (state.stream) q.set("stream", state.stream);
  if (state.sort !== "last_seen") q.set("sort", state.sort);
  if (state.since) q.set("since", state.since);
  for (const dim of FACET_DIMS) {
    if (state.facets[dim]) q.set(dim, state.facets[dim]);
  }
  history.replaceState(null, "", "?" + q.toString());
}

function facetParams() {
  const p = new URLSearchParams();
  for (const dim of FACET_DIMS) {
    if (state.facets[dim]) p.set(dim, state.facets[dim]);
  }
  return p;
}

function el(tag, attrs, children) {
  const e = document.createElement(tag);
  if (attrs) for (const k in attrs) {
    if (k === "class") e.className = attrs[k];
    // Removed: a raw `html:` attr that set innerHTML directly. It was unused
    // and a latent XSS sink for attacker-controlled fields. If a future caller
    // genuinely needs raw HTML, re-add it with explicit escaping of any
    // untrusted interpolation — do NOT pass attacker text through innerHTML.
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), attrs[k]);
    else e.setAttribute(k, attrs[k]);
  }
  if (children) for (const c of children) {
    if (c == null) continue;
    e.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return e;
}

function fmtScore(s) {
  if (s == null) return "—";
  const n = +s;
  return Number.isNaN(n) ? "—" : n.toFixed(2);
}

function fmtTs(s) { return s ? s.slice(0, 10) : "—"; }

function kindBadge(kind) {
  let cls = "fnd-kind-disc";
  if (kind === "playbook") cls = "fnd-kind-playbook";
  else if (kind === "campaign") cls = "fnd-kind-campaign";
  else if (kind && kind.endsWith("_drift")) cls = "fnd-kind-drift";
  else if (kind === "campaign_growth" || kind === "playbook_resurgence") cls = "fnd-kind-drift";
  return el("span", {class: `fnd-kind-badge ${cls}`}, [kind || "?"]);
}

function artifactLabel(r) {
  const a = r.artifact || {};
  const ev = r.evidence || {};
  if (!a.value) return "—";
  if (a.kind === "playbook") return ev.playbook_name || a.value;
  if (a.kind === "campaign") return ev.campaign_name || a.value;
  return a.value;
}

function sizeCell(r) {
  const ev = r.evidence || {};
  const parts = [];
  const sess = ev.session_count ?? ev.member_sessions;
  const ips = ev.ip_count ?? ev.member_ips;
  if (sess != null) parts.push(`${sess} sess`);
  if (ips != null) parts.push(`${ips} IPs`);
  return parts.length ? parts.join(" · ") : "—";
}

// ---------------------------------------------------------------------------
// Filter chips
// ---------------------------------------------------------------------------

function renderFacets(facetCounts) {
  const root = document.getElementById("facet-rail-extras");
  if (!root) return;
  root.innerHTML = "";

  const activeCount = Object.values(state.facets).filter(Boolean).length;
  if (activeCount > 0) {
    const clear = el("div", {class: "facet-group"}, [
      el("h5", null, ["Active facets"]),
      el("a", {
        href: "#", class: "facet-row",
        onclick: (e) => {
          e.preventDefault();
          state.facets = {};
          pushQuery();
          refreshAll();
        },
      }, [`clear ${activeCount} filter${activeCount === 1 ? "" : "s"}`]),
    ]);
    root.appendChild(clear);
  }

  for (const dim of FACET_DIMS) {
    const buckets = facetCounts[dim] || [];
    // Skip empty dimensions to keep the rail compact.
    const hasAny = buckets.some(b => b.count > 0) || state.facets[dim];
    if (!hasAny) continue;
    const group = el("div", {class: "facet-group"});
    group.appendChild(el("h5", null, [FACET_LABEL[dim] || dim]));
    for (const b of buckets) {
      if (b.count === 0 && state.facets[dim] !== b.key) continue;
      const isActive = state.facets[dim] === b.key;
      const row = el("div", {
        class: "facet-row" + (isActive ? " active" : ""),
        onclick: () => {
          // Toggle: clicking active bucket clears the dim; clicking a
          // different one swaps.
          state.facets[dim] = isActive ? "" : b.key;
          if (!state.facets[dim]) delete state.facets[dim];
          pushQuery();
          refreshAll();
        },
      }, [b.key, el("span", {class: "count"}, [`${b.count}`])]);
      group.appendChild(row);
    }
    root.appendChild(group);
  }
}


function renderStatusChips(counts) {
  const wrap = document.getElementById("status-chips");
  wrap.innerHTML = "";
  const all = ["all", ...STATUSES];
  for (const s of all) {
    const count = s === "all"
      ? Object.values(counts || {}).reduce((a, b) => a + b, 0)
      : (counts && counts[s]) || 0;
    const chip = el("span", {
      class: "facet-row" + (state.status === s ? " active" : ""),
      "data-tooltip": STATUS_TOOLTIP[s] || "",
      onclick: () => {
        state.status = s;
        pushQuery();
        refreshAll();
      },
    }, [s, el("span", {class: "count"}, [`${count}`])]);
    wrap.appendChild(chip);
  }
}

function renderStreamChips(counts) {
  const wrap = document.getElementById("stream-chips");
  if (!wrap) return;
  wrap.innerHTML = "";
  // "all" is represented by state.stream === "" so we don't send the
  // filter; otherwise drift/discovery/coverage map to the backend keys.
  const entries = [
    {key: "",          label: "all",     count: Object.values(counts || {}).reduce((a, b) => a + b, 0)},
    {key: "drift",     label: STREAM_LABEL.drift,     count: (counts && counts.drift)     || 0},
    {key: "discovery", label: STREAM_LABEL.discovery, count: (counts && counts.discovery) || 0},
    {key: "coverage",  label: STREAM_LABEL.coverage,  count: (counts && counts.coverage)  || 0},
  ];
  for (const e of entries) {
    const tooltipKey = e.key || "all";
    const chip = el("span", {
      class: "facet-row" + (state.stream === e.key ? " active" : ""),
      "data-tooltip": STREAM_TOOLTIP[tooltipKey] || "",
      onclick: () => {
        state.stream = e.key;
        pushQuery();
        refreshAll();
      },
    }, [e.label, el("span", {class: "count"}, [`${e.count}`])]);
    wrap.appendChild(chip);
  }
}

// ---------------------------------------------------------------------------
// Inbox table
// ---------------------------------------------------------------------------

function renderInbox(rows) {
  const body = document.getElementById("inbox-rows");
  body.innerHTML = "";
  if (!rows.length) {
    const scope = state.stream
      ? `${(STREAM_LABEL[state.stream] || state.stream).toLowerCase()} `
      : "";
    body.appendChild(el("p", {class: "fnd-empty"}, [
      `no ${scope}findings match this filter`,
    ]));
    return;
  }
  const table = el("table", {class: "fnd-table"});
  const headCb = el("input", {type: "checkbox", class: "fnd-select-all", title: "Select all visible"});
  headCb.addEventListener("change", (e) => {
    if (e.target.checked) for (const r of rows) state.selectedIds.add(r._id || r.finding_id);
    else for (const r of rows) state.selectedIds.delete(r._id || r.finding_id);
    syncSelectionUI(rows);
  });
  const thead = el("thead", null, [el("tr", null, [
    el("th", {class: "select"}, [headCb]),
    el("th", null, ["Kind"]),
    el("th", null, ["Artifact"]),
    el("th", null, ["Size"]),
    el("th", null, ["Trend"]),
    el("th", null, ["Narrative"]),
    el("th", null, ["First"]),
    el("th", null, ["Last"]),
    el("th", null, ["Next"]),
    el("th", null, ["Status"]),
  ])]);
  table.appendChild(thead);
  const tbody = el("tbody");
  for (const [rowIdx, r] of rows.entries()) {
    const fid = r._id || r.finding_id;
    const tr = el("tr", {
      class: "fnd-row",
      "data-fid": fid,
      onclick: (ev) => {
        // Don't open the drawer when interacting with the status select
        // or the selection checkbox.
        const t = ev.target.tagName;
        if (t === "SELECT" || t === "OPTION" || t === "INPUT") return;
        // Click also moves keyboard focus so j/k continue from the
        // clicked row.
        state.focusIdx = rowIdx;
        openDrawer(fid);
      },
    });
    const cb = el("input", {type: "checkbox", class: "fnd-row-select", "data-fid": fid});
    cb.checked = state.selectedIds.has(fid);
    cb.addEventListener("change", (e) => {
      if (e.target.checked) state.selectedIds.add(fid);
      else state.selectedIds.delete(fid);
      syncSelectionUI(rows);
    });
    tr.appendChild(el("td", {class: "select"}, [cb]));
    tr.appendChild(el("td", null, [kindBadge(r.kind)]));
    tr.appendChild(el("td", {class: "artifact"}, [artifactLabel(r)]));
    tr.appendChild(el("td", {class: "size"}, [sizeCell(r)]));
    // Trend — the same lifecycle snapshots the drawer plots, rendered
    // small so the analyst can scan "is this still moving?" without
    // opening every row. (#20)
    const snaps = r.lifecycle_snapshots || [];
    const trendCell = el("td", {class: "trend"});
    const spark = inlineSparkline(snaps, {w: 120, h: 18, stroke: 1.2});
    if (spark) {
      trendCell.appendChild(spark);
      const last = snaps[snaps.length - 1] || {};
      const first = snaps[0] || {};
      trendCell.setAttribute(
        "data-tooltip",
        `${snaps.length} snapshots · ` +
        `${first.session_count ?? "?"} → ${last.session_count ?? "?"} sessions`,
      );
    } else {
      trendCell.appendChild(el("span", {class: "trend-empty"}, ["—"]));
    }
    tr.appendChild(trendCell);
    // Score lives in the drawer only — the inbox triage decision hangs
    // on intent/intel_verdict/recency, not a numeric facet. (#12 amended)
    const narrText = r.narrative || "";
    const narrCell = el("td", {class: "narrative"});
    narrCell.appendChild(el("span", {class: "narrative-text"}, [narrText]));
    if (narrText) narrCell.setAttribute("data-tooltip", narrText);
    if (r.narrative_source === "llm") {
      narrCell.appendChild(el("span", {class: "narrative-llm-chip"}, ["LLM"]));
    }
    tr.appendChild(narrCell);
    const ev = r.evidence || {};
    tr.appendChild(el("td", null, [fmtTs(ev.first_seen || r.first_seen_at)]));
    tr.appendChild(el("td", null, [fmtTs(ev.last_seen || r.last_seen_at)]));
    // Next-action chip — the spine. Empty cell when the finding is
    // already confirmed/rejected or no template covers its kind.
    const actCell = el("td", {class: "next-action"});
    const action = nextAction(r);
    if (action) {
      const chip = el("span", {
        class: "action-chip action-" + action.verb,
        "data-tooltip": action.text,
      }, [ACTION_VERB_LABEL[action.verb] || action.verb]);
      actCell.appendChild(chip);
    } else {
      actCell.appendChild(el("span", {class: "action-empty"}, ["—"]));
    }
    tr.appendChild(actCell);
    const sel = el("select", {class: "fnd-status-select", "data-fid": r._id || r.finding_id});
    for (const s of STATUSES) {
      const opt = el("option", {value: s}, [s]);
      if (s === r.status) opt.setAttribute("selected", "selected");
      sel.appendChild(opt);
    }
    sel.addEventListener("change", (e) => mutateStatus(e.target.dataset.fid, e.target.value, sel));
    tr.appendChild(el("td", null, [sel]));
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  body.appendChild(table);
  state.lastRows = rows;
  // Clamp a stale focus if a previous row dropped off the page, but
  // don't auto-focus a row on first paint — the analyst opts into
  // keyboard nav by pressing j/k or clicking a row.
  if (state.focusIdx >= rows.length) state.focusIdx = rows.length - 1;
  syncSelectionUI(rows);
  syncFocusUI();
}

function syncFocusUI() {
  document.querySelectorAll("#inbox-rows tr.fnd-focus").forEach(
    (tr) => tr.classList.remove("fnd-focus"),
  );
  const rows = state.lastRows || [];
  if (state.focusIdx < 0 || state.focusIdx >= rows.length) return;
  const fid = rows[state.focusIdx]._id || rows[state.focusIdx].finding_id;
  const tr = document.querySelector(`#inbox-rows tr.fnd-row[data-fid="${CSS.escape(fid)}"]`);
  if (tr) {
    tr.classList.add("fnd-focus");
    tr.scrollIntoView({block: "nearest", behavior: "smooth"});
  }
}

function moveFocus(delta) {
  const n = state.lastRows.length;
  if (!n) return;
  if (state.focusIdx < 0) state.focusIdx = delta > 0 ? 0 : n - 1;
  else state.focusIdx = Math.max(0, Math.min(n - 1, state.focusIdx + delta));
  syncFocusUI();
}

function focusedRow() {
  if (state.focusIdx < 0 || state.focusIdx >= state.lastRows.length) return null;
  return state.lastRows[state.focusIdx];
}

// Apply a status to either the multi-selected batch (when one exists)
// or to the keyboard-focused row. Routes through the same endpoints
// the bulk bar + per-row select use, so behaviour stays consistent.
async function applyStatusShortcut(newStatus) {
  if (state.selectedIds.size) {
    await bulkMutateStatus(newStatus);
    return;
  }
  const r = focusedRow();
  if (!r) return;
  const fid = r._id || r.finding_id;
  try {
    const resp = await fetch(`/api/finding/${encodeURIComponent(fid)}/status`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({status: newStatus}),
    });
    if (!resp.ok) {
      alert(`status mutation failed: ${await resp.text()}`);
      return;
    }
    await refreshAll();
  } catch (exc) {
    alert(`status mutation failed: ${exc}`);
  }
}

// Cycle the Category facet (all → drift → discovery → coverage → all).
function cycleStream(delta) {
  const order = ["", "drift", "discovery", "coverage"];
  const idx = order.indexOf(state.stream || "");
  const next = order[((idx < 0 ? 0 : idx) + delta + order.length) % order.length];
  state.stream = next;
  pushQuery();
  refreshAll();
}

const SHORTCUTS_HELP = [
  ["j / ↓",     "next row (drawer: advance to next finding)"],
  ["k / ↑",     "previous row (drawer: advance to previous finding)"],
  ["Enter",     "open drawer on focused row"],
  ["c",         "confirm — selection, focused row, or open drawer"],
  ["a",         "ack — selection, focused row, or open drawer"],
  ["r",         "reject — selection, focused row, or open drawer"],
  ["n",         "reset to new — selection, focused row, or open drawer"],
  ["x / Space", "toggle selection on focused row"],
  ["[ / ]",     "previous / next category"],
  ["Escape",    "close drawer · clear selection"],
  ["?",         "show this help"],
];

function toggleShortcutsHelp(force) {
  const pop = document.getElementById("shortcuts-help");
  if (!pop) return;
  const show = force != null ? force : pop.hidden;
  if (show && !pop.dataset.built) {
    const ul = el("ul", {class: "shortcuts-list"});
    for (const [k, v] of SHORTCUTS_HELP) {
      ul.appendChild(el("li", null, [
        el("kbd", null, [k]),
        el("span", null, [v]),
      ]));
    }
    pop.appendChild(ul);
    pop.dataset.built = "1";
  }
  pop.hidden = !show;
}

// When the drawer is open, status + navigation shortcuts auto-advance:
// the analyst burns through findings without ever closing the drawer.
// Re-opens whatever row is now focused; closes the drawer when focus
// runs off the end of the list.
function _advanceDrawerToFocus() {
  const r = focusedRow();
  if (r) openDrawer(r._id || r.finding_id);
  else closeDrawer();
}

function handleShortcut(ev) {
  // Don't hijack typing in any form control (Notes textarea, status
  // select, etc.).
  const t = ev.target;
  if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable)) return;
  if (ev.ctrlKey || ev.metaKey || ev.altKey) return;
  const drawer = document.getElementById("drawer");
  const drawerOpen = drawer && drawer.classList.contains("open");

  const k = ev.key;
  if (k === "?") { ev.preventDefault(); toggleShortcutsHelp(); return; }
  if (k === "Escape") {
    // Precedence: drawer → help popover → multi-select → keyboard focus.
    // Each Escape unwinds one layer of state so the analyst can back
    // all the way out without grabbing the mouse.
    if (drawerOpen) {
      ev.preventDefault();
      closeDrawer();
      return;
    }
    const help = document.getElementById("shortcuts-help");
    if (help && !help.hidden) {
      ev.preventDefault();
      toggleShortcutsHelp(false);
      return;
    }
    if (state.selectedIds.size) {
      ev.preventDefault();
      state.selectedIds.clear();
      syncSelectionUI();
      return;
    }
    if (state.focusIdx >= 0) {
      ev.preventDefault();
      state.focusIdx = -1;
      syncFocusUI();
      return;
    }
    return;
  }

  if (k === "j" || k === "ArrowDown") {
    ev.preventDefault();
    moveFocus(1);
    if (drawerOpen) _advanceDrawerToFocus();
    return;
  }
  if (k === "k" || k === "ArrowUp") {
    ev.preventDefault();
    moveFocus(-1);
    if (drawerOpen) _advanceDrawerToFocus();
    return;
  }
  if (k === "Enter") {
    if (drawerOpen) return;  // let Enter activate focused buttons inside the drawer
    const r = focusedRow();
    if (r) { ev.preventDefault(); openDrawer(r._id || r.finding_id); }
    return;
  }
  if (k === "x" || k === " ") {
    if (drawerOpen) return;
    const r = focusedRow();
    if (!r) return;
    ev.preventDefault();
    const fid = r._id || r.finding_id;
    if (state.selectedIds.has(fid)) state.selectedIds.delete(fid);
    else state.selectedIds.add(fid);
    syncSelectionUI(state.lastRows);
    return;
  }
  // Status shortcuts. Outside the drawer: mutate + the refresh
  // naturally surfaces the next item at the same focus index. Inside
  // the drawer: mutate then auto-advance the drawer to the new
  // focused row so the analyst doesn't break their flow.
  if (k === "c" || k === "a" || k === "r" || k === "n") {
    ev.preventDefault();
    const map = {c: "confirmed", a: "ack", r: "rejected", n: "new"};
    const p = applyStatusShortcut(map[k]);
    if (drawerOpen) p.then(_advanceDrawerToFocus);
    return;
  }
  if (k === "[") {
    if (drawerOpen) return;
    ev.preventDefault();
    cycleStream(-1);
    return;
  }
  if (k === "]") {
    if (drawerOpen) return;
    ev.preventDefault();
    cycleStream(1);
    return;
  }
}

// ────────────────────────────────────────────────────────────────────────────
// "What changed since I last looked" strip (ROADMAP #17.17).
// Per-browser localStorage tracks the most recent visit timestamp.
// Per-session sessionStorage snapshots that value at the start of the
// session so reloads don't lose the reference. The strip shows counts
// and a "show only these" filter; "dismiss" resets the reference to
// now so the strip clears.
// ────────────────────────────────────────────────────────────────────────────
const LS_LAST_VISITED   = "inboxLastVisitedAt";
const SS_REFERENCE_TS   = "inboxReferenceTs";

// ROADMAP #17.9 — return-to-inbox crumb. The drawer's "Open in graph"
// stamps a token here; the graph reads it to render a "← Inbox" crumb;
// the inbox restores scroll on the round-trip back.
const SS_RETURN_PREFIX  = "inboxReturn:";

function saveInboxReturn() {
  const token = "r" + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
  // window.scrollY covers the common case; container scrollTop covers
  // a future layout that scrolls the inbox column internally.
  const container = document.getElementById("inbox-rows");
  const payload = {
    url: location.pathname + location.search,
    scrollY: window.scrollY || 0,
    scrollTop: container ? container.scrollTop : 0,
    ts: Date.now(),
  };
  try {
    sessionStorage.setItem(SS_RETURN_PREFIX + token, JSON.stringify(payload));
  } catch (_) { return null; }
  return token;
}

function consumeInboxReturn(token) {
  if (!token) return null;
  const key = SS_RETURN_PREFIX + token;
  let raw = null;
  try { raw = sessionStorage.getItem(key); } catch (_) { return null; }
  if (!raw) return null;
  try { sessionStorage.removeItem(key); } catch (_) {}
  try { return JSON.parse(raw); } catch (_) { return null; }
}

function initReferenceTs() {
  if (state.referenceTs) return state.referenceTs;
  let ref = null;
  try { ref = sessionStorage.getItem(SS_REFERENCE_TS); } catch (_) {}
  if (!ref) {
    try { ref = localStorage.getItem(LS_LAST_VISITED); } catch (_) {}
    // First-ever visit fallback — assume "24h ago" so the strip can
    // surface a useful snapshot rather than nothing.
    if (!ref) ref = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
    try { sessionStorage.setItem(SS_REFERENCE_TS, ref); } catch (_) {}
    try { localStorage.setItem(LS_LAST_VISITED, new Date().toISOString()); } catch (_) {}
  }
  state.referenceTs = ref;
  return ref;
}

function fmtSinceTime(iso) {
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    const sameDay = d.toDateString() === new Date().toDateString();
    const hh = String(d.getHours()).padStart(2, "0");
    const mm = String(d.getMinutes()).padStart(2, "0");
    if (sameDay) return `${hh}:${mm}`;
    const mon = d.toLocaleDateString(undefined, {month: "short", day: "numeric"});
    return `${mon} ${hh}:${mm}`;
  } catch (_) { return iso; }
}

async function refreshSinceStrip() {
  const strip = document.getElementById("since-strip");
  if (!strip) return;
  const ref = initReferenceTs();
  let data = {new: 0, changed: 0, total: 0};
  try {
    const r = await fetch("/api/findings/since-summary?ts=" + encodeURIComponent(ref));
    if (r.ok) data = await r.json();
  } catch (_) {}
  const textEl    = document.getElementById("since-text");
  const applyBtn  = document.getElementById("since-apply");
  const clearBtn  = document.getElementById("since-clear");
  if (!data.total) {
    strip.hidden = true;
    return;
  }
  strip.hidden = false;
  // Render the count summary plus the human-readable reference time.
  textEl.replaceChildren();
  const parts = [];
  if (data.new)     parts.push(`${data.new} new`);
  if (data.changed) parts.push(`${data.changed} changed`);
  textEl.appendChild(document.createTextNode(parts.join(" · ")));
  const tsSpan = document.createElement("span");
  tsSpan.className = "since-ts";
  tsSpan.textContent = `since ${fmtSinceTime(ref)}`;
  textEl.appendChild(tsSpan);
  // Toggle apply vs clear depending on whether the filter is active.
  applyBtn.hidden = !!state.since;
  clearBtn.hidden = !state.since;
}

// Single fetch — drives both the inbox rows and the rail (status,
// category, dynamic facet groups). The previous code ran four parallel
// fetches (one per stream + one facet-only); one query is sufficient
// now that the three accordions are a single ranked list.
async function fetchInbox() {
  const params = facetParams();
  params.set("status", state.status);
  if (state.stream) params.set("stream", state.stream);
  if (state.since)  params.set("since", state.since);
  params.set("size", 500);
  params.set("from", 0);
  params.set("sort", state.sort);
  try {
    const r = await fetch("/api/findings?" + params.toString());
    if (!r.ok) {
      renderInbox([]);
      return {};
    }
    return await r.json();
  } catch (exc) {
    renderInbox([]);
    return {};
  }
}

async function refreshAll() {
  const data = await fetchInbox();
  renderStatusChips(data.status_counts || {});
  renderStreamChips(data.stream_counts || {});
  renderFacets(data.facet_counts || {});
  renderInbox(data.rows || []);
  refreshSinceStrip();
}

// Keep checkboxes, the bulk bar, and the select-all header in sync with
// state.selectedIds. Called any time a checkbox is toggled or after a
// full table re-render.
function syncSelectionUI(rows) {
  const ids = state.selectedIds;
  const bar = document.getElementById("bulk-bar");
  if (bar) {
    bar.hidden = ids.size === 0;
    const count = document.getElementById("bulk-count");
    if (count) count.textContent = `${ids.size} selected`;
  }
  // Header "select all" — checked iff every visible row is in the set.
  const headCb = document.querySelector(".fnd-select-all");
  if (headCb) {
    if (rows) {
      const visible = rows.map(r => r._id || r.finding_id);
      headCb.checked = visible.length > 0 && visible.every(fid => ids.has(fid));
      headCb.indeterminate = !headCb.checked && visible.some(fid => ids.has(fid));
    } else {
      // Called without the row list (e.g. after "clear selection") —
      // collapse the header state to match the empty set.
      headCb.checked = false;
      headCb.indeterminate = false;
    }
  }
  // Per-row checked state — guard against stale boxes after re-render.
  document.querySelectorAll(".fnd-row-select").forEach((cb) => {
    cb.checked = ids.has(cb.dataset.fid);
  });
}

// Shared formatter — same shape for the bulk "Copy as markdown" path
// (which feeds a weekly-report draft) and the drawer's single-row
// "Copy as markdown" path (which captures one finding for a writeup).
function findingsToMarkdown(rows) {
  const now = new Date().toISOString().slice(0, 10);
  const lines = [
    rows.length === 1
      ? `# ${rows[0].kind} — \`${(rows[0].artifact || {}).kind || "?"}:${(rows[0].artifact || {}).value || "?"}\` (${now})`
      : `# Triage — ${rows.length} findings (${now})`,
    "",
  ];
  for (const r of rows) {
    const a = r.artifact || {};
    const ev = r.evidence || {};
    if (rows.length > 1) {
      lines.push(`## ${r.kind} — \`${a.kind || "?"}:${a.value || "?"}\``);
      lines.push("");
    }
    const meta = [
      `**Status:** ${r.status || "?"}`,
      `**First seen:** ${fmtTs(ev.first_seen || r.first_seen_at)}`,
      `**Last seen:**  ${fmtTs(ev.last_seen  || r.last_seen_at)}`,
    ];
    if (r.score != null) meta.push(`**Score:** ${fmtScore(r.score)}`);
    lines.push(meta.join("  \n"));
    lines.push("");
    if (r.narrative) {
      lines.push(`> ${r.narrative.replace(/\n+/g, " ")}`);
      lines.push("");
    }
    const action = nextAction(r);
    if (action) {
      lines.push(`**Next action:** ${ACTION_VERB_LABEL[action.verb] || action.verb} — ${action.text}`);
      lines.push("");
    }
    const history = r.status_history || [];
    if (history.length) {
      lines.push(`**Notes:**`);
      for (const h of history) {
        const verb = h.from === h.to ? "note" : `${h.from || "?"} → ${h.to || "?"}`;
        const note = h.note ? `: ${h.note}` : "";
        lines.push(`- ${fmtTs(h.ts)} (${verb})${note}`);
      }
      lines.push("");
    }
    if (rows.length > 1) {
      lines.push("---");
      lines.push("");
    }
  }
  return lines.join("\n");
}

// Copy markdown to the clipboard; flash a brief confirmation in the
// given element so the analyst sees the action took.
function copyMarkdown(md, feedbackEl, label) {
  return navigator.clipboard.writeText(md).then(
    () => {
      if (!feedbackEl) return;
      const original = feedbackEl.textContent;
      feedbackEl.textContent = label;
      setTimeout(() => {
        if (feedbackEl.textContent === label) feedbackEl.textContent = original;
      }, 1500);
    },
    (e) => alert(`clipboard write failed: ${e.message}`),
  );
}

function exportSelectedAsMarkdown() {
  const ids = state.selectedIds;
  if (!ids.size) return;
  const rows = state.lastRows.filter(r => ids.has(r._id || r.finding_id));
  if (!rows.length) {
    alert("Selected rows aren't in the current view — try refreshing or unselecting filters.");
    return;
  }
  copyMarkdown(findingsToMarkdown(rows),
               document.getElementById("bulk-count"),
               `copied ${rows.length} as markdown`);
}

function exportDrawerAsMarkdown(data) {
  if (!data) return;
  copyMarkdown(findingsToMarkdown([data]),
               document.getElementById("drawer-md-status"),
               "copied to clipboard");
}

async function bulkMutateStatus(newStatus) {
  const ids = Array.from(state.selectedIds);
  if (!ids.length) return;
  const bar = document.getElementById("bulk-bar");
  if (bar) bar.classList.add("bulk-bar-busy");
  try {
    const r = await fetch("/api/findings/status", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ids, status: newStatus}),
    });
    if (!r.ok) {
      alert(`bulk status mutation failed: ${await r.text()}`);
      return;
    }
    const data = await r.json();
    if (data.errors && data.errors.length) {
      alert(`${data.n_updated} updated, ${data.errors.length} failed:\n` +
            data.errors.slice(0, 5).map(e => `${e.id}: ${e.error}`).join("\n"));
    }
    state.selectedIds.clear();
    await refreshAll();
  } catch (exc) {
    alert(`bulk status mutation failed: ${exc}`);
  } finally {
    if (bar) bar.classList.remove("bulk-bar-busy");
  }
}

async function mutateStatus(fid, newStatus, selEl) {
  if (!fid || !newStatus) return;
  selEl.disabled = true;
  try {
    const r = await fetch(`/api/finding/${encodeURIComponent(fid)}/status`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({status: newStatus}),
    });
    if (!r.ok) {
      alert(`status mutation failed: ${await r.text()}`);
    } else {
      await refreshAll();
    }
  } catch (exc) {
    alert(`status mutation failed: ${exc}`);
  } finally {
    selEl.disabled = false;
  }
}

// ---------------------------------------------------------------------------
// Detail drawer
// ---------------------------------------------------------------------------

function inlineSparkline(snapshots, opts) {
  if (!snapshots || !snapshots.length) return null;
  const w = (opts && opts.w) || 480;
  const h = (opts && opts.h) || 50;
  const stroke = (opts && opts.stroke) || 1.5;
  const sessionVals = snapshots.map(s => +(s.session_count ?? 0));
  const max = Math.max(1, ...sessionVals);
  const pad = Math.max(2, stroke * 2);
  const SVG_NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("width", w);
  svg.setAttribute("height", h);
  svg.setAttribute("class", "sparkline");

  // Single snapshot: a path with one MoveTo has zero geometry and
  // renders nothing. Drop a small dot at the centre so the cell still
  // reads as "this finding exists, no trend across cycles yet".
  if (sessionVals.length === 1) {
    const dot = document.createElementNS(SVG_NS, "circle");
    dot.setAttribute("cx", String(w / 2));
    dot.setAttribute("cy", String(h / 2));
    dot.setAttribute("r", String(Math.max(1.2, stroke * 1.2)));
    dot.setAttribute("fill", "#4cc1ff");
    svg.appendChild(dot);
    return svg;
  }

  const dx = w / (snapshots.length - 1);
  let d = "";
  sessionVals.forEach((v, i) => {
    const x = i * dx;
    const y = h - (v / max) * (h - pad) - pad / 2;
    d += (i === 0 ? "M" : "L") + `${x.toFixed(1)},${y.toFixed(1)} `;
  });
  const path = document.createElementNS(SVG_NS, "path");
  path.setAttribute("d", d.trim());
  path.setAttribute("stroke", "#4cc1ff");
  path.setAttribute("stroke-width", String(stroke));
  path.setAttribute("fill", "none");
  svg.appendChild(path);
  return svg;
}

function intelPill(label) {
  if (!label) return null;
  const cls = ["clean", "malicious", "mixed", "no_data"].includes(label) ? label : "no_data";
  return el("span", {class: `intel-pill ${cls}`}, [label]);
}

// --- Cluster specificity (ROADMAP #4) -------------------------------------
const SPOT_KEY = "prism.spotlightOnly";
// "Distinctive" cutoff. Source-of-truth precedence:
//   localStorage `prism.spotlightThreshold` → server /api/config/ui → 0.5
// Initialized synchronously from localStorage; server value fills in async.
// Mirror of the same init in app.js so the findings page works standalone
// (findings.html doesn't load app.js).
function _parseSpecThresholdLS() {
  const raw = localStorage.getItem("prism.spotlightThreshold");
  if (raw == null) return null;
  const v = parseFloat(raw);
  return (isFinite(v) && v >= 0 && v <= 1) ? v : null;
}
window.PrismUI = window.PrismUI || {};
if (window.PrismUI.specThreshold == null) {
  const ls = _parseSpecThresholdLS();
  window.PrismUI.specThreshold = ls == null ? 0.5 : ls;
}
(async function _loadUIConfig() {
  try {
    const r = await fetch("/api/config/ui");
    if (!r.ok) return;
    const c = await r.json();
    if (_parseSpecThresholdLS() != null) return;
    if (typeof c.specificity_threshold === "number"
        && c.specificity_threshold >= 0 && c.specificity_threshold <= 1) {
      window.PrismUI.specThreshold = c.specificity_threshold;
      // If a drawer is currently open, re-render it so pills reflect the
      // new threshold; otherwise next open picks it up.
      if (window.__drawerData) renderDrawer(window.__drawerData);
    }
  } catch (_) { /* fallback in place */ }
})();
function specThreshold() {
  return (window.PrismUI && window.PrismUI.specThreshold) ?? 0.5;
}
function spotlightOn() { return localStorage.getItem(SPOT_KEY) === "1"; }
function setSpotlight(v) { localStorage.setItem(SPOT_KEY, v ? "1" : "0"); }

// Filled pill for cluster-specific entries, faded outline for commodity ones.
function specPill(score) {
  if (score == null) return null;
  const specific = score >= specThreshold();
  return el("span", {
    class: `spec-pill ${specific ? "specific" : "commodity"}`,
    title: `cluster specificity ${score.toFixed(2)} (1.0 = unique to this cluster, 0 = commodity)`,
  }, [(specific ? "★ " : "") + score.toFixed(2)]);
}

// True when spotlight is on AND this entry is below the distinctiveness floor.
function spotlightHides(score) {
  return spotlightOn() && (score == null || score < specThreshold());
}

function renderDrawer(data) {
  const body = document.getElementById("drawer-body");
  body.innerHTML = "";
  // Stash so the spotlight toggle can re-render without a re-fetch.
  window.__drawerData = data;
  const a = data.artifact || {};
  document.getElementById("drawer-title").textContent =
    `${data.kind || "finding"} — ${artifactLabel(data)}`;
  document.getElementById("drawer-subtitle").textContent =
    `${a.kind || "?"}:${a.value || ""}  •  status: ${data.status || "?"}  •  score ${fmtScore(data.score)}`;

  // Next action — the spine (ROADMAP #17.14). Rendered first so it's
  // the analyst's eye-anchor on drawer open. Suppressed for already-
  // decided rows so the drawer doesn't pretend there's something left
  // to do.
  const action = nextAction(data);
  if (action) {
    const sec = el("div", {class: "drawer-section drawer-next-action"});
    sec.appendChild(el("span", {
      class: "action-chip action-" + action.verb,
    }, [ACTION_VERB_LABEL[action.verb] || action.verb]));
    sec.appendChild(el("span", {class: "action-text"}, [" " + action.text]));
    body.appendChild(sec);
  }

  // Narrative
  if (data.narrative) {
    const sec = el("div", {class: "drawer-section"}, [
      el("h4", null, ["Narrative"]),
      el("p", null, [data.narrative]),
    ]);
    if (data.narrative_source === "llm") {
      sec.appendChild(el("div", {class: "drawer-meta"}, [
        "LLM-generated; confidence " + ((data.narrative_confidence ?? 0).toFixed(2)),
      ]));
    }
    body.appendChild(sec);
  }

  // Lifecycle: sparkline + summary
  const lc = data.lifecycle || {};
  const snaps = lc.snapshots || [];
  if (snaps.length) {
    const sec = el("div", {class: "drawer-section"});
    sec.appendChild(el("h4", null, ["Lifecycle"]));
    const meta = [
      `${lc.runs_observed || 0} runs observed`,
      `silent_runs_current: ${lc.silent_runs_current ?? 0}`,
      `first seen: ${fmtTs(lc.first_seen_ever)}`,
    ].join("  •  ");
    sec.appendChild(el("p", {class: "drawer-meta"}, [meta]));
    const spark = inlineSparkline(snaps);
    if (spark) sec.appendChild(spark);
    sec.appendChild(el("div", {class: "drawer-meta"}, [
      `session_count: ${snaps[0].session_count ?? "?"} → ${snaps[snaps.length-1].session_count ?? "?"}`,
    ]));
    body.appendChild(sec);
  }

  // Spotlight toggle (ROADMAP #4) — show only cluster-distinctive entries.
  // Only rendered when specificity is available (cluster pass has run).
  const cmds = data.top_commands || [];
  const ips = data.top_ips || [];
  const hasSpec = cmds.some(c => c.specificity != null) || ips.some(i => i.specificity != null);
  if (hasSpec) {
    const cb = el("input", {type: "checkbox"});
    cb.checked = spotlightOn();
    cb.addEventListener("change", () => { setSpotlight(cb.checked); renderDrawer(window.__drawerData); });
    const sec = el("div", {class: "drawer-section"}, [
      el("label", {class: "spotlight-toggle"}, [cb, " show distinctive only"]),
    ]);
    body.appendChild(sec);
  }

  // Pivot sub-panel host — populated when a command/IP is clicked.
  const pivotHost = el("div", {id: "drawer-pivot"});

  // Top commands
  const cmdsShown = spotlightOn() ? cmds.filter(c => !spotlightHides(c.specificity)) : cmds;
  if (cmdsShown.length) {
    const sec = el("div", {class: "drawer-section"});
    sec.appendChild(el("h4", null, ["Top novel commands"]));
    const ul = el("ul", {style: "padding-left:18px;margin:0;"});
    for (const c of cmdsShown) {
      const code = el("a", {
        class: "pivot-link", href: "#",
        onclick: (e) => { e.preventDefault(); openPivot("command", c.command_id, pivotHost); },
      }, [el("code", null, [c.command || "(empty)"])]);
      const li = el("li", null, [
        code,
        el("span", {class: "drawer-meta", style: "margin-left:6px;"}, [
          `nov ${c.novelty?.toFixed(2) ?? "?"}`,
        ]),
      ]);
      const sp = specPill(c.specificity);
      if (sp) li.appendChild(sp);
      if (c.description) {
        li.appendChild(el("div", {class: "drawer-meta"}, [c.description]));
      }
      ul.appendChild(li);
    }
    sec.appendChild(ul);
    body.appendChild(sec);
  }

  // Top IPs
  const ipsShown = spotlightOn() ? ips.filter(i => !spotlightHides(i.specificity)) : ips;
  if (ipsShown.length) {
    const sec = el("div", {class: "drawer-section"});
    sec.appendChild(el("h4", null, ["Top member IPs"]));
    const ul = el("ul", {style: "padding-left:18px;margin:0;"});
    for (const i of ipsShown) {
      const link = el("a", {
        class: "pivot-link", href: "#",
        onclick: (e) => { e.preventDefault(); openPivot("ip", i.ip, pivotHost); },
      }, [i.ip || "?"]);
      const li = el("li", null, [
        link,
        el("span", {class: "drawer-meta", style: "margin-left:6px;"}, [`${i.session_count} sess`]),
      ]);
      const sp = specPill(i.specificity);
      if (sp) li.appendChild(sp);
      const pill = intelPill(i.intel_verdict);
      if (pill) li.appendChild(pill);
      ul.appendChild(li);
    }
    sec.appendChild(ul);
    body.appendChild(sec);
  }

  body.appendChild(pivotHost);

  // Convergent campaigns
  const convs = data.convergent_campaigns || [];
  if (convs.length) {
    const sec = el("div", {class: "drawer-section"});
    sec.appendChild(el("h4", null, ["Convergent campaigns"]));
    const ul = el("ul", {style: "padding-left:18px;margin:0;"});
    for (const c of convs) {
      ul.appendChild(el("li", null, [
        `${c.campaign_name}  `,
        el("span", {class: "drawer-meta"}, [`(${c.kind}) — ${c.ip_count} IPs`]),
      ]));
    }
    sec.appendChild(ul);
    body.appendChild(sec);
  }

  // Anchor history (audit trail)
  const anchors = lc.confirm_anchors || [];
  if (anchors.length) {
    const sec = el("div", {class: "drawer-section"});
    sec.appendChild(el("h4", null, ["Anchor history"]));
    const ul = el("ul", {style: "padding-left:18px;margin:0;"});
    for (const an of anchors) {
      const li = el("li", null, [`${an.source} — ${fmtTs(an.ts)}`]);
      if (an.source === "provisional") {
        li.appendChild(el("span", {class: "provisional-chip"}, ["prov"]));
      }
      if (an.confirming_finding_id) {
        li.appendChild(el("div", {class: "drawer-meta"}, [`confirmed by ${an.confirming_finding_id}`]));
      }
      ul.appendChild(li);
    }
    sec.appendChild(ul);
    body.appendChild(sec);
  }

  // Open-in-graph link. ROADMAP #17.9: stash the inbox URL + scroll
  // position under a sessionStorage key so the graph's "← Inbox" crumb
  // can restore the exact view on return. We don't encode the full
  // state into the URL because facets+scroll can be long and would
  // bloat the graph URL for share-links; sessionStorage stays local
  // to the tab.
  if (a.kind === "playbook" || a.kind === "campaign" || a.kind === "ip") {
    const sec = el("div", {class: "drawer-section"});
    const link = el("a", {
      href: `/graph?ioc=${encodeURIComponent(a.kind)}:${encodeURIComponent(a.value)}`,
      class: "nav-link",
    }, ["Open in graph →"]);
    link.addEventListener("click", (ev) => {
      const token = saveInboxReturn();
      if (token) {
        const u = new URL(ev.currentTarget.href, location.origin);
        u.searchParams.set("return", token);
        ev.currentTarget.href = u.pathname + "?" + u.searchParams.toString();
      }
    });
    sec.appendChild(link);
    body.appendChild(sec);
  }

  // Notes — show status_history annotations and let the analyst append
  // a free-text note without forcing a status flip (ROADMAP #17.4
  // amended). Notes double as the writeup substrate; the markdown
  // export below stitches them into the day's triage report.
  renderNotesSection(body, data);
}

function renderNotesSection(body, data) {
  const fid = data._id || data.finding_id;
  if (!fid) return;
  const sec = el("div", {class: "drawer-section drawer-notes"});
  sec.appendChild(el("h4", null, ["Notes"]));

  const history = (data.status_history || []).slice().reverse();
  if (history.length) {
    const ul = el("ul", {class: "notes-list"});
    for (const h of history) {
      const li = el("li");
      const head = el("div", {class: "drawer-meta"}, [
        fmtTs(h.ts),
        h.from === h.to ? " · note" : ` · ${h.from || "?"} → ${h.to || "?"}`,
      ]);
      li.appendChild(head);
      if (h.note) li.appendChild(el("div", {class: "note-text"}, [h.note]));
      ul.appendChild(li);
    }
    sec.appendChild(ul);
  } else {
    sec.appendChild(el("p", {class: "drawer-meta"}, ["no notes yet"]));
  }

  const ta = el("textarea", {
    class: "note-textarea", rows: "2",
    placeholder: "Add a note (free text). Survives status changes and feeds the markdown export.",
  });
  const btn = el("button", {class: "note-add-btn", type: "button"}, ["Add note"]);
  btn.addEventListener("click", async () => {
    const text = ta.value.trim();
    if (!text) return;
    btn.disabled = true;
    try {
      const r = await fetch(`/api/finding/${encodeURIComponent(fid)}/note`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({note: text}),
      });
      if (!r.ok) { alert(`add-note failed: ${await r.text()}`); return; }
      ta.value = "";
      // Refresh the drawer with the new history entry.
      await openDrawer(fid);
    } finally {
      btn.disabled = false;
    }
  });
  sec.appendChild(ta);
  sec.appendChild(btn);
  body.appendChild(sec);
}

// Click-to-pivot (ROADMAP #4): fetch an IP / command cross-cluster footprint
// and render it into the drawer's pivot host.
async function openPivot(kind, id, host) {
  if (!id || !host) return;
  host.replaceChildren(el("div", {class: "drawer-section pivot-panel"}, [
    el("p", {class: "drawer-meta"}, ["loading pivot…"]),
  ]));
  host.scrollIntoView({behavior: "smooth", block: "nearest"});
  let data;
  try {
    const path = kind === "ip"
      ? `/api/ip/${encodeURIComponent(id)}/activity`
      : `/api/command/${encodeURIComponent(id)}/activity`;
    const r = await fetch(path);
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
    data = await r.json();
  } catch (e) {
    host.replaceChildren(el("div", {class: "drawer-section pivot-panel"}, [
      el("p", {class: "drawer-meta"}, [`pivot failed: ${e.message}`]),
    ]));
    return;
  }

  const sec = el("div", {class: "drawer-section pivot-panel"});
  const close = el("button", {class: "pivot-close", title: "close pivot",
    onclick: () => host.replaceChildren()}, ["✕"]);
  sec.appendChild(el("div", {class: "pivot-head"}, [
    el("h4", null, [kind === "ip" ? `IP pivot — ${id}` : `Command pivot — ${id}`]), close,
  ]));

  const meta = [`${data.total_sessions ?? 0} sessions`];
  if (kind === "ip") {
    if (data.intel_verdict) meta.push(`intel: ${data.intel_verdict}`);
    if (data.first_seen) meta.push(`first ${fmtTs(data.first_seen)}`);
    if (data.last_seen) meta.push(`last ${fmtTs(data.last_seen)}`);
  } else {
    if (data.occurrence_count != null) meta.push(`${data.occurrence_count} occurrences`);
    if (data.intent) meta.push(`intent: ${data.intent}`);
  }
  sec.appendChild(el("p", {class: "drawer-meta"}, [meta.join("  •  ")]));
  if (kind === "command" && data.command_line) {
    sec.appendChild(el("code", {class: "pivot-cmd"}, [data.command_line]));
  }

  const listBlock = (title, items, render) => {
    if (!items || !items.length) return;
    sec.appendChild(el("div", {class: "drawer-meta", style: "margin-top:6px;"}, [title]));
    const ul = el("ul", {style: "padding-left:18px;margin:0;"});
    for (const it of items) ul.appendChild(el("li", null, render(it)));
    sec.appendChild(ul);
  };
  // Closes the loop drawer → graph: every row carries a tiny ↗ that opens
  // the graph anchored to that entity (uses the existing /graph?ioc= route).
  const graphLink = (type, id) => el("a", {
    class: "pivot-link", href: `/graph?ioc=${encodeURIComponent(type)}:${encodeURIComponent(id || "")}`,
    title: `open ${type} in graph`,
    style: "margin-left:6px;",
  }, ["↗"]);
  listBlock("also appears in playbooks:", data.playbooks, (p) => [
    `${p.playbook_name || p.playbook_id}`,
    el("span", {class: "drawer-meta", style: "margin-left:6px;"}, [`${p.session_count} sess`]),
    graphLink("playbook", p.playbook_id),
  ]);
  if (kind === "ip") {
    listBlock("campaigns:", data.campaigns, (c) => [c.name || c.campaign_id]);
  } else {
    listBlock("source IPs:", data.ips, (i) => [
      i.ip, el("span", {class: "drawer-meta", style: "margin-left:6px;"}, [`${i.session_count} sess`]),
      graphLink("ip", i.ip),
    ]);
  }
  host.replaceChildren(sec);
  host.scrollIntoView({behavior: "smooth", block: "nearest"});
}

async function openDrawer(finding_id) {
  if (!finding_id) return;
  document.getElementById("drawer-title").textContent = "loading…";
  document.getElementById("drawer-subtitle").textContent = "";
  document.getElementById("drawer-body").innerHTML = "";
  document.getElementById("drawer-backdrop").style.display = "block";
  document.getElementById("drawer").classList.add("open");
  try {
    const r = await fetch(`/api/finding/${encodeURIComponent(finding_id)}/detail`);
    if (!r.ok) {
      document.getElementById("drawer-body").innerHTML =
        `<div class="drawer-section">load failed: ${await r.text()}</div>`;
      return;
    }
    renderDrawer(await r.json());
  } catch (exc) {
    document.getElementById("drawer-body").innerHTML =
      `<div class="drawer-section">load failed: ${exc}</div>`;
  }
}

function closeDrawer() {
  document.getElementById("drawer-backdrop").style.display = "none";
  document.getElementById("drawer").classList.remove("open");
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

(function init() {
  parseQuery();

  // Drawer close handlers (Escape lives in handleShortcut so the
  // precedence chain stays in one place).
  document.querySelector("#drawer .drawer-close").addEventListener("click", closeDrawer);
  document.getElementById("drawer-backdrop").addEventListener("click", closeDrawer);

  const sortSel = document.getElementById("sort-select");
  sortSel.value = state.sort;
  sortSel.addEventListener("change", () => {
    state.sort = sortSel.value;
    pushQuery();
    refreshAll();
  });

  // Bulk-action bar wiring — status buttons carry data-status; the
  // export button uses its own id; "clear selection" empties the set.
  document.querySelectorAll("#bulk-bar .bulk-btn[data-status]").forEach((btn) => {
    btn.addEventListener("click", () => bulkMutateStatus(btn.dataset.status));
  });
  const exportBtn = document.getElementById("bulk-export");
  if (exportBtn) exportBtn.addEventListener("click", exportSelectedAsMarkdown);
  const drawerMdBtn = document.getElementById("drawer-md-btn");
  if (drawerMdBtn) drawerMdBtn.addEventListener(
    "click",
    () => exportDrawerAsMarkdown(window.__drawerData),
  );

  // Keyboard shortcuts (ROADMAP #17.16). j/k navigate, Enter opens,
  // c/r/a/n flip status, [ / ] cycle category, ? toggles help.
  document.addEventListener("keydown", handleShortcut);
  const helpBtn = document.getElementById("shortcuts-help-btn");
  if (helpBtn) helpBtn.addEventListener("click", () => toggleShortcutsHelp());

  // "What changed since I last looked" strip (ROADMAP #17.17).
  const applyBtn = document.getElementById("since-apply");
  if (applyBtn) applyBtn.addEventListener("click", () => {
    state.since = initReferenceTs();
    pushQuery();
    refreshAll();
  });
  const clearBtn2 = document.getElementById("since-clear");
  if (clearBtn2) clearBtn2.addEventListener("click", () => {
    state.since = "";
    pushQuery();
    refreshAll();
  });
  const dismissBtn = document.getElementById("since-dismiss");
  if (dismissBtn) dismissBtn.addEventListener("click", () => {
    // Move the reference forward to "now" so the strip falls silent
    // until the next pipeline run produces something fresh. Also lift
    // the filter if it was active.
    const now = new Date().toISOString();
    try { sessionStorage.setItem(SS_REFERENCE_TS, now); } catch (_) {}
    try { localStorage.setItem(LS_LAST_VISITED, now); } catch (_) {}
    state.referenceTs = now;
    if (state.since) {
      state.since = "";
      pushQuery();
      refreshAll();
    } else {
      refreshSinceStrip();
    }
  });
  const clearBtn = document.getElementById("bulk-clear");
  if (clearBtn) clearBtn.addEventListener("click", () => {
    state.selectedIds.clear();
    syncSelectionUI();
  });

  // Round-trip from the graph (ROADMAP #17.9). The graph's "← Inbox"
  // crumb appends ?restore=<token>; consume the matching payload, kick
  // off the normal refresh, then restore scroll once the rows render.
  const params = new URLSearchParams(location.search);
  const restoreToken = params.get("restore");
  let restorePayload = null;
  if (restoreToken) {
    restorePayload = consumeInboxReturn(restoreToken);
    params.delete("restore");
    const tail = params.toString();
    history.replaceState(null, "", location.pathname + (tail ? "?" + tail : ""));
  }

  refreshAll().then(() => {
    if (!restorePayload) return;
    requestAnimationFrame(() => {
      if (restorePayload.scrollY) window.scrollTo(0, restorePayload.scrollY);
      const container = document.getElementById("inbox-rows");
      if (container && restorePayload.scrollTop) container.scrollTop = restorePayload.scrollTop;
    });
  });
})();
