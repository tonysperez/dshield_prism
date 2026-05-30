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
};

function parseQuery() {
  const q = new URLSearchParams(location.search);
  if (q.has("status")) state.status = q.get("status");
  if (q.has("stream")) state.stream = q.get("stream");
  if (q.has("sort")) state.sort = q.get("sort");
  for (const dim of FACET_DIMS) {
    if (q.has(dim)) state.facets[dim] = q.get(dim);
  }
}

function pushQuery() {
  const q = new URLSearchParams();
  q.set("status", state.status);
  if (state.stream) q.set("stream", state.stream);
  if (state.sort !== "last_seen") q.set("sort", state.sort);
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
  const thead = el("thead", null, [el("tr", null, [
    el("th", null, ["Kind"]),
    el("th", null, ["Artifact"]),
    el("th", null, ["Size"]),
    el("th", null, ["Trend"]),
    el("th", null, ["Narrative"]),
    el("th", null, ["First"]),
    el("th", null, ["Last"]),
    el("th", null, ["Status"]),
  ])]);
  table.appendChild(thead);
  const tbody = el("tbody");
  for (const r of rows) {
    const tr = el("tr", {
      class: "fnd-row",
      onclick: (ev) => {
        // Don't open the drawer when interacting with the status select.
        if (ev.target.tagName === "SELECT" || ev.target.tagName === "OPTION") return;
        openDrawer(r._id || r.finding_id);
      },
    });
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
}

// Single fetch — drives both the inbox rows and the rail (status,
// category, dynamic facet groups). The previous code ran four parallel
// fetches (one per stream + one facet-only); one query is sufficient
// now that the three accordions are a single ranked list.
async function fetchInbox() {
  const params = facetParams();
  params.set("status", state.status);
  if (state.stream) params.set("stream", state.stream);
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

  // Lineage (P2.2) — predecessor lifecycle docs whose anchors this one
  // inherited. Renders oldest → newest with a chip marking the current id.
  const lineage = data.lineage || [];
  if (lineage.length) {
    const sec = el("div", {class: "drawer-section"});
    sec.appendChild(el("h4", null, ["Lineage"]));
    sec.appendChild(el("p", {class: "drawer-meta"}, [
      `Inherited from ${lineage.length} prior id${lineage.length === 1 ? "" : "s"} ` +
      `— anchors carried forward across content-hashed id changes.`,
    ]));
    const ul = el("ul", {style: "padding-left:18px;margin:0;"});
    for (const p of lineage) {
      if (p.missing) {
        ul.appendChild(el("li", {class: "drawer-meta"}, [
          `${p.id}  (pruned)`,
        ]));
        continue;
      }
      const li = el("li", null, [
        el("code", {style: "font-size:11px;"}, [p.id]),
      ]);
      if (p.name) {
        li.appendChild(el("span", null, ["  " + p.name]));
      }
      li.appendChild(el("div", {class: "drawer-meta"}, [
        `${p.runs_observed ?? 0} runs · ${p.snapshot_count ?? 0} snapshots · ` +
        `${p.anchors_count ?? 0} anchors · last seen ${fmtTs(p.last_seen)}`,
      ]));
      ul.appendChild(li);
    }
    // Current id chip
    if (a.value) {
      const li = el("li", null, [
        el("code", {style: "font-size:11px;"}, [a.value]),
        el("span", {class: "provisional-chip", style: "background:#0a1929;color:#4cc1ff;border-color:#4cc1ff60;"}, ["current"]),
      ]);
      ul.appendChild(li);
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

  // Open-in-graph link
  if (a.kind === "playbook" || a.kind === "campaign" || a.kind === "ip") {
    const sec = el("div", {class: "drawer-section"});
    const url = `/graph?ioc=${encodeURIComponent(a.kind)}:${encodeURIComponent(a.value)}`;
    sec.appendChild(el("a", {href: url, class: "nav-link"}, ["Open in graph →"]));
    body.appendChild(sec);
  }
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

  // Drawer close handlers
  document.querySelector("#drawer .drawer-close").addEventListener("click", closeDrawer);
  document.getElementById("drawer-backdrop").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

  const sortSel = document.getElementById("sort-select");
  sortSel.value = state.sort;
  sortSel.addEventListener("change", () => {
    state.sort = sortSel.value;
    pushQuery();
    refreshAll();
  });

  refreshAll();
})();
