"use strict";

/* Findings v2 — three-section accordion + slide-in drawer.
 *
 * Three independent fetches drive the three sections (drift / discovery /
 * coverage). Each row in each section is clickable; clicking opens the
 * detail drawer at /api/finding/{id}/detail. The status select stays
 * inside the row so the analyst can triage without opening the drawer.
 *
 * URL state: ?status=new&sort=score survives reloads.
 */

const STATUSES = ["new", "ack", "confirmed", "rejected"];
const STREAMS = ["drift", "discovery", "coverage"];

const state = {
  status: "new",     // single status (chip click), or "all"
  sort: "score",
};

function parseQuery() {
  const q = new URLSearchParams(location.search);
  if (q.has("status")) state.status = q.get("status");
  if (q.has("sort")) state.sort = q.get("sort");
}

function pushQuery() {
  const q = new URLSearchParams();
  q.set("status", state.status);
  if (state.sort !== "score") q.set("sort", state.sort);
  history.replaceState(null, "", "?" + q.toString());
}

function el(tag, attrs, children) {
  const e = document.createElement(tag);
  if (attrs) for (const k in attrs) {
    if (k === "class") e.className = attrs[k];
    else if (k === "html") e.innerHTML = attrs[k];
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
      onclick: () => {
        state.status = s;
        pushQuery();
        refreshAll();
      },
    }, [s, el("span", {class: "count"}, [`${count}`])]);
    wrap.appendChild(chip);
  }
}

// ---------------------------------------------------------------------------
// Stream sections
// ---------------------------------------------------------------------------

function renderStreamRows(stream, rows) {
  const sec = document.getElementById(`section-${stream}`);
  const body = sec.querySelector(".fnd-stream-rows");
  body.innerHTML = "";
  if (!rows.length) {
    body.appendChild(el("p", {class: "fnd-empty"}, [
      stream === "coverage"
        ? "no coverage findings — `dshield_prism mine findings` populates these"
        : `no ${stream} findings match this filter`,
    ]));
    return;
  }
  const table = el("table", {class: "fnd-table"});
  const thead = el("thead", null, [el("tr", null, [
    el("th", null, ["Kind"]),
    el("th", null, ["Artifact"]),
    el("th", null, ["Size"]),
    el("th", null, ["Score"]),
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
    tr.appendChild(el("td", {class: "score"}, [fmtScore(r.score)]));
    const narrCell = el("td", {class: "narrative"}, [r.narrative || ""]);
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

async function fetchStream(stream) {
  const params = new URLSearchParams();
  params.set("status", state.status);
  params.set("stream", stream);
  params.set("size", 200);
  params.set("from", 0);
  params.set("sort", state.sort);
  try {
    const r = await fetch("/api/findings?" + params.toString());
    if (!r.ok) {
      renderStreamRows(stream, []);
      return {status_counts: {}, stream_counts: {}};
    }
    const data = await r.json();
    renderStreamRows(stream, data.rows || []);
    document.getElementById(`count-${stream}`).textContent =
      (data.stream_counts && data.stream_counts[stream]) ?? (data.rows || []).length;
    return data;
  } catch (exc) {
    renderStreamRows(stream, []);
    return {};
  }
}

async function refreshAll() {
  let firstData = null;
  for (const s of STREAMS) {
    const d = await fetchStream(s);
    if (!firstData) firstData = d;
  }
  if (firstData) renderStatusChips(firstData.status_counts || {});
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

function inlineSparkline(snapshots) {
  if (!snapshots || !snapshots.length) return null;
  const w = 480, h = 50;
  const sessionVals = snapshots.map(s => +(s.session_count ?? 0));
  const max = Math.max(1, ...sessionVals);
  const dx = w / Math.max(1, snapshots.length - 1);
  let d = "";
  sessionVals.forEach((v, i) => {
    const x = i * dx;
    const y = h - (v / max) * (h - 6) - 3;
    d += (i === 0 ? "M" : "L") + `${x.toFixed(1)},${y.toFixed(1)} `;
  });
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("width", w);
  svg.setAttribute("height", h);
  svg.setAttribute("class", "sparkline");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", d.trim());
  path.setAttribute("stroke", "#4cc1ff");
  path.setAttribute("stroke-width", "1.5");
  path.setAttribute("fill", "none");
  svg.appendChild(path);
  return svg;
}

function intelPill(label) {
  if (!label) return null;
  const cls = ["clean", "malicious", "mixed", "no_data"].includes(label) ? label : "no_data";
  return el("span", {class: `intel-pill ${cls}`}, [label]);
}

function renderDrawer(data) {
  const body = document.getElementById("drawer-body");
  body.innerHTML = "";
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

  // Top commands
  const cmds = data.top_commands || [];
  if (cmds.length) {
    const sec = el("div", {class: "drawer-section"});
    sec.appendChild(el("h4", null, ["Top novel commands"]));
    const ul = el("ul", {style: "padding-left:18px;margin:0;"});
    for (const c of cmds) {
      const li = el("li", null, [
        el("code", null, [c.command || "(empty)"]),
        el("span", {class: "drawer-meta", style:"margin-left:6px;"}, [
          `nov ${c.novelty?.toFixed(2) ?? "?"}`,
        ]),
      ]);
      if (c.description) {
        li.appendChild(el("div", {class: "drawer-meta"}, [c.description]));
      }
      ul.appendChild(li);
    }
    sec.appendChild(ul);
    body.appendChild(sec);
  }

  // Top IPs
  const ips = data.top_ips || [];
  if (ips.length) {
    const sec = el("div", {class: "drawer-section"});
    sec.appendChild(el("h4", null, ["Top member IPs"]));
    const ul = el("ul", {style: "padding-left:18px;margin:0;"});
    for (const i of ips) {
      const li = el("li", null, [
        i.ip || "?",
        el("span", {class: "drawer-meta", style:"margin-left:6px;"}, [`${i.session_count} sess`]),
      ]);
      const pill = intelPill(i.intel_verdict);
      if (pill) li.appendChild(pill);
      ul.appendChild(li);
    }
    sec.appendChild(ul);
    body.appendChild(sec);
  }

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

  // Accordion toggle
  document.querySelectorAll(".fnd-accordion-head").forEach(h => {
    h.addEventListener("click", () => {
      h.parentElement.classList.toggle("collapsed");
    });
  });

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
