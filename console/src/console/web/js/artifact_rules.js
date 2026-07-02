"use strict";

/* Artifact-rule panel module (ROADMAP #5).
 *
 * Reads /api/artifact-rules, renders a table, supports soft-delete /
 * reactivate via DELETE / POST{id}/reactivate, and exports the visible
 * rule set as JSON. Mirrors the findings.js patterns.
 *
 * Hosted as the "Rules" tab of the Tune page — IIFE-wrapped so its
 * helpers (state, el, …) stay local and don't collide with other panel
 * modules sharing the page.
 */
(() => {

const state = { filter: "active" };

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

function fmtDate(s) { return s ? s.slice(0, 10) : "—"; }

function activeQueryParam() {
  if (state.filter === "active") return "true";
  if (state.filter === "inactive") return "false";
  return null;
}

async function fetchRules() {
  const params = new URLSearchParams({ size: "500" });
  const a = activeQueryParam();
  if (a !== null) params.set("active", a);
  const r = await fetch(`/api/artifact-rules?${params.toString()}`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

function renderRows(rules) {
  const wrap = document.getElementById("rules-table-wrap");
  wrap.innerHTML = "";
  if (!rules.length) {
    wrap.appendChild(el("p", { class: "rules-empty" }, [
      "no rules match this filter — create one from the graph detail drawer",
    ]));
    return;
  }
  const table = el("table", { class: "rules-table" });
  table.appendChild(el("thead", null, [el("tr", null, [
    el("th", null, ["Kind"]),
    el("th", null, ["Match type"]),
    el("th", null, ["Pattern"]),
    el("th", null, ["Note"]),
    el("th", { class: "num" }, ["Matches"]),
    el("th", null, ["Created"]),
    el("th", null, ["By"]),
    el("th", null, ["Status"]),
    el("th", null, ["Actions"]),
  ])]));
  const tbody = el("tbody");
  for (const r of rules) {
    const active = !!r.active;
    const tr = el("tr", { class: active ? "" : "inactive" });
    tr.appendChild(el("td", null, [r.kind || "—"]));
    tr.appendChild(el("td", null, [r.match_type || "—"]));
    // Full pattern, wrapped across lines so the analyst can read and copy
    // the whole artifact — no truncation.
    tr.appendChild(el("td", { class: "pattern" }, [r.pattern || ""]));
    tr.appendChild(el("td", { class: "note" }, [r.notes || "—"]));
    tr.appendChild(el("td", { class: "num" }, [
      String(r.match_count_estimate ?? 0),
    ]));
    tr.appendChild(el("td", null, [fmtDate(r.created_at)]));
    tr.appendChild(el("td", null, [r.created_by || "—"]));
    tr.appendChild(el("td", null, [
      el("span", {
        class: "ar-badge " + (active ? "ar-badge-active" : "ar-badge-inactive"),
      }, [active ? "active" : "inactive"]),
    ]));
    const actions = el("td", { class: "actions" });
    if (active) {
      actions.appendChild(el("button", {
        type: "button",
        onclick: () => toggleActive(r.rule_id, false),
      }, ["soft-delete"]));
    } else {
      actions.appendChild(el("button", {
        type: "button",
        onclick: () => toggleActive(r.rule_id, true),
      }, ["reactivate"]));
    }
    tr.appendChild(actions);
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  wrap.appendChild(table);
}

async function toggleActive(ruleId, active) {
  const method = active ? "POST" : "DELETE";
  const url = active
    ? `/api/artifact-rule/${encodeURIComponent(ruleId)}/reactivate`
    : `/api/artifact-rule/${encodeURIComponent(ruleId)}`;
  const r = await fetch(url, { method });
  if (!r.ok) {
    alert(`failed: ${await r.text()}`);
    return;
  }
  refresh();
}

async function refresh() {
  document.getElementById("rules-count").textContent = "loading…";
  try {
    const data = await fetchRules();
    const rules = data.rules || [];
    document.getElementById("rules-count").textContent = `${rules.length}`;
    renderRows(rules);
    window._lastRules = rules;
  } catch (exc) {
    document.getElementById("rules-count").textContent = "error";
    document.getElementById("rules-table-wrap").innerHTML =
      `<p class="rules-empty">load failed: ${String(exc)}</p>`;
  }
}

function downloadJson(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

document.addEventListener("DOMContentLoaded", () => {
  for (const chip of document.querySelectorAll(".rules-chip")) {
    chip.addEventListener("click", () => {
      state.filter = chip.dataset.filter;
      for (const c of document.querySelectorAll(".rules-chip")) {
        c.classList.toggle("active", c === chip);
      }
      refresh();
    });
  }
  document.getElementById("export-json-btn").addEventListener("click", () => {
    const rules = window._lastRules || [];
    const bundle = {
      exported_at: new Date().toISOString(),
      source: "dshield_prism",
      rule_count: rules.length,
      rules,
    };
    downloadJson(bundle, "artifact-rules.json");
  });
  refresh();
});

})();
