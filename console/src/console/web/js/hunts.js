/* Hunts page — brutal-review phase 6.3.
 *
 * Read-only view of YAML-defined hypothesis hunts plus a "run now"
 * button. Click-through on a hunt row drops the analyst on
 * /findings?stream=hunt&hunt_id=<id> with that hunt's matches filtered
 * to status=all.
 */
(function () {
  "use strict";

  function el(tag, attrs, children) {
    const n = document.createElement(tag);
    if (attrs) {
      if (typeof attrs === "string") n.className = attrs;
      else for (const [k, v] of Object.entries(attrs)) {
        if (k === "class") n.className = v;
        else if (k === "onclick") n.addEventListener("click", v);
        else if (v !== undefined && v !== null) n.setAttribute(k, v);
      }
    }
    if (children) {
      if (!Array.isArray(children)) children = [children];
      for (const c of children) {
        if (c === null || c === undefined) continue;
        n.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
      }
    }
    return n;
  }

  function fmt(n) {
    if (n === null || n === undefined) return "—";
    return n.toLocaleString();
  }

  function renderFilters(filters) {
    // Compact per-filter rendering: `kind: <fields>`. Each filter type
    // has its own one-line summary so the analyst can audit the hunt
    // logic without reading raw YAML.
    if (!filters || !filters.length) return "(no filters)";
    return filters.map(f => {
      const k = f.kind || "?";
      if (k === "artifact_set_contains_any" || k === "artifact_set_contains_all") {
        return `${k}: [${(f.values || []).join(", ")}]`;
      }
      if (k === "intent_in") return `intent_in: [${(f.values || []).join(", ")}]`;
      if (k === "command_count_gte") return `command_count >= ${f.threshold}`;
      if (k === "login_fail_count_gte") return `login_fail_count >= ${f.threshold}`;
      if (k === "external_match_cosine_gte") return `external_match_cosine >= ${f.threshold}`;
      if (k === "window") return `window: last ${f.last_days} days`;
      return JSON.stringify(f);
    }).join("\n");
  }

  function renderHunts(data) {
    const body = document.getElementById("hunts-body");
    const status = document.getElementById("h-status");
    const huntsDir = document.getElementById("hunts-dir");
    body.innerHTML = "";
    if (data.hunts_dir) huntsDir.textContent = data.hunts_dir;

    if (data.error) {
      body.appendChild(el("div", "h-error",
        "Hunts directory load failed: " + data.error));
      status.textContent = "load error";
      return;
    }
    const hunts = data.hunts || [];
    if (!hunts.length) {
      body.appendChild(el("div", "h-empty", [
        "No hunts configured. Drop a YAML file into ",
        el("code", null, [data.hunts_dir || "config/hunts"]),
        " and refresh — see ",
        el("code", null, ["src/enrich/findings/hunts.py"]),
        " for the schema.",
      ]));
      status.textContent = "0 hunts loaded";
      return;
    }
    status.textContent = `${hunts.length} hunt${hunts.length === 1 ? "" : "s"} loaded`;

    for (const h of hunts) {
      const card = el("div", "h-item");
      const head = el("div", "h-head");
      head.appendChild(el("span", "h-id", h.id));
      head.appendChild(el("span", "h-name", h.name || "(unnamed)"));
      const cnt = el("span",
        "h-count" + (h.finding_count > 0 ? "" : " zero"),
        `${fmt(h.finding_count)} matches`);
      head.appendChild(cnt);
      card.appendChild(head);

      if (h.description) {
        card.appendChild(el("div", "h-desc", h.description.trim()));
      }
      const filtersStr = renderFilters(h.filters);
      card.appendChild(el("pre", "h-filters", filtersStr));

      const actions = el("div", "h-actions");
      // Click-through to the filtered inbox. status=all so the analyst
      // sees ack'd/confirmed hits too — hunt findings are typically
      // long-lived, not single-run anomalies.
      const link = el("a", {
        class: "h-link",
        href: `/inbox?stream=hunt&hunt_id=${encodeURIComponent(h.id)}&status=all`,
      }, ["Open in inbox →"]);
      actions.appendChild(link);
      card.appendChild(actions);
      body.appendChild(card);
    }
  }

  async function loadHunts() {
    const status = document.getElementById("h-status");
    status.textContent = "loading…";
    try {
      const resp = await fetch("/api/hunts");
      if (!resp.ok) throw new Error(resp.status + " " + resp.statusText);
      const data = await resp.json();
      renderHunts(data);
    } catch (e) {
      const body = document.getElementById("hunts-body");
      body.innerHTML = "";
      body.appendChild(el("div", "h-error", "Failed to load hunts: " + e.message));
      status.textContent = "load error";
    }
  }

  async function runAll() {
    const btn = document.getElementById("h-run-all");
    const status = document.getElementById("h-status");
    btn.disabled = true;
    status.textContent = "running hunts…";
    try {
      const resp = await fetch("/api/hunts/run", { method: "POST" });
      if (!resp.ok) throw new Error(resp.status + " " + resp.statusText);
      const data = await resp.json();
      const wrote = Object.values(data.written_by_hunt || {})
        .reduce((a, b) => a + b, 0);
      status.textContent = `ran ${data.loaded} hunts → ${wrote} findings written/refreshed`;
      // Reload counts.
      await loadHunts();
    } catch (e) {
      status.textContent = "run failed: " + e.message;
    } finally {
      btn.disabled = false;
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    loadHunts();
    document.getElementById("h-run-all").addEventListener("click", runAll);
  });
})();
