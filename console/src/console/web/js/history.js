/* History — archive discovery page. Salience-ranked, timeline-navigated.
   No external deps. Mirrors insights.js conventions. */
(function () {
  "use strict";

  function esc(s) {
    return String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function fmt(n) { return (n ?? 0).toLocaleString(); }
  function el(tag, cls, ...kids) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    for (const c of kids) {
      if (c == null) continue;
      e.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    }
    return e;
  }
  function dayfmt(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    return isNaN(d) ? String(iso).slice(0, 10) : d.toISOString().slice(0, 10);
  }

  // start/end scope the Standout ranking; sort is the analyst's lens.
  const state = { sort: "novel_reach", start: null, end: null };

  function graphPlaybook(pid) {
    window.location.href = "/graph?ioc=" + encodeURIComponent("playbook:" + pid);
  }

  // ─── timeline (the navigation map) ─────────────────────────────────────────
  function renderTimeline(timeline) {
    const wrap = document.getElementById("hist-timeline");
    const axis = document.getElementById("hist-axis");
    wrap.innerHTML = ""; axis.innerHTML = "";
    if (!timeline || !timeline.length) {
      wrap.appendChild(el("em", "hist-empty", "No activity in the archive."));
      return;
    }
    const max = timeline.reduce((m, b) => Math.max(m, b.sessions || 0), 1);
    timeline.forEach((b, i) => {
      const next = timeline[i + 1];
      const bar = el("div", "tl-bar");
      bar.style.height = Math.max(2, Math.round(((b.sessions || 0) / max) * 100)) + "%";
      bar.title = dayfmt(b.start) + " · " + fmt(b.sessions) + " sessions";
      // highlight buckets that fall inside the current scope
      if (state.start && b.start && b.start >= state.start && (!state.end || b.start < state.end)) {
        bar.classList.add("sel");
      }
      bar.addEventListener("click", () => {
        state.start = b.start;
        state.end = next ? next.start : null;  // null end → up to the archive boundary
        load();
      });
      wrap.appendChild(bar);
    });
    axis.appendChild(el("span", null, dayfmt(timeline[0].start)));
    axis.appendChild(el("span", null, dayfmt(timeline[timeline.length - 1].start)));
  }

  // ─── standout cards ────────────────────────────────────────────────────────
  function card(row) {
    const c = el("div", "hist-card");
    c.appendChild(el("div", "hc-name" + (row.name ? "" : " unnamed"), row.name || row.playbook_id));

    const nov = Math.max(0, Math.min(1, row.novelty || 0));
    const bar = el("div", "nov-bar");
    const track = el("div", "nov-track");
    const fill = el("div", "nov-fill"); fill.style.width = Math.round(nov * 100) + "%";
    track.appendChild(fill);
    bar.appendChild(track);
    bar.appendChild(el("span", "nov-val", nov.toFixed(2)));
    c.appendChild(bar);

    const meta = el("div", "hc-meta");
    meta.appendChild(el("span", null, el("b", null, fmt(row.sessions)), " sessions"));
    meta.appendChild(el("span", null, el("b", null, fmt(row.ips)), " IPs"));
    c.appendChild(meta);

    if (row.first_seen) {
      c.appendChild(el("div", "hc-span", dayfmt(row.first_seen) + " → " + dayfmt(row.last_seen)));
    }
    c.addEventListener("click", () => graphPlaybook(row.playbook_id));
    return c;
  }

  function renderStandout(rows) {
    const wrap = document.getElementById("hist-standout");
    wrap.innerHTML = "";
    if (!rows || !rows.length) {
      wrap.appendChild(el("em", "hist-empty", "No standout behaviours in this window."));
      return;
    }
    rows.forEach((r) => wrap.appendChild(card(r)));
  }

  function renderScope(scope) {
    const s = document.getElementById("hist-scope");
    if (state.start) {
      s.innerHTML = "scope: <b>" + esc(dayfmt(state.start)) + "</b> → <b>"
        + esc(state.end ? dayfmt(state.end) : "now-14d") + "</b>";
    } else if (scope && scope.total_playbooks != null) {
      s.innerHTML = "<b>" + fmt(scope.total_playbooks) + "</b> playbooks in the archive";
    } else {
      s.innerHTML = "";
    }
  }

  function syncLens() {
    document.querySelectorAll(".lens-btn").forEach((b) => {
      b.classList.toggle("active", b.dataset.sort === state.sort);
    });
  }

  // ─── load ──────────────────────────────────────────────────────────────────
  async function load() {
    syncLens();
    const qs = new URLSearchParams({ sort: state.sort });
    if (state.start) qs.set("start", state.start);
    if (state.end) qs.set("end", state.end);
    try {
      const resp = await fetch("/api/history?" + qs.toString());
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      const data = await resp.json();
      renderTimeline(data.timeline);
      renderStandout(data.standout);
      renderScope(data.scope);
    } catch (e) {
      const w = document.getElementById("hist-standout");
      w.innerHTML = "";
      w.appendChild(el("div", "hist-error", "History query failed: " + esc(e.message)));
    }
  }

  // ─── wire ──────────────────────────────────────────────────────────────────
  document.querySelectorAll(".lens-btn").forEach((b) => {
    b.addEventListener("click", () => { state.sort = b.dataset.sort; load(); });
  });
  document.getElementById("hist-reset").addEventListener("click", () => {
    state.start = null; state.end = null; load();
  });

  load();
})();
