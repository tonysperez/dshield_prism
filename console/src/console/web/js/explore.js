/* Explore — longitudinal lifecycle list. One row per playbook, its whole activity
   arc on a shared time axis, ranked by an `interest` composite. No external deps.
   The band renderer mirrors renderSparkline. */
(function () {
  "use strict";

  const SVGNS = "http://www.w3.org/2000/svg";

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
  function svg(tag, attrs) {
    const e = document.createElementNS(SVGNS, tag);
    for (const k in attrs) e.setAttribute(k, String(attrs[k]));
    return e;
  }
  function dayfmt(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    return isNaN(d) ? String(iso).slice(0, 10) : d.toISOString().slice(0, 10);
  }

  const state = { entity: "playbook", window: "90d", start: null, end: null,
    sort: "interest", filter: "all", life: "all" };

  const ENTITY_NOUN = {
    playbook: "playbooks", campaign: "campaigns", session_cluster: "session clusters",
    ip_cluster: "IP clusters", operation: "operations",
  };
  function entityNoun() { return ENTITY_NOUN[state.entity] || "entities"; }

  function graphEntity(id) {
    window.location.href = "/graph?ioc=" + encodeURIComponent(state.entity + ":" + id);
  }

  // ─── shared axis ticks ───────────────────────────────────────────────────
  function renderAxis(axis, returned) {
    const ticks = document.getElementById("hist-axticks");
    const meta = document.getElementById("hist-axmeta");
    ticks.innerHTML = "";
    meta.textContent = fmt(returned) + " " + entityNoun() + " · now ◀ · " + state.sort + " ▾";
    if (!axis || !axis.start || !axis.end) return;
    const t0 = new Date(axis.start).getTime();  // oldest
    const t1 = new Date(axis.end).getTime();    // now
    if (isNaN(t0) || isNaN(t1) || t1 <= t0) return;
    const N = 4;
    for (let i = 0; i < N; i++) {
      // FLIPPED: leftmost tick is now, rightmost is the oldest bucket.
      const t = t1 - ((t1 - t0) * i) / (N - 1);
      const label = i === 0 ? "now" : dayfmt(new Date(t).toISOString());
      ticks.appendChild(el("span", null, label));
    }
  }

  // ─── activity band (mirrors insights renderSparkline; FLIPPED so now is on the
  //     LEFT, oldest on the right) + a live-period strip along the bottom ────────
  function renderBand(row) {
    const W = 100, H = 34, pad = 3, stripY = H - 3, stripH = 2.5;
    const band = row.band || [];
    const s = svg("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none" });
    if (!band.length) return s;
    const max = Math.max(1, ...band);
    const n = band.length;
    const stepX = n > 1 ? W / (n - 1) : 0;
    // FLIP: now (index n-1) at x=0 (left edge), oldest (index 0) at x=W (right).
    const X = (i) => (n > 1 ? W - i * stepX : W / 2);
    const Y = (v) => (stripY - pad) - ((stripY - 2 * pad) * (v / max));
    const xy = band.map((v, i) => [X(i), Y(v)]);
    // faint filled area under the curve
    const areaPts = [`${X(0)},${stripY}`, ...xy.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`),
      `${X(n - 1)},${stripY}`].join(" ");
    s.appendChild(svg("polygon", { class: "band-fill", points: areaPts }));
    s.appendChild(svg("polyline", {
      points: xy.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" "),
    }));
    // live-period strip: a faint dead track + one green marker per alive episode
    s.appendChild(svg("rect", { class: "ep-track", x: 0, y: stripY, width: W, height: stripH }));
    (row.episodes || []).forEach(([a, b]) => {
      let left = Math.max(0, Math.min(X(a), X(b)) - stepX / 2);
      let right = Math.min(W, Math.max(X(a), X(b)) + stepX / 2);
      s.appendChild(svg("rect", { class: "ep-live", x: left.toFixed(1), y: stripY,
        width: Math.max(0.8, right - left).toFixed(1), height: stripH }));
    });
    // now-edge marker (left): live dot, or dead ✝ at the last active bucket
    let lastNz = -1;
    for (let i = n - 1; i >= 0; i--) { if (band[i] > 0) { lastNz = i; break; } }
    if (row.state === "live") {
      s.appendChild(svg("circle", { class: "band-live-dot", cx: X(n - 1), cy: Y(band[n - 1] || 0), r: 2.2 }));
    } else if (lastNz >= 0) {
      const t = svg("text", { class: "band-dead-x", x: X(lastNz).toFixed(1), y: 9 });
      t.textContent = "✝";
      s.appendChild(t);
    }
    const total = band.reduce((a, b) => a + b, 0);
    s.appendChild(svg("title", {})).textContent =
      `${total} sessions · peak ${max} · ${n} buckets · now ◀ left`;
    return s;
  }

  function row(r, rank) {
    const el_ = el("div", "hist-row");

    const idblk = el("div", "idblk");
    const idline = el("div", "idline");
    idline.appendChild(el("span", "rank", String(rank)));
    const cidEl = el("span", "cid" + (r.name ? "" : " unnamed"), r.name || r.id);
    cidEl.title = (r.name ? r.name + " · " : "") + r.id;   // full contents on hover, in case truncated
    idline.appendChild(cidEl);
    idline.appendChild(el("span", "badge-state " + (r.state || "dead"), r.state || "dead"));
    if (r.recurs > 0) idline.appendChild(el("span", "badge-recur", "⟳ " + r.recurs + "×"));
    idblk.appendChild(idline);
    const span = (r.first_seen ? dayfmt(r.first_seen) + " → " + dayfmt(r.last_seen) : "");
    idblk.appendChild(el("div", "idsub",
      span + " · " + fmt(r.sessions) + " sess · " + fmt(r.ips) + " IPs"));
    el_.appendChild(idblk);

    const bw = el("div", "band-wrap " + (r.state || "dead"));
    bw.appendChild(renderBand(r));
    el_.appendChild(bw);

    const score = el("div", "score");
    const hot = (r.interest || 0) >= 60;
    score.appendChild(el("span", "v" + (hot ? " hot" : ""), String(Math.round(r.interest || 0))));
    const arrow = r.trend_dir === "up" ? "▲" : r.trend_dir === "down" ? "▼" : "→";
    score.appendChild(el("span", "t " + (r.trend_dir || "flat"), arrow + " " + (r.trend_dir || "flat")));
    el_.appendChild(score);

    el_.addEventListener("click", () => graphEntity(r.id));
    return el_;
  }

  // ─── minimap (interest density + scroll thumb) ───────────────────────────
  function renderMinimap(rows) {
    const mm = document.getElementById("hist-minimap");
    mm.innerHTML = "";
    if (!rows || !rows.length) return;
    const n = rows.length;
    rows.forEach((r, i) => {
      const seg = el("div", "mm");
      seg.style.top = ((i / n) * 100).toFixed(2) + "%";
      seg.style.height = (100 / n).toFixed(3) + "%";
      const alpha = Math.max(0.06, Math.min(0.85, (r.interest || 0) / 100));
      seg.style.background = "rgba(251, 191, 36, " + alpha.toFixed(2) + ")";
      mm.appendChild(seg);
    });
    const thumb = el("div", "thumb");
    thumb.id = "hist-thumb";
    mm.appendChild(thumb);
    updateThumb();
  }

  function updateThumb() {
    const thumb = document.getElementById("hist-thumb");
    const list = document.getElementById("hist-list");
    if (!thumb || !list) return;
    const rect = list.getBoundingClientRect();
    const listH = list.offsetHeight || 1;
    const vh = window.innerHeight;
    const frac = Math.max(0.04, Math.min(1, vh / listH));
    // clamp top to [0, 1-frac] so overscroll past the bottom can't push the thumb
    // beyond the rail (which read as the bar "growing").
    const top = Math.max(0, Math.min(1 - frac, -rect.top / listH));
    thumb.style.top = (top * 100).toFixed(2) + "%";
    thumb.style.height = (frac * 100).toFixed(2) + "%";
  }

  function renderScope(scope) {
    const s = document.getElementById("hist-scope");
    if (!scope) { s.innerHTML = ""; return; }
    let html = "<b>" + fmt(scope.total) + "</b> " + entityNoun();
    // `capped` = more entities than the pool cap; we show the top `limit`. Report
    // the cap, not the (post-filter) row count.
    if (scope.capped) html += " · showing top <b>" + fmt(scope.limit) + "</b>";
    s.innerHTML = html;
  }

  function renderList(rows) {
    const wrap = document.getElementById("hist-list");
    wrap.innerHTML = "";
    if (!rows || !rows.length) {
      const msg = state.filter === "recurring"
        ? "No recurring behaviours in this window." : "No activity in this window.";
      wrap.appendChild(el("em", "hist-empty", msg));
      return;
    }
    rows.forEach((r, i) => wrap.appendChild(row(r, i + 1)));
  }

  // ─── controls ────────────────────────────────────────────────────────────
  function syncControls() {
    document.querySelectorAll("#hist-entity button").forEach((b) =>
      b.classList.toggle("on", b.dataset.entity === state.entity));
    document.querySelectorAll("#hist-window button").forEach((b) =>
      b.classList.toggle("on", b.dataset.window === state.window));
    document.querySelectorAll("#hist-filter button").forEach((b) =>
      b.classList.toggle("on", b.dataset.filter === state.filter));
    document.querySelectorAll("#hist-state button").forEach((b) =>
      b.classList.toggle("on", b.dataset.state === state.life));
    document.getElementById("hist-custom").classList.toggle("show", state.window === "custom");
    document.getElementById("hist-sort").value = state.sort;
  }

  async function load() {
    syncControls();
    const qs = new URLSearchParams({
      entity: state.entity, window: state.window, sort: state.sort,
      filter: state.filter, state: state.life,
    });
    if (state.window === "custom" && state.start && state.end) {
      qs.set("start", state.start); qs.set("end", state.end);
    }
    try {
      const resp = await fetch("/api/history?" + qs.toString());
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      const data = await resp.json();
      renderAxis(data.axis, (data.rows || []).length);
      renderScope(data.scope);
      renderList(data.rows);
      renderMinimap(data.rows);
    } catch (e) {
      // Clear the whole surface so no stale axis/scope/minimap from a prior
      // successful window lingers beside the error.
      renderAxis(null, 0);
      renderScope(null);
      renderMinimap([]);
      const w = document.getElementById("hist-list");
      w.innerHTML = "";
      w.appendChild(el("div", "hist-error", "Explore query failed: " + esc(e.message)));
    }
  }

  // ─── wire ────────────────────────────────────────────────────────────────
  document.querySelectorAll("#hist-entity button").forEach((b) => {
    b.addEventListener("click", () => { state.entity = b.dataset.entity; load(); });
  });
  document.querySelectorAll("#hist-window button").forEach((b) => {
    b.addEventListener("click", () => {
      state.window = b.dataset.window;
      // Selecting "custom" only reveals the date panel; wait for Apply rather
      // than reloading stale 90d data under a lit "custom" button.
      if (b.dataset.window === "custom" && !(state.start && state.end)) {
        syncControls();
        return;
      }
      load();
    });
  });
  document.querySelectorAll("#hist-filter button").forEach((b) => {
    b.addEventListener("click", () => { state.filter = b.dataset.filter; load(); });
  });
  document.querySelectorAll("#hist-state button").forEach((b) => {
    b.addEventListener("click", () => { state.life = b.dataset.state; load(); });
  });
  document.getElementById("hist-sort").addEventListener("change", (e) => {
    state.sort = e.target.value; load();
  });
  document.getElementById("hist-apply").addEventListener("click", () => {
    const s = document.getElementById("hist-start").value;
    const e = document.getElementById("hist-end").value;
    if (s && e) { state.start = s; state.end = e; state.window = "custom"; load(); }
  });
  window.addEventListener("scroll", updateThumb, { passive: true });
  window.addEventListener("resize", updateThumb, { passive: true });

  const today = new Date().toISOString().slice(0, 10);
  document.getElementById("hist-start").max = today;
  document.getElementById("hist-end").max = today;

  load();
})();
