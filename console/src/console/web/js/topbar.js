// Shared topbar behaviour. Loaded on every page via _base.html.
// Drives the #health freshness badge ("data Xm ago") off /api/health, and the
// site-wide #pipeline-banner off /api/pipeline/status (P4.3 — closes the
// pipeline-running half of ROADMAP #17.18 that A.3 deferred).

(() => {
  const REFRESH_MS = 60_000;
  // Running-banner cadence: poll the server often for the in-flight verb(s)
  // (backward-cycle steps are seconds long), and tick the displayed timer
  // every second so it reads as live without hammering ES.
  const PIPELINE_POLL_MS = 6_000;
  const PIPELINE_GRACE_MS = 25_000;  // bridge the sub-second gaps between steps

  function fmtDur(sec) {
    if (sec < 60) return `${sec}s`;
    if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`;
    return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
  }

  // The server reports a stable `since` = the start of the current contiguous
  // pipeline burst (identical for every client), so the elapsed timer survives
  // reloads / tab-switches instead of restarting. A grace window keeps the
  // banner up across the brief gaps between consecutive steps (no flicker).
  let pipeSince = null;      // server burst-start (ISO string) or null when idle
  let pipeLastActiveAt = 0;  // ms epoch of the most recent active poll
  let pipeStage = "";        // current verb(s) label

  function relative(iso) {
    if (!iso) return null;
    const then = Date.parse(iso);
    if (Number.isNaN(then)) return null;
    const sec = Math.max(0, Math.round((Date.now() - then) / 1000));
    if (sec < 60)        return `${sec}s ago`;
    if (sec < 3600)      return `${Math.round(sec / 60)}m ago`;
    if (sec < 86_400)    return `${Math.round(sec / 3600)}h ago`;
    return `${Math.round(sec / 86_400)}d ago`;
  }

  // Copy for the cycle dot per inferred prism.ops state. Keep terse — this is
  // the badge label; the full breakdown lives in the tooltip.
  const CYCLE_LABEL = {
    ok: "cycle ok",
    warn: "cycle failed",
    behind: "cycle behind",
    unknown: "cycle ?",
  };

  // The badge is a real <a href="/health"> with two signal dots + labels and a
  // chevron. `refresh()` paints both dots off /api/health: the ingestion dot
  // from last_data_ts (freshness), the cycle dot from h.cycle (inferred
  // prism.ops verb-run health). The whole pill degrades to a single .err state
  // when /api/health itself fails.
  function setErr(badge, msg) {
    badge.classList.add("err");
    const il = document.getElementById("health-ingest-label");
    const cl = document.getElementById("health-cycle-label");
    const idot = document.getElementById("health-ingest-dot");
    const cdot = document.getElementById("health-cycle-dot");
    if (il) il.textContent = "ES error";
    if (cl) cl.textContent = "";
    if (idot) idot.className = "health-dot err";
    if (cdot) cdot.className = "health-dot";
    // Keep the link's purpose in its accessible name — refresh() overwrites the
    // static template aria-label, so re-assert "open Health page" here too.
    badge.setAttribute("aria-label", `${msg} — open Health page`);
    badge.dataset.tooltip = msg;
  }

  async function refresh() {
    const badge = document.getElementById("health");
    if (!badge) return;
    const idot = document.getElementById("health-ingest-dot");
    const ilabel = document.getElementById("health-ingest-label");
    const cdot = document.getElementById("health-cycle-dot");
    const clabel = document.getElementById("health-cycle-label");
    try {
      const r = await fetch("/api/health", { headers: { Accept: "application/json" } });
      const h = await r.json();
      if (!h.ok) {
        setErr(badge, `ES error: ${h.error || "unknown"}`);
        return;
      }
      badge.classList.remove("err");

      // --- Ingestion dot: rollup freshness (existing logic). ---
      const rel = relative(h.last_data_ts);
      if (ilabel) ilabel.textContent = rel ? `data ${rel}` : "data: none yet";
      if (idot) idot.className = "health-dot " + (rel ? "ok" : "unknown");

      // --- Cycle dot: inferred prism.ops verb-run health. ---
      const cycle = h.cycle || {};
      const state = CYCLE_LABEL[cycle.state] ? cycle.state : "unknown";
      if (clabel) clabel.textContent = CYCLE_LABEL[state];
      if (cdot) cdot.className = "health-dot " + state;

      // --- Tooltip: break out both signals. ---
      const total = Object.values(h.doc_counts || {})
        .filter((v) => typeof v === "number")
        .reduce((a, b) => a + b, 0);
      const ingestLine = h.last_data_ts
        ? `Ingestion: freshest rollup ${h.last_data_ts}`
        : "Ingestion: no rollup data yet";
      let cycleLine = `Cycle: ${state}`;
      if (cycle.detail) cycleLine += ` — ${cycle.detail}`;
      const tip = [
        `ES ${h.elasticsearch_version || "?"} · ${total.toLocaleString()} docs`,
        ingestLine,
        cycleLine,
      ].join("\n");
      // No `title` — the CSS tooltip is the visible one; setting both also fires
      // the native tooltip on a delay and they overlap. aria-label keeps the
      // text discoverable to screen readers — and names the link's destination,
      // since this assignment overwrites the static template aria-label.
      badge.setAttribute("aria-label", `${tip.replace(/\n/g, " — ")} — open Health page`);
      badge.dataset.tooltip = tip;
    } catch (e) {
      setErr(badge, `ES error: ${e.message}`);
    }
  }

  // Render-only — recomputes elapsed from the server's stable `since`. Runs
  // every second so the banner reads as live between server polls.
  function renderBanner() {
    const banner = document.getElementById("pipeline-banner");
    if (!banner) return;
    if (pipeSince == null) {
      banner.classList.add("hidden");
      banner.textContent = "";
      return;
    }
    const startedMs = Date.parse(pipeSince);
    const sec = Number.isNaN(startedMs)
      ? 0 : Math.max(0, Math.round((Date.now() - startedMs) / 1000));
    const stage = pipeStage ? `${pipeStage} · ` : "";
    banner.textContent = `Pipeline running — ${stage}${fmtDur(sec)}`;
    banner.classList.remove("hidden");
  }

  // Server poll — updates the stable run-start, the in-flight verb(s), and the
  // active window.
  async function pollPipeline() {
    let data;
    try {
      // no-store + cache-buster: this is a live status poll, so it must never
      // be served from the browser/proxy cache (that's what froze the banner
      // between full page loads).
      const r = await fetch(`/api/pipeline/status?_=${Date.now()}`,
        { cache: "no-store", headers: { Accept: "application/json" } });
      data = await r.json();
    } catch (e) {
      return;  // transient — keep the current banner state, let the timer tick
    }
    const running = (data && data.running) || [];
    const active = !!(data && data.active && running.length);
    const now = Date.now();
    if (active) {
      pipeLastActiveAt = now;
      // Server-stable burst start — same value across reloads/tabs, so the
      // timer keeps counting instead of restarting.
      pipeSince = data.since || pipeSince;
      const verbs = [...new Set(running.map((r) => r.verb).filter(Boolean))];
      pipeStage = verbs.length <= 1 ? (verbs[0] || "") : `${verbs.length} steps`;
    } else if (pipeSince != null && (now - pipeLastActiveAt) >= PIPELINE_GRACE_MS) {
      // Idle past the grace window — the cycle is done.
      pipeSince = null;
      pipeStage = "";
    }
    renderBanner();
  }

  // Expose so other modules (e.g. graph) can prod a refresh after a
  // pipeline-affecting action without re-implementing the fetch.
  window.refreshTopbarHealth = refresh;
  window.refreshPipelineBanner = pollPipeline;

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => { refresh(); pollPipeline(); }, { once: true });
  } else {
    refresh();
    pollPipeline();
  }
  setInterval(refresh, REFRESH_MS);
  setInterval(pollPipeline, PIPELINE_POLL_MS);
  setInterval(renderBanner, 1_000);  // smooth per-second timer, no fetch
})();
