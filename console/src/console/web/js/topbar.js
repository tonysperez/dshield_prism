// Shared topbar behaviour. Loaded on every page via _base.html.
// Today: drives the #health freshness badge ("data Xm ago") off
// /api/health. A.3 lands the load-bearing half of ROADMAP #17.18; the
// pipeline-running half is deferred.

(() => {
  const REFRESH_MS = 60_000;

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

  async function refresh() {
    const badge = document.getElementById("health");
    if (!badge) return;
    try {
      const r = await fetch("/api/health", { headers: { Accept: "application/json" } });
      const h = await r.json();
      if (!h.ok) {
        badge.textContent = `ES error: ${h.error || "unknown"}`;
        badge.className = "health err";
        badge.removeAttribute("aria-label");
        delete badge.dataset.tooltip;
        return;
      }
      const rel = relative(h.last_data_ts);
      badge.textContent = rel ? `data ${rel}` : "data: none yet";
      badge.className = rel ? "health ok" : "health";
      const total = Object.values(h.doc_counts || {})
        .filter((v) => typeof v === "number")
        .reduce((a, b) => a + b, 0);
      const parts = [`ES ${h.elasticsearch_version || "?"} · ${total.toLocaleString()} docs`];
      if (h.last_data_ts) parts.push(`freshest rollup: ${h.last_data_ts}`);
      const tip = parts.join(" — ");
      // No `title` — the CSS tooltip is the visible one; setting both
      // also fires the native tooltip on a delay and they overlap.
      // aria-label keeps the text discoverable to screen readers.
      badge.setAttribute("aria-label", tip);
      badge.dataset.tooltip = tip;
    } catch (e) {
      badge.textContent = `ES error: ${e.message}`;
      badge.className = "health err";
      badge.removeAttribute("aria-label");
      delete badge.dataset.tooltip;
    }
  }

  // Expose so other modules (e.g. graph) can prod a refresh after a
  // pipeline-affecting action without re-implementing the fetch.
  window.refreshTopbarHealth = refresh;

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", refresh, { once: true });
  } else {
    refresh();
  }
  setInterval(refresh, REFRESH_MS);
})();
