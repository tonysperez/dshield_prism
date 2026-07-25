"use strict";

/* Grounding panel module (spec-grounding-precompute) — the Tune page's
 * "Grounding" tab.
 *
 * Single fetch to /api/tune/grounding-coverage reads the ONE precomputed
 * report doc the `track grounding-coverage` pipeline job writes — no
 * full-corpus scan happens on this request path (that's the whole point of
 * this spec; see docs/decisions.md "Computing command-grounding coverage on
 * the console request path"). Renders:
 *   - stat bar (totals + counts per bucket)
 *   - "needs definition" list — searchable + paginated
 *   - "tldr only" list — paginated
 *   - "denied" list — block/unblock rationale
 *
 * Block/unblock writes `denylist.yaml` immediately via
 * add_to_denylist/remove_from_denylist (same as the retired Curation page),
 * but the report's bucket counts only catch up on the next scheduled job
 * run — documented on the tab, not re-fetched here.
 *
 * Mirrors the deleted curation.js render logic (git show de42736^ --
 * console/src/console/web/js/curation.js), adapted to the precomputed
 * endpoint plus client-side search/pagination over the one fetched doc.
 */
(() => {
  const PAGE_SIZE = 25;

  const state = {
    data: null,
    needsDefFilter: "",
    needsDefPage: 0,
    tldrPage: 0,
  };

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function statCard(label, value, kind = "") {
    const card = el("div", `gc-stat-card ${kind}`.trim());
    card.appendChild(el("div", "gc-stat-label", label));
    card.appendChild(el("div", "gc-stat-value", value == null ? "—" : String(value)));
    return card;
  }

  function renderStats(stats) {
    const bar = document.getElementById("grounding-stats");
    if (!bar) return;
    bar.innerHTML = "";
    if (!stats) return;
    bar.appendChild(statCard("unique commands", stats.total_unique_cmds, "info"));
    bar.appendChild(statCard("curated", stats.curated, "ok"));
    bar.appendChild(statCard("tldr only", stats.tldr_only,
      stats.tldr_only > 0 ? "info" : "ok"));
    bar.appendChild(statCard("needs definition", stats.needs_def,
      stats.needs_def > 0 ? "warn" : "ok"));
    bar.appendChild(statCard("denied", stats.denied, "info"));
    bar.appendChild(statCard(
      "total occurrences",
      typeof stats.total_corpus_occurrences === "number"
        ? stats.total_corpus_occurrences.toLocaleString() : null,
      "info",
    ));
  }

  function renderList(containerId, items, emptyMsg, opts = {}) {
    const c = document.getElementById(containerId);
    if (!c) return;
    c.innerHTML = "";
    if (!items || items.length === 0) {
      c.appendChild(el("em", "gc-empty", emptyMsg));
      return;
    }
    for (const it of items) {
      const row = el("div", "gc-item");
      row.appendChild(el("div", "gc-cmd", it.name));

      const samplesWrap = el("div", "gc-samples");
      // For denied rows, the rationale is more useful than samples.
      if (opts.rationale && it.rationale) {
        samplesWrap.appendChild(el("div", "gc-sample", it.rationale));
      }
      for (const s of (it.samples || [])) {
        samplesWrap.appendChild(el("div", "gc-sample", s));
      }
      row.appendChild(samplesWrap);

      const actions = el("div", "gc-actions");
      actions.appendChild(el("div", "gc-count", `${it.count} occ`));
      if (opts.allowBlock) {
        const btn = el("button", "gc-btn gc-btn-block", "Block");
        btn.title = "Add this token to the denylist (suppresses it from the LLM " +
          "grounding block; moves to Denied on the next scheduled report run).";
        btn.addEventListener("click", () => blockToken(it.name, btn));
        actions.appendChild(btn);
      } else if (opts.allowUnblock) {
        const btn = el("button", "gc-btn", "Unblock");
        btn.title = "Remove this token from the denylist (it returns to needs_def " +
          "or tldr_only on the next scheduled report run).";
        btn.addEventListener("click", () => unblockToken(it.name, btn));
        actions.appendChild(btn);
      }
      row.appendChild(actions);

      c.appendChild(row);
    }
  }

  function paginate(items, page) {
    const start = page * PAGE_SIZE;
    return items.slice(start, start + PAGE_SIZE);
  }

  function renderPager(containerId, total, page, onChange) {
    const c = document.getElementById(containerId);
    if (!c) return;
    c.innerHTML = "";
    const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    if (pages <= 1) return;
    const prev = el("button", "", "‹ prev");
    prev.disabled = page <= 0;
    prev.addEventListener("click", () => onChange(page - 1));
    const next = el("button", "", "next ›");
    next.disabled = page >= pages - 1;
    next.addEventListener("click", () => onChange(page + 1));
    c.appendChild(prev);
    c.appendChild(el("span", "", `page ${page + 1} / ${pages} (${total})`));
    c.appendChild(next);
  }

  function renderNeedsDef() {
    if (!state.data) return;
    const all = state.data.needs_def || [];
    const q = state.needsDefFilter.trim().toLowerCase();
    const filtered = q ? all.filter((it) => (it.name || "").toLowerCase().includes(q)) : all;
    const maxPage = Math.max(0, Math.ceil(filtered.length / PAGE_SIZE) - 1);
    if (state.needsDefPage > maxPage) state.needsDefPage = maxPage;
    renderList(
      "grounding-needs-def",
      paginate(filtered, state.needsDefPage),
      q
        ? "no needs-definition commands match this filter."
        : "every command in the corpus has at least a tldr entry — nothing urgent to curate.",
      { allowBlock: true },
    );
    renderPager("grounding-needs-def-pager", filtered.length, state.needsDefPage, (p) => {
      state.needsDefPage = p;
      renderNeedsDef();
    });
  }

  function renderTldrOnly() {
    if (!state.data) return;
    const all = state.data.tldr_only || [];
    const maxPage = Math.max(0, Math.ceil(all.length / PAGE_SIZE) - 1);
    if (state.tldrPage > maxPage) state.tldrPage = maxPage;
    renderList(
      "grounding-tldr-only",
      paginate(all, state.tldrPage),
      "every command in the corpus has a curated entry.",
      { allowBlock: true },
    );
    renderPager("grounding-tldr-only-pager", all.length, state.tldrPage, (p) => {
      state.tldrPage = p;
      renderTldrOnly();
    });
  }

  function renderDenied() {
    if (!state.data) return;
    renderList(
      "grounding-denied",
      state.data.denied || [],
      "no denylisted tokens have appeared in the corpus.",
      { rationale: true, allowUnblock: true },
    );
  }

  // Shared "nothing to show" renderer for both the pending-first-run state
  // (no doc yet — empty, not an error) and a real fetch/ES failure (error).
  function renderPending(msg) {
    const bar = document.getElementById("grounding-stats");
    if (bar) {
      bar.innerHTML = "";
      bar.appendChild(el(
        msg ? "div" : "em",
        msg ? "gc-error" : "gc-empty",
        msg || "pending first run — the track grounding-coverage pipeline job hasn't written a report yet.",
      ));
    }
    for (const id of ["grounding-needs-def", "grounding-tldr-only", "grounding-denied"]) {
      const c = document.getElementById(id);
      if (c) c.innerHTML = "";
    }
    for (const id of ["grounding-needs-def-pager", "grounding-tldr-only-pager"]) {
      const c = document.getElementById(id);
      if (c) c.innerHTML = "";
    }
  }

  async function blockToken(name, btn) {
    const rationale = window.prompt(
      `Add "${name}" to the denylist.\n\nRationale ` +
      `(one short sentence — appears in the YAML and on the Denied bucket):`,
      "added via Tune page",
    );
    if (rationale === null) return; // user cancelled
    btn.disabled = true;
    btn.textContent = "…";
    try {
      const r = await fetch("/api/tune/grounding-coverage/denylist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: name, rationale: rationale || "added via Tune page" }),
      });
      if (!r.ok) {
        const text = await r.text();
        throw new Error(`HTTP ${r.status} — ${text}`);
      }
      // denylist.yaml is written immediately, but the report's buckets don't
      // reclassify until the next scheduled job run — reflect that instead
      // of re-fetching a report that hasn't changed.
      btn.textContent = "blocked (pending next report)";
    } catch (e) {
      window.alert(`Failed to block ${name}: ${e.message}`);
      btn.disabled = false;
      btn.textContent = "Block";
    }
  }

  async function unblockToken(name, btn) {
    if (!window.confirm(
      `Remove "${name}" from the denylist?\n\n` +
      "It will reappear in needs_def or tldr_only on the next scheduled report run.",
    )) return;
    btn.disabled = true;
    btn.textContent = "…";
    try {
      const r = await fetch(
        `/api/tune/grounding-coverage/denylist/${encodeURIComponent(name)}`,
        { method: "DELETE" },
      );
      if (!r.ok) {
        const text = await r.text();
        throw new Error(`HTTP ${r.status} — ${text}`);
      }
      btn.textContent = "unblocked (pending next report)";
    } catch (e) {
      window.alert(`Failed to unblock ${name}: ${e.message}`);
      btn.disabled = false;
      btn.textContent = "Unblock";
    }
  }

  async function load() {
    try {
      const r = await fetch("/api/tune/grounding-coverage");
      if (!r.ok) {
        const text = await r.text();
        throw new Error(`HTTP ${r.status} — ${text}`);
      }
      const data = await r.json();
      if (!data.available) {
        renderPending(data.error || "");
        return;
      }
      state.data = data;
      renderStats(data.stats);
      renderNeedsDef();
      renderTldrOnly();
      renderDenied();
    } catch (e) {
      renderPending(`Failed to load grounding coverage: ${e.message}`);
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    const search = document.getElementById("grounding-search");
    if (search) {
      search.addEventListener("input", () => {
        state.needsDefFilter = search.value;
        state.needsDefPage = 0;
        renderNeedsDef();
      });
    }
    // Eager load, same as the Rules tab's artifact_rules.js — the report
    // read is O(1), so there's no cost to loading before the tab is shown.
    load();
  });
})();
