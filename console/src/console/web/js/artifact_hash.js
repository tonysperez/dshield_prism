// File-hash artifact pane (#2). Renders /api/artifact/hash?value=<sha>.
// Mirrors artifact_url.js: derived consensus + per-provider cards
// (MalwareBazaar / ThreatFox / VirusTotal), plus the local droppers list.

(function () {
  "use strict";

  function getHashFromQuery() {
    return new URLSearchParams(window.location.search).get("value") || "";
  }
  function setText(id, t) { const el = document.getElementById(id); if (el) el.textContent = t; }
  function setHTML(id, h) { const el = document.getElementById(id); if (el) el.innerHTML = h; }
  function escapeHtml(s) {
    if (s === null || s === undefined) return "";
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  function badge(label, kind) {
    return `<span class="art-badge${kind ? " " + kind : ""}">${escapeHtml(label)}</span>`;
  }

  function renderBadges(data) {
    const out = [];
    const intel = data.intel;
    if (!intel) {
      out.push(badge("no hash intel yet", "unknown"));
    } else {
      const d = intel.derived || {};
      if (d.consensus_malicious) out.push(badge("MALICIOUS (known sample)", "malicious"));
      else if ((d.providers_with_data || 0) > 0) out.push(badge("providers: no flag", "benign"));
      else out.push(badge("providers: no data", "unknown"));
      if (d.consensus_label && d.consensus_label !== "unknown") out.push(badge(d.consensus_label, "neutral"));
    }
    setHTML("art-badges", out.join(""));
  }

  function renderDerived(intel) {
    if (!intel) {
      setHTML("derived-card",
        '<em class="empty-hint">no hash intel doc yet — this file has not been refreshed against MalwareBazaar / ThreatFox</em>');
      return;
    }
    const d = intel.derived || {};
    const rows = [
      ["consensus_malicious",      d.consensus_malicious === true ? "TRUE" : "false"],
      ["consensus_label",          d.consensus_label || "unknown"],
      ["malicious_provider_count", d.malicious_provider_count !== undefined ? d.malicious_provider_count : "—"],
      ["confidence_max",           (d.confidence_max !== undefined && d.confidence_max !== null) ? d.confidence_max : "—"],
      ["tags",                     (d.tags || []).join(", ") || "—"],
      ["last_refreshed",           intel.last_refreshed || "—"],
    ];
    setHTML("derived-card",
      `<div class="art-kv">${rows.map(([k, v]) =>
        `<div class="art-kv-key">${escapeHtml(k)}</div><div class="art-kv-val">${escapeHtml(v)}</div>`).join("")}</div>`);
  }

  function renderDroppers(droppers) {
    if (!droppers || droppers.length === 0) {
      setHTML("droppers-list",
        '<em class="empty-hint">no in-corpus droppers recorded for this hash</em>');
      return;
    }
    const html = droppers.map((row) => {
      const sid = row.session_id;
      const ch = row.command_hash;
      const sLink = sid
        ? `<a class="gl" href="/graph?ioc=session:${encodeURIComponent(sid)}">${escapeHtml(sid)}</a>` : "?";
      const cLink = ch
        ? `<a class="gl" href="/graph?ioc=command:${encodeURIComponent(ch)}">command ${escapeHtml(String(ch).slice(0, 12))}…</a>`
        : '<span style="color:#6b7494">(no in-session command — SFTP/script)</span>';
      return `<div class="cmd-row">
        <div class="cmd-line">${escapeHtml(row.filename || "(unnamed)")} &nbsp;·&nbsp; ${escapeHtml(row.action || "")}</div>
        <div class="cmd-meta">session ${sLink} &nbsp;·&nbsp; ${cLink}</div>
      </div>`;
    }).join("");
    setHTML("droppers-list", html);
  }

  function renderCrossref(rows) {
    if (!rows || rows.length === 0) {
      setHTML("crossref-list",
        '<em class="empty-hint">no cross-session activity recorded — run <code>mine file-crossref</code> after the next backward pass</em>');
      return;
    }
    const html = rows.map((row) => {
      const ip = row.source_ip || "(no ip)";
      const ipLink = `<a class="gl" href="/artifact/ip/${encodeURIComponent(ip)}">${escapeHtml(ip)}</a>`;
      const fs = row.first_seen || {};
      const fx = row.first_executed || null;
      const cs = row.cross_session === true;
      const csBadge = cs
        ? '<span class="art-badge malicious" style="font-size:10px;padding:1px 6px;margin-left:8px">CROSS-SESSION</span>'
        : '<span class="art-badge neutral" style="font-size:10px;padding:1px 6px;margin-left:8px">same-session</span>';

      const fsSidLink = fs.session_id
        ? `<a class="gl" href="/graph?ioc=session:${encodeURIComponent(fs.session_id)}">${escapeHtml(fs.session_id)}</a>`
        : "?";
      const fsFile = fs.filename ? `<code>${escapeHtml(fs.filename)}</code>` : "(unnamed)";
      const fsAction = fs.action || "drop";
      const fsLine = `${escapeHtml(fsAction)} &nbsp;·&nbsp; ${fsFile} &nbsp;·&nbsp; session ${fsSidLink} &nbsp;·&nbsp; ${escapeHtml(fs.ts || "")}`;

      let fxLine = '<div class="cmd-meta" style="margin-top:4px"><em class="empty-hint">no execution attribution yet (uploaded only, never run by this IP)</em></div>';
      if (fx && fx.session_id) {
        const fxSidLink = `<a class="gl" href="/graph?ioc=session:${encodeURIComponent(fx.session_id)}">${escapeHtml(fx.session_id)}</a>`;
        const cmdHash = fx.command_hash
          ? `<a class="gl" href="/graph?ioc=command:${encodeURIComponent(fx.command_hash)}">command ${escapeHtml(String(fx.command_hash).slice(0, 12))}…</a>`
          : "(no command_hash)";
        const cmdLineHtml = fx.command_line
          ? `<div class="cmd-line" style="margin-top:4px">${escapeHtml(fx.command_line)}</div>`
          : "";
        fxLine = `<div class="cmd-meta" style="margin-top:4px">first exec: session ${fxSidLink} &nbsp;·&nbsp; ${cmdHash} &nbsp;·&nbsp; ${escapeHtml(fx.ts || "")}</div>${cmdLineHtml}`;
      }
      const counts = `<div class="cmd-meta" style="margin-top:4px;color:#6b7494">sessions dropped: ${row.n_sessions_dropped || 0} &nbsp;·&nbsp; sessions executed: ${row.n_sessions_executed || 0}</div>`;
      return `<div class="cmd-row">
        <div class="cmd-meta" style="color:#cdd4e6">IP ${ipLink}${csBadge}</div>
        <div class="cmd-meta" style="margin-top:4px">first seen: ${fsLine}</div>
        ${fxLine}
        ${counts}
      </div>`;
    }).join("");
    setHTML("crossref-list", html);
  }

  function renderProviders(intel) {
    if (!intel || !intel.providers || Object.keys(intel.providers).length === 0) {
      setHTML("providers-grid",
        '<em class="empty-hint">no provider data yet — run <code>intel refresh</code></em>');
      return;
    }
    const providers = intel.providers || {};
    const cards = Object.keys(providers).sort().map((name) => {
      const p = providers[name] || {};
      const verdict = p.malicious === true ? badge("malicious", "malicious")
                    : p.malicious === false ? badge("benign", "benign")
                    : badge("no opinion", "unknown");
      const labelHtml = p.label ? `<div style="font-size:11px;color:#8a96b8;margin:4px 0">label: <code>${escapeHtml(p.label)}</code></div>` : "";
      const confHtml = (p.confidence !== null && p.confidence !== undefined)
                       ? `<div style="font-size:11px;color:#8a96b8">confidence: <code>${p.confidence}</code></div>` : "";
      const tagsHtml = (p.tags && p.tags.length)
                       ? `<div style="font-size:11px;color:#8a96b8;margin-top:3px">tags: ${p.tags.map(t => `<code>${escapeHtml(t)}</code>`).join(" ")}</div>` : "";
      const fetchedHtml = `<div style="font-size:10px;color:#414b62;margin-top:6px">fetched ${escapeHtml(p.fetched_at || "?")}</div>`;
      const rawJson = JSON.stringify(p.structured || {}, null, 2);
      return `<div class="provider-card">
        <div class="pc-name">${escapeHtml(name)}</div>
        <div class="pc-verdict">${verdict}</div>
        ${labelHtml}${confHtml}${tagsHtml}${fetchedHtml}
        <pre>${escapeHtml(rawJson)}</pre>
      </div>`;
    });
    setHTML("providers-grid", cards.join(""));
  }

  async function load() {
    const value = getHashFromQuery();
    if (!value) {
      setText("art-value", "no hash in query string — use /artifact/hash?value=<sha256>");
      return;
    }
    setText("art-value", value);
    let data;
    try {
      const res = await fetch(`/api/artifact/hash?value=${encodeURIComponent(value)}`);
      if (!res.ok) { setText("art-value", `${value} — error ${res.status}`); return; }
      data = await res.json();
    } catch (e) {
      setText("art-value", `${value} — fetch failed`);
      return;
    }
    if (data.rejected_reason) {
      setHTML("derived-card", `<em class="empty-hint">${escapeHtml(data.rejected_reason)}</em>`);
      setHTML("droppers-list", ""); setHTML("crossref-list", "");
      setHTML("providers-grid", "");
      return;
    }
    renderBadges(data);
    renderDerived(data.intel);
    renderDroppers(data.droppers);
    renderCrossref(data.crossref);
    renderProviders(data.intel);
  }

  document.addEventListener("DOMContentLoaded", load);
})();
