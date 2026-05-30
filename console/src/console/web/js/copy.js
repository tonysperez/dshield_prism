/* Copy artifacts modal — ROADMAP #6 / Phase H.
 *
 * Pulls in-memory artifacts from Graph.allNodes() and bulk-fetches the
 * fields the graph payload doesn't carry (full command_line + threat
 * indicators per command, credentials + file-event URLs per session).
 *
 * Categories: IPs, Commands, Session IDs, Credentials, URLs, Hashes,
 * Analyst artifacts. Each has its own sub-options; the analyst's last
 * selection rides in localStorage.
 *
 * Sha256s are surfaced wherever meaningful — commands already carry one,
 * file hashes ARE the artifact, and analyst-artifact values get a
 * client-computed sha256 via SubtleCrypto (the user's call: "even if
 * this has to be computed on the fly").
 */
(function () {
  const LS_PREFS = "prism.copyModal.prefs.v1";

  // ----- preference persistence ------------------------------------------
  function loadPrefs() {
    try {
      const raw = localStorage.getItem(LS_PREFS);
      if (raw) return JSON.parse(raw);
    } catch (_) {}
    return null;
  }
  function savePrefs(prefs) {
    try { localStorage.setItem(LS_PREFS, JSON.stringify(prefs)); } catch (_) {}
  }

  // ----- in-memory pull ---------------------------------------------------
  function stripPrefix(id, p) { return id && id.startsWith(p + ":") ? id.slice(p.length + 1) : id; }

  function inScope(node, scopeKind, pinnedSet) {
    if (scopeKind !== "highlighted") return true;
    return pinnedSet.has(node.id);
  }

  // Walk the graph and bucket nodes into the categories the modal
  // surfaces. Some categories (Credentials, URLs) are populated by the
  // bulk fetch — we collect the (session_ids, command_shas) we'll need
  // for that fetch as part of the same pass.
  function collectFromGraph(scopeKind) {
    if (!window.Graph) return null;
    const nodes = window.Graph.allNodes();
    const pinned = new Set(window.Graph.getPinned ? window.Graph.getPinned() : []);
    // When "highlighted" is selected with no pin, fall back to "all" so
    // the modal doesn't appear empty — common when the analyst hasn't
    // shift-clicked anything yet.
    const scope = (scopeKind === "highlighted" && pinned.size === 0) ? "all" : scopeKind;

    const ips = [];     // {ip, asn, country}
    const sessions = []; // {session_id}
    const commands = []; // {sha256, label, intent}
    const hashes = [];   // {sha256, filename, family, action, malicious}
    const playbooks = []; // {playbook_id, name}
    const campaigns = []; // {campaign_id, name}
    const session_ids = new Set();
    const command_shas = new Set();
    const playbook_ids = new Set();
    const campaign_ids = new Set();
    const ip_values = new Set();

    for (const n of nodes) {
      if (!inScope(n, scope, pinned)) continue;
      if (n.type === "ip") {
        const ip = stripPrefix(n.id, "ip");
        ips.push({
          ip, asn: n.asn || null, country: n.country || null,
          specificity: typeof n.specificity === "number" ? n.specificity : null,
        });
        if (ip) ip_values.add(ip);
      } else if (n.type === "session") {
        const sid = stripPrefix(n.id, "session");
        sessions.push({ session_id: sid });
        session_ids.add(sid);
      } else if (n.type === "command") {
        const sha = n.sha256 || stripPrefix(n.id, "cmd");
        commands.push({
          sha256: sha,
          label:  n.label || "",
          intent: n.intent || null,
          specificity: typeof n.specificity === "number" ? n.specificity : null,
          mitre_techniques: Array.isArray(n.mitre_techniques) ? n.mitre_techniques : [],
          mitre_tactics:    Array.isArray(n.mitre_tactics)    ? n.mitre_tactics    : [],
        });
        if (sha) command_shas.add(sha);
      } else if (n.type === "file") {
        hashes.push({
          sha256:   n.sha256 || stripPrefix(n.id, "file"),
          // The graph already prefers attacker-supplied filename when
          // known and falls back to a truncated sha; the dedicated
          // n.filename field is the authoritative copy.
          filename: n.filename || n.label || "",
          family: n.family || null,
          action: n.action || null,
          malicious: !!n.malicious,
          source: "file_event",
        });
      } else if (n.type === "playbook") {
        const pid = n.playbook_id || stripPrefix(n.id, "pb");
        playbooks.push({ playbook_id: pid, name: n.label || pid });
        if (pid) playbook_ids.add(pid);
      } else if (n.type === "campaign") {
        const cid = n.campaign_id || stripPrefix(n.id, "camp");
        campaigns.push({ campaign_id: cid, name: n.label || cid });
        if (cid) campaign_ids.add(cid);
      }
    }
    return {
      ips, sessions, commands, hashes, playbooks, campaigns,
      session_ids, command_shas, playbook_ids, campaign_ids, ip_values,
      scope,
    };
  }

  // ----- bulk fetch -------------------------------------------------------
  // One round-trip resolves every detail the graph payload doesn't carry.
  // Returns {sessions: {sid -> {…}}, commands: {sha -> {…}}}.
  async function bulkFetch(session_ids, command_shas, playbook_ids, campaign_ids, ips) {
    if (!session_ids.length && !command_shas.length && !playbook_ids.length
        && !campaign_ids.length && !ips.length) {
      return { sessions: {}, commands: {}, lifecycle_notes: [] };
    }
    const r = await fetch("/api/graph/artifacts-detail", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session_ids, command_shas, playbook_ids, campaign_ids, ips,
      }),
    });
    if (!r.ok) throw new Error(`artifacts-detail HTTP ${r.status}`);
    return await r.json();
  }

  // ----- sha256 of arbitrary strings (analyst-artifact values) ------------
  async function sha256Hex(s) {
    const bytes = new TextEncoder().encode(String(s));
    const buf = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, "0")).join("");
  }

  // ----- category builders ------------------------------------------------
  //
  // Each builder returns:
  //   { header, columns, rows }
  // where columns is an array of column names and rows is an array of
  // arrays of cell values. Format renderers (plain / md / csv / json)
  // consume this same shape regardless of category.
  function buildIps(pulled, opts, fetched) {
    const cols = ["ip"];
    if (opts.asn)     cols.push("asn");
    if (opts.country) cols.push("country");
    if (opts.specificity) cols.push("specificity");
    if (opts.hassh)   cols.push("hassh");
    if (opts.intel)   cols.push("intel");
    const ipIntel = (fetched && fetched.intel && fetched.intel.ip) || {};
    const ipExtra = (fetched && fetched.ip_extras) || {};
    const rows = [];
    const seen = new Set();
    for (const e of pulled.ips) {
      if (!e.ip || seen.has(e.ip)) continue;
      seen.add(e.ip);
      const row = [e.ip];
      if (opts.asn)     row.push(e.asn != null ? `AS${e.asn}` : "");
      if (opts.country) row.push(e.country || "");
      if (opts.specificity) row.push(e.specificity != null ? e.specificity.toFixed(2) : "");
      if (opts.hassh)   row.push((ipExtra[e.ip] && ipExtra[e.ip].hassh) || "");
      if (opts.intel) {
        const iv = ipIntel[e.ip];
        row.push(_fmtIntel(iv));
      }
      rows.push(row);
    }
    return { header: "IPs", columns: cols, rows };
  }

  // Minimal verdict line so the column stays readable: "malicious (3/5)"
  // or "clean (override: authoritative_clean)" or "unknown".
  function _fmtIntel(iv) {
    if (!iv) return "";
    const verdict = iv.verdict || "unknown";
    const fam = iv.family ? ` · ${iv.family}` : "";
    if (verdict === "malicious") {
      const c = iv.malicious_count != null ? ` (${iv.malicious_count}/${iv.provider_count || "?"})` : "";
      return `malicious${c}${fam}`;
    }
    if (verdict === "clean") {
      const ov = iv.override ? ` (${iv.override})` : "";
      return `clean${ov}`;
    }
    return verdict;
  }

  function buildCommands(pulled, opts, fetched) {
    const cols = [];
    if (opts.text)   cols.push("command");
    if (opts.sha256) cols.push("sha256");
    if (opts.intent) cols.push("intent");
    if (opts.specificity) cols.push("specificity");
    if (opts.mitre)  cols.push("mitre");
    const rows = [];
    const seen = new Set();
    for (const c of pulled.commands) {
      const sha = c.sha256;
      if (!sha || seen.has(sha)) continue;
      seen.add(sha);
      const detail = (fetched && fetched.commands && fetched.commands[sha]) || null;
      const fullText = detail ? detail.command_line : "";
      const fullSha  = detail ? (detail.sha256_full || sha) : sha;
      const text = fullText || c.label || "";
      const intent = (detail && detail.intent) || c.intent || "";
      const row = [];
      if (opts.text)   row.push(text);
      if (opts.sha256) row.push(fullSha);
      if (opts.intent) row.push(intent || "");
      if (opts.specificity) row.push(c.specificity != null ? c.specificity.toFixed(2) : "");
      if (opts.mitre) {
        const ids = [...(c.mitre_tactics || []), ...(c.mitre_techniques || [])];
        row.push(ids.join(" "));
      }
      rows.push(row);
    }
    return { header: "Commands", columns: cols, rows };
  }

  // Aggregate HASSH category — unique SSH-client fingerprints across
  // visible IPs, with the IP count + sample IPs sharing each one. The
  // per-IP HASSH column on the IPs section answers "what's this IP's
  // fingerprint"; this section answers "how many distinct clients do
  // we see, and which IPs share each".
  function buildHasshAggregate(pulled, fetched) {
    const ipExtra = (fetched && fetched.ip_extras) || {};
    const tally = new Map(); // hassh -> Set<ip>
    for (const e of pulled.ips) {
      const h = (ipExtra[e.ip] && ipExtra[e.ip].hassh) || "";
      if (!h) continue;
      if (!tally.has(h)) tally.set(h, new Set());
      tally.get(h).add(e.ip);
    }
    const rows = [...tally.entries()]
      .map(([h, ips]) => [h, ips.size])
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    return {
      header: "HASSH fingerprints",
      columns: ["hassh", "ip_count"],
      rows,
    };
  }

  // Aggregate MITRE category — unique tactic + technique IDs across all
  // visible commands, counted. Each row: id, type, command_count.
  function buildMitreAggregate(pulled) {
    const tally = new Map(); // id -> {type, count}
    for (const c of pulled.commands) {
      for (const t of c.mitre_tactics || []) {
        const v = tally.get(t) || { type: "tactic", count: 0 };
        v.count += 1; tally.set(t, v);
      }
      for (const t of c.mitre_techniques || []) {
        const v = tally.get(t) || { type: "technique", count: 0 };
        v.count += 1; tally.set(t, v);
      }
    }
    const rows = [...tally.entries()]
      .map(([id, v]) => [id, v.type, v.count])
      .sort((a, b) => b[2] - a[2] || a[0].localeCompare(b[0]));
    return { header: "MITRE ATT&CK", columns: ["id", "type", "command_count"], rows };
  }

  function buildSessions(pulled) {
    const rows = [];
    const seen = new Set();
    for (const s of pulled.sessions) {
      if (!s.session_id || seen.has(s.session_id)) continue;
      seen.add(s.session_id);
      rows.push([s.session_id]);
    }
    return { header: "Session IDs", columns: ["session_id"], rows };
  }

  function buildCredentials(pulled, fetched) {
    const rows = [];
    const seen = new Set();
    for (const s of pulled.sessions) {
      const sid = s.session_id;
      const detail = fetched && fetched.sessions && fetched.sessions[sid];
      const creds = (detail && detail.credentials) || [];
      for (const c of creds) {
        if (!c || seen.has(c)) continue;
        seen.add(c);
        rows.push([c]);
      }
    }
    return { header: "Credentials", columns: ["user:pass"], rows };
  }

  function buildUrls(pulled, opts, fetched) {
    const cols = ["url", "source"];
    if (opts.intel) cols.push("intel");
    const urlIntel = (fetched && fetched.intel && fetched.intel.url) || {};
    const rows = [];
    const seen = new Set();
    const push = (u, sourceLabel) => {
      if (!u || seen.has(u)) return;
      seen.add(u);
      const row = [u, sourceLabel];
      if (opts.intel) row.push(_fmtIntel(urlIntel[u]));
      rows.push(row);
    };
    for (const s of pulled.sessions) {
      const sid = s.session_id;
      const detail = fetched && fetched.sessions && fetched.sessions[sid];
      for (const u of (detail && detail.file_event_urls) || []) push(u, "file_event");
    }
    for (const c of pulled.commands) {
      const sha = c.sha256;
      const detail = fetched && fetched.commands && fetched.commands[sha];
      for (const u of (detail && detail.indicator_urls) || []) push(u, "command_indicator");
    }
    return { header: "URLs", columns: cols, rows };
  }

  function buildHashes(pulled, opts, fetched) {
    const wantFilename = opts.filename !== false;  // default on
    const wantAttr     = opts.attribution !== false; // default on
    const wantIntel    = !!opts.intel;
    const hashIntel = (fetched && fetched.intel && fetched.intel.hash) || {};
    const cmdLines  = (fetched && fetched.dropping_command_lines) || {};
    const cols = ["sha256"];
    if (wantFilename) cols.push("filename");
    if (wantAttr)     cols.push("dropping_cmd", "attribution");
    cols.push("source", "context");
    if (wantIntel)    cols.push("intel");
    const rows = [];
    // Key by sha; entries with a richer attribution win when multiple
    // file_events touch the same hash.
    const byHash = new Map();
    const push = (sha, filename, source, context, droppingHash, attribution, action) => {
      if (!sha) return;
      const prev = byHash.get(sha);
      if (prev) {
        if (!prev.filename && filename)        prev.filename = filename;
        if (!prev.context && context)          prev.context  = context;
        if (!prev.droppingHash && droppingHash) prev.droppingHash = droppingHash;
        if (!prev.attribution && attribution)   prev.attribution = attribution;
        if (!prev.action && action)            prev.action = action;
        return;
      }
      byHash.set(sha, {
        sha256: sha,
        filename: filename || "",
        source: source,
        context: context || "",
        droppingHash: droppingHash || "",
        attribution: attribution || "",
        action: action || "",
      });
    };
    // file nodes already on the graph (no attribution / dropping cmd here)
    for (const h of pulled.hashes) {
      const ctx = [
        h.family && `family=${h.family}`,
        h.malicious ? "malicious" : null,
      ].filter(Boolean).join(", ");
      push(h.sha256, h.filename, "file_event", ctx, "", "", h.action || "");
    }
    // session-rollup file_event entries from bulk fetch
    for (const s of pulled.sessions) {
      const detail = fetched && fetched.sessions && fetched.sessions[s.session_id];
      for (const fe of (detail && detail.file_event_files) || []) {
        push(fe.sha256, fe.filename, "file_event", "",
             fe.command_hash || "", fe.command_attribution || "",
             fe.action || "");
      }
    }
    // command threat.indicator.file.hash.sha256
    for (const c of pulled.commands) {
      const detail = fetched && fetched.commands && fetched.commands[c.sha256];
      for (const sha of (detail && detail.indicator_hashes) || []) {
        push(sha, "", "command_indicator", "", "", "", "");
      }
    }
    for (const v of byHash.values()) {
      const row = [v.sha256];
      if (wantFilename) row.push(v.filename);
      if (wantAttr) {
        row.push(_renderDroppingCmd(v, cmdLines));
        row.push(v.attribution);
      }
      row.push(v.source, v.context);
      if (wantIntel) row.push(_fmtIntel(hashIntel[v.sha256]));
      rows.push(row);
    }
    return { header: "File hashes", columns: cols, rows };
  }

  // Translate the dropping-command hash into something the analyst can
  // read. SFTP/SCP uploads typically carry no command_hash — call them
  // out so a blank cell doesn't suggest a missing dropper.
  function _renderDroppingCmd(v, cmdLines) {
    if (v.droppingHash) {
      const line = cmdLines[v.droppingHash];
      if (line) {
        return line.length > 160 ? line.slice(0, 157) + "…" : line;
      }
      // Fall back to the bare hash when the command doc isn't around
      // (rare — usually means the command index lacks the row).
      return v.droppingHash;
    }
    if (v.action === "upload") return "(SFTP/SCP upload)";
    if (v.action === "download") return "(unattributed download)";
    return "";
  }

  function buildSessionSequences(pulled, fetched) {
    const seqs = (fetched && fetched.session_sequences) || {};
    const rows = [];
    for (const s of pulled.sessions) {
      const sid = s.session_id;
      const cmds = seqs[sid] || [];
      cmds.forEach((c, i) => {
        rows.push([sid, i + 1, c.ts || "", c.command_line || "", c.sha256 || ""]);
      });
    }
    return {
      header: "Session sequences",
      columns: ["session_id", "seq", "ts", "command_line", "sha256"],
      rows,
      // Render hint: plain + markdown format these as per-session blocks
      // (a numbered list per session reads as the narrative the analyst
      // actually wants); csv + json fall back to the flat row shape.
      sequence_grouped: true,
    };
  }

  function buildLifecycleNotes(pulled, fetched) {
    const cols = ["ts", "anchor", "status", "note"];
    const rows = [];
    const labelFor = (kind, value) => {
      // Prefer human-readable graph labels (playbook name / campaign name)
      // when we have them; fall back to the bare value otherwise.
      if (kind === "playbook") {
        const m = pulled.playbooks.find(p => p.playbook_id === value);
        if (m && m.name) return `playbook · ${m.name}`;
      }
      if (kind === "campaign") {
        const m = pulled.campaigns.find(p => p.campaign_id === value);
        if (m && m.name) return `campaign · ${m.name}`;
      }
      return `${kind} · ${value}`;
    };
    for (const n of (fetched && fetched.lifecycle_notes) || []) {
      rows.push([
        n.ts || "",
        labelFor(n.artifact_kind, n.artifact_value),
        n.status || "",
        n.note || "",
      ]);
    }
    return { header: "Lifecycle notes", columns: cols, rows };
  }

  async function buildAnalystArtifacts(pulled, opts, fetched) {
    // notes from the rule that produced each match — surfaced as a
    // column so the analyst's rationale rides alongside the value in
    // the Report. A single (kind, value) may match multiple rules; we
    // union their notes with " // " between them.
    const ruleNotes = (fetched && fetched.rule_notes) || {};
    const cols = ["kind", "value"];
    if (opts.sha256) cols.push("value_sha256");
    cols.push("notes");
    const rows = [];
    const byKey = new Map(); // (kind|value) -> {row, noteSet}
    const pushArtifact = async (a) => {
      if (!a || typeof a !== "object") return;
      const kind = a.kind || "?";
      const value = a.value != null ? String(a.value) : "";
      const note = (ruleNotes[a.rule_id] || "").trim();
      const key = `${kind}|${value}`;
      if (byKey.has(key)) {
        if (note) byKey.get(key).noteSet.add(note);
        return;
      }
      const row = [kind, value];
      if (opts.sha256) row.push(value ? await sha256Hex(value) : "");
      row.push("");  // notes column — filled in after dedup pass
      byKey.set(key, { row, noteSet: new Set(note ? [note] : []) });
    };
    for (const s of pulled.sessions) {
      const detail = fetched && fetched.sessions && fetched.sessions[s.session_id];
      for (const a of (detail && detail.analyst_artifacts) || []) await pushArtifact(a);
    }
    for (const c of pulled.commands) {
      const detail = fetched && fetched.commands && fetched.commands[c.sha256];
      for (const a of (detail && detail.analyst_artifacts) || []) await pushArtifact(a);
    }
    for (const v of byKey.values()) {
      v.row[v.row.length - 1] = Array.from(v.noteSet).join(" // ");
      rows.push(v.row);
    }
    return { header: "Analyst artifacts", columns: cols, rows };
  }

  // ----- report header / provenance --------------------------------------
  // Pure-frontend: timestamp, anchor IOC parsed from URL, scope, the
  // F.1 URL state envelope (lanes / siblings / spotlight / require_* /
  // debug), and a reproducible graph URL link. Pulled from location +
  // localStorage so the analyst can paste a link that round-trips to
  // the exact view.
  function provenance(scope, pulled) {
    const p = new URLSearchParams(location.search);
    const ioc = p.get("ioc") || "";
    let anchorLabel = ioc;
    if (ioc.includes(":")) {
      const [kind, id] = ioc.split(":", 2);
      // Prefer the labelled form from the graph nodes when we have it.
      const labelMatch = (pulled && pulled.playbooks.find(x => x.playbook_id === id))
                     || (pulled && pulled.campaigns.find(x => x.campaign_id === id));
      const human = labelMatch ? (labelMatch.name || id) : id;
      anchorLabel = `${kind} · ${human}`;
    }
    const knobs = [];
    for (const k of ["siblings", "lanes", "spot", "sh", "st", "rl", "rc", "debug"]) {
      if (p.has(k)) knobs.push(`${k}=${p.get(k)}`);
    }
    return {
      generated_at: new Date().toISOString(),
      anchor:       anchorLabel || "(none)",
      scope:        scope === "highlighted" ? "pinned/highlighted only" : "everything in view",
      knobs:        knobs.length ? knobs.join(" ") : "(defaults)",
      url:          location.href,
    };
  }
  function renderHeaderPlain(h) {
    return [
      "# Prism Report",
      `Generated:  ${h.generated_at}`,
      `Anchor:     ${h.anchor}`,
      `Scope:      ${h.scope}`,
      `Knobs:      ${h.knobs}`,
      `Source URL: ${h.url}`,
      "",
    ].join("\n");
  }
  function renderHeaderMarkdown(h) {
    return [
      "# Prism Report",
      "",
      `- **Generated:** ${h.generated_at}`,
      `- **Anchor:** ${h.anchor}`,
      `- **Scope:** ${h.scope}`,
      `- **Knobs:** \`${h.knobs}\``,
      `- **Source URL:** ${h.url}`,
      "",
    ].join("\n");
  }
  function renderHeaderCsv(h) {
    return [
      "# Prism Report",
      `# Generated,${csvEscape(h.generated_at)}`,
      `# Anchor,${csvEscape(h.anchor)}`,
      `# Scope,${csvEscape(h.scope)}`,
      `# Knobs,${csvEscape(h.knobs)}`,
      `# Source URL,${csvEscape(h.url)}`,
      "",
    ].join("\n");
  }

  // ----- format renderers -------------------------------------------------
  function renderPlain(sections, header) {
    const out = [];
    if (header) out.push(renderHeaderPlain(header));
    for (const sec of sections) {
      if (!sec.rows.length) continue;
      out.push(`## ${sec.header}`);
      if (sec.sequence_grouped) {
        out.push(renderSequenceGroupedPlain(sec));
      } else {
        for (const r of sec.rows) {
          out.push(r.map(c => (c == null ? "" : String(c))).join("\t"));
        }
      }
      out.push("");
    }
    return out.join("\n");
  }

  function renderMarkdown(sections, header) {
    const out = [];
    if (header) out.push(renderHeaderMarkdown(header));
    for (const sec of sections) {
      if (!sec.rows.length) continue;
      out.push(`## ${sec.header}`);
      out.push("");
      if (sec.sequence_grouped) {
        out.push(renderSequenceGroupedMarkdown(sec));
      } else {
        out.push("| " + sec.columns.join(" | ") + " |");
        out.push("|" + sec.columns.map(() => "---").join("|") + "|");
        for (const r of sec.rows) {
          out.push("| " + r.map(mdEscape).join(" | ") + " |");
        }
      }
      out.push("");
    }
    return out.join("\n");
  }

  // Per-session numbered list — what an analyst actually wants to paste
  // into a writeup. CSV / JSON keep the flat row shape.
  function _groupSequencesBySession(sec) {
    const groups = new Map();
    for (const r of sec.rows) {
      const sid = r[0];
      if (!groups.has(sid)) groups.set(sid, []);
      groups.get(sid).push({ seq: r[1], ts: r[2], command_line: r[3], sha256: r[4] });
    }
    return groups;
  }
  function renderSequenceGroupedPlain(sec) {
    const out = [];
    for (const [sid, cmds] of _groupSequencesBySession(sec)) {
      out.push(`### Session ${sid}`);
      for (const c of cmds) {
        out.push(`${c.seq}. [${c.ts}] ${c.command_line}`);
      }
      out.push("");
    }
    return out.join("\n");
  }
  function renderSequenceGroupedMarkdown(sec) {
    const out = [];
    for (const [sid, cmds] of _groupSequencesBySession(sec)) {
      out.push(`### Session \`${sid}\``);
      out.push("");
      for (const c of cmds) {
        out.push(`${c.seq}. \`${c.ts}\` — \`${c.command_line.replace(/`/g, "\\`")}\``);
      }
      out.push("");
    }
    return out.join("\n");
  }
  function mdEscape(v) {
    if (v == null) return "";
    return String(v).replace(/\|/g, "\\|").replace(/\n/g, " ");
  }

  function renderCsv(sections, header) {
    const out = [];
    if (header) out.push(renderHeaderCsv(header));
    for (const sec of sections) {
      if (!sec.rows.length) continue;
      out.push(`# ${sec.header}`);
      out.push(sec.columns.map(csvEscape).join(","));
      for (const r of sec.rows) out.push(r.map(csvEscape).join(","));
      out.push("");
    }
    return out.join("\n");
  }
  function csvEscape(v) {
    if (v == null) return "";
    const s = String(v);
    if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
    return s;
  }

  function renderJson(sections, header) {
    const obj = header ? { meta: header } : {};
    for (const sec of sections) {
      if (!sec.rows.length) continue;
      obj[sec.header] = sec.rows.map(r => {
        const o = {};
        sec.columns.forEach((c, i) => { o[c] = r[i] != null ? r[i] : null; });
        return o;
      });
    }
    return JSON.stringify(obj, null, 2);
  }

  function render(sections, format, header) {
    if (format === "markdown") return renderMarkdown(sections, header);
    if (format === "csv")      return renderCsv(sections, header);
    if (format === "json")     return renderJson(sections, header);
    return renderPlain(sections, header);
  }

  // ----- count helpers (modal labels) -------------------------------------
  // Cheap pre-fetch counts so the analyst sees scope on the checkbox
  // before clicking. Credentials/URLs/analyst rely on bulk fetch and
  // their counts only update after Refresh.
  function localCounts(pulled) {
    const uniqIps      = new Set(pulled.ips.map(e => e.ip)).size;
    const uniqSess     = new Set(pulled.sessions.map(e => e.session_id)).size;
    const uniqCmds     = new Set(pulled.commands.map(e => e.sha256)).size;
    const uniqFiles    = new Set(pulled.hashes.map(e => e.sha256)).size;
    return {
      ips:      uniqIps,
      sessions: uniqSess,
      commands: uniqCmds,
      hashes:   uniqFiles,
      credentials: null,
      urls: null,
      analyst_artifacts: null,
      lifecycle_notes: null,
      mitre: null,
      hassh_agg: null,
      session_sequences: null,
    };
  }

  // After buildAll(), refresh count chips with post-fetch totals for the
  // categories that depend on the bulk endpoint.
  function refreshCountsFromSections(sections) {
    const map = {
      "IPs": "ips",
      "Commands": "commands",
      "Session IDs": "sessions",
      "Credentials": "credentials",
      "URLs": "urls",
      "File hashes": "hashes",
      "Analyst artifacts": "analyst_artifacts",
      "Lifecycle notes": "lifecycle_notes",
      "MITRE ATT&CK": "mitre",
      "HASSH fingerprints": "hassh_agg",
      "Session sequences": "session_sequences",
    };
    for (const sec of sections) {
      const cat = map[sec.header];
      if (!cat) continue;
      const el = document.querySelector(`.copy-cat-count[data-count-cat="${cat}"]`);
      if (el) el.textContent = `(${sec.rows.length})`;
    }
  }

  // ----- modal wiring -----------------------------------------------------
  function getOpts(cat) {
    const opts = {};
    document.querySelectorAll(`.copy-opt[data-cat="${cat}"]`).forEach((el) => {
      opts[el.dataset.opt] = el.checked;
    });
    return opts;
  }
  function getSelectedCats() {
    const out = [];
    document.querySelectorAll(".copy-cat").forEach((el) => {
      if (el.checked) out.push(el.dataset.cat);
    });
    return out;
  }
  function getScope() {
    const el = document.querySelector('input[name="copy-scope"]:checked');
    return el ? el.value : "all";
  }
  function getFormat() {
    const el = document.querySelector('input[name="copy-format"]:checked');
    return el ? el.value : "plain";
  }
  function setStatus(msg, tone = "neutral") {
    const el = document.getElementById("copy-status");
    if (!el) return;
    el.textContent = msg || "";
    el.dataset.tone = tone;
  }

  async function buildAll(pulled, fetched) {
    const cats = getSelectedCats();
    const sections = [];
    if (cats.includes("ips"))           sections.push(buildIps(pulled, getOpts("ips"), fetched));
    if (cats.includes("commands"))      sections.push(buildCommands(pulled, getOpts("commands"), fetched));
    if (cats.includes("sessions"))      sections.push(buildSessions(pulled));
    if (cats.includes("credentials"))   sections.push(buildCredentials(pulled, fetched));
    if (cats.includes("urls"))          sections.push(buildUrls(pulled, getOpts("urls"), fetched));
    if (cats.includes("hashes"))        sections.push(buildHashes(pulled, getOpts("hashes"), fetched));
    if (cats.includes("analyst_artifacts")) {
      sections.push(await buildAnalystArtifacts(pulled, getOpts("analyst_artifacts"), fetched));
    }
    if (cats.includes("lifecycle_notes")) sections.push(buildLifecycleNotes(pulled, fetched));
    if (cats.includes("mitre"))           sections.push(buildMitreAggregate(pulled));
    if (cats.includes("hassh_agg"))       sections.push(buildHasshAggregate(pulled, fetched));
    if (cats.includes("session_sequences")) sections.push(buildSessionSequences(pulled, fetched));
    return sections;
  }

  // Categories whose data requires the bulk endpoint. When any of these
  // is checked, we fetch and re-render.
  function needsFetch(cats) {
    if (cats.includes("credentials") || cats.includes("urls")
        || cats.includes("analyst_artifacts") || cats.includes("lifecycle_notes")
        || cats.includes("commands")            // text + indicators
        || cats.includes("hashes")              // filename, attribution, intel
        || cats.includes("session_sequences")   // per-session ordered commands
        || cats.includes("hassh_agg"))          // IP-extras carry hassh
      return true;
    // Intel/hassh/specificity sub-options on IPs/commands also trigger fetch.
    if (cats.includes("ips")) {
      const o = getOpts("ips");
      if (o.intel || o.hassh) return true;
    }
    return false;
  }

  let _lastFetchKey = null;
  let _lastFetched = { sessions: {}, commands: {} };
  let _lastPulled = null;

  async function rebuild() {
    const scope = getScope();
    const pulled = collectFromGraph(scope);
    _lastPulled = pulled;
    if (!pulled) return;

    // Local count chips
    const lc = localCounts(pulled);
    document.querySelectorAll(".copy-cat-count").forEach((el) => {
      const cat = el.dataset.countCat;
      const v = lc[cat];
      el.textContent = v == null ? "" : `(${v})`;
    });
    const sc = document.getElementById("copy-scope-count");
    if (sc) {
      sc.textContent = scope === "highlighted" && pulled.scope === "all"
        ? "(no pin set — falling back to Everything)"
        : "";
    }

    const cats = getSelectedCats();
    let fetched = _lastFetched;
    if (needsFetch(cats)) {
      const sids = Array.from(pulled.session_ids).sort();
      const shas = Array.from(pulled.command_shas).sort();
      const pids = Array.from(pulled.playbook_ids).sort();
      const cids = Array.from(pulled.campaign_ids).sort();
      const ips  = Array.from(pulled.ip_values).sort();
      const key = `${scope}|s:${sids.join(",")}|c:${shas.join(",")}|p:${pids.join(",")}|cmp:${cids.join(",")}|i:${ips.join(",")}`;
      if (key !== _lastFetchKey) {
        setStatus("fetching session + command + lifecycle detail…");
        try {
          fetched = await bulkFetch(sids, shas, pids, cids, ips);
          _lastFetched = fetched;
          _lastFetchKey = key;
          setStatus("");
        } catch (e) {
          setStatus(`bulk fetch failed: ${e.message || e}`, "error");
        }
      }
    } else {
      _lastFetchKey = null;
      _lastFetched = { sessions: {}, commands: {}, lifecycle_notes: [] };
      fetched = _lastFetched;
    }

    const sections = await buildAll(pulled, fetched);
    refreshCountsFromSections(sections);
    const headerOn = !!document.getElementById("copy-header-toggle")?.checked;
    const header = headerOn ? provenance(scope, pulled) : null;
    const text = render(sections, getFormat(), header);
    const pre = document.getElementById("copy-preview");
    if (pre) pre.textContent = text || "(empty selection)";
    return { sections, text };
  }

  async function doCopy() {
    const built = await rebuild();
    if (!built) return;
    try {
      await navigator.clipboard.writeText(built.text);
      setStatus(`copied ${built.text.length.toLocaleString()} chars`, "ok");
    } catch (e) {
      setStatus(`clipboard write failed: ${e.message || e}`, "error");
    }
  }
  async function doDownload() {
    const built = await rebuild();
    if (!built) return;
    const fmt = getFormat();
    const ext = fmt === "markdown" ? "md" : (fmt === "plain" ? "txt" : fmt);
    const blob = new Blob([built.text], { type: "text/plain;charset=utf-8" });
    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `prism-artifacts-${ts}.${ext}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setStatus(`downloaded ${a.download}`, "ok");
  }

  function applyPrefsToUI(prefs) {
    if (!prefs) return;
    // categories
    const cats = prefs.cats || {};
    document.querySelectorAll(".copy-cat").forEach((el) => {
      if (cats[el.dataset.cat] != null) el.checked = !!cats[el.dataset.cat];
    });
    // sub-options
    const opts = prefs.opts || {};
    document.querySelectorAll(".copy-opt").forEach((el) => {
      const cat = el.dataset.cat, opt = el.dataset.opt;
      if (opts[cat] && opts[cat][opt] != null) el.checked = !!opts[cat][opt];
    });
    // format
    if (prefs.format) {
      const r = document.querySelector(`input[name="copy-format"][value="${prefs.format}"]`);
      if (r) r.checked = true;
    }
    // scope is intentionally not persisted — it's contextual to the
    // current view, not a long-running preference.
  }
  function captureCurrentPrefs() {
    const cats = {};
    document.querySelectorAll(".copy-cat").forEach((el) => { cats[el.dataset.cat] = el.checked; });
    const opts = {};
    document.querySelectorAll(".copy-opt").forEach((el) => {
      opts[el.dataset.cat] = opts[el.dataset.cat] || {};
      opts[el.dataset.cat][el.dataset.opt] = el.checked;
    });
    return { cats, opts, format: getFormat() };
  }

  function openModal() {
    const m = document.getElementById("copy-artifacts-modal");
    if (m) m.classList.remove("hidden");
    rebuild();
  }
  function closeModal() {
    const m = document.getElementById("copy-artifacts-modal");
    if (m) m.classList.add("hidden");
  }

  function wire() {
    const btn = document.getElementById("copy-artifacts-btn");
    if (btn) btn.addEventListener("click", openModal);
    const close = document.getElementById("copy-artifacts-close");
    if (close) close.addEventListener("click", closeModal);

    const modal = document.getElementById("copy-artifacts-modal");
    if (modal) {
      // Click on backdrop closes (consistent with other modals).
      modal.addEventListener("click", (ev) => {
        if (ev.target === modal) closeModal();
      });
    }

    document.querySelectorAll(".copy-cat, .copy-opt").forEach((el) => {
      el.addEventListener("change", () => {
        savePrefs(captureCurrentPrefs());
        rebuild();
      });
    });
    const headerToggle = document.getElementById("copy-header-toggle");
    if (headerToggle) headerToggle.addEventListener("change", () => {
      savePrefs(captureCurrentPrefs());
      rebuild();
    });
    document.querySelectorAll('input[name="copy-format"]').forEach((el) => {
      el.addEventListener("change", () => {
        savePrefs(captureCurrentPrefs());
        rebuild();
      });
    });
    document.querySelectorAll('input[name="copy-scope"]').forEach((el) => {
      el.addEventListener("change", rebuild);
    });

    const copyBtn = document.getElementById("copy-clipboard");
    if (copyBtn) copyBtn.addEventListener("click", doCopy);
    const dlBtn = document.getElementById("copy-download");
    if (dlBtn) dlBtn.addEventListener("click", doDownload);

    document.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape") {
        const m = document.getElementById("copy-artifacts-modal");
        if (m && !m.classList.contains("hidden")) {
          closeModal();
          ev.stopPropagation();
        }
      }
    });

    applyPrefsToUI(loadPrefs());
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire);
  } else {
    wire();
  }
})();
