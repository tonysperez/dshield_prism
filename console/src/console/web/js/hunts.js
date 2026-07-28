/* Hunts page.
 *
 * Lists every YAML-defined hypothesis hunt — including disabled ones,
 * which render muted. Actions per hunt:
 *
 *   toggle   flips `enabled` in the hunt's YAML file. `enabled` gates
 *            whether the hunt WRITES findings; it never affects whether
 *            the hunt loads or can be previewed.
 *   Preview  executes the hunt's query and shows matching sessions.
 *            Writes nothing — no findings are created.
 *   Edit     opens the filter builder on the hunt's own YAML file.
 *   link     click-through to /inbox?stream=hunt&hunt_id=<id> with that
 *            hunt's existing matches at status=all.
 *
 * The builder is the only authoring surface — there is no raw-YAML
 * escape hatch, so an invalid clause cannot be composed. Client
 * validation mirrors `_validate_filter` in
 * src/enrich/findings/hunts.py, but it is a keystroke convenience only:
 * the server re-runs the loader's own validator on every write.
 *
 * "Run enabled hunts" and the builder's Save / Delete are the only
 * controls here that persist anything.
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

  /* --- Filter builder ------------------------------------------------
   * One spec entry per supported filter kind: which field the clause
   * carries, how the raw input text becomes that field's value, and
   * what makes it invalid. Mirrors `_validate_filter`; the server is
   * still the authority.
   */
  // One value per LINE, not per comma: artifact values legitimately
  // contain commas (`chattr +i`, argv fragments), and splitting on them
  // silently turned one value into two on every round-trip through the
  // editor.
  function parseList(raw) {
    return String(raw).split(/\r?\n/).map(s => s.trim()).filter(s => s.length);
  }

  function parseIntStrict(raw) {
    const t = String(raw).trim();
    if (!/^-?\d+$/.test(t)) return null;
    // `parseInt` happily rounds a 30-digit string to something else
    // entirely; anything past 2^53 is not the number the analyst typed.
    const n = Number(t);
    return Number.isSafeInteger(n) ? n : null;
  }

  function parseFloatStrict(raw) {
    const t = String(raw).trim();
    // Accept every finite literal YAML round-trips (`.85`, `1e-3`, `0.`),
    // not just the fixed-point subset — the range check below is what
    // actually constrains the value.
    if (!t) return null;
    const n = Number(t);
    if (!Number.isFinite(n)) return null;
    return n;
  }

  const MAX_LAST_DAYS = 3650;         // mirrors `_MAX_LAST_DAYS`

  const FILTER_KINDS = {
    artifact_set_contains_any: {
      label: "artifact set contains ANY of",
      field: "values", type: "list", parse: parseList,
      placeholder: "crontab\nauthorized_keys\nsystemctl",
      hint: "one value per line",
      validate: v => v.length ? null : "needs at least one value",
    },
    artifact_set_contains_all: {
      label: "artifact set contains ALL of",
      field: "values", type: "list", parse: parseList,
      placeholder: "crontab\nchattr +i",
      hint: "one value per line",
      validate: v => v.length ? null : "needs at least one value",
    },
    intent_in: {
      label: "dominant intent in",
      field: "values", type: "list", parse: parseList,
      placeholder: "install_persistence\nexecute_payload",
      hint: "one value per line",
      validate: v => v.length ? null : "needs at least one value",
    },
    command_count_gte: {
      label: "command count >=",
      field: "threshold", type: "number", parse: parseIntStrict,
      placeholder: "10", hint: "integer >= 0",
      validate: v => (v !== null && v >= 0) ? null : "must be an integer >= 0",
    },
    login_fail_count_gte: {
      label: "login failure count >=",
      field: "threshold", type: "number", parse: parseIntStrict,
      placeholder: "20", hint: "integer >= 0",
      validate: v => (v !== null && v >= 0) ? null : "must be an integer >= 0",
    },
    external_match_cosine_gte: {
      label: "external match cosine >=",
      field: "threshold", type: "number", parse: parseFloatStrict,
      placeholder: "0.85", hint: "0.0 – 1.0",
      validate: v => (v !== null && v >= 0 && v <= 1)
        ? null : "must be a number between 0 and 1",
    },
    window: {
      label: "seen within the last N days",
      field: "last_days", type: "number", parse: parseIntStrict,
      placeholder: "7", hint: "integer 1 – " + MAX_LAST_DAYS,
      validate: v => (v !== null && v > 0 && v <= MAX_LAST_DAYS)
        ? null : "must be an integer between 1 and " + MAX_LAST_DAYS,
    },
  };

  const KIND_ORDER = Object.keys(FILTER_KINDS);
  const HUNT_ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
  const ID_RULE =
    "lowercase letters, digits and hyphens; starts with a letter or digit; 64 max";

  // An existing clause's value, back into the text the input shows.
  function clauseToRaw(f) {
    const spec = FILTER_KINDS[f && f.kind];
    if (!spec) return "";
    const v = f[spec.field];
    if (spec.type === "list") return (v || []).join("\n");
    return (v === null || v === undefined) ? "" : String(v);
  }

  // Clauses the builder has no row type for. Seeding one as a blank
  // default row would let Save drop it silently, so the editor refuses
  // to open on the hunt at all.
  function unsupportedKinds(hunt) {
    const out = [];
    for (const f of (hunt && hunt.filters) || []) {
      const k = f && f.kind;
      if (!FILTER_KINDS[k]) {
        out.push(k === null || k === undefined ? "(missing)" : String(k));
      }
    }
    return out;
  }

  function field(labelText, control, hintText) {
    const wrap = el("div", "h-field", [
      el("label", "h-field-label", labelText),
      control,
    ]);
    if (hintText) wrap.appendChild(el("span", "h-field-hint", hintText));
    return wrap;
  }

  /* Build the editor panel. `hunt` null => create mode.
   * `onClose()` removes the panel from wherever the caller mounted it.
   */
  function buildEditor(hunt, onClose) {
    const isEdit = !!hunt;
    const rows = [];                 // [{kind, raw, el, input, errEl}]
    const wrap = el("div", "h-editor");

    wrap.appendChild(el("div", "h-editor-title",
      isEdit ? `Edit hunt ${hunt.id}` : "New hunt"));
    if (isEdit) {
      // A full-document rewrite; `set_hunt_enabled`'s surgical path is
      // what preserves comments, and Save is not that path.
      wrap.appendChild(el("div", "h-warn",
        "Saving rewrites this hunt's YAML file — comments and block "
        + "descriptions in it are lost."));
    }

    const idInput = el("input", {
      class: "h-input", type: "text", spellcheck: "false",
      placeholder: "persistence-touched",
      value: isEdit ? hunt.id : "",
    });
    if (isEdit) idInput.disabled = true;
    wrap.appendChild(field("id", idInput,
      isEdit ? "ids cannot be renamed" : ID_RULE));

    const nameInput = el("input", {
      class: "h-input", type: "text",
      placeholder: "Persistence vectors touched",
      value: isEdit ? (hunt.name || "") : "",
    });
    wrap.appendChild(field("name", nameInput, null));

    const descInput = el("textarea", {
      class: "h-input h-textarea", rows: "2",
      placeholder: "What hypothesis does this hunt test?",
    });
    descInput.value = isEdit ? (hunt.description || "") : "";
    wrap.appendChild(field("description", descInput, "optional"));

    const filtersLabel = el("div", "h-field-label", "filters (all must match)");
    wrap.appendChild(filtersLabel);
    const filterList = el("div", "h-filter-list");
    wrap.appendChild(filterList);

    const addBtn = el("button", { class: "h-btn h-btn-quiet", type: "button" },
      ["+ filter"]);
    wrap.appendChild(el("div", "h-filter-add", [addBtn]));

    const errLine = el("div", "h-editor-err");
    const saveBtn = el("button", { class: "h-btn", type: "button" }, ["Save"]);
    const cancelBtn = el("button", { class: "h-btn h-btn-quiet", type: "button" },
      ["Cancel"]);
    const actions = el("div", "h-editor-actions", [saveBtn, cancelBtn]);
    if (isEdit) {
      const delBtn = el("button", { class: "h-btn h-btn-danger", type: "button" },
        ["Delete"]);
      delBtn.addEventListener("click", () => deleteHunt(hunt, delBtn, errLine));
      actions.appendChild(delBtn);
    }
    actions.appendChild(errLine);
    wrap.appendChild(actions);

    function addRow(kind, raw) {
      const state = { kind: kind || KIND_ORDER[0], raw: raw || "" };
      const select = el("select", "h-select");
      for (const k of KIND_ORDER) {
        const opt = el("option", { value: k }, [FILTER_KINDS[k].label]);
        if (k === state.kind) opt.selected = true;
        select.appendChild(opt);
      }
      // A list kind takes one value per line, so it needs a textarea; a
      // threshold takes a single token. Both are built up-front and
      // swapped in place when the kind changes.
      const textInput = el("input", { class: "h-input", type: "text" });
      const listInput = el("textarea", { class: "h-input h-values", rows: "3" });
      let input = FILTER_KINDS[state.kind].type === "list"
        ? listInput : textInput;
      input.value = state.raw;
      const errEl = el("span", "h-filter-err");
      const rm = el("button", { class: "h-btn h-btn-quiet h-btn-icon",
                                type: "button", title: "remove this filter" },
        ["×"]);
      const rowEl = el("div", "h-filter-row", [select, input, rm, errEl]);
      const row = { state: state, el: rowEl, input: input, errEl: errEl };

      function applySpec() {
        const spec = FILTER_KINDS[state.kind];
        const next = spec.type === "list" ? listInput : textInput;
        if (next !== input) {
          rowEl.replaceChild(next, input);
          input = next;
          row.input = next;
        }
        input.value = state.raw;
        input.setAttribute("placeholder", spec.placeholder);
        input.setAttribute("title", spec.hint);
      }
      select.addEventListener("change", () => {
        state.kind = select.value;
        // Kinds don't share a value shape; a stale list under a
        // threshold field would validate as garbage.
        state.raw = "";
        applySpec();
        revalidate();
      });
      const onInput = () => { state.raw = input.value; revalidate(); };
      textInput.addEventListener("input", onInput);
      listInput.addEventListener("input", onInput);
      rm.addEventListener("click", () => {
        const i = rows.indexOf(row);
        if (i >= 0) rows.splice(i, 1);
        rowEl.remove();
        revalidate();
      });
      applySpec();
      rows.push(row);
      filterList.appendChild(rowEl);
    }

    // Collect the clause list, writing per-row errors. Returns null when
    // anything is invalid.
    function collectFilters() {
      let bad = false;
      const out = [];
      for (const row of rows) {
        const spec = FILTER_KINDS[row.state.kind];
        const value = spec.parse(row.state.raw);
        const err = spec.validate(value);
        row.errEl.textContent = err || "";
        row.el.classList.toggle("bad", !!err);
        if (err) { bad = true; continue; }
        const clause = { kind: row.state.kind };
        clause[spec.field] = value;
        out.push(clause);
      }
      return bad ? null : out;
    }

    function revalidate() {
      const filters = collectFilters();
      let err = "";
      if (!isEdit && !HUNT_ID_RE.test(idInput.value.trim())) {
        err = "id: " + ID_RULE;
      } else if (!nameInput.value.trim()) {
        err = "name is required";
      } else if (!rows.length) {
        err = "a hunt needs at least one filter";
      } else if (filters === null) {
        err = "fix the highlighted filter";
      }
      errLine.textContent = err;
      saveBtn.disabled = !!err;
      return err ? null : filters;
    }

    async function save() {
      const filters = revalidate();
      if (filters === null) return;
      const gen = renderGeneration;
      const id = isEdit ? hunt.id : idInput.value.trim();
      const payload = {
        id: id,
        name: nameInput.value.trim(),
        description: descInput.value,
        filters: filters,
      };
      saveBtn.disabled = true;
      cancelBtn.disabled = true;
      errLine.textContent = "saving…";
      try {
        const resp = await fetch(
          isEdit ? `/api/hunts/${encodeURIComponent(id)}` : "/api/hunts",
          {
            method: isEdit ? "PUT" : "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          });
        if (!resp.ok) throw new Error(await errText(resp));
        if (gen !== renderGeneration) return;   // panel is gone; drop it
        onClose();
        document.getElementById("h-status").textContent =
          isEdit ? `${id} saved` : `${id} created (disabled)`;
        await loadHunts();
      } catch (e) {
        if (gen !== renderGeneration) return;
        errLine.textContent = "save failed: " + e.message;
        saveBtn.disabled = false;
        cancelBtn.disabled = false;
      }
    }

    saveBtn.addEventListener("click", save);
    cancelBtn.addEventListener("click", onClose);
    addBtn.addEventListener("click", () => { addRow(null, null); revalidate(); });

    const seed = (isEdit && hunt.filters && hunt.filters.length)
      ? hunt.filters : [null];
    for (const f of seed) {
      if (f && FILTER_KINDS[f.kind]) addRow(f.kind, clauseToRaw(f));
      else addRow(null, null);
    }
    idInput.addEventListener("input", revalidate);
    nameInput.addEventListener("input", revalidate);
    revalidate();
    return wrap;
  }

  // FastAPI hands errors back as {"detail": "..."}; fall back to the
  // status line when the body isn't that.
  async function errText(resp) {
    let msg = resp.status + " " + resp.statusText;
    try {
      const body = await resp.json();
      if (body && typeof body.detail === "string") msg = body.detail;
    } catch (e) { /* non-JSON body — keep the status line */ }
    return msg;
  }

  async function deleteHunt(h, btn, errLine) {
    // Findings outlive their hunt — say so before the click is spent.
    const ok = window.confirm(
      `Delete hunt "${h.id}"?\n\n`
      + "Its YAML file is removed and it stops writing new findings. "
      + "The analyst_hunt findings it already wrote stay in the inbox.");
    if (!ok) return;
    const gen = renderGeneration;
    btn.disabled = true;
    errLine.textContent = "deleting…";
    try {
      const resp = await fetch(`/api/hunts/${encodeURIComponent(h.id)}`,
        { method: "DELETE" });
      if (!resp.ok) throw new Error(await errText(resp));
      if (gen !== renderGeneration) return;
      document.getElementById("h-status").textContent = `${h.id} deleted`;
      await loadHunts();
    } catch (e) {
      if (gen !== renderGeneration) return;
      errLine.textContent = "delete failed: " + e.message;
      btn.disabled = false;
    }
  }

  // Columns of the preview table, in render order. Keys match the
  // `sessions[]` rows the preview endpoint returns.
  const PREVIEW_COLS = [
    ["session_id",      "session",   true],
    ["source_ip",       "source ip", true],
    ["first_seen",      "first seen", false],
    ["command_count",   "cmds",      false],
    ["dominant_intent", "intent",    false],
    ["playbook_name",   "playbook",  false],
  ];

  function shortTs(v) {
    // ES timestamps are long; the date + HH:MM is all the analyst needs
    // to orient a preview row.
    if (!v) return "—";
    return String(v).replace("T", " ").slice(0, 16);
  }

  function renderPreview(result) {
    const wrap = el("div", "h-preview");
    const head = el("div", "h-preview-head");
    // `total` is the true match count, not the page size — it's what the
    // hunt would write if enabled, which is the number that decides
    // whether to switch it on.
    head.appendChild(el("span", null,
      `${fmt(result.total)} matching session${result.total === 1 ? "" : "s"}`));
    if (result.truncated) {
      head.appendChild(el("span", "h-preview-note",
        `showing first ${fmt(result.shown)} — refine the filters to narrow`));
    }
    // Preview never writes; say so plainly so nobody assumes the inbox
    // just gained rows.
    head.appendChild(el("span", "h-preview-note", "nothing saved"));
    if (result.note) head.appendChild(el("span", "h-preview-note", result.note));
    wrap.appendChild(head);

    const rows = result.sessions || [];
    if (!rows.length) {
      wrap.appendChild(el("div", "h-preview-empty", "No sessions matched."));
      return wrap;
    }
    const table = el("table");
    const thead = el("thead");
    const trh = el("tr");
    for (const [, label] of PREVIEW_COLS) trh.appendChild(el("th", null, label));
    thead.appendChild(trh);
    table.appendChild(thead);
    const tbody = el("tbody");
    for (const r of rows) {
      const tr = el("tr");
      for (const [key, , mono] of PREVIEW_COLS) {
        let v = r[key];
        if (key === "first_seen") v = shortTs(v);
        else if (v === null || v === undefined || v === "") v = "—";
        tr.appendChild(el("td", mono ? "mono" : null, String(v)));
      }
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    wrap.appendChild(table);
    return wrap;
  }

  // Bumped on every full re-render. An in-flight preview whose card was
  // replaced underneath it must not write into a detached node.
  let renderGeneration = 0;

  // At most one builder panel is open at a time — two panels editing the
  // same directory is a race the analyst can't see.
  let openEditor = null;

  // "Run enabled hunts" ends in a full reload, which replaces every card
  // — and with it an in-progress draft and every keystroke in it. Take
  // the button away while a panel is open rather than eat the work.
  function setEditorOpen(panel) {
    openEditor = panel || null;
    const btn = document.getElementById("h-run-all");
    if (!btn) return;
    btn.disabled = !!openEditor;
    btn.title = openEditor
      ? "close the open hunt editor first — a run reloads the list"
      : "";
  }

  function closeEditor() {
    if (openEditor) {
      const close = openEditor.__close;
      setEditorOpen(null);
      if (close) close();
    }
  }

  function clearCardMessages(card) {
    card.querySelectorAll(".h-error, .h-preview").forEach(n => n.remove());
  }

  async function previewHunt(h, card, btn) {
    const prev = card.querySelector(".h-preview");
    // Second click collapses — the button is a toggle, not a re-run.
    // Clear stale errors too, or they pile up under the card forever.
    if (prev) { clearCardMessages(card); btn.textContent = "Preview"; return; }
    clearCardMessages(card);
    const gen = renderGeneration;
    btn.disabled = true;
    btn.textContent = "previewing…";
    try {
      const resp = await fetch(
        `/api/hunts/${encodeURIComponent(h.id)}/preview?limit=100`,
        { method: "POST" });
      if (!resp.ok) throw new Error(resp.status + " " + resp.statusText);
      const data = await resp.json();
      if (gen !== renderGeneration) return;   // card is gone; drop the result
      card.appendChild(renderPreview(data));
      btn.textContent = "Hide preview";
    } catch (e) {
      if (gen !== renderGeneration) return;
      card.appendChild(el("div", "h-error", "Preview failed: " + e.message));
      btn.textContent = "Preview";
    } finally {
      btn.disabled = false;
    }
  }

  async function toggleHunt(h, card, toggle) {
    // `pointer-events: none` stops the mouse but NOT a keydown on a
    // focused switch. Without this, two fast Space presses race two
    // writes against the same YAML file.
    if (toggle.classList.contains("busy")) return;
    const next = !h.enabled;
    // Optimistic flip so the switch feels immediate; reverted below if
    // the file write fails.
    toggle.classList.add("busy");
    applyEnabled(h, card, toggle, next);
    try {
      const resp = await fetch(`/api/hunts/${encodeURIComponent(h.id)}/toggle`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: next }),
      });
      if (!resp.ok) throw new Error(resp.status + " " + resp.statusText);
      const data = await resp.json();
      applyEnabled(h, card, toggle, !!data.enabled);
      document.getElementById("h-status").textContent =
        `${h.id} ${data.enabled ? "enabled" : "disabled"}`;
    } catch (e) {
      applyEnabled(h, card, toggle, !next);
      document.getElementById("h-status").textContent =
        "toggle failed: " + e.message;
    } finally {
      toggle.classList.remove("busy");
    }
  }

  function applyEnabled(h, card, toggle, enabled) {
    h.enabled = enabled;
    toggle.classList.toggle("on", enabled);
    toggle.setAttribute("aria-checked", enabled ? "true" : "false");
    toggle.querySelector(".h-toggle-label").textContent =
      enabled ? "writes findings" : "disabled";
    card.classList.toggle("off", !enabled);
  }

  function renderHunts(data) {
    const body = document.getElementById("hunts-body");
    const status = document.getElementById("h-status");
    const huntsDir = document.getElementById("hunts-dir");
    // Invalidate any preview still in flight against the old cards.
    renderGeneration++;
    setEditorOpen(null);        // detached with the cards below
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
        "No hunts configured. Use ",
        el("strong", null, ["New hunt"]),
        " above, or drop a YAML file into ",
        el("code", null, [data.hunts_dir || "config/hunts"]),
        " and refresh — see ",
        el("code", null, ["src/enrich/findings/hunts.py"]),
        " for the schema.",
      ]));
      status.textContent = "0 hunts loaded";
      return;
    }
    const on = hunts.filter(h => h.enabled).length;
    status.textContent =
      `${hunts.length} hunt${hunts.length === 1 ? "" : "s"} loaded · ` +
      `${on} enabled`;

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

      const toggle = el("span", {
        class: "h-toggle",
        role: "switch",
        tabindex: "0",
        title: "Controls whether this hunt writes analyst_hunt findings. "
             + "Preview works either way.",
      }, [el("span", "h-track"), el("span", "h-toggle-label", "")]);
      const flip = () => toggleHunt(h, card, toggle);
      toggle.addEventListener("click", flip);
      toggle.addEventListener("keydown", (ev) => {
        if (ev.key === " " || ev.key === "Enter") { ev.preventDefault(); flip(); }
      });
      actions.appendChild(toggle);

      const previewBtn = el("button", { class: "h-btn", type: "button" },
        ["Preview"]);
      previewBtn.addEventListener("click",
        () => previewHunt(h, card, previewBtn));
      actions.appendChild(previewBtn);

      // Edit opens the builder inline, on this hunt's own file.
      const editBtn = el("button", { class: "h-btn h-btn-quiet", type: "button" },
        ["Edit"]);
      editBtn.addEventListener("click", () => {
        if (card.querySelector(".h-editor")) return;
        // A clause the builder can't render would be dropped by the
        // Save that follows. Refuse the edit; the YAML stays intact.
        const bad = unsupportedKinds(h);
        if (bad.length) {
          clearCardMessages(card);
          card.appendChild(el("div", "h-error",
            "Cannot edit " + h.id + " here: unsupported filter kind "
            + bad.join(", ") + ". Edit its YAML file by hand."));
          return;
        }
        closeEditor();
        editBtn.disabled = true;
        const close = () => {
          if (openEditor === panel) setEditorOpen(null);
          panel.remove();
          editBtn.disabled = false;
        };
        const panel = buildEditor(h, close);
        panel.__close = close;
        setEditorOpen(panel);
        card.appendChild(panel);
      });
      actions.appendChild(editBtn);

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

      // Sets the toggle's visual state, label and the card's muting.
      applyEnabled(h, card, toggle, !!h.enabled);
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
    status.textContent = "running enabled hunts…";
    try {
      const resp = await fetch("/api/hunts/run", { method: "POST" });
      if (!resp.ok) throw new Error(resp.status + " " + resp.statusText);
      const data = await resp.json();
      const wrote = Object.values(data.written_by_hunt || {})
        .reduce((a, b) => a + b, 0);
      const skipped = (data.skipped || []).length;
      status.textContent =
        `${wrote} findings written/refreshed` +
        (skipped ? ` · ${skipped} disabled hunt${skipped === 1 ? "" : "s"} skipped` : "");
      // Reload counts.
      await loadHunts();
    } catch (e) {
      status.textContent = "run failed: " + e.message;
    } finally {
      btn.disabled = false;
    }
  }

  function newHunt() {
    const body = document.getElementById("hunts-body");
    // Second click on New closes the draft rather than stacking panels.
    if (openEditor && openEditor.classList.contains("h-editor-new")) {
      closeEditor();
      return;
    }
    closeEditor();
    const close = () => {
      if (openEditor === panel) setEditorOpen(null);
      panel.remove();
    };
    const panel = buildEditor(null, close);
    panel.__close = close;
    panel.classList.add("h-editor-new");
    setEditorOpen(panel);
    // Draft sits above the list; the new hunt lands at the top of the
    // page's attention, not at the bottom of a long directory.
    body.insertBefore(panel, body.firstChild);
  }

  document.addEventListener("DOMContentLoaded", () => {
    loadHunts();
    document.getElementById("h-run-all").addEventListener("click", runAll);
    document.getElementById("h-new").addEventListener("click", newHunt);
  });
})();
