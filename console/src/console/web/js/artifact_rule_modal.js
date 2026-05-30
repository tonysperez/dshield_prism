"use strict";

/* Artifact-rule create modal + highlight-to-create affordance (ROADMAP #5).
 *
 * The analyst selects text inside #detail-pane → a small floating "Create
 * artifact rule" button appears anchored to the selection. Click → modal
 * opens with `pattern` pre-populated; submit → POST /api/artifact-rule.
 *
 * Loaded after app.js so all detail-pane content is already on the page.
 * Self-contained — no cross-script globals beyond the DOM.
 */
(function () {
  const floater = document.getElementById("create-rule-floater");
  const modal = document.getElementById("artifact-rule-modal");
  if (!floater || !modal) return;

  const detailPane = document.getElementById("detail-pane");
  const $kind = document.getElementById("ar-kind");
  const $kindList = document.getElementById("ar-kind-options");
  const $matchType = document.getElementById("ar-match-type");
  const $pattern = document.getElementById("ar-pattern");
  const $caseSensitive = document.getElementById("ar-case-sensitive");
  const $notes = document.getElementById("ar-notes");
  const $status = document.getElementById("ar-status");
  const $submit = document.getElementById("ar-submit");
  const $cancel = document.getElementById("ar-cancel");
  const $close = document.getElementById("artifact-rule-close");

  function escapeHtml(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  // ---- Floater positioning ------------------------------------------------

  function selectionInsideDetailPane() {
    const sel = window.getSelection();
    if (!sel || sel.isCollapsed) return null;
    if (!detailPane) return null;
    // The selection must be anchored inside the detail pane — otherwise a
    // selection in the search bar / Ask-AI pane would trigger the floater.
    let node = sel.anchorNode;
    while (node) {
      if (node === detailPane) {
        const text = sel.toString().trim();
        return text ? { text, sel } : null;
      }
      node = node.parentNode;
    }
    return null;
  }

  function positionFloater(sel) {
    const range = sel.getRangeAt(0);
    const rect = range.getBoundingClientRect();
    if (!rect.width && !rect.height) return false;
    // Anchor below the selection; clamp into viewport.
    const fw = floater.offsetWidth || 160;
    const fh = floater.offsetHeight || 28;
    let x = rect.left + rect.width / 2 - fw / 2;
    let y = rect.bottom + 6;
    if (x < 4) x = 4;
    if (x + fw > window.innerWidth - 4) x = window.innerWidth - fw - 4;
    if (y + fh > window.innerHeight - 4) y = rect.top - fh - 6;
    floater.style.left = `${x}px`;
    floater.style.top = `${y}px`;
    return true;
  }

  function updateFloater() {
    const hit = selectionInsideDetailPane();
    if (!hit) { floater.classList.add("hidden"); return; }
    floater.classList.remove("hidden");
    if (!positionFloater(hit.sel)) floater.classList.add("hidden");
  }

  document.addEventListener("selectionchange", updateFloater);
  // selectionchange fires before layout — recompute on mouseup so positioning
  // sees the final selection rect.
  document.addEventListener("mouseup", () => setTimeout(updateFloater, 0));

  // ---- Modal open / close -------------------------------------------------

  let pendingPattern = "";

  async function openModal(pattern) {
    pendingPattern = pattern || "";
    $kind.value = "";
    // Default to substring — literal's whitespace-boundary discipline trips
    // long opaque blobs (pubkeys, base64 payloads, quoted strings) that are
    // exactly what analysts most often want to pin. Literal is still the
    // right choice for short tokens that risk over-matching as substrings;
    // analysts who need it flip the selector.
    $matchType.value = "substring";
    $pattern.value = pendingPattern;
    $caseSensitive.checked = false;
    $notes.value = "";
    $status.textContent = "";
    $status.className = "setting-status";
    $submit.disabled = false;
    modal.classList.remove("hidden");
    // Populate kind suggestions.
    try {
      const r = await fetch("/api/artifact-kinds");
      if (r.ok) {
        const data = await r.json();
        $kindList.innerHTML = "";
        for (const k of (data.kinds || [])) {
          const opt = document.createElement("option");
          opt.value = k.kind;
          opt.label = `${k.kind} (${k.count})`;
          $kindList.appendChild(opt);
        }
      }
    } catch (_) { /* ignore — suggestions are optional */ }
    setTimeout(() => $kind.focus(), 0);
  }

  function closeModal() {
    modal.classList.add("hidden");
  }

  floater.addEventListener("click", () => {
    const hit = selectionInsideDetailPane();
    openModal(hit ? hit.text : "");
    floater.classList.add("hidden");
  });

  $close.addEventListener("click", closeModal);
  $cancel.addEventListener("click", closeModal);
  modal.addEventListener("click", (e) => { if (e.target === modal) closeModal(); });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !modal.classList.contains("hidden")) closeModal();
  });

  // ---- Submit -------------------------------------------------------------

  $submit.addEventListener("click", async () => {
    const kind = $kind.value.trim();
    const pattern = $pattern.value;
    if (!kind || !pattern) {
      $status.textContent = "kind and pattern are required";
      $status.className = "setting-status error";
      return;
    }
    $submit.disabled = true;
    $status.textContent = "creating rule + running scan…";
    $status.className = "setting-status";
    try {
      const r = await fetch("/api/artifact-rule", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          kind, pattern,
          match_type: $matchType.value,
          case_sensitive: $caseSensitive.checked,
          notes: $notes.value || "",
        }),
      });
      if (!r.ok) {
        const text = await r.text();
        $status.textContent = `failed: ${text.slice(0, 200)}`;
        $status.className = "setting-status error";
        $submit.disabled = false;
        return;
      }
      const data = await r.json();
      if (data.scan_status === "complete") {
        const updated = ((data.scan_stats || {}).updated) || 0;
        const matched = ((data.scan_stats || {}).matched_docs) || 0;
        $status.textContent = `rule created — matched ${matched} command${matched === 1 ? "" : "s"}, stamped ${updated}`;
        $status.className = "setting-status success";
      } else if (data.scan_status === "failed") {
        $status.textContent = `rule created but scan failed: ${data.scan_error || "(no detail)"} — fix the issue and re-run \`apply-artifact-rules --rule-id ${data.rule.rule_id}\``;
        $status.className = "setting-status error";
      } else {
        $status.textContent = `rule created — scan queued (≈${data.affected_estimate} docs); runs on the next backward cycle`;
        $status.className = "setting-status success";
      }
      // Leave the modal open so the analyst sees the count, then auto-close
      // after a moment. Submit stays disabled to prevent double-creation.
      setTimeout(closeModal, 2500);
    } catch (exc) {
      $status.textContent = `error: ${exc.message || exc}`;
      $status.className = "setting-status error";
      $submit.disabled = false;
    }
  });
})();
