"use strict";

/* Tune page tab controller.
 *
 * Wires the `.tune-tab` strip to its `.tune-panel` bodies. Built to host
 * many tuning tabs; today there is one (Rules). Adding a tab is purely
 * declarative — a `<button class="tune-tab" data-tab="x">` plus a
 * `<div id="tab-x" class="tune-panel">` and its own panel-module script.
 * This controller picks it up with no change.
 */
(() => {
  function activate(name) {
    for (const btn of document.querySelectorAll("#tune-tabs .tune-tab")) {
      const on = btn.dataset.tab === name;
      btn.classList.toggle("active", on);
      btn.setAttribute("aria-selected", on ? "true" : "false");
    }
    for (const panel of document.querySelectorAll("#tune-body .tune-panel")) {
      panel.classList.toggle("active", panel.id === `tab-${name}`);
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    for (const btn of document.querySelectorAll("#tune-tabs .tune-tab")) {
      btn.addEventListener("click", () => activate(btn.dataset.tab));
    }
  });
})();
