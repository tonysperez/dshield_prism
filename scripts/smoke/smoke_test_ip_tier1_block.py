"""Smoke test Phase K Tier 1 — the per-IP behaviour scalar block.

Pure-function test (no ES). Drives `_build_tier1_block` and asserts:

  (1) Two IPs with different intent distributions (100% recon vs 50/50
      recon/persistence across 3 playbooks) → DIFFERENT Tier 1 vectors.
  (2) Two IPs with identical Tier 1 inputs → IDENTICAL vectors (no noise
      sensitivity, deterministic).
  (3) The block width is the documented 30 dims and rows are finite/bounded.

Run from the repo root via the console venv:
    console/.venv/bin/python scripts/smoke_test_ip_tier1_block.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.ips import _build_tier1_block


def check(name: str, ok: bool, detail: str = "") -> bool:
    sym = "✓" if ok else "✗"
    suffix = f" — {detail}" if detail else ""
    print(f"  {sym} {name}{suffix}")
    return ok


def main() -> int:
    print("=" * 72)
    print("Smoke test: Phase K Tier 1 behaviour block")
    print("=" * 72)
    results: list[bool] = []

    ip_recon = {
        "intent_distribution": [{"intent": "reconnaissance", "count": 100}],
        "playbook_distribution": [{"playbook_id": "spb-zgrab", "count": 100}],
        "total_sessions": 100, "total_commands": 100,
        "file_download_count": 0, "active_days": 1.0,
    }
    ip_mixed = {
        "intent_distribution": [
            {"intent": "reconnaissance", "count": 25},
            {"intent": "persistence", "count": 25},
        ],
        "playbook_distribution": [
            {"playbook_id": "spb-a", "count": 20},
            {"playbook_id": "spb-b", "count": 20},
            {"playbook_id": "spb-c", "count": 10},
        ],
        "total_sessions": 50, "total_commands": 600,
        "file_download_count": 12, "active_days": 30.0,
    }

    print()
    print("[1] different intent/playbook profiles → different Tier 1 vectors")
    m = _build_tier1_block([ip_recon, ip_mixed], 0.05)
    results.append(check("rows differ", not np.allclose(m[0], m[1]),
                         f"maxdiff={float(np.abs(m[0] - m[1]).max()):.4f}"))

    print()
    print("[2] identical inputs → identical vectors (deterministic)")
    m2 = _build_tier1_block([ip_mixed, dict(ip_mixed)], 0.05)
    results.append(check("rows identical", bool(np.allclose(m2[0], m2[1])),
                         f"maxdiff={float(np.abs(m2[0] - m2[1]).max()):.6f}"))

    print()
    print("[3] block width = 30 dims; values finite and bounded")
    width_ok = m.shape[1] == 30
    bounded = bool(np.all(np.isfinite(m)) and m.max() <= 0.05 + 1e-6 and m.min() >= 0.0)
    results.append(check("width 30 and bounded [0, weight]", width_ok and bounded,
                         f"shape={m.shape}, max={float(m.max()):.4f}"))

    # Spot-check: recon IP has all intent mass in the reconnaissance cell.
    print()
    print("[4] intent cell semantics: recon IP is one-hot on reconnaissance")
    from enrich.sources.cowrie.ips import _TIER1_INTENT_ORDER
    recon_col = _TIER1_INTENT_ORDER.index("reconnaissance")
    row = _build_tier1_block([ip_recon], 0.05)[0]
    results.append(check(
        "reconnaissance cell carries full intent mass",
        abs(row[recon_col] - 0.05) < 1e-6,
        f"cell={row[recon_col]:.4f} (expected 0.05 = 1.0×weight)",
    ))

    print()
    print("=" * 72)
    all_ok = all(results)
    print(f"SMOKE TEST: {'PASS' if all_ok else 'FAIL'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
