"""Smoke test Phase K Tier 2 — the IP-as-bag-of-session-clusters block.

Pure-function test (no ES). Drives `_build_tier2_block` with synthetic per-IP
session-cluster bags and asserts:

  (1) IPs with different session-cluster bags → different Tier 2 vectors.
  (2) IPs with identical bags → identical vectors (deterministic SVD seed).
  (3) Empty bags / no signal → (n, 0) no-op block (geometry unchanged).
  (4) Rows are L2-normalised before the weight scale (||row|| ≈ weight).

Run from the repo root via the console venv:
    console/.venv/bin/python scripts/smoke_test_ip_tier2_block.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.ips import _build_tier2_block


def check(name: str, ok: bool, detail: str = "") -> bool:
    sym = "✓" if ok else "✗"
    print(f"  {sym} {name}{f' — {detail}' if detail else ''}")
    return ok


def main() -> int:
    print("=" * 72)
    print("Smoke test: Phase K Tier 2 (bag-of-session-clusters)")
    print("=" * 72)
    results: list[bool] = []

    # 6 IPs: two recon-heavy (cluster_18), two persistence-heavy (cluster_50),
    # two mixed — enough vocabulary + rows for a ≥2-component SVD.
    scalars = [
        {"source_ip": "a"}, {"source_ip": "b"}, {"source_ip": "c"},
        {"source_ip": "d"}, {"source_ip": "e"}, {"source_ip": "f"},
    ]
    bags = {
        "a": {"cluster_18": 5}, "b": {"cluster_18": 4, "cluster_19": 1},
        "c": {"cluster_50": 5}, "d": {"cluster_50": 4, "cluster_51": 1},
        "e": {"cluster_18": 2, "cluster_50": 3}, "f": {"cluster_36": 5},
    }

    print()
    print("[1] different bags → different vectors")
    m = _build_tier2_block(scalars, 0.10, bags=bags, dim=24)
    recon_vs_persist = not np.allclose(m[0], m[2])
    results.append(check("recon-IP vs persistence-IP differ", recon_vs_persist and m.shape[1] >= 2,
                         f"shape={m.shape}, maxdiff={float(np.abs(m[0]-m[2]).max()):.4f}"))

    print()
    print("[2] identical bags → identical vectors (deterministic)")
    bags2 = dict(bags); bags2["g"] = dict(bags["a"])
    s2 = scalars + [{"source_ip": "g"}]
    m2 = _build_tier2_block(s2, 0.10, bags=bags2, dim=24)
    results.append(check("IP a and its clone g match",
                         bool(np.allclose(m2[0], m2[-1])),
                         f"maxdiff={float(np.abs(m2[0]-m2[-1]).max()):.6f}"))

    print()
    print("[3] empty bags → (n, 0) no-op block")
    m3 = _build_tier2_block(scalars, 0.10, bags={}, dim=24)
    results.append(check("no bags → zero-width block", m3.shape == (6, 0), f"shape={m3.shape}"))

    print()
    print("[4] rows L2-normalised then weight-scaled (||row|| ≈ weight)")
    norms = np.linalg.norm(m, axis=1)
    results.append(check("row norms ≈ 0.10", bool(np.allclose(norms[norms > 0], 0.10, atol=1e-4)),
                         f"min={norms.min():.4f} max={norms.max():.4f}"))

    print()
    print("=" * 72)
    all_ok = all(results)
    print(f"SMOKE TEST: {'PASS' if all_ok else 'FAIL'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
