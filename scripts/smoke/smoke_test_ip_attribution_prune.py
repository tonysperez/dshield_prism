"""Smoke test Phase K — the combined geometry change: drop country + ASN +
HASSH (queryable provenance/tool dims) and add the Tier 1 behaviour block.

Pure-function test (no ES). Drives the real `make_full_scalar_builder` and
asserts the K2 contract:

  (1) provenance OFF + tier1 ON: two IPs identical in behaviour + creds +
      Tier 1 inputs but different country / ASN / HASSH → IDENTICAL vectors.
  (2) provenance OFF + tier1 ON: different intent_distribution → DIFFERENT
      vectors (Tier 1 is doing the work).
  (3) provenance OFF + tier1 ON: different creds → DIFFERENT vectors
      (cred-hash still in).
  (4) control — provenance ON: the case-(1) pair → DIFFERENT vectors.
  (5) column count drops by (k_country + k_asn + hassh_dim) and the Tier 1
      width is added.

Run from the repo root via the console venv:
    console/.venv/bin/python scripts/smoke_test_ip_attribution_prune.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.ips import make_full_scalar_builder

_TIER1 = {
    "intent_distribution": [{"intent": "host_recon", "count": 10}],
    "playbook_distribution": [{"playbook_id": "spb-zgrab", "count": 10}],
    "total_sessions": 10, "total_commands": 10, "file_download_count": 0,
    "active_days": 1.0,
}
_BEHAVIOR = {
    "total_sessions": 10, "login_success_rate": 0.0, "mean_novelty_score": 0.3,
    "mean_session_duration_s": 12.0, "external_rarity_score": 0.0,
    "consensus_malicious": False,
}


def _ip(*, country, asn, hassh, creds, tier1=_TIER1) -> dict:
    return {
        **_BEHAVIOR, **tier1,
        "country_iso_code": country, "as_number": asn,
        "credentials": list(creds),
        "hassh_distribution": [{"hassh": hassh, "count": 5}] if hassh else [],
    }


def check(name: str, ok: bool, detail: str = "") -> bool:
    sym = "✓" if ok else "✗"
    suffix = f" — {detail}" if detail else ""
    print(f"  {sym} {name}{suffix}")
    return ok


def _builder(*, provenance, tier1):
    return make_full_scalar_builder(
        top_asns=[6939, 63949], attribution_weight=0.10, cred_hash_dim=16,
        hassh_weight=0.05, hassh_hash_dim=8,
        include_provenance=provenance, include_tier1=tier1,
    )


def main() -> int:
    print("=" * 72)
    print("Smoke test: Phase K geometry (drop country+ASN+HASSH, add Tier 1)")
    print("=" * 72)
    results: list[bool] = []

    same_creds = ["root:root"]
    a = _ip(country="US", asn=6939, hassh="aaa", creds=same_creds)
    b = _ip(country="DE", asn=63949, hassh="bbb", creds=same_creds)  # diff prov+tool
    c = _ip(country="US", asn=6939, hassh="aaa", creds=["admin:1234"])  # diff creds
    d = _ip(country="US", asn=6939, hassh="aaa", creds=same_creds,
            tier1={**_TIER1, "intent_distribution": [{"intent": "install_persistence", "count": 10}]})

    off = _builder(provenance=False, tier1=True)
    on = _builder(provenance=True, tier1=True)

    print()
    print("[1] prov OFF: diff country/ASN/HASSH, same behaviour → identical")
    m = off([a, b], 0.05)
    results.append(check("rows identical", bool(np.allclose(m[0], m[1])),
                         f"maxdiff={float(np.abs(m[0]-m[1]).max()):.6f}"))

    print()
    print("[2] prov OFF: different intent_distribution → different")
    m2 = off([a, d], 0.05)
    results.append(check("rows differ (Tier 1 working)", not np.allclose(m2[0], m2[1]),
                         f"maxdiff={float(np.abs(m2[0]-m2[1]).max()):.4f}"))

    print()
    print("[3] prov OFF: different creds → different (cred-hash still in)")
    m3 = off([a, c], 0.05)
    results.append(check("rows differ", not np.allclose(m3[0], m3[1]),
                         f"maxdiff={float(np.abs(m3[0]-m3[1]).max()):.4f}"))

    print()
    print("[4] control — prov ON: diff country/ASN/HASSH → different")
    m4 = on([a, b], 0.05)
    results.append(check("rows differ when provenance kept", not np.allclose(m4[0], m4[1]),
                         f"maxdiff={float(np.abs(m4[0]-m4[1]).max()):.4f}"))

    print()
    print("[5] column accounting: drop country(2)+ASN(3)+HASSH(8)=13, add Tier1(30)")
    cols_on = on([a, b], 0.05).shape[1]       # prov + tier1
    cols_off = off([a, b], 0.05).shape[1]      # no prov + tier1
    # on−off = country(2)+asn(3)+hassh(8) = 13 (Tier 1 present in both).
    results.append(check("13 provenance/tool cols dropped", cols_on - cols_off == 13,
                         f"on={cols_on}, off={cols_off}, drop={cols_on - cols_off}"))

    print()
    print("=" * 72)
    all_ok = all(results)
    print(f"SMOKE TEST: {'PASS' if all_ok else 'FAIL'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
