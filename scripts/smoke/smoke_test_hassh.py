#!/usr/bin/env python3
"""Smoke test: HASSH attribution scaffolding (offline).

Covers the two pure pieces of the HASSH feature without a live ES:
  - `_compute_hassh` (sessions.py) — the md5 fallback reproduces cowrie's own
    `hassh` for a real captured algorithm string.
  - `_build_hassh_block` (ips.py) — the IP-clustering sub-block: shape, weight,
    L1-normalisation, that same-HASSH IPs land identical and differ from a
    third, and that empty/zero-dim inputs are no-ops.

Run: ./console/.venv/bin/python scripts/smoke_test_hassh.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import numpy as np

from enrich.sources.cowrie.ips import (
    _build_hassh_block,
    _hash_credential_bin,
)
from enrich.sources.cowrie.sessions import _compute_hassh

# A real cowrie-captured client algorithm string + the `hassh` md5 cowrie
# emitted for it (verified against the live corpus). Proves _compute_hassh
# reproduces cowrie's own value, not just a self-consistent hash.
_REAL_ALGOS = (
    "diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,"
    "diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,"
    "diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,"
    "diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp256,"
    "ecdh-sha2-nistp384,ecdh-sha2-nistp521,curve25519-sha256,"
    "curve25519-sha256@libssh.org,ext-info-c;des,3des,blowfish,none,3des-cbc,"
    "blowfish-cbc,cast128-cbc,arcfour,arcfour128,arcfour256,aes128-cbc,"
    "aes192-cbc,aes256-cbc,rijndael-cbc@lysator.liu.se,aes128-ctr,aes192-ctr,"
    "aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,"
    "chacha20-poly1305@openssh.com;hmac-sha1,hmac-sha1-96,hmac-sha2-256,"
    "hmac-sha2-512,hmac-md5,hmac-md5-96,hmac-ripemd160,"
    "hmac-ripemd160@openssh.com,umac-64@openssh.com,umac-128@openssh.com,"
    "hmac-sha1-etm@openssh.com,hmac-sha1-96-etm@openssh.com,"
    "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
    "hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,"
    "hmac-ripemd160-etm@openssh.com,umac-64-etm@openssh.com,"
    "umac-128-etm@openssh.com;none,zlib@openssh.com,zlib"
)
_REAL_HASSH = "acaa53e0a7d7ac7d1255103f37901306"


def _dist(hassh: str, count: int) -> list[dict]:
    return [{"hassh": hassh, "count": count}]


def main() -> int:
    failures: list[str] = []

    def check(name: str, got, want) -> None:
        ok = got == want
        if not ok:
            failures.append(f"{name}: got {got!r}, want {want!r}")
        print(f"  {'ok ' if ok else 'FAIL'} {name}")

    # 1. _compute_hassh reproduces cowrie's md5.
    check("compute_hassh matches cowrie", _compute_hassh(_REAL_ALGOS), _REAL_HASSH)
    check("compute_hassh is md5", _compute_hassh("a;b;c;d"),
          hashlib.md5(b"a;b;c;d", usedforsecurity=False).hexdigest())

    W, K = 0.05, 8
    # Two fake HASSH md5s chosen to land in DIFFERENT bins under K (feature
    # hashing can legitimately collide; pick a non-colliding pair so the
    # "different fingerprints differ" check isn't testing a collision).
    HA = "a" * 32
    HB = next(
        c * 32 for c in "bcdefghij"
        if _hash_credential_bin(c * 32, K) != _hash_credential_bin(HA, K)
    )

    # 2. Shape + weight: one IP, one fingerprint → single bin == weight, rest 0.
    block = _build_hassh_block([{"hassh_distribution": _dist(HA, 3)}], W, K)
    check("shape (1,K)", block.shape, (1, K))
    check("single fingerprint sums to weight", round(float(block.sum()), 6), round(W, 6))
    check("single hot bin", int((block > 0).sum()), 1)

    # 3. Same HASSH → identical rows; different HASSH → different row.
    rows = _build_hassh_block(
        [
            {"hassh_distribution": _dist(HA, 1)},
            {"hassh_distribution": _dist(HA, 9)},   # count differs, bin same
            {"hassh_distribution": _dist(HB, 1)},
        ], W, K,
    )
    check("same HASSH rows identical", np.allclose(rows[0], rows[1]), True)
    check("different HASSH rows differ", bool(np.allclose(rows[0], rows[2])), False)

    # 4. Empty distribution → zero row (no-op for IPs with no SSH fingerprint).
    z = _build_hassh_block([{"hassh_distribution": []}, {}], W, K)
    check("empty dist → zero rows", float(np.abs(z).sum()), 0.0)

    # 5. hassh_hash_dim=0 disables the block (zero-width).
    check("dim=0 → (n,0)", _build_hassh_block([{"hassh_distribution": _dist(HA, 1)}], W, 0).shape, (1, 0))

    print()
    if failures:
        print(f"FAILED ({len(failures)}):")
        for f in failures:
            print("  -", f)
        return 1
    print("All HASSH smoke checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
