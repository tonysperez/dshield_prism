"""G2 Arm C — deterministic behavioural session fingerprint.

Builds a fixed-dim (76) feature vector per session from existing rollup
fields only — no LLM, no embeddings. Tests the dp-009 hypothesis: that
real behavioural distinctions live in out-of-stream signal (file events,
HASSH, login pattern, credentials, host/network context) that the command
stream cannot carry.

Layout (all blocks concatenated, then the whole vector L2-normalized):

  * file event signature   (32) — signed feature-hash of each file_events
                                  entry (sparse; non-zero only on sessions
                                  that touched files).
  * HASSH                  (8)  — signed feature-hash of cowrie.hassh
                                  (modal SSH client fingerprint).
  * login pattern          (4)  — [success, fail, unique_creds, success_rate],
                                  log1p-normalized with fixed denominators.
  * credential signature   (8)  — signed feature-hash of the session's
                                  top user:password tuples.
  * counts + shape         (8)  — command_count, unique_commands,
                                  command_entropy, file_dl, file_ul,
                                  login_to_command_ratio, total_logins,
                                  unique_ratio — log1p / clip normalized.
                                  (duration-derived dims dropped — duration
                                  is not on the rollup.)
  * geo / ASN coarse       (16) — signed feature-hash of country_iso_code +
                                  AS organization name.

Determinism: feature hashing uses blake2b (not Python's salted ``hash``),
so identical inputs yield byte-identical output across processes/runs.
"""
from __future__ import annotations

import hashlib
import math

try:
    import numpy as np
except ImportError:  # pragma: no cover - mirrors clustering.py's guard
    np = None  # type: ignore[assignment]

_FILE_DIM = 32
_HASSH_DIM = 8
_LOGIN_DIM = 4
_CRED_DIM = 8
_SHAPE_DIM = 8
_GEO_DIM = 16
FINGERPRINT_DIM = _FILE_DIM + _HASSH_DIM + _LOGIN_DIM + _CRED_DIM + _SHAPE_DIM + _GEO_DIM  # 76

# Fixed corpus-scale denominators for log1p normalization (ROADMAP #14 pattern)
# — a given session yields identical contributions regardless of batch.
_D_LOGIN = 100.0
_D_UCRED = 50.0
_D_CMD = 100.0
_D_UCMD = 50.0
_D_FILE = 10.0
_D_TOTLOGIN = 200.0
_D_ENTROPY = 8.0


def _h64(token: str, salt: str) -> int:
    return int.from_bytes(
        hashlib.blake2b((salt + "\0" + token).encode("utf-8"), digest_size=8).digest(),
        "big",
    )


def _feature_hash(tokens, dim: int, salt: str):
    """Signed feature-hashing trick: each token bumps one bucket by ±1."""
    v = np.zeros(dim, dtype=np.float32)
    for t in tokens:
        if not t:
            continue
        hh = _h64(str(t), salt)
        v[hh % dim] += 1.0 if ((hh >> 40) & 1) else -1.0
    return v


def _log1p_norm(x, denom: float) -> float:
    return min(math.log1p(max(float(x or 0.0), 0.0)) / math.log1p(denom), 1.0)


def _file_event_tokens(file_events) -> list[str]:
    """Stable token per file event — the sorted key/value items, so the
    same event always hashes the same regardless of dict ordering."""
    toks = []
    for ev in file_events or []:
        if isinstance(ev, dict):
            toks.append("|".join(f"{k}={ev[k]}" for k in sorted(ev)))
        else:
            toks.append(str(ev))
    return toks


def build_fingerprint(source: dict):
    """76-dim L2-normalized deterministic fingerprint from a session rollup
    ``_source`` dict. Missing fields contribute zero."""
    s = (((source.get("dshield") or {}).get("cowrie") or {})
         .get("enrichment", {}).get("session", {}))
    cowrie = source.get("cowrie") or {}
    src_meta = source.get("source") or {}

    # blocks
    file_block = _feature_hash(_file_event_tokens(s.get("file_events")), _FILE_DIM, "fe")
    hassh = cowrie.get("hassh") or ""
    hassh_block = _feature_hash([hassh], _HASSH_DIM, "hassh")

    succ = s.get("login_success_count") or 0
    fail = s.get("login_fail_count") or 0
    total = succ + fail
    creds = [c for c in (s.get("credentials") or []) if c]
    ucred = len(set(creds))
    login_block = np.array([
        _log1p_norm(succ, _D_LOGIN), _log1p_norm(fail, _D_LOGIN),
        _log1p_norm(ucred, _D_UCRED), (succ / total) if total else 0.0,
    ], dtype=np.float32)

    cred_block = _feature_hash(sorted(set(creds))[:5], _CRED_DIM, "cred")

    ccount = s.get("command_count") or 0
    ucmd = s.get("unique_commands") or 0
    shape_block = np.array([
        _log1p_norm(ccount, _D_CMD),
        _log1p_norm(ucmd, _D_UCMD),
        min(abs(float(s.get("command_entropy") or 0.0)) / _D_ENTROPY, 1.0),
        _log1p_norm(s.get("file_download_count") or 0, _D_FILE),
        _log1p_norm(s.get("file_upload_count") or 0, _D_FILE),
        min(total / ccount, 1.0) if ccount else (1.0 if total else 0.0),
        _log1p_norm(total, _D_TOTLOGIN),
        min(ucmd / ccount, 1.0) if ccount else 0.0,
    ], dtype=np.float32)

    geo = (src_meta.get("geo") or {}).get("country_iso_code") or ""
    org = (src_meta.get("as") or {}).get("organization")
    org = org.get("name") if isinstance(org, dict) else (org or "")
    geo_block = _feature_hash([f"cc:{geo}", f"as:{org}"], _GEO_DIM, "geo")

    vec = np.concatenate([
        file_block, hassh_block, login_block, cred_block, shape_block, geo_block,
    ]).astype(np.float32)
    n = float(np.linalg.norm(vec))
    return vec / n if n > 0 else vec


def build_fingerprints(sources: list[dict]):
    """(n, 76) fingerprint matrix for a list of rollup ``_source`` dicts."""
    if not sources:
        return np.zeros((0, FINGERPRINT_DIM), dtype=np.float32)
    return np.vstack([build_fingerprint(s) for s in sources]).astype(np.float32)
