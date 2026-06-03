"""Smoke test the protocol-confusion credential filter (Phase K follow-up).

`_is_protocol_noise_credential` must drop HTTP/RTSP request lines + headers that
cowrie mis-captured as `user:password`, while keeping every genuine credential.

Run from the repo root via the console venv:
    console/.venv/bin/python scripts/smoke_test_credential_filter.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.sessions import _is_protocol_noise_credential


def check(name: str, ok: bool, detail: str = "") -> bool:
    sym = "✓" if ok else "✗"
    print(f"  {sym} {name}{f' — {detail}' if detail else ''}")
    return ok


# (credential string, should_be_filtered)
_CASES = [
    # --- protocol-confusion artifacts (must be FILTERED) ---
    ("GET / HTTP/1.1:Host: 71.33.158.205:23", True),
    ("OPTIONS rtsp://example.com RTSP/1.0:Cseq: 814", True),
    ("OPTIONS rtsp://example.com RTSP/1.0:Cseq: 8765", True),
    ("User-Agent: Mozilla/5.0 (Windows NT 10.0) Chrome/127.0.0.0:Accept-Encoding: gzip", True),
    ("POST /api HTTP/2:Content-Type: application/json", True),
    ("HEAD / HTTP/1.0:", True),
    ("\\x16\\x03\\x01://garbage", True),  # URL-scheme-ish TLS noise
    ("x:Sec-Fetch-Mode: navigate", True),
    # --- genuine credentials (must be KEPT) ---
    ("root:root", False),
    ("admin:admin", False),
    ("root:123456", False),
    (":", False),               # empty/empty
    ("user:", False),
    ("oracle:oracle123", False),
    ("ubnt:ubnt", False),
    ("*1:$4", False),           # short Redis-RESP-ish but constant, low-card — keep
    ("admin:P@ssw0rd:2024", False),   # password with colons but no protocol markers
    ("git:git", False),
]


def main() -> int:
    print("=" * 72)
    print("Smoke test: protocol-confusion credential filter")
    print("=" * 72)
    print()
    results = []
    for cred, want in _CASES:
        got = _is_protocol_noise_credential(cred)
        label = ("FILTER" if want else "KEEP  ") + f"  {cred[:60]}"
        results.append(check(label, got == want, "" if got == want else f"got filtered={got}"))
    print()
    print("=" * 72)
    ok = all(results)
    print(f"SMOKE TEST: {'PASS' if ok else 'FAIL'}  ({sum(results)}/{len(results)})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
