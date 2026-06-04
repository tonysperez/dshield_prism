"""Smoke test for ROADMAP #16: per-session credential aggregation.

Before the fix, the session rollup only kept the first-seen (user,
password) pair (via top-level `cowrie.password` / `user.name`). A
credential-spray bot trying 50 different combos in one session
contributed only one tuple to its IP's credentials set — the cred-hash
feature in #8 was silently under-counting the most attribution-rich
attackers (opposite of the intended failure mode).

The fix:
 1. `_record_credential(set, event)` extracts the (user, password) tuple
    from a login event and adds it to the session's set.
 2. `_build_session_doc` now collects every tuple from
    `cowrie.login.success` / `cowrie.login.failed` events into a new
    `session.credentials` keyword-array on the rollup, capped + sorted.
 3. The IP rollup unions session.credentials when present, falling back
    to the legacy first-seen tuple for pre-#16 docs whose backward pass
    hasn't recomputed them.

Standalone — no ES, no pytest. Pure-function tests of the helper plus
an end-to-end exercise of `_build_session_doc` with a synthetic event
stream.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_session_credentials.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.sessions import (
    _MAX_CREDENTIALS_PER_SESSION,
    _build_session_doc,
    _record_credential,
)


PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


def login_event(action: str, user: str = "", password: str = "") -> dict:
    """Build a minimal login event for the rollup function."""
    return {
        "@timestamp": "2026-05-16T00:00:00Z",
        "event": {"action": action},
        "user": {"name": user} if user else {},
        "cowrie": {"password": password} if password else {},
    }


# -----------------------------------------------------------------------------
# [1] _record_credential — basic shapes.
# -----------------------------------------------------------------------------
print("\n[1] _record_credential")
s: set[str] = set()
_record_credential(s, login_event("cowrie.login.failed", "root", "admin"))
check("root:admin captured", s == {"root:admin"}, f"got {s}")

_record_credential(s, login_event("cowrie.login.failed", "root", "admin"))
check("duplicate is deduped", s == {"root:admin"}, f"got {s}")

_record_credential(s, login_event("cowrie.login.failed", "admin", ""))
check("empty password still recorded (user-only spray fingerprint)",
      "admin:" in s, f"got {s}")

_record_credential(s, login_event("cowrie.login.failed", "", "p4ssword"))
check("empty user still recorded (password-only spray fingerprint)",
      ":p4ssword" in s, f"got {s}")

s2: set[str] = set()
_record_credential(s2, login_event("cowrie.login.failed", "", ""))
check("entirely empty event contributes nothing", s2 == set(), f"got {s2}")


# -----------------------------------------------------------------------------
# [2] _build_session_doc — credential-spray captures every pair.
# -----------------------------------------------------------------------------
print("\n[2] _build_session_doc captures every login tuple")
class _Cfg:  # minimal duck-typed config — only worker.command_max_chars and
    # session.embed_version are accessed in the rollup path.
    class _Worker:
        command_max_chars = 4000
    class _Session:
        embed_version = "v1"
    worker = _Worker()
    session = _Session()

cfg = _Cfg()

# 50 distinct (user, password) attempts in one session — the canonical
# credential-spray case the old code under-counted.
events = []
for i in range(50):
    events.append(login_event("cowrie.login.failed", f"user{i}", f"pass{i}"))
events.append({
    "@timestamp": "2026-05-16T00:00:01Z",
    "event": {"action": "cowrie.session.connect"},
    "source": {"ip": "1.2.3.4"},
})

doc = _build_session_doc("sess-spray", events, {}, cfg)
creds = doc["dshield"]["cowrie"]["enrichment"]["session"].get("credentials") or []
check(
    "50 distinct pairs all captured (was 1 in the buggy version)",
    len(creds) == 50,
    f"got {len(creds)} credentials",
)
check(
    "credentials list is sorted (deterministic for re-runs)",
    creds == sorted(creds),
    "list not sorted",
)
# Every entry is a "user:pass" string.
check(
    "every entry has the user:pass shape",
    all(":" in c for c in creds),
    f"bad entries: {[c for c in creds if ':' not in c][:3]}",
)


# -----------------------------------------------------------------------------
# [3] login.success AND login.failed are both captured.
# -----------------------------------------------------------------------------
print("\n[3] both success and failed login events contribute")
events = [
    login_event("cowrie.login.success", "root", "toor"),
    login_event("cowrie.login.failed", "admin", "12345"),
    login_event("cowrie.login.failed", "guest", "guest"),
    {"@timestamp": "2026-05-16T00:00:01Z", "event": {"action": "cowrie.session.closed"}},
]
doc = _build_session_doc("sess-mixed", events, {}, cfg)
creds = doc["dshield"]["cowrie"]["enrichment"]["session"]["credentials"]
check(
    "success + failed both captured (sorted)",
    creds == ["admin:12345", "guest:guest", "root:toor"],
    f"got {creds}",
)


# -----------------------------------------------------------------------------
# [4] No login events → no credentials field (don't write empty arrays).
# -----------------------------------------------------------------------------
print("\n[4] sessions without login events don't emit credentials")
events = [
    {"@timestamp": "2026-05-16T00:00:00Z", "event": {"action": "cowrie.session.connect"}},
    {"@timestamp": "2026-05-16T00:00:01Z", "event": {"action": "cowrie.command.input"},
     "process": {"command_line": "ls"}},
    {"@timestamp": "2026-05-16T00:00:02Z", "event": {"action": "cowrie.session.closed"}},
]
doc = _build_session_doc("sess-no-login", events, {}, cfg)
block = doc["dshield"]["cowrie"]["enrichment"]["session"]
check(
    "no login events → 'credentials' key absent",
    "credentials" not in block,
    f"got block keys: {sorted(block.keys())}",
)


# -----------------------------------------------------------------------------
# [5] Cap protects against pathological sessions.
# -----------------------------------------------------------------------------
print(f"\n[5] credentials list capped at {_MAX_CREDENTIALS_PER_SESSION}")
events = []
for i in range(_MAX_CREDENTIALS_PER_SESSION + 50):
    events.append(login_event("cowrie.login.failed", f"u{i:04d}", f"p{i:04d}"))
events.append({"@timestamp": "2026-05-16T00:00:00Z", "event": {"action": "cowrie.session.connect"}})

doc = _build_session_doc("sess-huge", events, {}, cfg)
creds = doc["dshield"]["cowrie"]["enrichment"]["session"]["credentials"]
check(
    f"capped at {_MAX_CREDENTIALS_PER_SESSION}",
    len(creds) == _MAX_CREDENTIALS_PER_SESSION,
    f"got {len(creds)}",
)


# -----------------------------------------------------------------------------
# [6] Duplicate attempts within a session collapse to one entry.
# -----------------------------------------------------------------------------
print("\n[6] duplicate (user, password) attempts dedupe")
events = [
    login_event("cowrie.login.failed", "root", "x"),
    login_event("cowrie.login.failed", "root", "x"),
    login_event("cowrie.login.failed", "root", "x"),
    login_event("cowrie.login.failed", "root", "y"),
]
doc = _build_session_doc("sess-dup", events, {}, cfg)
creds = doc["dshield"]["cowrie"]["enrichment"]["session"]["credentials"]
check(
    "three (root,x) + one (root,y) → 2 unique entries",
    creds == ["root:x", "root:y"],
    f"got {creds}",
)


# -----------------------------------------------------------------------------
# [7] _source filter on the IP-rollup iterator now requests `credentials`.
# Regression guard: a future refactor that drops this from the projection
# would silently revert the fix — the IP rollup would always read [] and
# fall back to the legacy first-seen path even on fresh sessions.
# -----------------------------------------------------------------------------
print("\n[7] IP rollup iterator requests the new credentials field")
import inspect
from enrich.sources.cowrie import ips as ips_mod
src = inspect.getsource(ips_mod)
check(
    "ips.py _source projection includes session.credentials",
    "dshield.cowrie.enrichment.session.credentials" in src,
    "field missing from ips.py — projection or rollup would lose data",
)


# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
