"""Smoke test for Phase I1 — direct-tcpip proxy abuse + command-outcome counters.

Exercises `_build_session_doc`'s new event handling end-to-end with synthetic
events shaped like the post-ingest raw docs. On a `direct-tcpip.request` event
Cowrie's `dst_ip`/`dst_port` (the proxy target) ride on
`destination.ip`/`destination.port` via the ingest pipeline's generic renames,
so that is what the rollup reads. Asserts:
  - proxy_attempts[] records {target_ip, target_port, ts} from request events
  - proxy_request_count / proxy_data_count carry true totals
  - command_failure_count / command_success_count always present
  - the proxy block is absent on sessions with no direct-tcpip activity
  - per-session proxy-attempt cap enforced (count still exceeds the capped list)

Standalone — no ES/LLM.

Run from the repo root via the console venv:
    console/.venv/bin/python scripts/smoke/smoke_test_proxy_command_outcome.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.sources.cowrie.sessions import (  # noqa: E402
    _MAX_PROXY_ATTEMPTS_PER_SESSION,
    _build_session_doc,
)

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


class _Cfg:
    class _Worker:
        command_max_chars = 4000
    class _Session:
        embed_version = "v1"
    worker = _Worker()
    session = _Session()


cfg = _Cfg()


def connect(ts="2026-05-30T00:00:00Z", ip="1.2.3.4"):
    return {"@timestamp": ts, "event": {"action": "cowrie.session.connect"},
            "source": {"ip": ip}}


def proxy_request(target_ip, target_port, ts):
    # Post-pipeline shape: dst_ip/dst_port already renamed to destination.*.
    return {"@timestamp": ts, "event": {"action": "cowrie.direct-tcpip.request"},
            "source": {"ip": "1.2.3.4"},
            "destination": {"ip": target_ip, "port": target_port}}


def proxy_data(target_ip, target_port, ts):
    return {"@timestamp": ts, "event": {"action": "cowrie.direct-tcpip.data"},
            "destination": {"ip": target_ip, "port": target_port},
            "cowrie": {"proxy": {"payload": "b'\\x16\\x03'", "channel_id": 0}}}


def cmd_input(line, ts):
    return {"@timestamp": ts, "event": {"action": "cowrie.command.input"},
            "process": {"command_line": line}}


def cmd_failed(line, ts):
    return {"@timestamp": ts, "event": {"action": "cowrie.command.failed",
            "outcome": "failure"}, "process": {"command_line": line}}


def cmd_success(line, ts):
    return {"@timestamp": ts, "event": {"action": "cowrie.command.success",
            "outcome": "success"}, "process": {"command_line": line}}


def sess(doc):
    return doc["dshield"]["cowrie"]["enrichment"]["session"]


# -----------------------------------------------------------------------------
print("[1] direct-tcpip request + data → proxy block")
events = [
    connect(),
    proxy_request("77.88.21.158", 25, "2026-05-30T00:00:01Z"),
    proxy_request("142.250.180.14", 443, "2026-05-30T00:00:02Z"),
    proxy_data("142.250.180.14", 443, "2026-05-30T00:00:03Z"),
]
s = sess(_build_session_doc("p1", events, {}, cfg))
check("proxy_request_count == 2", s.get("proxy_request_count") == 2, str(s.get("proxy_request_count")))
check("proxy_data_count == 1", s.get("proxy_data_count") == 1, str(s.get("proxy_data_count")))
pa = s.get("proxy_attempts") or []
check("two proxy_attempts recorded", len(pa) == 2, str(pa))
check("attempt carries target_ip/port/ts",
      pa[0].get("target_ip") == "77.88.21.158" and pa[0].get("target_port") == 25 and pa[0].get("ts"),
      str(pa[0]))

# -----------------------------------------------------------------------------
print("\n[2] command outcome counters")
events = [
    connect(),
    cmd_input("ls", "2026-05-30T00:00:01Z"),
    cmd_failed("sudo -l", "2026-05-30T00:00:02Z"),
    cmd_failed("dnf install", "2026-05-30T00:00:03Z"),
    cmd_success("whoami", "2026-05-30T00:00:04Z"),
]
s = sess(_build_session_doc("p2", events, {}, cfg))
check("command_failure_count == 2", s.get("command_failure_count") == 2, str(s.get("command_failure_count")))
check("command_success_count == 1", s.get("command_success_count") == 1, str(s.get("command_success_count")))
check("command.input still counted as a command", s.get("command_count") == 1, str(s.get("command_count")))

# -----------------------------------------------------------------------------
print("\n[3] no proxy activity → no proxy keys; outcome counters always present")
events = [connect(), cmd_input("uname -a", "2026-05-30T00:00:01Z")]
s = sess(_build_session_doc("p3", events, {}, cfg))
check("no proxy_request_count key", "proxy_request_count" not in s)
check("no proxy_attempts key", "proxy_attempts" not in s)
check("command_failure_count present and 0", s.get("command_failure_count") == 0, str(s))
check("command_success_count present and 0", s.get("command_success_count") == 0, str(s))

# -----------------------------------------------------------------------------
print("\n[4] proxy-attempt cap enforced; count still exceeds the capped list")
n = _MAX_PROXY_ATTEMPTS_PER_SESSION + 20
events = [connect()] + [
    proxy_request(f"10.0.0.{i % 256}", 1000 + i, f"2026-05-30T00:01:{i % 60:02d}Z")
    for i in range(n)
]
s = sess(_build_session_doc("p4", events, {}, cfg))
check("proxy_attempts capped", len(s.get("proxy_attempts") or []) == _MAX_PROXY_ATTEMPTS_PER_SESSION,
      str(len(s.get("proxy_attempts") or [])))
check("proxy_request_count carries true total", s.get("proxy_request_count") == n, str(s.get("proxy_request_count")))

# -----------------------------------------------------------------------------
print()
print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
