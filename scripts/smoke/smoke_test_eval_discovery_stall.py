"""Offline contract tests for scripts/eval_discovery_stall.py."""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

import eval_discovery_stall as target
import eval_novel_pool
from eval_jsonl import iter_jsonl

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name} ({detail})")


def make_report(*, generated_at="2026-08-01T00:00:00+00:00", n_sessions=100,
                 n_anchors=5, novel_rate=0.05, playbook_groups=3, deployed=True):
    row = {
        "deployed": deployed,
        "novel_rate": novel_rate,
        "novel_pool_shape": {"playbook_groups": playbook_groups},
    }
    return {
        "generated_at": generated_at,
        "n_sessions": n_sessions,
        "n_anchors": n_anchors,
        "rows": [row],
    }


def snapshot(*, n_sessions, n_anchors, playbook_groups=3, novel_rate=0.05,
             generated_at="2026-08-01T00:00:00+00:00"):
    return {
        "generated_at": generated_at,
        "n_sessions": n_sessions,
        "n_anchors": n_anchors,
        "novel_rate": novel_rate,
        "playbook_groups": playbook_groups,
    }


# --- extract_snapshot ------------------------------------------------------

happy = target.extract_snapshot(make_report())
check(
    "extract_snapshot happy path returns exactly 5 scalar fields",
    happy == {
        "generated_at": "2026-08-01T00:00:00+00:00",
        "n_sessions": 100,
        "n_anchors": 5,
        "novel_rate": 0.05,
        "playbook_groups": 3,
    },
    str(happy),
)

for label, report in [
    ("missing rows", {"generated_at": "x", "n_sessions": 1, "n_anchors": 1}),
    ("empty rows", {**make_report(), "rows": []}),
]:
    try:
        target.extract_snapshot(report)
        check(f"extract_snapshot rejects {label}", False, "no exception")
    except ValueError:
        check(f"extract_snapshot rejects {label}", True)

zero_deployed = make_report(deployed=False)
try:
    target.extract_snapshot(zero_deployed)
    check("extract_snapshot rejects zero deployed rows", False, "no exception")
except ValueError as exc:
    check("extract_snapshot rejects zero deployed rows", "deployed" in str(exc), str(exc))

two_deployed = make_report()
two_deployed["rows"].append(dict(two_deployed["rows"][0]))
try:
    target.extract_snapshot(two_deployed)
    check("extract_snapshot rejects two deployed rows", False, "no exception")
except ValueError as exc:
    check("extract_snapshot rejects two deployed rows", "deployed" in str(exc), str(exc))

for missing_field in ("generated_at", "n_sessions", "n_anchors"):
    bad = make_report()
    del bad[missing_field]
    try:
        target.extract_snapshot(bad)
        check(f"extract_snapshot rejects missing report field {missing_field}", False, "no exception")
    except ValueError:
        check(f"extract_snapshot rejects missing report field {missing_field}", True)

for missing_field in ("novel_rate",):
    bad = make_report()
    del bad["rows"][0][missing_field]
    try:
        target.extract_snapshot(bad)
        check(f"extract_snapshot rejects missing row field {missing_field}", False, "no exception")
    except ValueError:
        check(f"extract_snapshot rejects missing row field {missing_field}", True)

bad_shape = make_report()
del bad_shape["rows"][0]["novel_pool_shape"]["playbook_groups"]
try:
    target.extract_snapshot(bad_shape)
    check("extract_snapshot rejects missing playbook_groups", False, "no exception")
except ValueError:
    check("extract_snapshot rejects missing playbook_groups", True)


# --- evaluate_history --------------------------------------------------------

current = snapshot(n_sessions=200, n_anchors=5, playbook_groups=2)

check(
    "no history path -> insufficient_history",
    target.evaluate_history(current, None, stall_window=4) == target.STATUS_INSUFFICIENT_HISTORY,
)

with tempfile.TemporaryDirectory() as tmp:
    empty_history = Path(tmp) / "history.jsonl"
    check(
        "nonexistent history file -> insufficient_history",
        target.evaluate_history(current, empty_history, stall_window=4)
        == target.STATUS_INSUFFICIENT_HISTORY,
    )

    one_prior = Path(tmp) / "one.jsonl"
    one_prior.write_text(json.dumps(snapshot(n_sessions=50, n_anchors=5)) + "\n")
    check(
        "exactly one prior entry -> insufficient_history",
        target.evaluate_history(current, one_prior, stall_window=4)
        == target.STATUS_INSUFFICIENT_HISTORY,
    )

    stalled_history = Path(tmp) / "stalled.jsonl"
    with open(stalled_history, "w") as fh:
        fh.writelines(json.dumps(snapshot(n_sessions=n_sessions, n_anchors=5, playbook_groups=2)) + "\n" for n_sessions in (50, 80))
    stalled_status = target.evaluate_history(current, stalled_history, stall_window=4)
    check(
        "2+ prior inside the stall pattern -> anchor_growth_stalled",
        stalled_status == target.STATUS_ANCHOR_GROWTH_STALLED,
        stalled_status,
    )

    growing_history = Path(tmp) / "growing.jsonl"
    with open(growing_history, "w") as fh:
        fh.writelines(json.dumps(snapshot(n_sessions=n_sessions, n_anchors=n_anchors)) + "\n" for n_sessions, n_anchors in ((50, 1), (80, 3)))
    growing_current = snapshot(n_sessions=200, n_anchors=6, playbook_groups=5)
    growing_status = target.evaluate_history(growing_current, growing_history, stall_window=4)
    check(
        "2+ prior with n_anchors growing -> ok",
        growing_status == target.STATUS_OK,
        growing_status,
    )

    # Trailing-window re-arm: anchors grow early (weeks 1-3), then flatten for
    # weeks 3-6. With 6 prior entries and stall_window=4, the window is the
    # last 4 prior entries (weeks 3-6), so the baseline is week 3's entry
    # (n_anchors=6, index 2) -- NOT the all-time-first entry (week 1,
    # n_anchors=1), which would show growth (6 > 1) -> "ok" and miss the stall.
    rearm_history = Path(tmp) / "rearm.jsonl"
    rearm_rows = [
        snapshot(n_sessions=10, n_anchors=1, playbook_groups=1),   # week 1
        snapshot(n_sessions=20, n_anchors=3, playbook_groups=1),   # week 2
        snapshot(n_sessions=30, n_anchors=6, playbook_groups=2),   # week 3 (growth ends; window baseline)
        snapshot(n_sessions=40, n_anchors=6, playbook_groups=2),   # week 4
        snapshot(n_sessions=50, n_anchors=6, playbook_groups=2),   # week 5
        snapshot(n_sessions=60, n_anchors=6, playbook_groups=2),   # week 6
    ]
    with open(rearm_history, "w") as fh:
        fh.writelines(json.dumps(row) + "\n" for row in rearm_rows)
    rearm_current = snapshot(n_sessions=70, n_anchors=6, playbook_groups=2)  # week 7
    rearm_status = target.evaluate_history(rearm_current, rearm_history, stall_window=4)
    check(
        "trailing-window re-arm detects a stall that starts after early growth",
        rearm_status == target.STATUS_ANCHOR_GROWTH_STALLED,
        rearm_status,
    )
    # Sanity: the all-time-first baseline (week 1, n_anchors=1) would NOT flag
    # this as a stall, confirming the window logic (not the trigger condition)
    # is what makes the difference.
    all_time_first = rearm_rows[0]
    all_time_first_would_stall = (
        rearm_current["n_sessions"] > all_time_first["n_sessions"]
        and rearm_current["n_anchors"] <= all_time_first["n_anchors"]
        and rearm_current["playbook_groups"] <= 2
    )
    check(
        "the all-time-first baseline would have missed this stall (proves the window matters)",
        not all_time_first_would_stall,
    )

    # playbook_groups <= 2 is load-bearing: same n_sessions/n_anchors pattern
    # as the stalled case above, but healthy playbook_groups must NOT flag.
    healthy_groups_history = Path(tmp) / "healthy_groups.jsonl"
    with open(healthy_groups_history, "w") as fh:
        fh.writelines(
            json.dumps(snapshot(n_sessions=n_sessions, n_anchors=5, playbook_groups=5)) + "\n"
            for n_sessions in (50, 80)
        )
    healthy_groups_current = snapshot(n_sessions=200, n_anchors=5, playbook_groups=5)
    healthy_groups_status = target.evaluate_history(
        healthy_groups_current, healthy_groups_history, stall_window=4,
    )
    check(
        "flat n_anchors + growing n_sessions but playbook_groups > 2 -> ok, not stalled",
        healthy_groups_status == target.STATUS_OK,
        healthy_groups_status,
    )


# --- append_snapshot / iter_jsonl round trip --------------------------------

with tempfile.TemporaryDirectory() as tmp:
    history_path = Path(tmp) / "roundtrip.jsonl"
    target.append_snapshot(current, history_path)
    round_tripped = list(iter_jsonl(history_path))
    check(
        "append_snapshot + iter_jsonl round-trips exactly one line",
        len(round_tripped) == 1 and round_tripped[0] == current,
        str(round_tripped),
    )
    target.append_snapshot(current, history_path)
    check(
        "a second append_snapshot call adds exactly one more line",
        len(list(iter_jsonl(history_path))) == 2,
    )


# --- CLI: --live without confirmation exits 2 before touching ES -----------

def _explode(*_a, **_k):
    raise AssertionError("live loader called before operator confirmation")


_saved = (eval_novel_pool.load_config, eval_novel_pool.make_client, eval_novel_pool.load_public_inputs)
eval_novel_pool.load_config = _explode
eval_novel_pool.make_client = _explode
eval_novel_pool.load_public_inputs = _explode
try:
    try:
        target.main(["--live"])
        check("--live without confirm exits before touching ES", False, "main() returned")
    except SystemExit as exc:
        check("--live without confirm exits before touching ES", exc.code == 2, str(exc.code))
    except AssertionError as exc:
        check("--live without confirm exits before touching ES", False, str(exc))
finally:
    (
        eval_novel_pool.load_config,
        eval_novel_pool.make_client,
        eval_novel_pool.load_public_inputs,
    ) = _saved


# --- CLI: invalid JSON --report exits 2 -------------------------------------

with tempfile.TemporaryDirectory() as tmp:
    bad_json_path = Path(tmp) / "bad.json"
    bad_json_path.write_text("{not json")
    rc = target.main(["--report", str(bad_json_path)])
    check("invalid JSON --report exits 2", rc == 2, str(rc))


# --- CLI: valid JSON but not a JSON object --report exits 2 -----------------

with tempfile.TemporaryDirectory() as tmp:
    array_report_path = Path(tmp) / "array.json"
    array_report_path.write_text("[1, 2, 3]")
    rc = target.main(["--report", str(array_report_path)])
    check("non-object JSON --report exits 2", rc == 2, str(rc))


# --- CLI: --stall-window < 1 exits 2 (list[-0:] would be the whole list) ---

with tempfile.TemporaryDirectory() as tmp:
    report_path = Path(tmp) / "report.json"
    report_path.write_text(json.dumps(make_report()))
    try:
        target.main(["--report", str(report_path), "--stall-window", "0"])
        check("--stall-window 0 exits 2", False, "main() returned")
    except SystemExit as exc:
        check("--stall-window 0 exits 2", exc.code == 2, str(exc.code))
    try:
        target.main(["--report", str(report_path), "--stall-window", "-1"])
        check("--stall-window -1 exits 2", False, "main() returned")
    except SystemExit as exc:
        check("--stall-window -1 exits 2", exc.code == 2, str(exc.code))


# --- CLI: append_snapshot failure (bad --history path) returns 2 -----------

with tempfile.TemporaryDirectory() as tmp:
    report_path = Path(tmp) / "report.json"
    report_path.write_text(json.dumps(make_report()))
    unwritable_history = Path(tmp) / "no-such-parent-dir" / "history.jsonl"
    rc = target.main(["--report", str(report_path), "--history", str(unwritable_history)])
    check(
        "append_snapshot failure (missing parent dir) returns 2 instead of a raw traceback",
        rc == 2, str(rc),
    )


# --- CLI: --live where load_public_inputs raises RuntimeError returns 2 ----

from types import SimpleNamespace


def _raise_config(*_a, **_k):
    return SimpleNamespace(elasticsearch=object())


def _raise_client(*_a, **_k):
    return object()


def _raise_runtime(*_a, **_k):
    raise RuntimeError("ES unreachable")


_saved = (
    eval_novel_pool.load_config,
    eval_novel_pool.make_client,
    eval_novel_pool.load_secrets,
    eval_novel_pool.load_public_inputs,
)
eval_novel_pool.load_config = _raise_config
eval_novel_pool.make_client = _raise_client
eval_novel_pool.load_secrets = lambda *_a, **_k: {}
eval_novel_pool.load_public_inputs = _raise_runtime
try:
    rc = target.main(["--live", "--confirm-mixed-derived-anchors"])
    check("--live RuntimeError from load_public_inputs returns 2 cleanly", rc == 2, str(rc))
except Exception as exc:
    check("--live RuntimeError from load_public_inputs returns 2 cleanly", False, repr(exc))
finally:
    (
        eval_novel_pool.load_config,
        eval_novel_pool.make_client,
        eval_novel_pool.load_secrets,
        eval_novel_pool.load_public_inputs,
    ) = _saved


# --- CLI: valid report + history returns 0 with correct fields -------------

with tempfile.TemporaryDirectory() as tmp:
    report_path = Path(tmp) / "report.json"
    report_path.write_text(json.dumps(make_report(n_sessions=500, n_anchors=9, playbook_groups=2)))
    history_path = Path(tmp) / "history.jsonl"
    with open(history_path, "w") as fh:
        fh.writelines(json.dumps(snapshot(n_sessions=n_sessions, n_anchors=9, playbook_groups=2)) + "\n" for n_sessions in (100, 200))

    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = target.main(["--report", str(report_path), "--history", str(history_path)])
    check("valid report + history returns 0", rc == 0, str(rc))

    output = json.loads(buf.getvalue())
    check(
        "printed JSON exposes the required current fields and status",
        output["current"]["novel_rate"] == 0.05
        and output["current"]["playbook_groups"] == 2
        and output["current"]["n_anchors"] == 9
        and output["current"]["n_sessions"] == 500
        and output["status"] in (
            target.STATUS_INSUFFICIENT_HISTORY,
            target.STATUS_ANCHOR_GROWTH_STALLED,
            target.STATUS_OK,
        ),
        str(output),
    )

    history_lines = list(iter_jsonl(history_path))
    check(
        "exactly one line appended after evaluation",
        len(history_lines) == 3,
        str(len(history_lines)),
    )
    check(
        "the comparison did not include the sample being appended",
        output["status"] == target.STATUS_ANCHOR_GROWTH_STALLED,
        output["status"],
    )
    check(
        "appended snapshot contains no session ids, hashes, embeddings, bags, or command text",
        all(
            key in {"generated_at", "n_sessions", "n_anchors", "novel_rate", "playbook_groups"}
            for key in history_lines[-1]
        ),
        str(history_lines[-1]),
    )


print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    raise SystemExit(1)
