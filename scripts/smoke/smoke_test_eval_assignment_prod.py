"""Smoke test for the production-scale assignment-eval scoring
(`scripts/eval_assignment_prod.py::score_against_anchors`). No ES, no snapshot file.
"""
from __future__ import annotations

import contextlib
import io
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/

import capture_anchor_snapshot
from capture_anchor_snapshot import (
    anchor_row,
    background_query_filters,
    centroid,
    cohort_is_informative,
    explicitly_public_filters,
    require_public_command_taxonomy,
    resolve_min_public,
)
from eval_assignment_prod import baseline_anchor_count_error, score_against_anchors

from enrich.config import SessionConfig

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


def _u(v):
    a = np.array(v, dtype=np.float32)
    return a / np.linalg.norm(a)


# Two behaviour-pure anchors (A on e0, B on e1); two sessions per behaviour right on top.
anchors = np.array([[1, 0, 0, 0], [0, 1, 0, 0]], dtype=np.float32)
anchor_ids = ["spb-A", "spb-B"]
embs = np.array([_u([1, 0, 0.02, 0]), _u([1, 0, -0.02, 0]),
                 _u([0, 1, 0.02, 0]), _u([0, 1, -0.02, 0])], dtype=np.float32)
labels = ["recon", "recon", "persist", "persist"]

rep = score_against_anchors(embs, labels, anchor_ids, anchors, tau=0.9, confident_tau=0.98)
check("all assigned (known sessions on their anchors)", rep["assigned_rate"] == 1.0, str(rep))
check("novel_rate 0.0", rep["novel_rate"] == 0.0)
check("homogeneity 1.0 (each anchor is one behaviour)", rep["homogeneity"] == 1.0, str(rep["homogeneity"]))
check("anchor_label_purity 1.0", rep["anchor_label_purity"] == 1.0, str(rep["anchor_label_purity"]))
check("n_assigned == 4", rep["n_assigned"] == 4)

# A session far from every anchor → novel (lowers assigned_rate).
embs2 = np.vstack([embs, _u([0, 0, 1, 0])])  # orthogonal to both anchors
labels2 = [*labels, "weird"]
rep2 = score_against_anchors(embs2, labels2, anchor_ids, anchors, tau=0.9, confident_tau=0.98)
check("far session lands novel → assigned_rate 0.8", rep2["assigned_rate"] == 0.8, str(rep2))

# No anchors / nothing assigns → graceful Nones.
empty = score_against_anchors(embs, labels, [], np.zeros((0, 4), dtype=np.float32),
                              tau=0.9, confident_tau=0.98)
check("empty anchors → assigned_rate 0.0, homogeneity None",
      empty["assigned_rate"] == 0.0 and empty["homogeneity"] is None, str(empty))

# --- baseline/snapshot anchor-count compatibility guard (pure; no snapshot file) ---
current_report = {"n_anchors": 31}
check("matching baseline n_anchors passes compatibility guard",
      baseline_anchor_count_error(current_report, {"n_anchors": 31, "metrics": {}}) is None)
stale_error = baseline_anchor_count_error(current_report, {"n_anchors": 19, "metrics": {}})
check("stale baseline n_anchors fails compatibility guard",
      stale_error is not None
      and "baseline n_anchors=19" in stale_error
      and "current n_anchors=31" in stale_error
      and "rebaseline" in stale_error,
      str(stale_error))
check("legacy baseline without n_anchors preserves metric-gate behavior",
      baseline_anchor_count_error(current_report, {"metrics": {}}) is None)

# --- public-derived centroid math (capture_anchor_snapshot.centroid) ---
import math

check("centroid of identical unit vecs == itself", centroid([[1, 0], [1, 0]]) == [1.0, 0.0])
check("centroid normalises the mean",
      abs(centroid([[2, 0], [0, 0]])[0] - 1.0) < 1e-6, str(centroid([[2, 0], [0, 0]])))
c = centroid([[1, 0], [0, 1]])
check("centroid of orthogonal pair ~ [.707,.707]",
      abs(c[0] - math.sqrt(0.5)) < 1e-6 and abs(c[1] - math.sqrt(0.5)) < 1e-6, str(c))
check("zero mean → returned as-is (no div-by-zero)", centroid([[0.0, 0.0]]) == [0.0, 0.0])

# --- public command taxonomy guard (capture_anchor_snapshot, no ES) ---
def taxonomy_error(taxonomy: dict[str, str]) -> str:
    try:
        require_public_command_taxonomy(taxonomy)
    except ValueError as exc:
        return str(exc)
    return ""


for name, taxonomy in (
    ("empty", {}),
    ("all-outlier", {"h1": "cluster_outlier", "h2": "cluster_outlier"}),
    ("one-real-cluster", {"h1": "cluster_1", "h2": "cluster_outlier"}),
):
    error = taxonomy_error(taxonomy)
    check(f"{name} public taxonomy fails closed with classify/rebuild remediation",
          "lacks lexical diversity" in error and "Classify and rebuild" in error,
          error)

valid_taxonomy = {"h1": "cluster_1", "h2": "cluster_2", "h3": "cluster_outlier"}
check("two real cluster IDs are accepted unchanged",
      require_public_command_taxonomy(valid_taxonomy) is valid_taxonomy)

fail_open_cfg = SimpleNamespace(
    classification=SimpleNamespace(unclassified_is_confidential=False),
)
strict_filters = explicitly_public_filters(fail_open_cfg)
check("capture filters require explicit public under fail-open config",
      {"term": {"dshield.classification.keyword": "public"}} in strict_filters,
      str(strict_filters))

# --- background cohort selection + degeneracy guard (item 44b) ---
_CMDSET_EXISTS = {"exists": {"field": "dshield.cowrie.enrichment.session.command_set"}}
base_filters = [{"term": {"dshield.classification.keyword": "public"}}]
bg_filters = background_query_filters(base_filters)
check("background cohort requires a session that actually ran commands",
      _CMDSET_EXISTS in bg_filters, str(bg_filters))
check("background cohort keeps the caller's public filters ahead of the command clause",
      bg_filters[: len(base_filters)] == base_filters, str(bg_filters))
check("background_query_filters does not mutate the caller's list",
      base_filters == [{"term": {"dshield.classification.keyword": "public"}}], str(base_filters))

check("all-empty cohort is rejected (the observed 2000x cluster_empty capture)",
      not cohort_is_informative(["cluster_empty"] * 2000))
check("all-outlier cohort is rejected", not cohort_is_informative(["cluster_outlier"] * 50))
check("one real token is not enough to express a document difference",
      not cohort_is_informative(["cluster_7 cluster_7", "cluster_7 cluster_outlier"]))
check("two distinct real tokens make the cohort informative",
      cohort_is_informative(["cluster_7 cluster_outlier", "cluster_9 cluster_empty"]))
check("empty cohort is not informative", not cohort_is_informative([]))

# The expected taxonomy failure is handled at the CLI boundary before either
# capture query or output path can be reached. Use pre-existing sentinel files
# to prove every invalid shape leaves prior operator artifacts intact.
def check_invalid_taxonomy_cli(name: str, taxonomy: dict[str, str]) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        anchor_out = temp_path / "anchor.jsonl.gz"
        background_out = temp_path / "background.jsonl.gz"
        anchor_sentinel = b"anchor sentinel"
        background_sentinel = b"background sentinel"
        anchor_out.write_bytes(anchor_sentinel)
        background_out.write_bytes(background_sentinel)
        cfg = SimpleNamespace(
            elasticsearch=SimpleNamespace(
                indexes=SimpleNamespace(
                    cowrie=SimpleNamespace(sessions_rollup="sessions", commands="commands"),
                ),
            ),
            # Real SessionConfig: `--min-public` resolves off it, so a bare namespace
            # here would only prove the stub is wrong.
            session=SessionConfig(cluster_min_cluster_size=5,
                                  novel_pool_cluster_min_cluster_size=3),
        )
        sampling_called = [False]

        def unexpected_sampling(*args, **kwargs):
            sampling_called[0] = True
            raise AssertionError("invalid taxonomy must stop before session sampling")

        replacements = {
            "load_config": lambda config: cfg,
            "load_secrets": lambda config: object(),
            "make_client": lambda *args: object(),
            "pull_hash_to_cluster": lambda *args, **kwargs: taxonomy,
            "_public_playbook_ids": unexpected_sampling,
            "_sample_sessions": unexpected_sampling,
            "_sample_background_sessions": unexpected_sampling,
        }
        originals = {key: getattr(capture_anchor_snapshot, key) for key in replacements}
        old_argv = sys.argv
        stderr = io.StringIO()
        try:
            for key, replacement in replacements.items():
                setattr(capture_anchor_snapshot, key, replacement)
            sys.argv = [
                "capture_anchor_snapshot.py", "--out", str(anchor_out),
                "--background-out", str(background_out),
            ]
            with contextlib.redirect_stderr(stderr):
                exit_code = capture_anchor_snapshot.main()
        finally:
            sys.argv = old_argv
            for key, original in originals.items():
                setattr(capture_anchor_snapshot, key, original)
        check(f"{name} taxonomy CLI exits 2 before sampling without a traceback",
              exit_code == 2 and not sampling_called[0] and "Traceback" not in stderr.getvalue(),
              f"exit={exit_code}, stderr={stderr.getvalue()!r}")
        check(f"{name} taxonomy CLI leaves existing anchor and background files unchanged",
              anchor_out.read_bytes() == anchor_sentinel
              and background_out.read_bytes() == background_sentinel,
              f"anchor={anchor_out.read_bytes()!r}, background={background_out.read_bytes()!r}")


for name, taxonomy in (
    ("empty", {}),
    ("all-outlier", {"h1": "cluster_outlier"}),
    ("one-real-cluster", {"h1": "cluster_1", "h2": "cluster_outlier"}),
):
    check_invalid_taxonomy_cli(name, taxonomy)

# --- anchor_row (capture_anchor_snapshot's pure per-anchor snapshot-row assembly) ---
h2c = {"h1": "cluster_1", "h2": "cluster_2"}
row = anchor_row("spb-A", [[1, 0], [1, 0]], [["h1", "h2"], ["h1"]], h2c, min_public=2)
check("anchor_row bags pass through build_bag_texts unchanged",
      row is not None and row["command_cluster_bags"]
      == ["cluster_1 cluster_2", "cluster_1"], str(row))
check("anchor_row keeps n_public_sessions == len(embs)",
      row is not None and row["n_public_sessions"] == 2, str(row))

below = anchor_row("spb-B", [[1, 0]], [["h1"]], h2c, min_public=2)
check("anchor_row below min_public → None", below is None, str(below))

empty_cs = anchor_row("spb-C", [[1, 0]], [[]], h2c, min_public=1)
check("anchor_row empty command_set → cluster_empty token, no crash",
      empty_cs is not None and empty_cs["command_cluster_bags"] == ["cluster_empty"],
      str(empty_cs))

# --- resolve_min_public: the capture floor tracks the deployed minting floor (E9) ---
# A capture pinned above what production may MINT silently drops every rare-behaviour
# anchor — the exact set the labelled eval is short of. Explicit flag still wins.
mint3 = SimpleNamespace(session=SessionConfig(cluster_min_cluster_size=5,
                                              novel_pool_cluster_min_cluster_size=3))
check("min_public defaults to the novel-pool minting floor",
      resolve_min_public(None, mint3) == 3, str(resolve_min_public(None, mint3)))
check("an explicit --min-public still wins", resolve_min_public(9, mint3) == 9)
check("--min-public 0 is honoured, not treated as unset", resolve_min_public(0, mint3) == 0)

mint_off = SimpleNamespace(session=SessionConfig(cluster_min_cluster_size=5,
                                                 novel_pool_cluster_min_cluster_size=None))
check("novel-pool override disabled → falls back to the normal cluster floor",
      resolve_min_public(None, mint_off) == 5, str(resolve_min_public(None, mint_off)))

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
