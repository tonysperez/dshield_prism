"""E8.2 sweep — embed_input_order layouts at production scale.

Mirrors ``sweep_embed_input.py`` but operates at production scale, not
the eval subset:

  1. ``prelude_first``         (production default — unchanged)
  2. ``command_first``         (head context after the command line)
  3. ``command_only_with_tag`` (drops the prelude entirely, ``[shell] cmd``)

For each ordering the sweep walks the production commands index,
rebuilds the per-command embed text under that layout, re-embeds via
``llm.embed()`` (no ES writes), re-pools every production session via
the same IDF-weighted mean pool used at rollup time, clusters all
~4000 sessions at production HDBSCAN hyperparameters, restricts to
the eval-labeled subset (108 sessions), and scores. The labels +
divergent-pair metric come straight from the existing
``eval_clustering`` helpers, so the sweep numbers are gate-comparable.

Output: ``eval/results/embed-input-order-sweep-<ts>.{md,json}``.

Cost: ~4571 unique-command embed calls × 3 layouts ≈ 14k LLM calls
plus the metadata pulls. Roughly 3–6 minutes against a local LM Studio
@q8_0 endpoint. No production state mutated — purely in-memory.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/sweep_embed_input_order.py
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.cluster import HDBSCAN
from sklearn.metrics import (
    adjusted_rand_score,
    completeness_score,
    homogeneity_score,
    normalized_mutual_info_score,
    v_measure_score,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from enrich.clustering import l2_normalize, rescue_noise_points
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client
from enrich.llm import make_llm_client
from enrich.llm.schemas import CommandEnrichment
from enrich.sources.cowrie.commands import _build_embed_text
from enrich.sources.cowrie.sessions import (
    _idf_pool_weight, _mean_pool, build_session_scalar_block,
)

from eval_clustering import (  # type: ignore
    _load_labels,
    _per_label_breakdown,
    _divergent_pair_metrics,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sweep configs
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SweepConfig:
    name:           str
    order:          str  # one of the three valid layouts


SWEEP_CONFIGS: tuple[SweepConfig, ...] = (
    SweepConfig("prelude_first",          "prelude_first"),
    SweepConfig("command_first",          "command_first"),
    SweepConfig("command_only_with_tag",  "command_only_with_tag"),
)


# ---------------------------------------------------------------------------
# Production data pull
# ---------------------------------------------------------------------------

@dataclass
class SessionFacts:
    """All a sweep iteration needs to re-pool one production session.

    ``command_hashes`` carries the unique command hashes the rollup
    iteration witnessed (mirrors ``command_set`` in the rollup doc).
    ``label`` is non-empty only for the analyst-labeled subset.
    """
    session_id:      str
    label:           str | None
    scalars:         dict
    command_hashes:  list[str]


def _ce_doc_to_parsed(enrich_doc: dict) -> CommandEnrichment | None:
    """Map a persisted command-enrichment ES _source back to the
    in-memory ``CommandEnrichment`` ``_build_embed_text`` expects.
    Identical mapping to ``sweep_embed_input.py``'s helper, kept local
    so the sweeps don't share a moving target."""
    enr = (((enrich_doc.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {})
    threat = enrich_doc.get("threat") or {}
    description = (enrich_doc.get("event") or {}).get("reason") or ""
    intent = enr.get("intent") or "unknown"
    tactics = ((threat.get("tactic") or {}).get("id")) or []
    techniques = ((threat.get("technique") or {}).get("id")) or []
    confidence = enr.get("confidence") or 1
    if not description and intent == "unknown" and not tactics and not techniques:
        return None
    try:
        return CommandEnrichment(
            description=description,
            intent=intent,
            tactics=list(tactics),
            techniques=list(techniques),
            confidence=int(confidence),
        )
    except Exception:
        return None


def _pull_sessions(
    es, sessions_idx: str, page_size: int,
    sid_to_label: dict[str, str],
    limit: int | None,
) -> list[SessionFacts]:
    """Iterate every rollup that carries an embedding, returning the
    fields needed to re-pool. Stamps the analyst label when present."""
    body: dict = {
        "size": page_size,
        "_source": [
            "dshield.cowrie.enrichment.session.embedding",
            "dshield.cowrie.enrichment.session.command_count",
            "dshield.cowrie.enrichment.session.unique_commands",
            "dshield.cowrie.enrichment.session.login_success_count",
            "dshield.cowrie.enrichment.session.login_fail_count",
            "dshield.cowrie.enrichment.session.mean_novelty_score",
            "dshield.cowrie.enrichment.session.command_set",
            "cowrie.session_id",
        ],
        "query": {"exists": {"field": "dshield.cowrie.enrichment.session.embedding"}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    out: list[SessionFacts] = []
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=sessions_idx, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return out
        for h in hits:
            src = h["_source"]
            s = (((src.get("dshield") or {}).get("cowrie") or {})
                 .get("enrichment", {}).get("session", {}))
            sid = (src.get("cowrie") or {}).get("session_id", h["_id"])
            cmd_set = s.get("command_set") or []
            if not cmd_set:
                continue
            success = s.get("login_success_count") or 0
            fail = s.get("login_fail_count") or 0
            total = success + fail
            scalars = {
                "command_count":      s.get("command_count") or 1,
                "unique_commands":    s.get("unique_commands") or 1,
                "login_success_rate": success / total if total > 0 else 0.0,
                "mean_novelty_score": s.get("mean_novelty_score") or 0.0,
            }
            out.append(SessionFacts(
                session_id=sid,
                label=sid_to_label.get(sid),
                scalars=scalars,
                command_hashes=list(cmd_set),
            ))
            if limit is not None and len(out) >= limit:
                return out
        search_after = hits[-1]["sort"]


def _pull_command_enrichments(
    es, commands_idx: str, hashes: list[str], batch: int = 256,
) -> dict[str, dict]:
    """mget the enrichment docs for every command hash in the rollups.

    Returns ``{hash: {parsed: CommandEnrichment, command: str,
    occurrence_count: int}}``. Hashes that aren't found are skipped.
    """
    out: dict[str, dict] = {}
    t0 = time.time()
    for i in range(0, len(hashes), batch):
        chunk = hashes[i:i + batch]
        resp = es.mget(index=commands_idx, ids=chunk)
        for doc in resp.get("docs") or []:
            if not doc.get("found"):
                continue
            src = doc["_source"]
            parsed = _ce_doc_to_parsed(src)
            if parsed is None:
                continue
            # Two paths for the raw command text: prefer the
            # canonical-shape pre-enrich storage, fall back to the
            # process.command_line ECS field.
            cmd = (
                (((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {})
                .get("command")
            ) or (
                (src.get("process") or {}).get("command_line")
            )
            if not cmd:
                continue
            enr = (((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {})
            out[doc["_id"]] = {
                "command":          cmd,
                "parsed":           parsed,
                "occurrence_count": int(enr.get("occurrence_count") or 1),
            }
        if (i // batch + 1) % 8 == 0:
            log.info("mget enrichments: %d/%d (%.1fs)",
                     min(i + batch, len(hashes)), len(hashes),
                     time.time() - t0)
    log.info("mget enrichments complete: %d/%d hashes in %.1fs",
             len(out), len(hashes), time.time() - t0)
    return out


# ---------------------------------------------------------------------------
# Per-config measurement
# ---------------------------------------------------------------------------

def _embed_all_commands(
    llm, enrichments: dict[str, dict], order: str,
) -> dict[str, list[float]]:
    """Build embed text + call llm.embed() for every enriched command
    under the requested ordering. Returns ``{cmd_hash: vector}``."""
    out: dict[str, list[float]] = {}
    t0 = time.time()
    n = len(enrichments)
    for i, (h, data) in enumerate(enrichments.items()):
        embed_text = _build_embed_text(
            data["command"], data["parsed"], ["intent", "tactics", "techniques", "description"],
            cooccurring=None,
            embed_cooccurrence=False,
            order=order,
        )
        try:
            out[h] = llm.embed(embed_text)
        except Exception as e:
            log.warning("llm.embed failed for hash %s under %s: %s", h, order, e)
            continue
        if (i + 1) % 250 == 0:
            log.info("  %s: embedded %d/%d (%.1fs)", order, i + 1, n,
                     time.time() - t0)
    log.info("  %s: %d/%d embeddings in %.1fs", order, len(out), n,
             time.time() - t0)
    return out


def _pool_sessions(
    sessions: list[SessionFacts],
    cmd_vectors: dict[str, list[float]],
    enrichments: dict[str, dict],
) -> tuple[list[SessionFacts], list[list[float]]]:
    """IDF-weighted mean pool every session that has at least one
    embedded command. Returns the surviving sessions + their pooled
    vectors aligned. Sessions whose commands all failed to embed are
    dropped — clustering on a zero vector pulls everything toward the
    origin and noises the geometry."""
    kept_sessions: list[SessionFacts] = []
    pooled: list[list[float]] = []
    for s in sessions:
        embs: list[list[float]] = []
        weights: list[float] = []
        for h in s.command_hashes:
            vec = cmd_vectors.get(h)
            if vec is None:
                continue
            e = enrichments.get(h)
            occ = (e or {}).get("occurrence_count") or 1
            embs.append(vec)
            weights.append(_idf_pool_weight(occ))
        if not embs:
            continue
        pooled.append(_mean_pool(embs, weights))
        kept_sessions.append(s)
    return kept_sessions, pooled


def _cluster_at_production_scale(
    embeddings: list[list[float]], scalars_list: list[dict], scfg, rescue: bool,
) -> np.ndarray:
    matrix = np.array(embeddings, dtype=np.float32)
    normalized = l2_normalize(matrix)
    block = build_session_scalar_block(scalars_list, scfg.cluster_scalar_weight)
    cluster_matrix = np.hstack([normalized, block])
    clusterer = HDBSCAN(
        min_cluster_size=scfg.cluster_min_cluster_size,
        min_samples=scfg.cluster_min_samples,
        metric="euclidean",
    )
    labels = clusterer.fit_predict(cluster_matrix)
    if rescue and scfg.playbook_merge_threshold > 0.0:
        labels, _ = rescue_noise_points(normalized, labels, scfg.playbook_merge_threshold)
    return labels


def _score_against_labels(
    kept_sessions: list[SessionFacts],
    cluster_labels: np.ndarray,
    pair_to_sessions: dict[str, list[str]],
) -> dict:
    """Filter to the analyst-labeled subset, then compute the same
    metrics + per-label table the production-scale gate computes."""
    sid_to_cluster = {s.session_id: int(c) for s, c in zip(kept_sessions, cluster_labels)}
    eval_sids: list[str] = []
    eval_labels: list[str] = []
    eval_clusters: list[int] = []
    for s in kept_sessions:
        if s.label is None:
            continue
        eval_sids.append(s.session_id)
        eval_labels.append(s.label)
        eval_clusters.append(sid_to_cluster[s.session_id])

    cluster_arr = np.array(eval_clusters, dtype=np.int64)
    metrics = {
        "ari":          round(float(adjusted_rand_score(eval_labels, cluster_arr)), 4),
        "nmi":          round(float(normalized_mutual_info_score(eval_labels, cluster_arr)), 4),
        "homogeneity":  round(float(homogeneity_score(eval_labels, cluster_arr)), 4),
        "completeness": round(float(completeness_score(eval_labels, cluster_arr)), 4),
        "v_measure":    round(float(v_measure_score(eval_labels, cluster_arr)), 4),
    }
    if pair_to_sessions:
        v2_metrics, _outcomes = _divergent_pair_metrics(
            eval_sids, cluster_arr, eval_labels, pair_to_sessions,
        )
        metrics.update(v2_metrics)

    n_clusters_total = len({int(c) for c in cluster_labels if c >= 0})
    n_outliers_total = int((cluster_labels == -1).sum())
    return {
        "metrics":          metrics,
        "n_clusters_total": n_clusters_total,
        "n_outliers_total": n_outliers_total,
        "eval_subset_size": len(eval_sids),
        "per_label":        _per_label_breakdown(eval_sids, eval_labels, cluster_arr),
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

_METRIC_ORDER = (
    "ari", "completeness", "homogeneity", "nmi", "v_measure",
    "divergent_pair_resolution_rate",
)


def _render_markdown(rows: list[dict], baseline: dict, started_at: str) -> str:
    out: list[str] = []
    out.append("# E8.2 — embed_input_order sweep (production scale)")
    out.append("")
    out.append(f"_Captured {started_at}_")
    out.append("")
    out.append(f"Sorted by ARI descending. {len(rows)} layouts swept against "
               f"the full production corpus (~{baseline['rollups_pulled']} "
               "rollups), scored on the labeled eval subset.")
    out.append("")
    headers = ["layout"] + list(_METRIC_ORDER) + ["n_clusters_total", "n_outliers_total"]
    out.append("| " + " | ".join(headers) + " |")
    out.append("|" + "|".join(["---"] * len(headers)) + "|")
    for r in rows:
        cells = [r["config"]["name"]]
        for m in _METRIC_ORDER:
            v = r["score"]["metrics"].get(m)
            cells.append(f"{v:.4f}" if isinstance(v, float) else str(v if v is not None else "—"))
        cells.append(str(r["score"]["n_clusters_total"]))
        cells.append(str(r["score"]["n_outliers_total"]))
        out.append("| " + " | ".join(cells) + " |")
    out.append("")
    out.append("**Baseline** (persisted production cluster ids, no re-embed): "
               f"ARI {baseline['baseline_ari']:.4f}, completeness "
               f"{baseline['baseline_completeness']:.4f}.")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config-path", type=str, default=None)
    ap.add_argument("--labels", type=Path, default=Path("eval/labels-v1.yaml"))
    ap.add_argument("--labels-v2", type=Path, default=Path("eval/labels-v2.yaml"))
    ap.add_argument("--limit-rollups", type=int, default=None,
                    help="Cap the production pull at N rollups for dev runs.")
    ap.add_argument("--no-rescue", action="store_true",
                    help="Skip the production-faithful noise-rescue pass.")
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(message)s",
    )
    log.setLevel(logging.INFO)

    cfg = load_config(args.config_path)
    secrets = load_secrets(args.config_path)
    scfg = cfg.session
    es = make_client(cfg.elasticsearch, secrets)
    sessions_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    commands_idx = cfg.elasticsearch.indexes.cowrie.commands

    sid_to_label: dict[str, str] = {}
    pair_to_sessions: dict[str, list[str]] = {}
    for p in (args.labels, args.labels_v2):
        if not p.exists():
            continue
        block = _load_labels(p)
        sid_to_label.update({sid: b["playbook_label"] for sid, b in block.items()})
        if p == args.labels_v2:
            for sid, b in block.items():
                pid = b.get("divergent_pair_id")
                if isinstance(pid, str) and pid:
                    pair_to_sessions.setdefault(pid, []).append(sid)
    if not sid_to_label:
        raise SystemExit(f"No labels found in {args.labels} or {args.labels_v2}")

    started_at = datetime.now(timezone.utc).isoformat()
    log.info("pulling rollups from %s", sessions_idx)
    sessions = _pull_sessions(es, sessions_idx, scfg.page_size, sid_to_label, args.limit_rollups)
    log.info("pulled %d rollups", len(sessions))

    all_hashes = sorted({h for s in sessions for h in s.command_hashes})
    log.info("pulling enrichments for %d unique command hashes from %s",
             len(all_hashes), commands_idx)
    enrichments = _pull_command_enrichments(es, commands_idx, all_hashes)

    # Capture a "no re-embed" baseline by reading the persisted session
    # embeddings + scoring — same pattern eval_production_scale.py uses.
    # The sweep metrics are all relative to this floor.
    persisted: list[list[float]] = []
    scalars_list_for_baseline: list[dict] = []
    baseline_session_ids: list[str] = []
    body: dict = {
        "size": scfg.page_size,
        "_source": [
            "dshield.cowrie.enrichment.session.embedding",
            "dshield.cowrie.enrichment.session.command_count",
            "dshield.cowrie.enrichment.session.unique_commands",
            "dshield.cowrie.enrichment.session.login_success_count",
            "dshield.cowrie.enrichment.session.login_fail_count",
            "dshield.cowrie.enrichment.session.mean_novelty_score",
            "cowrie.session_id",
        ],
        "query": {"exists": {"field": "dshield.cowrie.enrichment.session.embedding"}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    sa = None
    while True:
        if sa:
            body["search_after"] = sa
        r = es.search(index=sessions_idx, **body)
        hits = r["hits"]["hits"]
        if not hits:
            break
        for h in hits:
            src = h["_source"]
            sb = (((src.get("dshield") or {}).get("cowrie") or {})
                  .get("enrichment", {}).get("session", {}))
            emb = sb.get("embedding")
            if not emb:
                continue
            sid = (src.get("cowrie") or {}).get("session_id", h["_id"])
            success = sb.get("login_success_count") or 0
            fail = sb.get("login_fail_count") or 0
            total = success + fail
            scalars_list_for_baseline.append({
                "command_count":      sb.get("command_count") or 1,
                "unique_commands":    sb.get("unique_commands") or 1,
                "login_success_rate": success / total if total > 0 else 0.0,
                "mean_novelty_score": sb.get("mean_novelty_score") or 0.0,
            })
            persisted.append(emb)
            baseline_session_ids.append(sid)
            if args.limit_rollups is not None and len(persisted) >= args.limit_rollups:
                break
        else:
            sa = hits[-1]["sort"]
            continue
        break
    baseline_labels = _cluster_at_production_scale(
        persisted, scalars_list_for_baseline, scfg, rescue=not args.no_rescue,
    )
    sid_to_baseline_cluster = {
        sid: int(c) for sid, c in zip(baseline_session_ids, baseline_labels)
    }
    baseline_eval_sids: list[str] = []
    baseline_eval_labels: list[str] = []
    baseline_eval_clusters: list[int] = []
    for sid, lbl in sid_to_label.items():
        if sid in sid_to_baseline_cluster:
            baseline_eval_sids.append(sid)
            baseline_eval_labels.append(lbl)
            baseline_eval_clusters.append(sid_to_baseline_cluster[sid])
    baseline_arr = np.array(baseline_eval_clusters, dtype=np.int64)
    baseline_ari = float(adjusted_rand_score(baseline_eval_labels, baseline_arr))
    baseline_comp = float(completeness_score(baseline_eval_labels, baseline_arr))

    # Run the sweep.
    results: list[dict] = []
    with make_llm_client(cfg.llm) as llm:
        for sc in SWEEP_CONFIGS:
            log.info("=== %s ===", sc.name)
            cmd_vecs = _embed_all_commands(llm, enrichments, sc.order)
            kept, pooled = _pool_sessions(sessions, cmd_vecs, enrichments)
            labels = _cluster_at_production_scale(
                pooled, [s.scalars for s in kept], scfg, rescue=not args.no_rescue,
            )
            score = _score_against_labels(kept, labels, pair_to_sessions)
            log.info("  ari=%s  hom=%s  comp=%s  v2pair=%s  n_clusters=%d  n_outliers=%d",
                     score["metrics"].get("ari"),
                     score["metrics"].get("homogeneity"),
                     score["metrics"].get("completeness"),
                     score["metrics"].get("divergent_pair_resolution_rate"),
                     score["n_clusters_total"],
                     score["n_outliers_total"])
            results.append({
                "config":  {"name": sc.name, "order": sc.order},
                "score":   score,
                "kept_sessions":   len(kept),
                "embedded_commands": len(cmd_vecs),
            })

    results.sort(key=lambda r: r["score"]["metrics"].get("ari", 0.0), reverse=True)

    baseline = {
        "rollups_pulled":        len(sessions),
        "enrichments_pulled":    len(enrichments),
        "baseline_ari":          round(baseline_ari, 4),
        "baseline_completeness": round(baseline_comp, 4),
        "captured_at":           started_at,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    md_path = args.output_dir / f"embed-input-order-sweep-{ts}.md"
    json_path = args.output_dir / f"embed-input-order-sweep-{ts}.json"
    md_path.write_text(_render_markdown(results, baseline, started_at), encoding="utf-8")
    json_path.write_text(json.dumps({
        "started_at": started_at,
        "baseline":   baseline,
        "results":    results,
        "config_at_capture": {
            "embedding_model":   cfg.llm.embedding_model,
            "embed_context":     list(cfg.llm.embed_context),
            "min_cluster_size":  scfg.cluster_min_cluster_size,
            "min_samples":       scfg.cluster_min_samples,
            "scalar_weight":     scfg.cluster_scalar_weight,
            "rescue":            (not args.no_rescue) and scfg.playbook_merge_threshold,
        },
    }, indent=2), encoding="utf-8")

    print(_render_markdown(results, baseline, started_at))
    print(f"\nwrote {md_path}")
    print(f"wrote {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
