"""P0 — scale-baseline measurement spike (scale-hardening plan P0.1–P0.3).

The scale-hardening plan sizes P1/P2 against a self-described "rough 90×"
multiplier. This script replaces that guess with measured per-doc / per-run
cost pulled live from the production Elasticsearch, then re-projects the
target table to ``<sensors> × <years>`` and emits the P0.3 decision.

Read-only: only ``count`` / aggregation / ``_cat`` / ``_stats`` calls. No
writes, no deletes (plan: "Risk: None — pure measurement"). The DShield API
credential is never touched.

Two projection axes are kept distinct, because they scale differently:

  * **corpus axis** — raw events, session/IP rollups, commands, source-IP
    lifecycle. Grows with ``sensors × years`` of append-only ingest.
  * **run axis** — the ``prism.cluster.*`` indices. Each backward cycle
    appends a fresh centroid set + ``run_summary`` and never prunes, so these
    grow with the *number of cluster runs* (calendar cadence × years), almost
    independent of corpus size. This is the P2.1 dead-state accumulation.

Run from the repo root via the console venv (the box with ES access):

    console/.venv/bin/python scripts/measure_scale_baseline.py
    console/.venv/bin/python scripts/measure_scale_baseline.py --sensors 3 --years 3

Writes ``eval/results/P0-projection.md`` (P0.2) and prints the same to stdout.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

# Session-rollup enrichment block (matches probe_canonical_session_count.py).
_SB = "dshield.cowrie.enrichment.session"
_CMD_COUNT = f"{_SB}.command_count"
_EMBEDDING = f"{_SB}.embedding"

_DAYS_PER_YEAR = 365.25


# --- ES read helpers (all read-only, all defensive) ------------------------

def _index_stats(es, pattern: str) -> dict:
    """Live top-level doc count + primary store bytes for ``pattern``.

    Docs come from the ``_count`` API, NOT ``_cat/indices docs.count``: the
    latter counts every Lucene document including ``nested`` sub-docs and
    not-yet-merged deletes, which inflates indices that carry nested arrays
    (source_ip lifecycle has ~30 nested snapshots per IP; the session rollup
    has a few). Projecting storage and cardinality off that inflated count is
    exactly the kind of error this spike exists to catch. Bytes still come
    from ``_cat`` primary store (the real disk cost, nesting included), so
    bytes/doc = store ÷ live-entity-count is meaningful.

    Returns zeros + ``missing=True`` when nothing matches, so a fresh box
    doesn't crash."""
    try:
        docs = int(es.count(index=pattern)["count"])
        missing = False
    except Exception:
        docs, missing = 0, True
    try:
        rows = es.cat.indices(
            index=pattern, format="json", bytes="b", h="pri.store.size",
        )
        nbytes = sum(int(r.get("pri.store.size") or 0) for r in rows)
    except Exception:
        nbytes = 0
    return {"docs": docs, "bytes": nbytes, "missing": missing}


def _count(es, idx: str, query: dict | None = None) -> int:
    try:
        kw = {"index": idx}
        if query is not None:
            kw["query"] = query
        return int(es.count(**kw)["count"])
    except Exception:
        return 0


def _avg(es, idx: str, field: str, query: dict | None = None) -> float | None:
    try:
        kw: dict = {"index": idx, "size": 0, "aggs": {"a": {"avg": {"field": field}}}}
        if query is not None:
            kw["query"] = query
        r = es.search(**kw)
        return r["aggregations"]["a"]["value"]
    except Exception:
        return None


def _time_span_days(es, idx: str) -> tuple[float | None, float | None, float | None]:
    """(min_epoch_ms, max_epoch_ms, span_days) over @timestamp; Nones if empty."""
    try:
        r = es.search(index=idx, size=0, aggs={
            "mn": {"min": {"field": "@timestamp"}},
            "mx": {"max": {"field": "@timestamp"}},
        })
        mn = r["aggregations"]["mn"]["value"]
        mx = r["aggregations"]["mx"]["value"]
    except Exception:
        return None, None, None
    if mn is None or mx is None:
        return None, None, None
    span_days = (mx - mn) / 1000.0 / 86400.0
    return mn, mx, span_days


def _latest_run_summary(es, idx: str) -> dict | None:
    """Most-recent run_summary doc for a cluster index (total_docs, runtime)."""
    try:
        r = es.search(
            index=idx, size=1,
            query={"term": {"doc_type": "run_summary"}},
            sort=[{"@timestamp": "desc"}],
        )
        hits = r["hits"]["hits"]
        return hits[0]["_source"] if hits else None
    except Exception:
        return None


def _run_cadence(es, idx: str) -> tuple[int, float | None]:
    """(run_summary count, runs/day) for a cluster index, from the @timestamp
    span of its run_summary docs."""
    n = _count(es, idx, {"term": {"doc_type": "run_summary"}})
    if n < 2:
        return n, None
    try:
        r = es.search(
            index=idx, size=0,
            query={"term": {"doc_type": "run_summary"}},
            aggs={
                "mn": {"min": {"field": "@timestamp"}},
                "mx": {"max": {"field": "@timestamp"}},
            },
        )
        mn = r["aggregations"]["mn"]["value"]
        mx = r["aggregations"]["mx"]["value"]
    except Exception:
        return n, None
    if mn is None or mx is None or mx <= mn:
        return n, None
    span_days = (mx - mn) / 1000.0 / 86400.0
    # n runs span (n-1) intervals across span_days.
    return n, (n - 1) / span_days if span_days > 0 else None


# --- formatting ------------------------------------------------------------

def _h_bytes(n: float | None) -> str:
    if n is None:
        return "n/a"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024.0
    return f"{n:.1f} TB"


def _h_int(n: float | None) -> str:
    return "n/a" if n is None else f"{int(round(n)):,}"


def _fnum(n: float | None, digits: int = 2) -> str:
    return "n/a" if n is None else f"{n:.{digits}f}"


# --- main ------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sensors", type=int, default=3,
                    help="Target sensor count (default 3).")
    ap.add_argument("--years", type=int, default=3,
                    help="Target retention horizon in calendar years (default 3).")
    ap.add_argument("--window-days", type=float, default=None,
                    help="Override the measured corpus window (days). Default: "
                         "derive from raw-events @timestamp span.")
    ap.add_argument("--backward-cadence-per-day", type=float, default=4.0,
                    help="Steady-state cluster-run cadence used for the run-axis "
                         "projection (default 4.0 = the every-6h backward timer). "
                         "The *observed* cadence is reported separately; it is "
                         "inflated by manual/dev cluster runs and a shorter "
                         "run_summary window, so it is not used for projection.")
    ap.add_argument("--output", type=Path,
                    default=Path("eval/results/P0-projection.md"))
    args = ap.parse_args()

    cfg = load_config()
    es = make_client(cfg.elasticsearch, load_secrets())
    cw = cfg.elasticsearch.indexes.cowrie
    src_ip_lifecycle = cfg.findings.indexes.source_ip_lifecycle

    raw_idx = cw.sessions_raw
    sess_idx = cw.sessions_rollup

    # --- corpus window ----------------------------------------------------
    _, _, span_days = _time_span_days(es, raw_idx)
    window_days = args.window_days if args.window_days is not None else span_days
    if not window_days or window_days <= 0:
        print(f"[fatal] could not derive corpus window from {raw_idx!r}; "
              f"pass --window-days explicitly.", file=sys.stderr)
        return 2

    sensor_years_measured = window_days / _DAYS_PER_YEAR
    target_sensor_years = args.sensors * args.years
    corpus_mult = target_sensor_years / sensor_years_measured
    calendar_years = float(args.years)

    # --- per-doc derived metrics (P0.1) -----------------------------------
    raw_stats = _index_stats(es, raw_idx)
    sess_stats = _index_stats(es, sess_idx)
    total_sessions = _count(es, sess_idx) or sess_stats["docs"]
    cmd_bearing = _count(es, sess_idx, {"range": {_CMD_COUNT: {"gt": 0}}})
    embed_bearing = _count(es, sess_idx, {"exists": {"field": _EMBEDDING}})
    avg_cmds = _avg(es, sess_idx, _CMD_COUNT, {"range": {_CMD_COUNT: {"gt": 0}}})

    events_per_session = (raw_stats["docs"] / total_sessions) if total_sessions else None
    bytes_per_raw = (raw_stats["bytes"] / raw_stats["docs"]) if raw_stats["docs"] else None
    bytes_per_rollup = (sess_stats["bytes"] / sess_stats["docs"]) if sess_stats["docs"] else None
    embed_rate = (embed_bearing / total_sessions) if total_sessions else None

    # --- cluster runtime per N + run cadence ------------------------------
    cluster_layers = [
        ("session", cw.session_clusters),
        ("command", cw.command_clusters),
        ("ip",      cw.ip_clusters),
    ]
    cluster_runtime: dict[str, dict] = {}
    cadence_samples: list[float] = []
    for label, idx in cluster_layers:
        rs = _latest_run_summary(es, idx)
        n_runs, runs_day = _run_cadence(es, idx)
        if runs_day:
            cadence_samples.append(runs_day)
        cluster_runtime[label] = {
            "idx": idx,
            "total_docs": (rs or {}).get("total_docs"),
            "runtime_s": (rs or {}).get("runtime_seconds"),
            "n_runs": n_runs,
            "runs_day": runs_day,
        }
    # One backward timer drives all three layers (they fire together), so the
    # max observed cadence is the per-cycle rate. But the run_summary window is
    # shorter than the corpus window and includes manual/dev runs, so the
    # *observed* rate over-counts steady state. Project on the deterministic
    # timer cadence instead; report the observed rate as context.
    observed_runs_per_day = max(cadence_samples) if cadence_samples else None
    steady_runs_per_day = args.backward_cadence_per_day
    projected_runs = steady_runs_per_day * _DAYS_PER_YEAR * calendar_years

    # --- per-index projection table ---------------------------------------
    # axis: "corpus" -> × corpus_mult; "run" -> × (projected_runs / n_runs).
    index_specs = [
        ("raw cowrie events",     raw_idx,           "corpus",
         "data stream + ILM — fine"),
        ("session rollups",       sess_idx,          "corpus",
         "single shard → near ~50 GB ceiling; full re-pool every 6 h"),
        ("IP rollups",            cw.ips_rollup,     "corpus",
         "I3 firewall adds 5–10×; scalar block balloons"),
        ("enriched commands",     cw.commands,       "corpus",
         "strong dedup; sub-linear in practice"),
        ("source_ip lifecycle",   src_ip_lifecycle,  "corpus",
         "one doc per IP forever; I3 explodes cardinality"),
        ("session clusters",      cw.session_clusters, "run",
         "dead centroid accumulation (P2.1)"),
        ("command clusters",      cw.command_clusters, "run",
         "dead centroid accumulation (P2.1)"),
        ("IP clusters",           cw.ip_clusters,    "run",
         "dead centroid accumulation (P2.1)"),
    ]

    rows: list[dict] = []
    for label, idx, axis, fail in index_specs:
        st = _index_stats(es, idx)
        if axis == "corpus":
            factor = corpus_mult
        else:
            # run-axis: scale by projected run count vs. runs observed so far.
            cl = next((v for v in cluster_runtime.values() if v["idx"] == idx), None)
            n_runs = (cl or {}).get("n_runs") or 0
            factor = (projected_runs / n_runs) if (projected_runs and n_runs) else None
        rows.append({
            "label": label, "idx": idx, "axis": axis, "fail": fail,
            "docs": st["docs"], "bytes": st["bytes"], "missing": st["missing"],
            "proj_docs": (st["docs"] * factor) if factor else None,
            "proj_bytes": (st["bytes"] * factor) if factor else None,
            "factor": factor,
        })

    # --- P0.3 decision ----------------------------------------------------
    if corpus_mult >= 150:
        decision = (
            f"(c) **materially LARGER than 90×** (measured {corpus_mult:.0f}×). "
            "P1's window decision should be more aggressive than the plan assumes; "
            "re-check the P2 partition strategy against the bigger number."
        )
    elif corpus_mult >= 60:
        decision = (
            f"(a) **confirms the ~90× framing** (measured {corpus_mult:.0f}×). "
            "Build proceeds as planned."
        )
    else:
        decision = (
            f"(b) **materially SMALLER than 90×** (measured {corpus_mult:.0f}×). "
            "Some P2 work may be deferrable — re-evaluate before committing to "
            "data-stream + ILM on the processed indices."
        )

    # --- render -----------------------------------------------------------
    md = _render(
        cfg=cfg, args=args, window_days=window_days,
        sensor_years_measured=sensor_years_measured,
        target_sensor_years=target_sensor_years, corpus_mult=corpus_mult,
        calendar_years=calendar_years,
        observed_runs_per_day=observed_runs_per_day,
        steady_runs_per_day=steady_runs_per_day,
        projected_runs=projected_runs,
        events_per_session=events_per_session, avg_cmds=avg_cmds,
        bytes_per_raw=bytes_per_raw, bytes_per_rollup=bytes_per_rollup,
        embed_rate=embed_rate, total_sessions=total_sessions,
        cmd_bearing=cmd_bearing, embed_bearing=embed_bearing,
        cluster_runtime=cluster_runtime, rows=rows, decision=decision,
    )
    print(md)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(md, encoding="utf-8")
    print(f"\nwrote {args.output}")
    return 0


def _render(**k) -> str:
    cfg = k["cfg"]
    rows = k["rows"]
    cr = k["cluster_runtime"]
    o: list[str] = []
    o.append("# P0 — scale-baseline projection")
    o.append("")
    # Host for provenance only — strip any embedded userinfo so a credential
    # in the URL never lands in the committed doc.
    hosts = getattr(cfg.elasticsearch, "hosts", None) or []
    host = hosts[0].split("@")[-1] if hosts else "(unknown)"
    o.append(f"_Captured {datetime.now(timezone.utc).isoformat()}_ · ES `{host}`")
    o.append("")
    o.append("Read-only measurement that replaces the scale-hardening plan's "
             '"rough 90×" multiplier with the figure derived from the live '
             "per-doc / per-run cost below.")
    o.append("")

    # --- horizon ----------------------------------------------------------
    o.append("## Horizon")
    o.append("")
    o.append(f"- Measured corpus window: **{k['window_days']:.1f} days** "
             f"(= {k['sensor_years_measured']:.3f} sensor-years, 1 sensor)")
    o.append(f"- Target: **{k['args'].sensors} sensors × {k['args'].years} years "
             f"= {k['target_sensor_years']} sensor-years**")
    o.append(f"- **Derived corpus multiplier: {k['corpus_mult']:.1f}×** "
             f"(plan assumed ~90×)")
    o.append(f"- Cluster-run cadence (run-axis growth): projecting on the "
             f"**steady-state {k['steady_runs_per_day']:.1f} runs/day** "
             f"(every-6h backward timer) → ~{_h_int(k['projected_runs'])} runs "
             f"over {k['calendar_years']:.0f} calendar years.")
    if k["observed_runs_per_day"]:
        o.append(f"  - _Observed_ cadence is **{k['observed_runs_per_day']:.2f} "
                 f"runs/day** (inflated by manual/dev runs over a short "
                 f"run_summary window). Note the plan's **2.76/day** undercounts "
                 f"even the timer rate — it divided runs by the full corpus "
                 f"window; P2.1 dead-state accumulation is therefore *larger* "
                 f"than the plan projected.")
    o.append("")

    # --- per-doc metrics --------------------------------------------------
    o.append("## Per-doc / per-run cost (P0.1)")
    o.append("")
    o.append(f"- avg events / session: **{_fnum(k['events_per_session'])}**")
    o.append(f"- avg commands / command-bearing session: **{_fnum(k['avg_cmds'])}** "
             f"({_h_int(k['cmd_bearing'])} command-bearing sessions)")
    o.append(f"- avg bytes / raw event: **{_h_bytes(k['bytes_per_raw'])}**")
    o.append(f"- avg bytes / session rollup: **{_h_bytes(k['bytes_per_rollup'])}**")
    o.append(f"- embed-rate (clustering N / total sessions): "
             f"**{(k['embed_rate'] or 0) * 100:.2f}%** "
             f"({_h_int(k['embed_bearing'])} / {_h_int(k['total_sessions'])})")
    o.append("")
    o.append("Cluster runtime per N (latest run_summary per layer):")
    o.append("")
    o.append("| layer | docs (N) | runtime (s) | ms/doc | runs so far | runs/day |")
    o.append("|---|---:|---:|---:|---:|---:|")
    for label in ("session", "command", "ip"):
        c = cr.get(label, {})
        n = c.get("total_docs")
        rt = c.get("runtime_s")
        ms = (rt * 1000.0 / n) if (rt and n) else None
        o.append(f"| {label} | {_h_int(n)} | {_fnum(rt, 1)} | {_fnum(ms, 2)} | "
                 f"{_h_int(c.get('n_runs'))} | {_fnum(c.get('runs_day'))} |")
    o.append("")

    # --- projection table -------------------------------------------------
    o.append("## Re-projected target table (P0.2)")
    o.append("")
    o.append("| Index | axis | docs today | store today | docs target | "
             "store target | failure mode if untouched |")
    o.append("|---|---|---:|---:|---:|---:|---|")
    for r in rows:
        tag = " ⚠️missing" if r["missing"] else ""
        o.append(
            f"| `{r['label']}`{tag} | {r['axis']} | {_h_int(r['docs'])} | "
            f"{_h_bytes(r['bytes'])} | {_h_int(r['proj_docs'])} | "
            f"{_h_bytes(r['proj_bytes'])} | {r['fail']} |"
        )
    o.append("")
    o.append("- **corpus axis** rows scale by the derived "
             f"{k['corpus_mult']:.1f}× corpus multiplier (sensors × years of "
             "append-only ingest).")
    o.append("- **run axis** rows (`prism.cluster.*`) scale by projected run "
             "count, not corpus size — this is the P2.1 dead-state accumulation. "
             "The per-run cost grows further as cluster counts rise, so these "
             "projections are a *lower bound*.")
    o.append("")
    o.append("### Corrections to the plan's live snapshot")
    o.append("")
    o.append("Doc counts above are live top-level docs (`_count`), not "
             "`_cat/indices docs.count` (which includes `nested` sub-docs). Two "
             "rows the plan's snapshot got wrong as a result:")
    o.append("")
    o.append("- **source_ip lifecycle** is **~10.9k actual IPs**, not the 332k "
             "the plan reported — that figure was ~30 nested rolling-snapshots "
             "per IP. Real cardinality tracks the IP rollup (~11k), so the "
             '"332k → 30M+" projection should be read as **~11k → ~1M** (still '
             "I3-sensitive: the firewall source explodes distinct-IP count).")
    o.append("- **session rollups** are ~228k live, not 240k (minor nested "
             "inflation). Storage projection is unaffected (bytes are real).")
    o.append("")

    # --- decision ---------------------------------------------------------
    o.append("## P0.3 decision")
    o.append("")
    o.append(k["decision"])
    o.append("")
    o.append("> Verify: counts above reconcile to `GET _cat/indices?bytes=b` and "
             "`GET <index>/_count` on the live sensor. Re-run after any reindex "
             "or retention change to refresh the multiplier.")
    return "\n".join(o)


if __name__ == "__main__":
    raise SystemExit(main())
