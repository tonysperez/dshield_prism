"""Synthetic load-test for the IP full re-cluster (backlog pre-flight B0.3).

The backlog (3 sensors x ~2 years) forces a full IP-layer re-cluster over the
entire ``prism.rollup.cowrie.ip`` index, with no windowing escape valve. Two
distinct scale events fall out of the Phase-K geometry and are timed here in
isolation, exactly as production calls them:

  * **HDBSCAN** over the ~824-dim IP matrix
    (``sklearn.cluster.HDBSCAN(min_cluster_size, min_samples,
    metric="euclidean").fit_predict`` -- ``clustering.py`` ~L915). At 824 dims
    no space-partitioning tree applies, so cost trends toward brute-force
    O(n^2). This is the suspected wall.
  * **Tier-2 SVD** -- ``TfidfVectorizer(token_pattern=r"[^ ]+")`` over each
    IP's bag-of-session-cluster-ids, then ``TruncatedSVD(24).fit_transform``,
    re-fit every run (``ips.py`` ``_build_tier2_block`` ~L976-1016). Its own
    memory + time bill, independent of HDBSCAN.

Each trial runs in an isolated child process with a hard timeout so a runaway
at one scale can't hang the box or destroy earlier results; peak RSS is read
from ``/proc/self/status`` (``VmHWM``) inside the child. Inputs are random --
HDBSCAN cost is driven by ``n`` and ``d``, not the values, so a random matrix
is the prescribed proxy (see handoff-backlog-readiness-review.md B0.3).

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/loadtest_ip_recluster.py \\
        --ip-scales 2000,11000,25000,50000,100000,250000 \\
        --session-clusters 2000 --timeout 600
"""
from __future__ import annotations

import argparse
import multiprocessing as mp
import time
from typing import Optional


def _peak_rss_mb() -> float:
    """Process peak resident set (VmHWM) in MB, or -1 if unavailable."""
    try:
        with open("/proc/self/status", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) / 1024.0
    except OSError:
        pass
    return -1.0


def _make_matrix(rng, n: int, dim: int, mode: str, n_blobs: int):
    """Synthetic IP matrix. ``random`` = diffuse 824-dim Gaussian (worst case,
    no density structure). ``normalized`` = the same rows L2-normalised onto the
    unit sphere (production embeddings are L2-normalised). ``blobs`` =
    production-faithful: the 768-dim embedding head is drawn from ``n_blobs``
    Gaussian centres on the unit sphere (mimics repeated scanner behaviour), the
    scalar tail is small random, matching ``hstack([normalized, scalar_block])``.
    """
    import numpy as np

    if mode == "blobs":
        head = min(768, dim)
        centers = rng.standard_normal((n_blobs, head)).astype(np.float32)
        centers /= np.linalg.norm(centers, axis=1, keepdims=True)
        assign = rng.integers(0, n_blobs, size=n)
        emb = centers[assign] + 0.15 * rng.standard_normal((n, head)).astype(np.float32)
        emb /= np.linalg.norm(emb, axis=1, keepdims=True)
        if dim > head:
            tail = 0.1 * rng.standard_normal((n, dim - head)).astype(np.float32)
            return np.hstack([emb, tail]).astype(np.float32)
        return emb
    x = rng.standard_normal((n, dim)).astype(np.float32)
    if mode == "normalized":
        x /= np.linalg.norm(x, axis=1, keepdims=True)
    return x


def _hdbscan_trial(
    n: int, dim: int, mcs: int, ms: int, seed: int, mode: str, n_blobs: int, q,
) -> None:
    import numpy as np
    from sklearn.cluster import HDBSCAN

    rng = np.random.default_rng(seed)
    x = _make_matrix(rng, n, dim, mode, n_blobs)
    matrix_mb = x.nbytes / (1024.0 * 1024.0)
    t0 = time.perf_counter()
    labels = HDBSCAN(
        min_cluster_size=mcs, min_samples=ms, metric="euclidean",
    ).fit_predict(x)
    elapsed = time.perf_counter() - t0
    n_clusters = int(len({int(c) for c in labels} - {-1}))
    n_outliers = int((labels == -1).sum())
    q.put({
        "elapsed_s": elapsed,
        "peak_rss_mb": _peak_rss_mb(),
        "matrix_mb": matrix_mb,
        "n_clusters": n_clusters,
        "n_outliers": n_outliers,
    })


def _svd_trial(n: int, n_clusters: int, dim: int, seed: int, q) -> None:
    import numpy as np
    from sklearn.decomposition import TruncatedSVD
    from sklearn.feature_extraction.text import TfidfVectorizer

    rng = np.random.default_rng(seed)
    # Per-IP bag of session-cluster ids: 1-5 distinct clusters, counts 1-9.
    # Mirrors _build_tier2_block's doc construction exactly.
    docs = []
    for _ in range(n):
        k = int(rng.integers(1, 6))
        cids = rng.integers(0, n_clusters, size=k)
        cnts = rng.integers(1, 10, size=k)
        docs.append(
            " ".join((str(c) + " ") * int(ct) for c, ct in zip(cids, cnts)).strip()
        )
    t0 = time.perf_counter()
    tfidf = TfidfVectorizer(token_pattern=r"[^ ]+").fit_transform(docs)
    k = min(dim, tfidf.shape[1] - 1, max(tfidf.shape[0] - 1, 1))
    if k < 2:
        q.put({"skipped": True})
        return
    reduced = TruncatedSVD(n_components=k, random_state=20260603).fit_transform(tfidf)
    elapsed = time.perf_counter() - t0
    q.put({
        "elapsed_s": elapsed,
        "peak_rss_mb": _peak_rss_mb(),
        "tfidf_shape": list(tfidf.shape),
        "svd_dim": int(k),
        "reduced_mb": reduced.nbytes / (1024.0 * 1024.0),
    })


def _run_isolated(target, args, timeout: float) -> Optional[dict]:
    """Run ``target`` in a child process; return its result dict or None on
    timeout / crash."""
    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    proc = ctx.Process(target=target, args=(*args, q))
    proc.start()
    proc.join(timeout)
    if proc.is_alive():
        proc.terminate()
        proc.join()
        return None
    try:
        return q.get_nowait()
    except Exception:
        return {"crashed": True}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--ip-scales", default="2000,11000,25000,50000,100000,250000",
        help="comma-separated projected distinct-IP counts to ramp",
    )
    ap.add_argument(
        "--session-clusters", type=int, default=2000,
        help="n_session_clusters (TF-IDF vocabulary width for the SVD trial)",
    )
    ap.add_argument("--dim", type=int, default=824, help="IP geometry dim")
    ap.add_argument("--tier2-dim", type=int, default=24, help="TruncatedSVD n_components")
    ap.add_argument("--mcs", type=int, default=3, help="HDBSCAN min_cluster_size")
    ap.add_argument("--ms", type=int, default=2, help="HDBSCAN min_samples")
    ap.add_argument(
        "--mode", choices=("random", "normalized", "blobs"), default="blobs",
        help="random=diffuse worst case; normalized=unit-sphere; "
             "blobs=production-faithful clustered (default)",
    )
    ap.add_argument("--n-blobs", type=int, default=400,
                    help="distinct behaviour centres for --mode blobs")
    ap.add_argument("--timeout", type=float, default=600.0, help="per-trial seconds")
    ap.add_argument("--seed", type=int, default=20260603)
    ap.add_argument("--skip-hdbscan", action="store_true")
    ap.add_argument("--skip-svd", action="store_true")
    args = ap.parse_args()

    scales = [int(s) for s in args.ip_scales.split(",") if s.strip()]

    print(f"IP geometry dim={args.dim}  HDBSCAN(mcs={args.mcs}, ms={args.ms})  "
          f"per-trial timeout={args.timeout:.0f}s\n")

    if not args.skip_svd:
        print(f"== Tier-2 SVD (TfidfVectorizer -> TruncatedSVD({args.tier2_dim}), "
              f"n_session_clusters={args.session_clusters}) ==")
        print(f"{'n_ips':>10}  {'elapsed_s':>10}  {'peak_rss_mb':>12}  "
              f"{'tfidf_shape':>16}  {'svd_dim':>8}")
        for n in scales:
            res = _run_isolated(
                _svd_trial, (n, args.session_clusters, args.tier2_dim, args.seed),
                args.timeout,
            )
            if res is None:
                print(f"{n:>10}  {'TIMEOUT/OOM':>10}  (stopping SVD ramp)")
                break
            if res.get("crashed") or res.get("skipped"):
                print(f"{n:>10}  {str(res):>10}")
                continue
            print(f"{n:>10}  {res['elapsed_s']:>10.2f}  {res['peak_rss_mb']:>12.0f}  "
                  f"{str(res['tfidf_shape']):>16}  {res['svd_dim']:>8}")
        print()

    if not args.skip_hdbscan:
        print(f"== HDBSCAN.fit_predict over ({{n_ips}}, {args.dim}) euclidean  "
              f"mode={args.mode}"
              f"{f' n_blobs={args.n_blobs}' if args.mode == 'blobs' else ''} ==")
        print(f"{'n_ips':>10}  {'elapsed_s':>10}  {'peak_rss_mb':>12}  "
              f"{'matrix_mb':>10}  {'n_clusters':>10}  {'n_outliers':>10}")
        for n in scales:
            res = _run_isolated(
                _hdbscan_trial,
                (n, args.dim, args.mcs, args.ms, args.seed, args.mode, args.n_blobs),
                args.timeout,
            )
            if res is None:
                print(f"{n:>10}  {'TIMEOUT/OOM':>10}  "
                      f"(wall stops here at <= {args.timeout:.0f}s)")
                break
            if res.get("crashed"):
                print(f"{n:>10}  CRASHED (likely OOM)")
                break
            print(f"{n:>10}  {res['elapsed_s']:>10.2f}  {res['peak_rss_mb']:>12.0f}  "
                  f"{res['matrix_mb']:>10.0f}  {res['n_clusters']:>10}  "
                  f"{res['n_outliers']:>10}")
        print()


if __name__ == "__main__":
    main()
