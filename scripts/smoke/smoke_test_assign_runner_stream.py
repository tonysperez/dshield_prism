"""Smoke test for the streamed full-corpus window scan in
`enrich.sources.cowrie.assign_runner._scan_window_embeddings`. No ES, no network.

The fix streams the session-rollup window scan and accumulates embeddings as
float32 chunks instead of a corpus-wide list[list[float]] (the backfill OOM).
This asserts the streamed result (win_ids, win_sets, W) is byte-identical to the
old list-materialize-then-`keep` reference, that W is float32, and that the
generator paging (`_iter_scan`) is exhaustive across multiple pages.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

try:
    import numpy as np
except ImportError:
    print("SKIP: numpy not installed ([cluster] extra); streaming test needs it")
    sys.exit(0)

from enrich.sources.cowrie.assign_runner import (
    _iter_scan,
    _sb,
    _scan,
    _scan_window_embeddings,
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


def _src(emb, cmdset):
    return {"dshield": {"cowrie": {"enrichment": {"session": {
        "embedding": emb, "command_set": cmdset}}}}}


def _hit(i, emb, cmdset):
    # sort key mirrors {"_doc":"asc"} search_after cursor semantics
    return {"_id": f"s{i}", "_source": _src(emb, cmdset), "sort": [i]}


class MockES:
    """Serves a fixed hit list in `size`-sized pages via search_after on `sort`.
    Counts searches so we can assert the scan pages rather than one huge fetch."""

    def __init__(self, hits):
        self._hits = hits
        self.searches = 0

    def search(self, index, **body):
        self.searches += 1
        size = body["size"]
        after = body.get("search_after")
        start = 0
        if after is not None:
            # first hit whose sort is strictly greater than the cursor
            start = next((k for k, h in enumerate(self._hits)
                          if h["sort"] > after), len(self._hits))
        page = self._hits[start:start + size]
        return {"hits": {"hits": page}}


# Fixture: 5 docs; s2 has NO embedding (must be dropped, like the old `keep`).
raw = [
    _hit(0, [1.0, 0.0, 0.0], ["h1", "h2"]),
    _hit(1, [0.0, 2.0, 0.0], ["h3"]),
    _hit(2, None, ["h9"]),            # dropped — no embedding
    _hit(3, [0.0, 0.0, 4.0], []),     # empty command_set
    _hit(4, [3.0, 4.0, 0.0], ["h1"]),
]
idx, filt, fields = "prism.rollup.cowrie.session", [{"match_all": {}}], ["e", "c"]


# --- reference: the old list-materialize + keep logic, verbatim ---
def _reference(hits):
    win = list(hits)
    ids = [h["_id"] for h in win]
    emb_raw = [_sb(h["_source"]).get("embedding") for h in win]
    keep = [i for i, e in enumerate(emb_raw) if e]
    ids = [ids[i] for i in keep]
    sets = [list(_sb(win[i]["_source"]).get("command_set") or []) for i in keep]
    W = np.array([emb_raw[i] for i in keep], dtype=np.float32)
    n = np.linalg.norm(W, axis=1, keepdims=True)
    return ids, sets, W / np.where(n == 0.0, 1.0, n)


ref_ids, ref_sets, ref_W = _reference(raw)

# --- streamed (page=2 forces multi-page paging) + small chunk to force flushes ---
es = MockES(raw)
win_ids, win_sets, W = _scan_window_embeddings(
    es, idx, filt, fields, chunk=2)

check("win_ids equals reference (s2 dropped)", win_ids == ref_ids,
      f"{win_ids} != {ref_ids}")
check("win_ids is exactly the embedding-bearing docs",
      win_ids == ["s0", "s1", "s3", "s4"], str(win_ids))
check("win_sets equals reference", win_sets == ref_sets,
      f"{win_sets} != {ref_sets}")
check("W dtype is float32", W.dtype == np.float32, str(W.dtype))
check("W equals reference (byte-identical, L2-normalized)",
      np.array_equal(W, ref_W), f"{W}\n!=\n{ref_W}")
check("W row count matches kept docs", W.shape[0] == 4, str(W.shape))

# --- _iter_scan / _scan exhaustiveness + paging (bounded caller unchanged) ---
es2 = MockES(raw)
all_ids = [h["_id"] for h in _iter_scan(es2, idx, filt, fields, page=2)]
check("_iter_scan yields every hit across pages",
      all_ids == ["s0", "s1", "s2", "s3", "s4"], str(all_ids))
check("_iter_scan actually paged (>1 search for 5 docs @ size=2)",
      es2.searches >= 3, f"searches={es2.searches}")

es3 = MockES(raw)
limited = _scan(es3, idx, filt, fields, page=2, limit=3)
check("_scan honors limit (bounded anchor caller)",
      [h["_id"] for h in limited] == ["s0", "s1", "s2"], str(limited))

es4 = MockES([])
eids, esets, eW = _scan_window_embeddings(es4, idx, filt, fields)
check("empty scan → empty ids/sets and W is None",
      eids == [] and esets == [] and eW is None, f"{eids},{esets},{eW}")

es5 = MockES([_hit(0, None, ["x"]), _hit(1, None, ["y"])])
nids, _, nW = _scan_window_embeddings(es5, idx, filt, fields)
check("all-embedding-less scan → empty (no sessions in window)",
      nids == [] and nW is None, f"{nids},{nW}")

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
