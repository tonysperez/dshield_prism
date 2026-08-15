"""Smoke test for the Option-A assignment core
(`src/enrich/sources/cowrie/assignment.py`): classify_status, resolve (the TF-IDF
band logic), assign_batch. No ES.

tau=0.94, confident_tau=0.98, tfidf_tau=0.80 throughout.

Standalone — no pytest.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.sources.cowrie.assignment import (
    ASSIGNED,
    BAND,
    NOVEL,
    assign_batch,
    classify_status,
    is_novel,
    resolve,
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


T = dict(tau=0.94, confident_tau=0.98)

# --- classify_status (pre-secondary) ---
check("0.99 → ASSIGNED (confident)", classify_status(0.99, **T) == ASSIGNED)
check("0.96 → BAND", classify_status(0.96, **T) == BAND)
check("0.90 → NOVEL", classify_status(0.90, **T) == NOVEL)
check("exactly tau (0.94) → BAND", classify_status(0.94, **T) == BAND)
check("exactly confident_tau (0.98) → ASSIGNED", classify_status(0.98, **T) == ASSIGNED)

# --- resolve (the band TF-IDF decision) ---
R = dict(tau=0.94, confident_tau=0.98, tfidf_tau=0.80)
check("confident 0.99 ignores tfidf → ASSIGNED", resolve(0.99, 0.1, **R) == ASSIGNED)
check("below tau 0.90 → NOVEL", resolve(0.90, 0.99, **R) == NOVEL)
check("band 0.96 + tfidf 0.85 → ASSIGNED (confirmed)", resolve(0.96, 0.85, **R) == ASSIGNED)
check("band 0.96 + tfidf 0.66 → NOVEL (conflation rejected)", resolve(0.96, 0.66, **R) == NOVEL)
check("band 0.96 + tfidf None → ASSIGNED (degraded, trust embedding)",
      resolve(0.96, None, **R) == ASSIGNED)
check("band 0.96 + tfidf None + defer_band → BAND (forward defers)",
      resolve(0.96, None, defer_band=True, **R) == BAND)
check("confident 0.99 + defer_band still ASSIGNED",
      resolve(0.99, None, defer_band=True, **R) == ASSIGNED)
check("below-tau 0.90 + defer_band still NOVEL",
      resolve(0.90, None, defer_band=True, **R) == NOVEL)


def _vec(cos: float) -> list[float]:
    return [cos, 0.0, math.sqrt(max(0.0, 1.0 - cos * cos)), 0.0]


# --- assign_batch end-to-end ---
anchor_emb = np.array([[1, 0, 0, 0], [0, 1, 0, 0]], dtype=np.float32)  # A=e0, B=e1
anchor_ids = ["spb-A", "spb-B"]
emb = np.array([_vec(1.00), _vec(0.96), _vec(0.96), _vec(0.90)], dtype=np.float32)
# band sessions are rows 1,2; supply their TF-IDF cosine to the nearest anchor
tfidf_lookup = {1: 0.85, 2: 0.50}
res = assign_batch(emb, anchor_emb, anchor_ids, tau=0.94, confident_tau=0.98,
                   tfidf_tau=0.80, tfidf_cos=lambda i, a: tfidf_lookup.get(i))

check("S1 (cos 1.0) → ASSIGNED spb-A",
      res[0].status == ASSIGNED and res[0].playbook_id == "spb-A", str(res[0]))
check("S2 (band, tfidf 0.85) → ASSIGNED + confirmed_in_band",
      res[1].status == ASSIGNED and res[1].playbook_id == "spb-A"
      and res[1].confirmed_in_band and res[1].tfidf_cosine == 0.85, str(res[1]))
check("S3 (band, tfidf 0.50) → NOVEL, no playbook",
      res[2].status == NOVEL and res[2].playbook_id is None, str(res[2]))
check("S4 (cos 0.90) → NOVEL", res[3].status == NOVEL and res[3].playbook_id is None, str(res[3]))
check("tfidf_cos NOT consulted for confident/novel rows (only band)",
      res[0].tfidf_cosine is None and res[3].tfidf_cosine is None)
check("is_novel predicate", is_novel(res[2]) and is_novel(res[3])
      and not is_novel(res[0]) and not is_novel(res[1]))
check("confident/band winners have cascade_rank 0",
      res[0].cascade_rank == 0 and res[1].cascade_rank == 0)

# --- band_trace (item 34): opt-in, byte-identical when unset ---
res_no_trace = assign_batch(emb, anchor_emb, anchor_ids, tau=0.94, confident_tau=0.98,
                            tfidf_tau=0.80, tfidf_cos=lambda i, a: tfidf_lookup.get(i))
check("band_trace=None (default) leaves output byte-identical",
      [(a.status, a.playbook_id, a.tfidf_cosine) for a in res_no_trace]
      == [(a.status, a.playbook_id, a.tfidf_cosine) for a in res])

trace: list[dict] = []
res_traced = assign_batch(emb, anchor_emb, anchor_ids, tau=0.94, confident_tau=0.98,
                          tfidf_tau=0.80, tfidf_cos=lambda i, a: tfidf_lookup.get(i),
                          band_trace=trace)
check("band_trace unaffects output vs untraced call",
      [(a.status, a.playbook_id) for a in res_traced] == [(a.status, a.playbook_id) for a in res])
check("band_trace collects one row per band check attempted (S2 confirm + S3 reject)",
      len(trace) == 2, str(trace))
check("band_trace rows carry emb_cos/tfidf_cos/confirmed",
      {"emb_cos", "tfidf_cos", "confirmed"} <= trace[0].keys())
check("band_trace confirmed flags match the resolved outcomes",
      sorted(row["confirmed"] for row in trace) == [False, True], str(trace))


# --- 2nd-nearest cascade: nearest is a band-rejected conflation, true home is farther ---
def _ang(deg: float) -> list[float]:
    r = math.radians(deg)
    return [math.cos(r), math.sin(r)]


anc2 = np.array([_ang(0), _ang(28)], dtype=np.float32)  # A at 0°, B at 28° (cos≈0.88 apart)
ids2 = ["spb-A", "spb-B"]
S = np.array([_ang(13)], dtype=np.float32)  # cos→A 0.974 (band, nearest), cos→B 0.966 (band)

# nearest A band-REJECTS (tfidf 0.5), 2nd B band-CONFIRMS (tfidf 0.85) → cascade to B
casc = assign_batch(S, anc2, ids2, tau=0.94, confident_tau=0.98, tfidf_tau=0.80,
                    tfidf_cos=lambda i, a: {(0, 0): 0.5, (0, 1): 0.85}[(i, a)])[0]
check("cascade: nearest conflation skipped, assigned 2nd-nearest spb-B",
      casc.status == ASSIGNED and casc.playbook_id == "spb-B", str(casc))
check("cascade: cascade_rank == 1 + confirmed_in_band", casc.cascade_rank == 1
      and casc.confirmed_in_band, str(casc))

casc_trace: list[dict] = []
assign_batch(S, anc2, ids2, tau=0.94, confident_tau=0.98, tfidf_tau=0.80,
            tfidf_cos=lambda i, a: {(0, 0): 0.5, (0, 1): 0.85}[(i, a)],
            band_trace=casc_trace)
check("band_trace records the cascaded-past rejection too (both anchors checked)",
      len(casc_trace) == 2 and sorted(row["confirmed"] for row in casc_trace) == [False, True],
      str(casc_trace))

# both band anchors reject → NOVEL (cosine reported is the nearest)
both_rej = assign_batch(S, anc2, ids2, tau=0.94, confident_tau=0.98, tfidf_tau=0.80,
                        tfidf_cos=lambda i, a: 0.5)[0]
check("cascade: both reject → NOVEL with nearest cosine",
      both_rej.status == NOVEL and both_rej.cosine == 0.9744, str(both_rej))

# confident nearest → no cascade, no tfidf consulted
conf = assign_batch(np.array([_ang(5)], dtype=np.float32), anc2, ids2, tau=0.94,
                    confident_tau=0.98, tfidf_tau=0.80,
                    tfidf_cos=lambda i, a: 0.0)[0]
check("confident nearest assigned at rank 0 without tfidf",
      conf.status == ASSIGNED and conf.playbook_id == "spb-A"
      and conf.cascade_rank == 0 and conf.tfidf_cosine is None, str(conf))

# forward pass: defer_band leaves band sessions pending on their nearest anchor
fwd = assign_batch(emb, anchor_emb, anchor_ids, tau=0.94, confident_tau=0.98,
                   tfidf_tau=0.80, tfidf_cos=None, defer_band=True)
check("forward: confident S1 → ASSIGNED", fwd[0].status == ASSIGNED)
check("forward: band S2 → BAND pending on nearest anchor (provisional spb-A)",
      fwd[1].status == BAND and fwd[1].playbook_id == "spb-A", str(fwd[1]))
check("forward: below-tau S4 → NOVEL", fwd[3].status == NOVEL)

# empty anchor library → everything novel
empty = assign_batch(emb, np.zeros((0, 4), dtype=np.float32), [], tau=0.94,
                     confident_tau=0.98, tfidf_tau=0.80)
check("empty anchor library → all NOVEL", all(a.status == NOVEL for a in empty) and len(empty) == 4)

# --- item 30: below-tau structural-predicate rescue tier ---
FIRES = {"key_write_immutability": True}
ALL_FALSE = {"key_write_immutability": False}
RESCUE_ANCHOR_SIG = {"key_write_immutability": 0.8}   # modal on the anchor
NO_SIG = {"key_write_immutability": 0.0}

# S4 (cos 0.90) is below tau (0.94) but above a lowered rescue_tau (0.85); positive
# overlap on both sides -> rescued to ASSIGNED on its nearest anchor (spb-A).
rescued = assign_batch(
    emb, anchor_emb, anchor_ids, tau=0.94, confident_tau=0.98, tfidf_tau=0.80,
    tfidf_cos=lambda i, a: tfidf_lookup.get(i), rescue_tau=0.85,
    session_predicates=[None, None, None, FIRES],
    anchor_predicate_signatures=[RESCUE_ANCHOR_SIG, NO_SIG],
)
check("rescue: below-tau session with positive overlap -> ASSIGNED + rescued=True",
      rescued[3].status == ASSIGNED and rescued[3].playbook_id == "spb-A"
      and rescued[3].rescued is True, str(rescued[3]))
check("rescue: non-rescued rows unaffected (S1/S2/S3 identical to the no-rescue call)",
      [(a.status, a.playbook_id, a.rescued) for a in rescued[:3]]
      == [(a.status, a.playbook_id, False) for a in res[:3]], str(rescued[:3]))

# same session, no predicate overlap -> stays NOVEL even though cosine clears rescue_tau
no_overlap = assign_batch(
    emb, anchor_emb, anchor_ids, tau=0.94, confident_tau=0.98, tfidf_tau=0.80,
    tfidf_cos=lambda i, a: tfidf_lookup.get(i), rescue_tau=0.85,
    session_predicates=[None, None, None, ALL_FALSE],
    anchor_predicate_signatures=[RESCUE_ANCHOR_SIG, NO_SIG],
)
check("rescue: below-tau session with NO overlap -> stays NOVEL",
      no_overlap[3].status == NOVEL and no_overlap[3].playbook_id is None
      and no_overlap[3].rescued is False, str(no_overlap[3]))

# all-false session vector against a fully-modal anchor signature must never rescue
# (constraint 2: never rescue on an all-false match on either side)
all_false_sess = assign_batch(
    emb, anchor_emb, anchor_ids, tau=0.94, confident_tau=0.98, tfidf_tau=0.80,
    tfidf_cos=lambda i, a: tfidf_lookup.get(i), rescue_tau=0.85,
    session_predicates=[None, None, None, {"key_write_immutability": False}],
    anchor_predicate_signatures=[{"key_write_immutability": 1.0}, NO_SIG],
)
check("rescue: all-false session vector never rescues, even vs a fully-modal anchor",
      all_false_sess[3].status == NOVEL, str(all_false_sess[3]))

# below rescue_tau entirely -> stays NOVEL, cascade still breaks (no rescue attempted)
below_rescue = assign_batch(
    np.array([_vec(0.80)], dtype=np.float32), anchor_emb, anchor_ids,
    tau=0.94, confident_tau=0.98, tfidf_tau=0.80, rescue_tau=0.85,
    session_predicates=[FIRES], anchor_predicate_signatures=[RESCUE_ANCHOR_SIG, NO_SIG],
)
check("rescue: cosine below rescue_tau -> stays NOVEL despite matching predicates",
      below_rescue[0].status == NOVEL and below_rescue[0].rescued is False,
      str(below_rescue[0]))

# combined band-reject-then-rescue path: the nearest anchor is a BAND-tier cosine that
# gets TF-IDF-rejected (falls through, per the ordinary cascade), and the farther
# anchor is below tau but gets rescued via predicate overlap (cascade_rank >= 1).
anc3 = np.array([_ang(0), _ang(40)], dtype=np.float32)  # A at 0°, B at 40°
ids3 = ["spb-A", "spb-B"]
S3 = np.array([_ang(15)], dtype=np.float32)  # cos->A 0.9659 (band); cos->B 0.9063 (below
                                              # tau=0.94, above rescue_tau=0.85)
band_reject_then_rescue = assign_batch(
    S3, anc3, ids3, tau=0.94, confident_tau=0.98, tfidf_tau=0.80,
    tfidf_cos=lambda i, a: {(0, 0): 0.5}[(i, a)],  # nearest (A) band-rejected
    rescue_tau=0.85,
    session_predicates=[FIRES],
    anchor_predicate_signatures=[NO_SIG, RESCUE_ANCHOR_SIG],
)[0]
check("cascade: nearest BAND anchor TF-IDF-rejected, farther below-tau anchor rescued "
      "via predicate overlap -> ASSIGNED to spb-B",
      band_reject_then_rescue.status == ASSIGNED
      and band_reject_then_rescue.playbook_id == "spb-B", str(band_reject_then_rescue))
check("cascade: band-reject-then-rescue lands at cascade_rank >= 1 with rescued=True",
      band_reject_then_rescue.cascade_rank >= 1 and band_reject_then_rescue.rescued is True,
      str(band_reject_then_rescue))

# feature-off: rescue_tau == tau (explicit) must be byte-identical to no rescue args
feature_off = assign_batch(
    emb, anchor_emb, anchor_ids, tau=0.94, confident_tau=0.98, tfidf_tau=0.80,
    tfidf_cos=lambda i, a: tfidf_lookup.get(i), rescue_tau=0.94,
    session_predicates=[None, None, None, FIRES],
    anchor_predicate_signatures=[RESCUE_ANCHOR_SIG, NO_SIG],
)
check("rescue: rescue_tau == tau is a no-op, byte-identical to the plain call",
      [(a.status, a.playbook_id, a.cosine, a.rescued) for a in feature_off]
      == [(a.status, a.playbook_id, a.cosine, False) for a in res], str(feature_off))

# feature-off: rescue_tau omitted entirely (default None) is likewise byte-identical,
# even with predicate data supplied — the hard regression bar from spec-30.
default_off = assign_batch(
    emb, anchor_emb, anchor_ids, tau=0.94, confident_tau=0.98, tfidf_tau=0.80,
    tfidf_cos=lambda i, a: tfidf_lookup.get(i),
    session_predicates=[None, None, None, FIRES],
    anchor_predicate_signatures=[RESCUE_ANCHOR_SIG, NO_SIG],
)
check("rescue: rescue_tau omitted (default) byte-identical to the pre-item-30 call",
      [(a.status, a.playbook_id, a.cosine, a.tfidf_cosine, a.confirmed_in_band,
        a.cascade_rank, a.band_checks, a.band_rejections) for a in default_off]
      == [(a.status, a.playbook_id, a.cosine, a.tfidf_cosine, a.confirmed_in_band,
           a.cascade_rank, a.band_checks, a.band_rejections) for a in res],
      str(default_off))
check("rescue: every Assignment defaults rescued=False when the tier never fires",
      all(a.rescued is False for a in default_off))

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
