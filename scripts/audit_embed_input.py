"""Audit what production actually feeds to ``llm.embed()``.

Per the embedding-quality plan E0.3: sample N commands from the eval set
and print the exact string ``_build_embed_text`` returns for each one,
plus character-count + token-shape summaries. Lets a human sanity-check:

  * Is the LLM-enrichment prelude dominating the raw command in length?
  * Are MITRE IDs (``TAxxxx`` / ``Txxxx``) prepended as bare token
    noise the embedder probably can't ground?
  * Is the enrichment description ever empty / wildly off-topic?

The script reconstructs the production ``embed_context`` config and
calls the real ``_build_embed_text`` so output is byte-identical to
what shipped — minus the cooccurrence-siblings block, which is built
from a runtime ES query and can't be reproduced offline. The audit
flags that omission explicitly in the header.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/audit_embed_input.py
"""
from __future__ import annotations

import argparse
import json
import random
import re
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.config import load_config
from enrich.llm.schemas import CommandEnrichment
from enrich.sources.cowrie.commands import _build_embed_text


# Matches the literal MITRE prefixes we'd prepend to the embed text via
# `embed_context`. We use it to count how many samples carry these
# opaque tokens — Nomic was trained on natural text, not on
# `TA0007`/`T1059.004` literals, so each ID is likely a single
# under-represented token that contributes mostly noise to the vector.
_MITRE_RE = re.compile(r"\b(TA\d{4}|T\d{4}(?:\.\d{3})?)\b")


def _iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def _enrichment_to_model(ce_doc: dict) -> CommandEnrichment | None:
    """Map a persisted ``prism.enriched.cowrie.command`` doc back to the
    in-memory ``CommandEnrichment`` shape that ``_build_embed_text``
    expects. Returns None when the doc lacks the load-bearing fields
    (intent + description) — those samples are uninformative for the
    audit."""
    enr = (
        (((ce_doc.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {})
    )
    threat = ce_doc.get("threat") or {}
    description = (ce_doc.get("event") or {}).get("reason") or ""
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


def _collect_commands(
    jsonl_path: Path,
    label_session_ids: set[str] | None,
) -> list[dict]:
    """Walk the eval JSONL once and emit one dict per **unique** command
    string (dedup is by ``process.command_line`` since the same command
    can appear in many sessions). Each dict carries the command, the
    parsed enrichment, and the session id we first saw it in."""
    seen_cmds: set[str] = set()
    out: list[dict] = []
    for rec in _iter_jsonl(jsonl_path):
        sid = rec.get("session_id")
        if label_session_ids is not None and sid not in label_session_ids:
            continue
        for ce_doc in rec.get("command_enrichments") or []:
            cmd = ((ce_doc.get("process") or {}).get("command_line")) or ""
            if not cmd or cmd in seen_cmds:
                continue
            parsed = _enrichment_to_model(ce_doc)
            if parsed is None:
                continue
            seen_cmds.add(cmd)
            out.append({
                "session_id": sid,
                "command":    cmd,
                "parsed":     parsed,
            })
    return out


def _render_one(idx: int, sample: dict, embed_text: str, fields_meta: dict) -> str:
    out: list[str] = []
    out.append(f"[{idx:02d}]  session={sample['session_id']}")
    out.append(f"      command ({len(sample['command'])} chars):")
    out.append(f"        {sample['command']}")
    p = sample["parsed"]
    out.append(f"      intent={p.intent}  tactics={p.tactics}  techniques={p.techniques}")
    desc = p.description.replace("\n", " ⏎ ")
    if len(desc) > 200:
        desc = desc[:199] + "…"
    out.append(f"      description: {desc}")
    out.append(
        f"      embed-text totals: total={fields_meta['total_chars']}  "
        f"command={fields_meta['cmd_chars']}  "
        f"prelude={fields_meta['head_chars']}  "
        f"prelude/command={fields_meta['ratio']:.2f}"
    )
    mitre_hits = fields_meta["mitre_token_count"]
    if mitre_hits:
        out.append(f"      MITRE-ID tokens in embed text: {mitre_hits}")
    out.append("      ─── embed text fed to llm.embed() ───")
    for line in embed_text.splitlines() or [""]:
        out.append(f"      | {line}")
    return "\n".join(out)


def _measure(embed_text: str, command: str) -> dict:
    total = len(embed_text)
    # _build_embed_text writes "<head>\nCommand: <command>" when any
    # context field fired. When all fields were empty, embed_text ==
    # command. Distinguish the two by looking for the trailer.
    trailer = f"\nCommand: {command}"
    if embed_text.endswith(trailer):
        head_chars = total - len(trailer)
    else:
        head_chars = 0
    cmd_chars = len(command)
    ratio = (head_chars / cmd_chars) if cmd_chars else 0.0
    return {
        "total_chars": total,
        "head_chars":  head_chars,
        "cmd_chars":   cmd_chars,
        "ratio":       ratio,
        "mitre_token_count": len(_MITRE_RE.findall(embed_text)),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--jsonl", type=Path,
                    default=Path("eval/sessions-v1.unlabeled.jsonl"))
    ap.add_argument("--labels", type=Path,
                    default=Path("eval/labels-v1.yaml"),
                    help=(
                        "If set, restrict the audit to commands seen in "
                        "labeled-real sessions. Default = whole eval JSONL."
                    ))
    ap.add_argument("--restrict-to-labeled", action="store_true",
                    help="Only sample from labeled-real sessions in --labels.")
    ap.add_argument("--n", type=int, default=20,
                    help="Number of unique commands to sample.")
    ap.add_argument("--seed", type=int, default=20260601)
    args = ap.parse_args()

    cfg = load_config()
    embed_context = list(cfg.llm.embed_context or [])

    label_session_ids: set[str] | None = None
    if args.restrict_to_labeled:
        # Lazy-load labels only when the flag is set so the default
        # invocation (whole JSONL) doesn't depend on the labels file.
        import yaml
        label_data = yaml.safe_load(args.labels.read_text(encoding="utf-8")) or {}
        label_session_ids = {
            sid for sid, block in label_data.items()
            if isinstance(block, dict) and block.get("annotated") and block.get("is_real")
        }

    pool = _collect_commands(args.jsonl, label_session_ids)
    if not pool:
        print("No commands found with parsed enrichment.", file=sys.stderr)
        return 1

    rng = random.Random(args.seed)
    sample_size = min(args.n, len(pool))
    samples = rng.sample(pool, sample_size)

    print("=" * 78)
    print("Audit — what production feeds to llm.embed()")
    print("=" * 78)
    print(f"pool size                 {len(pool)} unique commands")
    print(f"sampled                   {sample_size}  seed={args.seed}")
    print(f"llm.embed_context         {embed_context}")
    print(f"llm.embedding_model       {cfg.llm.embedding_model}")
    print(f"NOTE: cooccurrence siblings are runtime-only (ES-derived) and are")
    print(f"      NOT reproduced here. Production embed text in cluster runs")
    print(f"      with cooccurrence.embed_cooccurrence=true appends an extra")
    print(f"      'co-occurs with: ...' line — this audit shows everything")
    print(f"      else byte-for-byte.")
    print()

    per_sample_meta: list[dict] = []
    for idx, sample in enumerate(samples, start=1):
        embed_text = _build_embed_text(
            sample["command"],
            sample["parsed"],
            embed_context,
            cooccurring=None,
            embed_cooccurrence=False,
        )
        meta = _measure(embed_text, sample["command"])
        per_sample_meta.append(meta)
        print(_render_one(idx, sample, embed_text, meta))
        print()

    # Summary stats — what the analyst is meant to take away.
    ratios = [m["ratio"] for m in per_sample_meta]
    dominated = sum(1 for r in ratios if r > 1.0)
    mitre_counts = [m["mitre_token_count"] for m in per_sample_meta]
    samples_with_mitre = sum(1 for c in mitre_counts if c > 0)

    print("-" * 78)
    print("Summary")
    print("-" * 78)
    print(f"  prelude/command ratio:  "
          f"min={min(ratios):.2f}  "
          f"median={statistics.median(ratios):.2f}  "
          f"mean={statistics.mean(ratios):.2f}  "
          f"max={max(ratios):.2f}")
    print(f"  samples where prelude > command:  {dominated}/{sample_size}")
    print(f"  samples carrying ≥1 MITRE-ID token:  {samples_with_mitre}/{sample_size}")
    print(f"  total MITRE-ID tokens across sample: {sum(mitre_counts)}")
    print()
    print("Reader notes:")
    print("  * Prelude/command >> 1 means the enrichment text dominates the")
    print("    embedding signal — the command itself is a minor share of input.")
    print("  * MITRE IDs are short opaque alphanumerics. Nomic was not")
    print("    trained on them as IDs, so each contributes near-noise. If a")
    print("    high share of samples carry them, that's tokens spent on")
    print("    nothing the embedder can ground.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
