"""Analyst-authored artifact extraction rules (ROADMAP #5).

Rules live in the `prism.analyst.artifact_rules` index, are authored via the
console, and emit matches into command enrichment docs (the
`dshield.cowrie.enrichment.analyst_artifacts` block) and into session rollup
`artifact_set` strings (`analyst:<kind>:<value>`).

Public API is exported from `artifact_rules`.
"""
from . import artifact_rules  # noqa: F401
