"""Regression guard: the cowrie CLI layer must import without numpy installed.

`cli.py:_load_source_layer` imports `commands, sessions, ips, campaigns` for EVERY
cowrie verb. If anything in that chain pulls numpy at module scope, every verb dies
with `ModuleNotFoundError: No module named 'numpy'` on a lean deployment — including
verbs that do no vector math at all (`backfill-predicates`, `backfill-shape`, the
enrich/rollup verbs).

That regression shipped once: item 30/51 added a module-level `import numpy as np` to
`lexical.py`, and item 51 added `sessions.py -> from .lexical import
build_session_predicate_vectors`, which together made numpy a hard dependency of the
whole CLI. `clustering.py` and `assignment.py:assign_batch` both deliberately keep
numpy function-scoped for this reason.

Runs the import in a SUBPROCESS with numpy blocked by a meta_path hook. A subprocess
is required, not just convenient: numpy's C extension cannot be unloaded and
re-imported inside one process ("cannot load module more than once per process"), so
an in-process `sys.modules` swap corrupts numpy for every later test in the run.
Offline, no ES.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]

# The modules `cli.py:_load_source_layer` pulls in for every cowrie verb, plus the
# two that carried the regression.
_CHAIN = (
    "enrich.clustering",
    "enrich.sources.cowrie.predicates",
    "enrich.sources.cowrie.lexical",
    "enrich.sources.cowrie.commands",
    "enrich.sources.cowrie.sessions",
    "enrich.sources.cowrie.ips",
    "enrich.sources.cowrie.campaigns",
)

# Child program: block numpy, then import the chain. Prints OK or FAIL:<reason>.
_CHILD = """
import importlib, sys

class Blocker:
    # `find_spec` is required: the legacy `find_module`/`load_module` finder API was
    # REMOVED in Python 3.12, so a find_module-based blocker is silently ignored and
    # the test passes vacuously against real numpy. The blocker-effectiveness probe
    # below exists because exactly that happened while writing this test.
    def find_spec(self, name, path=None, target=None):
        if name == "numpy" or name.startswith("numpy."):
            raise ImportError("No module named %r (simulated lean deployment)" % name)
        return None

sys.meta_path.insert(0, Blocker())
sys.path.insert(0, {src!r})

# Prove the blocker works, so a pass below cannot be vacuous.
try:
    importlib.import_module("numpy")
except ImportError:
    pass
else:
    print("FAIL:blocker-ineffective")
    raise SystemExit(0)

for mod in {chain!r}:
    try:
        importlib.import_module(mod)
    except ImportError as exc:
        print("FAIL:%s: %s" % (mod, exc))
        raise SystemExit(0)
print("OK")
"""

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


proc = subprocess.run(
    [sys.executable, "-c", _CHILD.format(src=str(_REPO / "src"), chain=_CHAIN)],
    capture_output=True, text=True, cwd=_REPO, timeout=180,
)
out = (proc.stdout or "").strip()
err = (proc.stderr or "").strip()[-400:]

check("subprocess ran cleanly", proc.returncode == 0, f"rc={proc.returncode} {err}")
check("cowrie CLI layer imports with numpy unavailable",
      out.endswith("OK"), out or err)

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
