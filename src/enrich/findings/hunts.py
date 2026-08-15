"""Hypothesis-driven hunts.

A "hunt" is an analyst-authored YAML query against the session rollup
index that emits ``kind=analyst_hunt`` findings into ``prism.finding``.
The execution shape is deliberately small: a hunt is a list of
**filters** (AND-combined) plus a name and id; matching sessions
produce one finding per (hunt, session) pair.

The point is the *workflow*: analysts pursue hypotheses ("show me
sessions that touched these persistence vectors in the last 7 days")
without writing Elasticsearch queries by hand. The seed library in
``config/hunts/`` covers the standing-question cases.

Hunt findings differ from discovery / drift findings in two ways:

1. **Anchor on the session, not the playbook**. A session matching
   a hunt is the unit of analyst review — the playbook the session
   belongs to is incidental.
2. **The hunt is the delta signature**. Two hunts firing on the same
   session produce two distinct findings (one per hunt). The
   writer's ``delta_signature`` slot carries the ``hunt_id``.

Hunt YAML schema:

    id: persistence-touched
    name: "Persistence vectors touched"
    description: "Sessions that touched any standard Linux persistence vector"
    filters:
      - kind: artifact_set_contains_any
        values: [crontab, authorized_keys, systemctl, "chattr +i"]
      - kind: window
        last_days: 7
    enabled: false  # optional; default true

``enabled`` gates **writing findings**, not loading. Every valid hunt
is loaded, listed, and executable regardless of the flag — a disabled
hunt simply never contributes to ``prism.finding``. That distinction
is what makes the console toggle possible: a hunt you cannot see is a
hunt you cannot turn back on. Analysts run a disabled hunt through
``preview_hunt`` to see what it *would* match, and flip it on only
once the hypothesis is worth persisting.

The shipped seed hunts in ``config/hunts/`` are all ``enabled: false``.
A hunt file that omits the key entirely still defaults to ``true``, so
an operator's hand-written hunts keep firing across an upgrade.

Supported filter kinds:

    artifact_set_contains_any   values: list[str]
    artifact_set_contains_all   values: list[str]
    intent_in                   values: list[str]
    command_count_gte           threshold: int
    login_fail_count_gte        threshold: int
    external_match_cosine_gte   threshold: float  (uses 5.9's per-session field)
    window                      last_days: int    (event.start >= now - N days,
                                                   1..3650)
"""
from __future__ import annotations

import contextlib
import logging
import os
import re
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from elasticsearch import Elasticsearch

log = logging.getLogger(__name__)

# The process umask, read once at import — reading it is a get-and-set, so
# doing it per write would briefly clear the umask for every other thread
# in the process (uvicorn runs sync routes in a threadpool). Import time is
# single-threaded, so this is the one safe moment to look.
_UMASK = os.umask(0)
os.umask(_UMASK)


# Field paths on `prism.rollup.cowrie.session` — kept in one place so
# the hunt loader doesn't have to know where each value lives.
_F_ARTIFACT_SET   = "dshield.cowrie.enrichment.session.artifact_set.keyword"
_F_INTENT         = "dshield.cowrie.enrichment.session.dominant_intent"
_F_COMMAND_COUNT  = "dshield.cowrie.enrichment.session.command_count"
_F_LOGIN_FAILS    = "dshield.cowrie.enrichment.session.login_fail_count"
_F_EXT_COSINE     = "dshield.cowrie.enrichment.session.cluster.external_match_cosine"
_F_TS             = "event.start"

# Bounded by ES default max — hunts that match more than this many
# sessions per run silently truncate. Operator sees the number in the
# stats dict and can refine.
_MAX_FINDINGS_PER_HUNT = 500

# Upper bound on `window.last_days`. Without it a hand-written `last_days:
# 10**12` validates, then `timedelta` raises OverflowError deep inside
# `_filter_to_es_clause` — outside preview's try block, so the page 500s
# and `mine hunts` errors until someone edits the YAML by hand.
_MAX_LAST_DAYS = 3650          # 10 years


def _str_values(f: dict, *, hunt_id: str, idx: int, kind: str, msg: str) -> None:
    """Require `values` to be a non-empty list of non-empty strings.
    A member that isn't a string validates fine here but blows up at ES
    time, long after the analyst has left the editor."""
    values = f.get("values")
    if not isinstance(values, list) or not values:
        raise ValueError(f"hunt {hunt_id!r} filter[{idx}] ({kind}): {msg}")
    if any(not isinstance(v, str) or not v for v in values):
        raise ValueError(
            f"hunt {hunt_id!r} filter[{idx}] ({kind}): `values` must "
            "be a non-empty list of strings"
        )


def _validate_filter(f: dict, *, hunt_id: str, idx: int) -> None:
    """Raise ValueError when a filter clause is malformed. Catches typos
    early — a hunt with one bad filter shouldn't half-run silently."""
    if not isinstance(f, dict):
        raise ValueError(f"hunt {hunt_id!r} filter[{idx}]: not a mapping")
    kind = f.get("kind")
    if kind == "artifact_set_contains_any" or kind == "artifact_set_contains_all":
        _str_values(f, hunt_id=hunt_id, idx=idx, kind=kind,
                    msg="`values` must be a non-empty list of strings")
    elif kind == "intent_in":
        _str_values(f, hunt_id=hunt_id, idx=idx, kind=kind,
                    msg="`values` required")
    elif kind in ("command_count_gte", "login_fail_count_gte"):
        t = f.get("threshold")
        # `isinstance(True, int)` is True — a `threshold: true` would
        # silently mean 1.
        if isinstance(t, bool) or not isinstance(t, int) or t < 0:
            raise ValueError(
                f"hunt {hunt_id!r} filter[{idx}] ({kind}): `threshold` "
                "must be a non-negative int"
            )
    elif kind == "external_match_cosine_gte":
        t = f.get("threshold")
        if (isinstance(t, bool) or not isinstance(t, (int, float))
                or not (0.0 <= float(t) <= 1.0)):
            raise ValueError(
                f"hunt {hunt_id!r} filter[{idx}] ({kind}): `threshold` "
                "must be a float in [0, 1]"
            )
    elif kind == "window":
        d = f.get("last_days")
        if (isinstance(d, bool) or not isinstance(d, int)
                or not (0 < d <= _MAX_LAST_DAYS)):
            raise ValueError(
                f"hunt {hunt_id!r} filter[{idx}] ({kind}): `last_days` "
                f"must be a positive int <= {_MAX_LAST_DAYS}"
            )
    else:
        raise ValueError(
            f"hunt {hunt_id!r} filter[{idx}]: unknown filter kind {kind!r}"
        )


# YAML strings that mean "off". A bare `enabled: false` parses to a bool,
# but a quoted `enabled: "false"` — which config templating tools emit
# routinely — parses to a truthy *string*. `bool("false")` is True, so a
# naive coercion silently runs a hunt the operator switched off. That is
# the exact failure `--include-disabled` is gated to prevent, so refuse
# the ambiguity rather than guessing.
_FALSY_STR = frozenset({"false", "no", "off", "0", ""})
_TRUTHY_STR = frozenset({"true", "yes", "on", "1"})


def _coerce_enabled(value: Any, hunt_id: str) -> bool:
    if value is None:
        # A bare `enabled:` with no value parses to None. Treat it like
        # an absent key rather than aborting the whole directory load.
        return True
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in _FALSY_STR:
            return False
        if v in _TRUTHY_STR:
            return True
    if isinstance(value, int):
        return bool(value)
    raise ValueError(
        f"hunt {hunt_id!r}: `enabled` must be a boolean, got {value!r}"
    )


# A console-authored hunt id becomes a filename, so it is sanitised
# rather than trusted: lowercase alnum plus hyphens, alnum-initial, 64
# chars max. Anything that could traverse (`..`, `/`) or collide on a
# case-insensitive filesystem is refused before it reaches the path
# join — `write_hunt` still re-checks containment afterwards.
HUNT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


def validate_hunt_doc(doc: Any, *, source: str = "") -> str:
    """Validate one hunt document and return its id.

    Everything `load_hunts` checks **per file** lives here so the write
    path (`write_hunt`, and the console routes behind it) enforces the
    exact same rules the loader does — a hunt that saves but won't load
    would take the whole directory down on the next `mine hunts`.

    Deliberately *not* included: the cross-file duplicate-id check. That
    is directory state, not document state, and stays in `load_hunts`.

    ``source`` names the file in the error messages; omit it when the
    document didn't come from disk.
    """
    where = source or "<document>"
    if not isinstance(doc, dict):
        raise ValueError(f"hunts: {where} is not a YAML mapping")
    hunt_id = doc.get("id")
    if not isinstance(hunt_id, str) or not hunt_id:
        raise ValueError(f"hunts: {where} missing required `id`")
    if not isinstance(doc.get("name"), str):
        raise ValueError(f"hunt {hunt_id!r}: missing required `name`")
    filters = doc.get("filters") or []
    if not isinstance(filters, list) or not filters:
        raise ValueError(f"hunt {hunt_id!r}: `filters` must be a non-empty list")
    for i, flt in enumerate(filters):
        _validate_filter(flt, hunt_id=hunt_id, idx=i)
    # Raises on an uninterpretable value; the caller decides whether to
    # keep the coerced bool.
    _coerce_enabled(doc.get("enabled", True), hunt_id)
    return hunt_id


def load_hunts(hunts_dir: str) -> list[dict[str, Any]]:
    """Walk ``hunts_dir`` for ``*.yaml`` / ``*.yml`` files. Returns
    **every** valid hunt in id-sorted order — disabled ones included —
    each carrying a normalized bool ``enabled`` and a ``_source_path``
    naming the file it came from. A malformed file aborts the entire
    load — better than silently skipping a broken hunt and leaving the
    analyst wondering why nothing fired.

    Disabled hunts are returned so the console can list, preview, and
    re-enable them; filtering on ``enabled`` is the *caller's* job and
    belongs only on the write path (``run_hunts``).
    """
    p = Path(hunts_dir)
    if not p.is_dir():
        log.info("hunts: directory %s does not exist; nothing to run", hunts_dir)
        return []
    root = p.resolve()
    hunts: list[dict[str, Any]] = []
    seen_ids: dict[str, str] = {}
    for f in sorted(p.iterdir()):
        if f.suffix not in (".yaml", ".yml"):
            continue
        # `_source_path` is what the console's toggle rewrites, so it must
        # stay inside the hunts dir. A symlink pointing out of the tree
        # would otherwise turn "flip this hunt" into "rewrite that file".
        resolved = f.resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            raise ValueError(
                f"hunts: {f} resolves to {resolved}, outside {root}; "
                "refusing to load a hunt from outside the hunts directory"
            ) from None
        try:
            with f.open(encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
        except Exception as exc:
            raise ValueError(f"hunts: failed to parse {f}: {exc}") from exc
        hunt_id = validate_hunt_doc(doc, source=str(f))
        # Two files claiming one id would make `by_hunt` keys collide and
        # leave the console toggling whichever sorted first while the
        # other kept writing findings. Fail loudly instead.
        if hunt_id in seen_ids:
            raise ValueError(
                f"hunts: duplicate id {hunt_id!r} in {f.name} — already "
                f"declared by {seen_ids[hunt_id]}"
            )
        seen_ids[hunt_id] = f.name
        # Absent key defaults to True — see the module docstring.
        doc["enabled"] = _coerce_enabled(doc.get("enabled", True), hunt_id)
        doc["_source_path"] = str(resolved)
        hunts.append(doc)
    return hunts


def enabled_hunts(hunts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The subset of ``hunts`` allowed to write findings."""
    return [h for h in hunts if h.get("enabled")]


def set_hunt_enabled(hunt: dict[str, Any], enabled: bool) -> None:
    """Flip ``enabled`` in the hunt's own YAML file, in place.

    Deliberately a surgical single-line edit rather than a
    ``yaml.safe_dump`` round-trip: the seed hunts carry multi-paragraph
    ``description: |`` blocks and inline tuning comments that a dump
    would flatten and reorder. Replaces the first top-level
    ``enabled:`` line (preserving any trailing ``#`` comment); appends
    the key when the file doesn't have one.

    The new content is validated *before* it replaces anything, then
    swapped in with an atomic ``os.replace`` off a same-directory temp
    file. A crash, a full disk, or a concurrent ``mine hunts`` read can
    therefore never observe a half-written file — which matters more
    here than usual, because one unparseable YAML aborts the entire
    directory load, taking down the very console page an operator would
    use to undo the damage.
    """
    path = hunt.get("_source_path")
    if not path:
        raise ValueError(
            f"hunt {hunt.get('id')!r}: no `_source_path`; "
            "was it loaded via load_hunts()?"
        )
    p = Path(path)
    # newline="" disables universal-newline translation on read; without
    # it a CRLF file arrives as LF and the rewrite silently normalizes
    # every line ending, which is the opposite of the byte-fidelity this
    # whole surgical-edit approach exists to provide.
    with p.open("r", encoding="utf-8", newline="") as fh:
        text = fh.read()
    lines = text.splitlines(keepends=True)
    literal = "true" if enabled else "false"
    # Match a bare or quoted top-level key: `enabled:`, `"enabled":`,
    # `'enabled':`. PyYAML treats all three as the same key, so matching
    # only the bare form would append a *second* `enabled` and leave the
    # file self-contradictory (last-wins, silently).
    key_re = re.compile(r"""^(["']?)enabled\1\s*:""")
    for i, line in enumerate(lines):
        if key_re.match(line):
            # Preserve this line's own ending — a CRLF file must not come
            # back mixed-EOL, since byte-fidelity is the property that
            # justifies this rewrite over yaml.safe_dump.
            eol = "\r\n" if line.endswith("\r\n") else ("\n" if line.endswith("\n") else "")
            body = line[:len(line) - len(eol)] if eol else line
            # Keep a trailing comment (`enabled: false  # toggled from …`)
            # so the operator's own annotation survives the flip.
            m = re.search(r"(\s+#.*?)\s*$", body)
            comment = m.group(1) if m else ""
            lines[i] = f"enabled: {literal}{comment}{eol}"
            break
    else:
        # Guarantee the appended key starts on its own line even if the
        # file didn't end with a newline. Match the file's prevailing EOL.
        eol = "\r\n" if "\r\n" in text else "\n"
        if lines and not lines[-1].endswith(("\n", "\r")):
            lines[-1] += eol
        lines.append(f"enabled: {literal}{eol}")
    new_text = "".join(lines)

    # Validate the candidate content before it touches the real file.
    doc = yaml.safe_load(new_text)
    if not isinstance(doc, dict):
        raise ValueError(f"hunt {hunt.get('id')!r}: rewrite produced non-mapping YAML")
    if _coerce_enabled(doc.get("enabled", True), str(hunt.get("id"))) != bool(enabled):
        raise ValueError(f"hunt {hunt.get('id')!r}: rewrite did not take effect")

    # Atomic swap: same directory so os.replace stays on one filesystem.
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=f".{p.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(new_text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, p)
    except BaseException:
        # mkstemp created it; never leave the turd behind on failure.
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    hunt["enabled"] = bool(enabled)


# Key order written by `write_hunt`, so a console-authored file reads
# like the hand-written seeds. Anything else the document carries is
# appended after these, in its own order.
_WRITE_KEY_ORDER = ("id", "name", "description", "enabled", "filters")


def _contained(target: Path, root: Path, hunt_id: str, verb: str) -> None:
    """Refuse a path that resolves outside the hunts directory.

    The failure message names only the hunt id — these errors are
    surfaced to an HTTP client, and the operator's filesystem layout is
    not the client's business. The absolute paths go to the log.
    """
    try:
        target.relative_to(root)
    except ValueError:
        log.error("hunts: refusing to %s %s — resolves outside %s",
                  verb, target, root)
        raise ValueError(
            f"hunt {hunt_id!r}: resolved path escapes the hunts directory"
        ) from None


def write_hunt(
    hunts_dir: str, doc: dict[str, Any], *, path: str | None = None,
) -> str:
    """Write one hunt document to YAML and return the path written.

    The whole document is re-serialised with ``yaml.safe_dump``, which
    means comments and ``description: |`` block scalars do **not**
    survive — unlike `set_hunt_enabled`, which is surgical precisely to
    preserve them. That is the accepted cost of a full-document edit and
    it is only paid when a human explicitly saves from the console.

    Every write re-runs `validate_hunt_doc` (the loader's own rules) and
    re-parses the candidate text *before* it replaces anything, then
    swaps it in with an atomic `os.replace` off a same-directory temp
    file — one unparseable YAML aborts the entire directory load, taking
    down the page an operator would use to undo it.

    ``path`` targets an existing file (an edit writes back to the hunt's
    own ``_source_path``, which may be ``.yml`` or named differently
    from the id); omitted, the target is ``<hunts_dir>/<id>.yaml``.
    Either way the resolved target must live inside ``hunts_dir``.

    ``HUNT_ID_RE`` is enforced only when the filename is *derived* from
    the id — that is the only case where the id can traverse. With an
    explicit ``path`` the safety property is containment, checked below,
    so a hand-written legacy id like ``My_Hunt`` stays editable instead
    of being permanently unsaveable from the console.
    """
    hunt_id = validate_hunt_doc(doc)
    if path is None and not HUNT_ID_RE.match(hunt_id):
        raise ValueError(
            f"hunt id {hunt_id!r} is invalid: must match "
            f"{HUNT_ID_RE.pattern} — lowercase letters, digits and "
            "hyphens, starting with a letter or digit, 64 chars max"
        )
    root_p = Path(hunts_dir)
    root_p.mkdir(parents=True, exist_ok=True)
    root = root_p.resolve()
    target = (Path(path) if path else root / f"{hunt_id}.yaml").resolve()
    _contained(target, root, hunt_id, "write")

    payload = {k: v for k, v in doc.items() if k != "_source_path"}
    if "enabled" in payload:
        payload["enabled"] = _coerce_enabled(payload["enabled"], hunt_id)
    ordered: dict[str, Any] = {
        k: payload.pop(k) for k in _WRITE_KEY_ORDER if k in payload
    }
    ordered.update(payload)
    text = yaml.safe_dump(ordered, sort_keys=False, allow_unicode=True)
    # Prove the bytes we're about to install parse back into a hunt the
    # loader accepts, before they replace anything.
    validate_hunt_doc(yaml.safe_load(text))

    # `mkstemp` creates the temp file 0600 and `os.replace` keeps the
    # *temp* file's mode, so without this every saved hunt would come
    # back owner-only.
    try:
        mode = os.stat(target).st_mode & 0o777
    except FileNotFoundError:
        mode = 0o644 & ~_UMASK
    fd, tmp = tempfile.mkstemp(
        dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, target)
    except BaseException:
        # mkstemp created it; never leave the turd behind on failure.
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    return str(target)


def delete_hunt(hunt: dict[str, Any], *, hunts_dir: str | None = None) -> None:
    """Unlink the hunt's own YAML file.

    Findings the hunt already wrote are **not** touched — they outlive
    their definition; deleting the file only stops future writes.

    Containment is re-checked rather than trusted: the caller hands back
    a dict, and `_source_path` is the one field in it that names a file.
    Pass ``hunts_dir`` to check against the configured directory (what
    the console does); without it the path must at least be an already
    resolved ``.yaml``/``.yml`` file, which a symlink would fail.
    """
    path = hunt.get("_source_path")
    if not path:
        raise ValueError(
            f"hunt {hunt.get('id')!r}: no `_source_path`; "
            "was it loaded via load_hunts()?"
        )
    hunt_id = str(hunt.get("id"))
    p = Path(path)
    resolved = p.resolve()
    if resolved != p:
        log.error("hunts: refusing to delete %s — resolves to %s", p, resolved)
        raise ValueError(
            f"hunt {hunt_id!r}: `_source_path` is not a resolved path"
        )
    if resolved.suffix not in (".yaml", ".yml"):
        raise ValueError(
            f"hunt {hunt_id!r}: `_source_path` is not a hunt YAML file"
        )
    if hunts_dir is not None:
        _contained(resolved, Path(hunts_dir).resolve(), hunt_id, "delete")
    os.unlink(resolved)


def _filter_to_es_clause(f: dict) -> dict:
    """Translate one validated filter clause into an ES query fragment.
    Combined with sibling filters under a bool.must to form the hunt's
    full query. Field paths kept off the caller — this function owns
    the schema-to-field-path mapping."""
    kind = f["kind"]
    if kind == "artifact_set_contains_any":
        return {"terms": {_F_ARTIFACT_SET: list(f["values"])}}
    if kind == "artifact_set_contains_all":
        # ES has no "terms_set with minimum_should_match=ALL" shortcut
        # outside terms_set queries — easier to AND a series of term
        # clauses.
        return {"bool": {"must": [
            {"term": {_F_ARTIFACT_SET: v}} for v in f["values"]
        ]}}
    if kind == "intent_in":
        return {"terms": {_F_INTENT: list(f["values"])}}
    if kind == "command_count_gte":
        return {"range": {_F_COMMAND_COUNT: {"gte": int(f["threshold"])}}}
    if kind == "login_fail_count_gte":
        return {"range": {_F_LOGIN_FAILS: {"gte": int(f["threshold"])}}}
    if kind == "external_match_cosine_gte":
        return {"range": {_F_EXT_COSINE: {"gte": float(f["threshold"])}}}
    if kind == "window":
        cutoff = datetime.now(UTC) - timedelta(days=int(f["last_days"]))
        return {"range": {_F_TS: {"gte": cutoff.isoformat()}}}
    # `_validate_filter` already gated this; reaching here is a bug.
    raise ValueError(f"hunts: unsupported filter kind {kind!r}")


def _run_one_hunt(
    es: Elasticsearch, sessions_idx: str,
    hunt: dict, *, run_id: str, max_findings: int,
) -> list[dict[str, Any]]:
    """Execute one hunt's query against the session rollup. Returns a
    list of finding dicts ready for ``bulk_upsert_findings``. Empty
    list when no sessions match."""
    must = [_filter_to_es_clause(f) for f in hunt["filters"]]
    body = {
        "size": max_findings,
        "_source": [
            "cowrie.session_id",
            "source.ip",
            _F_TS,
            "event.end",
            _F_COMMAND_COUNT,
            _F_INTENT,
            "dshield.cowrie.enrichment.session.playbook_id",
            "dshield.cowrie.enrichment.session.playbook_name",
            "dshield.cowrie.enrichment.session.cluster.external_match_id",
            "dshield.cowrie.enrichment.session.cluster.external_match_cosine",
        ],
        "query": {"bool": {"must": must}},
        "sort": [{_F_TS: {"order": "desc"}}],
    }
    try:
        resp = es.search(index=sessions_idx, **body)
    except Exception as exc:
        log.warning("hunts: %s execution failed: %s", hunt["id"], exc)
        return []
    out: list[dict[str, Any]] = []
    for h in (resp.get("hits") or {}).get("hits") or []:
        s = h["_source"]
        sid = ((s.get("cowrie") or {}).get("session_id")) or h["_id"]
        sess_enr = ((s.get("dshield") or {}).get("cowrie", {})
                    .get("enrichment", {}).get("session", {})) or {}
        cluster = sess_enr.get("cluster") or {}
        out.append({
            "kind":     "analyst_hunt",
            "run_id":   run_id,
            "artifact": {"kind": "session", "value": sid},
            "score":    1.0,
            # `delta_signature` carries the hunt id so two different
            # hunts on the same session produce two distinct findings
            # (the writer hashes (kind, artifact_kind, artifact_value,
            # delta_signature) into the finding_id).
            "delta_signature": f"hunt:{hunt['id']}",
            "narrative": (
                f"Session {sid} matches hunt '{hunt['name']}' "
                f"({len(must)} filter{'s' if len(must) > 1 else ''})."
            ),
            "evidence": {
                "hunt_id":          hunt["id"],
                "hunt_name":        hunt["name"],
                "hunt_description": hunt.get("description") or "",
                "session_id":       sid,
                "source_ip":        (s.get("source") or {}).get("ip"),
                "first_seen":       s.get("event", {}).get("start"),
                "last_seen":        s.get("event", {}).get("end"),
                "command_count":    sess_enr.get("command_count"),
                "dominant_intent":  sess_enr.get("dominant_intent"),
                "playbook_id":      sess_enr.get("playbook_id"),
                "playbook_name":    sess_enr.get("playbook_name"),
                "external_match_id":     cluster.get("external_match_id"),
                "external_match_cosine": cluster.get("external_match_cosine"),
            },
        })
    return out


def _hunts_dir(cfg: Any) -> str:
    return getattr(getattr(cfg.findings, "hunts", None),
                   "config_dir", "config/hunts")


def _max_per_hunt(cfg: Any) -> int:
    return int(getattr(getattr(cfg.findings, "hunts", None),
                       "max_findings_per_hunt", _MAX_FINDINGS_PER_HUNT))


# Fields lifted out of a hunt match's `evidence` dict for the preview
# table. Preview shows *sessions*, not findings — no finding is created.
_PREVIEW_FIELDS = (
    "session_id", "source_ip", "first_seen", "last_seen",
    "command_count", "dominant_intent", "playbook_id", "playbook_name",
    "external_match_id", "external_match_cosine",
)


def preview_hunt(
    es: Elasticsearch, cfg: Any, hunt: dict[str, Any], *,
    limit: int | None = None,
) -> dict[str, Any]:
    """Execute one hunt and return what it *would* match, writing
    nothing. No ``bulk_upsert_findings``, no ``init_index``, no
    ``refresh``, no ``run_id`` — one ES search and a projection.

    Runs regardless of the hunt's ``enabled`` flag; previewing a
    disabled hunt is the whole point of the toggle workflow.

    Returns::

        {"hunt_id", "hunt_name", "enabled", "total", "shown", "truncated",
         "sessions": [...], "note": <optional str>}

    ``total`` is the true match count from a `_count`, not the size of
    the returned page — an analyst deciding whether to switch a hunt on
    needs to know it would write 4,000 findings, not that the preview
    showed 100.
    """
    cap = max(1, int(limit)) if limit is not None else _max_per_hunt(cfg)
    sessions_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    out: dict[str, Any] = {
        "hunt_id":   hunt["id"],
        "hunt_name": hunt.get("name") or hunt["id"],
        "enabled":   bool(hunt.get("enabled")),
        "total":     0,
        "shown":     0,
        "truncated": False,
        "sessions":  [],
    }
    if not es.indices.exists(index=sessions_idx):
        log.info("hunts: preview %s — sessions rollup %s does not exist",
                 hunt["id"], sessions_idx)
        out["note"] = f"session rollup {sessions_idx} does not exist"
        return out

    query = {"bool": {"must": [_filter_to_es_clause(f) for f in hunt["filters"]]}}
    try:
        out["total"] = int(es.count(index=sessions_idx, query=query).get("count", 0))
    except Exception as exc:
        # Don't fail the preview on a missing count — the page below is
        # still useful. But never silently report 0.
        log.warning("hunts: preview %s count failed: %s", hunt["id"], exc)
        out["note"] = f"match count unavailable: {exc}"

    rows = _run_one_hunt(
        es, sessions_idx, hunt, run_id="preview", max_findings=cap,
    )
    out["sessions"] = [
        {k: r["evidence"].get(k) for k in _PREVIEW_FIELDS} for r in rows
    ]
    out["shown"] = len(rows)
    out["truncated"] = out["total"] > len(rows)
    # `_run_one_hunt` swallows a failed search and returns []. Without
    # this, a shard failure or mapping error renders as "no sessions
    # matched" and the analyst discards a live hypothesis.
    if not rows and out["total"] > 0 and "note" not in out:
        out["note"] = ("query returned no rows despite "
                       f"{out['total']} counted matches — check the logs")
    return out


def run_hunts(
    es: Elasticsearch, cfg: Any, run_id: str, *,
    include_disabled: bool = False,
) -> dict[str, Any]:
    """Load every YAML in `cfg.findings.hunts.config_dir`, execute the
    **enabled** ones against the session rollup, and return:

        {
          "loaded":   n_hunts_on_disk,
          "by_hunt":  {hunt_id: [finding, ...]},
          "skipped":  ["disabled_id", ...],
          "errors":   [{"hunt_id": ..., "error": ...}],
        }

    ``loaded`` counts every hunt on disk, not just the executed ones, so
    the operator can see the enabled/total ratio at a glance.

    ``include_disabled`` forces disabled hunts to execute too. The CLI
    only exposes it alongside ``--dry-run`` — letting a flag write
    findings for a hunt the operator switched off would defeat the
    toggle.

    The caller writes the per-hunt finding lists via
    ``bulk_upsert_findings``.
    """
    hunts_dir = _hunts_dir(cfg)
    max_per_hunt = _max_per_hunt(cfg)
    sessions_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup

    out: dict[str, Any] = {
        "loaded":  0, "by_hunt": {}, "skipped": [], "ran_disabled": [],
        "errors": [],
    }
    try:
        hunts = load_hunts(hunts_dir)
    except Exception as exc:
        log.warning("hunts: load failed: %s", exc)
        out["errors"].append({"hunt_id": None, "error": str(exc)})
        return out
    out["loaded"] = len(hunts)
    if not hunts:
        return out

    if include_disabled:
        to_run = list(hunts)
        # Name them, so a --dry-run reader can tell which results came
        # from hunts the operator has switched off.
        out["ran_disabled"] = [h["id"] for h in hunts if not h.get("enabled")]
    else:
        to_run = enabled_hunts(hunts)
        out["skipped"] = [h["id"] for h in hunts if not h.get("enabled")]
        for hid in out["skipped"]:
            log.info("hunts: %s disabled; not writing findings", hid)
    if not to_run:
        return out

    if not es.indices.exists(index=sessions_idx):
        log.info("hunts: sessions rollup %s does not exist; skipping all",
                 sessions_idx)
        return out

    for hunt in to_run:
        try:
            findings = _run_one_hunt(
                es, sessions_idx, hunt,
                run_id=run_id, max_findings=max_per_hunt,
            )
            out["by_hunt"][hunt["id"]] = findings
        except Exception as exc:
            log.warning("hunts: %s failed: %s", hunt["id"], exc)
            out["errors"].append({"hunt_id": hunt["id"], "error": str(exc)})
    return out
