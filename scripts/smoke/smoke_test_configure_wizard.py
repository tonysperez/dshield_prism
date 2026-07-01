"""setup.sh config wizard — writes .env + minimal local.yaml, round-trips config.

The `setup/setup.sh --configure-only` path replaces the old manual editing of
`.env` + `config/local.yaml`. This drives it with canned answers into a tempdir
(via the ENV_FILE / LOCAL_CONFIG overrides) and asserts:

  - user/pass auth + accepted model defaults -> creds land in .env, ES hosts +
    llm.base_url round-trip through load_config/load_secrets, and the model keys
    are OMITTED from local.yaml (they track default.yaml);
  - API-key auth -> ES_API_KEY written, no ES_USERNAME;
  - explicit model overrides -> those keys DO appear and round-trip;
  - optional Anthropic + intel keys -> written to .env and flip
    cloud.enabled / intel.enabled on in local.yaml.

Standalone + offline — shells out to bash, no ES / LLM / network / root. Run
from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_configure_wizard.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from enrich.config import load_config, load_secrets  # noqa: E402

SETUP = REPO / "setup" / "setup.sh"
BASE_CONFIG = REPO / "config" / "default.yaml"

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASSED.append(name) if ok else FAILED.append((name, detail)))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"  {detail}"))


def run_wizard(tmp: Path, answers: list[str]) -> tuple[Path, Path, subprocess.CompletedProcess]:
    """Drive `setup.sh --configure-only` with canned stdin; return (env, local, proc)."""
    env_file = tmp / ".env"
    local_cfg = tmp / "local.yaml"
    proc = subprocess.run(
        # --no-verify: keep the smoke offline (the live ES/model checks would
        # otherwise try to reach the fake test URLs).
        ["bash", str(SETUP), "--configure-only", "--no-verify"],
        input="\n".join(answers) + "\n",
        text=True,
        capture_output=True,
        cwd=str(REPO),
        env={**os.environ, "ENV_FILE": str(env_file), "LOCAL_CONFIG": str(local_cfg)},
    )
    return env_file, local_cfg, proc


def load(env_file: Path, local_cfg: Path):
    """Load config the way the pipeline does, pointed at the wizard's output."""
    os.environ["PRISM_LOCAL_CONFIG"] = str(local_cfg)
    os.environ["PRISM_ENV"] = str(env_file)
    try:
        return load_config(str(BASE_CONFIG)), load_secrets(str(BASE_CONFIG))
    finally:
        os.environ.pop("PRISM_LOCAL_CONFIG", None)
        os.environ.pop("PRISM_ENV", None)


# ---------------------------------------------------------------------------
# [1] user/pass auth + accepted model defaults
# prompts: ES URL, verify?, auth, ES_USER, ES_PASS, provider, base_url,
#          gen-model, embed-model, anthropic, abuse_ch, greynoise, abuseipdb
print("[1] user/pass auth, accept model defaults")
with tempfile.TemporaryDirectory() as d:
    tmp = Path(d)
    answers = ["https://es.test:9200", "N", "2", "esuser", "espass",
               "1", "http://llm.test:11434", "", "", "", "", "", ""]
    env_file, local_cfg, proc = run_wizard(tmp, answers)
    check("wizard exits 0", proc.returncode == 0, proc.stderr)
    check(".env is mode 600", env_file.exists() and (env_file.stat().st_mode & 0o777) == 0o600,
          oct(env_file.stat().st_mode & 0o777) if env_file.exists() else "missing")
    local_text = local_cfg.read_text() if local_cfg.exists() else ""
    check("model keys omitted when defaults accepted",
          "generation_model" not in local_text and "embedding_model" not in local_text)
    cfg, sec = load(env_file, local_cfg)
    check("ES hosts round-trip", cfg.elasticsearch.hosts == ["https://es.test:9200"],
          repr(cfg.elasticsearch.hosts))
    check("verify_certs is False (default 'N')", cfg.elasticsearch.verify_certs is False)
    check("llm.provider round-trip", cfg.llm.provider == "ollama", cfg.llm.provider)
    check("llm.base_url round-trip", cfg.llm.base_url == "http://llm.test:11434", str(cfg.llm.base_url))
    check("ES username round-trips via .env", sec.es_username == "esuser", str(sec.es_username))
    check("ES password round-trips via .env", sec.es_password == "espass", str(sec.es_password))

# ---------------------------------------------------------------------------
# [2] API-key auth  (auth=1 -> single ES_API_KEY prompt, no user/pass)
print("\n[2] API-key auth")
with tempfile.TemporaryDirectory() as d:
    tmp = Path(d)
    answers = ["https://es.test:9200", "N", "1", "my-es-api-key",
               "1", "http://llm.test:11434", "", "", "", "", "", ""]
    env_file, local_cfg, proc = run_wizard(tmp, answers)
    check("wizard exits 0", proc.returncode == 0, proc.stderr)
    env_text = env_file.read_text() if env_file.exists() else ""
    check("ES_API_KEY written", "ES_API_KEY=my-es-api-key" in env_text)
    check("no ES_USERNAME line", "ES_USERNAME" not in env_text)
    _, sec = load(env_file, local_cfg)
    check("api key round-trips", sec.es_api_key == "my-es-api-key", str(sec.es_api_key))

# ---------------------------------------------------------------------------
# [3] explicit model overrides -> keys appear + round-trip
print("\n[3] explicit model overrides")
with tempfile.TemporaryDirectory() as d:
    tmp = Path(d)
    answers = ["https://es.test:9200", "N", "2", "esuser", "espass",
               "1", "http://llm.test:11434", "custom-gen-model", "custom-emb-model",
               "", "", "", ""]
    env_file, local_cfg, proc = run_wizard(tmp, answers)
    check("wizard exits 0", proc.returncode == 0, proc.stderr)
    local_text = local_cfg.read_text()
    check("generation_model override written", "generation_model: custom-gen-model" in local_text)
    check("embedding_model override written", "embedding_model: custom-emb-model" in local_text)
    cfg, _ = load(env_file, local_cfg)
    check("generation_model round-trips", cfg.llm.generation_model == "custom-gen-model", cfg.llm.generation_model)
    check("embedding_model round-trips", cfg.llm.embedding_model == "custom-emb-model", cfg.llm.embedding_model)

# ---------------------------------------------------------------------------
# [4] optional Anthropic + intel keys -> .env + enabled flags
print("\n[4] optional Anthropic + intel keys")
with tempfile.TemporaryDirectory() as d:
    tmp = Path(d)
    answers = ["https://es.test:9200", "N", "2", "esuser", "espass",
               "1", "http://llm.test:11434", "", "",
               "sk-ant-test", "abuse-ch-key", "", ""]
    env_file, local_cfg, proc = run_wizard(tmp, answers)
    check("wizard exits 0", proc.returncode == 0, proc.stderr)
    env_text = env_file.read_text()
    local_text = local_cfg.read_text()
    check("ANTHROPIC_API_KEY written", "ANTHROPIC_API_KEY=sk-ant-test" in env_text)
    check("ABUSE_CH_AUTH_KEY written", "ABUSE_CH_AUTH_KEY=abuse-ch-key" in env_text)
    check("empty intel keys omitted", "GREYNOISE_API_KEY" not in env_text and "ABUSEIPDB_API_KEY" not in env_text)
    cfg, sec = load(env_file, local_cfg)
    check("cloud.enabled flipped on", cfg.cloud.enabled is True)
    check("intel.enabled flipped on", cfg.intel.enabled is True)
    check("anthropic key round-trips", sec.anthropic_api_key == "sk-ant-test", str(sec.anthropic_api_key))

# ---------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
