"""Smoke test for deterministic LLM generation (ROADMAP "Open audit items").

Generation must be reproducible — temperature 0 (greedy) + a fixed seed — so a
re-enrich reproduces prior output and embeddings/clustering don't churn. This
verifies the request payload each client builds, using a fake httpx client (no
network).

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_llm_determinism.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.llm.anthropic import AnthropicClient
from enrich.llm.ollama import OllamaClient
from enrich.llm.openai_compat import OpenAICompatClient

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


class FakeResp:
    status_code = 200

    def __init__(self, body: dict) -> None:
        self._body = body

    def json(self) -> dict:
        return self._body


class FakeHTTP:
    """Captures the last POST payload; returns a canned response body."""

    def __init__(self, body: dict) -> None:
        self.body = body
        self.last_payload: dict | None = None

    def post(self, url, json=None):
        self.last_payload = json
        return FakeResp(self.body)


# -----------------------------------------------------------------------------
print("[1] Ollama generate_json — deterministic options")
c = OllamaClient("http://x", "gen", "emb")
c._client = FakeHTTP({"response": "{}"})
c.generate_json("p", schema={"type": "object"})
o = c._client.last_payload["options"]
check("ollama temperature 0", o["temperature"] == 0.0, str(o))
check("ollama fixed seed present", o.get("seed") == 0, str(o))
check("ollama keeps num_ctx", o.get("num_ctx") == 4096, str(o))

print("[2] Ollama — caller options merge, determinism not dropped")
c._client = FakeHTTP({"response": "{}"})
c.generate_json("p", options={"max_tokens": 256})
o = c._client.last_payload["options"]
check("ollama still temp 0 when caller passes only max_tokens", o["temperature"] == 0.0, str(o))
check("ollama caller option merged", o.get("max_tokens") == 256, str(o))
c._client = FakeHTTP({"response": "{}"})
c.generate_json("p", options={"temperature": 0.7})
check("ollama caller can override temperature", c._client.last_payload["options"]["temperature"] == 0.7)

# -----------------------------------------------------------------------------
print("\n[3] OpenAI-compat generate_json — deterministic payload")
oc = OpenAICompatClient("http://x", "gen", "emb")
oc._client = FakeHTTP({"choices": [{"message": {"content": "{}"}}]})
oc.generate_json("p", schema={"type": "object"})
p = oc._client.last_payload
check("openai_compat temperature 0", p["temperature"] == 0.0, str(p))
check("openai_compat fixed seed present", p.get("seed") == 0, str(p))
oc._client = FakeHTTP({"choices": [{"message": {"content": "{}"}}]})
oc.generate_json("p", options={"temperature": 0.9})
check("openai_compat caller can override temperature", oc._client.last_payload["temperature"] == 0.9)

# -----------------------------------------------------------------------------
print("\n[4] Anthropic generation — temperature 0")
ac = AnthropicClient(api_key="k", model="m")
ac._client = FakeHTTP({"content": [{"type": "text", "text": "{}"}],
                       "usage": {"input_tokens": 1, "output_tokens": 1}})
ac.generate_json("p")
check("anthropic temperature 0", ac._client.last_payload.get("temperature") == 0, str(ac._client.last_payload))

# -----------------------------------------------------------------------------
print()
print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
