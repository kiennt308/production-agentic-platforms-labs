"""Offline Deterministic Replay Gateway for OrderFlow Platform.

Supports $0.00 OpenAI-compatible and MCP tool replay responses, or
forwards requests when LLM_BASE_URL points to local Ollama.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any

REPLAY_SCENARIOS: dict[str, dict[str, Any]] = {
    "ch02_route": {
        "gateway": "agentgateway-v1.7.0",
        "backend": "orderflow-sre-primary",
        "mcp_encrypted": True,
        "status": "routed",
    },
    "ch05_tool_check": {
        "tool": "kubectl_get_pods",
        "namespace": "orderflow-prod",
        "action": "ALLOW",
        "reason": "read_only_scoped",
    },
    "ch07_redteam_attack": {
        "probe": "indirect_prompt_injection_asi01",
        "action": "BLOCKED",
        "guardrail": "external_opa_cel",
    },
    "ch08_incident_rca": {
        "incident": "orderflow-checkout-502",
        "tools_called": [
            {"name": "query_prometheus", "args": {"svc": "checkout"}},
            {"name": "read_otel_trace", "args": {"trace_id": "4bf9"}},
        ],
        "faithfulness": 0.96,
    },
}


def dispatch_replay(scenario: str, payload: dict[str, Any]) -> dict:
    """Return local Ollama response if configured, else deterministic."""
    base_url = os.environ.get("LLM_BASE_URL", "").strip()
    if base_url.startswith(("http://127.0.0.1", "http://localhost")):
        req = urllib.request.Request(
            f"{base_url.rstrip('/')}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))

    record = REPLAY_SCENARIOS.get(
        scenario,
        {"status": "unknown_scenario", "action": "DENY"},
    )
    return {
        "mode": "deterministic_replay",
        "cost_usd": 0.0,
        "scenario": scenario,
        "result": record,
    }


def main() -> None:
    """Verify all 4 platform replay scenarios run at $0.00 cost."""
    out = [
        dispatch_replay(name, {"prompt": name})
        for name in REPLAY_SCENARIOS
    ]
    assert len(out) == 4
    assert sum(item["cost_usd"] for item in out) == 0.0
    report = {"gateway_status": "READY", "scenarios": out}
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
