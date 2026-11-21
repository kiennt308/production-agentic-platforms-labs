"""Enterprise Agentic Control Plane Router for Volumes 06-09.

Enforces Zero-Overlap boundaries between Volume 09 (AI for Security)
and Volume 10 (Security OF Agents) across OrderFlow fleets.
"""

from __future__ import annotations

import json

MANAGED_FLEETS = {
    "urn:agent:orderflow-devops": {
        "source_volume": 6,
        "gateway": "agentgateway-v1.7.0",
        "sandbox_pool": "orderflow-runner-pool",
        "otel_provider_attr": "gen_ai.provider.name",
        "owns": "IaC/Helm/ArgoCD GitOps PRs (Vol. 06)",
    },
    "urn:agent:orderflow-sre": {
        "source_volume": 7,
        "gateway": "agentgateway-v1.7.0",
        "sandbox_pool": "orderflow-runner-pool",
        "otel_provider_attr": "gen_ai.provider.name",
        "owns": "Incident RCA & Bounded Self-Healing (Vol. 07)",
    },
    "urn:agent:orderflow-aws": {
        "source_volume": 8,
        "gateway": "agent-router-v1beta1",
        "sandbox_pool": "agentcore-or-gvisor-runner",
        "otel_provider_attr": "gen_ai.provider.name",
        "owns": "Strands/AgentCore & Cedar Ops (Vol. 08)",
    },
    "urn:agent:orderflow-devsecops": {
        "source_volume": 9,
        "gateway": "agentgateway-v1.7.0",
        "sandbox_pool": "orderflow-runner-pool",
        "otel_provider_attr": "gen_ai.provider.name",
        "owns": "EPSS/SLSA/Falco/Tetragon AI for Security (Vol. 09)",
    },
}

CONTROL_PLANE_LAYERS = [
    ("L1_GATEWAY", "ch02", "agentgateway v1.7.0 + Agent Router v1.1+"),
    ("L2_SANDBOX", "ch03", "K8s SIG Apps agent-sandbox + gVisor runsc"),
    ("L3_GUARDRAIL", "ch04-ch05", "OWASP ASI01-ASI10 OPA/Kyverno + Kill"),
    ("L4_TELEMETRY", "ch06", "OTel GenAI gen_ai.provider.name + _meta"),
    ("L5_EVALS", "ch07-ch08", "Promptfoo v0.126.0 + DeepEval pytest"),
    ("L6_FINOPS", "ch09", "FOCUS 1.2-1.4->1.5 Token ETL & Toil ROI"),
]


def route_governed_request(agent_urn: str, plane: str) -> dict:
    """Attach mandatory Vol. 10 platform controls to Vol. 06-09."""
    if agent_urn not in MANAGED_FLEETS:
        raise ValueError(f"Shadow agent rejected: {agent_urn}")
    return {
        "agent_urn": agent_urn,
        "plane": plane,
        "fleet": MANAGED_FLEETS[agent_urn],
        "platform_controls": [layer[0] for layer in CONTROL_PLANE_LAYERS],
        "egress_mode": "gateway_only",
    }


def main() -> None:
    """Demonstrate unified routing over all 4 governed Vol. 06-09."""
    routed = [
        route_governed_request(urn, "orderflow-agent-platform")
        for urn in MANAGED_FLEETS
    ]
    print(json.dumps({"governed_fleets": len(routed), "routes": routed}))


if __name__ == "__main__":
    main()
