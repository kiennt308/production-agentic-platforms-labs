"""Offline MCP Gateway & Agent Router Simulator (Zero-Bill Lab).

Author: Kien Nguyen
Demonstrates agentgateway v1.7.0 vs Agent Router v1beta1 routing,
MCP 2.2.0 tool schemas, CEL allowlisting, failover, and egress guards.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import mcp.types as mt
from mcp.server.mcpserver import MCPServer

DEFAULT_MATRIX = (
    Path(__file__).resolve().parent / "05-gateway-policy-matrix.json"
)
INJECTION_MARKERS = (
    "ignore previous instructions",
    "<system>",
    "exfiltrate",
)


def build_orderflow_mcp_server() -> tuple[MCPServer, dict[str, mt.Tool]]:
    """Create offline MCPServer (mcp 2.2.0) and typed Tool catalog."""
    server = MCPServer("orderflow-mcp-gateway")

    @server.tool()
    def kubectl_get_pods(namespace: str = "orderflow-prod") -> str:
        """Read pod status in an OrderFlow Kubernetes namespace."""
        return f"pods=healthy namespace={namespace}"

    @server.tool()
    def query_prometheus(svc: str = "checkout") -> str:
        """Query read-only RED metrics for an OrderFlow service."""
        return f"svc={svc} p99_ms=42 error_rate=0.001"

    @server.tool()
    def read_otel_trace(trace_id: str = "4bf92f") -> str:
        """Fetch an OTel GenAI trace span with redacted PII."""
        return f"trace_id={trace_id} status=OK"

    catalog = {
        "kubectl_get_pods": mt.Tool(
            name="kubectl_get_pods",
            description="Read pod health in OrderFlow namespace.",
            input_schema={
                "type": "object",
                "properties": {"namespace": {"type": "string"}},
            },
        ),
        "query_prometheus": mt.Tool(
            name="query_prometheus",
            description="Query Prometheus RED metrics.",
            input_schema={
                "type": "object",
                "properties": {"svc": {"type": "string"}},
            },
        ),
        "read_otel_trace": mt.Tool(
            name="read_otel_trace",
            description="Read sanitized OTel GenAI trace.",
            input_schema={
                "type": "object",
                "properties": {"trace_id": {"type": "string"}},
            },
        ),
    }
    return server, catalog


def inspect_tool_output(raw_text: str) -> tuple[bool, str]:
    """Guard tool outputs against embedded indirect injections."""
    lowered = raw_text.lower()
    if any(marker in lowered for marker in INJECTION_MARKERS):
        return False, "[REDACTED_UNSAFE_TOOL_OUTPUT]"
    return True, raw_text


def check_cel_allowlist(
    tool_name: str,
    args: dict[str, Any],
    allowed_tools: list[str],
) -> bool:
    """Simulate agentgateway CEL tool & argument policy evaluation."""
    if tool_name not in allowed_tools:
        return False
    if tool_name == "kubectl_get_pods":
        ns = str(args.get("namespace", ""))
        return ns.startswith("orderflow-")
    return True


def route_scenario(
    scenario: dict[str, Any],
    configs: dict[str, Any],
    catalog: dict[str, mt.Tool],
) -> dict[str, Any]:
    """Route a single agent request through governed AI gateways."""
    ag_cfg = configs["agentgateway-v1.7.0"]
    ar_cfg = configs["agent-router-v1beta1"]
    req_gw = scenario["gateway"]
    tool_name = scenario["tool"]
    args = scenario.get("args", {})

    if scenario.get("direct_egress", False):
        return {
            "id": scenario["id"],
            "status": "DENIED_DIRECT_BYPASS",
            "routed_via": "blocked",
            "mcp_encrypted": False,
        }

    if not check_cel_allowlist(
        tool_name, args, ag_cfg["cel_allowed_tools"]
    ):
        return {
            "id": scenario["id"],
            "status": "DENIED_CEL_ALLOWLIST",
            "routed_via": "blocked",
            "mcp_encrypted": ag_cfg["mcp_session_encryption"],
        }

    tokens = int(scenario.get("tokens_requested", 0))
    if tokens > int(ar_cfg["max_tokens_per_min"]):
        return {
            "id": scenario["id"],
            "status": "DENIED_TOKEN_BUDGET",
            "routed_via": "blocked",
            "mcp_encrypted": True,
        }

    routed_via = req_gw
    status = "ALLOWED"
    if req_gw == "agentgateway-v1.7.0" and not scenario["primary_up"]:
        routed_via = ag_cfg["fallback_gateway"]
        status = "ALLOWED_FAILOVER"

    tool_meta = catalog[tool_name]
    safe, payload = inspect_tool_output(
        f"tool={tool_meta.name} args={json.dumps(args)}"
    )
    mcp_res = mt.CallToolResult(
        content=[mt.TextContent(type="text", text=payload)],
        is_error=not safe,
    )
    return {
        "id": scenario["id"],
        "status": status,
        "routed_via": routed_via,
        "mcp_encrypted": ag_cfg["mcp_session_encryption"],
        "oauth_exchanged": ar_cfg["oauth_exchange_enabled"],
        "is_error": mcp_res.is_error,
    }


def run_simulation(matrix_path: Path = DEFAULT_MATRIX) -> dict[str, Any]:
    """Execute all gateway routing scenarios from JSON policy matrix."""
    data = json.loads(matrix_path.read_text(encoding="utf-8"))
    server, catalog = build_orderflow_mcp_server()
    results = [
        route_scenario(scn, data["gateway_configs"], catalog)
        for scn in data["scenarios"]
    ]
    allowed = sum(1 for r in results if r["status"].startswith("ALLOWED"))
    failovers = sum(
        1 for r in results if r["status"] == "ALLOWED_FAILOVER"
    )
    denied = sum(1 for r in results if r["status"].startswith("DENIED"))
    return {
        "server_name": server.name,
        "mcp_tools_registered": sorted(catalog.keys()),
        "total_scenarios": len(results),
        "allowed_count": allowed,
        "failover_count": failovers,
        "denied_count": denied,
        "cost_usd": 0.0,
        "results": results,
    }


def main() -> None:
    """Run offline gateway simulation and print JSON statistics."""
    summary = run_simulation()
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
