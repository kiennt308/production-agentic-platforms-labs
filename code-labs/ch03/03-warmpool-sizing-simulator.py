"""Warm-Pool Sizing & Latency Simulator for gVisor agent-sandbox.

Author: Kien Nguyen
Models SandboxWarmPool claim hit ratios, exact L_p99 latency vs cold
gVisor startup, standby RAM GiB, and sandbox template isolation guards.
"""

from __future__ import annotations

import heapq
import json
import math
from pathlib import Path
from typing import Any

DEFAULT_SCENARIOS = (
    Path(__file__).resolve().parent
    / "04-sandbox-workload-scenarios.json"
)


def percentile(values: list[float], pct: float) -> float:
    """Compute nearest-rank percentile on a non-empty float list."""
    if not values:
        raise ValueError("Cannot compute percentile of empty list")
    ordered = sorted(values)
    idx = max(0, math.ceil((pct / 100.0) * len(ordered)) - 1)
    return round(ordered[idx], 2)


def validate_sandbox_template(doc: dict[str, Any]) -> list[str]:
    """Validate SandboxTemplate against gVisor & isolation controls."""
    errors: list[str] = []
    if doc.get("kind") != "SandboxTemplate":
        return errors
    spec = doc.get("spec", {})
    if spec.get("runtimeClassName") != "gvisor":
        errors.append("SANDBOX_RUNTIME_MUST_BE_GVISOR")
    pod_spec = spec.get("template", {}).get("spec", {})
    for vol in pod_spec.get("volumes", []):
        if "hostPath" in vol:
            errors.append("SANDBOX_HOSTPATH_DENIED")
    for ctr in pod_spec.get("containers", []):
        sc = ctr.get("securityContext", {})
        if sc.get("privileged") is True:
            errors.append("SANDBOX_PRIVILEGED_DENIED")
    return errors


def simulate_scenario(scn: dict[str, Any]) -> dict[str, Any]:
    """Simulate deterministic arrivals on a gVisor SandboxWarmPool."""
    total = int(scn["total_requests"])
    replicas = int(scn["warm_pool_replicas"])
    interval = float(scn["arrival_interval_ms"])
    burst_k = int(scn["burst_every_k"])
    burst_sz = int(scn["burst_size"])
    warm_ms = float(scn["warm_claim_ms"])
    cold_ms = float(scn["cold_gvisor_boot_ms"])
    exec_ms = float(scn["exec_duration_ms"])
    ram_mb = float(scn["ram_mb_per_sandbox"])
    slo_ms = float(scn["slo_p99_ms"])

    pool_ready_at = [0.0] * replicas
    heapq.heapify(pool_ready_at)

    arrivals: list[float] = []
    t_now = 0.0
    req_idx = 0
    while len(arrivals) < total:
        arrivals.append(t_now)
        req_idx += 1
        if burst_k > 0 and req_idx % burst_k == 0:
            for _ in range(burst_sz - 1):
                if len(arrivals) < total:
                    arrivals.append(t_now)
        t_now += interval

    latencies: list[float] = []
    warm_hits = 0
    for t_arr in arrivals:
        if pool_ready_at and pool_ready_at[0] <= t_arr:
            heapq.heappop(pool_ready_at)
            heapq.heappush(pool_ready_at, t_arr + cold_ms)
            warm_hits += 1
            latencies.append(warm_ms + exec_ms)
        else:
            latencies.append(cold_ms + exec_ms)

    l_p50 = percentile(latencies, 50.0)
    l_p99 = percentile(latencies, 99.0)
    cold_baseline = round(cold_ms + exec_ms, 2)
    hit_ratio = round(warm_hits / total, 4)
    standby_gib = round((replicas * ram_mb) / 1024.0, 3)

    return {
        "name": scn["name"],
        "warm_pool_replicas": replicas,
        "total_requests": total,
        "warm_hits": warm_hits,
        "warm_hit_ratio": hit_ratio,
        "l_p50_ms": l_p50,
        "l_p99_ms": l_p99,
        "cold_baseline_p99_ms": cold_baseline,
        "standby_ram_gib": standby_gib,
        "slo_p99_ms": slo_ms,
        "slo_met": l_p99 <= slo_ms,
    }


def run_all_scenarios(
    scenarios_path: Path = DEFAULT_SCENARIOS,
) -> dict[str, Any]:
    """Run all OrderFlow sandbox warm-pool sizing scenarios."""
    payload = json.loads(scenarios_path.read_text(encoding="utf-8"))
    results = [simulate_scenario(s) for s in payload["scenarios"]]
    return {
        "runtime": payload["metadata"]["runtime"],
        "scenario_count": len(results),
        "cost_usd": 0.0,
        "scenarios": results,
    }


def main() -> None:
    """Execute warm-pool sizing simulation and print JSON metrics."""
    print(json.dumps(run_all_scenarios(), indent=2))


if __name__ == "__main__":
    main()
