"""Pytest isolation and warm-pool tests for Chapter 03.

Author: Kien Nguyen
Verifies warm-pool hit ratios, L_p99 vs cold threshold, and rejection
of insecure runc/hostPath/privileged SandboxTemplate manifests.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import yaml

CH03_DIR = Path(__file__).resolve().parent
SIM_PATH = CH03_DIR / "03-warmpool-sizing-simulator.py"
SCENARIOS_PATH = CH03_DIR / "04-sandbox-workload-scenarios.json"
VALID_YAML = CH03_DIR / "01-gvisor-runtimeclass-and-sandbox-valid.yaml"
NEG_YAML = CH03_DIR / "02-runc-hostpath-sandbox-negative.yaml"


def _load_sim():
    spec = importlib.util.spec_from_file_location("pool_sim", SIM_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_warm_pool_hit_ratio_for_sized_pools() -> None:
    """Sized warm pools achieve >= 0.98 hit ratio and exact RAM GiB."""
    sim = _load_sim()
    report = sim.run_all_scenarios(SCENARIOS_PATH)
    by_name = {s["name"]: s for s in report["scenarios"]}

    sized = ("steady_ci_checks", "pr_merge_burst", "incident_storm_peak")
    for name in sized:
        row = by_name[name]
        assert row["warm_hit_ratio"] >= 0.98
        assert row["slo_met"] is True
    assert by_name["steady_ci_checks"]["standby_ram_gib"] == 1.0
    assert by_name["incident_storm_peak"]["standby_ram_gib"] == 2.0


def test_p99_latency_beats_cold_gvisor_threshold() -> None:
    """Sized pools beat cold threshold; undersized pool fails SLO."""
    sim = _load_sim()
    report = sim.run_all_scenarios(SCENARIOS_PATH)
    by_name = {s["name"]: s for s in report["scenarios"]}

    sized = ("steady_ci_checks", "pr_merge_burst", "incident_storm_peak")
    for name in sized:
        row = by_name[name]
        assert row["l_p99_ms"] < row["cold_baseline_p99_ms"]
        assert row["l_p99_ms"] == 113.0

    bad = by_name["undersized_pool_warning"]
    assert bad["l_p99_ms"] == bad["cold_baseline_p99_ms"]
    assert bad["slo_met"] is False


def test_sandbox_template_rejects_runc_hostpath_and_privileged() -> None:
    """Reject insecure SandboxTemplate and accept hardened gVisor spec."""
    sim = _load_sim()
    valid_docs = list(
        yaml.safe_load_all(VALID_YAML.read_text(encoding="utf-8"))
    )
    for doc in valid_docs:
        assert sim.validate_sandbox_template(doc) == []

    neg_docs = list(
        yaml.safe_load_all(NEG_YAML.read_text(encoding="utf-8"))
    )
    tmpl = next(d for d in neg_docs if d["kind"] == "SandboxTemplate")
    errs = sim.validate_sandbox_template(tmpl)
    assert errs == [
        "SANDBOX_RUNTIME_MUST_BE_GVISOR",
        "SANDBOX_HOSTPATH_DENIED",
        "SANDBOX_PRIVILEGED_DENIED",
    ]
