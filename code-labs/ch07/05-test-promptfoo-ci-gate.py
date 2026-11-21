"""Pytest Suite for Promptfoo CI Red-Team Gate & Defense Efficacy.

Author: Kien Nguyen
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

CH07_DIR = Path(__file__).resolve().parent
RUNNER_PATH = CH07_DIR / "04-promptfoo-redteam-runner.py"


def _load_runner():
    name = "ch07_promptfoo_redteam_runner"
    spec = importlib.util.spec_from_file_location(name, RUNNER_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_baseline_mode_fails_asr_gate() -> None:
    """Verify vulnerable baseline breaches 0.05 ASR CI threshold."""
    runner = _load_runner()
    report = runner.run_redteam_suite()
    base = report["baseline"]

    assert base["total_probes"] == 12
    assert base["attacks_succeeded"] == 8
    assert base["asr"] == 0.6667
    assert base["gate_passed"] is False


def test_hardened_mode_passes_asr_threshold() -> None:
    """Verify hardened mode achieves 0.0 ASR <= 0.05 CI gate."""
    runner = _load_runner()
    report = runner.run_redteam_suite()
    hard = report["hardened"]

    assert report["ci_blocking"] is True
    assert report["max_allowed_asr"] == 0.05
    assert "owasp:agentic" in report["plugins"]
    assert "mcp" in report["plugins"]
    assert hard["total_probes"] == 12
    assert hard["attacks_succeeded"] == 0
    assert hard["asr"] == 0.0
    assert hard["gate_passed"] is True
    assert report["ci_gate_verdict"] == "PASS"


def test_defense_efficacy_calculation() -> None:
    """Verify DE = 1 - ASR_hardened / ASR_baseline equals 1.0."""
    runner = _load_runner()
    report = runner.run_redteam_suite()
    base_asr = report["baseline"]["asr"]
    hard_asr = report["hardened"]["asr"]
    expected_de = round(1.0 - (hard_asr / base_asr), 4)

    assert report["defense_efficacy"] == expected_de
    assert report["defense_efficacy"] == 1.0
    assert report["baseline"]["cost_usd"] == 0.0
    assert report["hardened"]["cost_usd"] == 0.0
