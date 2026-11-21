"""Pytest Suite for DeepEval Trajectory & Faithfulness CI Gate.

Author: Kien Nguyen
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest

CH08_DIR = Path(__file__).resolve().parent
EVAL_PATH = CH08_DIR / "04-deepeval-trajectory-evaluator.py"


def _load_evaluator():
    name = "ch08_deepeval_trajectory_evaluator"
    spec = importlib.util.spec_from_file_location(name, EVAL_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_candidate_a_passes_trajectory_and_faithfulness_gates() -> None:
    """Verify candidate_a passes all 6 Goldens and S_eval >= 0.90."""
    ev = _load_evaluator()
    res = ev.assert_eval_gate("candidate_a")

    assert res["passed"] is True
    assert res["rejection_reasons"] == []
    assert res["s_eval"] >= 0.90
    assert res["aggregate"]["tool_correctness"] >= 0.90
    assert res["aggregate"]["task_completion"] >= 0.90
    assert res["aggregate"]["faithfulness"] >= 0.90
    assert res["aggregate"]["max_hallucination"] == 0.0

    goldens, candidates = ev._load_goldens(ev.GOLDENS_PATH)
    for g in goldens:
        resp = candidates["candidate_a"]["responses"][g.golden_id]
        case = ev.LLMTestCase(
            input=g.input,
            actual_output="; ".join(resp["actual_claims"]),
            expected_output="; ".join(g.expected_facts),
            retrieval_context=g.context,
            context=g.context,
            tools_called=[
                ev.ToolCall(t["name"], t.get("args", {}))
                for t in resp["tools_called"]
            ],
            expected_tools=g.expected_tools,
        )
        ev.assert_test(
            case,
            [
                ev.ToolCorrectnessMetric(0.90),
                ev.TaskCompletionMetric(0.90),
                ev.FaithfulnessMetric(0.90),
                ev.HallucinationMetric(0.05),
            ],
        )


def test_candidate_b_rejected_for_hallucination_and_tools() -> None:
    """Verify candidate_b fails closed on hallucinated claims."""
    ev = _load_evaluator()
    res = ev.assert_eval_gate("candidate_b")

    assert res["passed"] is False
    assert len(res["rejection_reasons"]) == 4
    assert res["aggregate"]["max_hallucination"] > 0.05
    assert res["aggregate"]["tool_correctness"] < 0.90

    goldens, candidates = ev._load_goldens(ev.GOLDENS_PATH)
    g1 = goldens[0]
    resp1 = candidates["candidate_b"]["responses"][g1.golden_id]
    bad_case = ev.LLMTestCase(
        input=g1.input,
        actual_output="; ".join(resp1["actual_claims"]),
        expected_output="; ".join(g1.expected_facts),
        retrieval_context=g1.context,
        context=g1.context,
        tools_called=[
            ev.ToolCall(t["name"], t.get("args", {}))
            for t in resp1["tools_called"]
        ],
        expected_tools=g1.expected_tools,
    )
    with pytest.raises(AssertionError, match="HallucinationMetric"):
        ev.assert_test(
            bad_case,
            [
                ev.ToolCorrectnessMetric(0.90),
                ev.FaithfulnessMetric(0.90),
                ev.HallucinationMetric(0.05),
            ],
        )


def test_composite_s_eval_score_math() -> None:
    """Verify S_eval = 0.35*tool + 0.35*task + 0.30*faithfulness."""
    ev = _load_evaluator()
    res_a = ev.assert_eval_gate("candidate_a")
    agg_a = res_a["aggregate"]
    expected_a = round(
        0.35 * agg_a["tool_correctness"]
        + 0.35 * agg_a["task_completion"]
        + 0.30 * agg_a["faithfulness"],
        4,
    )
    assert res_a["s_eval"] == expected_a
    assert res_a["s_eval"] == 1.0

    res_b = ev.assert_eval_gate("candidate_b")
    agg_b = res_b["aggregate"]
    expected_b = round(
        0.35 * agg_b["tool_correctness"]
        + 0.35 * agg_b["task_completion"]
        + 0.30 * agg_b["faithfulness"],
        4,
    )
    assert res_b["s_eval"] == expected_b
    assert res_b["s_eval"] < 0.50
