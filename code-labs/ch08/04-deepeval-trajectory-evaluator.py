"""DeepEval v4.3.4-Compatible Offline Trajectory Evaluator ($0.00).

Author: Kien Nguyen
Implements ToolCall, LLMTestCase, Golden, ToolCorrectnessMetric,
TaskCompletionMetric, FaithfulnessMetric, HallucinationMetric, and
assert_eval_gate without requiring OPENAI_API_KEY.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re
from typing import Any

import yaml

CH08_DIR = Path(__file__).resolve().parent
GOLDENS_PATH = CH08_DIR / "01-orderflow-incident-goldens.json"
GATE_PATH = CH08_DIR / "02-eval-release-gate-valid.yaml"

FACT_TOKEN_RE = re.compile(
    r"[a-z]+=[a-z0-9._-]+|[0-9]+(?:\.[0-9]+)?%?(?:ms|s)?|"
    r"v[0-9]+\.[0-9]+|asi0[0-9]|oomkilled|outofsync|synced|"
    r"denied|succeeded|quarantined|exhausted|healthy|zero|4bf9"
)
WORD_RE = re.compile(r"[a-z0-9_-]{4,}")


@dataclass
class ToolCall:
    """Structured agent tool invocation for trajectory verification."""

    name: str
    input_parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMTestCase:
    """DeepEval-compatible offline evaluation test case."""

    input: str
    actual_output: str
    expected_output: str | None = None
    retrieval_context: list[str] = field(default_factory=list)
    context: list[str] = field(default_factory=list)
    tools_called: list[ToolCall] = field(default_factory=list)
    expected_tools: list[ToolCall] = field(default_factory=list)


@dataclass
class Golden:
    """OrderFlow incident evaluation golden record."""

    golden_id: str
    input: str
    expected_tools: list[ToolCall]
    context: list[str]
    expected_facts: list[str]


def _split_claims(text: str) -> list[str]:
    parts = re.split(r"[.;]\s+|\n+", text.strip())
    return [p.strip(" .;") for p in parts if p.strip(" .;")]


def _tool_matches(exp: ToolCall, actual: list[ToolCall]) -> bool:
    for act in actual:
        if act.name != exp.name:
            continue
        if all(
            act.input_parameters.get(k) == v
            for k, v in exp.input_parameters.items()
        ):
            return True
    return False


def _claim_grounded(claim: str, ctx_lower: str) -> bool:
    low = claim.lower()
    tokens = FACT_TOKEN_RE.findall(low)
    if any(tok not in ctx_lower for tok in tokens):
        return False
    words = WORD_RE.findall(low)
    if not words:
        return False
    hits = sum(1 for w in words if w in ctx_lower)
    return (hits / len(words)) >= 0.5


class ToolCorrectnessMetric:
    """DeepEval ToolCorrectnessMetric checking tool trajectory."""

    def __init__(self, threshold: float = 0.90) -> None:
        self.threshold = threshold
        self.score = 0.0
        self.success = False
        self.name = "ToolCorrectnessMetric"

    def measure(self, test_case: LLMTestCase) -> float:
        exp = test_case.expected_tools
        act = test_case.tools_called
        matched = sum(1 for tool in exp if _tool_matches(tool, act))
        denom = max(len(exp), len(act), 1)
        self.score = round(matched / denom, 4)
        self.success = self.score >= self.threshold
        return self.score


class TaskCompletionMetric:
    """DeepEval TaskCompletionMetric combining tools + goal facts."""

    def __init__(self, threshold: float = 0.90) -> None:
        self.threshold = threshold
        self.score = 0.0
        self.success = False
        self.name = "TaskCompletionMetric"

    def measure(self, test_case: LLMTestCase) -> float:
        exp = test_case.expected_tools
        act = test_case.tools_called
        tool_hits = sum(1 for t in exp if _tool_matches(t, act))
        tool_recall = tool_hits / max(len(exp), 1)

        facts = _split_claims(test_case.expected_output or "")
        out_low = test_case.actual_output.lower()
        if facts:
            fact_hits = sum(1 for f in facts if f.lower() in out_low)
            fact_recall = fact_hits / len(facts)
        else:
            fact_recall = 1.0

        self.score = round(0.5 * tool_recall + 0.5 * fact_recall, 4)
        self.success = self.score >= self.threshold
        return self.score


class FaithfulnessMetric:
    """DeepEval FaithfulnessMetric verifying claim grounding."""

    def __init__(self, threshold: float = 0.90) -> None:
        self.threshold = threshold
        self.score = 0.0
        self.success = False
        self.name = "FaithfulnessMetric"

    def measure(self, test_case: LLMTestCase) -> float:
        claims = _split_claims(test_case.actual_output)
        if not claims:
            self.score = 0.0
            self.success = False
            return self.score
        ctx = " ".join(test_case.retrieval_context).lower()
        grounded = sum(1 for c in claims if _claim_grounded(c, ctx))
        self.score = round(grounded / len(claims), 4)
        self.success = self.score >= self.threshold
        return self.score


class HallucinationMetric:
    """DeepEval HallucinationMetric flagging unsupported claims."""

    def __init__(self, threshold: float = 0.05) -> None:
        self.threshold = threshold
        self.score = 1.0
        self.success = False
        self.name = "HallucinationMetric"

    def measure(self, test_case: LLMTestCase) -> float:
        claims = _split_claims(test_case.actual_output)
        if not claims:
            self.score = 1.0
            self.success = False
            return self.score
        ctx_list = test_case.context or test_case.retrieval_context
        ctx = " ".join(ctx_list).lower()
        ungrounded = sum(
            1 for c in claims if not _claim_grounded(c, ctx)
        )
        self.score = round(ungrounded / len(claims), 4)
        self.success = self.score <= self.threshold
        return self.score


def assert_test(test_case: LLMTestCase, metrics: list[Any]) -> None:
    """DeepEval-style assertion raising AssertionError on failure."""
    failures: list[str] = []
    for metric in metrics:
        metric.measure(test_case)
        if not metric.success:
            failures.append(
                f"{metric.name}={metric.score} (limit {metric.threshold})"
            )
    if failures:
        raise AssertionError("; ".join(failures))


def _load_goldens(
    goldens_path: Path,
) -> tuple[list[Golden], dict[str, Any]]:
    raw = json.loads(goldens_path.read_text(encoding="utf-8"))
    goldens = [
        Golden(
            golden_id=g["golden_id"],
            input=g["input"],
            expected_tools=[
                ToolCall(t["name"], t.get("args", {}))
                for t in g["expected_tools"]
            ],
            context=list(g["retrieval_context"]),
            expected_facts=list(g["expected_facts"]),
        )
        for g in raw["goldens"]
    ]
    return goldens, raw["candidates"]


def assert_eval_gate(
    candidate_name: str,
    goldens_path: Path = GOLDENS_PATH,
    gate_spec_path: Path = GATE_PATH,
) -> dict[str, Any]:
    """Evaluate all 6 Goldens and compute S_eval and CI verdict."""
    spec = yaml.safe_load(
        gate_spec_path.read_text(encoding="utf-8")
    )["spec"]
    goldens, candidates = _load_goldens(goldens_path)
    cand = candidates[candidate_name]
    weights = spec["composite_weights"]
    max_halluc = float(spec.get("max_hallucination", 0.05))

    per_golden: list[dict[str, Any]] = []
    for g in goldens:
        resp = cand["responses"][g.golden_id]
        actual_tools = [
            ToolCall(t["name"], t.get("args", {}))
            for t in resp["tools_called"]
        ]
        case = LLMTestCase(
            input=g.input,
            actual_output="; ".join(resp["actual_claims"]),
            expected_output="; ".join(g.expected_facts),
            retrieval_context=g.context,
            context=g.context,
            tools_called=actual_tools,
            expected_tools=g.expected_tools,
        )
        m_tool = ToolCorrectnessMetric(0.90)
        m_task = TaskCompletionMetric(float(spec["min_task_completion"]))
        m_faith = FaithfulnessMetric(float(spec["min_faithfulness"]))
        m_hall = HallucinationMetric(max_halluc)

        s_tool = m_tool.measure(case)
        s_task = m_task.measure(case)
        s_faith = m_faith.measure(case)
        s_hall = m_hall.measure(case)
        per_golden.append(
            {
                "golden_id": g.golden_id,
                "tool_correctness": s_tool,
                "task_completion": s_task,
                "faithfulness": s_faith,
                "hallucination": s_hall,
            }
        )

    n = len(per_golden)
    avg_tool = round(
        sum(r["tool_correctness"] for r in per_golden) / n, 4
    )
    avg_task = round(
        sum(r["task_completion"] for r in per_golden) / n, 4
    )
    avg_faith = round(
        sum(r["faithfulness"] for r in per_golden) / n, 4
    )
    max_h = max(r["hallucination"] for r in per_golden)
    s_eval = round(
        weights["tool_correctness"] * avg_tool
        + weights["task_completion"] * avg_task
        + weights["faithfulness"] * avg_faith,
        4,
    )

    reasons: list[str] = []
    if spec["check_tool_trajectory"] and avg_tool < 0.90:
        reasons.append(f"ToolCorrectness {avg_tool} < 0.90")
    if avg_faith < float(spec["min_faithfulness"]):
        reasons.append(
            f"Faithfulness {avg_faith} < {spec['min_faithfulness']}"
        )
    if avg_task < float(spec["min_task_completion"]):
        reasons.append(
            f"TaskCompletion {avg_task} < {spec['min_task_completion']}"
        )
    if spec["block_on_unverified_claim"] and max_h > max_halluc:
        reasons.append(f"UnverifiedClaim max_hallucination={max_h}")

    return {
        "candidate": candidate_name,
        "label": cand["label"],
        "s_eval": s_eval,
        "aggregate": {
            "tool_correctness": avg_tool,
            "task_completion": avg_task,
            "faithfulness": avg_faith,
            "max_hallucination": max_h,
        },
        "passed": len(reasons) == 0,
        "rejection_reasons": reasons,
        "per_golden": per_golden,
    }


def main() -> None:
    """Evaluate Candidate A (pass) and Candidate B (rejected)."""
    res_a = assert_eval_gate("candidate_a")
    res_b = assert_eval_gate("candidate_b")
    print(json.dumps({"results": [res_a, res_b]}, indent=2))


if __name__ == "__main__":
    main()
