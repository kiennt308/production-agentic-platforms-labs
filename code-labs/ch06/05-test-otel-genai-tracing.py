"""Pytest Suite for OpenTelemetry GenAI SEP-414 & PII Redaction.

Author: Kien Nguyen
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import sys

import pytest

CH06_DIR = Path(__file__).resolve().parent
SAMPLE_PATH = CH06_DIR / "04-sample-mcp-trace-payloads.json"
MOD_PATH = CH06_DIR / "03-otel-genai-meta-propagator.py"

W3C_TRACEPARENT_RE = re.compile(
    r"^00-[0-9a-f]{32}-[0-9a-f]{16}-01$"
)


def _load_propagator_module():
    name = "ch06_otel_genai_meta_propagator"
    spec = importlib.util.spec_from_file_location(name, MOD_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_sep414_meta_traceparent_and_a2a_linkage() -> None:
    """Verify Host -> MCP _meta -> A2A preserve trace_id and parents."""
    mod = _load_propagator_module()
    payload = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    result = mod.run_trace_pipeline(payload, capture_content=False)

    assert result["span_count"] == 3
    assert W3C_TRACEPARENT_RE.match(result["mcp_meta_traceparent"])
    assert W3C_TRACEPARENT_RE.match(result["a2a_http_traceparent"])

    a2a_span, mcp_span, host_span = result["spans"]
    assert host_span["trace_id"] == result["trace_id"]
    assert mcp_span["trace_id"] == result["trace_id"]
    assert a2a_span["trace_id"] == result["trace_id"]

    assert host_span["parent_span_id"] is None
    assert mcp_span["parent_span_id"] == host_span["span_id"]
    assert a2a_span["parent_span_id"] == mcp_span["span_id"]
    assert mcp_span["attributes"]["mcp.method.name"] == "tools/call"
    assert mcp_span["attributes"]["gen_ai.operation.name"] == (
        "execute_tool"
    )


def test_gen_ai_provider_name_enforced() -> None:
    """Verify gen_ai.provider.name is used and gen_ai.system fails."""
    mod = _load_propagator_module()
    payload = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    result = mod.run_trace_pipeline(payload, capture_content=False)

    for span in result["spans"]:
        attrs = span["attributes"]
        assert "gen_ai.system" not in attrs
        assert attrs["gen_ai.provider.name"] == "aws.bedrock"

    with pytest.raises(ValueError, match="gen_ai.system"):
        mod.validate_genai_attributes({"gen_ai.system": "openai"})


def test_opt_in_default_false_zero_pii_leak() -> None:
    """Verify opt-in default False strips prompts and scrubs PII."""
    mod = _load_propagator_module()
    payload = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    result = mod.run_trace_pipeline(payload)

    assert result["capture_content"] is False
    assert result["pii_leaked_bytes"] == 0

    exported_text = json.dumps(result["spans"])
    assert "alice@orderflow.io" not in exported_text
    assert "sk-proj-98765432abcdef" not in exported_text
    assert "sk-admin-1122334455667788" not in exported_text
    assert "tok_live_abc123def456" not in exported_text
    assert "gen_ai.input.messages" not in exported_text
    assert "gen_ai.output.messages" not in exported_text
