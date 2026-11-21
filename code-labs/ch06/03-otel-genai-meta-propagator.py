"""OpenTelemetry GenAI Trace Propagator with SEP-414 _meta & Redaction.

Author: Kien Nguyen
Uses opentelemetry-api 1.44.0 W3C TraceContextTextMapPropagator to link
Host Agent -> MCP JSON-RPC params._meta.traceparent -> A2A HTTP hops.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
import copy
import json
from pathlib import Path
import re
from typing import Any

from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry.trace import (
    Span,
    SpanContext,
    SpanKind,
    Status,
    StatusCode,
    TraceFlags,
    format_span_id,
    format_trace_id,
)
from opentelemetry.trace.propagation.tracecontext import (
    TraceContextTextMapPropagator,
)
from opentelemetry.util import types as otel_types

SAMPLE_PATH = (
    Path(__file__).resolve().parent
    / "04-sample-mcp-trace-payloads.json"
)
EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)
SK_KEY_RE = re.compile(r"sk-[A-Za-z0-9_-]{8,}")
BEARER_RE = re.compile(r"Bearer\s+[A-Za-z0-9._-]+")
PII_PATTERNS = (EMAIL_RE, SK_KEY_RE, BEARER_RE)


def redact_pii(value: Any) -> Any:
    """Scrub emails, sk-* keys, and Bearer tokens recursively."""
    if isinstance(value, str):
        cleaned = EMAIL_RE.sub("[REDACTED_EMAIL]", value)
        cleaned = SK_KEY_RE.sub("[REDACTED_KEY]", cleaned)
        return BEARER_RE.sub("Bearer [REDACTED_TOKEN]", cleaned)
    if isinstance(value, list):
        return [redact_pii(item) for item in value]
    if isinstance(value, dict):
        return {k: redact_pii(v) for k, v in value.items()}
    return value


def validate_genai_attributes(attrs: Mapping[str, Any]) -> None:
    """Enforce gen_ai.provider.name and reject gen_ai.system."""
    if "gen_ai.system" in attrs:
        raise ValueError(
            "Deprecated gen_ai.system rejected; use gen_ai.provider.name"
        )
    has_genai = any(k.startswith("gen_ai.") for k in attrs)
    if has_genai and not attrs.get("gen_ai.provider.name"):
        raise ValueError(
            "Missing required gen_ai.provider.name attribute"
        )


def count_pii_leaked_bytes(spans: list[dict[str, Any]]) -> int:
    """Return total matched bytes of unredacted PII/secrets in spans."""
    serialized = json.dumps(spans, sort_keys=True)
    leaked = 0
    for pattern in PII_PATTERNS:
        for match in pattern.finditer(serialized):
            leaked += len(match.group(0).encode("utf-8"))
    return leaked


class DeterministicSpan(Span):
    """Lightweight opentelemetry.trace.Span for $0.00 offline export."""

    def __init__(
        self,
        name: str,
        context: SpanContext,
        parent_span_id: str | None,
        kind: SpanKind,
        collector: DeterministicCollector,
        attributes: Mapping[str, otel_types.AttributeValue] | None,
    ) -> None:
        self._name = name
        self._context = context
        self._parent_span_id = parent_span_id
        self._kind = kind
        self._collector = collector
        self._attrs: dict[str, Any] = {}
        self._events: list[dict[str, Any]] = []
        self._status = Status(StatusCode.OK)
        self._recording = True
        if attributes:
            self.set_attributes(attributes)

    def end(self, end_time: int | None = None) -> None:
        if not self._recording:
            return
        self._recording = False
        validate_genai_attributes(self._attrs)
        self._collector.exported.append(self.to_dict())

    def get_span_context(self) -> SpanContext:
        return self._context

    def set_attributes(
        self, attributes: Mapping[str, otel_types.AttributeValue]
    ) -> None:
        for key, val in attributes.items():
            self.set_attribute(key, val)

    def set_attribute(
        self, key: str, value: otel_types.AttributeValue
    ) -> None:
        if key == "gen_ai.system":
            raise ValueError(
                "Deprecated gen_ai.system rejected; "
                "use gen_ai.provider.name"
            )
        self._attrs[key] = redact_pii(value)

    def add_event(
        self,
        name: str,
        attributes: otel_types.Attributes = None,
        timestamp: int | None = None,
    ) -> None:
        clean_attrs = redact_pii(dict(attributes or {}))
        self._events.append({"name": name, "attributes": clean_attrs})

    def update_name(self, name: str) -> None:
        self._name = name

    def is_recording(self) -> bool:
        return self._recording

    def set_status(
        self,
        status: Status | StatusCode,
        description: str | None = None,
    ) -> None:
        if isinstance(status, Status):
            self._status = status
        else:
            self._status = Status(status, description)

    def record_exception(
        self,
        exception: BaseException,
        attributes: otel_types.Attributes = None,
        timestamp: int | None = None,
        escaped: bool = False,
    ) -> None:
        err_attrs = {"exception.type": type(exception).__name__}
        if attributes:
            err_attrs.update(dict(attributes))
        self.add_event("exception", err_attrs, timestamp)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self._name,
            "kind": self._kind.name,
            "trace_id": format_trace_id(self._context.trace_id),
            "span_id": format_span_id(self._context.span_id),
            "parent_span_id": self._parent_span_id,
            "attributes": dict(self._attrs),
            "events": list(self._events),
            "status": self._status.status_code.name,
        }


class DeterministicTracer(trace.Tracer):
    """Tracer emitting DeterministicSpan records without SDK."""

    def __init__(self, collector: DeterministicCollector) -> None:
        self._collector = collector

    def start_span(
        self,
        name: str,
        context: otel_context.Context | None = None,
        kind: SpanKind = SpanKind.INTERNAL,
        attributes: otel_types.Attributes = None,
        links: Sequence[trace.Link] | None = None,
        start_time: int | None = None,
        record_exception: bool = True,
        set_status_on_exception: bool = True,
    ) -> Span:
        active_ctx = context or otel_context.get_current()
        parent_span = trace.get_current_span(active_ctx)
        parent_ctx = parent_span.get_span_context()
        if parent_ctx.is_valid:
            trace_id = parent_ctx.trace_id
            parent_id: str | None = format_span_id(parent_ctx.span_id)
        else:
            trace_id = self._collector.trace_id
            parent_id = None
        span_id = self._collector.next_span_id()
        span_ctx = SpanContext(
            trace_id=trace_id,
            span_id=span_id,
            is_remote=False,
            trace_flags=TraceFlags(TraceFlags.SAMPLED),
        )
        return DeterministicSpan(
            name=name,
            context=span_ctx,
            parent_span_id=parent_id,
            kind=kind,
            collector=self._collector,
            attributes=attributes,
        )

    @contextmanager
    def start_as_current_span(
        self,
        name: str,
        context: otel_context.Context | None = None,
        kind: SpanKind = SpanKind.INTERNAL,
        attributes: otel_types.Attributes = None,
        links: Sequence[trace.Link] | None = None,
        start_time: int | None = None,
        record_exception: bool = True,
        set_status_on_exception: bool = True,
        end_on_exit: bool = True,
    ) -> Iterator[Span]:
        span = self.start_span(
            name=name,
            context=context,
            kind=kind,
            attributes=attributes,
        )
        with trace.use_span(span, end_on_exit=end_on_exit) as active:
            yield active


class DeterministicCollector(trace.TracerProvider):
    """In-memory deterministic collector implementing TracerProvider."""

    def __init__(
        self, trace_id: int = 0x4BF92F3577B34DA6A3CE929D0E0E4736
    ) -> None:
        self.trace_id = trace_id
        self._seq = 0
        self.exported: list[dict[str, Any]] = []

    def next_span_id(self) -> int:
        self._seq += 1
        return 0x00F067AA0BA902B0 + self._seq

    def get_tracer(
        self,
        instrumenting_module_name: str,
        instrumenting_library_version: str | None = None,
        schema_url: str | None = None,
        attributes: otel_types.Attributes | None = None,
    ) -> trace.Tracer:
        return DeterministicTracer(self)


def run_trace_pipeline(
    payload: dict[str, Any], capture_content: bool = False
) -> dict[str, Any]:
    """Propagate traceparent across Host -> MCP _meta -> A2A HTTP."""
    work = copy.deepcopy(payload)
    collector = DeterministicCollector()
    tracer = collector.get_tracer("orderflow.otel.genai", "1.44.0")
    propagator = TraceContextTextMapPropagator()

    mcp_req = work["mcp_request"]
    mcp_meta = mcp_req["params"]["_meta"]
    a2a = work["a2a_handoff"]

    host_attrs: dict[str, Any] = {
        "gen_ai.operation.name": "invoke_agent",
        "gen_ai.provider.name": work["provider"],
        "gen_ai.request.model": work["model"],
        "gen_ai.agent.name": work["host_agent"],
        "orderflow.opt_in_content": capture_content,
    }
    if capture_content:
        host_attrs["gen_ai.input.messages"] = work["raw_prompt"]
        host_attrs["gen_ai.output.messages"] = work["raw_response"]

    with tracer.start_as_current_span(
        f"invoke_agent {work['host_agent']}",
        kind=SpanKind.CLIENT,
        attributes=host_attrs,
    ):
        propagator.inject(mcp_meta)
        mcp_parent_ctx = propagator.extract(mcp_meta)
        args = mcp_req["params"]["arguments"]
        mcp_attrs: dict[str, Any] = {
            "gen_ai.operation.name": "execute_tool",
            "gen_ai.provider.name": work["provider"],
            "gen_ai.tool.name": mcp_req["params"]["name"],
            "mcp.method.name": mcp_req["method"],
            "orderflow.order_id": args["order_id"],
            "orderflow.requester": args["requester"],
            "orderflow.auth_hint": args["auth_hint"],
        }
        with tracer.start_as_current_span(
            f"execute_tool {mcp_req['params']['name']}",
            context=mcp_parent_ctx,
            kind=SpanKind.SERVER,
            attributes=mcp_attrs,
        ):
            propagator.inject(a2a["headers"])
            a2a_parent_ctx = propagator.extract(a2a["headers"])
            a2a_attrs: dict[str, Any] = {
                "gen_ai.operation.name": "invoke_agent",
                "gen_ai.provider.name": work["provider"],
                "gen_ai.agent.name": a2a["target_agent"],
                "a2a.skill": a2a["skill"],
                "a2a.note": a2a["note"],
            }
            with tracer.start_as_current_span(
                f"invoke_agent {a2a['target_agent']}",
                context=a2a_parent_ctx,
                kind=SpanKind.SERVER,
                attributes=a2a_attrs,
            ):
                pass

    leaked = count_pii_leaked_bytes(collector.exported)
    return {
        "trace_id": format_trace_id(collector.trace_id),
        "span_count": len(collector.exported),
        "capture_content": capture_content,
        "pii_leaked_bytes": leaked,
        "mcp_meta_traceparent": mcp_meta["traceparent"],
        "a2a_http_traceparent": a2a["headers"]["traceparent"],
        "spans": collector.exported,
    }


def main() -> None:
    """Run SEP-414 + A2A trace pipeline on sample fixture at $0.00."""
    payload = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    summary = run_trace_pipeline(payload, capture_content=False)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
