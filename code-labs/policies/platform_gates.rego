package main

import rego.v1

# --------------------------------------------------------------------
# 1. Ch01: Platform Control Plane Baseline & Shadow-Agent Retirements
# --------------------------------------------------------------------
deny contains msg if {
	input.kind == "OrderFlowAgentPlatformBaseline"
	input.spec.gateway.allow_direct_egress == true
	msg := "GATEWAY_DIRECT_EGRESS_DENIED: route via agentgateway/router"
}

deny contains msg if {
	input.kind == "OrderFlowAgentPlatformBaseline"
	not input.spec.gateway.mcp_session_encryption
	msg := "GATEWAY_SESSION_ENCRYPTION_REQUIRED: enable MCP crypto"
}

deny contains msg if {
	input.kind == "OrderFlowAgentPlatformBaseline"
	input.spec.sandbox.runtime_class != "gvisor"
	msg := "SANDBOX_GVISOR_REQUIRED: avoid shared runc agent execution"
}

deny contains msg if {
	input.kind == "OrderFlowAgentPlatformBaseline"
	count(input.spec.security.owasp_asi_covered) < 10
	msg := "OWASP_ASI_MATRIX_REQUIRED: cover all ASI01-ASI10 risks"
}

deny contains msg if {
	input.kind == "OrderFlowAgentPlatformBaseline"
	not input.spec.security.kill_switch_enabled
	msg := "KILL_SWITCH_REQUIRED: deploy out-of-band agent circuit break"
}

deny contains msg if {
	input.kind == "OrderFlowAgentPlatformBaseline"
	input.spec.observability.uses_deprecated_gen_ai_system == true
	msg := "OTEL_DEPRECATED_SYSTEM_ATTR: migrate to gen_ai.provider.name"
}

deny contains msg if {
	input.kind == "OrderFlowAgentPlatformBaseline"
	input.spec.observability.default_content_capture == true
	msg := "OTEL_DEFAULT_PII_CAPTURE_DENIED: require Opt-In capture"
}

deny contains msg if {
	input.kind == "OrderFlowAgentPlatformBaseline"
	not input.spec.evals.promptfoo_enabled
	msg := "CI_EVALS_GATE_REQUIRED: enable Promptfoo red-team checks"
}

deny contains msg if {
	input.kind == "OrderFlowAgentPlatformBaseline"
	not input.spec.evals.deepeval_enabled
	msg := "CI_EVALS_GATE_REQUIRED: enable DeepEval trajectory checks"
}

deny contains msg if {
	input.kind == "OrderFlowAgentPlatformBaseline"
	input.spec.finops.claims_native_focus12_tokens == true
	msg := "FOCUS_TOKEN_GAP_UNBRIDGED: ETL gateway tokens for FOCUS"
}

# --------------------------------------------------------------------
# 2. Ch02: Unified agentgateway v1.7.0 & Agent Router v1.1+
# --------------------------------------------------------------------
deny contains msg if {
	input.kind == "AgentgatewayPolicy"
	not input.spec.mcp.session_encryption_enabled
	msg := "MCP_SESSION_ENCRYPTION_OFF: enforce default MCP encryption"
}

deny contains msg if {
	input.kind == "AgentgatewayPolicy"
	not input.spec.guardrails.tool_output_inspection
	msg := "TOOL_OUTPUT_GUARD_MISSING: inspect all MCP tool outputs"
}

deny contains msg if {
	input.kind == "AgentgatewayPolicy"
	count(input.spec.mcp.cel_allowed_tools) == 0
	msg := "MCP_CEL_FILTER_MISSING: allowlist tools via CEL expression"
}

deny contains msg if {
	input.kind == "AIGatewayRoute"
	startswith(input.apiVersion, "aigateway.envoyproxy.io/v1alpha1")
	msg := "ENVOY_V1ALPHA1_RETIRED: upgrade to Agent Router v1beta1"
}

deny contains msg if {
	input.kind == "AIGatewayRoute"
	not input.spec.mcp.oauth_exchange_enabled
	msg := "MCP_OAUTH_MISSING: require OAuth token exchange on route"
}

deny contains msg if {
	input.kind == "AIGatewayRoute"
	not input.spec.rate_limiting.token_budget_enabled
	msg := "GATEWAY_TOKEN_LIMIT_MISSING: bind per-tenant token quota"
}

deny contains msg if {
	input.kind == "AIGatewayRoute"
	input.spec.direct_egress_bypass == true
	msg := "GATEWAY_DIRECT_BYPASS_DENIED: forbid direct LLM egress"
}

# --------------------------------------------------------------------
# 3. Ch03: K8s SIG Apps agent-sandbox v1.0.x & gVisor (runsc)
# --------------------------------------------------------------------
deny contains msg if {
	input.kind == "SandboxTemplate"
	input.spec.runtimeClassName != "gvisor"
	msg := "SANDBOX_RUNTIME_MUST_BE_GVISOR: set runtimeClassName gvisor"
}

deny contains msg if {
	input.kind == "SandboxTemplate"
	some v in input.spec.template.spec.volumes
	v.hostPath
	msg := "SANDBOX_HOSTPATH_DENIED: prohibit hostPath inside sandbox"
}

deny contains msg if {
	input.kind == "SandboxTemplate"
	some c in input.spec.template.spec.containers
	c.securityContext.privileged == true
	msg := "SANDBOX_PRIVILEGED_DENIED: forbid privileged containers"
}

deny contains msg if {
	input.kind == "SandboxWarmPool"
	input.spec.replicas < 2
	msg := "WARMPOOL_REPLICAS_TOO_LOW: keep >= 2 warm gVisor pods"
}

deny contains msg if {
	input.kind == "Sandbox"
	input.apiVersion != "agents.x-k8s.io/v1beta1"
	msg := "SANDBOX_API_MUST_BE_V1BETA1: upgrade Sandbox CRD API"
}

# --------------------------------------------------------------------
# 4. Ch04: OWASP ASI01-ASI10 Coverage & Principle of Least Agency
# --------------------------------------------------------------------
deny contains msg if {
	input.kind == "OrderFlowAgentAgencySpec"
	count(input.spec.owasp_asi_covered) < 10
	msg := "OWASP_ASI_INCOMPLETE: mitigate all 10 ASI01-ASI10 items"
}

deny contains msg if {
	input.kind == "OrderFlowAgentAgencySpec"
	input.spec.least_agency.cluster_admin_bound == true
	msg := "STATIC_ADMIN_ROLE_DENIED: cluster-admin violates ASI03"
}

deny contains msg if {
	input.kind == "OrderFlowAgentAgencySpec"
	input.spec.least_agency.token_ttl_seconds > 300
	msg := "TOKEN_TTL_EXCEEDS_MAX: cap delegated token TTL <= 300s"
}

deny contains msg if {
	input.kind == "OrderFlowAgentAgencySpec"
	not input.spec.supply_chain.mcp_sha256_pinned
	msg := "MCP_DIGEST_UNPINNED: pin MCP server SHA-256 against ASI04"
}

# --------------------------------------------------------------------
# 5. Ch05: Runtime OPA/Kyverno Guardrails, RAG Filter & Kill Switch
# --------------------------------------------------------------------
deny contains msg if {
	input.kind == "OrderFlowGuardrailConfig"
	input.spec.enforcement_mode != "external_opa_cel"
	msg := "IN_PROMPT_ONLY_RETIRED: enforce rules outside LLM prompt"
}

deny contains msg if {
	input.kind == "OrderFlowGuardrailConfig"
	not input.spec.rag_isolation.strip_embedded_instructions
	msg := "INDIRECT_INJECTION_FILTER_MISSING: isolate RAG payloads"
}

deny contains msg if {
	input.kind == "OrderFlowGuardrailConfig"
	not input.spec.a2a.require_signed_envelope
	msg := "A2A_SIGNATURE_REQUIRED: authenticate inter-agent hops"
}

deny contains msg if {
	input.kind == "OrderFlowGuardrailConfig"
	not input.spec.kill_switch.enabled
	msg := "KILL_SWITCH_LOOP_CAP_MISSING: enable runaway kill switch"
}

deny contains msg if {
	input.kind == "OrderFlowGuardrailConfig"
	input.spec.kill_switch.max_tool_calls_per_task > 20
	msg := "KILL_SWITCH_LOOP_CAP_MISSING: cap tool hops <= 20 per task"
}

deny contains msg if {
	input.kind == "ValidatingPolicy"
	input.apiVersion != "policies.kyverno.io/v1"
	msg := "KYVERNO_CEL_API_REQUIRED: use policies.kyverno.io/v1"
}

deny contains msg if {
	input.kind == "ClusterPolicy"
	startswith(input.apiVersion, "kyverno.io/")
	msg := "KYVERNO_CLUSTERPOLICY_RETIRED: migrate to ValidatingPolicy"
}

# --------------------------------------------------------------------
# 6. Ch06: OpenTelemetry GenAI, SEP-414 _meta & Opt-In Privacy
# --------------------------------------------------------------------
deny contains msg if {
	input.kind == "OrderFlowOtelGenAIConfig"
	input.spec.uses_gen_ai_system_attr == true
	msg := "OTEL_GENAI_SYSTEM_DEPRECATED: use gen_ai.provider.name"
}

deny contains msg if {
	input.kind == "OrderFlowOtelGenAIConfig"
	input.spec.provider_attr != "gen_ai.provider.name"
	msg := "OTEL_PROVIDER_NAME_REQUIRED: require gen_ai.provider.name"
}

deny contains msg if {
	input.kind == "OrderFlowOtelGenAIConfig"
	not input.spec.mcp_meta_traceparent_enabled
	msg := "OTEL_MCP_META_TRACEPARENT_MISSING: enable SEP-414 _meta"
}

deny contains msg if {
	input.kind == "OrderFlowOtelGenAIConfig"
	input.spec.capture_message_content_default == true
	msg := "OTEL_OPTIN_CAPTURE_MUST_DEFAULT_FALSE: keep content opt-in"
}

deny contains msg if {
	input.kind == "OrderFlowOtelGenAIConfig"
	not input.spec.pii_redaction_enabled
	msg := "OTEL_PII_REDACTION_REQUIRED: scrub secrets before export"
}

# --------------------------------------------------------------------
# 7. Ch07: Promptfoo YAML Red-Teaming CI Gate
# --------------------------------------------------------------------
deny contains msg if {
	input.kind == "OrderFlowPromptfooGateSpec"
	not input.spec.ci_blocking
	msg := "PROMPTFOO_VIBE_EVAL_RETIRED: enforce blocking CI redteam"
}

deny contains msg if {
	input.kind == "OrderFlowPromptfooGateSpec"
	not ("owasp:agentic" in input.spec.plugins)
	msg := "PROMPTFOO_OWASP_PLUGIN_MISSING: enable owasp:agentic"
}

deny contains msg if {
	input.kind == "OrderFlowPromptfooGateSpec"
	not ("mcp" in input.spec.plugins)
	msg := "PROMPTFOO_MCP_PLUGIN_MISSING: enable mcp attack plugin"
}

deny contains msg if {
	input.kind == "OrderFlowPromptfooGateSpec"
	input.spec.max_allowed_asr > 0.05
	msg := "PROMPTFOO_ASR_THRESHOLD_TOO_HIGH: cap allowed ASR <= 0.05"
}

# --------------------------------------------------------------------
# 8. Ch08: DeepEval Trajectory & Faithfulness CI Gate
# --------------------------------------------------------------------
deny contains msg if {
	input.kind == "OrderFlowDeepEvalGateSpec"
	not input.spec.check_tool_trajectory
	msg := "DEEPEVAL_OUTPUT_ONLY_RETIRED: assert ToolCorrectness"
}

deny contains msg if {
	input.kind == "OrderFlowDeepEvalGateSpec"
	input.spec.min_faithfulness < 0.90
	msg := "DEEPEVAL_FAITHFULNESS_REQUIRED: require >= 0.90 faithfulness"
}

deny contains msg if {
	input.kind == "OrderFlowDeepEvalGateSpec"
	input.spec.min_task_completion < 0.90
	msg := "DEEPEVAL_TASK_COMPLETION_REQUIRED: require >= 0.90 complete"
}

deny contains msg if {
	input.kind == "OrderFlowDeepEvalGateSpec"
	not input.spec.block_on_unverified_claim
	msg := "DEEPEVAL_HALLUCINATION_UNBLOCKED: gate unsupported claims"
}

# --------------------------------------------------------------------
# 9. Ch09: Enterprise Agentic FinOps (FOCUS) & 20-Point Capstone PRR
# --------------------------------------------------------------------
deny contains msg if {
	input.document_type == "OrderFlowCapstonePRR"
	input.gates_passed < 20
	msg := "CAPSTONE_PRR_INCOMPLETE: require 20/20 passed PRR controls"
}

deny contains msg if {
	input.document_type == "OrderFlowCapstonePRR"
	count(input.domains) < 5
	msg := "CAPSTONE_PRR_INCOMPLETE: verify all 5 platform domains"
}

deny contains msg if {
	input.document_type == "OrderFlowCapstonePRR"
	not input.finops.per_task_token_cap_enforced
	msg := "RUNAWAY_SPEND_CAP_MISSING: cap tokens per agent session"
}

deny contains msg if {
	input.document_type == "OrderFlowCapstonePRR"
	input.finops.claims_native_focus12_tokens == true
	msg := "FOCUS_TOKEN_ETL_REQUIRED: FOCUS 1.2/1.3 lacks native tokens"
}

deny contains msg if {
	input.document_type == "OrderFlowCapstonePRR"
	not input.finops.gateway_otel_etl_enabled
	msg := "FOCUS_TOKEN_ETL_REQUIRED: enable OTel/Gateway FOCUS ETL"
}
