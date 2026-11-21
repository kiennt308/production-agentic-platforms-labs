# Production Agentic Platforms: Companion Repository (Zero-Bill Labs)

> **Author & Publisher:** Kien Nguyen (`https://github.com/kiennt308`)
> **Repository:**
> `https://github.com/kiennt308/production-agentic-platforms-labs`
> **License:** Apache-2.0 (`code-labs/` source, policies, and fixtures)
> **Contract:** **$0.00 Cloud Spend** & **$0.00 Paid LLM API Spend**

Companion lab repository for **Volume 10 (Capstone)** of the
*Practical Engineering Series*. Every manifest, Rego/Kyverno gate,
sandbox spec, `OWASP ASI01-ASI10` guardrail, `OpenTelemetry GenAI`
trace propagator, `Promptfoo` red-team suite, `DeepEval` trajectory
`pytest` check, and `SQLite` FinOps `FOCUS` correlator runs locally
with zero paid cloud or LLM keys.

---

## Verified Local Toolchain

* **Python 3.11+:** `pytest`, `opentelemetry-api`, `mcp`, `cryptography`
* **Containerized Policy Gate:** `openpolicyagent/conftest:latest`
* **Optional Local Model:** Point `LLM_BASE_URL` to local Ollama
  (`http://127.0.0.1:11434/v1`) instead of deterministic replay mode.

---

## Chapter Map (48 Files Total)

| Path | Count | Verified Capstone Control Plane Scope |
| :--- | :---: | :--- |
| `README.md` | 1 | Zero-bill guide and verification commands |
| `policies/platform_gates.rego` | 1 | `51` Rego v1 gates (Ch. 1-9) |
| `ch01/` | 4 | Replay gateway, control-plane router, baseline |
| `ch02/` | 6 | `agentgateway v1.7`, `Agent Router`, `MCP` sim |
| `ch03/` | 5 | `agent-sandbox` + `gVisor` `runsc` & WarmPool math |
| `ch04/` | 5 | `OWASP ASI01-ASI10` matrix & Least Agency gates |
| `ch05/` | 6 | OPA tool blocker, RAG sanitizer & Kill Switch |
| `ch06/` | 5 | `OTel GenAI` `_meta.traceparent` & PII redactor |
| `ch07/` | 5 | `Promptfoo` YAML red-team (`owasp:agentic`/`mcp`) |
| `ch08/` | 5 | `DeepEval` trajectory & faithfulness `pytest` gate |
| `ch09/` | 5 | `FOCUS 1.2-1.4` token ETL, ROI & `20`-pt PRR |

---

## Quick Offline Verification (`$0.00` Spend)

Run Conftest across all positive manifests (`100%` pass) and confirm all
`9` negative controls fail closed with exit code `1`:

```bash
cd code-labs

docker run --rm -v "${PWD}:/work" -w /work \
  openpolicyagent/conftest:latest test \
  -p policies/platform_gates.rego \
  ch01/03-platform-baseline-valid.yaml \
  ch02/01-agentgateway-v17-config-valid.yaml \
  ch02/02-agent-router-v1beta1-valid.yaml \
  ch03/01-gvisor-runtimeclass-and-sandbox-valid.yaml \
  ch04/02-least-agency-manifest-valid.yaml \
  ch05/01-guardrail-and-killswitch-valid.yaml \
  ch05/03-kyverno-v119-agent-cel-valid.yaml \
  ch06/01-otel-collector-genai-valid.yaml \
  ch07/01-promptfoo-redteam-config-valid.yaml \
  ch08/02-eval-release-gate-valid.yaml \
  ch09/03-capstone-prr-ready.json

for neg in ch01/04-* ch02/03-* ch03/02-* ch04/03-* \
  ch05/02-* ch06/02-* ch07/02-* ch08/03-* ch09/04-*; do
  ! docker run --rm -v "${PWD}:/work" -w /work \
    openpolicyagent/conftest:latest test \
    -p policies/platform_gates.rego "$neg" >/dev/null
done
```

Execute all `8` `pytest` test modules cleanly without cache leakage:

```bash
PYTHONDONTWRITEBYTECODE=1 pytest -v -p no:cacheprovider \
  ch02/06-test-gateway-routing.py \
  ch03/05-test-sandbox-isolation.py \
  ch04/05-test-owasp-asi-coverage.py \
  ch05/06-test-guardrails-and-killswitch.py \
  ch06/05-test-otel-genai-tracing.py \
  ch07/05-test-promptfoo-ci-gate.py \
  ch08/05-test-deepeval-trajectories.py \
  ch09/05-test-finops-and-capstone-prr.py
```
