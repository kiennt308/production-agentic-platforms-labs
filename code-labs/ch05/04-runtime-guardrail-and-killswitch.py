"""Runtime Guardrail, RAG Sanitizer, A2A ECDSA Signer & Kill Switch.

Author: Kien Nguyen
Implements external deterministic tool interception, RAG prompt-injection
stripping, ECDSA SECP256R1 A2A signing, and Kill Switch state machine.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

DEFAULT_FIXTURE = (
    Path(__file__).resolve().parent
    / "05-adversarial-events-fixture.json"
)
BLOCKED_ARG_PATTERNS = (
    "rm -rf",
    "kubectl delete",
    "terraform destroy",
    "/var/run/docker.sock",
    "/etc/shadow",
    "--privileged",
    "| bash",
    "$(",
)
INJECTION_PATTERNS = (
    re.compile(r"<system>.*?</system>", re.IGNORECASE | re.DOTALL),
    re.compile(r"\[SYSTEM OVERRIDE\].*", re.IGNORECASE),
    re.compile(r"ignore previous instructions.*", re.IGNORECASE),
    re.compile(r"<!--.*?-->", re.DOTALL),
    re.compile(r"curl\s+\S+\s*\|\s*bash", re.IGNORECASE),
)
STATES = ("ARMED", "DEGRADED", "TRIPPED", "KILLED")


def evaluate_tool_call(
    tool_name: str, args: dict[str, Any]
) -> tuple[bool, str]:
    """Deterministically block destructive CLI and host-path calls."""
    serialized = f"{tool_name} {json.dumps(args, sort_keys=True)}".lower()
    for token in BLOCKED_ARG_PATTERNS:
        if token in serialized:
            return False, f"blocked_pattern:{token}"
    if tool_name == "exec_shell":
        return False, "blocked_unapproved_shell"
    return True, "allowed"


def sanitize_rag_chunk(raw_text: str) -> tuple[str, list[str]]:
    """Strip indirect prompt-injection tags and payloads from RAG."""
    cleaned = raw_text
    findings: list[str] = []
    for pat in INJECTION_PATTERNS:
        if pat.search(cleaned):
            findings.append(pat.pattern)
            cleaned = pat.sub("[STRIPPED_INSTRUCTION]", cleaned)
    return cleaned.strip(), findings


def generate_a2a_keypair() -> tuple[
    ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey
]:
    """Generate an ephemeral ECDSA SECP256R1 keypair for A2A hops."""
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


def sign_a2a_envelope(
    payload: dict[str, Any], priv_key: ec.EllipticCurvePrivateKey
) -> dict[str, Any]:
    """Sign canonical A2A payload JSON using ECDSA-P256-SHA256."""
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    sig = priv_key.sign(body, ec.ECDSA(hashes.SHA256()))
    return {
        "alg": "ECDSA-SECP256R1-SHA256",
        "payload": payload,
        "signature_b64": base64.b64encode(sig).decode("ascii"),
    }


def verify_a2a_envelope(
    envelope: dict[str, Any], pub_key: ec.EllipticCurvePublicKey
) -> bool:
    """Verify A2A envelope signature; fail closed on any tampering."""
    try:
        sig = base64.b64decode(envelope["signature_b64"].encode("ascii"))
        body = json.dumps(
            envelope["payload"], sort_keys=True
        ).encode("utf-8")
        pub_key.verify(sig, body, ec.ECDSA(hashes.SHA256()))
        return True
    except (KeyError, ValueError, InvalidSignature):
        return False


class KillSwitchStateMachine:
    """Out-of-band Kill Switch: ARMED -> DEGRADED -> TRIPPED -> KILLED."""

    def __init__(self, max_tool_calls: int = 12) -> None:
        self.max_tool_calls = max_tool_calls
        self.state = "ARMED"
        self.violation_count = 0
        self.history: list[str] = ["ARMED"]

    def is_halted(self) -> bool:
        """Return True once state reaches KILLED."""
        return self.state == "KILLED"

    def _set_state(self, new_state: str) -> None:
        if new_state != self.state:
            self.state = new_state
            self.history.append(new_state)

    def record_violation(self, severe: bool = False) -> str:
        """Advance state machine on guardrail or loop violations."""
        self.violation_count += 1
        if self.state == "KILLED":
            return self.state
        if severe or self.violation_count >= 6:
            self._set_state("KILLED")
        elif self.violation_count >= 3:
            self._set_state("TRIPPED")
        elif self.violation_count >= 1:
            self._set_state("DEGRADED")
        return self.state


def process_fixture(
    fixture_path: Path = DEFAULT_FIXTURE,
) -> dict[str, Any]:
    """Run adversarial fixture events through all Ch05 controls."""
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    max_hops = int(fixture["metadata"]["max_tool_calls_per_task"])
    ks = KillSwitchStateMachine(max_tool_calls=max_hops)
    priv_key, pub_key = generate_a2a_keypair()

    outcomes: list[dict[str, Any]] = []
    for evt in fixture["events"]:
        if ks.is_halted():
            outcomes.append(
                {
                    "id": evt["id"],
                    "decision": "DENIED_KILL_SWITCH",
                    "kill_switch_state": ks.state,
                }
            )
            continue

        etype = evt["type"]
        if etype == "tool_call":
            if int(evt.get("hop_count", 0)) > ks.max_tool_calls:
                ks.record_violation(severe=True)
                decision = "DENIED_LOOP_CAP"
            else:
                ok, _ = evaluate_tool_call(evt["tool"], evt["args"])
                if ok:
                    decision = "ALLOW"
                else:
                    ks.record_violation()
                    decision = "DENIED_UNSAFE_TOOL"
        elif etype == "rag_ingest":
            _, findings = sanitize_rag_chunk(evt["text"])
            if findings:
                ks.record_violation()
                decision = "SANITIZED_BLOCK_INJECTION"
            else:
                decision = "ALLOW"
        elif etype == "a2a_message":
            payload = {
                "sender": evt["sender"],
                "recipient": evt["recipient"],
                "action": evt["action"],
            }
            env = sign_a2a_envelope(payload, priv_key)
            if evt.get("tamper_payload"):
                env["payload"]["action"] = "grant_cluster_admin"
            if verify_a2a_envelope(env, pub_key):
                decision = "ALLOW"
            else:
                ks.record_violation()
                decision = "DENIED_INVALID_A2A_SIG"
        else:
            ks.record_violation()
            decision = "DENIED_UNKNOWN_EVENT"

        outcomes.append(
            {
                "id": evt["id"],
                "decision": decision,
                "kill_switch_state": ks.state,
            }
        )

    return {
        "final_kill_switch_state": ks.state,
        "state_transitions": ks.history,
        "events_processed": len(outcomes),
        "cost_usd": 0.0,
        "outcomes": outcomes,
    }


def main() -> None:
    """Execute Ch05 guardrail simulation and print JSON output."""
    print(json.dumps(process_fixture(), indent=2))


if __name__ == "__main__":
    main()
