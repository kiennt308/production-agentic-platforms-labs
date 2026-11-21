"""OWASP ASI01-ASI10 & Principle of Least Agency Auditor.

Author: Kien Nguyen
Audits threat matrix completeness (10/10 ASI01-ASI10) and enforces
Principle of Least Agency (no cluster-admin, TTL <= 300s, SHA-256).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

CH04_DIR = Path(__file__).resolve().parent
DEFAULT_MATRIX = CH04_DIR / "01-orderflow-asi-threat-matrix.json"
DEFAULT_MANIFEST = CH04_DIR / "02-least-agency-manifest-valid.yaml"
EXPECTED_ASI = [f"ASI{i:02d}" for i in range(1, 11)]
VALID_FLEETS = {
    "urn:agent:orderflow-devops",
    "urn:agent:orderflow-sre",
    "urn:agent:orderflow-aws",
    "urn:agent:orderflow-devsecops",
}
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def audit_threat_matrix(matrix_data: dict[str, Any]) -> dict[str, Any]:
    """Verify 10/10 ASI01-ASI10 threats map to Vol. 06-09 fleets."""
    threats = matrix_data.get("threats", [])
    seen_ids = [item.get("id") for item in threats]
    missing = [asi for asi in EXPECTED_ASI if asi not in seen_ids]
    bad_fleets: list[str] = []
    for item in threats:
        for fleet in item.get("affected_fleets", []):
            if fleet not in VALID_FLEETS:
                bad_fleets.append(f"{item.get('id')}:{fleet}")
    passed = (
        len(missing) == 0
        and len(set(seen_ids)) == 10
        and len(bad_fleets) == 0
    )
    return {
        "covered_count": len(set(seen_ids) & set(EXPECTED_ASI)),
        "missing_asi": missing,
        "unknown_fleets": bad_fleets,
        "matrix_passed": passed,
    }


def audit_agency_manifest(doc: dict[str, Any]) -> list[str]:
    """Enforce Least Agency and supply-chain digest rules on YAML."""
    violations: list[str] = []
    spec = doc.get("spec", {})
    covered = set(spec.get("owasp_asi_covered", []))
    if not set(EXPECTED_ASI).issubset(covered):
        violations.append("OWASP_ASI_INCOMPLETE")

    la = spec.get("least_agency", {})
    if la.get("cluster_admin_bound") is True:
        violations.append("STATIC_ADMIN_ROLE_DENIED")
    if int(la.get("token_ttl_seconds", 9999)) > 300:
        violations.append("TOKEN_TTL_EXCEEDS_MAX")

    sc = spec.get("supply_chain", {})
    if sc.get("mcp_sha256_pinned") is not True:
        violations.append("MCP_DIGEST_UNPINNED")
    for srv in sc.get("pinned_servers", []):
        digest = str(srv.get("sha256", "")).strip()
        if not SHA256_HEX_RE.match(digest):
            violations.append(f"INVALID_SHA256:{srv.get('name')}")
    return violations


def run_audit(
    matrix_path: Path = DEFAULT_MATRIX,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> dict[str, Any]:
    """Run full Chapter 04 ASI matrix and Least Agency audit."""
    matrix_data = json.loads(matrix_path.read_text(encoding="utf-8"))
    manifest_doc = yaml.safe_load(
        manifest_path.read_text(encoding="utf-8")
    )
    matrix_res = audit_threat_matrix(matrix_data)
    manifest_violations = audit_agency_manifest(manifest_doc)
    return {
        "matrix_audit": matrix_res,
        "manifest_name": manifest_doc["metadata"]["name"],
        "manifest_violations": manifest_violations,
        "audit_passed": (
            matrix_res["matrix_passed"] and len(manifest_violations) == 0
        ),
        "cost_usd": 0.0,
    }


def main() -> None:
    """Execute Chapter 04 audit and print JSON summary."""
    report = run_audit()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
