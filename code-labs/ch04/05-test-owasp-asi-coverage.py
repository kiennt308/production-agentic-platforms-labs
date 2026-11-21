"""Pytest suite for OWASP ASI01-ASI10 & Principle of Least Agency.

Author: Kien Nguyen
Verifies 10/10 ASI threat coverage, valid Least Agency manifest pass,
and over-privileged manifest rejection.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import yaml

CH04_DIR = Path(__file__).resolve().parent
AUDITOR_PATH = CH04_DIR / "04-asi-threat-and-agency-auditor.py"
MATRIX_PATH = CH04_DIR / "01-orderflow-asi-threat-matrix.json"
VALID_YAML = CH04_DIR / "02-least-agency-manifest-valid.yaml"
NEG_YAML = CH04_DIR / "03-overprivileged-agent-negative.yaml"


def _load_auditor():
    spec = importlib.util.spec_from_file_location("asi_aud", AUDITOR_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_asi_threat_matrix_covers_all_ten_risks() -> None:
    """Confirm 10/10 ASI01-ASI10 risks map cleanly to OrderFlow."""
    auditor = _load_auditor()
    data = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    res = auditor.audit_threat_matrix(data)
    assert res["covered_count"] == 10
    assert res["missing_asi"] == []
    assert res["unknown_fleets"] == []
    assert res["matrix_passed"] is True


def test_least_agency_valid_manifest_passes() -> None:
    """Confirm valid Least Agency manifest passes all checks."""
    auditor = _load_auditor()
    report = auditor.run_audit(MATRIX_PATH, VALID_YAML)
    assert report["manifest_violations"] == []
    assert report["audit_passed"] is True
    assert report["cost_usd"] == 0.0


def test_overprivileged_negative_manifest_is_rejected() -> None:
    """Reject cluster-admin, 86400s TTL, unpinned MCP, and ASI gaps."""
    auditor = _load_auditor()
    neg_doc = yaml.safe_load(NEG_YAML.read_text(encoding="utf-8"))
    violations = auditor.audit_agency_manifest(neg_doc)
    assert "OWASP_ASI_INCOMPLETE" in violations
    assert "STATIC_ADMIN_ROLE_DENIED" in violations
    assert "TOKEN_TTL_EXCEEDS_MAX" in violations
    assert "MCP_DIGEST_UNPINNED" in violations
    assert "INVALID_SHA256:mcp-floating-latest" in violations
