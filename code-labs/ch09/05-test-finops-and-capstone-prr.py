"""Pytest Suite for FinOps FOCUS ETL, Net Toil ROI & Capstone PRR.

Author: Kien Nguyen
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

CH09_DIR = Path(__file__).resolve().parent
LEDGER_PATH = CH09_DIR / "02-focus-finops-and-roi-ledger.py"
PRR_READY_PATH = CH09_DIR / "03-capstone-prr-ready.json"


def _load_ledger():
    name = "ch09_focus_finops_roi_ledger"
    spec = importlib.util.spec_from_file_location(name, LEDGER_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_sqlite_focus_etl_schema_and_columns() -> None:
    """Verify FOCUS v1.2-v1.4 columns and OTel token bridge JSON."""
    mod = _load_ledger()
    conn, summary = mod.build_focus_ledger()
    try:
        cols = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(focus_billing_records)"
            ).fetchall()
        }
        expected_cols = {
            "event_id",
            "BillingPeriodStart",
            "ServiceCategory",
            "ServiceName",
            "SubAccountId",
            "BilledCost",
            "AllocatedClusterCost",
            "EffectiveCost",
            "SplitCostAllocationData",
            "x_GenAITokenBreakdown",
        }
        assert expected_cols.issubset(cols)
        assert summary["event_count"] == 12

        rows = conn.execute(
            "SELECT * FROM focus_billing_records"
        ).fetchall()
        for row in rows:
            assert row["ServiceCategory"] == "AI and Machine Learning"
            split = json.loads(row["SplitCostAllocationData"])
            bridge = json.loads(row["x_GenAITokenBreakdown"])
            assert split["focus_spec"] == "1.2-1.3"
            assert "gen_ai.usage.input_tokens" in bridge
            assert "gen_ai.usage.output_tokens" in bridge
            assert row["EffectiveCost"] == round(
                row["BilledCost"] + row["AllocatedClusterCost"], 4
            )
    finally:
        conn.close()


def test_positive_net_toil_roi_and_cpir() -> None:
    """Verify exact CPIR and positive Net Toil ROI computation."""
    mod = _load_ledger()
    conn, summary = mod.build_focus_ledger()
    try:
        assert summary["incidents_resolved"] == 21
        assert summary["token_cost_usd"] == 1.81
        assert summary["cluster_cost_usd"] == 24.0
        assert summary["total_operational_cost_usd"] == 25.81
        assert summary["cost_per_incident_resolved_usd"] == round(
            25.81 / 21, 4
        )
        assert summary["human_toil_saved_usd"] == 1260.0
        assert summary["net_toil_roi_usd"] == 1234.19
        assert summary["net_toil_roi_usd"] > 0
        assert summary["net_toil_roi_pct"] > 0
    finally:
        conn.close()


def test_runaway_session_cap_detection_and_prr() -> None:
    """Verify runaway cap query flags E-09 and PRR meets 20/20."""
    mod = _load_ledger()
    conn, summary = mod.build_focus_ledger()
    try:
        flagged = summary["runaway_cap_events"]
        assert len(flagged) == 1
        assert flagged[0]["event_id"] == "E-09"
        assert flagged[0]["SubAccountId"] == "urn:agent:orderflow-sre"
    finally:
        conn.close()

    prr = json.loads(PRR_READY_PATH.read_text(encoding="utf-8"))
    assert prr["document_type"] == "OrderFlowCapstonePRR"
    assert prr["gates_passed"] == 20
    assert len(prr["domains"]) == 5
    assert prr["finops"]["per_task_token_cap_enforced"] is True
    assert prr["finops"]["claims_native_focus12_tokens"] is False
    assert prr["finops"]["gateway_otel_etl_enabled"] is True
