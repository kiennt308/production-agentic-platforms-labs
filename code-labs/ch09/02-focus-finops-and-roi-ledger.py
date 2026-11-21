"""SQLite :memory: FinOps FOCUS ETL & Net Toil ROI Ledger ($0.00).

Author: Kien Nguyen
Normalizes Gateway + OTel gen_ai.usage.* telemetry into FOCUS
v1.2/v1.3 SplitCostAllocationData + FOCUS v1.4 AI & ML ServiceCategory
+ x_GenAITokenBreakdown bridge ahead of FOCUS v1.5 token billing.
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Any

EVENTS_PATH = (
    Path(__file__).resolve().parent / "01-agentic-finops-events.json"
)

SCHEMA_SQL = """
CREATE TABLE focus_billing_records (
    event_id TEXT PRIMARY KEY,
    BillingPeriodStart TEXT NOT NULL,
    ServiceCategory TEXT NOT NULL,
    ServiceName TEXT NOT NULL,
    SubAccountId TEXT NOT NULL,
    PricingUnit TEXT NOT NULL,
    BilledCost REAL NOT NULL,
    AllocatedClusterCost REAL NOT NULL,
    EffectiveCost REAL NOT NULL,
    SplitCostAllocationData TEXT NOT NULL,
    x_GenAITokenBreakdown TEXT NOT NULL,
    IncidentsResolved INTEGER NOT NULL,
    HitRunawayCap INTEGER NOT NULL
);
"""


def build_focus_ledger(
    events_path: Path = EVENTS_PATH,
) -> tuple[sqlite3.Connection, dict[str, Any]]:
    """Load 12 telemetry events into SQLite FOCUS schema and score."""
    raw = json.loads(events_path.read_text(encoding="utf-8"))
    period = raw["billing_period"]
    cluster_pool = float(raw["shared_cluster_cost_usd"])
    toil_cfg = raw["toil_baseline"]

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(SCHEMA_SQL)

    for ev in raw["events"]:
        share_pct = float(ev["cluster_share_pct"])
        allocated = round(cluster_pool * (share_pct / 100.0), 4)
        billed = round(float(ev["session_cost_usd"]), 4)
        effective = round(billed + allocated, 4)

        split_data = {
            "focus_spec": "1.2-1.3",
            "allocation_method": "proportional_pod_share",
            "cluster_share_pct": share_pct,
            "shared_pool_usd": cluster_pool,
            "allocated_usd": allocated,
        }
        token_bridge = {
            "focus_bridge": "1.4-to-1.5",
            "source_volume": ev["source_volume"],
            "model": ev["model"],
            "tier": ev["tier"],
            "gen_ai.usage.input_tokens": ev["input_tokens"],
            "gen_ai.usage.cached_tokens": ev["cached_tokens"],
            "gen_ai.usage.output_tokens": ev["output_tokens"],
        }
        conn.execute(
            """
            INSERT INTO focus_billing_records VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                ev["event_id"],
                period,
                "AI and Machine Learning",
                "OrderFlow Agentic Gateway",
                ev["agent_urn"],
                "1K Tokens",
                billed,
                allocated,
                effective,
                json.dumps(split_data),
                json.dumps(token_bridge),
                int(ev["incidents_resolved"]),
                1 if ev["hit_runaway_cap"] else 0,
            ),
        )
    conn.commit()

    totals = conn.execute(
        """
        SELECT
            COUNT(*) AS event_count,
            ROUND(SUM(BilledCost), 4) AS token_cost_usd,
            ROUND(SUM(AllocatedClusterCost), 4) AS cluster_cost_usd,
            ROUND(SUM(EffectiveCost), 4) AS total_op_cost_usd,
            SUM(IncidentsResolved) AS incidents_resolved
        FROM focus_billing_records
        """
    ).fetchone()

    runaway_rows = conn.execute(
        """
        SELECT event_id, SubAccountId, BilledCost, EffectiveCost
        FROM focus_billing_records
        WHERE HitRunawayCap = 1
        ORDER BY event_id
        """
    ).fetchall()

    resolved = int(totals["incidents_resolved"])
    total_cost = float(totals["total_op_cost_usd"])
    cpir = round(total_cost / resolved, 4) if resolved > 0 else 0.0

    hours_saved_each = (
        float(toil_cfg["minutes_saved_per_incident"]) / 60.0
    )
    hourly_rate = float(toil_cfg["hourly_oncall_rate_usd"])
    toil_saved = round(resolved * hours_saved_each * hourly_rate, 4)
    net_roi = round(toil_saved - total_cost, 4)
    roi_pct = round((net_roi / total_cost) * 100.0, 2)

    summary = {
        "focus_spec_alignment": "v1.2-v1.3-v1.4-to-v1.5-bridge",
        "service_category": "AI and Machine Learning",
        "event_count": int(totals["event_count"]),
        "token_cost_usd": float(totals["token_cost_usd"]),
        "cluster_cost_usd": float(totals["cluster_cost_usd"]),
        "total_operational_cost_usd": total_cost,
        "incidents_resolved": resolved,
        "cost_per_incident_resolved_usd": cpir,
        "human_toil_saved_usd": toil_saved,
        "net_toil_roi_usd": net_roi,
        "net_toil_roi_pct": roi_pct,
        "runaway_cap_events": [dict(row) for row in runaway_rows],
    }
    return conn, summary


def main() -> None:
    """Execute SQLite FOCUS ETL and print CPIR + Net Toil ROI."""
    conn, summary = build_focus_ledger()
    try:
        print(json.dumps(summary, indent=2))
    finally:
        conn.close()


if __name__ == "__main__":
    main()
