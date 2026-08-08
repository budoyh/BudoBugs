from __future__ import annotations

from datetime import UTC, datetime

from budobugs.core.io import atomic_write_json
from budobugs.models import CostRecord, PhaseName, ToolExecutionReceipt
from budobugs.tui import BudoBugsTui


def test_tui_discovers_typed_tool_receipts_and_summarizes_costs(workspace) -> None:
    receipt = ToolExecutionReceipt(
        receipt_id="receipt-tui-001",
        invocation_id="invoke-tui-001",
        run_id="run-tui-001",
        engagement_id="lab-tui-001",
        tool_name="fixture-tool",
        executable="fixture",
        arguments=["--version"],
        target=None,
        started_at=datetime.now(UTC),
        exit_code=0,
        timed_out=False,
        attempt_count=1,
        stdout_artifact="stdout.txt",
        stderr_artifact="stderr.txt",
        normalized_output_artifact="normalized.json",
        stdout_sha256="0" * 64,
        stderr_sha256="1" * 64,
        redaction_applied=False,
        policy_decision_id="policy-tui-001",
        status="completed",
    )
    path = workspace.runs / receipt.run_id / "artifacts" / "tools" / receipt.tool_name / "receipt.json"
    atomic_write_json(path, receipt.model_dump(mode="json"))

    discovered = BudoBugsTui._tool_receipts(workspace.runs)
    assert [(item.tool_name, item.status) for item, _ in discovered] == [("fixture-tool", "completed")]

    cost = CostRecord(
        cost_id="cost-tui-001",
        run_id=receipt.run_id,
        phase=PhaseName.INIT,
        model="local-deterministic",
        input_tokens=0,
        output_tokens=0,
        elapsed_ms=12,
        estimated_cost_usd=0,
    )
    assert BudoBugsTui._cost_summary([cost]) == "$0.0000 / 12ms"
