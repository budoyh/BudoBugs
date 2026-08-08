"""Read-only Textual status dashboard."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from textual.app import App, ComposeResult
from textual.widgets import DataTable, Footer, Header, Static

from budobugs.models import CostRecord, Run, ToolExecutionReceipt
from budobugs.orchestration.service import RepositoryService


class BudoBugsTui(App[None]):
    TITLE = "BudoBugs"
    SUB_TITLE = "授权任务、阶段、候选、风险与成本"
    BINDINGS = [("q", "quit", "退出"), ("r", "refresh", "刷新")]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("只读视图；报告仍需人工复核和提交。", id="notice")
        yield Static("Runs / 阶段")
        yield DataTable(id="runs")
        yield Static("工具任务")
        yield DataTable(id="tools")
        yield Static("候选")
        yield DataTable(id="findings")
        yield Static("证据")
        yield DataTable(id="evidence")
        yield Footer()

    def on_mount(self) -> None:
        runs = self.query_one("#runs", DataTable)
        runs.add_columns("任务", "Run", "阶段", "状态", "恢复次数", "Tokens", "成本/耗时")
        tools = self.query_one("#tools", DataTable)
        tools.add_columns("Run", "工具", "Invocation", "状态", "Exit", "Receipt")
        findings = self.query_one("#findings", DataTable)
        findings.add_columns("Finding", "类型", "状态", "Critic", "风险", "成本")
        evidence = self.query_one("#evidence", DataTable)
        evidence.add_columns("Finding", "Evidence IDs", "完整性哈希", "Gate receipt", "报告状态")
        self.action_refresh()

    def action_refresh(self) -> None:
        service = RepositoryService()
        runs = self.query_one("#runs", DataTable)
        tools_table = self.query_one("#tools", DataTable)
        findings_table = self.query_one("#findings", DataTable)
        evidence_table = self.query_one("#evidence", DataTable)
        runs.clear()
        tools_table.clear()
        findings_table.clear()
        evidence_table.clear()

        costs = service.list_costs()
        for run in service.store.list("run", Run):
            run_costs = [item for item in costs if item.run_id == run.run_id]
            runs.add_row(
                run.engagement_id,
                run.run_id,
                run.current_phase.value,
                run.status,
                str(run.resume_count),
                str(sum(item.input_tokens + item.output_tokens for item in run_costs)),
                self._cost_summary(run_costs),
            )
        for receipt, path in self._tool_receipts(service.paths.runs):
            tools_table.add_row(
                receipt.run_id,
                receipt.tool_name,
                receipt.invocation_id,
                receipt.status,
                str(receipt.exit_code) if receipt.exit_code is not None else "-",
                str(path.relative_to(service.paths.runs)),
            )
        for finding in service.list_findings():
            finding_costs = [item for item in costs if item.candidate_id == finding.finding_id]
            findings_table.add_row(
                finding.finding_id,
                finding.vulnerability_class,
                finding.status.value,
                finding.critic_verdict.value if finding.critic_verdict else "pending",
                finding.severity.value,
                self._cost_summary(finding_costs),
            )
            gate_path = Path(finding.gate_receipt_path) if finding.gate_receipt_path else None
            evidence_table.add_row(
                finding.finding_id,
                str(len(finding.evidence_ids)),
                str(len(finding.evidence_hashes)),
                "present" if gate_path is not None and gate_path.is_file() else "missing",
                finding.reportability,
            )

    @staticmethod
    def _tool_receipts(runs_root: Path) -> list[tuple[ToolExecutionReceipt, Path]]:
        receipts: list[tuple[ToolExecutionReceipt, Path]] = []
        if not runs_root.is_dir():
            return receipts
        for path in sorted(runs_root.glob("*/artifacts/**/receipt.json"))[:500]:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
                continue
            try:
                receipt = ToolExecutionReceipt.model_validate(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            receipts.append((receipt, path))
        return receipts

    @staticmethod
    def _cost_summary(costs: Sequence[object]) -> str:
        typed = [item for item in costs if isinstance(item, CostRecord)]
        elapsed = sum(item.elapsed_ms for item in typed)
        known = [item.estimated_cost_usd for item in typed if item.estimated_cost_usd is not None]
        unknown = any(item.estimated_cost_usd is None for item in typed)
        dollars = f"${sum(known):.4f}" if not unknown else "provider receipt"
        return f"{dollars} / {elapsed}ms"
