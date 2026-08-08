"""Registry-backed source security scans with artifact-derived observations."""

from __future__ import annotations

import json
from pathlib import Path

from budobugs.core.identifiers import new_id
from budobugs.core.io import atomic_write_json
from budobugs.models import Engagement, ToolRequest
from budobugs.tools.registry import ToolRegistry
from budobugs.tools.wrapper import ToolExecutionError, ToolRunner


class SourceScanCoordinator:
    tool_names = ("gitleaks", "semgrep", "trivy", "osv-scanner")

    def __init__(self, repository_root: Path, artifact_root: Path) -> None:
        self.repository_root = repository_root.resolve()
        self.artifact_root = artifact_root.resolve()
        self.registry = ToolRegistry.load(self.repository_root / "tools" / "registry")
        self.runner = ToolRunner(
            self.registry,
            self.artifact_root,
            workspace_root=self.repository_root,
            output_limit_bytes=25 * 1024 * 1024,
        )

    async def run(self, engagement: Engagement, run_id: str) -> dict[str, object]:
        results: list[dict[str, object]] = []
        for root in engagement.root_targets:
            target = str(Path(root.uri).resolve())
            for tool_name in self.tool_names:
                directory = f"source-tools/{root.label}/{tool_name}"
                request = ToolRequest(
                    invocation_id=new_id("source-scan"),
                    run_id=run_id,
                    engagement_id=engagement.engagement_id,
                    tool_name=tool_name,
                    target=target,
                    purpose=f"authorized source scan: {tool_name}",
                    output_directory=directory,
                )
                try:
                    receipt = await self.runner.run(request, engagement)
                except ToolExecutionError as exc:
                    results.append(
                        {
                            "tool": tool_name,
                            "target_label": root.label,
                            "status": "NEEDS_RUNTIME",
                            "observation": str(exc),
                            "finding_count": None,
                        }
                    )
                    continue
                report_path = self._report_path(tool_name, self.artifact_root / directory)
                finding_count = self._finding_count(tool_name, report_path)
                report_ready = report_path is not None and report_path.is_file()
                results.append(
                    {
                        "tool": tool_name,
                        "target_label": root.label,
                        "status": (
                            "COMPLETED_WITH_FINDINGS"
                            if report_ready and finding_count
                            else "PASS"
                            if report_ready
                            else receipt.status.upper()
                        ),
                        "executor_status": receipt.status,
                        "receipt": str(self.artifact_root / directory / "receipt.json"),
                        "report": str(report_path) if report_path else None,
                        "finding_count": finding_count,
                    }
                )
        summary = {
            "schema_version": 1,
            "run_id": run_id,
            "engagement_id": engagement.engagement_id,
            "results": results,
            "executed": sum(item["status"] != "NEEDS_RUNTIME" for item in results),
            "needs_runtime": sum(item["status"] == "NEEDS_RUNTIME" for item in results),
        }
        atomic_write_json(self.artifact_root / "source-scan-summary.json", summary)
        return summary

    @staticmethod
    def _report_path(tool_name: str, directory: Path) -> Path | None:
        names = {
            "gitleaks": "gitleaks.json",
            "semgrep": "semgrep.json",
            "trivy": "trivy.json",
            "osv-scanner": "osv.json",
        }
        name = names.get(tool_name)
        return directory / name if name else None

    @staticmethod
    def _finding_count(tool_name: str, report_path: Path | None) -> int | None:
        if report_path is None or not report_path.is_file():
            return None
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if tool_name == "gitleaks" and isinstance(payload, list):
            return len(payload)
        if tool_name == "semgrep" and isinstance(payload, dict) and isinstance(payload.get("results"), list):
            return len(payload["results"])
        if tool_name == "trivy" and isinstance(payload, dict):
            results = payload.get("Results")
            if isinstance(results, list):
                return sum(
                    len(item.get("Vulnerabilities", []))
                    + len(item.get("Secrets", []))
                    + len(item.get("Misconfigurations", []))
                    for item in results
                    if isinstance(item, dict)
                )
        if tool_name == "osv-scanner" and isinstance(payload, dict):
            results = payload.get("results")
            if isinstance(results, list):
                count = 0
                for item in results:
                    packages = item.get("packages") if isinstance(item, dict) else None
                    if not isinstance(packages, list):
                        continue
                    for package in packages:
                        if not isinstance(package, dict):
                            continue
                        groups = package.get("groups")
                        vulnerabilities = package.get("vulnerabilities")
                        count += len(groups) if isinstance(groups, list) else 0
                        if not isinstance(groups, list) and isinstance(vulnerabilities, list):
                            count += len(vulnerabilities)
                return count
        return 0
