from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from budobugs.analysis.source_scan import SourceScanCoordinator
from budobugs.core.io import atomic_write_json
from budobugs.models import Engagement, EngagementMode, Target
from budobugs.tools.wrapper import ToolExecutionError


def _source_engagement(root: Path) -> Engagement:
    return Engagement(
        engagement_id="source-fixture-001",
        platform="local-source-test",
        vendor="BudoBugs TEST FIXTURE",
        user_authorization_attestation="I own and authorize this isolated source fixture for analysis.",
        root_targets=[Target(uri=str(root), label="source", kind="source")],
        selected_mode=EngagementMode.SOURCE,
    )


@pytest.mark.asyncio
async def test_source_scan_coordinator_counts_artifact_backed_results(
    tmp_path: Path, repository_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    artifacts = tmp_path / "artifacts"
    coordinator = SourceScanCoordinator(repository_root, artifacts)
    reports: dict[str, object] = {
        "gitleaks": [{"RuleID": "fixture"}],
        "semgrep": {"results": [{"check_id": "one"}, {"check_id": "two"}]},
        "trivy": {
            "Results": [
                {
                    "Vulnerabilities": [{"id": "one"}],
                    "Secrets": [{"id": "two"}],
                    "Misconfigurations": [{"id": "three"}],
                }
            ]
        },
        "osv-scanner": {
            "results": [
                {
                    "source": {"path": "uv.lock", "type": "lockfile"},
                    "packages": [{"package": {"name": "fixture"}, "groups": [{"ids": ["OSV-1"]}]}],
                }
            ]
        },
    }

    async def execute(request, _engagement):
        directory = artifacts / request.output_directory
        directory.mkdir(parents=True, exist_ok=True)
        report_path = coordinator._report_path(request.tool_name, directory)
        assert report_path is not None
        atomic_write_json(report_path, reports[request.tool_name])
        atomic_write_json(directory / "receipt.json", {"status": "completed"})
        status = "failed" if request.tool_name in {"gitleaks", "osv-scanner"} else "completed"
        return SimpleNamespace(status=status)

    monkeypatch.setattr(coordinator.runner, "run", execute)
    summary = await coordinator.run(_source_engagement(source), "run-source-001")
    results = {item["tool"]: item for item in summary["results"]}
    assert summary["executed"] == 4
    assert summary["needs_runtime"] == 0
    assert results["gitleaks"]["finding_count"] == 1
    assert results["semgrep"]["finding_count"] == 2
    assert results["trivy"]["finding_count"] == 3
    assert results["osv-scanner"]["finding_count"] == 1
    assert all(item["status"] == "COMPLETED_WITH_FINDINGS" for item in results.values())
    assert (
        json.loads((artifacts / "source-scan-summary.json").read_text(encoding="utf-8"))["run_id"] == "run-source-001"
    )


@pytest.mark.asyncio
async def test_source_scan_coordinator_reports_missing_runtime_without_inventing_findings(
    tmp_path: Path, repository_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    coordinator = SourceScanCoordinator(repository_root, tmp_path / "artifacts")

    async def unavailable(_request, _engagement):
        raise ToolExecutionError("fixture executable unavailable")

    monkeypatch.setattr(coordinator.runner, "run", unavailable)
    summary = await coordinator.run(_source_engagement(source), "run-source-002")
    assert summary["executed"] == 0
    assert summary["needs_runtime"] == 4
    assert all(item["finding_count"] is None for item in summary["results"])


def test_source_scan_counting_fails_closed_for_missing_or_invalid_reports(tmp_path: Path) -> None:
    assert SourceScanCoordinator._report_path("unknown", tmp_path) is None
    assert SourceScanCoordinator._finding_count("unknown", None) is None
    invalid = tmp_path / "invalid.json"
    invalid.write_text("not-json", encoding="utf-8")
    assert SourceScanCoordinator._finding_count("semgrep", invalid) is None
    empty = tmp_path / "empty.json"
    empty.write_text("{}", encoding="utf-8")
    assert SourceScanCoordinator._finding_count("unknown", empty) == 0
