from __future__ import annotations

from pathlib import Path

import pytest
from tests.conftest import make_exchange

from budobugs.evidence.pack import EvidencePackBuilder, EvidencePackError, pack_finding
from budobugs.models import CandidateStatus, CriticVerdict, Engagement, HttpExchange
from budobugs.orchestration.engine import HuntEngine
from budobugs.reporting.generator import ReportGenerationError, ReportGenerator
from budobugs.validation.critic import AdversarialCritic
from budobugs.validation.gates import EvidenceGate


def _fixture_findings(engagement: Engagement) -> tuple[object, object, list[object], list[object], list[HttpExchange]]:
    exchanges = [make_exchange(exchange_id=f"exchange-{index:03d}") for index in range(1, 8)]
    valid, killed, valid_controls, killed_controls = HuntEngine._make_findings(engagement, exchanges)
    return valid, killed, valid_controls, killed_controls, exchanges


def test_evidence_gate_critic_and_report_are_artifact_consistent(
    tmp_path: Path, lab_engagement: Engagement, repository_root: Path
) -> None:
    valid, _killed, controls, _killed_controls, exchanges = _fixture_findings(lab_engagement)
    builder = EvidencePackBuilder(tmp_path / "findings")
    pack = builder.build(valid, exchanges[:5], controls)
    preliminary = EvidenceGate().evaluate(valid, pack, require_critic=False)
    critique = AdversarialCritic().review(valid, preliminary)
    assert critique.verdict is CriticVerdict.CONFIRMED
    valid.critic_verdict = CriticVerdict.CONFIRMED
    valid.status = CandidateStatus.READY_FOR_HUMAN_REVIEW
    valid.reportability = "submission-ready"
    pack = builder.build(valid, exchanges[:5], controls, critique=critique)
    final = EvidenceGate().evaluate(valid, pack, require_critic=True)
    assert final.passed
    report = ReportGenerator(repository_root / "src" / "budobugs" / "reporting" / "templates").generate(
        valid,
        pack,
        vendor=lab_engagement.vendor,
        engagement_platform=lab_engagement.platform,
    )
    assert Path(report.markdown_path).is_file()
    assert Path(report.html_path).is_file()
    assert lab_engagement.vendor in Path(report.markdown_path).read_text(encoding="utf-8")
    assert lab_engagement.platform in Path(report.html_path).read_text(encoding="utf-8")
    assert pack_finding(pack, tmp_path / "export.zip").is_file()


def test_report_refuses_self_reported_ready_without_critic(
    tmp_path: Path, lab_engagement: Engagement, repository_root: Path
) -> None:
    valid, _killed, controls, _killed_controls, exchanges = _fixture_findings(lab_engagement)
    pack = EvidencePackBuilder(tmp_path / "findings").build(valid, exchanges[:5], controls)
    valid.status = CandidateStatus.READY_FOR_HUMAN_REVIEW
    valid.reportability = "submission-ready"
    with pytest.raises(ReportGenerationError):
        ReportGenerator(repository_root / "src" / "budobugs" / "reporting" / "templates").generate(
            valid,
            pack,
            vendor=lab_engagement.vendor,
            engagement_platform=lab_engagement.platform,
        )


def test_export_fails_closed_when_a_secret_is_added(tmp_path: Path, lab_engagement: Engagement) -> None:
    valid, _killed, controls, _killed_controls, exchanges = _fixture_findings(lab_engagement)
    pack = EvidencePackBuilder(tmp_path / "findings").build(valid, exchanges[:5], controls)
    (pack / "tool-output" / "leak.txt").write_text("Bearer abcdefghijklmnop", encoding="utf-8")
    with pytest.raises(EvidencePackError, match="secret scan failed"):
        pack_finding(pack, tmp_path / "export.zip")
