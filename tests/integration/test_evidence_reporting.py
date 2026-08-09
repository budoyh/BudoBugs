from __future__ import annotations

from pathlib import Path

import pytest
from tests.conftest import make_exchange, make_finding

from budobugs.core.identifiers import new_id
from budobugs.evidence.pack import EvidencePackBuilder, EvidencePackError, pack_finding
from budobugs.models import CandidateStatus, ControlExperiment, CriticVerdict, Engagement, HttpExchange
from budobugs.reporting.generator import ReportGenerationError, ReportGenerator, _remediation
from budobugs.validation.critic import AdversarialCritic
from budobugs.validation.gates import EvidenceGate


def _fixture_findings(engagement: Engagement) -> tuple[object, object, list[object], list[object], list[HttpExchange]]:
    exchanges = [make_exchange(exchange_id=f"exchange-{index:03d}") for index in range(1, 8)]
    valid = make_finding(engagement_id=engagement.engagement_id)
    controls = [
        ControlExperiment(
            control_id=new_id("control"),
            kind="normal",
            description="bob reads its self-owned object",
            request_exchange_ids=[exchanges[0].exchange_id],
            observed_result="HTTP 200",
            supports_finding=True,
        ),
        ControlExperiment(
            control_id=new_id("control"),
            kind="negative",
            description="anonymous access is denied",
            request_exchange_ids=[exchanges[1].exchange_id],
            observed_result="HTTP 401",
            supports_finding=True,
        ),
    ]
    return valid, valid.model_copy(), controls, list(controls), exchanges


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
    markdown = Path(report.markdown_path).read_text(encoding="utf-8")
    assert "GET /api/objects/1 HTTP/1.1" in markdown
    assert "HTTP/1.1 200" in markdown
    assert "跨账号、跨角色、跨租户" in markdown
    assert pack_finding(pack, tmp_path / "export.zip").is_file()


def test_report_remediation_is_specific_to_root_cause(lab_engagement: Engagement) -> None:
    finding = make_finding(engagement_id=lab_engagement.engagement_id)
    xss = finding.model_copy(
        update={
            "vulnerability_class": "client-side-xss",
            "enforcement_point": "preview renderer",
        }
    )
    csrf = finding.model_copy(
        update={
            "vulnerability_class": "csrf",
            "enforcement_point": "order update handler",
        }
    )
    assert any("innerHTML" in item for item in _remediation(xss))
    assert any("CSRF token" in item for item in _remediation(csrf))
    assert all("对象所有权" not in item for item in _remediation(xss))


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


def test_evidence_pack_keeps_browser_credentials_and_opaque_traces_private(
    tmp_path: Path,
    lab_engagement: Engagement,
) -> None:
    valid, _killed, controls, _killed_controls, exchanges = _fixture_findings(lab_engagement)
    browser = tmp_path / "browser" / "alice"
    (browser / "dom").mkdir(parents=True)
    state = browser / "storage-state.json"
    state.write_text('{"cookies":[{"value":"opaque-session-value"}]}', encoding="utf-8")
    trace = browser / "trace.zip"
    trace.write_bytes(b"opaque trace with an unscannable session")
    har = browser / "traffic.har"
    har.write_text('{"log":{"entries":[]}}', encoding="utf-8")
    dom = browser / "dom" / "page.html"
    dom.write_text("<main>safe rendered evidence</main>", encoding="utf-8")
    pack = EvidencePackBuilder(tmp_path / "findings").build(
        valid,
        exchanges[:5],
        controls,
        browser_artifacts=[state, trace, har, dom],
    )
    copied = {path.name for path in (pack / "browser-trace").iterdir()}
    assert any(name.endswith("page.html") for name in copied)
    assert not any("storage-state" in name for name in copied)
    assert not any(name.endswith((".har", ".zip")) for name in copied)
