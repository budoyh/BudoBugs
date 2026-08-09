from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from budobugs.cli.app import app
from budobugs.mcp.doctor import probe_stdio
from budobugs.models import CandidateStatus, Finding, Run, Severity
from budobugs.proxy.burp import BurpMcpAdapter
from budobugs.proxy.caido import CaidoClient
from budobugs.proxy.zap import ZapClient


def test_cli_read_only_smoke_commands(repository_root, monkeypatch) -> None:
    monkeypatch.chdir(repository_root)
    runner = CliRunner()
    result = runner.invoke(app, ["version", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["name"] == "budobugs"
    tools = runner.invoke(app, ["tools", "list", "--profile", "core", "--json"])
    assert tools.exit_code == 0
    assert json.loads(tools.stdout)


def test_hunt_dry_run_makes_no_run_or_cost_records(service, lab_engagement, monkeypatch) -> None:
    service.save_engagement(lab_engagement)
    monkeypatch.setattr("budobugs.cli.app._service", lambda: service)
    result = CliRunner().invoke(app, ["hunt", lab_engagement.engagement_id, "--dry-run", "--json"])
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["status"] == "DRY_RUN"
    assert payload["active_hunt_or_target_network_performed"] is False
    assert payload["planned_model_call_upper_bound"] == 0
    assert service.latest_run(lab_engagement.engagement_id) is None
    assert service.list_costs() == []


async def test_proxy_adapters_report_unavailable_local_endpoints_truthfully() -> None:
    caido_ready, caido_detail = await CaidoClient("http://127.0.0.1:1/graphql", "fixture", timeout=0.1).health()
    zap_ready, zap_detail = await ZapClient("http://127.0.0.1:1", timeout=0.1).health()
    burp_ready, burp_detail = await BurpMcpAdapter("http://127.0.0.1:1/mcp").health()
    assert not caido_ready
    assert any(label in caido_detail.lower() for label in ("failed", "timed out", "not installed"))
    assert not zap_ready
    assert "connection failed" in zap_detail.lower()
    assert not burp_ready
    assert burp_detail


async def test_mcp_stdio_doctor_performs_initialize_and_tool_discovery(repository_root: Path, tmp_path: Path) -> None:
    result = await probe_stdio(repository_root, tmp_path / "runtime")
    assert result["status"] == "PASS"
    assert result["transport"] == "stdio"
    assert result["server"] == "budobugs"
    assert set(result["tools"]) >= {"engagement_show", "status", "traffic_search", "finding_show"}


def _feedback_finding(engagement_id: str) -> Finding:
    return Finding(
        finding_id="finding-feedback-001",
        engagement_id=engagement_id,
        title="typed fixture finding",
        vulnerability_class="authorization",
        affected_asset="http://127.0.0.1:8765",
        affected_feature="fixture object",
        endpoint_family="GET /api/objects/{id}",
        attacker_prerequisites=["self-owned test account"],
        victim_conditions=["second self-owned object"],
        security_invariant="accounts may read only authorized objects",
        protected_asset="one test object",
        trust_boundary="two self-owned accounts",
        enforcement_point="object resolver",
        observed_behavior="single-variable cross-account read repeated",
        expected_behavior="deny non-owner",
        capability_before="own object only",
        capability_after="second account object",
        capability_delta="one cross-account read",
        normal_control="own object succeeds",
        negative_control="anonymous access denied",
        strongest_benign_explanation="public access was denied",
        refutation_attempts=["anonymous control", "repeat"],
        reproduction_steps=["read own object", "replace one identifier and repeat"],
        requests=[],
        responses=[],
        data_exposure_scope="one self-owned fixture object",
        mutation_scope="read-only",
        cleanup_status="none required",
        impact="private object disclosure",
        severity=Severity.MEDIUM,
        confidence=0.95,
        duplicate_risk="same owner-check repair boundary",
        status=CandidateStatus.VALIDATING,
    )


def test_hunt_cli_wires_proxy_login_resume_receipt_and_outcome_feedback(
    service, lab_engagement, tmp_path: Path, monkeypatch
) -> None:
    service.save_engagement(lab_engagement)
    captured: dict[str, object] = {}

    class Engine:
        def __init__(self, _service, **kwargs: object) -> None:
            captured.update(kwargs)

        async def run(self, engagement, **kwargs: object) -> SimpleNamespace:
            captured.update(kwargs)
            return SimpleNamespace(
                run=Run(
                    run_id="run-cli-agent-loop",
                    engagement_id=engagement.engagement_id,
                    selected_mode=engagement.selected_mode,
                    status="interrupted",
                ),
                confirmed_finding_id=None,
                killed_finding_id=None,
                report_markdown=None,
                report_html=None,
                confirmed_finding_ids=(),
                killed_finding_ids=(),
                report_markdowns=(),
                report_htmls=(),
                agent_loop_receipt=str(tmp_path / "receipt.json"),
            )

    har = tmp_path / "authorized.har"
    har.write_text("{}", encoding="utf-8")
    monkeypatch.setattr("budobugs.cli.app._service", lambda: service)
    monkeypatch.setattr("budobugs.cli.app.HuntEngine", Engine)
    result = CliRunner().invoke(
        app,
        [
            "hunt",
            lab_engagement.engagement_id,
            "--agent-mode",
            "codex",
            "--proxy",
            "har",
            "--har",
            str(har),
            "--interactive-login",
            "--headed",
            "--agent-stop-after-turns",
            "3",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["agent_loop_receipt"].endswith("receipt.json")
    assert captured["proxy_backend"] == "har"
    assert captured["interactive_login"] is True
    assert captured["headless"] is False
    assert captured["agent_stop_after_turns"] == 3

    finding = _feedback_finding(lab_engagement.engagement_id)
    service.save_finding(finding)
    feedback = CliRunner().invoke(
        app,
        [
            "outcome",
            "record",
            finding.finding_id,
            "--status",
            "rejected",
            "--reward",
            "0",
            "--reason",
            "missing negative control on platform review",
            "--json",
        ],
    )
    assert feedback.exit_code == 0, feedback.stdout
    feedback_payload = json.loads(feedback.stdout)
    assert feedback_payload["outcome"]["status"] == "rejected"
    assert feedback_payload["updated_priors"]["acceptance"] < 0.55
