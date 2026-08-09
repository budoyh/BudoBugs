from __future__ import annotations

import asyncio
import json
import socket
import sys
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from budobugs.cli.app import app
from budobugs.labs.manager import LabManager
from budobugs.models import (
    AgentLoopState,
    AgentRole,
    CandidateDecision,
    EngagementMode,
    Hypothesis,
    ProgramValidationPlan,
    SafeWebSocketAction,
    SafeWebSocketExperimentTemplate,
    Target,
)
from budobugs.orchestration.catalog import ActionCatalogBuilder
from budobugs.orchestration.engine import HuntEngine
from budobugs.orchestration.executor import TypedActionExecutor
from budobugs.orchestration.service import RepositoryService
from budobugs.proxy.direct import DirectProxyBackend
from budobugs.proxy.factory import ProxySelection


async def _assert_native_fixture_stopped(manager: LabManager, primary_error: BaseException | None) -> None:
    try:
        stopped = await asyncio.to_thread(manager.down)
        assert not stopped.running
        assert stopped.backend == "none"
        assert stopped.services == {"fixture": False}
        assert not manager.state_file.exists()
    except BaseException as cleanup_error:
        if primary_error is None:
            raise
        primary_error.add_note(f"native fixture cleanup also failed: {cleanup_error!r}")


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _template(base: str, *, expected_cross_owner: str = "alice") -> SafeWebSocketExperimentTemplate:
    def action(
        action_id: str,
        path: str,
        *,
        event: str = "message",
        pointer: str | None = "/owner",
        value: object | None = None,
        close_codes: list[int] | None = None,
        send_text: str | None = None,
    ) -> SafeWebSocketAction:
        return SafeWebSocketAction(
            action_id=action_id,
            account_alias="bob",
            target_url=f"{base}{path}",
            send_text=send_text,
            expected_event=event,  # type: ignore[arg-type]
            expected_close_codes=close_codes or [],
            expected_json_pointer=pointer,
            expected_json_value=value,
        )

    return SafeWebSocketExperimentTemplate(
        template_id="program-ws-idor-001",
        title="WebSocket object resolver permits cross-account message reads",
        vulnerability_class="websocket-authorization",
        affected_feature="fixture object WebSocket resolver",
        security_invariant="WebSocket object messages must enforce the same owner boundary as HTTP object reads.",
        root_cause_key="fixture-websocket-object-resolver-policy",
        repair_boundary="shared WebSocket object resolver authorization check",
        capability_before="bob reads only bob self-owned fixture object messages",
        capability_after="bob reads alice self-owned fixture object messages",
        capability_delta="one cross-account private fixture object message",
        strongest_benign_explanation="the object could be intentionally public or the actor context could be ignored",
        impact="a WebSocket client can read a private object from another declared account",
        normal_control=action("ws-normal-bob-own", "/ws/objects/2", value="bob"),
        experiment=action(
            "ws-repeat-bob-cross-alice",
            "/ws/objects/1",
            value=expected_cross_owner,
            send_text="super-secret-frame-content-must-not-persist",
        ),
        negative_control=action(
            "ws-secure-negative",
            "/ws/secure-objects/1",
            event="close",
            pointer=None,
            close_codes=[4403],
        ),
    )


def _proxy(tmp_path: Path) -> ProxySelection:
    return ProxySelection(
        backend=DirectProxyBackend(),
        requested="direct",
        selected="direct",
        ready=True,
        detail="test direct backend",
        attempted=(),
        receipt_path=str(tmp_path / "proxy-selection.json"),
    )


@pytest.mark.e2e
async def test_program_websocket_template_runs_via_api_auth_catalog_and_preserves_frame_privacy(
    workspace, repository_root: Path, lab_engagement, monkeypatch
) -> None:
    port = _free_port()
    base_http = f"http://127.0.0.1:{port}"
    base_ws = f"ws://127.0.0.1:{port}"
    manager = LabManager(repository_root, workspace.runtime_home, fixture_port=port)
    assert (await asyncio.to_thread(manager.up, native_only=True)).running
    try:
        async with httpx.AsyncClient(timeout=2, trust_env=False) as client:
            assert (await client.get(f"{base_http}/healthz")).status_code == 200
        service = RepositoryService(workspace)
        program = lab_engagement.model_copy(
            update={
                "engagement_id": "program-websocket-001",
                "selected_mode": EngagementMode.PROGRAM,
                "root_targets": [Target(uri=base_http, label="fixture")],
                "testing_accounts_secret_refs": {"bob": "env://BUDO_WS_BOB"},
            }
        )
        service.save_engagement(program)
        template = _template(base_ws)
        monkeypatch.setenv("BUDO_WS_BOB", json.dumps({"headers": {"Authorization": "Fixture bob"}}))
        monkeypatch.setenv("BUDO_WS_TEMPLATE", template.model_dump_json())
        monkeypatch.setattr(
            "budobugs.cli.app.SecretStore.set",
            lambda _self, _namespace, _name, _value: "env://BUDO_WS_TEMPLATE",
        )
        monkeypatch.setattr("budobugs.cli.app._service", lambda: service)
        cli = CliRunner().invoke(
            app,
            [
                "engagement",
                "websocket-experiment-set",
                program.engagement_id,
                "--spec-env",
                "BUDO_WS_TEMPLATE",
                "--json",
            ],
        )
        assert cli.exit_code == 0, cli.output
        registered = service.load_engagement(program.engagement_id)
        assert registered.websocket_experiment_secret_refs == {template.template_id: "env://BUDO_WS_TEMPLATE"}
        loaded = HuntEngine(service)._safe_websocket_experiment_templates(registered)
        assert [item.template_id for item in loaded] == [template.template_id]
        authorized = service.authorize_engagement(program.engagement_id)
        executor = TypedActionExecutor(
            repository_root=repository_root,
            runtime_home=workspace.runtime_home,
            artifact_root=workspace.runs / "ws-run" / "artifacts",
            engagement=authorized,
            run_id="ws-run",
            proxy=_proxy(workspace.runtime_home),
            account_headers={"bob": {"Authorization": "Fixture bob"}},
            safe_websocket_experiments=loaded,
        )
        candidate_id = "candidate-websocket-001"
        executor.hypotheses.append(
            Hypothesis(
                hypothesis_id=candidate_id,
                engagement_id=authorized.engagement_id,
                title="WebSocket object authorization is missing",
                vulnerability_class=template.vulnerability_class,
                endpoint_family_id=f"websocket:{base_ws}/ws/objects/1",
                invariant_id="ws-object-owner",
                rationale="fixture browser discovery observed the WebSocket endpoint",
                proposed_single_variable_change="replace bob object 2 with alice object 1",
                expected_control="secure WebSocket route closes cross-owner session",
                protocol="websocket",
                validator_id="websocket-session-authorization",
                skill_name="api-auth-session",
            )
        )
        executor.program_validation_plans.append(
            ProgramValidationPlan(
                plan_id="program-ws-plan-001",
                hypothesis_id=candidate_id,
                endpoint_family_id=f"websocket:{base_ws}/ws/objects/1",
                validator_id=f"program-websocket-experiment--{template.template_id}",
                specialist_role="api-auth-specialist",
                control_source="engagement-safe-experiment",
                control_ids=[
                    template.normal_control.action_id,
                    template.experiment.action_id,
                    template.negative_control.action_id,
                ],
                safe_experiment_template_id=template.template_id,
            )
        )
        catalog = ActionCatalogBuilder(
            authorized,
            safe_websocket_experiments=loaded,
            hypotheses=executor.hypotheses,
            program_validation_plans=executor.program_validation_plans,
        )
        proposal = next(
            item
            for item in catalog.actions(
                AgentRole.API_AUTH_SPECIALIST,
                2,
                AgentLoopState(
                    loop_id="ws-loop",
                    run_id="ws-run",
                    engagement_id=authorized.engagement_id,
                ),
            )
            if item.validator_id == f"program-websocket-experiment--{template.template_id}"
        )
        private_browser_root = executor._private_browser_root() / "bob"
        existing_pre_traces = {path.resolve() for path in private_browser_root.glob("trace-pre-ws-*.zip")}
        observation = await executor.execute(proposal)
        await executor.close_browser()
        assert observation.status.value == "executed"
        assert executor.validator_results[-1].outcome.decision is CandidateDecision.CONFIRMED
        assert len(executor.validator_results[-1].exchanges) == 4
        assert all(
            item.response_headers["x-budobugs-websocket-frame-payload-persisted"] == "false"
            for item in executor.validator_results[-1].exchanges
        )
        assert all(
            item.response_headers["x-budobugs-websocket-status-origin"] == "synthetic-open-event"
            for item in executor.validator_results[-1].exchanges
        )
        evidence = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in (workspace.runs / "ws-run" / "artifacts").rglob("*")
            if path.is_file() and path.suffix in {".json", ".jsonl", ".har"}
        )
        assert "super-secret-frame-content-must-not-persist" not in evidence
        assert '"origin_navigation_url"' in evidence
        browser_root = workspace.runs / "ws-run" / "artifacts" / "browser" / "bob"
        assert not private_browser_root.is_relative_to(repository_root)
        assert not list(browser_root.glob("trace*.zip"))
        traces = list(private_browser_root.glob("trace*.zip"))
        assert traces
        assert all(b"super-secret-frame-content-must-not-persist" not in path.read_bytes() for path in traces)
        pre_traces = sorted(
            path
            for path in private_browser_root.glob("trace-pre-ws-*.zip")
            if path.resolve() not in existing_pre_traces
        )
        repeated_pre_traces = sorted(
            path
            for path in private_browser_root.glob("trace-pre-ws-*-ws-repeat-bob-cross-alice*.zip")
            if path.resolve() not in existing_pre_traces
        )
        assert len(pre_traces) == 4
        assert len(repeated_pre_traces) == 2
        assert repeated_pre_traces[0].name != repeated_pre_traces[1].name
        assert pre_traces[0].is_file()
        assert pre_traces[0].stat().st_size > 0

        killed_template = _template(base_ws, expected_cross_owner="bob")
        killed_template = killed_template.model_copy(update={"template_id": "program-ws-kill-001"})
        executor.safe_websocket_experiments = [killed_template]
        killed = await executor._run_safe_websocket_program_experiment(killed_template, "candidate-websocket-kill")
        await executor.close_browser()
        assert killed.outcome.decision is CandidateDecision.KILL
    finally:
        await _assert_native_fixture_stopped(manager, sys.exception())


def test_websocket_template_fails_closed_for_unknown_account_and_out_of_scope_url(
    service,
    lab_engagement,
    monkeypatch,
) -> None:
    program = lab_engagement.model_copy(
        update={
            "engagement_id": "program-websocket-boundary-001",
            "selected_mode": EngagementMode.PROGRAM,
            "testing_accounts_secret_refs": {"bob": "env://BUDO_WS_BOB"},
        }
    )
    service.save_engagement(program)
    template = _template("wss://outside.example")
    monkeypatch.setenv("BUDO_WS_TEMPLATE", template.model_dump_json())
    monkeypatch.setattr("budobugs.cli.app._service", lambda: service)
    denied = CliRunner().invoke(
        app,
        ["engagement", "websocket-experiment-set", program.engagement_id, "--spec-env", "BUDO_WS_TEMPLATE", "--json"],
    )
    assert denied.exit_code != 0
    assert "out of scope" in denied.output

    unknown = template.model_copy(
        update={
            "normal_control": template.normal_control.model_copy(update={"account_alias": "mallory"}),
            "experiment": template.experiment.model_copy(update={"account_alias": "mallory"}),
            "negative_control": template.negative_control.model_copy(update={"account_alias": "mallory"}),
        }
    )
    monkeypatch.setenv("BUDO_WS_TEMPLATE", unknown.model_dump_json())
    unknown_result = CliRunner().invoke(
        app,
        ["engagement", "websocket-experiment-set", program.engagement_id, "--spec-env", "BUDO_WS_TEMPLATE", "--json"],
    )
    assert unknown_result.exit_code != 0
    assert "undeclared" in unknown_result.output


def test_websocket_action_rejects_credential_like_query_parameters() -> None:
    with pytest.raises(ValidationError, match="credential-like"):
        SafeWebSocketAction(
            action_id="ws-secret-query",
            account_alias="bob",
            target_url="wss://fixture.example/ws?access_token=do-not-persist",
            expected_event="message",
        )
