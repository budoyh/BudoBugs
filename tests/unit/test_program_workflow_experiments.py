from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from budobugs.core.identifiers import new_id
from budobugs.labs.fixture_app import app as fixture_app
from budobugs.models import (
    ActionKind,
    AgentLoopState,
    AgentRole,
    CandidateDecision,
    EngagementMode,
    HttpExchange,
    Hypothesis,
    ObservationStatus,
    ProgramValidationPlan,
    SafeHttpAction,
    SafeWorkflowExperimentTemplate,
    WorkflowSlotCapture,
    WorkflowSlotInjection,
    WorkflowStep,
)
from budobugs.orchestration.catalog import ActionCatalogBuilder
from budobugs.orchestration.executor import TypedActionExecutor
from budobugs.orchestration.workflow import SafeWorkflowRunner, build_workflow_validator_result
from budobugs.proxy import DirectProxyBackend, ProxySelection
from budobugs.traffic.normalization import normalize_exchange


class AsgiDirect:
    def __init__(self, *, fail_path_once: str | None = None, interrupt: bool = False) -> None:
        self.fail_path_once = fail_path_once
        self.interrupt = interrupt
        self.failed = False

    async def send(
        self,
        engagement,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        content: str | None = None,
        account_alias: str | None = None,
        source: str = "direct",
    ) -> HttpExchange:
        if self.fail_path_once and httpx.URL(url).path == self.fail_path_once and not self.failed:
            self.failed = True
            if self.interrupt:
                raise KeyboardInterrupt(f"simulated recoverable process interruption: {headers}")
            raise RuntimeError(f"simulated bounded request failure: {headers}")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=fixture_app),
            base_url="http://127.0.0.1:8765",
        ) as client:
            response = await client.request(method, url, headers=headers, content=content)
        return normalize_exchange(
            HttpExchange(
                exchange_id=new_id("http"),
                engagement_id=engagement.engagement_id,
                method=method,
                url=str(response.request.url),
                request_headers=dict(response.request.headers),
                request_body=response.request.content.decode(errors="replace") if response.request.content else None,
                response_status=response.status_code,
                response_headers=dict(response.headers),
                response_body=response.text,
                http_version="HTTP/1.1",
                account_alias=account_alias,
                source=source,
            )
        )


def _action(
    base: str,
    action_id: str,
    account: str,
    method: str,
    path: str,
    statuses: list[int],
    *,
    body: object = None,
    headers: dict[str, str] | None = None,
) -> SafeHttpAction:
    return SafeHttpAction(
        action_id=action_id,
        account_alias=account,
        method=method,
        target_url=f"{base}{path}",
        expected_statuses=statuses,
        body=body,
        headers=headers or {},
        operation_boundary="execute exact disposable fixture workflow",
        object_boundary="local fixture session/share lifecycle",
    )


def _metadata(**updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "template_id": "session-revocation-workflow",
        "specialist_role": "api-auth-specialist",
        "title": "Revoked API session remains valid for protected reads",
        "vulnerability_class": "session-revocation",
        "affected_feature": "API session lifecycle",
        "security_invariant": "A revoked API session must immediately lose protected read access.",
        "root_cause_key": "fixture-session-consumer-revocation-check",
        "repair_boundary": "enforce revocation in the shared API session consumer",
        "capability_before": "one self-owned session can access its own profile",
        "capability_after": "the same revoked session still accesses its own protected profile",
        "capability_delta": "continued protected access after explicit session revocation",
        "strongest_benign_explanation": "revocation may be eventual or the endpoint may intentionally ignore it",
        "impact": "stolen or revoked sessions can retain access after the user terminates them",
    }
    value.update(updates)
    return value


def _session_template(base: str) -> SafeWorkflowExperimentTemplate:
    slot_header = WorkflowSlotInjection(
        slot_name="old_session",
        destination="header",
        name="X-Fixture-API-Session",
    )
    return SafeWorkflowExperimentTemplate(
        **_metadata(),
        normal_steps=[
            WorkflowStep(
                action=_action(base, "start-old-session", "alice", "POST", "/api/session/start", [200]),
                captures=[WorkflowSlotCapture(slot_name="old_session", source="json", json_pointer="/session")],
                expected_json_pointer="/state",
                expected_json_value="authenticated",
            ),
            WorkflowStep(
                action=_action(base, "baseline-old-session", "alice", "GET", "/api/session/me", [200]),
                injections=[slot_header],
                expected_json_pointer="/revoked",
                expected_json_value="false",
            ),
        ],
        experiment_steps=[
            WorkflowStep(
                action=_action(base, "revoke-old-session", "alice", "POST", "/api/session/revoke", [200]),
                injections=[slot_header],
                expected_json_pointer="/state",
                expected_json_value="revoked",
            ),
            WorkflowStep(
                action=_action(base, "reuse-revoked-session", "alice", "GET", "/api/session/me", [200]),
                injections=[slot_header],
                expected_json_pointer="/revoked",
                expected_json_value="true",
            ),
        ],
        negative_steps=[
            WorkflowStep(
                action=_action(base, "secure-revoked-session", "alice", "GET", "/api/secure-session/me", [401]),
                injections=[slot_header],
            )
        ],
        cleanup_steps=[
            WorkflowStep(
                action=_action(
                    base,
                    "reset-session-fixture",
                    "alice",
                    "POST",
                    "/__fixture__/reset",
                    [200],
                    headers={"X-Budo-Fixture": "reset-local-test-state"},
                ),
                expected_json_pointer="/status",
                expected_json_value="reset",
            )
        ],
        cleanup_verification_steps=[
            WorkflowStep(
                action=_action(base, "verify-old-session-removed", "alice", "GET", "/api/session/me", [401]),
                injections=[slot_header],
            )
        ],
    )


def _share_template(base: str) -> SafeWorkflowExperimentTemplate:
    inject_json = WorkflowSlotInjection(slot_name="share_token", destination="json", json_pointer="/token")
    body = {"token": "engagement-declared-placeholder"}
    return SafeWorkflowExperimentTemplate(
        **_metadata(
            template_id="cross-account-share-workflow",
            specialist_role="authorization-specialist",
            title="Revoked cross-account JSON share remains readable",
            vulnerability_class="file-share-revocation",
            affected_feature="cross-account JSON share lifecycle",
            security_invariant="A revoked share must deny the declared recipient on every consumer.",
            root_cause_key="fixture-json-share-revocation-check",
            repair_boundary="enforce active-share state in the shared JSON consumer",
            capability_before="bob reads an active share explicitly created by alice",
            capability_after="bob still reads the same share after alice revokes it",
            capability_delta="continued cross-account file access after explicit share revocation",
            impact="revoked recipients retain access to shared private files",
        ),
        normal_steps=[
            WorkflowStep(
                action=_action(
                    base,
                    "create-alice-bob-share",
                    "alice",
                    "POST",
                    "/api/shares",
                    [200],
                    body={"file_id": 1, "recipient": "bob"},
                ),
                captures=[WorkflowSlotCapture(slot_name="share_token", source="json", json_pointer="/token")],
                expected_json_pointer="/state",
                expected_json_value="active",
            ),
            WorkflowStep(
                action=_action(base, "bob-active-share", "bob", "POST", "/api/secure-share-access", [200], body=body),
                injections=[inject_json],
                expected_json_pointer="/revoked",
                expected_json_value=False,
            ),
        ],
        experiment_steps=[
            WorkflowStep(
                action=_action(base, "alice-revoke-share", "alice", "POST", "/api/share-revoke", [200], body=body),
                injections=[inject_json],
                expected_json_pointer="/state",
                expected_json_value="revoked",
            ),
            WorkflowStep(
                action=_action(base, "bob-reuse-share", "bob", "POST", "/api/share-access", [200], body=body),
                injections=[inject_json],
                expected_json_pointer="/revoked",
                expected_json_value=True,
            ),
        ],
        negative_steps=[
            WorkflowStep(
                action=_action(
                    base,
                    "bob-secure-revoked-share",
                    "bob",
                    "POST",
                    "/api/secure-share-access",
                    [403],
                    body=body,
                ),
                injections=[inject_json],
            )
        ],
        cleanup_steps=[
            WorkflowStep(
                action=_action(
                    base,
                    "reset-share-fixture",
                    "alice",
                    "POST",
                    "/__fixture__/reset",
                    [200],
                    headers={"X-Budo-Fixture": "reset-local-test-state"},
                )
            )
        ],
        cleanup_verification_steps=[
            WorkflowStep(action=_action(base, "verify-share-removed", "bob", "GET", "/api/shares/share-1-bob", [403]))
        ],
    )


def _program(lab_engagement):
    return lab_engagement.model_copy(
        update={
            "selected_mode": EngagementMode.PROGRAM,
            "testing_accounts_secret_refs": {
                "alice": "keyring://fixture/alice",
                "bob": "keyring://fixture/bob",
            },
        }
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("template_factory", [_session_template, _share_template])
async def test_real_fixture_workflows_confirm_and_never_persist_slots(
    tmp_path: Path,
    lab_engagement,
    template_factory,
) -> None:
    engagement = _program(lab_engagement)
    template = template_factory(engagement.root_targets[0].uri)
    runner = SafeWorkflowRunner(
        engagement=engagement,
        run_id="run-workflow-fixture",
        artifact_root=tmp_path,
        direct=AsgiDirect(),  # type: ignore[arg-type]
        account_headers={"alice": {"Authorization": "Fixture alice"}, "bob": {"Authorization": "Fixture bob"}},
    )
    execution = await runner.run(template)
    result = build_workflow_validator_result(template, execution, engagement, "candidate-workflow")

    assert execution.decision is CandidateDecision.CONFIRMED
    assert execution.repeated
    assert execution.normal_passed
    assert execution.negative_passed
    assert execution.cleanup_completed
    assert execution.evidence_closed
    assert result.outcome.decision is CandidateDecision.CONFIRMED
    persisted = Path(execution.receipt_path).read_text(encoding="utf-8") + json.dumps(
        [item.model_dump(mode="json") for item in execution.exchanges]
    )
    assert "fixture-api-alice" not in persisted
    assert "share-1-bob" not in persisted
    assert "captured_slot_names" in persisted


@pytest.mark.asyncio
async def test_workflow_failure_still_cleans_and_interrupted_receipt_resumes(
    tmp_path: Path,
    lab_engagement,
) -> None:
    engagement = _program(lab_engagement)
    template = _session_template(engagement.root_targets[0].uri)
    headers = {"alice": {"Authorization": "Fixture alice"}, "bob": {"Authorization": "Fixture bob"}}

    failed = await SafeWorkflowRunner(
        engagement=engagement,
        run_id="run-failed-workflow",
        artifact_root=tmp_path / "failed",
        direct=AsgiDirect(fail_path_once="/api/session/me"),  # type: ignore[arg-type]
        account_headers=headers,
    ).run(template)
    assert failed.decision is CandidateDecision.HOLD
    assert failed.cleanup_completed
    assert failed.error_summaries
    assert "fixture-api-alice" not in Path(failed.receipt_path).read_text(encoding="utf-8")

    interrupted_root = tmp_path / "interrupted"
    with pytest.raises(KeyboardInterrupt, match="recoverable"):
        await SafeWorkflowRunner(
            engagement=engagement,
            run_id="run-resumed-workflow",
            artifact_root=interrupted_root,
            direct=AsgiDirect(fail_path_once="/api/session/me", interrupt=True),  # type: ignore[arg-type]
            account_headers=headers,
        ).run(template)
    resumed = await SafeWorkflowRunner(
        engagement=engagement,
        run_id="run-resumed-workflow",
        artifact_root=interrupted_root,
        direct=AsgiDirect(),  # type: ignore[arg-type]
        account_headers=headers,
    ).run(template)
    receipt = json.loads(Path(resumed.receipt_path).read_text(encoding="utf-8"))
    assert resumed.decision is CandidateDecision.CONFIRMED
    assert receipt["resumed"] is True
    assert receipt["attempt_count"] == 2
    assert receipt["prior_attempts"][0]["status"] == "INTERRUPTED"


@pytest.mark.asyncio
async def test_workflow_cleanup_predicate_gap_is_hold_not_executor_confirmation(
    tmp_path: Path,
    lab_engagement,
) -> None:
    engagement = _program(lab_engagement)
    template = _session_template(engagement.root_targets[0].uri)
    template = template.model_copy(
        update={
            "cleanup_steps": [
                template.cleanup_steps[0].model_copy(
                    update={"action": template.cleanup_steps[0].action.model_copy(update={"expected_statuses": [201]})}
                )
            ]
        }
    )
    execution = await SafeWorkflowRunner(
        engagement=engagement,
        run_id="run-cleanup-hold",
        artifact_root=tmp_path,
        direct=AsgiDirect(),  # type: ignore[arg-type]
        account_headers={"alice": {"Authorization": "Fixture alice"}},
    ).run(template)
    receipt = json.loads(Path(execution.receipt_path).read_text(encoding="utf-8"))

    assert execution.decision is CandidateDecision.HOLD
    assert not execution.cleanup_completed
    assert not execution.evidence_closed
    cleanup = next(item for item in receipt["steps"] if item["phase"] == "cleanup")
    assert cleanup["status"] == "PREDICATE_FAILED"


def test_workflow_template_rejects_unsafe_mutation_and_unbound_slots(lab_engagement) -> None:
    template = _session_template(lab_engagement.root_targets[0].uri)
    payload = template.model_dump(mode="python")
    payload["experiment_steps"][0]["action"]["account_alias"] = "anonymous"
    with pytest.raises(ValueError, match="self-owned"):
        SafeWorkflowExperimentTemplate.model_validate(payload)

    payload = template.model_dump(mode="python")
    payload["normal_steps"][0]["captures"] = []
    with pytest.raises(ValueError, match="before capture"):
        SafeWorkflowExperimentTemplate.model_validate(payload)

    unrelated_normal = template.model_dump(mode="python")
    for step in unrelated_normal["normal_steps"]:
        step["action"]["object_boundary"] = "unrelated fixture object"
    with pytest.raises(ValueError, match="normal workflow must cover"):
        SafeWorkflowExperimentTemplate.model_validate(unrelated_normal)

    unrelated_negative = template.model_dump(mode="python")
    unrelated_negative["negative_steps"][0]["action"]["object_boundary"] = "unrelated fixture object"
    with pytest.raises(ValueError, match="negative workflow must bind"):
        SafeWorkflowExperimentTemplate.model_validate(unrelated_negative)

    unrelated_cleanup = template.model_dump(mode="python")
    unrelated_cleanup["cleanup_steps"][0]["action"]["object_boundary"] = "unrelated fixture object"
    with pytest.raises(ValueError, match="cleanup mutations must cover"):
        SafeWorkflowExperimentTemplate.model_validate(unrelated_cleanup)

    unrelated_verification = template.model_dump(mode="python")
    unrelated_verification["cleanup_verification_steps"][0]["action"]["object_boundary"] = "unrelated fixture object"
    with pytest.raises(ValueError, match="cleanup verification must cover"):
        SafeWorkflowExperimentTemplate.model_validate(unrelated_verification)

    leaking_normal_mutation = template.model_dump(mode="python")
    leaking_normal_mutation["normal_steps"][0]["action"]["object_boundary"] = "normal-created-object"
    with pytest.raises(ValueError, match="possibly successful workflow mutation object"):
        SafeWorkflowExperimentTemplate.model_validate(leaking_normal_mutation)

    leaking_successful_negative = template.model_dump(mode="python")
    leaking_successful_negative["negative_steps"][0]["action"].update(
        {
            "method": "POST",
            "expected_statuses": [200],
            "object_boundary": "negative-created-object",
        }
    )
    with pytest.raises(ValueError, match="negative workflow must bind|possibly successful workflow mutation"):
        SafeWorkflowExperimentTemplate.model_validate(leaking_successful_negative)


def test_specialist_catalog_emits_typed_workflow_validator(lab_engagement) -> None:
    engagement = _program(lab_engagement)
    template = _session_template(engagement.root_targets[0].uri)
    hypothesis = Hypothesis(
        hypothesis_id="hypothesis-session-workflow",
        engagement_id=engagement.engagement_id,
        title="session revocation lifecycle",
        vulnerability_class="authentication-session",
        endpoint_family_id="family-session-revoke",
        invariant_id="invariant-session-revoke",
        rationale="observed exact local session lifecycle",
        proposed_single_variable_change="revoke only the disposable old session",
        expected_control="secure old-session route denies twice",
        validator_id="session-lifecycle",
        skill_name="api-auth-session",
    )
    plan = ProgramValidationPlan(
        plan_id="plan-session-workflow",
        hypothesis_id=hypothesis.hypothesis_id,
        endpoint_family_id=hypothesis.endpoint_family_id,
        validator_id=f"program-workflow--{template.template_id}",
        specialist_role="api-auth-specialist",
        control_source="engagement-safe-experiment",
        control_ids=[action.action_id for action in template.all_actions()],
        safe_experiment_template_id=template.template_id,
    )
    catalog = ActionCatalogBuilder(
        engagement,
        safe_experiments=[template],
        hypotheses=[hypothesis],
        program_validation_plans=[plan],
    )
    state = AgentLoopState(
        loop_id="loop-session-workflow",
        run_id="run-session-workflow",
        engagement_id=engagement.engagement_id,
        current_round=2,
    )

    actions = catalog.actions(AgentRole.API_AUTH_SPECIALIST, 2, state)
    validator = next(item for item in actions if item.validator_id == plan.validator_id)
    assert validator.kind is ActionKind.VALIDATOR_RUN
    assert validator.candidate_id == hypothesis.hypothesis_id
    assert validator.mutation_scope == "self-owned"


@pytest.mark.asyncio
async def test_typed_executor_executes_catalog_workflow_and_persists_redacted_evidence(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement,
) -> None:
    engagement = _program(lab_engagement)
    template = _session_template(engagement.root_targets[0].uri)
    hypothesis = Hypothesis(
        hypothesis_id="hypothesis-executor-session-workflow",
        engagement_id=engagement.engagement_id,
        title="session revocation lifecycle",
        vulnerability_class="authentication-session",
        endpoint_family_id="family-session-revoke",
        invariant_id="invariant-session-revoke",
        rationale="observed exact local session lifecycle",
        proposed_single_variable_change="revoke only the disposable old session",
        expected_control="secure old-session route denies twice",
        validator_id="session-lifecycle",
        skill_name="api-auth-session",
    )
    plan = ProgramValidationPlan(
        plan_id="plan-executor-session-workflow",
        hypothesis_id=hypothesis.hypothesis_id,
        endpoint_family_id=hypothesis.endpoint_family_id,
        validator_id=f"program-workflow--{template.template_id}",
        specialist_role="api-auth-specialist",
        control_source="engagement-safe-experiment",
        control_ids=[action.action_id for action in template.all_actions()],
        safe_experiment_template_id=template.template_id,
    )
    artifact_root = tmp_path / "typed-workflow"
    executor = TypedActionExecutor(
        repository_root=repository_root,
        runtime_home=tmp_path / "runtime",
        artifact_root=artifact_root,
        engagement=engagement,
        run_id="run-typed-workflow",
        proxy=ProxySelection(
            backend=DirectProxyBackend(),
            requested="direct",
            selected="direct",
            ready=True,
            detail="local ASGI fixture adapter",
            attempted=(),
            receipt_path=str(tmp_path / "proxy.json"),
        ),
        account_headers={"alice": {"Authorization": "Fixture alice"}},
        safe_experiments=[template],
    )
    executor.direct = AsgiDirect()  # type: ignore[assignment]
    executor.hypotheses.append(hypothesis)
    executor.program_validation_plans.append(plan)
    proposal = next(
        item
        for item in ActionCatalogBuilder(
            engagement,
            safe_experiments=[template],
            hypotheses=executor.hypotheses,
            program_validation_plans=executor.program_validation_plans,
        ).actions(
            AgentRole.API_AUTH_SPECIALIST,
            2,
            AgentLoopState(
                loop_id="loop-typed-workflow",
                run_id="run-typed-workflow",
                engagement_id=engagement.engagement_id,
                current_round=2,
            ),
        )
        if item.validator_id == plan.validator_id
    )

    observation = await executor.execute(proposal)

    assert observation.status is ObservationStatus.EXECUTED
    assert executor.validator_results[-1].outcome.decision is CandidateDecision.CONFIRMED
    persisted = "\n".join(path.read_text(encoding="utf-8") for path in artifact_root.rglob("*.json"))
    assert "fixture-api-alice" not in persisted
    assert "workflow-slot:old_session" in persisted


def test_workflow_slot_supports_authorization_header_query_json_and_header_capture() -> None:
    token = "short-lived-token-001"
    url = "http://127.0.0.1:8765/api/use?slot=declared-placeholder"
    headers: dict[str, str] = {}
    body: object = {"nested": {"slot": "declared-placeholder"}}
    injections = [
        WorkflowSlotInjection(slot_name="token", destination="authorization", prefix="Bearer "),
        WorkflowSlotInjection(slot_name="token", destination="header", name="X-Workflow-Token"),
        WorkflowSlotInjection(slot_name="token", destination="query", name="slot"),
        WorkflowSlotInjection(slot_name="token", destination="json", json_pointer="/nested/slot"),
    ]
    for injection in injections:
        url, headers, body = SafeWorkflowRunner._inject(injection, token, url, headers, body)

    assert headers["Authorization"] == f"Bearer {token}"
    assert headers["X-Workflow-Token"] == token
    assert httpx.URL(url).params["slot"] == token
    assert body == {"nested": {"slot": token}}
    exchange = HttpExchange(
        exchange_id="http-header-slot",
        engagement_id="lab-fixture-001",
        method="POST",
        url=url,
        response_status=200,
        response_headers={"X-New-Session": token},
        source="fixture",
    )
    assert (
        SafeWorkflowRunner._capture(
            exchange,
            WorkflowSlotCapture(slot_name="token", source="header", header_name="X-New-Session"),
        )
        == token
    )
