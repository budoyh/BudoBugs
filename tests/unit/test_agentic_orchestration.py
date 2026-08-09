from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError
from tests.conftest import make_exchange

from budobugs.agents.router import ModelRouter
from budobugs.agents.runner import AgentResult, CodexTaskRunner
from budobugs.core.identifiers import new_id
from budobugs.core.io import atomic_write_json
from budobugs.knowledge.vendor import BountyPrioritizer, RootCauseDeduper, VendorKnowledgeBase
from budobugs.models import (
    ActionKind,
    ActionProposal,
    AgentInvocation,
    AgentLoopState,
    AgentLoopStatus,
    AgentRole,
    AgentTurnReceipt,
    CandidateDecision,
    CostRecord,
    DuplicateAssessmentDecision,
    Engagement,
    EngagementMode,
    Observation,
    ObservationStatus,
    OutcomeStatus,
    PhaseName,
    PlatformOutcome,
    ValidationOutcome,
)
from budobugs.orchestration.agent_loop import (
    AgentLoopInterrupted,
    AgentOrchestrator,
    CodexProposalProvider,
    PolicyProposalProvider,
)
from budobugs.orchestration.catalog import ActionCatalogBuilder
from budobugs.orchestration.engine import HuntEngine
from budobugs.orchestration.skill_runtime import SkillRuntime
from budobugs.proxy.base import ProxyUnavailable
from budobugs.proxy.factory import ProxyBackendFactory
from budobugs.traffic.modeler import build_traffic_model


def _action(
    *,
    action_id: str = "safe-action",
    role: AgentRole = AgentRole.COORDINATOR,
    skill: str = "budobugs-controller",
    kind: ActionKind = ActionKind.PROXY_SEARCH,
    gain: float = 0.5,
) -> ActionProposal:
    values: dict[str, object] = {}
    if kind is ActionKind.HTTP_REQUEST:
        values.update(target_url="http://127.0.0.1:8765/api/objects/1", method="GET")
    return ActionProposal(
        proposal_id=new_id("proposal"),
        catalog_action_id=action_id,
        round_index=1,
        agent_role=role,
        skill_name=skill,
        kind=kind,
        objective="execute one bounded experiment",
        expected_observation="one typed observation",
        expected_information_gain=gain,
        **values,
    )


def _complete_codex_choice(
    action: ActionProposal,
    *,
    rationale: str,
    expected_information_gain: float,
    follow_up: str,
) -> dict[str, object]:
    """Shape the only Codex specialist response the executor may accept."""

    return {
        "proposal_json": json.dumps(
            action.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        "rationale": rationale,
        "expected_information_gain": expected_information_gain,
        "follow_up": follow_up,
    }


def test_action_contract_rejects_credentials_shapes_and_unbounded_mutation() -> None:
    with pytest.raises(ValidationError, match="credentials"):
        ActionProposal.model_validate({**_action().model_dump(mode="json"), "headers": {"Authorization": "secret"}})
    payload = _action(kind=ActionKind.HTTP_REQUEST).model_dump(mode="json")
    payload["target_url"] = None
    with pytest.raises(ValidationError, match="requires target_url"):
        ActionProposal.model_validate(payload)
    with pytest.raises(ValidationError, match="self-owned"):
        ActionProposal.model_validate(
            {
                **_action(kind=ActionKind.HTTP_REQUEST).model_dump(mode="json"),
                "target_url": "http://127.0.0.1:8765/api/objects",
                "method": "POST",
            }
        )


def test_codex_specialist_schema_is_flat_draft_json_without_long_proposal_enum() -> None:
    action = _action(kind=ActionKind.HTTP_REQUEST)
    schema = CodexProposalProvider._schema([action])
    Draft202012Validator.check_schema(schema)

    assert "$defs" not in schema
    assert "anyOf" not in json.dumps(schema, ensure_ascii=False)
    assert isinstance(schema["additionalProperties"], bool)
    assert schema["properties"].keys() == {
        "proposal_json",
        "rationale",
        "expected_information_gain",
        "follow_up",
    }
    proposal_json = schema["properties"]["proposal_json"]
    assert isinstance(proposal_json, dict)
    assert proposal_json == {"type": "string", "minLength": 2, "maxLength": 20_000}
    assert "enum" not in json.dumps(schema, ensure_ascii=False)


def test_codex_runner_windows_resolver_replaces_shell_shim_with_native_executable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "budobugs.agents.runner.shutil.which",
        lambda name: "C:/native/codex.exe" if name == "codex.exe" else None,
    )
    executable = CodexTaskRunner._resolve_windows_executable(
        "C:/project/node_modules/.bin/codex.cmd",
        tmp_path,
    )
    assert executable == "C:/native/codex.exe"


def test_skill_runtime_and_catalog_bind_real_skills_to_all_required_specialists(
    repository_root: Path, lab_engagement: Engagement
) -> None:
    runtime = SkillRuntime(repository_root)
    contract = runtime.validate(_action())
    assert contract.name == "budobugs-controller"
    assert Path(contract.path).is_file()
    with pytest.raises(PermissionError, match="cannot invoke"):
        runtime.validate(
            _action(
                role=AgentRole.BROWSER_EXPLORER,
                skill="budobugs-controller",
                kind=ActionKind.PROXY_SEARCH,
            )
        )
    with pytest.raises(PermissionError, match="cannot propose"):
        runtime.validate(_action(kind=ActionKind.HTTP_REQUEST))
    with pytest.raises(FileNotFoundError):
        runtime.load("does-not-exist")

    catalog = ActionCatalogBuilder(lab_engagement)
    state = AgentLoopState(
        loop_id="agent-loop-test",
        run_id="run-test",
        engagement_id=lab_engagement.engagement_id,
    )
    roles = {role for round_index in (1, 2, 3) for role in catalog.schedule(round_index)}
    assert roles >= {
        AgentRole.COORDINATOR,
        AgentRole.BROWSER_EXPLORER,
        AgentRole.TRAFFIC_MODELER,
        AgentRole.AUTHORIZATION_SPECIALIST,
        AgentRole.BUSINESS_LOGIC_SPECIALIST,
        AgentRole.API_AUTH_SPECIALIST,
        AgentRole.EVIDENCE_VALIDATOR,
        AgentRole.ADVERSARIAL_CRITIC,
    }
    auth_ids: list[str] = []
    for _ in range(6):
        actions = catalog.actions(AgentRole.AUTHORIZATION_SPECIALIST, 2, state)
        selected = max(actions, key=lambda item: item.expected_information_gain)
        auth_ids.append(selected.validator_id or "")
        state.executed_catalog_actions.append(selected.catalog_action_id)
    assert set(auth_ids) == {
        "fixture-horizontal-rest",
        "fixture-horizontal-graphql",
        "fixture-horizontal-websocket",
        "fixture-vertical-role",
        "fixture-cross-tenant",
        "fixture-file-share",
    }
    client_ids = {
        action.validator_id
        for action in catalog.actions(AgentRole.WEB_CLIENT_SPECIALIST, 2, state)
        if action.kind is ActionKind.VALIDATOR_RUN
    }
    assert client_ids >= {
        "fixture-client-xss",
        "fixture-cors-credentialed-origin",
        "fixture-csrf-token-bypass",
    }


def test_catalog_review_dependencies_fail_closed_and_refresh_only_after_live_research(
    lab_engagement: Engagement,
) -> None:
    catalog = ActionCatalogBuilder(lab_engagement)
    state = AgentLoopState(
        loop_id="loop-main-chain-dependencies",
        run_id="run-main-chain-dependencies",
        engagement_id=lab_engagement.engagement_id,
        executed_catalog_actions=[
            "lab-engagement-intake",
            "lab-proxy-inventory",
            "lab-browser-two-account-explore",
            "lab-traffic-model",
        ],
    )

    assert catalog.actions(AgentRole.TRAFFIC_MODELER, 2, state) == []
    assert catalog.actions(AgentRole.ADVERSARIAL_CRITIC, 3, state) == []
    assert catalog.actions(AgentRole.REPORT_WRITER, 3, state) == []
    assert catalog.actions(AgentRole.COORDINATOR, 3, state) == []

    round_two_roles = (
        AgentRole.RECON_RESEARCHER,
        AgentRole.SOURCE_REVIEWER,
        AgentRole.BROWSER_EXPLORER,
        AgentRole.AUTHORIZATION_SPECIALIST,
        AgentRole.BUSINESS_LOGIC_SPECIALIST,
        AgentRole.API_AUTH_SPECIALIST,
        AgentRole.WEB_CLIENT_SPECIALIST,
    )
    while True:
        live = [action for role in round_two_roles for action in catalog.actions(role, 2, state)]
        if not live:
            break
        state.executed_catalog_actions.extend(action.catalog_action_id for action in live)

    remodel = catalog.actions(AgentRole.TRAFFIC_MODELER, 2, state)
    assert [item.catalog_action_id for item in remodel] == ["lab-traffic-remodel"]
    state.executed_catalog_actions.append("lab-traffic-remodel")
    false_suite = catalog.actions(AgentRole.EVIDENCE_VALIDATOR, 3, state)
    assert [(item.catalog_action_id, item.skill_name) for item in false_suite] == [
        ("fixture-false-control-suite", "lab-evaluation")
    ]
    state.executed_catalog_actions.append("fixture-false-control-suite")
    hypothesis_review = catalog.actions(AgentRole.EVIDENCE_VALIDATOR, 3, state)
    assert [(item.catalog_action_id, item.skill_name) for item in hypothesis_review] == [
        ("lab-hypothesis-evidence-review", "hypothesis-and-validation")
    ]
    assert catalog.actions(AgentRole.ADVERSARIAL_CRITIC, 3, state) == []
    state.executed_catalog_actions.append("lab-hypothesis-evidence-review")
    assert [item.catalog_action_id for item in catalog.actions(AgentRole.ADVERSARIAL_CRITIC, 3, state)] == [
        "lab-adversarial-review"
    ]
    assert catalog.actions(AgentRole.REPORT_WRITER, 3, state) == []
    state.executed_catalog_actions.append("lab-adversarial-review")
    assert [item.catalog_action_id for item in catalog.actions(AgentRole.REPORT_WRITER, 3, state)] == [
        "lab-report-readiness-review"
    ]
    assert catalog.actions(AgentRole.COORDINATOR, 3, state) == []
    state.blocked_catalog_actions.append("lab-report-readiness-review")
    assert catalog.actions(AgentRole.COORDINATOR, 3, state) == []
    state.blocked_catalog_actions.clear()
    state.executed_catalog_actions.append("lab-report-readiness-review")
    assert [item.catalog_action_id for item in catalog.actions(AgentRole.COORDINATOR, 3, state)] == ["lab-finish"]


def test_program_review_report_and_finish_dependencies_require_executed_observations(
    lab_engagement: Engagement,
) -> None:
    program = lab_engagement.model_copy(update={"selected_mode": EngagementMode.PROGRAM})
    catalog = ActionCatalogBuilder(program)
    state = AgentLoopState(
        loop_id="loop-program-review-dependencies",
        run_id="run-program-review-dependencies",
        engagement_id=program.engagement_id,
        executed_catalog_actions=[
            "program-passive-history-inventory",
            "program-registered-http-probe",
            "program-captured-source-review",
            "program-authorization-specialist-authorization-input-review",
            "program-business-logic-specialist-business-logic-input-review",
            "program-api-auth-specialist-authentication-session-input-review",
            "program-web-client-specialist-web-client-file-input-review",
        ],
    )
    hypothesis = catalog.actions(AgentRole.EVIDENCE_VALIDATOR, 3, state)
    assert [item.catalog_action_id for item in hypothesis] == ["program-hypothesis-evidence-review"]
    assert catalog.actions(AgentRole.ADVERSARIAL_CRITIC, 3, state) == []
    assert catalog.actions(AgentRole.REPORT_WRITER, 3, state) == []
    assert catalog.actions(AgentRole.COORDINATOR, 3, state) == []

    state.blocked_catalog_actions.append("program-hypothesis-evidence-review")
    assert catalog.actions(AgentRole.EVIDENCE_VALIDATOR, 3, state) == []
    assert catalog.actions(AgentRole.ADVERSARIAL_CRITIC, 3, state) == []
    state.blocked_catalog_actions.clear()
    state.executed_catalog_actions.append("program-hypothesis-evidence-review")
    assert [item.catalog_action_id for item in catalog.actions(AgentRole.EVIDENCE_VALIDATOR, 3, state)] == [
        "program-evidence-review"
    ]
    state.executed_catalog_actions.append("program-evidence-review")
    assert [item.catalog_action_id for item in catalog.actions(AgentRole.ADVERSARIAL_CRITIC, 3, state)] == [
        "program-adversarial-review"
    ]
    state.executed_catalog_actions.append("program-adversarial-review")
    assert [item.catalog_action_id for item in catalog.actions(AgentRole.REPORT_WRITER, 3, state)] == [
        "program-report-readiness-review"
    ]
    state.blocked_catalog_actions.append("program-report-readiness-review")
    assert catalog.actions(AgentRole.COORDINATOR, 3, state) == []
    state.blocked_catalog_actions.clear()
    state.executed_catalog_actions.append("program-report-readiness-review")
    assert [item.catalog_action_id for item in catalog.actions(AgentRole.COORDINATOR, 3, state)] == ["program-finish"]


@pytest.mark.asyncio
async def test_policy_loop_executes_all_twelve_roles_and_fourteen_skills_without_claiming_acceptance(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement: Engagement,
) -> None:
    class PolicyExecutor:
        safe_experiments: list[object] = []
        safe_websocket_experiments: list[object] = []
        validator_results: list[object] = []
        exchanges: list[object] = []
        browser_artifacts: list[str] = []
        root_cause_clusters: list[object] = []

        class proxy:
            selected = "direct"

        def __init__(self) -> None:
            self.skill_runtime = SkillRuntime(repository_root)

        async def close_browser(self) -> None:
            return None

        async def execute(self, proposal: ActionProposal) -> Observation:
            self.skill_runtime.validate(proposal)
            discovered = (
                [f"{lab_engagement.root_targets[0].uri.rstrip('/')}/app/orders"]
                if proposal.kind in {ActionKind.BROWSER_EXPLORE, ActionKind.BROWSER_NAVIGATE}
                else []
            )
            details = (
                {
                    "replayable_exchanges": [
                        {"exchange_id": "exchange-policy-loop", "method": "GET", "account_alias": "alice"}
                    ]
                }
                if proposal.kind is ActionKind.PROXY_SEARCH
                else {}
            )
            return Observation(
                observation_id=new_id("observation"),
                proposal_id=proposal.proposal_id,
                round_index=proposal.round_index,
                status=ObservationStatus.EXECUTED,
                summary="policy fixture executor completed one typed catalog action",
                information_gain=0.8,
                discovered_urls=discovered,
                details=details,
            )

    orchestrator = AgentOrchestrator(
        engagement=lab_engagement,
        run_id="run-all-agent-skill-main-chain",
        artifact_root=tmp_path / "all-agent-skill-main-chain",
        executor=PolicyExecutor(),  # type: ignore[arg-type]
        provider=PolicyProposalProvider(),
        max_rounds=3,
    )
    execution = await orchestrator.run(resume=False)
    assert execution.state.status is AgentLoopStatus.COMPLETED
    assert set(execution.state.participating_agents) == set(AgentRole)
    assert set(execution.state.invoked_skills) == set(SkillRuntime.SKILL_ACTIONS)
    assert len(execution.state.participating_agents) == 12
    assert len(execution.state.invoked_skills) == 14
    actual_turn_pairs = {
        (turn.proposal.agent_role, turn.proposal.skill_name)
        for turn in execution.state.turns
        if turn.observation.status is ObservationStatus.EXECUTED
    }
    assert {skill for _, skill in actual_turn_pairs} == set(SkillRuntime.SKILL_ACTIONS)
    assert all(
        any(skill in SkillRuntime.ROLE_SKILLS[role] for actual_role, skill in actual_turn_pairs if actual_role is role)
        for role in AgentRole
    )
    assert execution.state.turns[-1].proposal.catalog_action_id == "lab-finish"

    context: dict[str, object] = {
        "agent_loop_receipt": execution.receipt_path,
        "validation_outcomes": [],
        "root_cause_clusters": [],
        "finding_packs": {},
        "reports": {},
    }
    HuntEngine._finalize_agent_receipt(context, agent_mode="policy")  # noqa: SLF001
    receipt = json.loads(Path(execution.receipt_path).read_text(encoding="utf-8"))
    assert receipt["artifact_binding_gate"]["passed"] is True
    assert receipt["artifact_binding_gate"]["ledger_path"] is None
    assert receipt["acceptance_passed"] is False
    assert receipt["acceptance_checks"]["at_least_four_vulnerability_classes_confirmed"] is False
    assert receipt["acceptance_checks"]["reports_complete_for_primary_root_causes"] is False

    program = lab_engagement.model_copy(
        update={
            "selected_mode": EngagementMode.PROGRAM,
            "testing_accounts_secret_refs": {
                "alice": "env://BUDOBUGS_TEST_ALICE",
                "bob": "env://BUDOBUGS_TEST_BOB",
            },
        }
    )
    program_orchestrator = AgentOrchestrator(
        engagement=program,
        run_id="run-all-program-agent-skill-main-chain",
        artifact_root=tmp_path / "all-program-agent-skill-main-chain",
        executor=PolicyExecutor(),  # type: ignore[arg-type]
        provider=PolicyProposalProvider(),
        max_rounds=3,
    )
    program_execution = await program_orchestrator.run(resume=False)
    assert program_execution.state.status is AgentLoopStatus.COMPLETED
    assert set(program_execution.state.participating_agents) == set(AgentRole)
    assert set(program_execution.state.invoked_skills) == set(SkillRuntime.SKILL_ACTIONS) - {"lab-evaluation"}
    assert len(program_execution.state.invoked_skills) == 13
    assert {
        turn.proposal.skill_name
        for turn in program_execution.state.turns
        if turn.observation.status is ObservationStatus.EXECUTED
    } == set(SkillRuntime.SKILL_ACTIONS) - {"lab-evaluation"}
    assert program_execution.state.turns[-1].proposal.catalog_action_id == "program-finish"


def test_program_catalog_derives_replay_navigation_direct_and_tool_actions_from_observations(
    lab_engagement: Engagement,
) -> None:
    program = lab_engagement.model_copy(
        update={
            "selected_mode": EngagementMode.PROGRAM,
            "testing_accounts_secret_refs": {
                "alice": "env://BUDOBUGS_TEST_ALICE",
                "bob": "env://BUDOBUGS_TEST_BOB",
            },
        }
    )
    state = AgentLoopState(
        loop_id="agent-loop-program-catalog",
        run_id="run-program-catalog",
        engagement_id=program.engagement_id,
        observations=[
            Observation(
                observation_id="observation-program-catalog",
                proposal_id="proposal-program-catalog",
                round_index=1,
                status=ObservationStatus.EXECUTED,
                summary="scoped browser and proxy history captured",
                discovered_urls=[
                    "http://127.0.0.1:8765/app/orders?session=must-not-enter-catalog",
                    "https://outside.example/path",
                    "http://127.0.0.1:8765/logout",
                ],
                details={
                    "replayable_exchanges": [
                        {"exchange_id": "exchange-safe-get", "method": "GET", "account_alias": "alice"},
                        {"exchange_id": "exchange-unsafe-post", "method": "POST", "account_alias": "alice"},
                    ]
                },
            )
        ],
    )
    catalog = ActionCatalogBuilder(program)
    recon = catalog.actions(AgentRole.RECON_RESEARCHER, 2, state)
    browser = catalog.actions(AgentRole.BROWSER_EXPLORER, 2, state)
    authorization = catalog.actions(AgentRole.AUTHORIZATION_SPECIALIST, 2, state)
    api = catalog.actions(AgentRole.API_AUTH_SPECIALIST, 2, state)

    assert [(item.kind, item.skill_name) for item in recon] == [(ActionKind.PROXY_SEARCH, "passive-recon")]
    state.executed_catalog_actions.append(recon[0].catalog_action_id)
    tool_actions = catalog.actions(AgentRole.RECON_RESEARCHER, 2, state)
    assert [(item.kind, item.skill_name) for item in tool_actions] == [(ActionKind.TOOL_TASK, "tool-operator")]
    assert {item.kind for item in browser} == {ActionKind.BROWSER_NAVIGATE}
    assert browser[0].target_url == "http://127.0.0.1:8765/app/orders"
    assert {item.kind for item in authorization} == {ActionKind.PROXY_REPLAY}
    replay = next(item for item in authorization if item.kind is ActionKind.PROXY_REPLAY)
    assert replay.base_exchange_id == "exchange-safe-get"
    assert replay.method == "GET"
    assert {item.kind for item in api} == {ActionKind.HTTP_REQUEST}
    assert next(item for item in api if item.kind is ActionKind.HTTP_REQUEST).target_url == browser[0].target_url

    state.blocked_catalog_actions.append(replay.catalog_action_id)
    assert all(
        item.base_exchange_id != "exchange-safe-get"
        for item in catalog.actions(AgentRole.AUTHORIZATION_SPECIALIST, 3, state)
    )


@pytest.mark.asyncio
async def test_policy_and_codex_providers_select_only_catalog_actions_and_resume_threads(
    service, tmp_path: Path
) -> None:
    action = _action()
    state = AgentLoopState(loop_id="loop-provider", run_id="run-provider", engagement_id="eng-provider")
    selected, invocation = await PolicyProposalProvider().propose(
        role=AgentRole.COORDINATOR,
        skill_instruction="reviewed",
        skill_workflow="observe then plan",
        candidates=[action],
        state=state,
    )
    assert selected.catalog_action_id == action.catalog_action_id
    assert invocation.provider == "policy"
    with pytest.raises(RuntimeError, match="no safe catalog"):
        await PolicyProposalProvider().propose(
            role=AgentRole.COORDINATOR,
            skill_instruction="reviewed",
            skill_workflow="workflow",
            candidates=[],
            state=state,
        )

    calls: list[list[str]] = []

    class Process:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            payload = json.dumps(
                _complete_codex_choice(
                    action,
                    rationale="highest safe information gain",
                    expected_information_gain=0.72,
                    follow_up="execute and inspect the typed observation",
                )
            )
            usage = [(9000, 500, 1000), (12000, 700, 1300), (15000, 1000, 1700)][len(calls) - 1]
            events = [
                {"type": "thread.started", "thread_id": "thread-provider-001"},
                {
                    "item": {"type": "agent_message", "text": payload},
                    "usage": {
                        "input_tokens": usage[0],
                        "output_tokens": usage[1],
                        "cached_input_tokens": usage[2],
                    },
                },
            ]
            return ("\n".join(json.dumps(item) for item in events).encode(), b"")

    async def create_subprocess_exec(*arguments: str, **_kwargs: object) -> Process:
        calls.append(list(arguments))
        return Process()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("budobugs.agents.runner.asyncio.create_subprocess_exec", create_subprocess_exec)
    try:
        runner = CodexTaskRunner(tmp_path, executable="codex-fixture", working_directory=tmp_path)
        router = ModelRouter(
            {
                "profiles": {
                    "quality-first": {
                        "analysis": ["gpt-test"],
                        "critical_judgment": ["gpt-test"],
                        "phase_token_budget": 5000,
                    }
                },
                "reasoning": {"analysis": "high"},
            }
        )
        provider = CodexProposalProvider(
            service=service,
            router=router,
            runner=runner,
            profile="quality-first",
            run_id=state.run_id,
            engagement_token_budget=20000,
        )
        proposal, first = await provider.propose(
            role=AgentRole.COORDINATOR,
            skill_instruction="reviewed contract",
            skill_workflow="observe, plan, execute",
            candidates=[action],
            state=state,
        )
        assert proposal.rationale == "highest safe information gain"
        assert first.thread_id == "thread-provider-001"
        assert "--output-schema" in calls[0]
        state.role_thread_ids[AgentRole.COORDINATOR.value] = first.thread_id or ""
        state.turns.append(
            AgentTurnReceipt(
                turn_id="turn-provider-first",
                round_index=1,
                proposal=proposal,
                invocation=first,
                observation=Observation(
                    observation_id="observation-provider-first",
                    proposal_id=proposal.proposal_id,
                    round_index=1,
                    status=ObservationStatus.EXECUTED,
                    summary="first cumulative Codex usage",
                ),
            )
        )
        _, resumed = await provider.propose(
            role=AgentRole.COORDINATOR,
            skill_instruction="reviewed contract",
            skill_workflow="observe, plan, execute",
            candidates=[action],
            state=state,
        )
        assert resumed.resumed_thread
        assert calls[1][1:3] == ["exec", "resume"]
        state.turns.append(
            AgentTurnReceipt(
                turn_id="turn-provider-resumed",
                round_index=1,
                proposal=proposal,
                invocation=resumed,
                observation=Observation(
                    observation_id="observation-provider-resumed",
                    proposal_id=proposal.proposal_id,
                    round_index=1,
                    status=ObservationStatus.EXECUTED,
                    summary="second cumulative Codex usage",
                ),
            )
        )
        _, resumed_again = await provider.propose(
            role=AgentRole.COORDINATOR,
            skill_instruction="reviewed contract",
            skill_workflow="observe, plan, execute",
            candidates=[action],
            state=state,
        )
        assert resumed_again.resumed_thread
        assert len(calls) == 3  # Naively summing 9,500 + 12,700 would wrongly exhaust 20,000.
        assert (first.input_tokens, first.output_tokens, first.cached_input_tokens) == (9000, 500, 1000)
        assert (resumed.input_tokens, resumed.output_tokens, resumed.cached_input_tokens) == (12000, 700, 1300)
        assert (resumed_again.input_tokens, resumed_again.output_tokens, resumed_again.cached_input_tokens) == (
            15000,
            1000,
            1700,
        )
        costs = service.list_costs(run_id=state.run_id)
        assert sorted((item.input_tokens, item.output_tokens, item.cached_input_tokens) for item in costs) == [
            (3000, 200, 300),
            (3000, 300, 400),
            (9000, 500, 1000),
        ]
    finally:
        monkeypatch.undo()


@pytest.mark.asyncio
async def test_codex_threads_rotate_after_cumulative_context_limit_without_resetting_budget(service) -> None:
    action = _action(role=AgentRole.BROWSER_EXPLORER, skill="browser-explorer")

    class Runner:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str | None]] = []
            self.responses = [
                ("thread-specialist-old", 199_000, 999),
                ("thread-specialist-old", 199_000, 1_000),
                ("thread-specialist-new", 300, 10),
                ("thread-coordinator-old", 199_000, 1_000),
                ("thread-coordinator-new", 400, 20),
            ]

        async def run(self, _selection: object, **kwargs: object) -> tuple[AgentResult, CostRecord]:
            role = str(kwargs["agent_role"])
            thread_id = kwargs["thread_id"]
            assert thread_id is None or isinstance(thread_id, str)
            self.calls.append((role, thread_id))
            resolved_thread, input_tokens, output_tokens = self.responses[len(self.calls) - 1]
            if role == AgentRole.COORDINATOR.value:
                output = json.dumps(
                    {
                        "selected_role": AgentRole.BROWSER_EXPLORER.value,
                        "rationale": "the browser role has the open evidence gap",
                        "expected_information_gain": 0.7,
                        "follow_up": "select one typed browser action",
                    }
                )
            else:
                output = json.dumps(
                    _complete_codex_choice(
                        action,
                        rationale="the only bounded action closes the gap",
                        expected_information_gain=0.7,
                        follow_up="execute the typed action",
                    )
                )
            result = AgentResult(
                model="gpt-test",
                output=output,
                thread_id=resolved_thread,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cached_input_tokens=0,
                events_path=f"events-{len(self.calls)}.json",
            )
            return result, CostRecord(
                cost_id=f"cost-{len(self.calls)}",
                run_id=str(kwargs["run_id"]),
                phase=PhaseName.NORMAL_BROWSER_EXPLORATION,
                model="gpt-test",
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cached_input_tokens=0,
                elapsed_ms=0,
            )

    router = ModelRouter(
        {
            "profiles": {"quality-first": {"analysis": ["gpt-test"], "phase_token_budget": 500_000}},
            "reasoning": {"analysis": "high"},
        }
    )
    state = AgentLoopState(
        loop_id="loop-thread-rotation", run_id="run-thread-rotation", engagement_id="eng-thread-rotation"
    )
    runner = Runner()
    provider = CodexProposalProvider(
        service=service,
        router=router,
        runner=runner,  # type: ignore[arg-type]
        profile="quality-first",
        run_id=state.run_id,
        engagement_token_budget=500_000,
    )

    _, initial = await provider.propose(
        role=AgentRole.BROWSER_EXPLORER,
        skill_instruction="reviewed contract",
        skill_workflow="observe then plan",
        candidates=[action],
        state=state,
    )
    state.role_thread_ids[AgentRole.BROWSER_EXPLORER.value] = initial.thread_id or ""
    _, final_old_thread_turn = await provider.propose(
        role=AgentRole.BROWSER_EXPLORER,
        skill_instruction="reviewed contract",
        skill_workflow="observe then plan",
        candidates=[action],
        state=state,
    )
    assert final_old_thread_turn.resumed_thread
    assert runner.calls[1] == (AgentRole.BROWSER_EXPLORER.value, "thread-specialist-old")

    _, rotated_specialist = await provider.propose(
        role=AgentRole.BROWSER_EXPLORER,
        skill_instruction="reviewed contract",
        skill_workflow="observe then plan",
        candidates=[action],
        state=state,
    )
    assert not rotated_specialist.resumed_thread
    assert runner.calls[2] == (AgentRole.BROWSER_EXPLORER.value, None)
    state.role_thread_ids[AgentRole.BROWSER_EXPLORER.value] = rotated_specialist.thread_id or ""

    _, _, _, initial_route = await provider.route(
        candidates_by_role={AgentRole.BROWSER_EXPLORER: [action]},
        state=state,
        skill_instruction="reviewed coordinator contract",
        skill_workflow="route a live safe role",
    )
    assert initial_route.thread_id == "thread-coordinator-old"
    state.role_thread_ids[AgentRole.COORDINATOR.value] = initial_route.thread_id or ""
    _, _, _, rotated_route = await provider.route(
        candidates_by_role={AgentRole.BROWSER_EXPLORER: [action]},
        state=state,
        skill_instruction="reviewed coordinator contract",
        skill_workflow="route a live safe role",
    )
    assert runner.calls[3] == (AgentRole.COORDINATOR.value, None)
    assert runner.calls[4] == (AgentRole.COORDINATOR.value, None)
    assert rotated_route.thread_id == "thread-coordinator-new"
    assert not rotated_route.resumed_thread
    state.role_thread_ids[AgentRole.COORDINATOR.value] = rotated_route.thread_id or ""

    ledger = provider._load_ledger(state)
    assert [entry.thread_id for entry in ledger.entries] == [
        "thread-specialist-old",
        "thread-specialist-old",
        "thread-specialist-new",
        "thread-coordinator-old",
        "thread-coordinator-new",
    ]
    assert CodexProposalProvider._engagement_used_tokens(ledger) == 400_730
    costs = service.list_costs(run_id=state.run_id)
    assert len(costs) == 5
    assert sum(cost.input_tokens + cost.output_tokens for cost in costs) == 400_730


@pytest.mark.asyncio
async def test_codex_thread_identity_is_scoped_to_role_and_skill_not_role_alone(service) -> None:
    """A coordinator route cannot donate its context to a different coordinator Skill."""

    intake = _action(
        action_id="coordinator-engagement-intake",
        role=AgentRole.COORDINATOR,
        skill="engagement-intake",
    )
    source_review = _action(
        action_id="coordinator-source-review",
        role=AgentRole.COORDINATOR,
        skill="source-secret-supply-chain",
    )

    class Runner:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str, str | None]] = []
            self.responses = [
                ("thread-route", 100, 10),
                ("thread-intake", 100, 10),
                ("thread-intake", 150, 15),
                ("thread-source-review", 100, 10),
            ]

        async def run(self, _selection: object, **kwargs: object) -> tuple[AgentResult, CostRecord]:
            role = kwargs["agent_role"]
            skill_name = kwargs["skill_name"]
            thread_id = kwargs["thread_id"]
            assert isinstance(role, str)
            assert isinstance(skill_name, str)
            assert thread_id is None or isinstance(thread_id, str)
            self.calls.append((role, skill_name, thread_id))
            resolved_thread, input_tokens, output_tokens = self.responses[len(self.calls) - 1]
            if len(self.calls) == 1:
                output = json.dumps(
                    {
                        "selected_role": AgentRole.COORDINATOR.value,
                        "rationale": "the engagement-intake action is the only live evidence gap",
                        "expected_information_gain": 0.7,
                        "follow_up": "ask the intake specialist for its bounded action",
                    }
                )
            else:
                action = intake if skill_name == intake.skill_name else source_review
                output = json.dumps(
                    _complete_codex_choice(
                        action,
                        rationale="the catalog action closes the next bounded evidence gap",
                        expected_information_gain=0.7,
                        follow_up="execute and persist the typed observation",
                    )
                )
            return (
                AgentResult(
                    model="gpt-test",
                    output=output,
                    thread_id=resolved_thread,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    cached_input_tokens=0,
                    events_path=f"events-role-skill-{len(self.calls)}.json",
                ),
                CostRecord(
                    cost_id=f"cost-role-skill-{len(self.calls)}",
                    run_id=str(kwargs["run_id"]),
                    phase=PhaseName.NORMAL_BROWSER_EXPLORATION,
                    model="gpt-test",
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    cached_input_tokens=0,
                    elapsed_ms=0,
                ),
            )

    router = ModelRouter(
        {
            "profiles": {"quality-first": {"analysis": ["gpt-test"], "phase_token_budget": 5000}},
            "reasoning": {"analysis": "high"},
        }
    )
    state = AgentLoopState(
        loop_id="loop-role-skill-thread",
        run_id="run-role-skill-thread",
        engagement_id="eng-role-skill-thread",
    )
    runner = Runner()
    provider = CodexProposalProvider(
        service=service,
        router=router,
        runner=runner,  # type: ignore[arg-type]
        profile="quality-first",
        run_id=state.run_id,
        engagement_token_budget=2_000,
    )
    legacy_state = AgentLoopState(
        loop_id="loop-role-skill-legacy",
        run_id=state.run_id,
        engagement_id=state.engagement_id,
        role_thread_ids={AgentRole.COORDINATOR.value: "thread-legacy-role-only"},
    )
    # Pre-ledger snapshots did not carry skill identity, so they retain the
    # old recovery behavior.  Once the controller ledger exists below, it wins.
    assert (
        provider._thread_for_next_invocation(
            legacy_state,
            provider._load_ledger(legacy_state),
            AgentRole.COORDINATOR,
            intake.skill_name,
        )
        == "thread-legacy-role-only"
    )

    _, _, _, route = await provider.route(
        candidates_by_role={AgentRole.COORDINATOR: [intake]},
        state=state,
        skill_instruction="reviewed controller contract",
        skill_workflow="route a live safe role",
    )
    state.role_thread_ids[AgentRole.COORDINATOR.value] = route.thread_id or ""
    _, first_intake = await provider.propose(
        role=AgentRole.COORDINATOR,
        skill_instruction="reviewed intake contract",
        skill_workflow="observe then plan",
        candidates=[intake],
        state=state,
    )
    state.role_thread_ids[AgentRole.COORDINATOR.value] = first_intake.thread_id or ""
    _, resumed_intake = await provider.propose(
        role=AgentRole.COORDINATOR,
        skill_instruction="reviewed intake contract",
        skill_workflow="observe then plan",
        candidates=[intake],
        state=state,
    )
    _, source = await provider.propose(
        role=AgentRole.COORDINATOR,
        skill_instruction="reviewed source-review contract",
        skill_workflow="observe then plan",
        candidates=[source_review],
        state=state,
    )

    assert runner.calls == [
        (AgentRole.COORDINATOR.value, "budobugs-controller", None),
        (AgentRole.COORDINATOR.value, intake.skill_name, None),
        (AgentRole.COORDINATOR.value, intake.skill_name, "thread-intake"),
        (AgentRole.COORDINATOR.value, source_review.skill_name, None),
    ]
    assert not first_intake.resumed_thread
    assert resumed_intake.resumed_thread
    assert not source.resumed_thread
    ledger = provider._load_ledger(state)
    assert CodexProposalProvider._engagement_used_tokens(ledger) == 385


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid_payload",
    [
        "not JSON",
        json.dumps(
            {
                "catalog_action_id": "not-in-the-catalog",
                "rationale": "this must be rejected",
                "expected_information_gain": 0.5,
                "follow_up": "do not execute this",
            }
        ),
        json.dumps(
            {
                "proposal": _action().model_dump(mode="json"),
                "follow_up": "legacy nested proposal must be rejected",
            }
        ),
    ],
    ids=["invalid-json", "legacy-id-only", "legacy-nested"],
)
async def test_codex_invalid_selection_persists_usage_and_resumes_same_thread(
    service, lab_engagement: Engagement, tmp_path: Path, invalid_payload: str
) -> None:
    action = _action(action_id="only-safe-action")
    calls: list[list[str]] = []
    payloads = [
        json.dumps(
            {
                "selected_role": AgentRole.COORDINATOR.value,
                "rationale": "route to the only role with a safe catalog action",
                "expected_information_gain": 0.7,
                "follow_up": "ask the specialist to select the bounded action",
            }
        ),
        invalid_payload,
        json.dumps(
            _complete_codex_choice(
                action,
                rationale="recover with the only safe typed action",
                expected_information_gain=0.7,
                follow_up="execute the bounded action",
            )
        ),
    ]

    class Process:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            usage = [(400, 50, 20), (900, 100, 50), (1200, 150, 70)][len(calls) - 1]
            events = [
                {"type": "thread.started", "thread_id": "thread-invalid-selection"},
                {
                    "item": {"type": "agent_message", "text": payloads[len(calls) - 1]},
                    "usage": {
                        "input_tokens": usage[0],
                        "output_tokens": usage[1],
                        "cached_input_tokens": usage[2],
                    },
                },
            ]
            return ("\n".join(json.dumps(item) for item in events).encode(), b"")

    async def create_subprocess_exec(*arguments: str, **_kwargs: object) -> Process:
        calls.append(list(arguments))
        return Process()

    class Contract:
        instruction = "reviewed contract"
        workflow = "observe, plan, execute"

    class Executor:
        safe_experiments: list[object] = []
        validator_results: list[object] = []
        exchanges: list[object] = []
        browser_artifacts: list[str] = []
        root_cause_clusters: list[object] = []
        close_calls = 0

        def __init__(self) -> None:
            self.executed: list[ActionProposal] = []

        class skill_runtime:
            @staticmethod
            def load(_skill_name: str) -> Contract:
                return Contract()

        class proxy:
            selected = "direct"

        async def close_browser(self) -> None:
            self.close_calls += 1

        async def execute(self, proposal: ActionProposal) -> Observation:
            self.executed.append(proposal)
            return Observation(
                observation_id=new_id("observation"),
                proposal_id=proposal.proposal_id,
                round_index=proposal.round_index,
                status=ObservationStatus.EXECUTED,
                summary="typed executor received only the catalog action",
                information_gain=0.7,
            )

    class Catalog:
        @staticmethod
        def schedule(round_index: int) -> list[AgentRole]:
            return [AgentRole.COORDINATOR] if round_index == 1 else []

        @staticmethod
        def actions(_role: AgentRole, _round_index: int, state: AgentLoopState) -> list[ActionProposal]:
            return [] if state.executed_catalog_actions else [action]

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("budobugs.agents.runner.asyncio.create_subprocess_exec", create_subprocess_exec)
    try:
        runner = CodexTaskRunner(tmp_path, executable="codex-fixture", working_directory=tmp_path)
        router = ModelRouter(
            {
                "profiles": {"quality-first": {"analysis": ["gpt-test"], "phase_token_budget": 5000}},
                "reasoning": {"analysis": "high"},
            }
        )
        provider = CodexProposalProvider(
            service=service,
            router=router,
            runner=runner,
            profile="quality-first",
            run_id="run-invalid-selection",
            engagement_token_budget=2000,
        )
        executor = Executor()
        orchestrator = AgentOrchestrator(
            engagement=lab_engagement,
            run_id="run-invalid-selection",
            artifact_root=tmp_path,
            executor=executor,  # type: ignore[arg-type]
            provider=provider,
            max_rounds=2,
        )
        orchestrator.catalog = Catalog()  # type: ignore[assignment]

        with pytest.raises(RuntimeError, match="invalid typed action|outside the safe catalog"):
            await orchestrator.run(resume=False)

        failed_receipt = json.loads(orchestrator.receipt_path.read_text(encoding="utf-8"))
        ledger_path = (
            service.paths.runs / "run-invalid-selection" / "artifacts" / "agent-loop" / "invocation-ledger.json"
        )
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
        assert failed_receipt["executed_turn_count"] == 0
        assert failed_receipt["turn_count"] == 0
        assert ledger["run_id"] == "run-invalid-selection"
        assert ledger["engagement_id"] == lab_engagement.engagement_id
        assert ledger["entries"][-1]["status"] == "INVALID_OUTPUT"
        assert ledger["entries"][-1]["thread_id"] == "thread-invalid-selection"
        assert ledger["entries"][-1]["input_tokens"] == 900
        assert failed_receipt["coordinator_route_count"] == 1

        completed = await orchestrator.run(resume=True)
        assert completed.state.status is AgentLoopStatus.COMPLETED
        assert completed.state.role_thread_ids[AgentRole.COORDINATOR.value] == "thread-invalid-selection"
        assert calls[1][1:3] == ["exec", "resume"]
        assert calls[2][1:3] == ["exec", "resume"]
        assert CodexProposalProvider._engagement_used_tokens(completed.state) == 1350
        assert len(completed.state.turns) == 1
        assert completed.state.turns[0].invocation.input_tokens == 1200
        persisted = completed.state.turns[0].proposal
        assert persisted.model_dump(
            mode="json", exclude={"rationale", "expected_information_gain"}
        ) == action.model_dump(mode="json", exclude={"rationale", "expected_information_gain"})
        assert persisted.rationale == "recover with the only safe typed action"
        assert executor.executed == [persisted]
        costs = service.list_costs(run_id="run-invalid-selection")
        assert sorted((item.input_tokens, item.output_tokens, item.cached_input_tokens) for item in costs) == [
            (300, 50, 20),
            (400, 50, 20),
            (500, 50, 30),
        ]
    finally:
        monkeypatch.undo()


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["target_url", "body", "tool_arguments"])
async def test_codex_rejects_policy_critical_proposal_changes_before_executor(
    boundary: str,
    service,
    lab_engagement: Engagement,
    tmp_path: Path,
) -> None:
    """A schema-valid full response cannot change any catalog execution capability."""

    if boundary == "tool_arguments":
        action = ActionProposal(
            proposal_id=new_id("proposal"),
            catalog_action_id="only-safe-tool",
            round_index=1,
            agent_role=AgentRole.BROWSER_EXPLORER,
            skill_name="browser-explorer",
            kind=ActionKind.TOOL_TASK,
            objective="inspect a bounded fixture artifact",
            tool_name="fixture-inspector",
            tool_arguments={"scope": "known-safe"},
            expected_observation="one bounded tool receipt",
        )
    else:
        action = ActionProposal(
            proposal_id=new_id("proposal"),
            catalog_action_id="only-safe-http",
            round_index=1,
            agent_role=AgentRole.BROWSER_EXPLORER,
            skill_name="browser-explorer",
            kind=ActionKind.HTTP_REQUEST,
            objective="read one owned fixture object",
            target_url="http://127.0.0.1:8765/api/objects/owned",
            method="GET",
            body={"object_id": "owned"},
            expected_observation="one bounded HTTP observation",
        )
    choice = _complete_codex_choice(
        action,
        rationale="the bounded action closes the current evidence gap",
        expected_information_gain=0.7,
        follow_up="record the typed observation",
    )
    proposal_json = choice["proposal_json"]
    assert isinstance(proposal_json, str)
    proposal = json.loads(proposal_json)
    if boundary == "target_url":
        proposal["target_url"] = "http://127.0.0.1:8765/api/objects/outside-catalog"
    elif boundary == "body":
        proposal["body"] = {"object_id": "outside-catalog"}
    else:
        proposal["tool_arguments"] = {"scope": "outside-catalog"}
    choice["proposal_json"] = json.dumps(proposal, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    class Runner:
        async def run(self, _selection: object, **kwargs: object) -> tuple[AgentResult, CostRecord]:
            role = kwargs["agent_role"]
            if role == AgentRole.COORDINATOR.value:
                output = json.dumps(
                    {
                        "selected_role": action.agent_role.value,
                        "rationale": "route the only available specialist",
                        "expected_information_gain": 0.7,
                        "follow_up": "select its bounded typed action",
                    }
                )
            else:
                output = json.dumps(choice)
            return (
                AgentResult(
                    model="gpt-test",
                    output=output,
                    thread_id="thread-policy-boundary",
                    input_tokens=100,
                    output_tokens=20,
                    cached_input_tokens=0,
                    events_path="events-policy-boundary.json",
                ),
                CostRecord(
                    cost_id=new_id("cost"),
                    run_id=str(kwargs["run_id"]),
                    phase=PhaseName.NORMAL_BROWSER_EXPLORATION,
                    model="gpt-test",
                    input_tokens=100,
                    output_tokens=20,
                    elapsed_ms=0,
                ),
            )

    class Contract:
        instruction = "reviewed contract"
        workflow = "observe, plan, execute"

    class Executor:
        safe_experiments: list[object] = []
        validator_results: list[object] = []
        exchanges: list[object] = []
        browser_artifacts: list[str] = []
        root_cause_clusters: list[object] = []

        class skill_runtime:
            @staticmethod
            def load(_skill_name: str) -> Contract:
                return Contract()

        class proxy:
            selected = "direct"

        def __init__(self) -> None:
            self.executed: list[ActionProposal] = []

        async def close_browser(self) -> None:
            return None

        async def execute(self, proposal: ActionProposal) -> Observation:
            self.executed.append(proposal)
            raise AssertionError("an out-of-catalog proposal must never reach the executor")

    class Catalog:
        @staticmethod
        def schedule(round_index: int) -> list[AgentRole]:
            return [action.agent_role] if round_index == 1 else []

        @staticmethod
        def actions(_role: AgentRole, _round_index: int, state: AgentLoopState) -> list[ActionProposal]:
            return [] if state.executed_catalog_actions else [action]

    router = ModelRouter(
        {
            "profiles": {"quality-first": {"analysis": ["gpt-test"], "phase_token_budget": 5000}},
            "reasoning": {"analysis": "high"},
        }
    )
    provider = CodexProposalProvider(
        service=service,
        router=router,
        runner=Runner(),  # type: ignore[arg-type]
        profile="quality-first",
        run_id=f"run-policy-boundary-{boundary}",
        engagement_token_budget=2000,
    )
    executor = Executor()
    orchestrator = AgentOrchestrator(
        engagement=lab_engagement,
        run_id=f"run-policy-boundary-{boundary}",
        artifact_root=tmp_path / boundary,
        executor=executor,  # type: ignore[arg-type]
        provider=provider,
        max_rounds=1,
    )
    orchestrator.catalog = Catalog()  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="policy-critical fields"):
        await orchestrator.run(resume=False)

    ledger_path = (
        service.paths.runs / f"run-policy-boundary-{boundary}" / "artifacts" / "agent-loop" / "invocation-ledger.json"
    )
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert ledger["entries"][-1]["status"] == "INVALID_OUTPUT"
    assert executor.executed == []


def test_codex_engagement_usage_uses_thread_maxima_and_threadless_calls() -> None:
    action = _action()

    def turn(invocation_id: str, thread_id: str | None, input_tokens: int, output_tokens: int) -> AgentTurnReceipt:
        return AgentTurnReceipt(
            turn_id=invocation_id,
            round_index=1,
            proposal=action,
            invocation=AgentInvocation(
                invocation_id=invocation_id,
                role=AgentRole.COORDINATOR,
                skill_name=action.skill_name,
                provider="codex",
                model="gpt-test",
                thread_id=thread_id,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                status="PASS",
            ),
            observation=Observation(
                observation_id=f"observation-{invocation_id}",
                proposal_id=action.proposal_id,
                round_index=1,
                status=ObservationStatus.EXECUTED,
                summary="persisted Codex invocation",
            ),
        )

    state = AgentLoopState(
        loop_id="loop-cumulative-budget",
        run_id="run-cumulative-budget",
        engagement_id="eng-cumulative-budget",
        turns=[
            turn("invocation-alpha-first", "thread-alpha", 900, 100),
            turn("invocation-alpha-resumed", "thread-alpha", 1200, 150),
            turn("invocation-beta", "thread-beta", 400, 40),
            turn("invocation-threadless", None, 50, 5),
        ],
    )

    assert CodexProposalProvider._engagement_used_tokens(state) == 1845


@pytest.mark.asyncio
async def test_agent_loop_persists_provider_failure_and_resumes_the_same_chain(
    lab_engagement: Engagement, tmp_path: Path
) -> None:
    action = _action(action_id="resume-after-provider-failure")

    class Contract:
        instruction = "reviewed contract"
        workflow = "observe, plan, execute"

    class Executor:
        safe_experiments: list[object] = []
        validator_results: list[object] = []
        exchanges: list[object] = []
        browser_artifacts: list[str] = []
        root_cause_clusters: list[object] = []
        close_calls = 0

        class skill_runtime:
            @staticmethod
            def load(_skill_name: str) -> Contract:
                return Contract()

        class proxy:
            selected = "direct"

        async def close_browser(self) -> None:
            self.close_calls += 1

        async def execute(self, proposal: ActionProposal) -> Observation:
            return Observation(
                observation_id=new_id("observation"),
                proposal_id=proposal.proposal_id,
                round_index=proposal.round_index,
                status=ObservationStatus.EXECUTED,
                summary="typed executor completed the recovered action",
                information_gain=0.7,
            )

    class Catalog:
        @staticmethod
        def schedule(round_index: int) -> list[AgentRole]:
            return [AgentRole.COORDINATOR] if round_index == 1 else []

        @staticmethod
        def actions(_role: AgentRole, _round_index: int, state: AgentLoopState) -> list[ActionProposal]:
            return [] if state.executed_catalog_actions else [action]

    class Provider:
        calls = 0

        async def propose(self, **kwargs: object) -> tuple[ActionProposal, AgentInvocation]:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("engagement agent token budget exhausted: Bearer secret-token-value")
            candidates = kwargs["candidates"]
            assert isinstance(candidates, list)
            selected = candidates[0]
            assert isinstance(selected, ActionProposal)
            return selected, AgentInvocation(
                invocation_id=new_id("agent-invocation"),
                role=selected.agent_role,
                skill_name=selected.skill_name,
                provider="policy",
                model="fixture-policy",
                status="PASS",
            )

    executor = Executor()
    provider = Provider()
    orchestrator = AgentOrchestrator(
        engagement=lab_engagement,
        run_id="run-provider-failure-resume",
        artifact_root=tmp_path,
        executor=executor,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]
        max_rounds=2,
    )
    orchestrator.catalog = Catalog()  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="token budget exhausted"):
        await orchestrator.run(resume=False)

    persisted = AgentLoopState.model_validate_json(orchestrator.state_path.read_text(encoding="utf-8"))
    receipt = json.loads(orchestrator.receipt_path.read_text(encoding="utf-8"))
    assert persisted.status is AgentLoopStatus.BUDGET_EXHAUSTED
    assert receipt["status"] == AgentLoopStatus.BUDGET_EXHAUSTED.value
    assert "secret-token-value" not in (persisted.stop_reason or "")
    assert "REDACTED" in (persisted.stop_reason or "")
    assert executor.close_calls == 1

    completed = await orchestrator.run(resume=True)
    final_receipt = json.loads(orchestrator.receipt_path.read_text(encoding="utf-8"))
    assert completed.state.loop_id == persisted.loop_id
    assert completed.state.status is AgentLoopStatus.COMPLETED
    assert completed.state.resume_count == 1
    assert len(completed.state.turns) == 1
    assert final_receipt["status"] == AgentLoopStatus.COMPLETED.value
    assert executor.close_calls == 2


@pytest.mark.asyncio
async def test_agent_loop_retries_a_durable_failed_typed_action_on_resume(
    lab_engagement: Engagement, tmp_path: Path
) -> None:
    action = _action(action_id="retry-durable-failed-action")

    class Contract:
        instruction = "reviewed contract"
        workflow = "observe, plan, execute"

    class Executor:
        safe_experiments: list[object] = []
        validator_results: list[object] = []
        exchanges: list[object] = []
        browser_artifacts: list[str] = []
        root_cause_clusters: list[object] = []
        calls = 0

        class skill_runtime:
            @staticmethod
            def load(_skill_name: str) -> Contract:
                return Contract()

        class proxy:
            selected = "direct"

        async def close_browser(self) -> None:
            return None

        async def execute(self, proposal: ActionProposal) -> Observation:
            self.calls += 1
            status = ObservationStatus.FAILED if self.calls == 1 else ObservationStatus.EXECUTED
            return Observation(
                observation_id=new_id("observation"),
                proposal_id=proposal.proposal_id,
                round_index=proposal.round_index,
                status=status,
                summary="transient driver failure" if self.calls == 1 else "retry completed",
                information_gain=0 if self.calls == 1 else 0.7,
            )

    class Catalog:
        @staticmethod
        def schedule(round_index: int) -> list[AgentRole]:
            return [AgentRole.COORDINATOR] if round_index == 1 else []

        @staticmethod
        def actions(_role: AgentRole, _round_index: int, state: AgentLoopState) -> list[ActionProposal]:
            return [] if action.catalog_action_id in state.executed_catalog_actions else [action]

    class Provider:
        async def propose(self, **kwargs: object) -> tuple[ActionProposal, AgentInvocation]:
            candidates = kwargs["candidates"]
            assert isinstance(candidates, list)
            selected = candidates[0]
            assert isinstance(selected, ActionProposal)
            return selected, AgentInvocation(
                invocation_id=new_id("agent-invocation"),
                role=selected.agent_role,
                skill_name=selected.skill_name,
                provider="policy",
                model="fixture-policy",
                status="PASS",
            )

    executor = Executor()
    orchestrator = AgentOrchestrator(
        engagement=lab_engagement,
        run_id="run-typed-failure-resume",
        artifact_root=tmp_path,
        executor=executor,  # type: ignore[arg-type]
        provider=Provider(),  # type: ignore[arg-type]
        max_rounds=2,
    )
    orchestrator.catalog = Catalog()  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="typed action retry-durable-failed-action failed"):
        await orchestrator.run(resume=False)

    failed = AgentLoopState.model_validate_json(orchestrator.state_path.read_text(encoding="utf-8"))
    assert failed.status is AgentLoopStatus.FAILED
    assert len(failed.turns) == 1
    assert failed.turns[0].observation.status is ObservationStatus.FAILED
    assert action.catalog_action_id not in failed.blocked_catalog_actions

    completed = await orchestrator.run(resume=True)
    assert completed.state.loop_id == failed.loop_id
    assert completed.state.status is AgentLoopStatus.COMPLETED
    assert completed.state.resume_count == 1
    assert [turn.observation.status for turn in completed.state.turns] == [
        ObservationStatus.FAILED,
        ObservationStatus.EXECUTED,
    ]
    assert action.catalog_action_id in completed.state.executed_catalog_actions
    assert action.catalog_action_id not in completed.state.blocked_catalog_actions


@pytest.mark.asyncio
async def test_agent_loop_resume_keeps_schedule_cursor_and_does_not_replay_early_roles(
    lab_engagement: Engagement, tmp_path: Path
) -> None:
    first = _action(action_id="cursor-first", role=AgentRole.COORDINATOR)
    second = _action(action_id="cursor-second", role=AgentRole.BROWSER_EXPLORER, skill="browser-explorer")

    class Contract:
        instruction = "reviewed contract"
        workflow = "observe, plan, execute"

    class Executor:
        safe_experiments: list[object] = []
        validator_results: list[object] = []
        exchanges: list[object] = []
        browser_artifacts: list[str] = []
        root_cause_clusters: list[object] = []
        executed: list[str] = []

        class skill_runtime:
            @staticmethod
            def load(_skill_name: str) -> Contract:
                return Contract()

        class proxy:
            selected = "direct"

        async def close_browser(self) -> None:
            return None

        async def execute(self, proposal: ActionProposal) -> Observation:
            self.executed.append(proposal.catalog_action_id)
            return Observation(
                observation_id=new_id("observation"),
                proposal_id=proposal.proposal_id,
                round_index=proposal.round_index,
                status=ObservationStatus.EXECUTED,
                summary="typed executor completed scheduled action",
                information_gain=0.7,
            )

    class Catalog:
        @staticmethod
        def schedule(round_index: int) -> list[AgentRole]:
            return [AgentRole.COORDINATOR, AgentRole.BROWSER_EXPLORER] if round_index == 1 else []

        @staticmethod
        def actions(role: AgentRole, _round_index: int, state: AgentLoopState) -> list[ActionProposal]:
            action = first if role is AgentRole.COORDINATOR else second
            return [] if action.catalog_action_id in state.executed_catalog_actions else [action]

    class Provider:
        calls: list[AgentRole] = []

        async def propose(self, **kwargs: object) -> tuple[ActionProposal, AgentInvocation]:
            role = kwargs["role"]
            candidates = kwargs["candidates"]
            assert isinstance(role, AgentRole)
            assert isinstance(candidates, list)
            selected = candidates[0]
            assert isinstance(selected, ActionProposal)
            self.calls.append(role)
            return selected, AgentInvocation(
                invocation_id=new_id("agent-invocation"),
                role=role,
                skill_name=selected.skill_name,
                provider="policy",
                model="fixture-policy",
                status="PASS",
            )

    executor = Executor()
    provider = Provider()
    orchestrator = AgentOrchestrator(
        engagement=lab_engagement,
        run_id="run-schedule-cursor-resume",
        artifact_root=tmp_path,
        executor=executor,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]
        max_rounds=2,
    )
    orchestrator.catalog = Catalog()  # type: ignore[assignment]

    with pytest.raises(Exception, match="intentionally interrupted"):
        await orchestrator.run(resume=False, max_new_turns=1)

    checkpoint = AgentLoopState.model_validate_json(orchestrator.state_path.read_text(encoding="utf-8"))
    assert checkpoint.current_round == 1
    assert checkpoint.schedule_cursor == 1
    assert provider.calls == [AgentRole.COORDINATOR]

    # A state file produced before cursor support has enough receipt history to
    # recover the pending role without replaying the coordinator.
    legacy_checkpoint = json.loads(orchestrator.state_path.read_text(encoding="utf-8"))
    legacy_checkpoint.pop("schedule_cursor")
    atomic_write_json(orchestrator.state_path, legacy_checkpoint)

    completed = await orchestrator.run(resume=True)
    assert completed.state.status is AgentLoopStatus.COMPLETED
    assert completed.state.resume_count == 1
    assert completed.state.schedule_cursor == 0
    assert provider.calls == [AgentRole.COORDINATOR, AgentRole.BROWSER_EXPLORER]
    assert executor.executed == ["cursor-first", "cursor-second"]


@pytest.mark.asyncio
async def test_policy_coordinator_routes_from_observations_and_live_candidate_availability() -> None:
    provider = PolicyProposalProvider()
    authorization = _action(
        action_id="route-authorization",
        role=AgentRole.AUTHORIZATION_SPECIALIST,
        skill="authorization-specialist",
        gain=0.8,
    )
    browser = _action(
        action_id="route-browser",
        role=AgentRole.BROWSER_EXPLORER,
        skill="browser-explorer",
        gain=0.7,
    )
    available = {
        AgentRole.AUTHORIZATION_SPECIALIST: [authorization],
        AgentRole.BROWSER_EXPLORER: [browser],
    }
    state = AgentLoopState(loop_id="loop-route-policy", run_id="run-route-policy", engagement_id="eng-route-policy")

    first_role, _, _, _ = await provider.route(
        candidates_by_role=available,
        state=state,
        skill_instruction="reviewed coordinator contract",
        skill_workflow="route, observe, update",
    )
    assert first_role is AgentRole.AUTHORIZATION_SPECIALIST

    low_gain = Observation(
        observation_id="observation-low-gain-authorization",
        proposal_id=authorization.proposal_id,
        round_index=1,
        status=ObservationStatus.EXECUTED,
        summary="authorization replay added no new evidence",
        information_gain=0.01,
    )
    state.observations.append(low_gain)
    state.turns.append(
        AgentTurnReceipt(
            turn_id="turn-low-gain-authorization",
            round_index=1,
            proposal=authorization,
            invocation=AgentInvocation(
                invocation_id="invocation-low-gain-authorization",
                role=AgentRole.AUTHORIZATION_SPECIALIST,
                skill_name=authorization.skill_name,
                provider="policy",
                model="fixture-policy",
                status="PASS",
            ),
            observation=low_gain,
        )
    )

    observation_driven_role, _, _, _ = await provider.route(
        candidates_by_role=available,
        state=state,
        skill_instruction="reviewed coordinator contract",
        skill_workflow="route, observe, update",
    )
    assert observation_driven_role is AgentRole.BROWSER_EXPLORER

    availability_driven_role, _, _, _ = await provider.route(
        candidates_by_role={AgentRole.AUTHORIZATION_SPECIALIST: [authorization]},
        state=state,
        skill_instruction="reviewed coordinator contract",
        skill_workflow="route, observe, update",
    )
    assert availability_driven_role is AgentRole.AUTHORIZATION_SPECIALIST


@pytest.mark.asyncio
async def test_dynamic_coordinator_route_is_durable_and_reused_on_resume(
    lab_engagement: Engagement, tmp_path: Path
) -> None:
    action = _action(
        action_id="durable-routed-browser-action",
        role=AgentRole.BROWSER_EXPLORER,
        skill="browser-explorer",
    )

    class Contract:
        instruction = "reviewed contract"
        workflow = "observe, plan, execute"

    class Executor:
        safe_experiments: list[object] = []
        validator_results: list[object] = []
        exchanges: list[object] = []
        browser_artifacts: list[str] = []
        root_cause_clusters: list[object] = []
        executed: list[str] = []

        class skill_runtime:
            @staticmethod
            def load(_skill_name: str) -> Contract:
                return Contract()

        class proxy:
            selected = "direct"

        async def close_browser(self) -> None:
            return None

        async def execute(self, proposal: ActionProposal) -> Observation:
            self.executed.append(proposal.catalog_action_id)
            return Observation(
                observation_id=new_id("observation"),
                proposal_id=proposal.proposal_id,
                round_index=proposal.round_index,
                status=ObservationStatus.EXECUTED,
                summary="typed executor completed the coordinator-routed action",
                information_gain=0.8,
            )

    class Catalog:
        @staticmethod
        def schedule(round_index: int) -> list[AgentRole]:
            return [AgentRole.BROWSER_EXPLORER] if round_index == 1 else []

        @staticmethod
        def actions(role: AgentRole, _round_index: int, state: AgentLoopState) -> list[ActionProposal]:
            if role is not AgentRole.BROWSER_EXPLORER or action.catalog_action_id in state.executed_catalog_actions:
                return []
            return [action]

    class Provider:
        route_calls = 0
        proposal_calls = 0

        async def route(self, **kwargs: object) -> tuple[AgentRole, str, float, AgentInvocation]:
            candidates_by_role = kwargs["candidates_by_role"]
            assert isinstance(candidates_by_role, dict)
            assert set(candidates_by_role) == {AgentRole.BROWSER_EXPLORER}
            self.route_calls += 1
            return (
                AgentRole.BROWSER_EXPLORER,
                "browser exploration is the only live safe route",
                0.8,
                AgentInvocation(
                    invocation_id=new_id("agent-invocation"),
                    role=AgentRole.COORDINATOR,
                    skill_name="budobugs-controller",
                    provider="codex",
                    model="fixture-coordinator",
                    thread_id="thread-durable-route",
                    status="PASS",
                ),
            )

        async def propose(self, **kwargs: object) -> tuple[ActionProposal, AgentInvocation]:
            self.proposal_calls += 1
            if self.proposal_calls == 1:
                raise RuntimeError("specialist transport interrupted after route persistence")
            candidates = kwargs["candidates"]
            assert isinstance(candidates, list)
            selected = candidates[0]
            assert isinstance(selected, ActionProposal)
            return selected, AgentInvocation(
                invocation_id=new_id("agent-invocation"),
                role=AgentRole.BROWSER_EXPLORER,
                skill_name=selected.skill_name,
                provider="codex",
                model="fixture-specialist",
                status="PASS",
            )

    executor = Executor()
    provider = Provider()
    orchestrator = AgentOrchestrator(
        engagement=lab_engagement,
        run_id="run-durable-dynamic-route",
        artifact_root=tmp_path,
        executor=executor,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]
        max_rounds=2,
    )
    orchestrator.catalog = Catalog()  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="specialist transport interrupted"):
        await orchestrator.run(resume=False)

    checkpoint = AgentLoopState.model_validate_json(orchestrator.state_path.read_text(encoding="utf-8"))
    assert len(checkpoint.route_receipts) == 1
    assert checkpoint.route_receipts[0].status == "pending"
    assert checkpoint.route_receipts[0].selected_role is AgentRole.BROWSER_EXPLORER
    assert provider.route_calls == 1
    route_only_receipt = json.loads(orchestrator.receipt_path.read_text(encoding="utf-8"))
    assert route_only_receipt["participating_agents"] == []
    assert route_only_receipt["invoked_skills"] == []

    completed = await orchestrator.run(resume=True)
    assert provider.route_calls == 1
    assert provider.proposal_calls == 2
    assert executor.executed == [action.catalog_action_id]
    assert completed.state.route_receipts[0].status == "completed"
    assert completed.state.route_receipts[0].selected_action_id == action.catalog_action_id
    receipt = json.loads(orchestrator.receipt_path.read_text(encoding="utf-8"))
    assert receipt["dynamic_coordinator_route_count"] == 1
    assert receipt["participating_agents"] == [AgentRole.BROWSER_EXPLORER.value]
    assert receipt["invoked_skills"] == [action.skill_name]
    assert receipt["coordinator_route_summary"][0]["action_count"] == 1
    assert receipt["coordinator_route_summary"][0]["observation_count"] == 1


@pytest.mark.asyncio
async def test_one_durable_role_assignment_executes_three_specialist_actions_with_one_route(
    lab_engagement: Engagement, tmp_path: Path
) -> None:
    actions = [
        _action(
            action_id=f"authorization-assignment-{index}",
            role=AgentRole.AUTHORIZATION_SPECIALIST,
            skill="authorization-specialist",
            gain=0.8,
        )
        for index in range(1, 4)
    ]

    class Contract:
        instruction = "reviewed contract"
        workflow = "observe, plan, execute"

    class Executor:
        safe_experiments: list[object] = []
        validator_results: list[object] = []
        exchanges: list[object] = []
        browser_artifacts: list[str] = []
        root_cause_clusters: list[object] = []

        class skill_runtime:
            @staticmethod
            def load(_skill_name: str) -> Contract:
                return Contract()

        class proxy:
            selected = "direct"

        async def close_browser(self) -> None:
            return None

        async def execute(self, proposal: ActionProposal) -> Observation:
            return Observation(
                observation_id=new_id("observation"),
                proposal_id=proposal.proposal_id,
                round_index=proposal.round_index,
                status=ObservationStatus.EXECUTED,
                summary="authorization specialist closed one evidence gap",
                information_gain=0.8,
            )

    class Catalog:
        @staticmethod
        def schedule(round_index: int) -> list[AgentRole]:
            return [AgentRole.AUTHORIZATION_SPECIALIST] if round_index == 1 else []

        @staticmethod
        def actions(role: AgentRole, _round_index: int, state: AgentLoopState) -> list[ActionProposal]:
            if role is not AgentRole.AUTHORIZATION_SPECIALIST:
                return []
            return [item for item in actions if item.catalog_action_id not in state.executed_catalog_actions]

    class Provider:
        route_calls = 0
        proposal_calls = 0

        async def route(self, **_kwargs: object) -> tuple[AgentRole, str, float, AgentInvocation]:
            self.route_calls += 1
            return (
                AgentRole.AUTHORIZATION_SPECIALIST,
                "continue the bounded authorization evidence assignment",
                0.8,
                AgentInvocation(
                    invocation_id=new_id("agent-invocation"),
                    role=AgentRole.COORDINATOR,
                    skill_name="budobugs-controller",
                    provider="codex",
                    model="fixture-coordinator",
                    thread_id="thread-three-action-route",
                    status="PASS",
                ),
            )

        async def propose(self, **kwargs: object) -> tuple[ActionProposal, AgentInvocation]:
            self.proposal_calls += 1
            candidates = kwargs["candidates"]
            assert isinstance(candidates, list)
            selected = candidates[0]
            assert isinstance(selected, ActionProposal)
            return selected, AgentInvocation(
                invocation_id=new_id("agent-invocation"),
                role=AgentRole.AUTHORIZATION_SPECIALIST,
                skill_name=selected.skill_name,
                provider="codex",
                model="fixture-specialist",
                thread_id="thread-authorization-specialist",
                resumed_thread=self.proposal_calls > 1,
                status="PASS",
            )

    provider = Provider()
    orchestrator = AgentOrchestrator(
        engagement=lab_engagement,
        run_id="run-three-action-role-assignment",
        artifact_root=tmp_path,
        executor=Executor(),  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]
        max_rounds=2,
    )
    orchestrator.catalog = Catalog()  # type: ignore[assignment]

    with pytest.raises(AgentLoopInterrupted):
        await orchestrator.run(resume=False, max_new_turns=1)

    checkpoint = AgentLoopState.model_validate_json(orchestrator.state_path.read_text(encoding="utf-8"))
    assert checkpoint.route_receipts[0].status == "pending"
    assert checkpoint.route_receipts[0].selected_action_ids == [actions[0].catalog_action_id]
    assert provider.route_calls == 1

    execution = await orchestrator.run(resume=True)
    assert provider.route_calls == 1
    assert provider.proposal_calls == 3
    assert [turn.proposal.catalog_action_id for turn in execution.state.turns] == [
        item.catalog_action_id for item in actions
    ]
    route = execution.state.route_receipts[0]
    assert route.status == "completed"
    assert route.selected_action_ids == [item.catalog_action_id for item in actions]
    assert len(route.observation_ids) == 3
    assert route.completion_reason == "selected specialist exhausted its safe catalog candidates"


@pytest.mark.asyncio
async def test_low_gain_observation_completes_assignment_and_forces_coordinator_reroute(
    lab_engagement: Engagement, tmp_path: Path
) -> None:
    authorization = [
        _action(
            action_id=f"low-gain-authorization-{index}",
            role=AgentRole.AUTHORIZATION_SPECIALIST,
            skill="authorization-specialist",
            gain=0.8,
        )
        for index in range(1, 3)
    ]
    browser = _action(
        action_id="post-low-gain-browser",
        role=AgentRole.BROWSER_EXPLORER,
        skill="browser-explorer",
        gain=0.7,
    )

    class Contract:
        instruction = "reviewed contract"
        workflow = "observe, plan, execute"

    class Executor:
        safe_experiments: list[object] = []
        validator_results: list[object] = []
        exchanges: list[object] = []
        browser_artifacts: list[str] = []
        root_cause_clusters: list[object] = []

        class skill_runtime:
            @staticmethod
            def load(_skill_name: str) -> Contract:
                return Contract()

        class proxy:
            selected = "direct"

        async def close_browser(self) -> None:
            return None

        async def execute(self, proposal: ActionProposal) -> Observation:
            low_gain = proposal.agent_role is AgentRole.AUTHORIZATION_SPECIALIST
            return Observation(
                observation_id=new_id("observation"),
                proposal_id=proposal.proposal_id,
                round_index=proposal.round_index,
                status=ObservationStatus.EXECUTED,
                summary="no new authorization evidence" if low_gain else "new browser evidence",
                information_gain=0.01 if low_gain else 0.7,
            )

    class Catalog:
        @staticmethod
        def schedule(round_index: int) -> list[AgentRole]:
            return [AgentRole.AUTHORIZATION_SPECIALIST, AgentRole.BROWSER_EXPLORER] if round_index == 1 else []

        @staticmethod
        def actions(role: AgentRole, _round_index: int, state: AgentLoopState) -> list[ActionProposal]:
            if role is AgentRole.AUTHORIZATION_SPECIALIST:
                return [item for item in authorization if item.catalog_action_id not in state.executed_catalog_actions]
            if role is AgentRole.BROWSER_EXPLORER and browser.catalog_action_id not in state.executed_catalog_actions:
                return [browser]
            return []

    class Provider:
        route_calls = 0

        async def route(self, **_kwargs: object) -> tuple[AgentRole, str, float, AgentInvocation]:
            role = AgentRole.AUTHORIZATION_SPECIALIST if self.route_calls == 0 else AgentRole.BROWSER_EXPLORER
            self.route_calls += 1
            return (
                role,
                "reroute after durable information-gain feedback",
                0.8,
                AgentInvocation(
                    invocation_id=new_id("agent-invocation"),
                    role=AgentRole.COORDINATOR,
                    skill_name="budobugs-controller",
                    provider="codex",
                    model="fixture-coordinator",
                    status="PASS",
                ),
            )

        async def propose(self, **kwargs: object) -> tuple[ActionProposal, AgentInvocation]:
            candidates = kwargs["candidates"]
            role = kwargs["role"]
            assert isinstance(candidates, list)
            assert isinstance(role, AgentRole)
            selected = candidates[0]
            assert isinstance(selected, ActionProposal)
            return selected, AgentInvocation(
                invocation_id=new_id("agent-invocation"),
                role=role,
                skill_name=selected.skill_name,
                provider="codex",
                model="fixture-specialist",
                status="PASS",
            )

    provider = Provider()
    orchestrator = AgentOrchestrator(
        engagement=lab_engagement,
        run_id="run-low-gain-reroute",
        artifact_root=tmp_path,
        executor=Executor(),  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]
        max_rounds=2,
    )
    orchestrator.catalog = Catalog()  # type: ignore[assignment]

    with pytest.raises(AgentLoopInterrupted) as interrupted:
        await orchestrator.run(resume=False, max_new_turns=2)

    state = interrupted.value.execution.state
    assert provider.route_calls == 2
    assert [receipt.selected_role for receipt in state.route_receipts] == [
        AgentRole.AUTHORIZATION_SPECIALIST,
        AgentRole.BROWSER_EXPLORER,
    ]
    assert state.route_receipts[0].status == "completed"
    assert state.route_receipts[0].completion_reason == ("latest observation fell below the information-gain threshold")
    assert state.route_receipts[0].selected_action_ids == [authorization[0].catalog_action_id]


@pytest.mark.asyncio
async def test_proxy_factory_selects_direct_and_real_har_history(
    repository_root: Path, tmp_path: Path, lab_engagement: Engagement
) -> None:
    factory = ProxyBackendFactory(repository_root, tmp_path / "runtime")
    direct = await factory.select(
        lab_engagement,
        requested="direct",
        receipt_path=tmp_path / "direct-receipt.json",
    )
    assert direct.selected == "direct"
    assert json.loads(Path(direct.receipt_path).read_text(encoding="utf-8"))["status"] == "PASS"

    har = tmp_path / "traffic.har"
    atomic_write_json(
        har,
        {
            "log": {
                "entries": [
                    {
                        "time": 1,
                        "request": {
                            "method": "GET",
                            "url": "http://127.0.0.1:8765/api/objects/1",
                            "headers": [],
                        },
                        "response": {
                            "status": 200,
                            "headers": [{"name": "content-type", "value": "application/json"}],
                            "content": {"text": '{"id":1}'},
                        },
                    }
                ]
            }
        },
    )
    selected = await factory.select(
        lab_engagement,
        requested="har",
        har_path=har,
        receipt_path=tmp_path / "har-receipt.json",
    )
    history = await selected.backend.search(lab_engagement, method="GET")
    assert selected.selected == "har"
    assert len(history) == 1
    exported = await selected.backend.export(tmp_path / "export.har")
    assert exported.read_bytes() == har.read_bytes()


@pytest.mark.asyncio
async def test_proxy_factory_rejects_unavailable_explicit_backend_and_records_auto_fallback(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement: Engagement,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = ProxyBackendFactory(repository_root, tmp_path / "runtime")
    with pytest.raises(ValueError, match="unsupported proxy backend"):
        await factory.select(
            lab_engagement,
            requested="unknown",
            receipt_path=tmp_path / "unknown.json",
        )
    with pytest.raises(ProxyUnavailable, match="requested proxy backend is unavailable"):
        await factory.select(
            lab_engagement,
            requested="har",
            receipt_path=tmp_path / "missing-har.json",
        )

    def unavailable(*_args: object) -> object:
        raise ProxyUnavailable("fixture backend is unavailable")

    monkeypatch.setattr(factory, "_construct", unavailable)
    selected = await factory.select(
        lab_engagement,
        requested="auto",
        receipt_path=tmp_path / "auto-fallback.json",
    )
    receipt = json.loads(Path(selected.receipt_path).read_text(encoding="utf-8"))
    assert selected.selected == "direct"
    assert [attempt["ready"] for attempt in selected.attempted] == [False, True]
    assert receipt["attempted"][-1]["detail"].startswith("automatic selection")


def test_proxy_factory_auto_candidates_and_adapter_construction(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement: Engagement,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    atomic_write_json(
        runtime / "proxy" / "caido.json",
        {
            "url": "http://127.0.0.1:7777",
            "pat_reference": "env://BUDOBUGS_TEST_CAIDO_PAT",
        },
    )
    monkeypatch.setenv("BUDOBUGS_TEST_CAIDO_PAT", "fixture-only-pat")
    monkeypatch.setenv("BUDOBUGS_BURP_MCP_URL", "http://127.0.0.1:7778/mcp")
    monkeypatch.setenv("BUDOBUGS_ZAP_URL", "http://127.0.0.1:7779")
    factory = ProxyBackendFactory(repository_root, runtime)
    assert factory._auto_candidates(tmp_path / "traffic.har") == [
        "caido",
        "burp",
        "zap",
        "har",
        "direct",
    ]
    assert factory._construct("burp", lab_engagement, None).name == "burp-mcp"
    assert factory._construct("zap", lab_engagement, None).name == "zap"
    assert factory._construct("caido", lab_engagement, None).name == "caido"

    monkeypatch.delenv("BUDOBUGS_TEST_CAIDO_PAT")
    with pytest.raises(ProxyUnavailable, match="PAT reference cannot be resolved"):
        factory._construct("caido", lab_engagement, None)
    with pytest.raises(ValueError, match="cannot construct"):
        factory._construct("invalid", lab_engagement, None)


def test_vendor_memory_bounty_feedback_and_same_fix_dedup(service, lab_engagement: Engagement) -> None:
    knowledge_base = VendorKnowledgeBase(service.store)
    knowledge = knowledge_base.load(lab_engagement)
    high = BountyPrioritizer.score(
        "candidate-high",
        category="business-logic",
        expected_reward=5000,
        confirmation_probability=0.7,
        business_impact=1.4,
        uniqueness=1.2,
        duplicate_risk=0.2,
        request_cost=1,
        token_cost=1,
        research_cost=1,
        knowledge=knowledge,
    )
    noise = BountyPrioritizer.score(
        "candidate-noise",
        category="scanner-noise",
        expected_reward=500,
        confirmation_probability=0.3,
        business_impact=0.4,
        uniqueness=0.5,
        duplicate_risk=0.8,
        request_cost=2,
        token_cost=2,
        research_cost=2,
        knowledge=knowledge,
    )
    assert high.score > noise.score

    def outcome(candidate: str, finding: str, validator: str) -> ValidationOutcome:
        return ValidationOutcome(
            outcome_id=new_id("validation"),
            validator_id=validator,
            candidate_id=candidate,
            decision=CandidateDecision.CONFIRMED,
            vulnerability_class="authorization",
            title="same resolver policy",
            root_cause_key="shared-resolver-owner-check",
            repair_boundary="enforce owner policy in shared resolver",
            finding_id=finding,
            capability_delta="cross-account read",
            strongest_benign_explanation="public control denied",
            repeated=True,
            normal_control_passed=True,
            negative_control_passed=True,
            cleanup_completed=True,
            evidence_closed=True,
            confidence=0.95,
        )

    outcomes = [
        outcome("candidate-rest", "finding-rest", "rest-entry"),
        outcome("candidate-graphql", "finding-graphql", "graphql-entry"),
    ]
    clusters = RootCauseDeduper.cluster(outcomes)
    assert len(clusters) == 1
    assert set(clusters[0].merged_entry_points) == {"rest-entry", "graphql-entry"}
    updated = knowledge_base.update_from_validation(lab_engagement, outcomes)
    assert set(updated.confirmed_finding_ids) >= {"finding-rest", "finding-graphql"}

    feedback = PlatformOutcome(
        outcome_id="platform-outcome-001",
        finding_id="finding-rest",
        vendor_key=updated.vendor_key,
        status=OutcomeStatus.DUPLICATE,
        reward=0,
        reason="same root cause as an earlier accepted report",
    )
    after = knowledge_base.record_outcome(lab_engagement, feedback)
    assert after.duplicate_risk_prior > updated.duplicate_risk_prior
    assert "finding-rest" in after.duplicate_finding_ids


def test_vendor_knowledge_scopes_traffic_changes_feedback_and_catalog_priority(
    service, lab_engagement: Engagement
) -> None:
    knowledge_base = VendorKnowledgeBase(service.store)
    legacy = knowledge_base.load(lab_engagement).model_copy(update={"schema_version": 1})
    service.store.save("vendor-knowledge", legacy.vendor_key, legacy)
    assert knowledge_base.load(lab_engagement).schema_version == 1
    exchange = make_exchange(
        exchange_id="exchange-workflow-change",
        url="http://127.0.0.1:8765/api/orders/1/transition",
        response='{"previous":"draft","current":"paid"}',
    ).model_copy(update={"method": "POST", "request_body": '{"state":"paid"}'})
    model = build_traffic_model([exchange])
    knowledge = knowledge_base.update_from_traffic(lab_engagement, model, candidate_ids=["candidate-tested"])
    assert knowledge.schema_version == 2
    assert "route:api/orders" in knowledge.product_features
    assert any(item.startswith("new-endpoint:") for item in knowledge.change_observations)
    assert "candidate-tested" in knowledge.tested_candidate_ids
    assert any(item.startswith("endpoint-anomaly:") for item in knowledge.anomalous_behaviors) is False

    accepted = PlatformOutcome(
        outcome_id="outcome-scoped-accepted",
        finding_id="finding-scoped-accepted",
        vendor_key=knowledge.vendor_key,
        status=OutcomeStatus.ACCEPTED,
        reward=6000,
        reason="accepted",
        vulnerability_class="business-logic-workflow",
        root_cause_key="order-transition-guard",
        feature_key="orders-transition",
        exploitation_method="business-workflow",
    )
    rejected = PlatformOutcome(
        outcome_id="outcome-scoped-rejected",
        finding_id="finding-scoped-rejected",
        vendor_key=knowledge.vendor_key,
        status=OutcomeStatus.REJECTED,
        reason="normal workflow explanation was sufficient",
        vulnerability_class="business-logic-workflow",
        root_cause_key="order-transition-guard",
        feature_key="orders-transition",
    )
    knowledge = knowledge_base.record_outcome(lab_engagement, accepted)
    knowledge = knowledge_base.record_outcome(lab_engagement, rejected)
    scoped = VendorKnowledgeBase.prior_for(
        knowledge,
        vulnerability_class="business-logic-workflow",
        root_cause_key="order-transition-guard",
        feature="orders-transition",
    )
    assert scoped is not None
    assert (scoped.accepted, scoped.rejected, scoped.reward_total) == (1, 1, 6000)
    assert rejected.reason not in knowledge.false_positive_rules
    assert any(rejected.reason in rules for rules in knowledge.scoped_false_positive_rules.values())
    score = BountyPrioritizer.score(
        "candidate-scoped",
        category="business-logic",
        expected_reward=1000,
        confirmation_probability=0.5,
        business_impact=1,
        uniqueness=1,
        duplicate_risk=0.3,
        request_cost=1,
        token_cost=1,
        research_cost=1,
        knowledge=knowledge,
        vulnerability_class="business-logic-workflow",
        root_cause_key="order-transition-guard",
        feature="orders-transition",
    )
    assert score.expected_reward == 3500

    state = AgentLoopState(
        loop_id="loop-knowledge",
        run_id="run-knowledge",
        engagement_id=lab_engagement.engagement_id,
        executed_catalog_actions=["lab-engagement-intake"],
    )
    plain = ActionCatalogBuilder(lab_engagement).actions(AgentRole.BROWSER_EXPLORER, 1, state)[0]
    informed = ActionCatalogBuilder(lab_engagement, knowledge=knowledge).actions(AgentRole.BROWSER_EXPLORER, 1, state)[
        0
    ]
    assert informed.expected_information_gain > plain.expected_information_gain


def test_historical_duplicate_assessment_distinguishes_duplicate_and_regression(
    service, lab_engagement: Engagement
) -> None:
    knowledge_base = VendorKnowledgeBase(service.store)
    knowledge = knowledge_base.load(lab_engagement)
    historical = PlatformOutcome(
        outcome_id="outcome-historical",
        finding_id="finding-historical",
        vendor_key=knowledge.vendor_key,
        status=OutcomeStatus.ACCEPTED,
        reason="accepted before",
        vulnerability_class="horizontal-authorization",
        root_cause_key="shared-owner-check",
        feature_key="document-download",
        exploitation_method="authorization-differential",
    )
    knowledge = knowledge_base.record_outcome(lab_engagement, historical)

    def confirmed(finding_id: str) -> ValidationOutcome:
        return ValidationOutcome(
            outcome_id=f"outcome-{finding_id}",
            validator_id="authorization-differential",
            candidate_id=f"candidate-{finding_id}",
            decision=CandidateDecision.CONFIRMED,
            vulnerability_class="horizontal-authorization",
            title="shared owner check",
            affected_feature="document-download",
            root_cause_key="shared-owner-check",
            repair_boundary="shared owner middleware",
            finding_id=finding_id,
            capability_delta="cross-account read",
            strongest_benign_explanation="public control denied",
            repeated=True,
            normal_control_passed=True,
            negative_control_passed=True,
            cleanup_completed=True,
            evidence_closed=True,
            confidence=0.95,
        )

    knowledge = knowledge_base.update_from_validation(lab_engagement, [confirmed("finding-repeat")])
    assert knowledge.historical_duplicate_assessments[-1].decision is DuplicateAssessmentDecision.PLATFORM_DUPLICATE
    fixed = historical.model_copy(
        update={"outcome_id": "outcome-fixed", "finding_id": "finding-fixed", "previously_fixed": True}
    )
    knowledge_base.record_outcome(lab_engagement, fixed)
    knowledge = knowledge_base.update_from_validation(lab_engagement, [confirmed("finding-regression")])
    assert knowledge.historical_duplicate_assessments[-1].decision is DuplicateAssessmentDecision.REGRESSION
    assert "finding-regression" in knowledge.regression_finding_ids
