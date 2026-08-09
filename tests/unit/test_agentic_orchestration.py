from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from budobugs.agents.router import ModelRouter
from budobugs.agents.runner import CodexTaskRunner
from budobugs.core.identifiers import new_id
from budobugs.core.io import atomic_write_json
from budobugs.knowledge.vendor import BountyPrioritizer, RootCauseDeduper, VendorKnowledgeBase
from budobugs.models import (
    ActionKind,
    ActionProposal,
    AgentLoopState,
    AgentRole,
    CandidateDecision,
    Engagement,
    OutcomeStatus,
    PlatformOutcome,
    ValidationOutcome,
)
from budobugs.orchestration.agent_loop import CodexProposalProvider, PolicyProposalProvider
from budobugs.orchestration.catalog import ActionCatalogBuilder
from budobugs.orchestration.skill_runtime import SkillRuntime
from budobugs.proxy.base import ProxyUnavailable
from budobugs.proxy.factory import ProxyBackendFactory


def _action(
    *,
    action_id: str = "safe-action",
    role: AgentRole = AgentRole.COORDINATOR,
    skill: str = "budobugs-controller",
    kind: ActionKind = ActionKind.PROXY_SEARCH,
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
        **values,
    )


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
    for _ in range(5):
        actions = catalog.actions(AgentRole.AUTHORIZATION_SPECIALIST, 2, state)
        selected = max(actions, key=lambda item: item.expected_information_gain)
        auth_ids.append(selected.validator_id or "")
        state.executed_catalog_actions.append(selected.catalog_action_id)
    assert set(auth_ids) == {
        "fixture-horizontal-rest",
        "fixture-horizontal-graphql",
        "fixture-vertical-role",
        "fixture-cross-tenant",
        "fixture-file-share",
    }


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
                {
                    "catalog_action_id": action.catalog_action_id,
                    "rationale": "highest safe information gain",
                    "expected_information_gain": 0.72,
                    "follow_up": "execute and inspect the typed observation",
                }
            )
            events = [
                {"type": "thread.started", "thread_id": "thread-provider-001"},
                {
                    "item": {"type": "agent_message", "text": payload},
                    "usage": {"input_tokens": 12, "output_tokens": 8, "cached_input_tokens": 2},
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
            engagement_token_budget=10000,
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
        _, resumed = await provider.propose(
            role=AgentRole.COORDINATOR,
            skill_instruction="reviewed contract",
            skill_workflow="observe, plan, execute",
            candidates=[action],
            state=state,
        )
        assert resumed.resumed_thread
        assert calls[1][1:3] == ["exec", "resume"]
        assert len(service.list_costs(run_id=state.run_id)) == 2
    finally:
        monkeypatch.undo()


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
