from __future__ import annotations

import asyncio
import json
import socket
import sys
from pathlib import Path

import httpx
import pytest

from budobugs.core.io import atomic_write_json
from budobugs.labs.manager import LabManager
from budobugs.models import (
    AgentRole,
    CandidateStatus,
    CriticVerdict,
    Engagement,
    EngagementMode,
    PhaseName,
    SafeExperimentTemplate,
    SafeHttpAction,
    Target,
)
from budobugs.orchestration.engine import HuntEngine
from budobugs.orchestration.service import RepositoryService
from budobugs.proxy.direct import DirectProxyBackend
from budobugs.validation.executors import ValidatorRegistry


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


@pytest.mark.e2e
async def test_local_fixture_full_hunt_and_completed_resume(
    workspace, repository_root: Path, lab_engagement: Engagement
) -> None:
    """No mocks: launch uvicorn, capture localhost traffic, drive Playwright, and emit evidence."""

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        fixture_port = int(probe.getsockname()[1])
    engagement = lab_engagement.model_copy(
        update={"root_targets": [Target(uri=f"http://127.0.0.1:{fixture_port}", label="fixture")]}
    )
    manager = LabManager(repository_root, workspace.runtime_home, fixture_port=fixture_port)
    status = await asyncio.to_thread(manager.up, native_only=True)
    assert status.running
    assert status.backend == "native"
    try:
        async with httpx.AsyncClient(timeout=2, trust_env=False) as client:
            health = await client.get(f"http://127.0.0.1:{fixture_port}/healthz")
            assert health.status_code == 200
        service = RepositoryService(workspace)
        service.save_engagement(engagement)
        engagement = service.authorize_engagement(engagement.engagement_id)
        try:
            interrupted = await HuntEngine(service).run(engagement, stop_after=PhaseName.TRAFFIC_MODEL)
            assert interrupted.run.status == "interrupted"
            completed_attempts = {
                item.name: item.attempt for item in interrupted.run.phases if item.status == "completed"
            }
            assert completed_attempts[PhaseName.NORMAL_BROWSER_EXPLORATION] == 1
            browser_outputs = next(
                item.output_artifacts
                for item in interrupted.run.phases
                if item.name is PhaseName.NORMAL_BROWSER_EXPLORATION
            )
            assert any(item.endswith("steps.jsonl") for item in browser_outputs)
            assert any("/dom/" in item.replace("\\", "/") and item.endswith(".html") for item in browser_outputs)
            assert any(item.endswith(".png.metadata.json") for item in browser_outputs)
            result = await HuntEngine(service).run(engagement, resume=True)
        except Exception as exc:
            if "Executable doesn't exist" in str(exc):
                pytest.skip("NEEDS_RUNTIME: Playwright browser is not installed")
            raise
        confirmed = service.load_finding(result.confirmed_finding_id)
        killed = service.load_finding(result.killed_finding_id)
        assert confirmed.critic_verdict is CriticVerdict.CONFIRMED
        assert confirmed.status is CandidateStatus.READY_FOR_HUMAN_REVIEW
        assert killed.status is CandidateStatus.KILL
        assert Path(result.report_markdown).is_file()
        assert Path(result.report_html).is_file()
        assert result.run.run_id == interrupted.run.run_id
        assert result.run.resume_count == 1
        assert all(
            next(item for item in result.run.phases if item.name is phase).attempt == attempt
            for phase, attempt in completed_attempts.items()
        )
        costs = service.list_costs(run_id=result.run.run_id)
        phase_costs = [item for item in costs if item.model == "local-deterministic"]
        assert len(phase_costs) == len(PhaseName)
        assert {item.phase for item in phase_costs} == set(PhaseName)
        assert any(item.candidate_id == confirmed.finding_id for item in phase_costs)
        resumed = await HuntEngine(service).run(engagement, resume=True)
        assert resumed.run.run_id == result.run.run_id
    finally:
        await _assert_native_fixture_stopped(manager, sys.exception())


@pytest.mark.e2e
async def test_agent_loop_turn_checkpoint_resumes_same_chain_and_closes_acceptance(
    workspace, repository_root: Path, lab_engagement: Engagement
) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        fixture_port = int(probe.getsockname()[1])
    engagement = lab_engagement.model_copy(
        update={
            "engagement_id": "lab-agent-loop-resume-001",
            "root_targets": [Target(uri=f"http://127.0.0.1:{fixture_port}", label="fixture")],
        }
    )
    manager = LabManager(repository_root, workspace.runtime_home, fixture_port=fixture_port)
    assert (await asyncio.to_thread(manager.up, native_only=True)).running
    try:
        service = RepositoryService(workspace)
        service.save_engagement(engagement)
        engagement = service.authorize_engagement(engagement.engagement_id)
        try:
            interrupted = await HuntEngine(service, agent_stop_after_turns=5).run(engagement)
            assert interrupted.run.status == "interrupted"
            assert interrupted.agent_loop_receipt is not None
            first_receipt = json.loads(Path(interrupted.agent_loop_receipt).read_text(encoding="utf-8"))
            assert first_receipt["turn_count"] == 5
            assert first_receipt["status"] == "interrupted"
            result = await HuntEngine(service).run(engagement, resume=True)
        except Exception as exc:
            if "Executable doesn't exist" in str(exc):
                pytest.skip("NEEDS_RUNTIME: Playwright browser is not installed")
            raise
        assert result.run.run_id == interrupted.run.run_id
        assert result.agent_loop_receipt is not None
        receipt = json.loads(Path(result.agent_loop_receipt).read_text(encoding="utf-8"))
        assert receipt["resume_count"] == 1
        assert receipt["participating_agent_count"] == 12
        assert set(receipt["participating_agents"]) == {role.value for role in AgentRole}
        assert set(receipt["invoked_skills"]) == set(HuntEngine.REQUIRED_LAB_AGENT_SKILLS)
        successful_turns = [
            item
            for item in receipt["agent_execution_receipts"]
            if item["observation_status"] == "executed" and item["invocation_status"] == "PASS"
        ]
        assert {item["agent_role"] for item in successful_turns} == {role.value for role in AgentRole}
        assert {item["skill_name"] for item in successful_turns} == set(HuntEngine.REQUIRED_LAB_AGENT_SKILLS)
        assert receipt["round_count"] >= 3
        assert {"browser_navigate", "proxy_replay", "http_request", "tool_task"}.issubset(
            set(receipt["typed_action_kinds_executed"])
        )
        assert len(receipt["network_or_browser_actions_executed"]) >= 4
        assert len(receipt["confirmed_vulnerability_classes"]) >= 4
        assert len(receipt["killed_outcomes"]) >= 3
        assert receipt["same_fix_merged_clusters"]
        assert receipt["acceptance_passed"] is True
        assert receipt["dynamic_coordinator_route_count"] == 0
        assert receipt["policy_coordinator_route_count"] >= 3
        assert receipt["coordinator_route_summary"]
        assert receipt["acceptance_checks"]["dynamic_coordinator_routes"] is False
        assert "dynamic_coordinator_routes" in receipt["acceptance_exceptions"]
        assert all(
            passed or check_name in receipt["acceptance_exceptions"]
            for check_name, passed in receipt["acceptance_checks"].items()
        )
        assert len(result.confirmed_finding_ids) >= 4
        assert len(result.killed_finding_ids) >= 3
        assert result.report_markdowns
        assert all(Path(item).is_file() for item in result.report_markdowns)
    finally:
        await _assert_native_fixture_stopped(manager, sys.exception())


@pytest.mark.e2e
async def test_program_mode_two_accounts_validate_path_query_and_graphql_objects(
    workspace, repository_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        fixture_port = int(probe.getsockname()[1])
    base = f"http://127.0.0.1:{fixture_port}"
    manager = LabManager(repository_root, workspace.runtime_home, fixture_port=fixture_port)
    status = await asyncio.to_thread(manager.up, native_only=True)
    assert status.running
    try:
        monkeypatch.setenv("BUDOBUGS_TEST_ALICE", json.dumps({"headers": {"Authorization": "Fixture alice"}}))
        monkeypatch.setenv("BUDOBUGS_TEST_BOB", json.dumps({"headers": {"Authorization": "Fixture bob"}}))

        def action(action_id: str, method: str, path: str, expected: list[int]) -> SafeHttpAction:
            return SafeHttpAction(
                action_id=action_id,
                account_alias="alice",
                method=method,
                target_url=f"{base}{path}",
                expected_statuses=expected,
            )

        object_boundary = "fixture-order:1"
        operation_boundary = "confirm self-owned order once"
        normal = action("normal-order-state", "GET", "/api/orders/1", [200]).model_copy(
            update={"object_boundary": object_boundary}
        )
        experiment = action("repeat-order-confirm", "POST", "/api/orders/1/confirm", [200]).model_copy(
            update={"operation_boundary": operation_boundary, "object_boundary": object_boundary}
        )
        negative = action("secure-order-confirm", "POST", "/api/secure-orders/1/confirm", [409]).model_copy(
            update={"operation_boundary": operation_boundary, "object_boundary": object_boundary}
        )
        mutation_template = SafeExperimentTemplate(
            template_id="program-workflow-repeat-001",
            specialist_role="business-logic-specialist",
            title="Repeated confirmation bypasses the one-time order workflow",
            vulnerability_class="business-logic-workflow",
            affected_feature="order confirmation workflow",
            security_invariant="A self-owned order must be reviewed and confirmed only once.",
            root_cause_key="fixture-order-confirmation-state",
            repair_boundary="enforce reviewed state and one-time effect in the shared confirmation service",
            capability_before="one self-owned order can be confirmed once",
            capability_after="the same self-owned order can trigger confirmation twice",
            capability_delta="one extra confirmation effect on a disposable self-owned order",
            strongest_benign_explanation="the endpoint might be an idempotent confirmation API",
            impact="duplicate confirmation can repeat a protected business effect",
            normal_control=normal,
            experiment=experiment,
            negative_control=negative,
            effect_observation=normal.model_copy(update={"action_id": "observe-confirm-count"}),
            effect_json_pointer="/confirm_count",
            expected_effect_sequence=[0, 1, 2],
            cleanup=[
                action("reset-disposable-order", "POST", "/__fixture__/reset", [200]).model_copy(
                    update={"headers": {"X-Budo-Fixture": "reset-local-test-state"}}
                )
            ],
            cleanup_verification=normal.model_copy(update={"action_id": "verify-order-restored"}),
        )
        monkeypatch.setenv("BUDOBUGS_TEST_SAFE_EXPERIMENT", mutation_template.model_dump_json())
        engagement = Engagement(
            engagement_id="program-local-001",
            platform="local-authorized-program-test",
            vendor="BudoBugs TEST FIXTURE",
            user_authorization_attestation=(
                "I authorize both self-owned local fixture accounts for bounded read-only validation."
            ),
            root_targets=[Target(uri=base, label="fixture")],
            selected_mode=EngagementMode.PROGRAM,
            testing_accounts_secret_refs={
                "alice": "env://BUDOBUGS_TEST_ALICE",
                "bob": "env://BUDOBUGS_TEST_BOB",
            },
            safe_experiment_secret_refs={mutation_template.template_id: "env://BUDOBUGS_TEST_SAFE_EXPERIMENT"},
        )
        service = RepositoryService(workspace)
        service.save_engagement(engagement)
        engagement = service.authorize_engagement(engagement.engagement_id)
        direct = DirectProxyBackend(timeout=5)
        # PROGRAM validation plans are derived from traffic that was actually
        # observed before an active experiment.  Seed one authorized,
        # self-owned normal workflow exchange so the pre-registered template
        # is bound to the real POST family rather than trusted as a finding by
        # itself; reset immediately so the typed executor still proves the
        # complete baseline/repeat/negative/cleanup sequence from state zero.
        observed_order = await direct.send(
            engagement,
            "GET",
            f"{base}/api/orders/1",
            headers={"Authorization": "Fixture alice"},
            account_alias="alice",
        )
        observed_confirmation = await direct.send(
            engagement,
            "POST",
            f"{base}/api/orders/1/confirm",
            headers={"Authorization": "Fixture alice"},
            account_alias="alice",
        )
        reset = await direct.send(
            engagement,
            "POST",
            f"{base}/__fixture__/reset",
            headers={"X-Budo-Fixture": "reset-local-test-state"},
            account_alias=None,
        )
        assert reset.response_status == 200
        graphql_alice = json.dumps(
            {
                "query": "query Object($objectId: Int!) { object(id: $objectId) { id } }",
                "variables": {"objectId": 1},
                "operationName": "Object",
            }
        )
        graphql_bob = json.dumps(
            {
                "query": "query Object($objectId: Int!) { object(id: $objectId) { id } }",
                "variables": {"objectId": 2},
                "operationName": "Object",
            }
        )
        alice_path, bob_path, alice_query, bob_query, alice_graphql, bob_graphql = await asyncio.gather(
            direct.send(
                engagement,
                "GET",
                f"{base}/api/objects/1",
                headers={"Authorization": "Fixture alice"},
                account_alias="alice",
            ),
            direct.send(
                engagement,
                "GET",
                f"{base}/api/objects/2",
                headers={"Authorization": "Fixture bob"},
                account_alias="bob",
            ),
            direct.send(
                engagement,
                "GET",
                f"{base}/api/object-query?object_id=1",
                headers={"Authorization": "Fixture alice"},
                account_alias="alice",
            ),
            direct.send(
                engagement,
                "GET",
                f"{base}/api/object-query?object_id=2",
                headers={"Authorization": "Fixture bob"},
                account_alias="bob",
            ),
            direct.send(
                engagement,
                "POST",
                f"{base}/graphql",
                headers={"Authorization": "Fixture alice", "Content-Type": "application/json"},
                content=graphql_alice,
                account_alias="alice",
            ),
            direct.send(
                engagement,
                "POST",
                f"{base}/graphql",
                headers={"Authorization": "Fixture bob", "Content-Type": "application/json"},
                content=graphql_bob,
                account_alias="bob",
            ),
        )
        imported = workspace.runtime_home / "imports" / engagement.engagement_id / "owned-objects.json"
        imported_exchanges = [
            observed_order,
            observed_confirmation,
            alice_path,
            bob_path,
            alice_query,
            bob_query,
            alice_graphql,
            bob_graphql,
        ]
        atomic_write_json(imported, [item.model_dump(mode="json") for item in imported_exchanges])
        result = await HuntEngine(service).run(engagement)
        assert result.confirmed_finding_id is not None
        finding = service.load_finding(result.confirmed_finding_id)
        assert finding.critic_verdict is CriticVerdict.CONFIRMED
        findings = [service.load_finding(finding_id) for finding_id in result.confirmed_finding_ids]
        scopes = {item.mutation_scope for item in findings}
        assert any(" path " in scope for scope in scopes)
        assert any(" query " in scope for scope in scopes)
        assert any(" graphql " in scope for scope in scopes)
        assert any(scope.startswith("Self-owned POST") for scope in scopes)
        assert any(item.vulnerability_class == "business-logic-workflow" for item in findings)
        assert all(item.critic_verdict is CriticVerdict.CONFIRMED for item in findings)
        assert result.report_markdown is not None
        assert Path(result.report_markdown).is_file()
    finally:
        await _assert_native_fixture_stopped(manager, sys.exception())


@pytest.mark.e2e
async def test_local_fixture_cors_and_csrf_validators_prove_effect_and_cleanup(
    workspace, repository_root: Path, lab_engagement: Engagement
) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        fixture_port = int(probe.getsockname()[1])
    engagement = lab_engagement.model_copy(
        update={"root_targets": [Target(uri=f"http://127.0.0.1:{fixture_port}", label="fixture")]}
    )
    manager = LabManager(repository_root, workspace.runtime_home, fixture_port=fixture_port)
    assert (await asyncio.to_thread(manager.up, native_only=True)).running
    try:
        registry = ValidatorRegistry(workspace.runtime_home / "cors-csrf-validators")
        cors = (await registry.run("fixture-cors-credentialed-origin", engagement))[0]
        csrf = (await registry.run("fixture-csrf-token-bypass", engagement))[0]
        assert {cors.outcome.vulnerability_class, csrf.outcome.vulnerability_class} == {
            "cors-misconfiguration",
            "csrf-protection-bypass",
        }
        assert all(
            item.outcome.decision.value == "CONFIRMED"
            and item.outcome.repeated
            and item.outcome.normal_control_passed
            and item.outcome.negative_control_passed
            and item.outcome.cleanup_completed
            and item.outcome.evidence_closed
            for item in (cors, csrf)
        )
        cors_evil = [
            item
            for item in cors.exchanges
            if item.url.endswith("/api/cors/transfer")
            and item.request_headers.get("origin") == "https://evil.fixture.invalid"
        ]
        assert len(cors_evil) == 2
        assert all(
            item.response_headers.get("access-control-allow-origin") == "https://evil.fixture.invalid"
            for item in cors_evil
        )
        assert all(item.response_headers.get("access-control-allow-credentials") == "true" for item in cors_evil)
    finally:
        await _assert_native_fixture_stopped(manager, sys.exception())
