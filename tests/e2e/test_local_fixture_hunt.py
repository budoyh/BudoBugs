from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path

import httpx
import pytest

from budobugs.core.io import atomic_write_json
from budobugs.labs.manager import LabManager
from budobugs.models import CandidateStatus, CriticVerdict, Engagement, EngagementMode, PhaseName, Target
from budobugs.orchestration.engine import HuntEngine
from budobugs.orchestration.service import RepositoryService
from budobugs.proxy.direct import DirectProxyBackend


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
        await asyncio.to_thread(manager.down)


@pytest.mark.e2e
async def test_program_mode_two_self_owned_accounts_get_only_validation(
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
        engagement = Engagement(
            engagement_id="program-local-001",
            platform="local-authorized-program-test",
            vendor="BudoBugs TEST FIXTURE",
            user_authorization_attestation=(
                "I authorize both self-owned local fixture accounts for GET-only validation."
            ),
            root_targets=[Target(uri=base, label="fixture")],
            selected_mode=EngagementMode.PROGRAM,
            testing_accounts_secret_refs={
                "alice": "env://BUDOBUGS_TEST_ALICE",
                "bob": "env://BUDOBUGS_TEST_BOB",
            },
        )
        service = RepositoryService(workspace)
        service.save_engagement(engagement)
        engagement = service.authorize_engagement(engagement.engagement_id)
        direct = DirectProxyBackend(timeout=5)
        alice, bob = await asyncio.gather(
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
        )
        imported = workspace.runtime_home / "imports" / engagement.engagement_id / "owned-objects.json"
        atomic_write_json(imported, [alice.model_dump(mode="json"), bob.model_dump(mode="json")])
        result = await HuntEngine(service).run(engagement)
        assert result.confirmed_finding_id is not None
        finding = service.load_finding(result.confirmed_finding_id)
        assert finding.critic_verdict is CriticVerdict.CONFIRMED
        assert finding.mutation_scope.startswith("GET-only")
        assert result.report_markdown is not None
        assert Path(result.report_markdown).is_file()
    finally:
        await asyncio.to_thread(manager.down)
