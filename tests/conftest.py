"""Shared fixtures for isolated BudoBugs tests.

The local fixture is deliberately started by the E2E test instead of being
mocked: tests never send traffic beyond 127.0.0.1.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from budobugs.core.paths import WorkspacePaths
from budobugs.models import (
    CandidateStatus,
    Engagement,
    EngagementMode,
    Finding,
    HttpExchange,
    Severity,
    Target,
)
from budobugs.orchestration.service import RepositoryService


@pytest.fixture
def repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def workspace(tmp_path: Path, repository_root: Path) -> WorkspacePaths:
    """A complete workspace whose mutable state remains below pytest's tmp path."""

    root = tmp_path / "workspace"
    paths = WorkspacePaths(
        root=repository_root,
        runtime_home=root / ".budobugs",
        engagements=root / "engagements",
        runs=root / "runs",
        findings=root / "findings",
        state=root / ".budobugs" / "state",
        events=root / ".budobugs" / "events",
    )
    paths.initialize()
    return paths


@pytest.fixture
def service(workspace: WorkspacePaths) -> RepositoryService:
    return RepositoryService(workspace)


@pytest.fixture
def lab_engagement() -> Engagement:
    return Engagement(
        engagement_id="lab-fixture-001",
        platform="local-test",
        vendor="BudoBugs TEST FIXTURE",
        user_authorization_attestation="I authorize only this local test fixture for automated validation.",
        root_targets=[Target(uri="http://127.0.0.1:8765", label="fixture")],
        selected_mode=EngagementMode.LAB,
    )


def make_exchange(
    *,
    exchange_id: str = "exchange-001",
    url: str = "http://127.0.0.1:8765/api/objects/1",
    status: int = 200,
    account: str | None = "bob",
    response: str = '{"id":"1","owner":"alice"}',
) -> HttpExchange:
    return HttpExchange(
        exchange_id=exchange_id,
        engagement_id="lab-fixture-001",
        method="GET",
        url=url,
        request_headers={"Authorization": "Fixture bob"} if account else {},
        response_status=status,
        response_headers={"content-type": "application/json"},
        response_body=response,
        account_alias=account,
        source="fixture",
    )


def make_finding(*, engagement_id: str = "lab-fixture-001", finding_id: str = "finding-test-001") -> Finding:
    return Finding(
        finding_id=finding_id,
        engagement_id=engagement_id,
        title="本地夹具对象级授权缺失",
        vulnerability_class="horizontal-authorization",
        affected_asset="http://127.0.0.1:8765",
        affected_feature="fixture object API",
        endpoint_family="GET /api/objects/{id}",
        attacker_prerequisites=["self-owned bob fixture account"],
        victim_conditions=["object belongs to self-owned alice control account"],
        security_invariant="accounts may read only owned or granted objects",
        protected_asset="one private fixture object",
        trust_boundary="two self-owned fixture accounts",
        enforcement_point="object resolver",
        observed_behavior="bob reads alice object twice after one identifier replacement",
        expected_behavior="deny the non-owner",
        capability_before="bob reads only bob object",
        capability_after="bob reads one alice object",
        capability_delta="one cross-account private-object read",
        normal_control="bob own-object request succeeds",
        negative_control="anonymous and secure-owner routes deny access",
        strongest_benign_explanation="public access is refuted by the anonymous denial control",
        refutation_attempts=["anonymous control", "owner-enforcing route", "repeat"],
        reproduction_steps=["read the bob control object", "replace one object id and repeat twice"],
        requests=[],
        responses=[],
        data_exposure_scope="one self-owned fixture object only",
        mutation_scope="read-only",
        cleanup_status="no cleanup required",
        impact="one private test object is disclosed across an account boundary",
        severity=Severity.MEDIUM,
        confidence=0.99,
        duplicate_risk="same resolver owner-check repair boundary",
        status=CandidateStatus.VALIDATING,
    )
