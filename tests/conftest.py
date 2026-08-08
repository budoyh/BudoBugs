"""Shared fixtures for isolated BudoBugs tests.

The local fixture is deliberately started by the E2E test instead of being
mocked: tests never send traffic beyond 127.0.0.1.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from budobugs.core.paths import WorkspacePaths
from budobugs.models import Engagement, EngagementMode, HttpExchange, Target
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
