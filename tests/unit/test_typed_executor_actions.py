from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from tests.conftest import make_exchange

from budobugs.core.identifiers import new_id
from budobugs.models import (
    ActionKind,
    ActionProposal,
    AgentLoopState,
    AgentRole,
    CandidateDecision,
    EngagementMode,
    ObservationStatus,
    ProgramValidationPlan,
    SafeExperimentTemplate,
    SafeHttpAction,
    SelfOwnedObjectRecipe,
    VendorKnowledge,
)
from budobugs.orchestration.agent_loop import _turn_executed_successfully
from budobugs.orchestration.catalog import ActionCatalogBuilder
from budobugs.orchestration.executor import TypedActionExecutor
from budobugs.proxy.base import CredentialSubstitutedReplay, ProxyBackend, ProxyCapabilities, ProxyUnavailable
from budobugs.proxy.direct import DirectProxyBackend
from budobugs.proxy.factory import ProxySelection
from budobugs.validation.executors import ValidatorRegistry


def _proposal(
    *,
    action_id: str,
    kind: ActionKind,
    role: AgentRole,
    skill: str,
    **values: object,
) -> ActionProposal:
    return ActionProposal(
        proposal_id=new_id("proposal"),
        catalog_action_id=action_id,
        round_index=2,
        agent_role=role,
        skill_name=skill,
        kind=kind,
        objective="execute one typed scoped follow-up",
        expected_observation="one fresh typed observation",
        **values,
    )


@pytest.mark.asyncio
async def test_evidence_review_receipt_uses_real_redacted_source_schema_and_report_inputs(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement,
) -> None:
    artifact_root = tmp_path / "real-review-inputs"
    executor = TypedActionExecutor(
        repository_root=repository_root,
        runtime_home=tmp_path / "runtime",
        artifact_root=artifact_root,
        engagement=lab_engagement,
        run_id="run-real-review-inputs",
        proxy=ProxySelection(
            backend=DirectProxyBackend(),
            requested="direct",
            selected="direct",
            ready=True,
            detail="test direct backend",
            attempted=(),
            receipt_path=str(tmp_path / "review-proxy.json"),
        ),
    )
    base = lab_engagement.root_targets[0].uri.rstrip("/")
    javascript = make_exchange(
        exchange_id="exchange-review-javascript",
        url=f"{base}/assets/app.js",
        response='fetch("/api/orders/1")',
    ).model_copy(
        update={
            "engagement_id": lab_engagement.engagement_id,
            "request_headers": {"Authorization": "Bearer must-not-enter-review-receipt"},
            "response_headers": {"content-type": "application/javascript"},
        }
    )
    schema = make_exchange(
        exchange_id="exchange-review-schema",
        url=f"{base}/api/orders/1",
        response='{"id":1,"state":"draft"}',
    ).model_copy(
        update={
            "engagement_id": lab_engagement.engagement_id,
            "response_headers": {"content-type": "application/json"},
        }
    )
    executor.ingest_exchanges([javascript, schema])
    browser_artifact = artifact_root / "browser" / "alice" / "dom" / "page.html"
    browser_artifact.parent.mkdir(parents=True)
    browser_artifact.write_text("<main>captured fixture DOM</main>", encoding="utf-8")
    executor.browser_artifacts.append(str(browser_artifact))
    modeled = await executor.execute(
        _proposal(
            action_id="lab-traffic-model-review-inputs",
            kind=ActionKind.TRAFFIC_MODEL,
            role=AgentRole.TRAFFIC_MODELER,
            skill="traffic-object-model",
        )
    )
    assert modeled.status is ObservationStatus.EXECUTED

    reviewed = await executor.execute(
        _proposal(
            action_id="lab-captured-source-review",
            kind=ActionKind.EVIDENCE_REVIEW,
            role=AgentRole.SOURCE_REVIEWER,
            skill="source-secret-supply-chain",
        )
    )
    assert reviewed.status is ObservationStatus.EXECUTED
    receipt_path = artifact_root / "evidence-review" / "lab-captured-source-review.json"
    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    source = payload["input_summary"]["traffic_and_captured_source"]
    assert source["model_present"] is True
    assert source["exchange_ids"] == ["exchange-review-javascript", "exchange-review-schema"]
    assert source["javascript_exchange_ids"] == ["exchange-review-javascript"]
    assert source["response_schema_family_ids"]
    assert source["api_schema_clue_exchange_ids"] == ["exchange-review-javascript"]
    assert source["browser_artifact_count"] == 1
    assert payload["input_summary"]["input_artifact_refs"] == [
        str(artifact_root / "traffic" / "model.json"),
        str(browser_artifact),
    ]
    assert "must-not-enter-review-receipt" not in receipt_path.read_text(encoding="utf-8")

    report_review = await executor.execute(
        _proposal(
            action_id="lab-report-readiness-review",
            kind=ActionKind.EVIDENCE_REVIEW,
            role=AgentRole.REPORT_WRITER,
            skill="butian-report",
        )
    )
    assert report_review.status is ObservationStatus.EXECUTED
    assert report_review.details["report_ready"] == 0


class _HistoricalReplayBackend(ProxyBackend):
    """Records whether an executor ever asks a proxy to replay stored credentials."""

    name = "history-test"
    capabilities = ProxyCapabilities(
        history=True,
        replay=True,
        http2=True,
        active_automation=False,
        export=True,
        credential_substitution_replay=True,
    )

    def __init__(self, exchange):
        self.exchange = exchange
        self.replay_calls: list[tuple[str, str | None]] = []
        self.substituted_replay_calls: list[CredentialSubstitutedReplay] = []

    async def health(self) -> tuple[bool, str]:
        return True, "test backend"

    async def search(self, _engagement, **_kwargs):
        return [self.exchange]

    async def get(self, exchange_id: str):
        if exchange_id != self.exchange.exchange_id:
            raise KeyError(exchange_id)
        return self.exchange

    async def replay(self, _engagement, exchange, *, account_alias: str | None = None):
        self.replay_calls.append((exchange.exchange_id, account_alias))
        raise AssertionError("historical credential replay must not be called in program mode")

    async def replay_with_request(self, _engagement, request: CredentialSubstitutedReplay):
        self.substituted_replay_calls.append(request)
        return self.exchange.model_copy(
            update={
                "exchange_id": f"{self.exchange.exchange_id}-substituted",
                "request_headers": request.headers,
                "request_body": request.body,
                "account_alias": request.account_alias,
                "source": "burp",
            }
        )

    async def export(self, destination: Path) -> Path:
        return destination


@pytest.mark.asyncio
async def test_program_hypothesis_candidate_flows_through_plan_proposal_observation_and_outcome(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement,
    monkeypatch: pytest.MonkeyPatch,
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
    knowledge = VendorKnowledge(
        vendor_key="local-test--budobugs-test-fixture",
        platform=program.platform,
        vendor=program.vendor,
    )
    saved_knowledge: list[VendorKnowledge] = []
    executor = TypedActionExecutor(
        repository_root=repository_root,
        runtime_home=tmp_path / "runtime",
        artifact_root=tmp_path / "program-taxonomy",
        engagement=program,
        run_id="run-program-taxonomy-link",
        proxy=ProxySelection(
            backend=DirectProxyBackend(),
            requested="direct",
            selected="direct",
            ready=True,
            detail="test direct backend",
            attempted=(),
            receipt_path=str(tmp_path / "program-taxonomy-proxy.json"),
        ),
        account_headers={
            "alice": {"Authorization": "Fixture alice"},
            "bob": {"Authorization": "Fixture bob"},
        },
        knowledge=knowledge,
        knowledge_saver=lambda item: saved_knowledge.append(item.model_copy(deep=True)),
    )
    base = program.root_targets[0].uri.rstrip("/")
    executor.ingest_exchanges(
        [
            make_exchange(
                exchange_id="exchange-program-taxonomy-alice",
                url=f"{base}/api/admin/objects/1",
                account="alice",
                response='{"id":1,"owner":"alice"}',
            ).model_copy(update={"engagement_id": program.engagement_id}),
            make_exchange(
                exchange_id="exchange-program-taxonomy-bob",
                url=f"{base}/api/admin/objects/2",
                account="bob",
                response='{"id":2,"owner":"bob"}',
            ).model_copy(update={"engagement_id": program.engagement_id}),
            make_exchange(
                exchange_id="exchange-program-taxonomy-tenant",
                url=f"{base}/api/tenants/1/objects/3",
                account="alice",
            ).model_copy(update={"engagement_id": program.engagement_id}),
            make_exchange(
                exchange_id="exchange-program-taxonomy-oauth",
                url=f"{base}/api/oauth/1/revoke",
                account="alice",
            ).model_copy(update={"engagement_id": program.engagement_id}),
            make_exchange(
                exchange_id="exchange-program-taxonomy-websocket",
                url=f"{base}/app",
                account=None,
                response='<html><a href="ws://127.0.0.1:8765/ws/events">events</a></html>',
            ).model_copy(
                update={
                    "engagement_id": program.engagement_id,
                    "response_headers": {"content-type": "text/html"},
                }
            ),
        ]
    )
    modeled = await executor.execute(
        ActionProposal(
            proposal_id="proposal-program-taxonomy-model",
            catalog_action_id="program-taxonomy-model",
            round_index=1,
            agent_role=AgentRole.TRAFFIC_MODELER,
            skill_name="traffic-object-model",
            kind=ActionKind.TRAFFIC_MODEL,
            objective="derive program taxonomy from observed self-owned controls",
            expected_observation="persist hypotheses and executable control plans",
        )
    )
    assert modeled.status is ObservationStatus.EXECUTED
    persisted_hypotheses = json.loads(
        (tmp_path / "program-taxonomy" / "hypotheses" / "generated.json").read_text(encoding="utf-8")
    )
    horizontal = next(item for item in executor.hypotheses if item.vulnerability_class == "horizontal-authorization")
    unsupported_classes = {
        "vertical-authorization",
        "cross-tenant-authorization",
        "authentication-session",
        "websocket-authorization",
    }
    unsupported = {
        item.hypothesis_id for item in executor.hypotheses if item.vulnerability_class in unsupported_classes
    }
    assert {item.vulnerability_class for item in executor.hypotheses} >= unsupported_classes
    assert horizontal.hypothesis_id in {item["hypothesis_id"] for item in persisted_hypotheses}
    assert unsupported <= set(knowledge.unfinished_candidate_ids)
    assert horizontal.hypothesis_id not in knowledge.unfinished_candidate_ids
    assert saved_knowledge

    resumed = TypedActionExecutor(
        repository_root=repository_root,
        runtime_home=tmp_path / "runtime",
        artifact_root=tmp_path / "program-taxonomy",
        engagement=program,
        run_id="run-program-taxonomy-link",
        proxy=ProxySelection(
            backend=DirectProxyBackend(),
            requested="direct",
            selected="direct",
            ready=True,
            detail="test direct backend",
            attempted=(),
            receipt_path=str(tmp_path / "program-taxonomy-resumed-proxy.json"),
        ),
        account_headers={
            "alice": {"Authorization": "Fixture alice"},
            "bob": {"Authorization": "Fixture bob"},
        },
        knowledge=knowledge,
        knowledge_saver=lambda item: saved_knowledge.append(item.model_copy(deep=True)),
    )
    assert horizontal.hypothesis_id in {item.hypothesis_id for item in resumed.hypotheses}
    await resumed.execute(
        ActionProposal(
            proposal_id="proposal-program-taxonomy-remodel",
            catalog_action_id="program-taxonomy-remodel",
            round_index=2,
            agent_role=AgentRole.TRAFFIC_MODELER,
            skill_name="traffic-object-model",
            kind=ActionKind.TRAFFIC_MODEL,
            objective="resume the persisted taxonomy against rebuilt traffic family IDs",
            expected_observation="preserve stable hypothesis IDs and rebuild exact controls",
        )
    )
    horizontal = next(item for item in resumed.hypotheses if item.vulnerability_class == "horizontal-authorization")
    assert horizontal.hypothesis_id in {item["hypothesis_id"] for item in persisted_hypotheses}

    catalog = ActionCatalogBuilder(
        program,
        knowledge=knowledge,
        hypotheses=resumed.hypotheses,
        program_validation_plans=resumed.program_validation_plans,
    )
    state = AgentLoopState(
        loop_id="loop-program-taxonomy-link",
        run_id="run-program-taxonomy-link",
        engagement_id=program.engagement_id,
    )
    validation_actions = [
        item
        for item in catalog.actions(AgentRole.AUTHORIZATION_SPECIALIST, 2, state)
        if item.kind is ActionKind.VALIDATOR_RUN
    ]
    assert [item.candidate_id for item in validation_actions] == [horizontal.hypothesis_id]
    assert unsupported.isdisjoint(
        item.candidate_id for role in catalog.routable_roles(2) for item in catalog.actions(role, 2, state)
    )
    forged = await resumed.execute(
        _proposal(
            action_id="program-generic-hold-placeholder-is-forbidden",
            kind=ActionKind.VALIDATOR_RUN,
            role=AgentRole.BUSINESS_LOGIC_SPECIALIST,
            skill="authz-business-logic",
            validator_id="program-business-workflow",
            candidate_id=min(unsupported),
        )
    )
    assert forged.status is ObservationStatus.FAILED
    assert not resumed.validator_results
    proposal = validation_actions[0]

    async def send(_engagement, method: str, url: str, **kwargs: object):
        alias = str(kwargs.get("account_alias") or "anonymous")
        object_id = url.rstrip("/").rsplit("/", 1)[-1]
        if alias == "anonymous":
            status = 401
            response = '{"detail":"authentication required"}'
            account = None
        else:
            status = 200
            owner = "alice" if object_id == "1" else "bob"
            response = f'{{"id":{object_id},"owner":"{owner}"}}'
            account = alias
        return make_exchange(
            exchange_id=new_id("exchange-program-taxonomy-control"),
            url=url,
            status=status,
            account=account,
            response=response,
        ).model_copy(update={"engagement_id": program.engagement_id, "method": method})

    monkeypatch.setattr(resumed.direct, "send", send)
    observation = await resumed.execute(proposal)
    outcome = resumed.validator_results[-1].outcome
    assert observation.status is ObservationStatus.EXECUTED
    assert observation.candidate_ids == [horizontal.hypothesis_id]
    assert proposal.candidate_id == horizontal.hypothesis_id
    assert outcome.candidate_id == horizontal.hypothesis_id
    assert outcome.decision is CandidateDecision.CONFIRMED


@pytest.mark.asyncio
@pytest.mark.parametrize("location", ["path", "query", "body", "graphql"])
async def test_program_object_differential_plan_binds_each_supported_parameter_location(
    location: str,
    repository_root: Path,
    tmp_path: Path,
    lab_engagement,
) -> None:
    program = lab_engagement.model_copy(update={"selected_mode": EngagementMode.PROGRAM})
    base = program.root_targets[0].uri.rstrip("/")
    if location == "path":
        urls = [f"{base}/api/objects/1", f"{base}/api/objects/2"]
        bodies = [None, None]
        method = "GET"
    elif location == "query":
        urls = [f"{base}/api/objects?object_id=1", f"{base}/api/objects?object_id=2"]
        bodies = [None, None]
        method = "GET"
    elif location == "body":
        urls = [f"{base}/api/objects", f"{base}/api/objects"]
        bodies = ['{"object_id":1}', '{"object_id":2}']
        method = "GET"
    else:
        urls = [f"{base}/graphql", f"{base}/graphql"]
        bodies = [
            '{"query":"query Object($objectId: ID!){object(id:$objectId){id}}",'
            f'"variables":{{"objectId":"{value}"}}}}'
            for value in (1, 2)
        ]
        method = "POST"
    executor = TypedActionExecutor(
        repository_root=repository_root,
        runtime_home=tmp_path / "runtime",
        artifact_root=tmp_path / f"program-object-{location}",
        engagement=program,
        run_id=f"run-program-object-{location}",
        proxy=ProxySelection(
            backend=DirectProxyBackend(),
            requested="direct",
            selected="direct",
            ready=True,
            detail="test direct backend",
            attempted=(),
            receipt_path=str(tmp_path / f"program-object-{location}-proxy.json"),
        ),
        account_headers={
            "alice": {"Authorization": "Fixture alice"},
            "bob": {"Authorization": "Fixture bob"},
        },
    )
    executor.ingest_exchanges(
        [
            make_exchange(
                exchange_id=f"exchange-program-{location}-{alias}",
                url=url,
                account=alias,
                response=f'{{"id":{index},"owner":"{alias}"}}',
            ).model_copy(update={"engagement_id": program.engagement_id, "method": method, "request_body": body})
            for index, (alias, url, body) in enumerate(zip(("alice", "bob"), urls, bodies, strict=True), start=1)
        ]
    )
    observation = await executor.execute(
        _proposal(
            action_id=f"program-model-{location}",
            kind=ActionKind.TRAFFIC_MODEL,
            role=AgentRole.TRAFFIC_MODELER,
            skill="traffic-object-model",
        )
    )
    assert observation.status is ObservationStatus.EXECUTED
    plans = [
        item for item in executor.program_validation_plans if item.control_source == "observed-object-differential"
    ]
    assert len(plans) == 1
    assert plans[0].parameter_location == location
    assert set(plans[0].control_ids) == {
        f"exchange-program-{location}-alice",
        f"exchange-program-{location}-bob",
    }


@pytest.mark.asyncio
async def test_executor_search_replay_and_direct_get_are_real_typed_actions(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = DirectProxyBackend()
    original = make_exchange(exchange_id="exchange-replayable-get")
    backend._history[original.exchange_id] = original
    selection = ProxySelection(
        backend=backend,
        requested="direct",
        selected="direct",
        ready=True,
        detail="test direct backend",
        attempted=(),
        receipt_path=str(tmp_path / "proxy-selection.json"),
    )
    executor = TypedActionExecutor(
        repository_root=repository_root,
        runtime_home=tmp_path / "runtime",
        artifact_root=tmp_path / "artifacts",
        engagement=lab_engagement,
        run_id="run-typed-actions",
        proxy=selection,
        account_headers={"bob": {"Authorization": "Fixture bob"}},
    )

    search = await executor.execute(
        _proposal(
            action_id="typed-proxy-search",
            kind=ActionKind.PROXY_SEARCH,
            role=AgentRole.COORDINATOR,
            skill="budobugs-controller",
        )
    )
    assert search.status is ObservationStatus.EXECUTED
    assert search.details["replayable_exchanges"] == [
        {"exchange_id": original.exchange_id, "method": "GET", "account_alias": "bob"}
    ]

    async def send(
        _engagement,
        method: str,
        url: str,
        **kwargs: object,
    ):
        assert method == "GET"
        assert url == original.url
        return make_exchange(
            exchange_id=f"exchange-executed-{len(executor.exchanges)}",
            url=url,
            account=str(kwargs.get("account_alias") or "bob"),
        )

    monkeypatch.setattr(executor.direct, "send", send)
    replay = await executor.execute(
        _proposal(
            action_id="typed-proxy-replay",
            kind=ActionKind.PROXY_REPLAY,
            role=AgentRole.AUTHORIZATION_SPECIALIST,
            skill="authz-business-logic",
            method="GET",
            base_exchange_id=original.exchange_id,
            account_aliases=["bob"],
        )
    )
    assert replay.status is ObservationStatus.EXECUTED
    assert replay.details["base_exchange_id"] == original.exchange_id
    assert replay.exchange_ids

    monkeypatch.setattr(executor.direct, "send", send)
    direct = await executor.execute(
        _proposal(
            action_id="typed-direct-get",
            kind=ActionKind.HTTP_REQUEST,
            role=AgentRole.API_AUTH_SPECIALIST,
            skill="api-auth-session",
            target_url=original.url,
            method="GET",
            account_aliases=["bob"],
        )
    )
    assert direct.status is ObservationStatus.EXECUTED
    assert direct.exchange_ids
    assert not direct.state_changes

    expected_ids = [original.exchange_id, *replay.exchange_ids, *direct.exchange_ids]
    ledger = json.loads(executor.exchange_ledger_path.read_text(encoding="utf-8"))
    assert [item["exchange_id"] for item in ledger["exchanges"]] == expected_ids

    resumed = TypedActionExecutor(
        repository_root=repository_root,
        runtime_home=tmp_path / "runtime",
        artifact_root=tmp_path / "artifacts",
        engagement=lab_engagement,
        run_id="run-typed-actions",
        proxy=ProxySelection(
            backend=DirectProxyBackend(),
            requested="direct",
            selected="direct",
            ready=True,
            detail="fresh backend after stop_after resume",
            attempted=(),
            receipt_path=str(tmp_path / "proxy-selection-resumed.json"),
        ),
        account_headers={"bob": {"Authorization": "Fixture bob"}},
    )
    assert [item.exchange_id for item in resumed.exchanges] == expected_ids
    resumed.ingest_exchanges([original, *executor.exchanges])
    assert [item.exchange_id for item in resumed.exchanges] == expected_ids


@pytest.mark.asyncio
async def test_program_direct_http_request_blocks_unresolved_identity_before_backend_send(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    program = lab_engagement.model_copy(
        update={
            "selected_mode": EngagementMode.PROGRAM,
            "testing_accounts_secret_refs": {"alice": "test://accounts/alice"},
        }
    )
    executor = TypedActionExecutor(
        repository_root=repository_root,
        runtime_home=tmp_path / "runtime",
        artifact_root=tmp_path / "artifacts",
        engagement=program,
        run_id="run-program-direct-account-boundary",
        proxy=ProxySelection(
            backend=DirectProxyBackend(),
            requested="direct",
            selected="direct",
            ready=True,
            detail="test direct backend",
            attempted=(),
            receipt_path=str(tmp_path / "proxy-selection.json"),
        ),
    )
    calls: list[dict[str, object]] = []

    async def send(_engagement, method: str, url: str, **kwargs: object):
        calls.append({"method": method, "url": url, **kwargs})
        return make_exchange(
            exchange_id="exchange-program-direct-account-boundary",
            url=url,
            account=str(kwargs.get("account_alias") or "anonymous"),
        ).model_copy(update={"method": method})

    monkeypatch.setattr(executor.direct, "send", send)
    blocked = await executor.execute(
        _proposal(
            action_id="program-direct-unresolved-account",
            kind=ActionKind.HTTP_REQUEST,
            role=AgentRole.API_AUTH_SPECIALIST,
            skill="api-auth-session",
            target_url=program.root_targets[0].uri,
            method="GET",
            account_aliases=["alice"],
        )
    )
    assert blocked.status is ObservationStatus.BLOCKED
    assert blocked.details["request_sent"] is False
    assert "no resolved declared request headers" in blocked.details["reason"]
    assert calls == []

    executor.account_headers["alice"] = {"Authorization": "Fixture alice"}
    executed = await executor.execute(
        _proposal(
            action_id="program-direct-declared-account",
            kind=ActionKind.HTTP_REQUEST,
            role=AgentRole.API_AUTH_SPECIALIST,
            skill="api-auth-session",
            target_url=program.root_targets[0].uri,
            method="GET",
            account_aliases=["alice"],
        )
    )
    assert executed.status is ObservationStatus.EXECUTED
    assert calls == [
        {
            "method": "GET",
            "url": program.root_targets[0].uri,
            "headers": {"Authorization": "Fixture alice"},
            "content": None,
            "account_alias": "alice",
            "source": "direct",
        }
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("selected", ["caido", "burp", "zap"])
async def test_program_external_proxy_uses_credential_substitution_not_direct_reissue(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement,
    monkeypatch: pytest.MonkeyPatch,
    selected: str,
) -> None:
    """A stored Cookie is evidence only; it is never an outbound program credential."""

    program = lab_engagement.model_copy(
        update={
            "selected_mode": EngagementMode.PROGRAM,
            "testing_accounts_secret_refs": {"bob": "test://accounts/bob"},
        }
    )
    original = make_exchange(exchange_id=f"exchange-{selected}-history", account="bob").model_copy(
        update={
            "request_headers": {
                "Authorization": "Bearer historical-secret",
                "Cookie": "session=historical-secret",
                "X-History": "evidence-only",
            }
        }
    )
    backend = _HistoricalReplayBackend(original)
    backend.name = selected
    executor = TypedActionExecutor(
        repository_root=repository_root,
        runtime_home=tmp_path / "runtime",
        artifact_root=tmp_path / selected,
        engagement=program,
        run_id=f"run-program-{selected}",
        proxy=ProxySelection(
            backend=backend,
            requested=selected,
            selected=selected,
            ready=True,
            detail="test history backend",
            attempted=(),
            receipt_path=str(tmp_path / f"{selected}-proxy.json"),
        ),
        account_headers={"bob": {"Authorization": "Bearer declared-bob", "X-Account": "bob"}},
    )

    async def unexpected_direct(*_args: object, **_kwargs: object):
        raise AssertionError("live external proxy replay must not fall back to direct transport")

    monkeypatch.setattr(executor.direct, "replay_with_request", unexpected_direct)
    observation = await executor.execute(
        _proposal(
            action_id=f"program-{selected}-replay",
            kind=ActionKind.PROXY_REPLAY,
            role=AgentRole.AUTHORIZATION_SPECIALIST,
            skill="authz-business-logic",
            method="GET",
            base_exchange_id=original.exchange_id,
            account_aliases=["bob"],
        )
    )

    assert observation.status is ObservationStatus.EXECUTED
    assert backend.replay_calls == []
    assert len(backend.substituted_replay_calls) == 1
    request = backend.substituted_replay_calls[0]
    headers = request.headers
    assert headers == {"X-History": "evidence-only", "Authorization": "Bearer declared-bob", "X-Account": "bob"}
    assert "Cookie" not in headers
    assert all("historical-secret" not in value for value in headers.values())
    assert request.account_alias == "bob"
    assert observation.details["execution_backend"] == selected
    assert observation.details["credential_substitution"] is True


@pytest.mark.asyncio
async def test_program_har_history_is_honestly_direct_reissued_with_declared_account_headers(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    program = lab_engagement.model_copy(
        update={
            "selected_mode": EngagementMode.PROGRAM,
            "testing_accounts_secret_refs": {"bob": "test://accounts/bob"},
        }
    )
    original = make_exchange(exchange_id="exchange-har-history", account="bob").model_copy(
        update={"request_headers": {"Cookie": "session=historical-secret", "Connection": "keep-alive"}}
    )
    backend = _HistoricalReplayBackend(original)
    backend.name = "har"
    executor = TypedActionExecutor(
        repository_root=repository_root,
        runtime_home=tmp_path / "runtime",
        artifact_root=tmp_path / "har",
        engagement=program,
        run_id="run-program-har",
        proxy=ProxySelection(
            backend=backend,
            requested="har",
            selected="har",
            ready=True,
            detail="test HAR history backend",
            attempted=(),
            receipt_path=str(tmp_path / "har-proxy.json"),
        ),
        account_headers={"bob": {"Authorization": "Bearer declared-bob"}},
    )
    sent: list[CredentialSubstitutedReplay] = []

    async def direct_replay(_engagement, request: CredentialSubstitutedReplay):
        sent.append(request)
        return make_exchange(
            exchange_id="exchange-har-reissued",
            url=request.exchange.url,
            account=request.account_alias,
        )

    monkeypatch.setattr(executor.direct, "replay_with_request", direct_replay)
    observation = await executor.execute(
        _proposal(
            action_id="program-har-replay",
            kind=ActionKind.PROXY_REPLAY,
            role=AgentRole.AUTHORIZATION_SPECIALIST,
            skill="authz-business-logic",
            method="GET",
            base_exchange_id=original.exchange_id,
            account_aliases=["bob"],
        )
    )
    assert observation.status is ObservationStatus.EXECUTED
    assert len(sent) == 1
    assert sent[0].headers == {"Authorization": "Bearer declared-bob"}
    assert observation.details["execution_backend"] == "direct"
    assert observation.details["replay_source"] == "direct/har-history"


@pytest.mark.asyncio
async def test_program_proxy_replay_blocks_alias_mismatch_without_backend_or_direct_request(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    program = lab_engagement.model_copy(
        update={
            "selected_mode": EngagementMode.PROGRAM,
            "testing_accounts_secret_refs": {"alice": "test://accounts/alice", "bob": "test://accounts/bob"},
        }
    )
    original = make_exchange(exchange_id="exchange-history-alice", account="alice").model_copy(
        update={"request_headers": {"Cookie": "session=alice-history"}}
    )
    backend = _HistoricalReplayBackend(original)
    executor = TypedActionExecutor(
        repository_root=repository_root,
        runtime_home=tmp_path / "runtime",
        artifact_root=tmp_path / "blocked-replay",
        engagement=program,
        run_id="run-blocked-replay",
        proxy=ProxySelection(
            backend=backend,
            requested="har",
            selected="har",
            ready=True,
            detail="test history backend",
            attempted=(),
            receipt_path=str(tmp_path / "har-proxy.json"),
        ),
        account_headers={
            "alice": {"Authorization": "Bearer declared-alice"},
            "bob": {"Authorization": "Bearer declared-bob"},
        },
    )

    async def unexpected_direct(*_args: object, **_kwargs: object):
        raise AssertionError("blocked replay must not create a direct request")

    monkeypatch.setattr(executor.direct, "send", unexpected_direct)
    observation = await executor.execute(
        _proposal(
            action_id="program-alias-mismatch-replay",
            kind=ActionKind.PROXY_REPLAY,
            role=AgentRole.AUTHORIZATION_SPECIALIST,
            skill="authz-business-logic",
            method="GET",
            base_exchange_id=original.exchange_id,
            account_aliases=["bob"],
        )
    )

    assert observation.status is ObservationStatus.BLOCKED
    assert "exactly match" in observation.details["reason"]
    assert backend.replay_calls == []
    assert observation.exchange_ids == []


@pytest.mark.asyncio
async def test_program_external_proxy_without_credential_substitution_is_blocked_not_directly_reissued(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    program = lab_engagement.model_copy(
        update={
            "selected_mode": EngagementMode.PROGRAM,
            "testing_accounts_secret_refs": {"bob": "test://accounts/bob"},
        }
    )
    original = make_exchange(exchange_id="exchange-no-substitution", account="bob")
    backend = _HistoricalReplayBackend(original)
    backend.name = "burp"

    async def unavailable(*_args: object, **_kwargs: object):
        raise ProxyUnavailable("MCP edition has no explicit request sender")

    monkeypatch.setattr(backend, "replay_with_request", unavailable)
    executor = TypedActionExecutor(
        repository_root=repository_root,
        runtime_home=tmp_path / "runtime",
        artifact_root=tmp_path / "unsupported",
        engagement=program,
        run_id="run-proxy-no-substitution",
        proxy=ProxySelection(
            backend=backend,
            requested="burp",
            selected="burp",
            ready=True,
            detail="test unsupported sender",
            attempted=(),
            receipt_path=str(tmp_path / "burp-proxy.json"),
        ),
        account_headers={"bob": {"Authorization": "Bearer declared-bob"}},
    )

    async def unexpected_direct(*_args: object, **_kwargs: object):
        raise AssertionError("unsupported external proxy must not masquerade as direct replay")

    monkeypatch.setattr(executor.direct, "replay_with_request", unexpected_direct)
    observation = await executor.execute(
        _proposal(
            action_id="program-burp-no-substitution",
            kind=ActionKind.PROXY_REPLAY,
            role=AgentRole.AUTHORIZATION_SPECIALIST,
            skill="authz-business-logic",
            method="GET",
            base_exchange_id=original.exchange_id,
            account_aliases=["bob"],
        )
    )
    assert observation.status is ObservationStatus.BLOCKED
    assert "does not support credential-substituted replay" in observation.details["reason"]
    assert observation.details["execution_backend"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("receipt_status", "expected_status", "accepted"),
    [
        ("completed", ObservationStatus.EXECUTED, True),
        ("blocked", ObservationStatus.BLOCKED, False),
        ("failed", ObservationStatus.FAILED, False),
        ("timeout", ObservationStatus.FAILED, False),
    ],
)
async def test_tool_task_receipt_status_controls_execution_and_acceptance(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement,
    monkeypatch: pytest.MonkeyPatch,
    receipt_status: str,
    expected_status: ObservationStatus,
    accepted: bool,
) -> None:
    from budobugs.tools.wrapper import ToolRunner

    async def run_tool(_runner, _request, _engagement):
        return SimpleNamespace(status=receipt_status)

    monkeypatch.setattr(ToolRunner, "run", run_tool)
    executor = TypedActionExecutor(
        repository_root=repository_root,
        runtime_home=tmp_path / "runtime",
        artifact_root=tmp_path / receipt_status,
        engagement=lab_engagement,
        run_id=f"run-tool-{receipt_status}",
        proxy=ProxySelection(
            backend=DirectProxyBackend(),
            requested="direct",
            selected="direct",
            ready=True,
            detail="test direct backend",
            attempted=(),
            receipt_path=str(tmp_path / f"proxy-{receipt_status}.json"),
        ),
    )
    proposal = _proposal(
        action_id=f"tool-{receipt_status}",
        kind=ActionKind.TOOL_TASK,
        role=AgentRole.RECON_RESEARCHER,
        skill="passive-recon",
        tool_name="httpx",
        target_url=lab_engagement.root_targets[0].uri,
    )

    observation = await executor.execute(proposal)

    assert observation.status is expected_status
    assert observation.details["status"] == receipt_status
    assert _turn_executed_successfully(SimpleNamespace(proposal=proposal, observation=observation)) is accepted


def test_browser_artifact_suffix_rejects_path_injection(tmp_path: Path, lab_engagement) -> None:
    from budobugs.browser.session import BrowserSessionManager

    with pytest.raises(ValueError, match="safe filename"):
        BrowserSessionManager(tmp_path, lab_engagement, artifact_suffix="-../escape")


def test_browser_login_pause_marker_is_resume_stable(tmp_path: Path, lab_engagement) -> None:
    from budobugs.browser.session import BrowserSessionManager
    from budobugs.core.io import atomic_write_json

    manager = BrowserSessionManager(tmp_path, lab_engagement)
    assert not manager.has_completed_login("alice")
    (tmp_path / "alice" / "profile").mkdir(parents=True)
    atomic_write_json(tmp_path / "alice" / "login-complete.json", {"account_alias": "alice"})
    assert manager.has_completed_login("alice")


def _object_recipe(base: str, alias: str) -> SelfOwnedObjectRecipe:
    def action(action_id: str, method: str, path: str, statuses: list[int], body: object = None) -> SafeHttpAction:
        return SafeHttpAction(
            action_id=action_id,
            account_alias=alias,
            method=method,
            target_url=f"{base}{path}",
            body=body,
            expected_statuses=statuses,
        )

    return SelfOwnedObjectRecipe(
        recipe_id=f"{alias}-safe-object",
        account_alias=alias,
        object_description=f"one harmless {alias} fixture object",
        create=action(f"{alias}-create", "POST", f"/api/{alias}/objects", [201], {"label": f"{alias}-safe"}),
        verification=action(f"{alias}-verify", "GET", f"/api/{alias}/objects/safe", [200]),
        cleanup=action(f"{alias}-cleanup", "DELETE", f"/api/{alias}/objects/safe", [204]),
        cleanup_verification=action(f"{alias}-cleanup-verify", "GET", f"/api/{alias}/objects/safe", [404]),
    )


@pytest.mark.asyncio
async def test_program_browser_reuses_context_creates_two_declared_objects_and_cleans_up(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A run owns one manager, not one Chromium profile per typed action."""

    import budobugs.orchestration.executor as executor_module

    program = lab_engagement.model_copy(
        update={
            "selected_mode": EngagementMode.PROGRAM,
            "testing_accounts_secret_refs": {
                "alice": "keyring://engagement/program/account/alice",
                "bob": "keyring://engagement/program/account/bob",
            },
        }
    )

    class FakeBrowser:
        instances: list[FakeBrowser] = []

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self.calls: list[tuple[str, str]] = []
            self.stopped = False
            FakeBrowser.instances.append(self)

        async def explore(self, alias: str, url: str, **_kwargs: object) -> dict[str, object]:
            self.calls.append(("explore", alias))
            return {"visited_urls": [url], "discovered_urls": [], "created_harmless_objects": []}

        async def request_json(self, alias: str, *, method: str, url: str, **_kwargs: object) -> dict[str, object]:
            self.calls.append((method, alias))
            if method == "POST":
                status = 201
            elif method == "DELETE":
                status = 204
            elif (
                "cleanup-verify" in url
                or url.endswith("/safe")
                and any(item == ("DELETE", alias) for item in self.calls)
            ):
                status = 404
            else:
                status = 200
            return {"url": url, "method": method, "status": status, "response_preview": "fixture"}

        async def stop(self) -> None:
            self.stopped = True

        def has_completed_login(self, _alias: str) -> bool:
            return False

    monkeypatch.setattr(executor_module, "BrowserSessionManager", FakeBrowser)
    executor = TypedActionExecutor(
        repository_root=repository_root,
        runtime_home=tmp_path / "runtime",
        artifact_root=tmp_path / "artifacts",
        engagement=program,
        run_id="run-browser-lifecycle",
        proxy=ProxySelection(
            backend=DirectProxyBackend(),
            requested="direct",
            selected="direct",
            ready=True,
            detail="test direct backend",
            attempted=(),
            receipt_path=str(tmp_path / "proxy.json"),
        ),
        account_headers={"alice": {"X-Fixture": "alice"}, "bob": {"X-Fixture": "bob"}},
        self_owned_object_recipes=[
            _object_recipe(program.root_targets[0].uri, "alice"),
            _object_recipe(program.root_targets[0].uri, "bob"),
        ],
    )
    proposal = _proposal(
        action_id="program-two-account-browser",
        kind=ActionKind.BROWSER_EXPLORE,
        role=AgentRole.BROWSER_EXPLORER,
        skill="web-attack-surface",
        target_url=program.root_targets[0].uri,
        account_aliases=["alice", "bob"],
    )

    first = await executor.execute(proposal)
    second = await executor.execute(proposal.model_copy(update={"proposal_id": new_id("proposal")}))
    await executor.close_browser()

    assert first.details["self_owned_object_setup"] == {
        "alice": "CREATED_AND_VERIFIED",
        "bob": "CREATED_AND_VERIFIED",
    }
    assert second.details["self_owned_object_setup"] == {
        "alice": "REUSED_ACTIVE_OBJECT",
        "bob": "REUSED_ACTIVE_OBJECT",
    }
    assert len(FakeBrowser.instances) == 1
    browser = FakeBrowser.instances[0]
    assert browser.stopped is True
    assert browser.calls.count(("POST", "alice")) == 1
    assert browser.calls.count(("POST", "bob")) == 1
    assert browser.calls.count(("DELETE", "alice")) == 1
    assert browser.calls.count(("DELETE", "bob")) == 1
    ledger = json.loads((tmp_path / "artifacts" / "self-owned-objects" / "ledger.json").read_text(encoding="utf-8"))
    assert {item["state"] for item in ledger["objects"]} == {"CLEANED"}


@pytest.mark.asyncio
async def test_program_browser_mfa_pause_is_once_then_uses_persisted_context_across_turns(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import budobugs.orchestration.executor as executor_module

    program = lab_engagement.model_copy(
        update={
            "selected_mode": EngagementMode.PROGRAM,
            "testing_accounts_secret_refs": {"alice": "keyring://engagement/program/account/alice"},
        }
    )

    class Page:
        async def close(self) -> None:
            return None

    class FakeBrowser:
        paused = 0
        complete = False

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            return None

        def has_completed_login(self, _alias: str) -> bool:
            return FakeBrowser.complete

        async def pause_for_login(self, _alias: str, _url: str) -> Page:
            FakeBrowser.paused += 1
            FakeBrowser.complete = True
            return Page()

        async def explore(self, _alias: str, url: str, **_kwargs: object) -> dict[str, object]:
            return {"visited_urls": [url], "discovered_urls": [], "created_harmless_objects": []}

        async def stop(self) -> None:
            return None

    monkeypatch.setattr(executor_module, "BrowserSessionManager", FakeBrowser)
    executor = TypedActionExecutor(
        repository_root=repository_root,
        runtime_home=tmp_path / "runtime",
        artifact_root=tmp_path / "artifacts",
        engagement=program,
        run_id="run-browser-mfa",
        proxy=ProxySelection(DirectProxyBackend(), "direct", "direct", True, "test", (), str(tmp_path / "proxy.json")),
        account_login_urls={"alice": f"{program.root_targets[0].uri}/login"},
        interactive_login=True,
        headless=False,
    )
    proposal = _proposal(
        action_id="program-mfa-browser",
        kind=ActionKind.BROWSER_EXPLORE,
        role=AgentRole.BROWSER_EXPLORER,
        skill="web-attack-surface",
        target_url=program.root_targets[0].uri,
        account_aliases=["alice"],
    )

    first = await executor.execute(proposal)
    second = await executor.execute(proposal.model_copy(update={"proposal_id": new_id("proposal")}))
    await executor.close_browser()

    assert FakeBrowser.paused == 1
    assert first.details["identity_basis"] == {"alice": "interactive-login"}
    assert second.details["identity_basis"] == {"alice": "persisted-login"}


def test_self_owned_object_recipe_rejects_secret_request_headers_and_non_get_verification() -> None:
    base = "http://127.0.0.1:8765"
    recipe = _object_recipe(base, "alice")
    with pytest.raises(ValidationError, match="credentials"):
        recipe.model_copy(
            update={"create": recipe.create.model_copy(update={"headers": {"Authorization": "secret"}})}
        ).__class__.model_validate(
            {
                **recipe.model_dump(mode="json"),
                "create": {**recipe.create.model_dump(mode="json"), "headers": {"Authorization": "secret"}},
            }
        )
    with pytest.raises(ValidationError, match="verification must be GET"):
        SelfOwnedObjectRecipe.model_validate(
            {
                **recipe.model_dump(mode="json"),
                "verification": {**recipe.verification.model_dump(mode="json"), "method": "POST"},
            }
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind",
    [ActionKind.BROWSER_EXPLORE, ActionKind.BROWSER_NAVIGATE, ActionKind.BROWSER_FORM],
)
async def test_program_browser_actions_block_before_collecting_unauthenticated_account_evidence(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement,
    kind: ActionKind,
) -> None:
    program = lab_engagement.model_copy(
        update={
            "selected_mode": EngagementMode.PROGRAM,
            "testing_accounts_secret_refs": {"alice": "keyring://engagement/program/account/alice"},
        }
    )
    executor = TypedActionExecutor(
        repository_root=repository_root,
        runtime_home=tmp_path / "runtime",
        artifact_root=tmp_path / kind.value,
        engagement=program,
        run_id=f"run-program-browser-{kind.value}",
        proxy=ProxySelection(
            backend=DirectProxyBackend(),
            requested="direct",
            selected="direct",
            ready=True,
            detail="test direct backend",
            attempted=(),
            receipt_path=str(tmp_path / f"proxy-{kind.value}.json"),
        ),
        account_login_urls={"alice": f"{program.root_targets[0].uri}/login"},
    )
    values: dict[str, object] = {
        "target_url": program.root_targets[0].uri,
        "account_aliases": ["alice"],
    }
    if kind is ActionKind.BROWSER_FORM:
        values.update(mutation_scope="self-owned", tool_arguments={"fields": {}})
    observation = await executor.execute(
        _proposal(
            action_id=f"program-{kind.value}-without-login",
            kind=kind,
            role=AgentRole.BROWSER_EXPLORER,
            skill="web-attack-surface",
            **values,
        )
    )

    assert observation.status is ObservationStatus.BLOCKED
    assert observation.details["login_required"] == ["alice"]
    assert observation.details["authenticated_evidence_collected"] is False
    assert observation.exchange_ids == []
    assert not (tmp_path / kind.value / "browser" / "alice" / "profile").exists()


@pytest.mark.asyncio
async def test_program_browser_identity_accepts_declared_headers_persisted_login_and_completed_pause(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from budobugs.browser.session import BrowserSessionManager
    from budobugs.core.io import atomic_write_json

    program = lab_engagement.model_copy(
        update={
            "selected_mode": EngagementMode.PROGRAM,
            "testing_accounts_secret_refs": {"alice": "keyring://engagement/program/account/alice"},
        }
    )

    def executor(name: str, **values: object) -> TypedActionExecutor:
        return TypedActionExecutor(
            repository_root=repository_root,
            runtime_home=tmp_path / "runtime",
            artifact_root=tmp_path / name,
            engagement=program,
            run_id=f"run-{name}",
            proxy=ProxySelection(
                backend=DirectProxyBackend(),
                requested="direct",
                selected="direct",
                ready=True,
                detail="test direct backend",
                attempted=(),
                receipt_path=str(tmp_path / f"proxy-{name}.json"),
            ),
            **values,
        )

    header_executor = executor("declared-headers", account_headers={"alice": {"Authorization": "Fixture alice"}})
    header_manager = BrowserSessionManager(tmp_path / "declared-headers" / "browser", program)
    assert await header_executor._ensure_program_browser_identity(header_manager, "alice") == "declared-headers"

    persisted_executor = executor("persisted-login")
    persisted_root = tmp_path / "persisted-login" / "browser"
    (persisted_root / "alice" / "profile").mkdir(parents=True)
    atomic_write_json(persisted_root / "alice" / "login-complete.json", {"account_alias": "alice"})
    persisted_manager = BrowserSessionManager(persisted_root, program)
    assert await persisted_executor._ensure_program_browser_identity(persisted_manager, "alice") == "persisted-login"

    interactive_executor = executor(
        "interactive-login",
        account_login_urls={"alice": f"{program.root_targets[0].uri}/login"},
        interactive_login=True,
        headless=False,
    )
    interactive_root = tmp_path / "interactive-login" / "browser"
    interactive_manager = BrowserSessionManager(interactive_root, program, headless=False)

    class Page:
        async def close(self) -> None:
            return None

    async def complete_login(alias: str, _url: str) -> Page:
        (interactive_root / alias / "profile").mkdir(parents=True)
        atomic_write_json(interactive_root / alias / "login-complete.json", {"account_alias": alias})
        return Page()

    monkeypatch.setattr(interactive_manager, "pause_for_login", complete_login)
    assert (
        await interactive_executor._ensure_program_browser_identity(interactive_manager, "alice") == "interactive-login"
    )


def _safe_template(base: str) -> SafeExperimentTemplate:
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
    experiment = action("repeat-confirm", "POST", "/api/orders/1/confirm", [200]).model_copy(
        update={"operation_boundary": operation_boundary, "object_boundary": object_boundary}
    )
    negative = action("secure-repeat", "POST", "/api/secure-orders/1/confirm", [409]).model_copy(
        update={"operation_boundary": operation_boundary, "object_boundary": object_boundary}
    )
    return SafeExperimentTemplate(
        template_id="safe-boundary-001",
        specialist_role="business-logic-specialist",
        title="Repeated confirmation bypasses one-time workflow enforcement",
        vulnerability_class="business-logic-workflow",
        affected_feature="order confirmation workflow",
        security_invariant="A one-time confirmation must not execute twice.",
        root_cause_key="order-confirmation-idempotency",
        repair_boundary="enforce reviewed state and one-time effect in the shared confirmation service",
        capability_before="one self-owned order can be confirmed once",
        capability_after="the same self-owned order can trigger confirmation twice",
        capability_delta="one extra confirmation effect on a disposable self-owned order",
        strongest_benign_explanation="the endpoint may be intentionally idempotent without a second effect",
        impact="duplicate confirmation can repeat a protected business effect",
        normal_control=normal,
        experiment=experiment,
        negative_control=negative,
        effect_observation=normal.model_copy(update={"action_id": "observe-confirm-count"}),
        effect_json_pointer="/confirm_count",
        expected_effect_sequence=[0, 1, 2],
        cleanup=[action("reset-order", "POST", "/__fixture__/reset", [200])],
        cleanup_verification=normal.model_copy(update={"action_id": "verify-order-restored"}),
    )


def _safe_template_for_family(
    base: str,
    *,
    template_id: str,
    vulnerability_class: str,
    specialist_role: str,
    method: str,
    path: str,
) -> SafeExperimentTemplate:
    source = _safe_template(base)
    prefix = template_id.removeprefix("safe-")
    family_url = f"{base}{path}"
    normal_url = family_url if method == "GET" else source.normal_control.target_url
    experiment_url = family_url if method == "POST" else source.experiment.target_url
    normal = source.normal_control.model_copy(update={"action_id": f"{prefix}-normal", "target_url": normal_url})
    template = source.model_copy(
        update={
            "template_id": template_id,
            "specialist_role": specialist_role,
            "title": f"Safe controls for {vulnerability_class}",
            "vulnerability_class": vulnerability_class,
            "affected_feature": path,
            "normal_control": normal,
            "experiment": source.experiment.model_copy(
                update={"action_id": f"{prefix}-experiment", "target_url": experiment_url}
            ),
            "negative_control": source.negative_control.model_copy(update={"action_id": f"{prefix}-negative"}),
            "effect_observation": normal.model_copy(update={"action_id": f"{prefix}-effect"}),
            "cleanup": [source.cleanup[0].model_copy(update={"action_id": f"{prefix}-cleanup"})],
            "cleanup_verification": normal.model_copy(update={"action_id": f"{prefix}-verify"}),
        }
    )
    return SafeExperimentTemplate.model_validate(template.model_dump(mode="python"))


@pytest.mark.asyncio
async def test_program_safe_experiments_bind_only_matching_taxonomy_family(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement,
) -> None:
    program = lab_engagement.model_copy(
        update={
            "selected_mode": EngagementMode.PROGRAM,
            "testing_accounts_secret_refs": {"alice": "env://BUDOBUGS_TEST_ALICE"},
        }
    )
    base = program.root_targets[0].uri.rstrip("/")
    cases = [
        ("business", "business-logic-workflow", "business-logic-specialist", "POST", "/api/orders/1/confirm"),
        ("session", "authentication-session", "api-auth-specialist", "POST", "/api/session/1/revoke"),
        ("file", "file-share-authorization", "authorization-specialist", "POST", "/api/files/1/share"),
        ("cors", "cors-misconfiguration", "web-client-specialist", "POST", "/api/cors/transfer"),
        ("csrf", "csrf-protection-bypass", "web-client-specialist", "POST", "/api/csrf/transfer"),
        ("client", "client-side-trust", "web-client-specialist", "GET", "/api/render/1"),
    ]
    templates = [
        _safe_template_for_family(
            base,
            template_id=f"safe-{name}",
            vulnerability_class=vulnerability_class,
            specialist_role=role,
            method=method,
            path=path,
        )
        for name, vulnerability_class, role, method, path in cases
    ]
    templates.append(
        _safe_template_for_family(
            base,
            template_id="safe-unobserved",
            vulnerability_class="business-logic-workflow",
            specialist_role="business-logic-specialist",
            method="POST",
            path="/api/unobserved/1/confirm",
        )
    )
    executor = TypedActionExecutor(
        repository_root=repository_root,
        runtime_home=tmp_path / "runtime",
        artifact_root=tmp_path / "program-safe-template-matching",
        engagement=program,
        run_id="run-program-safe-template-matching",
        proxy=ProxySelection(
            backend=DirectProxyBackend(),
            requested="direct",
            selected="direct",
            ready=True,
            detail="test direct backend",
            attempted=(),
            receipt_path=str(tmp_path / "program-safe-template-matching-proxy.json"),
        ),
        account_headers={"alice": {"Authorization": "Fixture alice"}},
        safe_experiments=templates,
    )
    executor.ingest_exchanges(
        [
            make_exchange(
                exchange_id=f"exchange-safe-template-{name}",
                url=f"{base}{path}",
                account="alice",
            ).model_copy(
                update={
                    "engagement_id": program.engagement_id,
                    "method": method,
                    "request_body": '{"object_id":1}' if method == "POST" else None,
                }
            )
            for name, _vulnerability_class, _role, method, path in cases
        ]
    )
    observation = await executor.execute(
        _proposal(
            action_id="program-match-safe-templates",
            kind=ActionKind.TRAFFIC_MODEL,
            role=AgentRole.TRAFFIC_MODELER,
            skill="traffic-object-model",
        )
    )
    assert observation.status is ObservationStatus.EXECUTED
    assert executor.traffic_model is not None
    client_hypothesis = next(item for item in executor.hypotheses if item.vulnerability_class == "client-side-trust")
    assert executor._safe_http_template_matches_hypothesis(templates[5], client_hypothesis, executor.traffic_model)
    planned_template_ids = {item.safe_experiment_template_id for item in executor.program_validation_plans}
    assert {f"safe-{name}" for name, *_rest in cases} <= planned_template_ids
    assert "safe-unobserved" not in planned_template_ids
    hypotheses_by_id = {item.hypothesis_id: item for item in executor.hypotheses}
    plans_by_template = {
        item.safe_experiment_template_id: item
        for item in executor.program_validation_plans
        if item.safe_experiment_template_id is not None
    }
    for name, vulnerability_class, _role, _method, _path in cases:
        bound = plans_by_template[f"safe-{name}"]
        assert hypotheses_by_id[bound.hypothesis_id].vulnerability_class == vulnerability_class


def _bind_safe_program_plan(
    executor: TypedActionExecutor,
    template: SafeExperimentTemplate,
    candidate_id: str,
) -> None:
    executor.program_validation_plans.append(
        ProgramValidationPlan(
            plan_id=f"plan-{candidate_id}",
            hypothesis_id=candidate_id,
            endpoint_family_id="fixture-safe-experiment-family",
            validator_id=f"program-experiment--{template.template_id}",
            specialist_role=template.specialist_role,
            control_source="engagement-safe-experiment",
            control_ids=[
                template.normal_control.action_id,
                template.experiment.action_id,
                template.negative_control.action_id,
                template.cleanup_verification.action_id,
            ],
            safe_experiment_template_id=template.template_id,
        )
    )


def test_safe_http_action_requires_exact_case_insensitive_declared_response_headers() -> None:
    action = SafeHttpAction(
        action_id="cors-header-control",
        account_alias="alice",
        method="POST",
        target_url="http://127.0.0.1:8765/api/cors/transfer",
        expected_statuses=[200],
        expected_response_headers={
            "Access-Control-Allow-Origin": "https://evil.fixture.invalid",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    exchange = make_exchange().model_copy(
        update={
            "response_headers": {
                "access-control-allow-origin": "https://evil.fixture.invalid",
                "ACCESS-CONTROL-ALLOW-CREDENTIALS": "true",
            }
        }
    )
    assert TypedActionExecutor._safe_action_passes(exchange, action)
    assert not TypedActionExecutor._safe_action_passes(
        exchange.model_copy(update={"response_headers": {"access-control-allow-origin": "*"}}), action
    )


def test_websocket_validator_decision_fails_closed_for_missing_controls_and_kills_rejected_cross_object() -> None:
    def websocket(status: int, body: str = ""):
        return make_exchange().model_copy(update={"response_status": status, "response_body": body})

    confirmed = ValidatorRegistry._websocket_decision(
        websocket(101, '{"object":1}'),
        websocket(101, '{"object":2}'),
        websocket(101, '{"object":2}'),
        websocket(401),
    )
    killed = ValidatorRegistry._websocket_decision(
        websocket(101, '{"object":1}'), websocket(403), websocket(403), websocket(401)
    )
    held = ValidatorRegistry._websocket_decision(
        websocket(404), websocket(101, '{"object":2}'), websocket(101, '{"object":2}'), websocket(401)
    )
    assert confirmed == (CandidateDecision.CONFIRMED, True, True)
    assert killed == (CandidateDecision.KILL, False, True)
    assert held == (CandidateDecision.HOLD, False, False)


def test_safe_program_template_rejects_equivalent_negative_and_unrestorable_delete(
    lab_engagement,
) -> None:
    template = _safe_template(lab_engagement.root_targets[0].uri)
    duplicate_negative = template.model_dump(mode="python")
    duplicate_negative["negative_control"] = template.experiment.model_copy(
        update={"action_id": "negative-copy", "expected_statuses": [200]}
    )
    with pytest.raises(ValidationError, match="independent"):
        SafeExperimentTemplate.model_validate(duplicate_negative)

    unrelated_negative = template.model_dump(mode="python")
    unrelated_negative["negative_control"] = template.negative_control.model_copy(
        update={"object_boundary": "fixture-order:2"}
    )
    with pytest.raises(ValidationError, match="same operation and object"):
        SafeExperimentTemplate.model_validate(unrelated_negative)

    unrestorable_delete = template.model_dump(mode="python")
    unrestorable_delete["experiment"] = template.experiment.model_copy(update={"method": "DELETE"})
    unrestorable_delete["cleanup"] = [template.cleanup[0].model_copy(update={"method": "DELETE"})]
    with pytest.raises(ValidationError, match="non-DELETE restoration"):
        SafeExperimentTemplate.model_validate(unrestorable_delete)


@pytest.mark.asyncio
async def test_safe_program_mutation_stops_on_bad_baseline_and_persists_cleanup_after_failure(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    program = lab_engagement.model_copy(update={"selected_mode": EngagementMode.PROGRAM})
    template = _safe_template(program.root_targets[0].uri)
    candidate_id = "hypothesis-safe-boundary-001"

    def executor(name: str) -> TypedActionExecutor:
        value = TypedActionExecutor(
            repository_root=repository_root,
            runtime_home=tmp_path / "runtime",
            artifact_root=tmp_path / name,
            engagement=program,
            run_id=f"run-{name}",
            proxy=ProxySelection(
                backend=DirectProxyBackend(),
                requested="direct",
                selected="direct",
                ready=True,
                detail="test direct backend",
                attempted=(),
                receipt_path=str(tmp_path / f"{name}-proxy.json"),
            ),
            account_headers={"alice": {"Authorization": "Fixture alice"}},
            safe_experiments=[template],
        )
        _bind_safe_program_plan(value, template, candidate_id)
        return value

    baseline_executor = executor("bad-baseline")
    baseline_calls: list[str] = []

    async def bad_baseline(_engagement, method: str, url: str, **_kwargs: object):
        baseline_calls.append(method)
        return make_exchange(
            exchange_id="exchange-bad-baseline",
            url=url,
            status=409,
            account="alice",
            response='{"state":"unexpected"}',
        ).model_copy(update={"method": method})

    monkeypatch.setattr(baseline_executor.direct, "send", bad_baseline)
    baseline_observation = await baseline_executor.execute(
        _proposal(
            action_id="program-experiment--safe-boundary-001",
            kind=ActionKind.VALIDATOR_RUN,
            role=AgentRole.BUSINESS_LOGIC_SPECIALIST,
            skill="authz-business-logic",
            validator_id="program-experiment--safe-boundary-001",
            candidate_id=candidate_id,
            mutation_scope="self-owned",
        )
    )
    assert baseline_calls == ["GET"]
    assert baseline_observation.status is ObservationStatus.EXECUTED
    assert baseline_executor.validator_results[-1].outcome.decision is CandidateDecision.HOLD

    failed_executor = executor("failed-mutation")
    failure_calls: list[str] = []

    async def fail_first_mutation(_engagement, method: str, url: str, **_kwargs: object):
        failure_calls.append(method)
        if len(failure_calls) == 2:
            raise RuntimeError("bounded fixture mutation failed")
        response = '{"state":"draft"}' if method == "GET" else '{"status":"reset"}'
        return make_exchange(
            exchange_id=f"exchange-failure-{len(failure_calls)}",
            url=url,
            status=200,
            account="alice",
            response=response,
        ).model_copy(update={"method": method})

    monkeypatch.setattr(failed_executor.direct, "send", fail_first_mutation)
    failed_observation = await failed_executor.execute(
        _proposal(
            action_id="program-experiment--safe-boundary-001",
            kind=ActionKind.VALIDATOR_RUN,
            role=AgentRole.BUSINESS_LOGIC_SPECIALIST,
            skill="authz-business-logic",
            validator_id="program-experiment--safe-boundary-001",
            candidate_id=candidate_id,
            mutation_scope="self-owned",
        )
    )
    outcome = failed_executor.validator_results[-1].outcome
    assert failure_calls == ["GET", "POST", "POST", "GET"]
    assert failed_observation.status is ObservationStatus.EXECUTED
    assert outcome.decision is CandidateDecision.HOLD
    assert outcome.cleanup_completed
    assert Path(failed_observation.artifact_refs[0]).is_file()


@pytest.mark.asyncio
async def test_declared_safe_program_mutation_executes_controls_repeat_and_cleanup(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    program = lab_engagement.model_copy(update={"selected_mode": EngagementMode.PROGRAM})
    base = program.root_targets[0].uri

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
    experiment = action("repeat-confirm", "POST", "/api/orders/1/confirm", [200]).model_copy(
        update={"operation_boundary": operation_boundary, "object_boundary": object_boundary}
    )
    negative = action("secure-repeat", "POST", "/api/secure-orders/1/confirm", [409]).model_copy(
        update={"operation_boundary": operation_boundary, "object_boundary": object_boundary}
    )
    template = SafeExperimentTemplate(
        template_id="workflow-repeat-001",
        specialist_role="business-logic-specialist",
        title="Repeated confirmation bypasses one-time workflow enforcement",
        vulnerability_class="business-logic-workflow",
        affected_feature="order confirmation workflow",
        security_invariant="A one-time confirmation must not execute twice.",
        root_cause_key="order-confirmation-idempotency",
        repair_boundary="enforce reviewed state and one-time effect in the shared confirmation service",
        capability_before="one self-owned order can be confirmed once",
        capability_after="the same self-owned order can trigger confirmation twice",
        capability_delta="one extra confirmation effect on a disposable self-owned order",
        strongest_benign_explanation="the endpoint may be intentionally idempotent without a second effect",
        impact="duplicate confirmation can repeat a protected business effect",
        normal_control=normal,
        experiment=experiment,
        negative_control=negative,
        effect_observation=normal.model_copy(update={"action_id": "observe-confirm-count"}),
        effect_json_pointer="/confirm_count",
        expected_effect_sequence=[0, 1, 2],
        cleanup=[
            action("reset-order", "POST", "/__fixture__/reset", [200]).model_copy(
                update={"headers": {"X-Budo-Fixture": "reset-local-test-state"}}
            )
        ],
        cleanup_verification=normal.model_copy(update={"action_id": "verify-order-restored"}),
    )
    backend = DirectProxyBackend()
    executor = TypedActionExecutor(
        repository_root=repository_root,
        runtime_home=tmp_path / "runtime",
        artifact_root=tmp_path / "artifacts",
        engagement=program,
        run_id="run-safe-program-mutation",
        proxy=ProxySelection(
            backend=backend,
            requested="direct",
            selected="direct",
            ready=True,
            detail="test direct backend",
            attempted=(),
            receipt_path=str(tmp_path / "proxy-selection.json"),
        ),
        account_headers={"alice": {"Authorization": "Fixture alice"}},
        safe_experiments=[template],
    )
    candidate_id = "hypothesis-workflow-repeat-001"
    _bind_safe_program_plan(executor, template, candidate_id)
    calls: list[tuple[str, str]] = []
    confirm_count = 0

    async def send(_engagement, method: str, url: str, **kwargs: object):
        nonlocal confirm_count
        calls.append((method, url))
        status = 409 if "/secure-orders/" in url else 200
        if url.endswith("/api/orders/1/confirm"):
            confirm_count += 1
            response = f'{{"confirm_count":{confirm_count},"state":"confirmed"}}'
        elif url.endswith("/__fixture__/reset"):
            confirm_count = 0
            response = '{"status":"reset"}'
        elif url.endswith("/api/orders/1"):
            response = f'{{"confirm_count":{confirm_count},"state":"draft"}}'
        else:
            response = '{"detail":"reviewed one-time order required"}'
        return make_exchange(
            exchange_id=f"exchange-safe-mutation-{len(calls)}",
            url=url,
            status=status,
            account=str(kwargs.get("account_alias") or "alice"),
            response=response,
        ).model_copy(update={"method": method})

    monkeypatch.setattr(executor.direct, "send", send)
    observation = await executor.execute(
        _proposal(
            action_id="program-experiment--workflow-repeat-001",
            kind=ActionKind.VALIDATOR_RUN,
            role=AgentRole.BUSINESS_LOGIC_SPECIALIST,
            skill="authz-business-logic",
            validator_id="program-experiment--workflow-repeat-001",
            candidate_id=candidate_id,
            mutation_scope="self-owned",
        )
    )
    assert observation.status is ObservationStatus.EXECUTED
    assert [method for method, _url in calls] == ["GET", "POST", "GET", "POST", "GET", "POST", "POST", "GET"]
    assert executor.validator_results[-1].outcome.decision is CandidateDecision.CONFIRMED
    assert executor.validator_results[-1].outcome.cleanup_completed
    assert executor.validator_results[-1].outcome.normal_control_passed
    assert executor.validator_results[-1].outcome.negative_control_passed


@pytest.mark.asyncio
async def test_safe_program_status_only_repeat_is_killed_without_effect_delta(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    program = lab_engagement.model_copy(update={"selected_mode": EngagementMode.PROGRAM})
    template = _safe_template(program.root_targets[0].uri)
    executor = TypedActionExecutor(
        repository_root=repository_root,
        runtime_home=tmp_path / "runtime",
        artifact_root=tmp_path / "status-only",
        engagement=program,
        run_id="run-safe-status-only",
        proxy=ProxySelection(
            backend=DirectProxyBackend(),
            requested="direct",
            selected="direct",
            ready=True,
            detail="test direct backend",
            attempted=(),
            receipt_path=str(tmp_path / "status-only-proxy.json"),
        ),
        account_headers={"alice": {"Authorization": "Fixture alice"}},
        safe_experiments=[template],
    )
    candidate_id = "hypothesis-safe-status-only-001"
    _bind_safe_program_plan(executor, template, candidate_id)

    async def status_only(_engagement, method: str, url: str, **kwargs: object):
        status = 409 if "/secure-orders/" in url else 200
        response = '{"confirm_count":0,"state":"draft"}' if url.endswith("/api/orders/1") else '{"result":"bounded"}'
        return make_exchange(
            exchange_id=new_id("exchange-status-only"),
            url=url,
            status=status,
            account=str(kwargs.get("account_alias") or "alice"),
            response=response,
        ).model_copy(update={"method": method})

    monkeypatch.setattr(executor.direct, "send", status_only)
    observation = await executor.execute(
        _proposal(
            action_id="program-experiment--safe-boundary-001",
            kind=ActionKind.VALIDATOR_RUN,
            role=AgentRole.BUSINESS_LOGIC_SPECIALIST,
            skill="authz-business-logic",
            validator_id="program-experiment--safe-boundary-001",
            candidate_id=candidate_id,
            mutation_scope="self-owned",
        )
    )

    outcome = executor.validator_results[-1].outcome
    assert observation.status is ObservationStatus.EXECUTED
    assert outcome.decision is CandidateDecision.KILL
    assert not outcome.repeated
    assert outcome.cleanup_completed
