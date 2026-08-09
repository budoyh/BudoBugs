"""Policy-bound execution of typed agent actions with artifact receipts."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable
from pathlib import Path
from time import perf_counter
from typing import Any, Literal, cast
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from budobugs.browser.session import BrowserSessionManager, browser_artifact_paths
from budobugs.core.identifiers import new_id
from budobugs.core.io import atomic_write_json
from budobugs.core.policy import require_allowed, target_allowed, websocket_target_allowed
from budobugs.core.redaction import redact_headers
from budobugs.hypotheses.generator import generate_hypotheses
from budobugs.knowledge.vendor import RootCauseDeduper
from budobugs.models import (
    ActionKind,
    ActionProposal,
    AgentRole,
    CandidateDecision,
    CandidateStatus,
    ControlExperiment,
    Engagement,
    EngagementMode,
    Finding,
    HttpExchange,
    Hypothesis,
    Observation,
    ObservationStatus,
    Parameter,
    ProgramValidationPlan,
    RootCauseCluster,
    SafeExperimentTemplate,
    SafeHttpAction,
    SafeWebSocketAction,
    SafeWebSocketExperimentTemplate,
    SafeWorkflowExperimentTemplate,
    SelfOwnedObjectRecipe,
    Severity,
    ToolRequest,
    ValidationOutcome,
    VendorKnowledge,
)
from budobugs.models.base import utc_now
from budobugs.orchestration.multipart import build_harmless_multipart
from budobugs.orchestration.skill_runtime import SkillRuntime
from budobugs.orchestration.workflow import SafeWorkflowRunner, build_workflow_validator_result
from budobugs.proxy import DirectProxyBackend, ProxySelection
from budobugs.proxy.base import CredentialSubstitutedReplay, ProxyUnavailable
from budobugs.tools.registry import ToolRegistry
from budobugs.tools.wrapper import ToolRunner
from budobugs.traffic.importer import TrafficImportError, import_har
from budobugs.traffic.modeler import TrafficModel, build_traffic_model
from budobugs.traffic.normalization import normalized_json_structure, path_template
from budobugs.validation.executors import ValidatorRegistry, ValidatorResult


class TypedActionExecutor:
    """Execute only catalog-backed actions and preserve every observation boundary."""

    def __init__(
        self,
        *,
        repository_root: Path,
        runtime_home: Path,
        artifact_root: Path,
        engagement: Engagement,
        run_id: str,
        proxy: ProxySelection,
        account_headers: dict[str, dict[str, str]] | None = None,
        account_login_urls: dict[str, str] | None = None,
        safe_experiments: list[SafeExperimentTemplate | SafeWorkflowExperimentTemplate] | None = None,
        safe_websocket_experiments: list[SafeWebSocketExperimentTemplate] | None = None,
        self_owned_object_recipes: list[SelfOwnedObjectRecipe] | None = None,
        knowledge: VendorKnowledge | None = None,
        knowledge_saver: Callable[[VendorKnowledge], object] | None = None,
        interactive_login: bool = False,
        headless: bool = True,
    ) -> None:
        self.repository_root = repository_root.resolve()
        self.runtime_home = runtime_home.resolve()
        self.artifact_root = artifact_root.resolve()
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        self.engagement = engagement
        self.run_id = run_id
        self.proxy = proxy
        self.account_headers = account_headers or {}
        self.account_login_urls = account_login_urls or {}
        self.safe_experiments = safe_experiments or []
        self.safe_websocket_experiments = safe_websocket_experiments or []
        self.self_owned_object_recipes = self_owned_object_recipes or []
        self.knowledge = knowledge
        self.knowledge_saver = knowledge_saver
        self.interactive_login = interactive_login
        self.headless = headless
        self.skill_runtime = SkillRuntime(self.repository_root)
        self.validator_registry = ValidatorRegistry(
            self.artifact_root / "validators",
            private_root=self._private_browser_root() / "validators",
        )
        self.direct = DirectProxyBackend(timeout=20)
        self.exchanges: list[HttpExchange] = []
        self.exchange_ledger_path = self.artifact_root / "exchanges" / "ledger.json"
        self.validator_results: list[ValidatorResult] = []
        self.traffic_model: TrafficModel | None = None
        self.hypotheses: list[Hypothesis] = []
        self.program_validation_plans: list[ProgramValidationPlan] = []
        self._hypothesis_identity_ids: dict[str, str] = {}
        self.root_cause_clusters: list[RootCauseCluster] = []
        self.browser_artifacts: list[str] = []
        self._browser_manager: BrowserSessionManager | None = None
        self.self_owned_object_ledger_path = self.artifact_root / "self-owned-objects" / "ledger.json"
        self._self_owned_objects: dict[str, dict[str, object]] = {}
        self._restore_exchange_ledger()
        self._restore_artifacts()
        self._restore_self_owned_object_ledger()

    def ingest_exchanges(self, exchanges: list[HttpExchange]) -> None:
        """Seed the loop with verified imports captured before active exploration."""

        self._add_exchanges(exchanges)

    async def execute(self, proposal: ActionProposal) -> Observation:
        """Validate the Skill contract, execute one action, and persist its observation."""

        self.skill_runtime.validate(proposal)
        if proposal.target_url is not None:
            require_allowed(target_allowed(self.engagement, proposal.target_url))
        try:
            observation = await self._dispatch(proposal)
        except Exception as exc:
            observation = Observation(
                observation_id=new_id("observation"),
                proposal_id=proposal.proposal_id,
                round_index=proposal.round_index,
                status=ObservationStatus.FAILED,
                summary=f"{type(exc).__name__}: {str(exc)[:4000]}",
                information_gain=0,
                backend=self.proxy.selected,
                details={"error_type": type(exc).__name__},
            )
        path = self.artifact_root / "observations" / f"{proposal.catalog_action_id}.json"
        atomic_write_json(path, observation.model_dump(mode="json"))
        if str(path) not in observation.artifact_refs:
            observation.artifact_refs.append(str(path))
            atomic_write_json(path, observation.model_dump(mode="json"))
        return observation

    async def _dispatch(self, proposal: ActionProposal) -> Observation:
        if proposal.kind is ActionKind.PROXY_SEARCH:
            return await self._proxy_search(proposal)
        if proposal.kind is ActionKind.PROXY_REPLAY:
            return await self._proxy_replay(proposal)
        if proposal.kind is ActionKind.HTTP_REQUEST:
            return await self._http_request(proposal)
        if proposal.kind is ActionKind.BROWSER_EXPLORE:
            return await self._browser_explore(proposal)
        if proposal.kind is ActionKind.BROWSER_NAVIGATE:
            return await self._browser_navigate(proposal)
        if proposal.kind is ActionKind.BROWSER_FORM:
            return await self._browser_form(proposal)
        if proposal.kind is ActionKind.TRAFFIC_MODEL:
            return self._model_traffic(proposal)
        if proposal.kind is ActionKind.VALIDATOR_RUN:
            return await self._validator(proposal)
        if proposal.kind is ActionKind.EVIDENCE_REVIEW:
            return self._evidence_review(proposal)
        if proposal.kind is ActionKind.TOOL_TASK:
            return await self._tool_task(proposal)
        if proposal.kind is ActionKind.FINISH:
            return self._finish(proposal)
        raise ValueError(f"unsupported action kind: {proposal.kind.value}")

    async def _proxy_search(self, proposal: ActionProposal) -> Observation:
        items = await self.proxy.backend.search(self.engagement)
        self._add_exchanges(items)
        return self._observation(
            proposal,
            f"Selected {self.proxy.selected} backend returned {len(items)} scoped history exchanges.",
            gain=0.7 if items else 0.25,
            exchanges=items,
            artifacts=[self.proxy.receipt_path],
            details={
                "requested_backend": self.proxy.requested,
                "selected_backend": self.proxy.selected,
                "history_count": len(items),
                "capabilities": {
                    "history": self.proxy.backend.capabilities.history,
                    "replay": self.proxy.backend.capabilities.replay,
                    "export": self.proxy.backend.capabilities.export,
                    "credential_substitution_replay": (self.proxy.backend.capabilities.credential_substitution_replay),
                },
                "replayable_exchanges": self._replayable_exchange_details(items),
            },
        )

    async def _proxy_replay(self, proposal: ActionProposal) -> Observation:
        assert proposal.base_exchange_id is not None
        try:
            original = await self.proxy.backend.get(proposal.base_exchange_id)
        except KeyError as exc:
            if not isinstance(self.proxy.backend, DirectProxyBackend):
                raise
            fallback = next(
                (item for item in self.exchanges if item.exchange_id == proposal.base_exchange_id),
                None,
            )
            if fallback is None:
                raise KeyError(f"unknown exchange: {proposal.base_exchange_id}") from exc
            original = fallback
        require_allowed(target_allowed(self.engagement, original.url))
        if proposal.method is not None and proposal.method != original.method:
            raise ValueError("proxy replay method does not match the cataloged exchange")
        alias: str | None
        execution_backend: str
        replay_source: str
        credential_substitution = False
        if self.engagement.selected_mode is EngagementMode.PROGRAM:
            blocked_reason = self._program_replay_block_reason(proposal, original)
            if blocked_reason is not None:
                return self._blocked_replay_observation(proposal, original, blocked_reason)
            alias = proposal.account_aliases[0]
            request = CredentialSubstitutedReplay.build(
                original,
                account_alias=alias,
                declared_account_headers=self.account_headers[alias],
                proposal_headers=proposal.headers,
            )
            credential_substitution = True
            # HAR/trace are evidence stores, not native senders. Their replay
            # receipt must name the direct reissue honestly; configured live
            # proxy backends never silently fall back to direct transport.
            if self.proxy.backend.name in {"har", "playwright-trace"}:
                replayed = await self.direct.replay_with_request(self.engagement, request)
                execution_backend = "direct"
                replay_source = f"direct/{self.proxy.backend.name}-history"
            elif not self.proxy.backend.capabilities.credential_substitution_replay:
                return self._blocked_replay_observation(
                    proposal,
                    original,
                    f"{self.proxy.selected} does not advertise credential-substituted replay capability",
                )
            else:
                try:
                    replayed = await self.proxy.backend.replay_with_request(self.engagement, request)
                except ProxyUnavailable as exc:
                    return self._blocked_replay_observation(
                        proposal,
                        original,
                        f"{self.proxy.selected} does not support credential-substituted replay: {str(exc)[:500]}",
                    )
                execution_backend = self.proxy.backend.name
                replay_source = self.proxy.backend.name
        else:
            # LAB may exercise the fixture's native replay semantics, but its
            # result remains associated with the account captured in history;
            # a proposal must never relabel it as another account.
            if proposal.account_aliases and proposal.account_aliases != [original.account_alias]:
                return self._blocked_replay_observation(
                    proposal,
                    original,
                    "lab replay account alias must exactly match the history exchange",
                )
            alias = original.account_alias
            if isinstance(self.proxy.backend, DirectProxyBackend):
                headers = dict(self.account_headers.get(alias or "", {}))
                headers.update(proposal.headers)
                replayed = await self.direct.send(
                    self.engagement,
                    original.method,
                    original.url,
                    headers=headers,
                    content=original.request_body,
                    account_alias=alias,
                    source="direct",
                )
                execution_backend = "direct"
                replay_source = "direct"
            else:
                replayed = await self.proxy.backend.replay(self.engagement, original, account_alias=alias)
                execution_backend = self.proxy.backend.name
                replay_source = self.proxy.backend.name
        self._add_exchanges([replayed])
        return self._observation(
            proposal,
            f"Replayed one scoped {original.method} exchange through {self.proxy.selected}; "
            f"received HTTP {replayed.response_status}.",
            gain=0.7,
            exchanges=[replayed],
            state_changes=[proposal.mutation_scope] if original.method in {"POST", "PUT", "PATCH", "DELETE"} else [],
            details={
                "base_exchange_id": original.exchange_id,
                "account_alias": alias,
                "history_backend": self.proxy.backend.name,
                "execution_backend": execution_backend,
                "replay_source": replay_source,
                "credential_substitution": credential_substitution,
            },
        )

    def _program_replay_block_reason(self, proposal: ActionProposal, original: HttpExchange) -> str | None:
        """Return the precise policy failure for a credentialed program reissue."""

        if original.method not in {"GET", "OPTIONS"}:
            return "program replay only permits read-only GET or OPTIONS history exchanges"
        if len(proposal.account_aliases) != 1:
            return "program replay requires exactly one declared account alias"
        alias = proposal.account_aliases[0]
        if alias == "anonymous":
            return "program replay requires a declared self-owned account alias"
        if original.account_alias != alias:
            return "program replay account alias must exactly match the history exchange"
        if alias not in self.engagement.testing_accounts_secret_refs:
            return "program replay account alias is not declared by the engagement"
        if not self.account_headers.get(alias):
            return "program replay account has no resolved declared request headers"
        return None

    def _blocked_replay_observation(
        self,
        proposal: ActionProposal,
        original: HttpExchange,
        reason: str,
    ) -> Observation:
        return self._observation(
            proposal,
            f"Blocked proxy replay: {reason}.",
            gain=0.0,
            status=ObservationStatus.BLOCKED,
            details={
                "base_exchange_id": original.exchange_id,
                "history_account_alias": original.account_alias,
                "requested_account_aliases": proposal.account_aliases,
                "reason": reason,
                "credentialed_backend_replay": False,
                "execution_backend": None,
            },
        )

    async def _http_request(self, proposal: ActionProposal) -> Observation:
        assert proposal.target_url is not None
        assert proposal.method is not None
        if proposal.method in {"POST", "PUT", "PATCH", "DELETE"}:
            self._require_mutation_boundary(proposal)
        if self.engagement.selected_mode is EngagementMode.PROGRAM:
            blocked_reason = self._program_http_request_block_reason(proposal)
            if blocked_reason is not None:
                return self._observation(
                    proposal,
                    f"Blocked direct HTTP request: {blocked_reason}.",
                    gain=0.0,
                    status=ObservationStatus.BLOCKED,
                    details={
                        "reason": blocked_reason,
                        "requested_account_aliases": proposal.account_aliases,
                        "request_sent": False,
                    },
                )
        alias = proposal.account_aliases[0] if proposal.account_aliases else None
        headers = dict(self.account_headers.get(alias or "", {}))
        headers.update(proposal.headers)
        content: str | None = None
        if proposal.body is not None:
            content = json.dumps(proposal.body, ensure_ascii=False, separators=(",", ":"))
            headers.setdefault("Content-Type", "application/json")
        exchange = await self.direct.send(
            self.engagement,
            proposal.method,
            proposal.target_url,
            headers=headers,
            content=content,
            account_alias=alias,
            source="direct",
        )
        self._add_exchanges([exchange])
        return self._observation(
            proposal,
            f"Typed executor sent one scoped {proposal.method} request and received HTTP {exchange.response_status}.",
            gain=0.65,
            exchanges=[exchange],
            state_changes=([proposal.mutation_scope] if proposal.method in {"POST", "PUT", "PATCH", "DELETE"} else []),
        )

    def _program_http_request_block_reason(self, proposal: ActionProposal) -> str | None:
        """Require a resolved declared identity before a program direct reissue."""

        aliases = proposal.account_aliases
        if not aliases or aliases == ["anonymous"]:
            return None
        if len(aliases) != 1 or aliases[0] == "anonymous":
            return "program HTTP request requires exactly one declared account alias or anonymous access"
        alias = aliases[0]
        if alias not in self.engagement.testing_accounts_secret_refs:
            return "program HTTP request account alias is not declared by the engagement"
        if not self.account_headers.get(alias):
            return "program HTTP request account has no resolved declared request headers"
        return None

    async def _browser_explore(self, proposal: ActionProposal) -> Observation:
        assert proposal.target_url is not None
        browser_root = self.artifact_root / "browser"
        manager = self._browser()
        aliases = proposal.account_aliases or ["anonymous"]
        results: list[dict[str, object]] = []
        login_paused: list[str] = []
        login_reused: list[str] = []
        identity_basis: dict[str, str] = {}
        if self.engagement.selected_mode is EngagementMode.PROGRAM:
            for alias in aliases:
                basis = await self._ensure_program_browser_identity(manager, alias)
                if basis is None:
                    return self._browser_login_required(proposal, [alias])
                identity_basis[alias] = basis
                if basis == "interactive-login":
                    login_paused.append(alias)
                elif basis == "persisted-login":
                    login_reused.append(alias)
            object_setup = await self._ensure_program_self_owned_objects(manager, aliases)
        else:
            object_setup = {}
        for alias in aliases:
            start_url = proposal.target_url
            if self.engagement.selected_mode is EngagementMode.LAB and alias != "anonymous":
                login = urljoin(f"{proposal.target_url.rstrip('/')}/", f"login/{alias}")
                page = await manager.open(alias, login)
                await page.close()
                start_url = urljoin(f"{proposal.target_url.rstrip('/')}/", "app")
            results.append(
                await manager.explore(
                    alias,
                    start_url,
                    create_harmless_object=self.engagement.selected_mode is EngagementMode.LAB,
                )
            )
        artifacts = browser_artifact_paths(browser_root)
        for artifact in artifacts:
            if artifact not in self.browser_artifacts:
                self.browser_artifacts.append(artifact)
        imported: list[HttpExchange] = []
        for alias in aliases:
            har = self._browser_har_path(manager, alias)
            imported.extend(self._import_browser_har(har, alias))
        self._add_exchanges(imported)
        visited = [str(url) for result in results for url in self._string_list(result.get("visited_urls"))]
        discovered = self._safe_discovered_urls(
            [str(url) for result in results for url in self._string_list(result.get("discovered_urls"))]
        )
        created = [
            str(marker) for result in results for marker in self._string_list(result.get("created_harmless_objects"))
        ]
        return self._observation(
            proposal,
            f"Explored {len(set(visited))} pages in {len(aliases)} scoped persistent browser contexts; "
            f"captured {len(imported)} HAR exchanges and {len(artifacts)} browser artifacts.",
            gain=0.95 if imported else 0.5,
            exchanges=imported,
            artifacts=artifacts,
            discovered=discovered,
            state_changes=[f"created self-owned harmless object {item}" for item in created],
            details={
                "accounts": aliases,
                "visited_urls": list(dict.fromkeys(visited)),
                "har_exchange_count": len(imported),
                "artifact_count": len(artifacts),
                "login_paused_once": login_paused,
                "login_context_reused": login_reused,
                "identity_basis": identity_basis,
                "self_owned_object_setup": object_setup,
                "replayable_exchanges": (
                    self._replayable_exchange_details(imported)
                    if isinstance(self.proxy.backend, DirectProxyBackend)
                    else []
                ),
            },
        )

    async def _browser_navigate(self, proposal: ActionProposal) -> Observation:
        assert proposal.target_url is not None
        alias = proposal.account_aliases[0] if proposal.account_aliases else "anonymous"
        manager = self._browser()
        identity_basis = await self._ensure_program_browser_identity(manager, alias)
        if identity_basis is None:
            return self._browser_login_required(proposal, [alias])
        page = await manager.open(alias, proposal.target_url)
        shot = await manager.screenshot(alias, page, proposal.catalog_action_id)
        final_url = page.url
        await page.close()
        # Native HAR never becomes a public artifact.  Its in-memory model is
        # explicitly redacted before the ledger/observation boundary.
        imported = self._import_browser_har(self._browser_har_path(manager, alias), alias)
        self._add_exchanges(imported)
        artifacts = [str(shot)]
        self.browser_artifacts = list(dict.fromkeys([*self.browser_artifacts, *artifacts]))
        return self._observation(
            proposal,
            f"Navigated scoped browser context {alias} and captured its rendered state.",
            gain=0.55,
            exchanges=imported,
            artifacts=artifacts,
            discovered=self._safe_discovered_urls([final_url]),
            details={
                "account_alias": alias,
                "identity_basis": identity_basis,
                "replayable_exchanges": (
                    self._replayable_exchange_details(imported)
                    if isinstance(self.proxy.backend, DirectProxyBackend)
                    else []
                ),
            },
        )

    async def _browser_form(self, proposal: ActionProposal) -> Observation:
        assert proposal.target_url is not None
        self._require_mutation_boundary(proposal)
        alias = proposal.account_aliases[0] if proposal.account_aliases else "anonymous"
        raw_fields = proposal.tool_arguments.get("fields", {})
        if not isinstance(raw_fields, dict) or not all(
            isinstance(name, str) and isinstance(value, str) for name, value in raw_fields.items()
        ):
            raise ValueError("browser_form fields must be a string mapping")
        fields = {str(name): str(value) for name, value in raw_fields.items()}
        selector = proposal.tool_arguments.get("submit_selector", "button[type='submit']")
        if not isinstance(selector, str):
            raise ValueError("browser_form submit_selector must be a string")
        manager = self._browser()
        identity_basis = await self._ensure_program_browser_identity(manager, alias)
        if identity_basis is None:
            return self._browser_login_required(proposal, [alias])
        result = await manager.submit_form(
            alias,
            proposal.target_url,
            fields=fields,
            submit_selector=selector,
        )
        response_status = result["status"]
        if not isinstance(response_status, int):
            raise RuntimeError("browser form response status is invalid")
        # Native HAR never becomes a public artifact.  Its in-memory model is
        # explicitly redacted before the ledger/observation boundary.
        imported = self._import_browser_har(self._browser_har_path(manager, alias), alias)
        self._add_exchanges(imported)
        artifacts = [str(result["screenshot"])]
        self.browser_artifacts = list(dict.fromkeys([*self.browser_artifacts, *artifacts]))
        return self._observation(
            proposal,
            f"Submitted one typed self-owned form and observed HTTP {result['status']}.",
            gain=0.7,
            exchanges=imported,
            artifacts=artifacts,
            discovered=self._safe_discovered_urls([str(result["page_url"])]),
            state_changes=[proposal.mutation_scope],
            details={
                "response_status": response_status,
                "account_alias": alias,
                "identity_basis": identity_basis,
                "replayable_exchanges": (
                    self._replayable_exchange_details(imported)
                    if isinstance(self.proxy.backend, DirectProxyBackend)
                    else []
                ),
            },
        )

    def _model_traffic(self, proposal: ActionProposal) -> Observation:
        self.traffic_model = build_traffic_model(self.exchanges)
        path = self.artifact_root / "traffic" / "model.json"
        atomic_write_json(path, self.traffic_model.as_dict())
        model = self.traffic_model
        hypothesis_artifacts: list[str] = []
        if self.engagement.selected_mode is EngagementMode.PROGRAM:
            hypothesis_artifacts = self._refresh_program_hypotheses(model)
        return self._observation(
            proposal,
            f"Modeled {len(model.endpoint_families)} endpoint families, {len(model.objects)} object "
            f"references, {len(model.roles)} roles, {len(model.tenants)} tenants, and "
            f"{len(model.state_transitions)} state transitions.",
            gain=0.85 if model.endpoint_families else 0.2,
            artifacts=[str(path), *hypothesis_artifacts],
            details={
                "endpoint_families": len(model.endpoint_families),
                "objects": len(model.objects),
                "roles": len(model.roles),
                "tenants": len(model.tenants),
                "state_transitions": len(model.state_transitions),
                "graphql_or_schema_clues": len(model.api_schema_clues),
                "frontend_api_links": len(model.frontend_api_links),
                "generated_hypotheses": len(self.hypotheses),
                "executable_program_validation_plans": len(self.program_validation_plans),
                "unfinished_hypotheses": len(self.hypotheses) - len(self.program_validation_plans),
            },
        )

    def _refresh_program_hypotheses(self, model: TrafficModel) -> list[str]:
        invariants, hypotheses = generate_hypotheses(
            self.engagement.engagement_id,
            model,
            self.knowledge,
        )
        hypotheses = [
            item.model_copy(
                update={
                    "hypothesis_id": self._hypothesis_identity_ids.get(
                        self._hypothesis_identity(item, model),
                        item.hypothesis_id,
                    )
                }
            )
            for item in hypotheses
        ]
        identity_ids = {self._hypothesis_identity(item, model): item.hypothesis_id for item in hypotheses}
        plans = self._build_program_validation_plans(hypotheses, model)
        self.hypotheses.clear()
        self.hypotheses.extend(hypotheses)
        self.program_validation_plans.clear()
        self.program_validation_plans.extend(plans)
        self._hypothesis_identity_ids.clear()
        self._hypothesis_identity_ids.update(identity_ids)
        root = self.artifact_root / "hypotheses"
        hypotheses_path = root / "generated.json"
        invariants_path = root / "invariants.json"
        plans_path = root / "program-validation-plans.json"
        context_path = root / "generation-context.json"
        atomic_write_json(hypotheses_path, [item.model_dump(mode="json") for item in hypotheses])
        atomic_write_json(invariants_path, [item.model_dump(mode="json") for item in invariants])
        atomic_write_json(plans_path, [item.model_dump(mode="json") for item in plans])
        atomic_write_json(
            context_path,
            {
                "engagement_id": self.engagement.engagement_id,
                "vendor_key": self.knowledge.vendor_key if self.knowledge is not None else None,
                "knowledge_schema_version": self.knowledge.schema_version if self.knowledge is not None else None,
                "knowledge_outcome_prior_scopes": (
                    sorted(self.knowledge.outcome_priors) if self.knowledge is not None else []
                ),
                "generated_hypothesis_ids": [item.hypothesis_id for item in hypotheses],
                "executable_hypothesis_ids": [item.hypothesis_id for item in plans],
                "hypothesis_identity_ids": identity_ids,
            },
        )
        self._remember_unfinished_hypotheses(hypotheses, plans)
        return [str(hypotheses_path), str(invariants_path), str(plans_path), str(context_path)]

    @staticmethod
    def _hypothesis_identity(hypothesis: Hypothesis, model: TrafficModel) -> str:
        family = next(
            (item for item in model.endpoint_families if item.family_id == hypothesis.endpoint_family_id),
            None,
        )
        endpoint_selector: tuple[str, str, str] | str
        if family is None:
            endpoint_selector = hypothesis.endpoint_family_id
        else:
            endpoint_selector = (family.host, family.method, family.path_template)
        return json.dumps(
            [
                endpoint_selector,
                hypothesis.vulnerability_class,
                hypothesis.validator_id,
                hypothesis.protocol,
                hypothesis.parameter_location,
            ],
            ensure_ascii=False,
            separators=(",", ":"),
        )

    def _build_program_validation_plans(
        self,
        hypotheses: list[Hypothesis],
        model: TrafficModel,
    ) -> list[ProgramValidationPlan]:
        plans: list[ProgramValidationPlan] = []
        planned: set[str] = set()
        for hypothesis in hypotheses:
            binding = self._object_differential_controls(hypothesis, model)
            if binding is None:
                continue
            parameter, controls = binding
            family = next(item for item in model.endpoint_families if item.family_id == hypothesis.endpoint_family_id)
            plans.append(
                ProgramValidationPlan(
                    plan_id=new_id("program-plan"),
                    hypothesis_id=hypothesis.hypothesis_id,
                    endpoint_family_id=hypothesis.endpoint_family_id,
                    validator_id="program-authorization-differential",
                    specialist_role=AgentRole.AUTHORIZATION_SPECIALIST.value,
                    control_source="observed-object-differential",
                    control_ids=controls,
                    parameter_name=parameter.name,
                    parameter_location=cast("Literal['path', 'query', 'body', 'graphql']", parameter.location),
                    endpoint_host=family.host,
                    endpoint_method=cast("Literal['GET', 'POST']", family.method),
                    endpoint_path_template=family.path_template,
                    expected_information_gain=min(1.0, max(0.5, hypothesis.bounty_score / 1000)),
                )
            )
            planned.add(hypothesis.hypothesis_id)
        by_score = sorted(hypotheses, key=lambda item: (item.bounty_score, item.hypothesis_id), reverse=True)
        for template in self.safe_experiments:
            role = AgentRole(template.specialist_role)
            matched_hypothesis = next(
                (
                    item
                    for item in by_score
                    if item.hypothesis_id not in planned
                    and self._safe_http_template_matches_hypothesis(template, item, model)
                    and self._hypothesis_role(item) is role
                ),
                None,
            )
            if matched_hypothesis is None:
                continue
            plans.append(
                ProgramValidationPlan(
                    plan_id=new_id("program-plan"),
                    hypothesis_id=matched_hypothesis.hypothesis_id,
                    endpoint_family_id=matched_hypothesis.endpoint_family_id,
                    validator_id=(
                        f"program-workflow--{template.template_id}"
                        if isinstance(template, SafeWorkflowExperimentTemplate)
                        else f"program-experiment--{template.template_id}"
                    ),
                    specialist_role=template.specialist_role,
                    control_source="engagement-safe-experiment",
                    control_ids=(
                        [action.action_id for action in template.all_actions()]
                        if isinstance(template, SafeWorkflowExperimentTemplate)
                        else [
                            template.normal_control.action_id,
                            template.experiment.action_id,
                            template.negative_control.action_id,
                            template.effect_observation.action_id,
                            *[item.action_id for item in template.cleanup],
                            template.cleanup_verification.action_id,
                        ]
                    ),
                    safe_experiment_template_id=template.template_id,
                    expected_information_gain=template.expected_information_gain,
                )
            )
            planned.add(matched_hypothesis.hypothesis_id)
        for websocket_template in self.safe_websocket_experiments:
            matched_hypothesis = next(
                (
                    item
                    for item in by_score
                    if item.hypothesis_id not in planned
                    and self._safe_websocket_template_matches_hypothesis(websocket_template, item)
                ),
                None,
            )
            if matched_hypothesis is None:
                continue
            plans.append(
                ProgramValidationPlan(
                    plan_id=new_id("program-plan"),
                    hypothesis_id=matched_hypothesis.hypothesis_id,
                    endpoint_family_id=matched_hypothesis.endpoint_family_id,
                    validator_id=f"program-websocket-experiment--{websocket_template.template_id}",
                    specialist_role=websocket_template.specialist_role,
                    control_source="engagement-safe-experiment",
                    control_ids=[
                        websocket_template.normal_control.action_id,
                        websocket_template.experiment.action_id,
                        websocket_template.negative_control.action_id,
                    ],
                    safe_experiment_template_id=websocket_template.template_id,
                    expected_information_gain=websocket_template.expected_information_gain,
                )
            )
            planned.add(matched_hypothesis.hypothesis_id)
        return plans

    def _object_differential_controls(
        self,
        hypothesis: Hypothesis,
        model: TrafficModel,
    ) -> tuple[Parameter, list[str]] | None:
        if (
            hypothesis.validator_id != "authorization-differential"
            or hypothesis.parameter_location not in {"path", "query", "body", "graphql"}
            or len(self.account_headers) < 2
        ):
            return None
        family = next(
            (item for item in model.endpoint_families if item.family_id == hypothesis.endpoint_family_id),
            None,
        )
        if family is None:
            return None
        members = [item for item in self.exchanges if item.exchange_id in family.exchange_ids]
        if not self._program_read_only_family(family.method, members):
            return None
        for parameter in model.parameters.get(family.family_id, []):
            if parameter.location != hypothesis.parameter_location or not (
                parameter.dynamic_kind in {"id", "uuid"}
                or any(marker in parameter.name.lower() for marker in ("id", "uuid", "key", "file", "token"))
            ):
                continue
            by_alias: dict[str, tuple[str, str]] = {}
            for exchange in members:
                alias = exchange.account_alias
                value = self._program_parameter_value(exchange, parameter)
                if alias in self.account_headers and value is not None:
                    by_alias.setdefault(str(alias), (str(value), exchange.exchange_id))
            aliases = sorted(by_alias)
            for index, left_alias in enumerate(aliases):
                for right_alias in aliases[index + 1 :]:
                    left_value, left_exchange_id = by_alias[left_alias]
                    right_value, right_exchange_id = by_alias[right_alias]
                    if left_value != right_value:
                        return parameter, [left_exchange_id, right_exchange_id]
        return None

    @staticmethod
    def _safe_http_template_matches_hypothesis(
        template: SafeExperimentTemplate | SafeWorkflowExperimentTemplate,
        hypothesis: Hypothesis,
        model: TrafficModel,
    ) -> bool:
        if (
            not isinstance(template, SafeWorkflowExperimentTemplate)
            and hypothesis.vulnerability_class.casefold() != template.vulnerability_class.casefold()
        ):
            return False
        family = next(
            (item for item in model.endpoint_families if item.family_id == hypothesis.endpoint_family_id),
            None,
        )
        if family is None:
            return False
        actions = (
            template.all_actions()
            if isinstance(template, SafeWorkflowExperimentTemplate)
            else [
                template.normal_control,
                template.experiment,
                template.negative_control,
                template.effect_observation,
                *template.cleanup,
                template.cleanup_verification,
            ]
        )
        return any(
            action.method == family.method
            and urlsplit(action.target_url).netloc.casefold() == family.host.casefold()
            and path_template(action.target_url) == family.path_template
            for action in actions
        )

    @staticmethod
    def _safe_websocket_template_matches_hypothesis(
        template: SafeWebSocketExperimentTemplate,
        hypothesis: Hypothesis,
    ) -> bool:
        if (
            hypothesis.protocol != "websocket"
            or hypothesis.vulnerability_class.casefold() != template.vulnerability_class.casefold()
            or hypothesis.validator_id != "websocket-session-authorization"
        ):
            return False
        endpoint = hypothesis.endpoint_family_id.removeprefix("websocket:")
        parsed_endpoint = urlsplit(endpoint)
        return any(
            (
                urlsplit(action.target_url).scheme.casefold(),
                urlsplit(action.target_url).netloc.casefold(),
                urlsplit(action.target_url).path,
            )
            == (parsed_endpoint.scheme.casefold(), parsed_endpoint.netloc.casefold(), parsed_endpoint.path)
            for action in (template.normal_control, template.experiment, template.negative_control)
        )

    @staticmethod
    def _hypothesis_role(hypothesis: Hypothesis) -> AgentRole | None:
        mapping = {
            "authorization-differential": AgentRole.AUTHORIZATION_SPECIALIST,
            "vertical-authorization": AgentRole.AUTHORIZATION_SPECIALIST,
            "cross-tenant-authorization": AgentRole.AUTHORIZATION_SPECIALIST,
            "business-workflow": AgentRole.BUSINESS_LOGIC_SPECIALIST,
            "session-lifecycle": AgentRole.API_AUTH_SPECIALIST,
            "websocket-session-authorization": AgentRole.API_AUTH_SPECIALIST,
            "file-share-lifecycle": AgentRole.AUTHORIZATION_SPECIALIST,
            "cors-credentialed-origin": AgentRole.WEB_CLIENT_SPECIALIST,
            "csrf-token-bypass": AgentRole.WEB_CLIENT_SPECIALIST,
            "client-trust": AgentRole.WEB_CLIENT_SPECIALIST,
        }
        return mapping.get(hypothesis.validator_id or "")

    def _remember_unfinished_hypotheses(
        self,
        hypotheses: list[Hypothesis],
        plans: list[ProgramValidationPlan],
    ) -> None:
        if self.knowledge is None:
            return
        current_ids = {item.hypothesis_id for item in hypotheses}
        planned_ids = {item.hypothesis_id for item in plans}
        retained = [item for item in self.knowledge.unfinished_candidate_ids if item not in current_ids]
        self.knowledge.unfinished_candidate_ids = list(
            dict.fromkeys(
                [*retained, *(item.hypothesis_id for item in hypotheses if item.hypothesis_id not in planned_ids)]
            )
        )[-5000:]
        if self.knowledge_saver is not None:
            self.knowledge_saver(self.knowledge)

    async def _validator(self, proposal: ActionProposal) -> Observation:
        assert proposal.validator_id is not None
        if proposal.validator_id.startswith("fixture-"):
            results = await self.validator_registry.run(proposal.validator_id, self.engagement)
        else:
            results = await self._program_plan_validator(proposal)
        if proposal.candidate_id is not None and any(
            result.outcome.candidate_id != proposal.candidate_id for result in results
        ):
            raise RuntimeError("validator outcome candidate does not match its typed proposal hypothesis")
        for result in results:
            self._persist_validator_result(result)
        self.validator_results.extend(results)
        new_exchanges = [exchange for result in results for exchange in result.exchanges]
        self._add_exchanges(new_exchanges)
        outcomes = [result.outcome for result in results]
        decisions = {
            decision.value: sum(item.decision is decision for item in outcomes) for decision in CandidateDecision
        }
        candidates = [item.candidate_id for item in outcomes]
        artifacts = [item for result in results for item in result.artifact_refs]
        artifacts.extend(
            str(self._validator_path(result.outcome.validator_id, result.outcome.outcome_id)) for result in results
        )
        return self._observation(
            proposal,
            f"Executed validator {proposal.validator_id}: {decisions['CONFIRMED']} CONFIRMED, "
            f"{decisions['HOLD']} HOLD, {decisions['KILL']} KILL.",
            gain=max((item.confidence for item in outcomes), default=0.15),
            exchanges=new_exchanges,
            artifacts=artifacts,
            candidates=candidates,
            state_changes=[proposal.mutation_scope] if proposal.mutation_scope != "read-only" else [],
            details={"validator_id": proposal.validator_id, "decisions": decisions},
        )

    async def _program_plan_validator(self, proposal: ActionProposal) -> list[ValidatorResult]:
        if proposal.candidate_id is None or proposal.validator_id is None:
            raise ValueError("program validation requires a typed hypothesis candidate")
        plan = next(
            (
                item
                for item in self.program_validation_plans
                if item.hypothesis_id == proposal.candidate_id and item.validator_id == proposal.validator_id
            ),
            None,
        )
        if plan is None:
            raise ValueError("program validation proposal has no executable control plan")
        if plan.control_source == "engagement-safe-experiment":
            if proposal.validator_id.startswith("program-websocket-experiment--"):
                websocket_template = next(
                    (
                        item
                        for item in self.safe_websocket_experiments
                        if item.template_id == plan.safe_experiment_template_id
                    ),
                    None,
                )
                if websocket_template is None:
                    raise ValueError("program validation plan references an unavailable safe websocket experiment")
                return [await self._run_safe_websocket_program_experiment(websocket_template, proposal.candidate_id)]
            http_template = next(
                (item for item in self.safe_experiments if item.template_id == plan.safe_experiment_template_id),
                None,
            )
            if http_template is None:
                raise ValueError("program validation plan references an unavailable safe experiment")
            if isinstance(http_template, SafeWorkflowExperimentTemplate):
                return [await self._run_safe_program_workflow(http_template, proposal.candidate_id)]
            return [await self._run_safe_program_experiment(http_template, proposal.candidate_id)]
        model = self.traffic_model or build_traffic_model(self.exchanges)
        results = await self._program_object_differentials(
            model,
            endpoint_family_id=plan.endpoint_family_id,
            endpoint_host=plan.endpoint_host,
            endpoint_method=plan.endpoint_method,
            endpoint_path_template=plan.endpoint_path_template,
            parameter_name=plan.parameter_name,
            parameter_location=plan.parameter_location,
            control_exchange_ids=plan.control_ids,
            candidate_id=proposal.candidate_id,
        )
        if not results:
            raise RuntimeError("bound object-differential controls did not produce a closed validation outcome")
        return results

    async def _run_safe_program_workflow(
        self,
        template: SafeWorkflowExperimentTemplate,
        candidate_id: str | None = None,
    ) -> ValidatorResult:
        execution = await SafeWorkflowRunner(
            engagement=self.engagement,
            run_id=self.run_id,
            artifact_root=self.artifact_root,
            direct=self.direct,
            account_headers=self.account_headers,
        ).run(template)
        return build_workflow_validator_result(template, execution, self.engagement, candidate_id)

    async def _run_safe_program_experiment(
        self,
        template: SafeExperimentTemplate,
        candidate_id: str | None = None,
    ) -> ValidatorResult:
        """Execute an engagement-declared normal/repeat/negative/cleanup mutation contract."""

        all_exchanges: list[HttpExchange] = []
        cleanup_exchanges: list[HttpExchange] = []
        cleanup_errors: list[str] = []
        execution_errors: list[str] = []
        normal: HttpExchange | None = None
        experiments: list[HttpExchange] = []
        effect_observations: list[HttpExchange] = []
        negative: HttpExchange | None = None
        cleanup_verification: HttpExchange | None = None
        mutation_started = False
        normal_passed = False
        try:
            normal = await self._send_safe_http_action(template.normal_control)
            all_exchanges.append(normal)
            normal_passed = self._safe_action_passes(normal, template.normal_control)
            if not normal_passed:
                execution_errors.append(
                    f"{template.normal_control.action_id}: normal control returned HTTP {normal.response_status}"
                )
            else:
                mutation_started = True
                for _ in range(template.repeat_count):
                    exchange = await self._send_safe_http_action(template.experiment)
                    experiments.append(exchange)
                    all_exchanges.append(exchange)
                    effect = await self._send_safe_http_action(template.effect_observation)
                    effect_observations.append(effect)
                    all_exchanges.append(effect)
                negative = await self._send_safe_http_action(template.negative_control)
                all_exchanges.append(negative)
        except Exception as exc:
            execution_errors.append(f"{type(exc).__name__}: {str(exc)[:300]}")
        finally:
            for action in template.cleanup if mutation_started else []:
                try:
                    exchange = await self._send_safe_http_action(action)
                except Exception as exc:
                    cleanup_errors.append(f"{action.action_id}: {type(exc).__name__}: {str(exc)[:300]}")
                    continue
                cleanup_exchanges.append(exchange)
                all_exchanges.append(exchange)
            if mutation_started:
                try:
                    cleanup_verification = await self._send_safe_http_action(template.cleanup_verification)
                except Exception as exc:
                    cleanup_errors.append(
                        f"{template.cleanup_verification.action_id}: {type(exc).__name__}: {str(exc)[:300]}"
                    )
                else:
                    all_exchanges.append(cleanup_verification)
        experiment_statuses_passed = len(experiments) == template.repeat_count and all(
            self._safe_action_passes(item, template.experiment) for item in experiments
        )
        if template.repeat_relation == "same-response" and experiments:
            first_content = self._comparable_content(experiments[0].response_body)
            repeat_transport_passed = experiment_statuses_passed and all(
                self._comparable_content(item.response_body) == first_content for item in experiments[1:]
            )
        else:
            repeat_transport_passed = experiment_statuses_passed
        effect_values: list[object] = []
        effect_observable = (
            normal is not None
            and len(effect_observations) == template.repeat_count
            and all(self._safe_action_passes(item, template.effect_observation) for item in effect_observations)
        )
        if effect_observable and normal is not None:
            for exchange in [normal, *effect_observations]:
                found, value = self._json_pointer_value(exchange.response_body, template.effect_json_pointer)
                if not found:
                    effect_observable = False
                    effect_values = []
                    break
                effect_values.append(value)
        effect_proven = effect_observable and effect_values == list(template.expected_effect_sequence)
        repeated = repeat_transport_passed and effect_proven
        negative_expected = negative is not None and self._safe_action_passes(negative, template.negative_control)
        if template.negative_relation == "deny-status":
            negative_passed = bool(
                negative_expected and negative is not None and 400 <= negative.response_status <= 499
            )
        elif template.negative_relation == "different-response":
            negative_passed = bool(
                negative_expected
                and negative is not None
                and experiments
                and (
                    negative.response_status != experiments[0].response_status
                    or self._comparable_content(negative.response_body)
                    != self._comparable_content(experiments[0].response_body)
                )
            )
        else:
            negative_passed = bool(
                negative_expected
                and negative is not None
                and normal is not None
                and negative.response_status == normal.response_status
                and self._comparable_content(negative.response_body) == self._comparable_content(normal.response_body)
            )
        cleanup_actions_passed = len(cleanup_exchanges) == len(template.cleanup) and all(
            self._safe_action_passes(exchange, action)
            for exchange, action in zip(cleanup_exchanges, template.cleanup, strict=False)
        )
        cleanup_verification_passed = bool(
            normal is not None
            and cleanup_verification is not None
            and self._safe_action_passes(cleanup_verification, template.cleanup_verification)
            and cleanup_verification.response_status == normal.response_status
            and self._comparable_content(cleanup_verification.response_body)
            == self._comparable_content(normal.response_body)
        )
        cleanup_completed = (
            not mutation_started or not cleanup_errors and cleanup_actions_passed and cleanup_verification_passed
        )
        controls_closed = not execution_errors and normal_passed and negative_passed and cleanup_completed
        if controls_closed and repeated:
            decision = CandidateDecision.CONFIRMED
            confidence = 0.95
            status = CandidateStatus.VALIDATING
            capability_delta = template.capability_delta
            severity = template.severity
        elif controls_closed and repeat_transport_passed and effect_observable:
            decision = CandidateDecision.KILL
            confidence = 0.9
            status = CandidateStatus.KILL
            capability_delta = "none; the observed effect sequence did not match the declared capability increment"
            severity = Severity.INFO
        else:
            decision = CandidateDecision.HOLD
            confidence = 0.3
            status = CandidateStatus.HOLD
            capability_delta = "none; one or more declared controls or cleanup checks did not close"
            severity = Severity.INFO
        controls = [
            ControlExperiment(
                control_id=new_id("control"),
                kind="normal",
                description=f"Execute declared normal control {template.normal_control.action_id}.",
                request_exchange_ids=[normal.exchange_id] if normal is not None else [],
                observed_result=(
                    f"HTTP {normal.response_status}; expected {template.normal_control.expected_statuses}"
                    if normal is not None
                    else "normal control did not return an exchange"
                ),
                supports_finding=normal_passed,
            ),
            ControlExperiment(
                control_id=new_id("control"),
                kind="negative",
                description=f"Execute declared negative control {template.negative_control.action_id}.",
                request_exchange_ids=[negative.exchange_id] if negative is not None else [],
                observed_result=(
                    f"HTTP {negative.response_status}; expected {template.negative_control.expected_statuses}; "
                    f"relation={template.negative_relation}"
                    if negative is not None
                    else "negative control was not reached"
                ),
                supports_finding=negative_passed,
            ),
            ControlExperiment(
                control_id=new_id("control"),
                kind="refutation",
                description=(
                    f"Repeat declared mutation {template.experiment.action_id} exactly {template.repeat_count} times "
                    "and measure the protected effect after every request."
                ),
                request_exchange_ids=[
                    item.exchange_id for pair in zip(experiments, effect_observations, strict=False) for item in pair
                ],
                observed_result=(
                    f"statuses={[item.response_status for item in experiments]}; "
                    f"relation={template.repeat_relation}; pointer={template.effect_json_pointer}; "
                    f"effect_values={effect_values}; expected={template.expected_effect_sequence}; "
                    f"effect_observable={effect_observable}; passed={repeated}"
                ),
                supports_finding=repeated,
            ),
            ControlExperiment(
                control_id=new_id("control"),
                kind="refutation",
                description="Execute every engagement-declared cleanup lifecycle action.",
                request_exchange_ids=[item.exchange_id for item in cleanup_exchanges]
                + ([cleanup_verification.exchange_id] if cleanup_verification is not None else []),
                observed_result=(
                    f"statuses={[item.response_status for item in cleanup_exchanges]}; "
                    f"verification={cleanup_verification.response_status if cleanup_verification else None}; "
                    f"errors={cleanup_errors}; passed={cleanup_completed}"
                ),
                supports_finding=cleanup_completed,
            ),
            ControlExperiment(
                control_id=new_id("control"),
                kind="refutation",
                description="Record any request failure and prove that mutation stopped or cleanup still ran.",
                request_exchange_ids=[item.exchange_id for item in all_exchanges],
                observed_result=f"mutation_started={mutation_started}; errors={execution_errors}",
                supports_finding=not execution_errors,
            ),
        ]
        parsed = urlsplit(template.experiment.target_url)
        endpoint = f"{template.experiment.method} {parsed.path}"
        finding = Finding(
            finding_id=new_id("finding"),
            engagement_id=self.engagement.engagement_id,
            title=template.title if decision is CandidateDecision.CONFIRMED else f"{decision.value}: {template.title}",
            vulnerability_class=template.vulnerability_class,
            affected_asset=urlunsplit((parsed.scheme, parsed.netloc, "", "", "")),
            affected_feature=template.affected_feature,
            endpoint_family=endpoint,
            attacker_prerequisites=[
                f"declared self-owned account {template.experiment.account_alias}",
                "engagement-declared exact safe experiment template",
            ],
            victim_conditions=["only disposable self-owned test data is used"],
            security_invariant=template.security_invariant,
            protected_asset="self-owned disposable test object and its declared lifecycle",
            trust_boundary="engagement-declared accounts, exact URLs, bodies, statuses, and cleanup actions",
            enforcement_point=template.affected_feature,
            observed_behavior=(
                f"normal={normal.response_status if normal else None}; repeated mutation statuses="
                f"{[item.response_status for item in experiments]}; "
                f"effect pointer {template.effect_json_pointer} values={effect_values}; "
                f"negative={negative.response_status if negative else None}; "
                f"cleanup={[item.response_status for item in cleanup_exchanges]}; "
                f"cleanup_verification={cleanup_verification.response_status if cleanup_verification else None}; "
                f"errors={execution_errors + cleanup_errors}"
            ),
            expected_behavior=(
                "The declared negative control or repeated exploit relation must prevent the capability gain."
            ),
            capability_before=template.capability_before,
            capability_after=(
                template.capability_after if decision is CandidateDecision.CONFIRMED else template.capability_before
            ),
            capability_delta=capability_delta,
            normal_control=(
                f"{template.normal_control.action_id} returned HTTP {normal.response_status}."
                if normal is not None
                else f"{template.normal_control.action_id} did not return an exchange."
            ),
            negative_control=(
                f"{template.negative_control.action_id} returned HTTP {negative.response_status} "
                f"under relation {template.negative_relation}."
                if negative is not None
                else f"{template.negative_control.action_id} was not reached."
            ),
            strongest_benign_explanation=template.strongest_benign_explanation,
            refutation_attempts=[
                "fresh normal control",
                f"exact mutation repeated {template.repeat_count} times",
                "machine-checked effect sequence after every mutation",
                "declared negative control",
                "full cleanup lifecycle",
            ],
            reproduction_steps=[
                f"Execute normal control {template.normal_control.action_id}.",
                f"Execute mutation {template.experiment.action_id} exactly {template.repeat_count} times, "
                f"running {template.effect_observation.action_id} after each request.",
                f"Verify JSON pointer {template.effect_json_pointer} equals "
                f"{template.expected_effect_sequence} from baseline through the final repeat.",
                f"Execute negative control {template.negative_control.action_id}.",
                "Execute every cleanup action and verify its expected status.",
                f"Repeat normal control as cleanup verification {template.cleanup_verification.action_id}.",
            ],
            requests=[],
            responses=[],
            data_exposure_scope="Only exact objects and accounts declared in the safe experiment template.",
            mutation_scope=(
                f"Self-owned {template.experiment.method} experiment with exact normal/negative controls and cleanup."
            ),
            cleanup_status=(
                "No mutation executed because the normal control failed; cleanup was not required."
                if not mutation_started
                else "All declared cleanup actions completed and the original normal response was restored."
                if cleanup_completed
                else "Cleanup incomplete: " + "; ".join(cleanup_errors or ["post-cleanup state differs from baseline"])
            ),
            impact=template.impact
            if decision is CandidateDecision.CONFIRMED
            else "No reportable capability increment.",
            severity=severity,
            confidence=confidence,
            duplicate_risk=f"Deduplicate by repair boundary: {template.repair_boundary}",
            status=status,
        )
        outcome = ValidationOutcome(
            outcome_id=new_id("validation"),
            validator_id=f"program-experiment--{template.template_id}",
            candidate_id=candidate_id or new_id("candidate"),
            decision=decision,
            vulnerability_class=template.vulnerability_class,
            title=finding.title,
            affected_feature=template.affected_feature,
            root_cause_key=template.root_cause_key,
            repair_boundary=template.repair_boundary,
            finding_id=finding.finding_id,
            control_ids=[item.control_id for item in controls],
            exchange_ids=[item.exchange_id for item in all_exchanges],
            capability_delta=capability_delta,
            strongest_benign_explanation=template.strongest_benign_explanation,
            repeated=repeated,
            normal_control_passed=normal_passed,
            negative_control_passed=negative_passed,
            cleanup_completed=cleanup_completed,
            evidence_closed=decision in {CandidateDecision.CONFIRMED, CandidateDecision.KILL},
            confidence=confidence,
        )
        return ValidatorResult(outcome, finding, controls, all_exchanges, [])

    async def _run_safe_websocket_program_experiment(
        self,
        template: SafeWebSocketExperimentTemplate,
        candidate_id: str | None = None,
    ) -> ValidatorResult:
        """Run one declared browser WebSocket normal/repeat/negative contract.

        Frames are evaluated in memory and never copied to exchanges or
        artifacts.  This lets a report prove handshake/event/predicate closure
        while preserving the same no-third-party-data evidence boundary used by
        the browser explorer.
        """

        exchanges: list[HttpExchange] = []
        artifacts: list[str] = []
        errors: list[str] = []
        normal: tuple[HttpExchange, dict[str, object]] | None = None
        repeats: list[tuple[HttpExchange, dict[str, object]]] = []
        negative: tuple[HttpExchange, dict[str, object]] | None = None
        try:
            normal = await self._send_safe_websocket_action(template.normal_control)
            exchanges.append(normal[0])
            artifacts.extend(self._websocket_artifact_refs(normal[1]))
            for _ in range(template.repeat_count):
                item = await self._send_safe_websocket_action(template.experiment)
                repeats.append(item)
                exchanges.append(item[0])
                artifacts.extend(self._websocket_artifact_refs(item[1]))
            negative = await self._send_safe_websocket_action(template.negative_control)
            exchanges.append(negative[0])
            artifacts.extend(self._websocket_artifact_refs(negative[1]))
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {str(exc)[:300]}")

        normal_passed = normal is not None and self._safe_websocket_action_passes(normal[1], template.normal_control)
        repeated = len(repeats) == template.repeat_count and all(
            self._safe_websocket_action_passes(result, template.experiment) for _, result in repeats
        )
        negative_passed = negative is not None and self._safe_websocket_action_passes(
            negative[1], template.negative_control
        )
        repeat_messages_received = len(repeats) == template.repeat_count and all(
            result.get("opened") is True and result.get("event") == "message" for _, result in repeats
        )
        controls_closed = not errors and normal_passed and negative_passed
        if controls_closed and repeated:
            decision = CandidateDecision.CONFIRMED
            confidence = 0.95
            status = CandidateStatus.VALIDATING
            capability_delta = template.capability_delta
            severity = template.severity
        elif controls_closed and repeat_messages_received:
            decision = CandidateDecision.KILL
            confidence = 0.9
            status = CandidateStatus.KILL
            capability_delta = "none; repeated WebSocket messages did not satisfy the declared capability predicate"
            severity = Severity.INFO
        else:
            decision = CandidateDecision.HOLD
            confidence = 0.3
            status = CandidateStatus.HOLD
            capability_delta = "none; one or more declared WebSocket controls did not close"
            severity = Severity.INFO

        def result_summary(result: dict[str, object] | None) -> str:
            if result is None:
                return "not reached"
            return (
                f"opened={result.get('opened')}; event={result.get('event')}; "
                f"close_code={result.get('close_code')}; predicate={result.get('json_predicate_matched')}"
            )

        normal_exchange = normal[0] if normal is not None else None
        negative_exchange = negative[0] if negative is not None else None
        controls = [
            ControlExperiment(
                control_id=new_id("control"),
                kind="normal",
                description=f"Open declared normal WebSocket {template.normal_control.action_id}.",
                request_exchange_ids=[normal_exchange.exchange_id] if normal_exchange is not None else [],
                observed_result=result_summary(normal[1] if normal is not None else None),
                supports_finding=normal_passed,
            ),
            ControlExperiment(
                control_id=new_id("control"),
                kind="negative",
                description=f"Open declared denied WebSocket control {template.negative_control.action_id}.",
                request_exchange_ids=[negative_exchange.exchange_id] if negative_exchange is not None else [],
                observed_result=result_summary(negative[1] if negative is not None else None),
                supports_finding=negative_passed,
            ),
            ControlExperiment(
                control_id=new_id("control"),
                kind="refutation",
                description=(
                    f"Repeat exact WebSocket experiment {template.experiment.action_id} {template.repeat_count} times."
                ),
                request_exchange_ids=[exchange.exchange_id for exchange, _ in repeats],
                observed_result=(
                    f"repeat_count={len(repeats)}; expected={template.repeat_count}; "
                    f"messages_received={repeat_messages_received}; predicate_passed={repeated}"
                ),
                supports_finding=repeated,
            ),
            ControlExperiment(
                control_id=new_id("control"),
                kind="refutation",
                description="Every WebSocket was closed by the browser before its durable receipt was emitted.",
                request_exchange_ids=[item.exchange_id for item in exchanges],
                observed_result=f"errors={errors}; durable_frame_payloads=false",
                supports_finding=not errors,
            ),
        ]
        parsed = urlsplit(template.experiment.target_url)
        asset_scheme = "https" if parsed.scheme == "wss" else "http"
        affected_asset = urlunsplit((asset_scheme, parsed.netloc, "", "", ""))
        finding = Finding(
            finding_id=new_id("finding"),
            engagement_id=self.engagement.engagement_id,
            title=template.title if decision is CandidateDecision.CONFIRMED else f"{decision.value}: {template.title}",
            vulnerability_class=template.vulnerability_class,
            affected_asset=affected_asset,
            affected_feature=template.affected_feature,
            endpoint_family=f"WEBSOCKET {parsed.path}",
            attacker_prerequisites=[
                f"declared self-owned account {template.experiment.account_alias}",
                "engagement-declared exact WebSocket experiment template",
            ],
            victim_conditions=["only declared local/self-owned test accounts and object identifiers are used"],
            security_invariant=template.security_invariant,
            protected_asset="message-level authorization boundary for declared self-owned test objects",
            trust_boundary="persistent account browser context and engagement-declared WS/WSS URLs",
            enforcement_point=template.affected_feature,
            observed_behavior=(
                f"normal={result_summary(normal[1] if normal else None)}; "
                f"repeats={[result_summary(item) for _, item in repeats]}; "
                f"negative={result_summary(negative[1] if negative else None)}; errors={errors}"
            ),
            expected_behavior="The negative WebSocket endpoint must close without an authorized message.",
            capability_before=template.capability_before,
            capability_after=(
                template.capability_after if decision is CandidateDecision.CONFIRMED else template.capability_before
            ),
            capability_delta=capability_delta,
            normal_control=f"{template.normal_control.action_id}: {result_summary(normal[1] if normal else None)}",
            negative_control=(
                f"{template.negative_control.action_id}: {result_summary(negative[1] if negative else None)}"
            ),
            strongest_benign_explanation=template.strongest_benign_explanation,
            refutation_attempts=[
                "normal account-owned message baseline",
                f"exact cross-object handshake/message repeated {template.repeat_count} times",
                "separate denied WebSocket control",
                "raw frame payloads excluded from durable artifacts",
            ],
            reproduction_steps=[
                f"Open normal control {template.normal_control.action_id} using the declared account context.",
                f"Open experiment {template.experiment.action_id} exactly {template.repeat_count} times.",
                "Verify its declared JSON pointer predicate after each message without exporting the frame.",
                f"Open negative control {template.negative_control.action_id} and verify its expected close code.",
            ],
            requests=[],
            responses=[],
            data_exposure_scope=(
                "Only frame metadata and declared predicate results are retained; raw frames are not persisted."
            ),
            mutation_scope=(
                "Read-only WebSocket handshakes/messages; each browser socket is closed before receipt persistence."
            ),
            cleanup_status=(
                "All opened browser WebSockets were bounded and closed; no durable server mutation was requested."
            ),
            impact=(
                template.impact if decision is CandidateDecision.CONFIRMED else "No reportable capability increment."
            ),
            severity=severity,
            confidence=confidence,
            duplicate_risk=f"Deduplicate by repair boundary: {template.repair_boundary}",
            status=status,
        )
        outcome = ValidationOutcome(
            outcome_id=new_id("validation"),
            validator_id=f"program-websocket-experiment--{template.template_id}",
            candidate_id=candidate_id or new_id("candidate"),
            decision=decision,
            vulnerability_class=template.vulnerability_class,
            title=finding.title,
            affected_feature=template.affected_feature,
            root_cause_key=template.root_cause_key,
            repair_boundary=template.repair_boundary,
            finding_id=finding.finding_id,
            control_ids=[item.control_id for item in controls],
            exchange_ids=[item.exchange_id for item in exchanges],
            capability_delta=capability_delta,
            strongest_benign_explanation=template.strongest_benign_explanation,
            repeated=repeated,
            normal_control_passed=normal_passed,
            negative_control_passed=negative_passed,
            cleanup_completed=True,
            evidence_closed=decision in {CandidateDecision.CONFIRMED, CandidateDecision.KILL},
            confidence=confidence,
        )
        return ValidatorResult(outcome, finding, controls, exchanges, list(dict.fromkeys(artifacts)))

    @staticmethod
    def _websocket_artifact_refs(result: dict[str, object]) -> list[str]:
        receipt = result.get("receipt")
        return [receipt] if isinstance(receipt, str) else []

    @staticmethod
    def _safe_websocket_action_passes(result: dict[str, object], action: SafeWebSocketAction) -> bool:
        if result.get("opened") is not True:
            return False
        if result.get("event") != action.expected_event:
            return False
        if action.expected_event == "close":
            return result.get("close_code") in action.expected_close_codes
        return result.get("json_predicate_matched") is True

    async def _send_safe_websocket_action(
        self,
        action: SafeWebSocketAction,
    ) -> tuple[HttpExchange, dict[str, object]]:
        require_allowed(websocket_target_allowed(self.engagement, action.target_url))
        if self.engagement.selected_mode is not EngagementMode.PROGRAM:
            raise PermissionError("safe WebSocket experiments are available only in formal program mode")
        if action.account_alias not in self.engagement.testing_accounts_secret_refs:
            raise PermissionError("safe WebSocket action account is not declared by the engagement")
        manager = self._browser()
        if await self._ensure_program_browser_identity(manager, action.account_alias) is None:
            raise PermissionError("safe WebSocket action requires declared headers or a completed browser login")
        started = perf_counter()
        result = await manager.websocket_interaction(
            action.account_alias,
            url=action.target_url,
            send_text=action.send_text,
            expected_json_pointer=action.expected_json_pointer,
            expected_json_value=action.expected_json_value,
            step=action.action_id,
        )
        response_headers = {
            "x-budobugs-websocket-event": str(result.get("event", "close")),
            "x-budobugs-websocket-opened": str(result.get("opened") is True).lower(),
            "x-budobugs-websocket-close-code": str(result.get("close_code") or ""),
            "x-budobugs-websocket-json-predicate": str(result.get("json_predicate_matched") is True).lower(),
            "x-budobugs-websocket-frame-payload-persisted": "false",
            "x-budobugs-websocket-status-origin": "synthetic-open-event",
        }
        exchange = HttpExchange(
            exchange_id=new_id("websocket"),
            engagement_id=self.engagement.engagement_id,
            run_id=self.run_id,
            method="GET",
            url=action.target_url,
            request_headers={},
            request_body=None,
            # ``HttpExchange`` has no WebSocket transport type.  101 here is
            # an internal open-event marker, never a claim that Playwright
            # exposed a raw HTTP upgrade response/status line.
            response_status=101 if result.get("opened") is True else 0,
            response_headers=response_headers,
            response_body=None,
            http_version="HTTP/1.1",
            elapsed_ms=(perf_counter() - started) * 1000,
            account_alias=action.account_alias,
            source="playwright",
        )
        return exchange, result

    @staticmethod
    def _safe_action_passes(exchange: HttpExchange, action: SafeHttpAction) -> bool:
        """Match declared status and exact case-insensitive response-header predicates."""

        if exchange.response_status not in action.expected_statuses:
            return False
        response_headers = {name.lower(): value for name, value in exchange.response_headers.items()}
        return all(
            response_headers.get(name.lower()) == expected
            for name, expected in action.expected_response_headers.items()
        )

    async def _send_safe_http_action(self, action: SafeHttpAction) -> HttpExchange:
        require_allowed(target_allowed(self.engagement, action.target_url))
        headers = dict(action.headers)
        if action.account_alias == "anonymous":
            alias: str | None = None
        else:
            if action.account_alias not in self.account_headers:
                raise RuntimeError(f"safe experiment account is unresolved: {action.account_alias}")
            headers.update(self.account_headers[action.account_alias])
            alias = action.account_alias
        content: str | bytes | None = None
        if action.multipart_upload is not None:
            content, content_type = build_harmless_multipart(action.multipart_upload)
            headers["Content-Type"] = content_type
        elif action.body is not None:
            content = json.dumps(action.body, ensure_ascii=False, separators=(",", ":"))
            headers.setdefault("Content-Type", "application/json")
        return await self.direct.send(
            self.engagement,
            action.method,
            action.target_url,
            headers=headers,
            content=content,
            account_alias=alias,
            source="direct",
        )

    async def _program_object_differentials(
        self,
        model: TrafficModel,
        *,
        endpoint_family_id: str | None = None,
        endpoint_host: str | None = None,
        endpoint_method: str | None = None,
        endpoint_path_template: str | None = None,
        parameter_name: str | None = None,
        parameter_location: str | None = None,
        control_exchange_ids: list[str] | None = None,
        candidate_id: str | None = None,
    ) -> list[ValidatorResult]:
        """Test observed path, query, JSON, and GraphQL IDs using only self-owned controls."""

        results: list[ValidatorResult] = []
        for family in model.endpoint_families:
            stable_selector_supplied = all((endpoint_host, endpoint_method, endpoint_path_template))
            if stable_selector_supplied and (
                family.host != endpoint_host
                or family.method != endpoint_method
                or family.path_template != endpoint_path_template
            ):
                continue
            if (
                not stable_selector_supplied
                and endpoint_family_id is not None
                and family.family_id != endpoint_family_id
            ):
                continue
            members = [item for item in self.exchanges if item.exchange_id in family.exchange_ids]
            if control_exchange_ids is not None:
                allowed_controls = set(control_exchange_ids)
                members = [item for item in members if item.exchange_id in allowed_controls]
            if not self._program_read_only_family(family.method, members):
                continue
            parameters = [
                item
                for item in model.parameters.get(family.family_id, [])
                if item.location in {"path", "query", "body", "graphql"}
                and (parameter_name is None or item.name == parameter_name)
                and (parameter_location is None or item.location == parameter_location)
                and (
                    item.dynamic_kind in {"id", "uuid"}
                    or any(marker in item.name.lower() for marker in ("id", "uuid", "key", "file", "token"))
                )
            ]
            matched = False
            for parameter in parameters:
                by_alias: dict[str, tuple[HttpExchange, object]] = {}
                for exchange in members:
                    alias = exchange.account_alias
                    value = self._program_parameter_value(exchange, parameter)
                    if alias in self.account_headers and value is not None:
                        by_alias.setdefault(str(alias), (exchange, value))
                aliases = sorted(by_alias)
                for owner_alias in aliases:
                    for attacker_alias in aliases:
                        if owner_alias == attacker_alias:
                            continue
                        owner_exchange, owner_value = by_alias[owner_alias]
                        attacker_exchange, attacker_value = by_alias[attacker_alias]
                        if owner_value == attacker_value:
                            continue
                        cross = self._program_replace_parameter(attacker_exchange, parameter, owner_value)
                        if cross is None:
                            continue
                        cross_url, cross_body = cross
                        require_allowed(target_allowed(self.engagement, cross_url))
                        owner = await self._program_send_observed(owner_exchange, owner_alias)
                        own = await self._program_send_observed(attacker_exchange, attacker_alias)
                        cross_first = await self._program_send_variant(
                            attacker_exchange,
                            attacker_alias,
                            cross_url,
                            cross_body,
                        )
                        cross_second = await self._program_send_variant(
                            attacker_exchange,
                            attacker_alias,
                            cross_url,
                            cross_body,
                        )
                        anonymous = await self._program_send_variant(
                            attacker_exchange,
                            "anonymous",
                            cross_url,
                            cross_body,
                            authenticated=False,
                        )
                        repeated = (
                            200 <= cross_first.response_status < 300
                            and cross_second.response_status == cross_first.response_status
                            and self._comparable_content(cross_first.response_body)
                            == self._comparable_content(cross_second.response_body)
                        )
                        owner_match = self._comparable_content(cross_first.response_body) == self._comparable_content(
                            owner.response_body
                        )
                        own_distinct = self._comparable_content(own.response_body) != self._comparable_content(
                            cross_first.response_body
                        )
                        anonymous_denied = anonymous.response_status in {401, 403, 404} or (
                            self._comparable_content(anonymous.response_body)
                            != self._comparable_content(cross_first.response_body)
                        )
                        if not (repeated and owner_match and own_distinct and anonymous_denied):
                            continue
                        results.append(
                            self._program_authorization_result(
                                family_host=family.host,
                                family_method=family.method,
                                family_path=family.path_template,
                                parameter=parameter,
                                owner_alias=owner_alias,
                                attacker_alias=attacker_alias,
                                cross_url=cross_url,
                                exchanges=[owner, own, cross_first, cross_second, anonymous],
                                candidate_id=candidate_id,
                            )
                        )
                        matched = True
                        break
                    if matched:
                        break
                if matched:
                    break
            if len(results) >= 8:
                break
        return results

    @staticmethod
    def _program_read_only_family(method: str, members: list[HttpExchange]) -> bool:
        if method == "GET":
            return True
        if method != "POST":
            return False
        for exchange in members:
            try:
                body = json.loads(exchange.request_body or "")
            except json.JSONDecodeError:
                continue
            if not isinstance(body, dict) or not isinstance(body.get("query"), str):
                continue
            query = str(body["query"]).lstrip().lower()
            if not query.startswith("mutation") and query.startswith(("query", "{")):
                return True
        return False

    @staticmethod
    def _program_parameter_value(exchange: HttpExchange, parameter: Parameter) -> object | None:
        if parameter.location == "path":
            try:
                index = int(parameter.name.rsplit("_", 1)[1])
                return [item for item in urlsplit(exchange.url).path.split("/") if item][index]
            except (IndexError, ValueError):
                return None
        if parameter.location == "query":
            return dict(parse_qsl(urlsplit(exchange.url).query, keep_blank_values=True)).get(parameter.name)
        try:
            body = json.loads(exchange.request_body or "")
        except json.JSONDecodeError:
            return None
        if not isinstance(body, dict):
            return None
        if parameter.location == "graphql":
            variables = body.get("variables")
            if isinstance(variables, dict) and parameter.name in variables:
                value = variables[parameter.name]
                return value if isinstance(value, (str, int, float, bool)) else None
        value = body.get(parameter.name)
        return value if isinstance(value, (str, int, float, bool)) else None

    @staticmethod
    def _program_replace_parameter(
        exchange: HttpExchange,
        parameter: Parameter,
        replacement: object,
    ) -> tuple[str, str | None] | None:
        parsed = urlsplit(exchange.url)
        if parameter.location == "path":
            try:
                index = int(parameter.name.rsplit("_", 1)[1])
            except (IndexError, ValueError):
                return None
            segments = [item for item in parsed.path.split("/") if item]
            if index >= len(segments):
                return None
            segments[index] = str(replacement)
            path = "/" + "/".join(segments)
            return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, "")), exchange.request_body
        if parameter.location == "query":
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            if not any(name == parameter.name for name, _value in pairs):
                return None
            query = urlencode([(name, str(replacement) if name == parameter.name else value) for name, value in pairs])
            return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, "")), exchange.request_body
        try:
            body = json.loads(exchange.request_body or "")
        except json.JSONDecodeError:
            return None
        if not isinstance(body, dict):
            return None
        if parameter.location == "graphql":
            variables = body.get("variables")
            if not isinstance(variables, dict) or parameter.name not in variables:
                return None
            variables[parameter.name] = replacement
        elif parameter.name in body:
            body[parameter.name] = replacement
        else:
            return None
        return exchange.url, json.dumps(body, ensure_ascii=False, separators=(",", ":"))

    async def _program_send_observed(self, exchange: HttpExchange, alias: str) -> HttpExchange:
        return await self._program_send_variant(exchange, alias, exchange.url, exchange.request_body)

    async def _program_send_variant(
        self,
        exchange: HttpExchange,
        alias: str,
        url: str,
        body: str | None,
        *,
        authenticated: bool = True,
    ) -> HttpExchange:
        headers = dict(self.account_headers.get(alias, {})) if authenticated else {}
        if body is not None:
            content_type = next(
                (value for name, value in exchange.request_headers.items() if name.lower() == "content-type"),
                "application/json",
            )
            headers["Content-Type"] = content_type
        return await self.direct.send(
            self.engagement,
            exchange.method,
            url,
            headers=headers,
            content=body,
            account_alias=alias,
            source="direct",
        )

    def _program_authorization_result(
        self,
        *,
        family_host: str,
        family_method: str,
        family_path: str,
        parameter: Parameter,
        owner_alias: str,
        attacker_alias: str,
        cross_url: str,
        exchanges: list[HttpExchange],
        candidate_id: str | None = None,
    ) -> ValidatorResult:
        owner, own, cross_first, cross_second, anonymous = exchanges
        material = f"{family_path} {parameter.name}".lower()
        if any(word in material for word in ("file", "download", "upload", "share", "preview", "attachment")):
            vulnerability_class = "file-share-authorization"
        elif any(word in material for word in ("tenant", "workspace", "organization", "org_id")):
            vulnerability_class = "cross-tenant-authorization"
        else:
            vulnerability_class = f"horizontal-authorization-{parameter.location}"
        controls = [
            ControlExperiment(
                control_id=new_id("control"),
                kind="normal",
                description=(
                    f"{owner_alias} and {attacker_alias} each request their own previously observed test object."
                ),
                request_exchange_ids=[owner.exchange_id, own.exchange_id],
                observed_result=(f"owner HTTP {owner.response_status}; attacker own-object HTTP {own.response_status}"),
                supports_finding=True,
            ),
            ControlExperiment(
                control_id=new_id("control"),
                kind="negative",
                description="Anonymous access cannot reproduce the authenticated cross-account content.",
                request_exchange_ids=[anonymous.exchange_id],
                observed_result=f"anonymous HTTP {anonymous.response_status} with non-equivalent content",
                supports_finding=True,
            ),
            ControlExperiment(
                control_id=new_id("control"),
                kind="refutation",
                description="The single-variable cross-account experiment is repeated exactly.",
                request_exchange_ids=[cross_first.exchange_id, cross_second.exchange_id],
                observed_result="both responses have the same status and normalized content",
                supports_finding=True,
            ),
        ]
        endpoint = f"{family_method} {family_path}"
        finding = Finding(
            finding_id=new_id("finding"),
            engagement_id=self.engagement.engagement_id,
            title=f"{endpoint} omits authorization for a {parameter.location} object reference",
            vulnerability_class=vulnerability_class,
            affected_asset=urlunsplit((*urlsplit(cross_url)[:2], "", "", "")),
            affected_feature=endpoint,
            endpoint_family=endpoint,
            attacker_prerequisites=[f"self-owned test account {attacker_alias}"],
            victim_conditions=[f"object is owned by self-owned control account {owner_alias}"],
            security_invariant="An authenticated account may access only objects it owns or is explicitly granted.",
            protected_asset=f"one self-owned {owner_alias} control object",
            trust_boundary=f"declared test accounts {owner_alias}/{attacker_alias}",
            enforcement_point=endpoint,
            observed_behavior=(
                f"Keeping {attacker_alias} identity and request shape fixed while changing only "
                f"{parameter.location} parameter {parameter.name} returned the owner baseline twice."
            ),
            expected_behavior="The service must deny a non-owner or return an equivalent non-disclosing response.",
            capability_before=f"{attacker_alias} reads only its own test object.",
            capability_after=f"{attacker_alias} reads one {owner_alias}-owned test object.",
            capability_delta="crossed one self-owned account boundary to read one private test object",
            normal_control=(
                f"owner baseline HTTP {owner.response_status}; attacker own-object HTTP {own.response_status}."
            ),
            negative_control=f"anonymous request returned HTTP {anonymous.response_status} and different content.",
            strongest_benign_explanation=(
                "The object might be public or shared; the anonymous denial, recorded ownership, owner match, "
                "and distinct attacker-owned baseline refute that explanation."
            ),
            refutation_attempts=[
                "repeated the exact single-variable request",
                "freshly reproduced the owner baseline",
                "compared an anonymous/public baseline",
                "compared the attacker own-object baseline",
            ],
            reproduction_steps=[
                f"Record one object owned by each declared account {owner_alias} and {attacker_alias}.",
                f"Keep {attacker_alias} identity fixed and replace only {parameter.location} {parameter.name}.",
                "Repeat and compare with fresh owner, attacker-owned, and anonymous controls.",
            ],
            requests=[],
            responses=[],
            data_exposure_scope="Exactly one object owned by a second declared test account; no third party.",
            mutation_scope=f"{family_method}-only read-only single-variable {parameter.location} validation.",
            cleanup_status="Read-only validation; no cleanup required.",
            impact="A low-privilege account can read another account's private object.",
            severity=Severity.MEDIUM,
            confidence=0.95,
            duplicate_risk=f"Deduplicate by the owner-policy repair at {endpoint}.",
            status=CandidateStatus.VALIDATING,
        )
        outcome = ValidationOutcome(
            outcome_id=new_id("validation"),
            validator_id="program-authorization-differential",
            candidate_id=candidate_id or new_id("candidate"),
            decision=CandidateDecision.CONFIRMED,
            vulnerability_class=finding.vulnerability_class,
            title=finding.title,
            affected_feature=finding.affected_feature,
            root_cause_key=f"missing-object-owner-check:{family_host}{family_path}:{parameter.location}",
            repair_boundary=f"enforce object ownership at {endpoint} for {parameter.location} references",
            finding_id=finding.finding_id,
            control_ids=[item.control_id for item in controls],
            exchange_ids=[item.exchange_id for item in exchanges],
            capability_delta=finding.capability_delta,
            strongest_benign_explanation=finding.strongest_benign_explanation,
            repeated=True,
            normal_control_passed=True,
            negative_control_passed=True,
            cleanup_completed=True,
            evidence_closed=True,
            confidence=0.95,
        )
        return ValidatorResult(outcome, finding, controls, exchanges, [])

    @staticmethod
    def _json_pointer_value(body: str | None, pointer: str) -> tuple[bool, object]:
        try:
            current: object = json.loads(body or "")
        except json.JSONDecodeError:
            return False, None
        for raw_segment in pointer[1:].split("/"):
            segment = raw_segment.replace("~1", "/").replace("~0", "~")
            if isinstance(current, dict) and segment in current:
                current = current[segment]
            elif isinstance(current, list) and segment.isdecimal() and int(segment) < len(current):
                current = current[int(segment)]
            else:
                return False, None
        return True, current

    @staticmethod
    def _comparable_content(body: str | None) -> object:
        value = normalized_json_structure(body)

        def drop_actor(item: object) -> object:
            if isinstance(item, dict):
                return {
                    str(key): drop_actor(child)
                    for key, child in item.items()
                    if str(key).lower() not in {"requested_by", "requester", "viewer", "current_user"}
                }
            if isinstance(item, list):
                return [drop_actor(child) for child in item]
            return item

        return drop_actor(value)

    def _evidence_review(self, proposal: ActionProposal) -> Observation:
        outcomes = [result.outcome for result in self.validator_results]
        self.root_cause_clusters = RootCauseDeduper.cluster(outcomes)
        confirmed = [item for item in outcomes if item.decision is CandidateDecision.CONFIRMED]
        killed = [item for item in outcomes if item.decision is CandidateDecision.KILL]
        incomplete = [
            item
            for item in confirmed
            if not (
                item.repeated
                and item.normal_control_passed
                and item.negative_control_passed
                and item.cleanup_completed
                and item.evidence_closed
            )
        ]
        report_ready = [item for item in confirmed if item not in incomplete]
        input_summary = self._review_input_summary(proposal, outcomes, report_ready)
        path = self.artifact_root / "evidence-review" / f"{proposal.catalog_action_id}.json"
        atomic_write_json(
            path,
            {
                "reviewer": proposal.agent_role.value,
                "skill": proposal.skill_name,
                "catalog_action_id": proposal.catalog_action_id,
                "input_summary": input_summary,
                "confirmed": [item.model_dump(mode="json") for item in confirmed],
                "killed": [item.model_dump(mode="json") for item in killed],
                "incomplete_confirmations": [item.outcome_id for item in incomplete],
                "report_ready_outcome_ids": [item.outcome_id for item in report_ready],
                "root_cause_clusters": [item.model_dump(mode="json") for item in self.root_cause_clusters],
            },
        )
        return self._observation(
            proposal,
            f"Reviewed {len(outcomes)} outcomes: {len(confirmed)} confirmed, {len(killed)} killed, "
            f"{len(incomplete)} incomplete confirmations, {len(self.root_cause_clusters)} same-fix clusters.",
            gain=0.65 if outcomes else 0.2 if self.exchanges or self.browser_artifacts else 0.1,
            artifacts=[str(path)],
            candidates=[item.candidate_id for item in outcomes],
            details={
                "review_kind": proposal.skill_name,
                "confirmed": len(confirmed),
                "killed": len(killed),
                "incomplete_confirmations": len(incomplete),
                "report_ready": len(report_ready),
                "root_cause_clusters": len(self.root_cause_clusters),
                "traffic_exchange_inputs": len(self.exchanges),
                "browser_artifact_inputs": len(self.browser_artifacts),
                "hypothesis_inputs": len(self.hypotheses),
            },
        )

    def _review_input_summary(
        self,
        proposal: ActionProposal,
        outcomes: list[ValidationOutcome],
        report_ready: list[ValidationOutcome],
    ) -> dict[str, Any]:
        """Describe only executor-held inputs; never turn target text into review instructions."""

        model = self.traffic_model or (build_traffic_model(self.exchanges) if self.exchanges else None)
        domain_specific_role = proposal.agent_role in {
            AgentRole.AUTHORIZATION_SPECIALIST,
            AgentRole.BUSINESS_LOGIC_SPECIALIST,
            AgentRole.API_AUTH_SPECIALIST,
            AgentRole.WEB_CLIENT_SPECIALIST,
        }
        relevant_hypotheses = [
            item
            for item in self.hypotheses
            if not domain_specific_role or self._hypothesis_role(item) is proposal.agent_role
        ]
        relevant_ids = {item.hypothesis_id for item in relevant_hypotheses}
        relevant_plans = [
            item
            for item in self.program_validation_plans
            if not domain_specific_role or item.hypothesis_id in relevant_ids
        ]
        javascript_exchange_ids = [
            item.exchange_id
            for item in self.exchanges
            if urlsplit(item.url).path.casefold().endswith(".js")
            or "javascript" in self._header_value(item.response_headers, "content-type").casefold()
        ]
        artifact_types: dict[str, int] = {}
        for raw_path in self.browser_artifacts:
            category = self._browser_artifact_category(Path(raw_path))
            artifact_types[category] = artifact_types.get(category, 0) + 1
        method_counts: dict[str, int] = {}
        status_counts: dict[str, int] = {}
        for exchange in self.exchanges:
            method_counts[exchange.method] = method_counts.get(exchange.method, 0) + 1
            status = str(exchange.response_status)
            status_counts[status] = status_counts.get(status, 0) + 1
        traffic_summary: dict[str, Any] = {
            "model_present": model is not None,
            "exchange_count": len(self.exchanges),
            "exchange_ids": [item.exchange_id for item in self.exchanges[:250]],
            "method_counts": method_counts,
            "status_counts": status_counts,
            "javascript_exchange_ids": javascript_exchange_ids[:100],
            "browser_artifact_count": len(self.browser_artifacts),
            "browser_artifact_types": artifact_types,
        }
        source_input_refs: list[str] = []
        traffic_path = self.artifact_root / "traffic" / "model.json"
        if traffic_path.is_file():
            source_input_refs.append(str(traffic_path))
        source_input_refs.extend(path for path in self.browser_artifacts[:100] if Path(path).is_file())
        if model is not None:
            traffic_summary.update(
                {
                    "endpoint_family_ids": [item.family_id for item in model.endpoint_families[:250]],
                    "object_reference_count": len(model.objects),
                    "role_count": len(model.roles),
                    "tenant_count": len(model.tenants),
                    "state_transition_ids": [item.transition_id for item in model.state_transitions[:250]],
                    "response_schema_family_ids": sorted(model.response_schemas)[:250],
                    "api_schema_clue_exchange_ids": sorted(
                        {
                            str(item.get("exchange_id"))
                            for item in model.api_schema_clues
                            if isinstance(item.get("exchange_id"), str)
                        }
                    )[:250],
                    "frontend_api_link_exchange_ids": sorted(
                        {
                            str(item.get("exchange_id"))
                            for item in model.frontend_api_links
                            if isinstance(item.get("exchange_id"), str)
                        }
                    )[:250],
                }
            )
        return {
            "engagement": {
                "engagement_id": self.engagement.engagement_id,
                "mode": self.engagement.selected_mode.value,
                "authorization_status": self.engagement.authorization_status.value,
                "declared_roots": [
                    {"uri": item.uri, "label": item.label, "kind": item.kind} for item in self.engagement.root_targets
                ],
                "allowed_subdomains": sorted(self.engagement.optional_allowed_subdomains),
                "excluded_targets": sorted(self.engagement.excluded_targets),
                "account_aliases": sorted(self.engagement.testing_accounts_secret_refs),
                "safe_experiment_ids": sorted(self.engagement.safe_experiment_secret_refs),
                "websocket_experiment_ids": sorted(self.engagement.websocket_experiment_secret_refs),
                "rate_profile": self.engagement.optional_rate_profile,
            },
            "traffic_and_captured_source": traffic_summary,
            "input_artifact_refs": source_input_refs,
            "hypotheses": {
                "hypothesis_ids": [item.hypothesis_id for item in relevant_hypotheses[:250]],
                "vulnerability_classes": sorted({item.vulnerability_class for item in relevant_hypotheses}),
                "plan_ids": [item.plan_id for item in relevant_plans[:250]],
                "planned_hypothesis_ids": [item.hypothesis_id for item in relevant_plans[:250]],
                "unfinished_hypothesis_ids": (
                    sorted(set(self.knowledge.unfinished_candidate_ids).intersection(relevant_ids))[:250]
                    if self.knowledge is not None
                    else []
                ),
            },
            "validation": {
                "outcome_ids": [item.outcome_id for item in outcomes[:250]],
                "candidate_ids": [item.candidate_id for item in outcomes[:250]],
                "decision_counts": {
                    decision.value: sum(item.decision is decision for item in outcomes)
                    for decision in CandidateDecision
                },
                "report_ready_outcome_ids": [item.outcome_id for item in report_ready[:250]],
                "root_cause_cluster_ids": [item.cluster_id for item in self.root_cause_clusters[:250]],
            },
        }

    @staticmethod
    def _header_value(headers: dict[str, str], name: str) -> str:
        lowered = name.casefold()
        return next((value for key, value in headers.items() if key.casefold() == lowered), "")

    @staticmethod
    def _browser_artifact_category(path: Path) -> str:
        material = "/".join(part.casefold() for part in path.parts[-3:])
        for category in ("traffic", "trace", "dom", "screenshot", "steps", "javascript"):
            if category in material:
                return category
        return "other"

    async def _tool_task(self, proposal: ActionProposal) -> Observation:
        assert proposal.tool_name is not None
        raw_arguments = proposal.tool_arguments.get("arguments", [])
        if not isinstance(raw_arguments, list) or not all(isinstance(item, str) for item in raw_arguments):
            raise ValueError("tool_task arguments must be a string list")
        arguments = [str(item) for item in raw_arguments]
        raw_target = proposal.tool_arguments.get("target")
        target = raw_target if isinstance(raw_target, str) else proposal.target_url
        registry = ToolRegistry.load(self.repository_root / "tools" / "registry")
        runner = ToolRunner(
            registry,
            self.artifact_root / "tools",
            workspace_root=self.repository_root,
        )
        request = ToolRequest(
            invocation_id=new_id("tool-invocation"),
            run_id=self.run_id,
            engagement_id=self.engagement.engagement_id,
            tool_name=proposal.tool_name,
            target=target,
            arguments=arguments,
            purpose=proposal.objective,
            output_directory=proposal.catalog_action_id,
        )
        receipt = await runner.run(request, self.engagement)
        receipt_path = self.artifact_root / "tools" / proposal.catalog_action_id / "receipt.json"
        observation_status = (
            ObservationStatus.EXECUTED
            if receipt.status == "completed"
            else ObservationStatus.BLOCKED
            if receipt.status == "blocked"
            else ObservationStatus.FAILED
        )
        return self._observation(
            proposal,
            f"Registered tool {proposal.tool_name} returned receipt status {receipt.status} "
            "through the no-shell wrapper.",
            gain=0.6 if receipt.status == "completed" else 0.1,
            status=observation_status,
            artifacts=[str(receipt_path)],
            details={"tool_name": proposal.tool_name, "status": receipt.status},
        )

    def _finish(self, proposal: ActionProposal) -> Observation:
        return self._observation(
            proposal,
            "Coordinator stopped because the useful scoped action catalog was exhausted or below the "
            "information-gain threshold.",
            gain=0.05,
            details={"stop_reason": proposal.objective},
        )

    def _require_mutation_boundary(self, proposal: ActionProposal) -> None:
        if proposal.mutation_scope == "read-only":
            raise PermissionError("mutating action lacks a self-owned boundary")
        if self.engagement.selected_mode is EngagementMode.PROGRAM and proposal.mutation_scope != "self-owned":
            raise PermissionError("formal program mutation must be explicitly self-owned")
        if self.engagement.selected_mode is EngagementMode.PROGRAM and (
            len(proposal.account_aliases) != 1
            or proposal.account_aliases[0] not in self.engagement.testing_accounts_secret_refs
        ):
            raise PermissionError("formal program mutation requires exactly one declared self-owned account")
        if proposal.method == "DELETE" and proposal.cleanup_action_id is None:
            raise PermissionError("DELETE requires an explicit cleanup/lifecycle action id")

    def _browser(self) -> BrowserSessionManager:
        """Return the single run-scoped browser manager, creating it lazily."""

        if self._browser_manager is None:
            self._browser_manager = BrowserSessionManager(
                self.artifact_root / "browser",
                self.engagement,
                headless=self.headless,
                account_headers=self.account_headers,
                private_root=self._private_browser_root(),
            )
        return self._browser_manager

    def _private_browser_root(self) -> Path:
        """Keep browser credentials outside the repository-visible run tree.

        ``BUDOBUGS_HOME`` may deliberately point to an external private runtime
        directory.  The backwards-compatible default (``.budobugs`` below the
        repository) is *not* private from a read-only Codex subprocess whose
        cwd is the repository, so it falls back to the per-user private home.
        """

        configured = os.environ.get("BUDOBUGS_PRIVATE_HOME")
        if os.name == "nt":
            # Chromium's profile/cache tree still encounters MAX_PATH failures
            # on deep external runtime paths. A Windows run therefore always
            # uses the short local application-data root unless an explicitly
            # configured external private home has a proven path budget.
            if configured:
                configured_home = Path(configured).expanduser().resolve()
                configured_root = self._windows_private_browser_root(configured_home)
                if not configured_home.is_relative_to(self.repository_root) and self._windows_profile_path_is_safe(
                    configured_root
                ):
                    return configured_root
            private_home = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "BudoBugs"
            fallback = self._windows_private_browser_root(private_home)
            if not self._windows_profile_path_is_safe(fallback):
                raise RuntimeError("no Windows private browser root satisfies the Chromium profile path-length budget")
            return fallback

        candidate = self.runtime_home / "private-artifacts" / "browser"
        if not candidate.is_relative_to(self.repository_root):
            return candidate / self.engagement.engagement_id / self.run_id
        if configured:
            configured_home = Path(configured).expanduser().resolve()
            if not configured_home.is_relative_to(self.repository_root):
                return configured_home / "private-artifacts" / "browser" / self.engagement.engagement_id / self.run_id
        private_home = Path.home() / ".local" / "share" / "budobugs"
        return private_home / "private-artifacts" / "browser" / self.engagement.engagement_id / self.run_id

    def _windows_private_browser_root(self, private_home: Path) -> Path:
        """Return a compact, stable private root for Chromium on Windows."""

        engagement_key = hashlib.sha256(self.engagement.engagement_id.encode("utf-8")).hexdigest()[:16]
        run_key = hashlib.sha256(self.run_id.encode("utf-8")).hexdigest()[:16]
        return private_home / "private-artifacts" / "browser" / f"e-{engagement_key}" / f"r-{run_key}"

    def _windows_profile_path_is_safe(self, root: Path) -> bool:
        """Reserve headroom for Chromium's nested Default/cache paths."""

        aliases = [*self.engagement.testing_accounts_secret_refs, "anonymous", "websocket-client"]
        longest_alias = max((len(alias) for alias in aliases), default=1)
        chromium_leaf = "Default/Network/Cookies-journal"
        # 190 leaves roughly 70 characters for Chromium's deeper cache and
        # component paths before the legacy 260-character Windows boundary.
        return len(str(root / ("a" * longest_alias) / "profile" / chromium_leaf)) <= 190

    async def close_browser(self) -> None:
        """Close the run-scoped browser after cleanup and harvest durable artifacts.

        The orchestrator invokes this from a ``finally`` block, including an
        intentional turn checkpoint and provider/executor failure.  Login state
        is retained in the profile directory; in-memory tabs and contexts are
        deliberately never retained across a process restart.
        """

        manager = self._browser_manager
        if manager is None:
            return
        browser_root = self.artifact_root / "browser"
        try:
            await self._cleanup_active_self_owned_objects(manager)
        finally:
            try:
                await manager.stop()
            finally:
                self._browser_manager = None
        artifacts = browser_artifact_paths(browser_root)
        self.browser_artifacts = list(dict.fromkeys([*self.browser_artifacts, *artifacts]))
        imported: list[HttpExchange] = []
        for har in sorted(browser_root.glob("*/traffic*.har")):
            imported.extend(self._import_browser_har(har, har.parent.name))
        self._add_exchanges(imported)

    def _recipe_for_alias(self, account_alias: str) -> SelfOwnedObjectRecipe | None:
        return next((item for item in self.self_owned_object_recipes if item.account_alias == account_alias), None)

    async def _ensure_program_self_owned_objects(
        self,
        manager: BrowserSessionManager,
        aliases: list[str],
    ) -> dict[str, str]:
        """Create exactly one declared harmless object per logged-in account.

        A missing recipe is evidence of a setup boundary, not an excuse to
        invent a POST.  Read-only browser exploration continues and records the
        explicit blocked state in the durable ledger.
        """

        results: dict[str, str] = {}
        for alias in aliases:
            if alias == "anonymous":
                continue
            recipe = self._recipe_for_alias(alias)
            if recipe is None:
                key = f"missing-recipe:{alias}"
                self._self_owned_objects[key] = {
                    "object_id": key,
                    "account_alias": alias,
                    "state": "BLOCKED_RECIPE_MISSING",
                    "updated_at": utc_now().isoformat(),
                }
                self._persist_self_owned_object_ledger()
                results[alias] = "BLOCKED_RECIPE_MISSING"
                continue
            active = next(
                (
                    item
                    for item in self._self_owned_objects.values()
                    if item.get("account_alias") == alias
                    and item.get("recipe_id") == recipe.recipe_id
                    and item.get("state") == "ACTIVE"
                ),
                None,
            )
            if active is not None:
                results[alias] = "REUSED_ACTIVE_OBJECT"
                continue
            object_id = new_id("self-owned-object")
            record: dict[str, object] = {
                "object_id": object_id,
                "account_alias": alias,
                "recipe_id": recipe.recipe_id,
                "object_description": recipe.object_description,
                "state": "CREATING",
                "created_at": utc_now().isoformat(),
            }
            self._self_owned_objects[object_id] = record
            self._persist_self_owned_object_ledger()
            try:
                creation = await self._run_recipe_action(manager, recipe.create)
                record["create"] = creation
                if self._recipe_status(creation) not in recipe.create.expected_statuses:
                    record["state"] = "CREATE_STATUS_MISMATCH"
                    results[alias] = "CREATE_STATUS_MISMATCH"
                    self._persist_self_owned_object_ledger()
                    continue
                verification = await self._run_recipe_action(manager, recipe.verification)
                record["verification"] = verification
                if self._recipe_status(verification) not in recipe.verification.expected_statuses:
                    record["state"] = "VERIFY_STATUS_MISMATCH"
                    results[alias] = "VERIFY_STATUS_MISMATCH"
                    self._persist_self_owned_object_ledger()
                    # A successful create still gets a best-effort bounded cleanup.
                    await self._cleanup_self_owned_object(manager, record, recipe)
                    continue
                record["state"] = "ACTIVE"
                record["verified_at"] = utc_now().isoformat()
                results[alias] = "CREATED_AND_VERIFIED"
            except Exception as exc:
                record["state"] = "CREATE_FAILED"
                record["error"] = f"{type(exc).__name__}: {str(exc)[:500]}"
                results[alias] = "CREATE_FAILED"
            self._persist_self_owned_object_ledger()
        return results

    async def _run_recipe_action(
        self,
        manager: BrowserSessionManager,
        action: SafeHttpAction,
    ) -> dict[str, object]:
        result = await manager.request_json(
            action.account_alias,
            method=action.method,
            url=action.target_url,
            body=action.body,
            headers=action.headers,
        )
        return {**result, "action_id": action.action_id, "expected_statuses": action.expected_statuses}

    @staticmethod
    def _recipe_status(result: dict[str, object]) -> int:
        status = result.get("status")
        if not isinstance(status, int):
            raise RuntimeError("browser object recipe response status is invalid")
        return status

    async def _cleanup_active_self_owned_objects(self, manager: BrowserSessionManager) -> None:
        for record in list(self._self_owned_objects.values()):
            if record.get("state") != "ACTIVE":
                continue
            recipe_id = record.get("recipe_id")
            recipe = next((item for item in self.self_owned_object_recipes if item.recipe_id == recipe_id), None)
            if recipe is None:
                record["state"] = "CLEANUP_BLOCKED_RECIPE_UNAVAILABLE"
                record["updated_at"] = utc_now().isoformat()
                self._persist_self_owned_object_ledger()
                continue
            await self._cleanup_self_owned_object(manager, record, recipe)

    async def _cleanup_self_owned_object(
        self,
        manager: BrowserSessionManager,
        record: dict[str, object],
        recipe: SelfOwnedObjectRecipe,
    ) -> None:
        try:
            cleanup = await self._run_recipe_action(manager, recipe.cleanup)
            record["cleanup"] = cleanup
            if self._recipe_status(cleanup) not in recipe.cleanup.expected_statuses:
                record["state"] = "CLEANUP_STATUS_MISMATCH"
            else:
                verification = await self._run_recipe_action(manager, recipe.cleanup_verification)
                record["cleanup_verification"] = verification
                record["state"] = (
                    "CLEANED"
                    if self._recipe_status(verification) in recipe.cleanup_verification.expected_statuses
                    else "CLEANUP_VERIFY_STATUS_MISMATCH"
                )
        except Exception as exc:
            record["state"] = "CLEANUP_FAILED"
            record["cleanup_error"] = f"{type(exc).__name__}: {str(exc)[:500]}"
        record["updated_at"] = utc_now().isoformat()
        self._persist_self_owned_object_ledger()

    def _restore_self_owned_object_ledger(self) -> None:
        if not self.self_owned_object_ledger_path.is_file():
            return
        try:
            payload = json.loads(self.self_owned_object_ledger_path.read_text(encoding="utf-8"))
            if (
                not isinstance(payload, dict)
                or payload.get("schema_version") != 1
                or payload.get("run_id") != self.run_id
                or payload.get("engagement_id") != self.engagement.engagement_id
                or not isinstance(payload.get("objects"), list)
            ):
                raise ValueError("self-owned object ledger identity or schema mismatch")
            self._self_owned_objects = {
                str(item["object_id"]): item
                for item in payload["objects"]
                if isinstance(item, dict) and isinstance(item.get("object_id"), str)
            }
        except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"self-owned object ledger is missing valid recoverable state: {self.self_owned_object_ledger_path}"
            ) from exc

    def _persist_self_owned_object_ledger(self) -> None:
        atomic_write_json(
            self.self_owned_object_ledger_path,
            {
                "schema_version": 1,
                "run_id": self.run_id,
                "engagement_id": self.engagement.engagement_id,
                "objects": list(self._self_owned_objects.values()),
            },
        )

    async def _ensure_program_browser_identity(
        self,
        manager: BrowserSessionManager,
        account_alias: str,
    ) -> str | None:
        """Return the declared identity basis, or fail closed before browser evidence is collected."""

        if self.engagement.selected_mode is not EngagementMode.PROGRAM:
            return "lab-fixture" if account_alias != "anonymous" else "anonymous"
        if account_alias == "anonymous":
            return "anonymous"
        if account_alias not in self.engagement.testing_accounts_secret_refs:
            return None
        if self.account_headers.get(account_alias):
            return "declared-headers"
        if manager.has_completed_login(account_alias):
            return "persisted-login"
        login_url = self.account_login_urls.get(account_alias)
        if not self.interactive_login or login_url is None:
            return None
        page = await manager.pause_for_login(account_alias, login_url)
        await page.close()
        return "interactive-login" if manager.has_completed_login(account_alias) else None

    def _browser_login_required(self, proposal: ActionProposal, aliases: list[str]) -> Observation:
        return self._observation(
            proposal,
            "Program browser action was blocked because a declared account has no usable headers or "
            "completed interactive login context.",
            gain=0,
            status=ObservationStatus.BLOCKED,
            details={
                "login_required": list(dict.fromkeys(aliases)),
                "requires_interactive_login": True,
                "authenticated_evidence_collected": False,
            },
        )

    def _add_exchanges(self, exchanges: list[HttpExchange]) -> None:
        existing = {item.exchange_id for item in self.exchanges}
        changed = False
        for exchange in exchanges:
            if exchange.exchange_id not in existing:
                self.exchanges.append(exchange.model_copy(update={"run_id": self.run_id}))
                existing.add(exchange.exchange_id)
                changed = True
        if changed:
            self._persist_exchange_ledger()

    def _persist_exchange_ledger(self) -> None:
        atomic_write_json(
            self.exchange_ledger_path,
            {
                "schema_version": 1,
                "run_id": self.run_id,
                "engagement_id": self.engagement.engagement_id,
                "exchanges": [item.model_dump(mode="json") for item in self.exchanges],
            },
        )

    def _restore_exchange_ledger(self) -> None:
        if not self.exchange_ledger_path.is_file():
            return
        try:
            payload = json.loads(self.exchange_ledger_path.read_text(encoding="utf-8"))
            if (
                not isinstance(payload, dict)
                or payload.get("schema_version") != 1
                or payload.get("run_id") != self.run_id
                or payload.get("engagement_id") != self.engagement.engagement_id
                or not isinstance(payload.get("exchanges"), list)
            ):
                raise ValueError("exchange ledger identity or schema mismatch")
            restored = [HttpExchange.model_validate(item) for item in payload["exchanges"]]
            if any(
                item.engagement_id != self.engagement.engagement_id or item.run_id != self.run_id for item in restored
            ):
                raise ValueError("exchange ledger contains an exchange outside the active run")
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"exchange ledger is missing valid recoverable state: {self.exchange_ledger_path}"
            ) from exc
        seen: set[str] = set()
        self.exchanges = []
        for exchange in restored:
            if exchange.exchange_id not in seen:
                self.exchanges.append(exchange)
                seen.add(exchange.exchange_id)

    def _validator_path(self, validator_id: str, outcome_id: str) -> Path:
        return self.artifact_root / "validators" / validator_id / f"{outcome_id}.json"

    def _persist_validator_result(self, result: ValidatorResult) -> None:
        path = self._validator_path(result.outcome.validator_id, result.outcome.outcome_id)
        atomic_write_json(
            path,
            {
                "outcome": result.outcome.model_dump(mode="json"),
                "finding": result.finding.model_dump(mode="json"),
                "controls": [item.model_dump(mode="json") for item in result.controls],
                "exchanges": [item.model_dump(mode="json") for item in result.exchanges],
                "artifact_refs": result.artifact_refs,
            },
        )

    def _restore_artifacts(self) -> None:
        for path in sorted((self.artifact_root / "validators").glob("*/*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                result = ValidatorResult(
                    ValidationOutcome.model_validate(payload["outcome"]),
                    Finding.model_validate(payload["finding"]),
                    [ControlExperiment.model_validate(item) for item in payload["controls"]],
                    [HttpExchange.model_validate(item) for item in payload["exchanges"]],
                    [str(item) for item in payload.get("artifact_refs", [])],
                )
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                continue
            self.validator_results.append(result)
            self._add_exchanges(result.exchanges)
        browser_root = self.artifact_root / "browser"
        if browser_root.is_dir():
            self.browser_artifacts = browser_artifact_paths(browser_root)
            for har in sorted(browser_root.glob("*/traffic*.har")):
                self._add_exchanges(self._import_browser_har(har, har.parent.name))
        model_path = self.artifact_root / "traffic" / "model.json"
        if model_path.is_file() and self.exchanges:
            self.traffic_model = build_traffic_model(self.exchanges)
        hypotheses_path = self.artifact_root / "hypotheses" / "generated.json"
        plans_path = self.artifact_root / "hypotheses" / "program-validation-plans.json"
        context_path = self.artifact_root / "hypotheses" / "generation-context.json"
        if context_path.is_file():
            try:
                payload = json.loads(context_path.read_text(encoding="utf-8"))
                identity_ids = payload.get("hypothesis_identity_ids") if isinstance(payload, dict) else None
                if isinstance(identity_ids, dict):
                    self._hypothesis_identity_ids.update(
                        {
                            key: value
                            for key, value in identity_ids.items()
                            if isinstance(key, str) and isinstance(value, str)
                        }
                    )
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                self._hypothesis_identity_ids.clear()
        if hypotheses_path.is_file():
            try:
                payload = json.loads(hypotheses_path.read_text(encoding="utf-8"))
                if isinstance(payload, list):
                    self.hypotheses.extend(Hypothesis.model_validate(item) for item in payload)
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                self.hypotheses.clear()
        if plans_path.is_file():
            try:
                payload = json.loads(plans_path.read_text(encoding="utf-8"))
                if isinstance(payload, list):
                    self.program_validation_plans.extend(ProgramValidationPlan.model_validate(item) for item in payload)
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                self.program_validation_plans.clear()
        if self.validator_results:
            self.root_cause_clusters = RootCauseDeduper.cluster(result.outcome for result in self.validator_results)

    @staticmethod
    def _string_list(value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, str)]

    def _import_browser_har(self, path: Path, alias: str) -> list[HttpExchange]:
        if not path.is_file():
            return []
        try:
            return [
                self._redact_browser_exchange(item.model_copy(update={"account_alias": alias, "run_id": self.run_id}))
                for item in import_har(path, self.engagement)
            ]
        except TrafficImportError:
            return []

    def _browser_har_path(self, manager: BrowserSessionManager, alias: str) -> Path:
        """Locate the native HAR without making it a public artifact reference."""

        private_root = getattr(manager, "private_root", self.artifact_root / "browser")
        return Path(private_root) / alias / "traffic.har"

    @staticmethod
    def _redact_browser_exchange(exchange: HttpExchange) -> HttpExchange:
        """Make a browser capture safe before it reaches a run artifact.

        ``import_har`` already removes standard authorization headers, but its
        generic normalizer intentionally preserves query/body structure.  The
        browser-private HAR may contain session material in those fields, so
        apply the stricter audit projection before the exchange ledger, model,
        or Codex-visible observation can receive it.
        """

        return exchange.model_copy(
            update={
                "url": BrowserSessionManager._redact_har_url(exchange.url),
                "request_headers": redact_headers(exchange.request_headers),
                "response_headers": redact_headers(exchange.response_headers),
                "request_body": (
                    BrowserSessionManager._redact_har_text(exchange.request_body)
                    if exchange.request_body is not None
                    else None
                ),
                "response_body": (
                    BrowserSessionManager._redact_har_text(exchange.response_body)
                    if exchange.response_body is not None
                    else None
                ),
            }
        )

    def _safe_discovered_urls(self, values: list[str]) -> list[str]:
        result: list[str] = []
        for value in values:
            try:
                parsed = urlsplit(value)
                safe = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
            except ValueError:
                continue
            if (
                parsed.username is not None
                or parsed.password is not None
                or not target_allowed(self.engagement, safe).allowed
                or safe in result
            ):
                continue
            result.append(safe)
        return result

    def _replayable_exchange_details(self, exchanges: list[HttpExchange]) -> list[dict[str, str | None]]:
        result: list[dict[str, str | None]] = []
        seen: set[str] = set()
        for exchange in exchanges:
            if (
                exchange.method not in {"GET", "OPTIONS"}
                or exchange.exchange_id in seen
                or not 1 <= len(exchange.exchange_id) <= 128
                or not target_allowed(self.engagement, exchange.url).allowed
            ):
                continue
            seen.add(exchange.exchange_id)
            result.append(
                {
                    "exchange_id": exchange.exchange_id,
                    "method": exchange.method,
                    "account_alias": exchange.account_alias,
                }
            )
            if len(result) >= 50:
                break
        return result

    @staticmethod
    def _browser_artifact_suffix(proposal: ActionProposal) -> str:
        safe = re.sub(r"[^A-Za-z0-9_-]+", "-", proposal.catalog_action_id).strip("-")[:64]
        return f"-{safe or 'action'}"

    def _observation(
        self,
        proposal: ActionProposal,
        summary: str,
        *,
        gain: float,
        status: ObservationStatus = ObservationStatus.EXECUTED,
        exchanges: list[HttpExchange] | None = None,
        artifacts: list[str] | None = None,
        discovered: list[str] | None = None,
        state_changes: list[str] | None = None,
        candidates: list[str] | None = None,
        details: dict[str, Any] | None = None,
    ) -> Observation:
        return Observation(
            observation_id=new_id("observation"),
            proposal_id=proposal.proposal_id,
            round_index=proposal.round_index,
            status=status,
            summary=summary,
            information_gain=min(1.0, max(0.0, gain)),
            exchange_ids=[item.exchange_id for item in exchanges or []],
            artifact_refs=list(dict.fromkeys(artifacts or [])),
            discovered_urls=list(dict.fromkeys(discovered or [])),
            state_changes=state_changes or [],
            candidate_ids=candidates or [],
            backend=self.proxy.selected,
            details=details or {},
        )
