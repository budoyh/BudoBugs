"""Policy-bound execution of typed agent actions with artifact receipts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from budobugs.browser.session import BrowserSessionManager, browser_artifact_paths
from budobugs.core.identifiers import new_id
from budobugs.core.io import atomic_write_json
from budobugs.core.policy import require_allowed, target_allowed
from budobugs.knowledge.vendor import RootCauseDeduper
from budobugs.models import (
    ActionKind,
    ActionProposal,
    CandidateDecision,
    CandidateStatus,
    ControlExperiment,
    Engagement,
    EngagementMode,
    Finding,
    HttpExchange,
    Observation,
    ObservationStatus,
    Parameter,
    RootCauseCluster,
    Severity,
    ToolRequest,
    ValidationOutcome,
)
from budobugs.orchestration.skill_runtime import SkillRuntime
from budobugs.proxy import DirectProxyBackend, ProxySelection
from budobugs.tools.registry import ToolRegistry
from budobugs.tools.wrapper import ToolRunner
from budobugs.traffic.importer import TrafficImportError, import_har
from budobugs.traffic.modeler import TrafficModel, build_traffic_model
from budobugs.traffic.normalization import normalized_json_structure
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
        self.interactive_login = interactive_login
        self.headless = headless
        self.skill_runtime = SkillRuntime(self.repository_root)
        self.validator_registry = ValidatorRegistry(self.artifact_root / "validators")
        self.direct = DirectProxyBackend(timeout=20)
        self.exchanges: list[HttpExchange] = []
        self.validator_results: list[ValidatorResult] = []
        self.traffic_model: TrafficModel | None = None
        self.root_cause_clusters: list[RootCauseCluster] = []
        self.browser_artifacts: list[str] = []
        self._restore_artifacts()

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
                },
            },
        )

    async def _proxy_replay(self, proposal: ActionProposal) -> Observation:
        assert proposal.base_exchange_id is not None
        original = await self.proxy.backend.get(proposal.base_exchange_id)
        alias = proposal.account_aliases[0] if proposal.account_aliases else original.account_alias
        replayed = await self.proxy.backend.replay(self.engagement, original, account_alias=alias)
        self._add_exchanges([replayed])
        return self._observation(
            proposal,
            f"Replayed one scoped {original.method} exchange through {self.proxy.selected}; "
            f"received HTTP {replayed.response_status}.",
            gain=0.7,
            exchanges=[replayed],
            details={"base_exchange_id": original.exchange_id, "account_alias": alias},
        )

    async def _http_request(self, proposal: ActionProposal) -> Observation:
        assert proposal.target_url is not None
        assert proposal.method is not None
        if proposal.method in {"POST", "PUT", "PATCH", "DELETE"}:
            self._require_mutation_boundary(proposal)
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
            state_changes=[proposal.mutation_scope] if proposal.method != "GET" else [],
        )

    async def _browser_explore(self, proposal: ActionProposal) -> Observation:
        assert proposal.target_url is not None
        browser_root = self.artifact_root / "browser"
        manager = BrowserSessionManager(
            browser_root,
            self.engagement,
            headless=self.headless,
            account_headers=self.account_headers,
        )
        aliases = proposal.account_aliases or ["anonymous"]
        results: list[dict[str, object]] = []
        try:
            for alias in aliases:
                start_url = proposal.target_url
                if self.engagement.selected_mode is EngagementMode.LAB and alias != "anonymous":
                    login = urljoin(f"{proposal.target_url.rstrip('/')}/", f"login/{alias}")
                    page = await manager.open(alias, login)
                    await page.close()
                    start_url = urljoin(f"{proposal.target_url.rstrip('/')}/", "app")
                elif alias in self.account_login_urls and self.interactive_login:
                    page = await manager.pause_for_login(alias, self.account_login_urls[alias])
                    await page.close()
                results.append(
                    await manager.explore(
                        alias,
                        start_url,
                        create_harmless_object=self.engagement.selected_mode is EngagementMode.LAB,
                    )
                )
        finally:
            await manager.stop()
        artifacts = browser_artifact_paths(browser_root)
        self.browser_artifacts = list(dict.fromkeys([*self.browser_artifacts, *artifacts]))
        imported: list[HttpExchange] = []
        for alias in aliases:
            har = browser_root / alias / "traffic.har"
            if not har.is_file():
                continue
            try:
                imported.extend(
                    item.model_copy(update={"account_alias": alias, "run_id": self.run_id})
                    for item in import_har(har, self.engagement)
                )
            except TrafficImportError:
                continue
        self._add_exchanges(imported)
        visited = [str(url) for result in results for url in self._string_list(result.get("visited_urls"))]
        discovered = [str(url) for result in results for url in self._string_list(result.get("discovered_urls"))]
        created = [
            str(marker) for result in results for marker in self._string_list(result.get("created_harmless_objects"))
        ]
        return self._observation(
            proposal,
            f"Explored {len(set(visited))} pages in {len(aliases)} persistent isolated account contexts; "
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
            },
        )

    async def _browser_navigate(self, proposal: ActionProposal) -> Observation:
        assert proposal.target_url is not None
        alias = proposal.account_aliases[0] if proposal.account_aliases else "anonymous"
        manager = BrowserSessionManager(
            self.artifact_root / "browser",
            self.engagement,
            headless=self.headless,
            account_headers=self.account_headers,
        )
        try:
            page = await manager.open(alias, proposal.target_url)
            shot = await manager.screenshot(alias, page, proposal.catalog_action_id)
            final_url = page.url
            await page.close()
        finally:
            await manager.stop()
        return self._observation(
            proposal,
            f"Navigated account context {alias} to a scoped page and captured its rendered state.",
            gain=0.55,
            artifacts=[str(shot)],
            discovered=[final_url],
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
        manager = BrowserSessionManager(
            self.artifact_root / "browser",
            self.engagement,
            headless=self.headless,
            account_headers=self.account_headers,
        )
        try:
            result = await manager.submit_form(
                alias,
                proposal.target_url,
                fields=fields,
                submit_selector=selector,
            )
        finally:
            await manager.stop()
        response_status = result["status"]
        if not isinstance(response_status, int):
            raise RuntimeError("browser form response status is invalid")
        return self._observation(
            proposal,
            f"Submitted one typed self-owned form and observed HTTP {result['status']}.",
            gain=0.7,
            artifacts=[str(result["screenshot"])],
            discovered=[str(result["page_url"])],
            state_changes=[proposal.mutation_scope],
            details={"response_status": response_status},
        )

    def _model_traffic(self, proposal: ActionProposal) -> Observation:
        self.traffic_model = build_traffic_model(self.exchanges)
        path = self.artifact_root / "traffic" / "model.json"
        atomic_write_json(path, self.traffic_model.as_dict())
        model = self.traffic_model
        return self._observation(
            proposal,
            f"Modeled {len(model.endpoint_families)} endpoint families, {len(model.objects)} object "
            f"references, {len(model.roles)} roles, {len(model.tenants)} tenants, and "
            f"{len(model.state_transitions)} state transitions.",
            gain=0.85 if model.endpoint_families else 0.2,
            artifacts=[str(path)],
            details={
                "endpoint_families": len(model.endpoint_families),
                "objects": len(model.objects),
                "roles": len(model.roles),
                "tenants": len(model.tenants),
                "state_transitions": len(model.state_transitions),
                "graphql_or_schema_clues": len(model.api_schema_clues),
                "frontend_api_links": len(model.frontend_api_links),
            },
        )

    async def _validator(self, proposal: ActionProposal) -> Observation:
        assert proposal.validator_id is not None
        if proposal.validator_id.startswith("fixture-"):
            results = await self.validator_registry.run(proposal.validator_id, self.engagement)
        else:
            results = await self._program_validator(proposal.validator_id)
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

    async def _program_validator(self, validator_id: str) -> list[ValidatorResult]:
        """Perform conservative real analysis; HOLD when self-owned controls are insufficient."""

        if validator_id not in {
            "program-authorization-differential",
            "program-business-workflow",
            "program-api-auth-session",
            "program-client-file",
        }:
            raise ValueError(f"unknown program validator: {validator_id}")
        model = self.traffic_model or build_traffic_model(self.exchanges)
        if validator_id == "program-authorization-differential":
            confirmed = await self._program_object_differentials(model)
            if confirmed:
                return confirmed
        evidence_ids = [item.exchange_id for item in self.exchanges[:20]]
        missing: list[str] = []
        if len(self.account_headers) < 2:
            missing.append("two resolvable self-owned account contexts")
        if not model.endpoint_families:
            missing.append("captured endpoint traffic")
        if validator_id == "program-business-workflow" and not model.state_transitions:
            missing.append("a reversible self-owned state transition")
        if validator_id == "program-api-auth-session" and not any(
            "session" in family.path_template.lower() or "auth" in family.path_template.lower()
            for family in model.endpoint_families
        ):
            missing.append("an observed authentication/session lifecycle endpoint")
        if validator_id == "program-client-file" and not (model.frontend_api_links or self.browser_artifacts):
            missing.append("captured browser source/sink or file/share evidence")
        finding = Finding(
            finding_id=new_id("finding"),
            engagement_id=self.engagement.engagement_id,
            title=f"HOLD: {validator_id} requires additional self-owned controls",
            vulnerability_class=validator_id.removeprefix("program-").replace("-", " "),
            affected_asset=self.engagement.root_targets[0].uri,
            affected_feature="observed authorized workflow",
            endpoint_family="; ".join(family.path_template for family in model.endpoint_families[:5]) or "unobserved",
            attacker_prerequisites=["authorized self-owned testing account"],
            victim_conditions=["second self-owned account or reversible self-owned object"],
            security_invariant=(
                "A candidate cannot be reported without normal, negative, repeat, and ownership controls."
            ),
            protected_asset="authorized test data only",
            trust_boundary="declared engagement accounts and targets",
            enforcement_point="observed server-side endpoint",
            observed_behavior="No safe confirmation was made because required controls were incomplete.",
            expected_behavior="The system must preserve account, role, tenant, object, and state boundaries.",
            capability_before="No demonstrated cross-boundary capability.",
            capability_after="No demonstrated cross-boundary capability.",
            capability_delta="none; candidate remains HOLD",
            normal_control="Not executed because the exact self-owned baseline was unavailable.",
            negative_control="Not executed because the exact deny/public baseline was unavailable.",
            strongest_benign_explanation="Observed differences may be intended product behavior or incomplete state.",
            refutation_attempts=["inspected normalized traffic and available account/object/state provenance"],
            reproduction_steps=["Capture the missing self-owned controls, then resume this same research chain."],
            requests=[],
            responses=[],
            data_exposure_scope="No third-party data requested or retained.",
            mutation_scope="No mutation performed without a reversible self-owned fixture.",
            cleanup_status="No cleanup required.",
            impact="Unconfirmed; no reportable capability increment.",
            severity=Severity.INFO,
            confidence=0.2,
            duplicate_risk="Unknown until a root cause is demonstrated.",
            status=CandidateStatus.HOLD,
        )
        controls = [
            ControlExperiment(
                control_id=new_id("control"),
                kind="refutation",
                description="Require all missing ownership and lifecycle controls before active validation.",
                request_exchange_ids=evidence_ids,
                observed_result="missing: " + ", ".join(missing or ["specialist-selected exact control"]),
                supports_finding=False,
            )
        ]
        outcome = ValidationOutcome(
            outcome_id=new_id("validation"),
            validator_id=validator_id,
            candidate_id=new_id("candidate"),
            decision=CandidateDecision.HOLD,
            vulnerability_class=finding.vulnerability_class,
            title=finding.title,
            root_cause_key=f"unresolved:{validator_id}",
            repair_boundary="no repair boundary until controls close",
            finding_id=finding.finding_id,
            control_ids=[item.control_id for item in controls],
            exchange_ids=evidence_ids,
            capability_delta=finding.capability_delta,
            strongest_benign_explanation=finding.strongest_benign_explanation,
            repeated=False,
            normal_control_passed=False,
            negative_control_passed=False,
            cleanup_completed=True,
            evidence_closed=False,
            confidence=0.2,
        )
        return [ValidatorResult(outcome, finding, controls, [], self.browser_artifacts[:20])]

    async def _program_object_differentials(self, model: TrafficModel) -> list[ValidatorResult]:
        """Test observed path, query, JSON, and GraphQL IDs using only self-owned controls."""

        results: list[ValidatorResult] = []
        for family in model.endpoint_families:
            members = [item for item in self.exchanges if item.exchange_id in family.exchange_ids]
            if not self._program_read_only_family(family.method, members):
                continue
            parameters = [
                item
                for item in model.parameters.get(family.family_id, [])
                if item.location in {"path", "query", "body", "graphql"}
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
            candidate_id=new_id("candidate"),
            decision=CandidateDecision.CONFIRMED,
            vulnerability_class=finding.vulnerability_class,
            title=finding.title,
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
        path = self.artifact_root / "evidence-review" / f"{proposal.catalog_action_id}.json"
        atomic_write_json(
            path,
            {
                "reviewer": proposal.agent_role.value,
                "confirmed": [item.model_dump(mode="json") for item in confirmed],
                "killed": [item.model_dump(mode="json") for item in killed],
                "incomplete_confirmations": [item.outcome_id for item in incomplete],
                "root_cause_clusters": [item.model_dump(mode="json") for item in self.root_cause_clusters],
            },
        )
        return self._observation(
            proposal,
            f"Reviewed {len(outcomes)} outcomes: {len(confirmed)} confirmed, {len(killed)} killed, "
            f"{len(incomplete)} incomplete confirmations, {len(self.root_cause_clusters)} same-fix clusters.",
            gain=0.65 if outcomes else 0.1,
            artifacts=[str(path)],
            candidates=[item.candidate_id for item in outcomes],
            details={
                "confirmed": len(confirmed),
                "killed": len(killed),
                "incomplete_confirmations": len(incomplete),
                "root_cause_clusters": len(self.root_cause_clusters),
            },
        )

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
        return self._observation(
            proposal,
            f"Executed registered tool {proposal.tool_name} through the no-shell wrapper: {receipt.status}.",
            gain=0.6 if receipt.status == "completed" else 0.1,
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
        if proposal.method == "DELETE" and proposal.cleanup_action_id is None:
            raise PermissionError("DELETE requires an explicit cleanup/lifecycle action id")

    def _add_exchanges(self, exchanges: list[HttpExchange]) -> None:
        existing = {item.exchange_id for item in self.exchanges}
        for exchange in exchanges:
            if exchange.exchange_id not in existing:
                self.exchanges.append(exchange.model_copy(update={"run_id": self.run_id}))
                existing.add(exchange.exchange_id)

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
            for har in sorted(browser_root.glob("*/traffic.har")):
                try:
                    items = import_har(har, self.engagement)
                except TrafficImportError:
                    continue
                self._add_exchanges(
                    [
                        item.model_copy(update={"account_alias": har.parent.name, "run_id": self.run_id})
                        for item in items
                    ]
                )
        model_path = self.artifact_root / "traffic" / "model.json"
        if model_path.is_file() and self.exchanges:
            self.traffic_model = build_traffic_model(self.exchanges)
        if self.validator_results:
            self.root_cause_clusters = RootCauseDeduper.cluster(result.outcome for result in self.validator_results)

    @staticmethod
    def _string_list(value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, str)]

    def _observation(
        self,
        proposal: ActionProposal,
        summary: str,
        *,
        gain: float,
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
            status=ObservationStatus.EXECUTED,
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
