"""Scope-derived action catalogs from which specialists select the next experiment."""

from __future__ import annotations

import re
from typing import Literal, cast
from urllib.parse import urlsplit, urlunsplit

from pydantic import JsonValue

from budobugs.core.identifiers import new_id
from budobugs.core.policy import target_allowed
from budobugs.models import (
    ActionKind,
    ActionProposal,
    AgentLoopState,
    AgentRole,
    Engagement,
    EngagementMode,
    Hypothesis,
    ProgramValidationPlan,
    SafeExperimentTemplate,
    SafeWebSocketExperimentTemplate,
    SafeWorkflowExperimentTemplate,
    VendorKnowledge,
)


class ActionCatalogBuilder:
    """Build safe actions; target content never supplies commands or raw arguments."""

    ROUTABLE_ROLES: tuple[AgentRole, ...] = (
        AgentRole.COORDINATOR,
        AgentRole.RECON_RESEARCHER,
        AgentRole.BROWSER_EXPLORER,
        AgentRole.TRAFFIC_MODELER,
        AgentRole.AUTHORIZATION_SPECIALIST,
        AgentRole.BUSINESS_LOGIC_SPECIALIST,
        AgentRole.API_AUTH_SPECIALIST,
        AgentRole.WEB_CLIENT_SPECIALIST,
        AgentRole.EVIDENCE_VALIDATOR,
        AgentRole.ADVERSARIAL_CRITIC,
        AgentRole.SOURCE_REVIEWER,
        AgentRole.REPORT_WRITER,
    )

    LAB_SCHEDULE: dict[int, tuple[AgentRole, ...]] = {
        1: (
            AgentRole.COORDINATOR,
            AgentRole.COORDINATOR,
            AgentRole.BROWSER_EXPLORER,
            AgentRole.TRAFFIC_MODELER,
        ),
        2: (
            AgentRole.RECON_RESEARCHER,
            AgentRole.RECON_RESEARCHER,
            AgentRole.SOURCE_REVIEWER,
            AgentRole.BROWSER_EXPLORER,
            AgentRole.AUTHORIZATION_SPECIALIST,
            AgentRole.AUTHORIZATION_SPECIALIST,
            AgentRole.AUTHORIZATION_SPECIALIST,
            AgentRole.AUTHORIZATION_SPECIALIST,
            AgentRole.AUTHORIZATION_SPECIALIST,
            AgentRole.AUTHORIZATION_SPECIALIST,
            AgentRole.AUTHORIZATION_SPECIALIST,
            AgentRole.BUSINESS_LOGIC_SPECIALIST,
            AgentRole.API_AUTH_SPECIALIST,
            AgentRole.API_AUTH_SPECIALIST,
            AgentRole.WEB_CLIENT_SPECIALIST,
            AgentRole.WEB_CLIENT_SPECIALIST,
            AgentRole.WEB_CLIENT_SPECIALIST,
            AgentRole.TRAFFIC_MODELER,
        ),
        3: (
            AgentRole.EVIDENCE_VALIDATOR,
            AgentRole.EVIDENCE_VALIDATOR,
            AgentRole.ADVERSARIAL_CRITIC,
            AgentRole.REPORT_WRITER,
            AgentRole.COORDINATOR,
        ),
    }
    PROGRAM_OBSERVE_SCHEDULE: tuple[AgentRole, ...] = (
        AgentRole.COORDINATOR,
        AgentRole.COORDINATOR,
        AgentRole.BROWSER_EXPLORER,
        AgentRole.TRAFFIC_MODELER,
    )
    PROGRAM_RESEARCH_SCHEDULE: tuple[AgentRole, ...] = (
        AgentRole.RECON_RESEARCHER,
        AgentRole.RECON_RESEARCHER,
        AgentRole.SOURCE_REVIEWER,
        AgentRole.BROWSER_EXPLORER,
        AgentRole.BROWSER_EXPLORER,
        AgentRole.AUTHORIZATION_SPECIALIST,
        AgentRole.AUTHORIZATION_SPECIALIST,
        AgentRole.BUSINESS_LOGIC_SPECIALIST,
        AgentRole.BUSINESS_LOGIC_SPECIALIST,
        AgentRole.API_AUTH_SPECIALIST,
        AgentRole.API_AUTH_SPECIALIST,
        AgentRole.WEB_CLIENT_SPECIALIST,
        AgentRole.WEB_CLIENT_SPECIALIST,
        AgentRole.TRAFFIC_MODELER,
        AgentRole.EVIDENCE_VALIDATOR,
        AgentRole.EVIDENCE_VALIDATOR,
        AgentRole.ADVERSARIAL_CRITIC,
        AgentRole.REPORT_WRITER,
        AgentRole.COORDINATOR,
    )

    def __init__(
        self,
        engagement: Engagement,
        safe_experiments: list[SafeExperimentTemplate | SafeWorkflowExperimentTemplate] | None = None,
        safe_websocket_experiments: list[SafeWebSocketExperimentTemplate] | None = None,
        knowledge: VendorKnowledge | None = None,
        hypotheses: list[Hypothesis] | None = None,
        program_validation_plans: list[ProgramValidationPlan] | None = None,
    ) -> None:
        self.engagement = engagement
        self.safe_experiments = safe_experiments or []
        self.safe_websocket_experiments = safe_websocket_experiments or []
        self.knowledge = knowledge
        self.hypotheses = hypotheses if hypotheses is not None else []
        self.program_validation_plans = program_validation_plans if program_validation_plans is not None else []

    def schedule(self, round_index: int) -> tuple[AgentRole, ...]:
        """Return the deterministic recovery fallback order, not the normal route."""

        if self.engagement.selected_mode is EngagementMode.LAB:
            return self.LAB_SCHEDULE.get(round_index, ())
        if self.engagement.selected_mode is EngagementMode.PROGRAM:
            if round_index == 1:
                return self.PROGRAM_OBSERVE_SCHEDULE
            if 2 <= round_index <= 8:
                return self.PROGRAM_RESEARCH_SCHEDULE
        return ()

    def routable_roles(self, round_index: int) -> tuple[AgentRole, ...]:
        """Return allow-listed hunt roles; ``actions`` determines live availability."""

        del round_index
        return self.ROUTABLE_ROLES

    def actions(
        self,
        role: AgentRole,
        round_index: int,
        state: AgentLoopState,
    ) -> list[ActionProposal]:
        candidates = (
            self._lab_actions(role, round_index, state)
            if self.engagement.selected_mode is EngagementMode.LAB
            else self._program_actions(role, round_index, state)
        )
        completed = {*state.executed_catalog_actions, *state.blocked_catalog_actions}
        ranked = [
            item.model_copy(
                update={
                    "expected_information_gain": min(
                        1.0,
                        item.expected_information_gain + self._knowledge_gain(item),
                    )
                }
            )
            for item in candidates
            if item.catalog_action_id not in completed
        ]
        return sorted(ranked, key=lambda item: (-item.expected_information_gain, item.catalog_action_id))

    def _knowledge_gain(self, action: ActionProposal) -> float:
        """Use observed changes and anomalies to rank safe follow-up actions."""

        if self.knowledge is None:
            return 0.0
        if action.catalog_action_id in self.knowledge.tested_candidate_ids:
            return -0.25
        gain = 0.0
        if self.knowledge.change_observations and action.agent_role in {
            AgentRole.BROWSER_EXPLORER,
            AgentRole.TRAFFIC_MODELER,
            AgentRole.BUSINESS_LOGIC_SPECIALIST,
            AgentRole.WEB_CLIENT_SPECIALIST,
        }:
            gain += 0.08
        if self.knowledge.anomalous_behaviors and action.agent_role in {
            AgentRole.AUTHORIZATION_SPECIALIST,
            AgentRole.BUSINESS_LOGIC_SPECIALIST,
            AgentRole.API_AUTH_SPECIALIST,
        }:
            gain += 0.10
        return gain

    def _action(
        self,
        action_id: str,
        round_index: int,
        role: AgentRole,
        skill: str,
        kind: ActionKind,
        objective: str,
        expected: str,
        *,
        target_url: str | None = None,
        method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] | None = None,
        accounts: list[str] | None = None,
        validator_id: str | None = None,
        base_exchange_id: str | None = None,
        tool_name: str | None = None,
        tool_arguments: dict[str, JsonValue] | None = None,
        candidate_id: str | None = None,
        mutation_scope: str = "read-only",
        gain: float = 0.6,
    ) -> ActionProposal:
        return ActionProposal(
            proposal_id=new_id("proposal"),
            catalog_action_id=action_id,
            round_index=round_index,
            agent_role=role,
            skill_name=skill,
            kind=kind,
            objective=objective,
            target_url=target_url,
            method=method,
            account_aliases=accounts or [],
            validator_id=validator_id,
            base_exchange_id=base_exchange_id,
            tool_name=tool_name,
            tool_arguments=tool_arguments or {},
            candidate_id=candidate_id,
            mutation_scope=mutation_scope,  # type: ignore[arg-type]
            expected_observation=expected,
            expected_information_gain=gain,
        )

    def _lab_actions(
        self,
        role: AgentRole,
        round_index: int,
        state: AgentLoopState,
    ) -> list[ActionProposal]:
        base = self.engagement.root_targets[0].uri.rstrip("/")
        if round_index == 1 and role is AgentRole.COORDINATOR:
            if not self._has_executed(state, "lab-engagement-intake"):
                return [
                    self._action(
                        "lab-engagement-intake",
                        1,
                        role,
                        "engagement-intake",
                        ActionKind.EVIDENCE_REVIEW,
                        "Recheck the already authorized lab engagement boundary before any scoped observation.",
                        "An executor-written summary of mode, declared roots, exclusions, accounts, and rate policy; "
                        "no new authorization is inferred.",
                        gain=0.99,
                    )
                ]
            return [
                self._action(
                    "lab-proxy-inventory",
                    1,
                    role,
                    "budobugs-controller",
                    ActionKind.PROXY_SEARCH,
                    "Read the selected backend's scoped live history before planning active experiments.",
                    "A normalized scoped history inventory and backend receipt.",
                    gain=0.7,
                )
            ]
        if round_index == 1 and role is AgentRole.BROWSER_EXPLORER:
            if not self._has_executed(state, "lab-engagement-intake"):
                return []
            return [
                self._action(
                    "lab-browser-two-account-explore",
                    1,
                    role,
                    "web-attack-surface",
                    ActionKind.BROWSER_EXPLORE,
                    "Log in as Alice and Bob in persistent isolated contexts, create one harmless object each, "
                    "and traverse the main fixture flows.",
                    "HAR, trace, DOM, screenshots, JS/API clues, forms, state changes, and new scoped URLs "
                    "for both accounts.",
                    target_url=base,
                    accounts=["alice", "bob"],
                    gain=0.95,
                )
            ]
        if round_index == 1 and role is AgentRole.TRAFFIC_MODELER:
            if not self._has_executed(
                state,
                "lab-proxy-inventory",
                "lab-browser-two-account-explore",
            ):
                return []
            return [
                self._action(
                    "lab-traffic-model",
                    1,
                    role,
                    "traffic-object-model",
                    ActionKind.TRAFFIC_MODEL,
                    "Normalize browser, proxy, and validation traffic into endpoints, parameters, objects, "
                    "roles, tenants, states, schemas, and differences.",
                    "A typed traffic model with provenance and uncertainty retained.",
                    gain=0.85,
                )
            ]
        validators: dict[AgentRole, list[tuple[str, str, str, float]]] = {
            AgentRole.AUTHORIZATION_SPECIALIST: [
                (
                    "fixture-horizontal-rest",
                    "authz-business-logic",
                    "Validate REST horizontal object authorization with two accounts and full controls.",
                    0.95,
                ),
                (
                    "fixture-horizontal-graphql",
                    "authz-business-logic",
                    "Validate GraphQL variable object authorization and test whether it shares the REST root cause.",
                    0.92,
                ),
                (
                    "fixture-horizontal-websocket",
                    "authz-business-logic",
                    "Validate actual WebSocket handshake and message-level object authorization, repeat the "
                    "cross-account subscription, and test the shared resolver root cause.",
                    0.91,
                ),
                (
                    "fixture-vertical-role",
                    "authz-business-logic",
                    "Validate low-role versus admin function authorization with repeat and secure equivalent control.",
                    0.93,
                ),
                (
                    "fixture-cross-tenant",
                    "authz-business-logic",
                    "Validate tenant context isolation using only red and blue fixture tenants.",
                    0.94,
                ),
                (
                    "fixture-file-share",
                    "authz-business-logic",
                    "Validate private file download and revoked-share consumption with owner and lifecycle controls.",
                    0.96,
                ),
            ],
            AgentRole.BUSINESS_LOGIC_SPECIALIST: [
                (
                    "fixture-business-workflow",
                    "authz-business-logic",
                    "Validate skipped workflow prerequisites and repeated one-time confirmation on a "
                    "resettable self-owned order.",
                    0.98,
                )
            ],
            AgentRole.API_AUTH_SPECIALIST: [
                (
                    "fixture-session-revocation",
                    "api-auth-session",
                    "Validate old-session capability after explicit revocation, including a revocation-aware "
                    "negative control.",
                    0.96,
                )
            ],
            AgentRole.WEB_CLIENT_SPECIALIST: [
                (
                    "fixture-client-xss",
                    "client-file-workflows",
                    "Validate an inert URL-to-innerHTML DOM flow against a textContent control in isolated "
                    "Playwright contexts.",
                    0.90,
                ),
                (
                    "fixture-cors-credentialed-origin",
                    "client-file-workflows",
                    "Validate trusted and evil Origin credentialed CORS behavior, exact ACAO/ACAC headers, "
                    "repeatable self-owned effect, and an allowlist-enforcing negative control.",
                    0.94,
                ),
                (
                    "fixture-csrf-token-bypass",
                    "client-file-workflows",
                    "Validate a trusted token baseline, repeated evil-Origin tokenless self-owned mutations, "
                    "and a CSRF-enforcing negative control with reset cleanup.",
                    0.94,
                ),
            ],
        }
        if round_index == 2 and role in validators:
            actions = [
                self._action(
                    validator_id,
                    2,
                    role,
                    skill,
                    ActionKind.VALIDATOR_RUN,
                    objective,
                    "Repeated result, normal and negative controls, strongest benign explanation, capability "
                    "delta, cleanup, and evidence closure.",
                    validator_id=validator_id,
                    mutation_scope=(
                        "reversible-fixture"
                        if validator_id in {"fixture-business-workflow", "fixture-session-revocation"}
                        else "read-only"
                    ),
                    gain=gain,
                )
                for validator_id, skill, objective, gain in validators[role]
            ]
            if role is AgentRole.AUTHORIZATION_SPECIALIST:
                actions.extend(
                    self._replay_actions(
                        "lab",
                        round_index,
                        role,
                        "authz-business-logic",
                        state=state,
                    )
                )
            if role is AgentRole.API_AUTH_SPECIALIST:
                actions.extend(
                    self._direct_get_actions(
                        "lab",
                        round_index,
                        role,
                        "api-auth-session",
                        state=state,
                        accounts=["alice", "bob"],
                    )
                )
            return actions
        if round_index == 2 and role is AgentRole.RECON_RESEARCHER:
            return self._recon_actions("lab", round_index, role, base, state)
        if round_index == 2 and role is AgentRole.SOURCE_REVIEWER:
            if not self._has_executed(
                state,
                "lab-browser-two-account-explore",
                "lab-traffic-model",
            ):
                return []
            return [
                self._action(
                    "lab-captured-source-review",
                    round_index,
                    role,
                    "source-secret-supply-chain",
                    ActionKind.EVIDENCE_REVIEW,
                    "Review only the client JavaScript, API links, response schemas, and browser artifacts "
                    "actually captured from the scoped fixture.",
                    "A redacted executor-derived input inventory with exchange, schema-family, clue, and "
                    "browser-artifact identifiers; no static signal is promoted to a finding.",
                    gain=0.81,
                )
            ]
        if round_index == 2 and role is AgentRole.BROWSER_EXPLORER:
            return self._navigation_actions(
                "lab",
                round_index,
                role,
                "web-attack-surface",
                state=state,
                accounts=["alice", "bob"],
            )
        if round_index == 2 and role is AgentRole.TRAFFIC_MODELER:
            if self._lab_has_pending_round_two_research(state):
                return []
            return [
                self._action(
                    "lab-traffic-remodel",
                    round_index,
                    role,
                    "traffic-object-model",
                    ActionKind.TRAFFIC_MODEL,
                    "Refresh the typed traffic model after specialist browser, replay, direct, tool, "
                    "and validator actions.",
                    "A post-experiment endpoint/object/role/tenant/state model.",
                    gain=0.78,
                )
            ]
        if round_index == 3 and role is AgentRole.EVIDENCE_VALIDATOR:
            if not self._has_executed(
                state,
                "lab-traffic-remodel",
                "lab-passive-history-inventory",
                "lab-registered-http-probe",
                "lab-captured-source-review",
            ):
                return []
            if self._has_executed(state, "fixture-false-control-suite"):
                return [
                    self._action(
                        "lab-hypothesis-evidence-review",
                        3,
                        role,
                        "hypothesis-and-validation",
                        ActionKind.EVIDENCE_REVIEW,
                        "Bind every fixture hypothesis and validator outcome to its repeat, normal, negative, "
                        "cleanup, benign-explanation, and evidence-closure result.",
                        "An executor-derived hypothesis/outcome inventory that preserves missing controls and "
                        "candidate identities.",
                        gain=0.76,
                    )
                ]
            return [
                self._action(
                    "fixture-false-control-suite",
                    3,
                    role,
                    "lab-evaluation",
                    ActionKind.VALIDATOR_RUN,
                    "Attempt to falsify public-object, owner-enforced, and escaped-client lookalikes.",
                    "At least three artifact-backed KILL decisions if the controls behave safely.",
                    validator_id="fixture-false-control-suite",
                    gain=0.82,
                )
            ]
        if round_index == 3 and role is AgentRole.ADVERSARIAL_CRITIC:
            if not self._has_executed(
                state,
                "fixture-false-control-suite",
                "lab-hypothesis-evidence-review",
            ):
                return []
            return [
                self._action(
                    "lab-adversarial-review",
                    3,
                    role,
                    "evidence-critic",
                    ActionKind.EVIDENCE_REVIEW,
                    "Review every validator result for public design, cache, sharing, state pollution, "
                    "third-party data, impact inflation, and same-fix duplication.",
                    "A conservative review summary and unresolved tests; no self-reported PASS is trusted.",
                    gain=0.65,
                )
            ]
        if round_index == 3 and role is AgentRole.REPORT_WRITER:
            if not self._has_executed(state, "lab-adversarial-review"):
                return []
            return [
                self._action(
                    "lab-report-readiness-review",
                    3,
                    role,
                    "butian-report",
                    ActionKind.EVIDENCE_REVIEW,
                    "Check which critic-reviewed fixture findings have complete, redacted, independently "
                    "reproducible inputs for the downstream Butian/SRC report generator.",
                    "An executor-derived report-input readiness receipt; it does not claim that a report was "
                    "submitted or generated by this review action.",
                    gain=0.54,
                )
            ]
        if round_index == 3 and role is AgentRole.COORDINATOR:
            if not self._has_executed(state, "lab-report-readiness-review"):
                return []
            return [
                self._action(
                    "lab-finish",
                    3,
                    role,
                    "budobugs-controller",
                    ActionKind.FINISH,
                    "Stop after the evidence review because the bounded fixture action catalog is exhausted.",
                    "A stop reason tied to exhausted useful actions, not a fixed model-call count.",
                    gain=0.1,
                )
            ]
        return []

    def _lab_has_pending_round_two_research(self, state: AgentLoopState) -> bool:
        """Keep the refresh behind every currently live round-two research action."""

        completed = {*state.executed_catalog_actions, *state.blocked_catalog_actions}
        roles = (
            AgentRole.RECON_RESEARCHER,
            AgentRole.SOURCE_REVIEWER,
            AgentRole.BROWSER_EXPLORER,
            AgentRole.AUTHORIZATION_SPECIALIST,
            AgentRole.BUSINESS_LOGIC_SPECIALIST,
            AgentRole.API_AUTH_SPECIALIST,
            AgentRole.WEB_CLIENT_SPECIALIST,
        )
        return any(
            action.catalog_action_id not in completed for role in roles for action in self._lab_actions(role, 2, state)
        )

    def _program_actions(
        self,
        role: AgentRole,
        round_index: int,
        state: AgentLoopState,
    ) -> list[ActionProposal]:
        base = self.engagement.root_targets[0].uri.rstrip("/")
        accounts = list(self.engagement.testing_accounts_secret_refs) or ["anonymous"]
        if round_index == 1 and role is AgentRole.COORDINATOR:
            if not self._has_executed(state, "program-engagement-intake"):
                return [
                    self._action(
                        "program-engagement-intake",
                        1,
                        role,
                        "engagement-intake",
                        ActionKind.EVIDENCE_REVIEW,
                        "Recheck the one-time authorized program engagement, exact roots, exclusions, account "
                        "aliases, and rate boundary before observation.",
                        "An executor-written authorization-boundary summary without secret values or inferred "
                        "affiliated assets.",
                        gain=0.99,
                    )
                ]
            return [
                self._action(
                    "program-proxy-inventory",
                    1,
                    role,
                    "budobugs-controller",
                    ActionKind.PROXY_SEARCH,
                    "Read current scoped proxy/HAR history and recover previous entry points.",
                    "Scoped history observations that can trigger browser or replay follow-ups.",
                    gain=0.8,
                )
            ]
        if round_index == 1 and role is AgentRole.BROWSER_EXPLORER:
            if not self._has_executed(state, "program-engagement-intake"):
                return []
            return [
                self._action(
                    "program-authenticated-browser-explore",
                    1,
                    role,
                    "web-attack-surface",
                    ActionKind.BROWSER_EXPLORE,
                    "Use persistent account contexts to traverse scoped menus, forms, main workflows, "
                    "scripts, and APIs.",
                    "Account-linked HAR, trace, DOM, screenshot, JS/API, form, and state observations.",
                    target_url=base,
                    accounts=accounts,
                    gain=0.95,
                )
            ]
        if round_index == 1 and role is AgentRole.TRAFFIC_MODELER:
            if not self._has_executed(
                state,
                "program-proxy-inventory",
                "program-authenticated-browser-explore",
            ):
                return []
            return [
                self._action(
                    "program-traffic-model",
                    1,
                    role,
                    "traffic-object-model",
                    ActionKind.TRAFFIC_MODEL,
                    "Build the current endpoint/object/role/tenant/state and schema model from all captured traffic.",
                    "A typed model that creates protocol- and parameter-aware validation candidates.",
                    gain=0.9,
                )
            ]
        research_roles = {
            AgentRole.RECON_RESEARCHER,
            AgentRole.BROWSER_EXPLORER,
            AgentRole.AUTHORIZATION_SPECIALIST,
            AgentRole.BUSINESS_LOGIC_SPECIALIST,
            AgentRole.API_AUTH_SPECIALIST,
            AgentRole.WEB_CLIENT_SPECIALIST,
        }
        if round_index >= 2 and role in research_roles:
            return self._program_research_actions(role, round_index, state)
        if round_index >= 2 and role is AgentRole.SOURCE_REVIEWER:
            if not self._has_executed(
                state,
                "program-authenticated-browser-explore",
                "program-traffic-model",
            ):
                return []
            return [
                self._action(
                    "program-captured-source-review",
                    round_index,
                    role,
                    "source-secret-supply-chain",
                    ActionKind.EVIDENCE_REVIEW,
                    "Review only captured client JavaScript, frontend/API links, response schemas, and browser "
                    "artifacts inside the declared program scope.",
                    "A redacted executor-derived source/schema inventory whose empty and unresolved inputs remain "
                    "explicit rather than being promoted to findings.",
                    gain=0.81,
                )
            ]
        if round_index >= 2 and role is AgentRole.TRAFFIC_MODELER and self._needs_traffic_refresh(state):
            return [
                self._action(
                    f"program-traffic-remodel-{round_index}",
                    round_index,
                    role,
                    "traffic-object-model",
                    ActionKind.TRAFFIC_MODEL,
                    "Refresh the business and traffic model after newly executed browser, replay, direct, "
                    "or validator actions.",
                    "A current model whose provenance includes every newly observed exchange.",
                    gain=0.8,
                )
            ]
        pending_research = self._program_has_pending_research(state, round_index)
        research_prerequisites_done = self._has_executed(
            state,
            "program-passive-history-inventory",
            "program-registered-http-probe",
            "program-captured-source-review",
        )
        model_is_current = not self._needs_traffic_refresh(state)
        if (
            round_index >= 3
            and not pending_research
            and research_prerequisites_done
            and model_is_current
            and role is AgentRole.EVIDENCE_VALIDATOR
        ):
            if not self._has_executed(state, "program-hypothesis-evidence-review"):
                return [
                    self._action(
                        "program-hypothesis-evidence-review",
                        round_index,
                        role,
                        "hypothesis-and-validation",
                        ActionKind.EVIDENCE_REVIEW,
                        "Reconcile observed program hypotheses, executable plans, unfinished candidates, and every "
                        "normal, negative, repeat, cleanup, and benign-explanation result.",
                        "An executor-derived hypothesis/plan/outcome inventory with unsupported candidates left "
                        "unfinished rather than represented by placeholder HOLD outcomes.",
                        gain=0.7,
                    )
                ]
            return [
                self._action(
                    "program-evidence-review",
                    round_index,
                    role,
                    "evidence-critic",
                    ActionKind.EVIDENCE_REVIEW,
                    "Recompute controls and evidence closure for all program candidates.",
                    "CONFIRMED, HOLD, or KILL per candidate with missing tests made explicit.",
                    gain=0.65,
                )
            ]
        hypothesis_review_done = "program-hypothesis-evidence-review" in state.executed_catalog_actions
        evidence_done = "program-evidence-review" in state.executed_catalog_actions
        if (
            round_index >= 3
            and not pending_research
            and research_prerequisites_done
            and model_is_current
            and hypothesis_review_done
            and evidence_done
            and role is AgentRole.ADVERSARIAL_CRITIC
        ):
            return [
                self._action(
                    "program-adversarial-review",
                    round_index,
                    role,
                    "evidence-critic",
                    ActionKind.EVIDENCE_REVIEW,
                    "Attempt to falsify every candidate and test same-fix duplication.",
                    "A conservative independent review bound to observed artifacts.",
                    gain=0.55,
                )
            ]
        critic_done = "program-adversarial-review" in state.executed_catalog_actions
        if (
            round_index >= 3
            and not pending_research
            and research_prerequisites_done
            and model_is_current
            and hypothesis_review_done
            and evidence_done
            and critic_done
            and role is AgentRole.REPORT_WRITER
        ):
            return [
                self._action(
                    "program-report-readiness-review",
                    round_index,
                    role,
                    "butian-report",
                    ActionKind.EVIDENCE_REVIEW,
                    "Check which independently criticized findings have the exact redacted evidence, controls, "
                    "capability delta, cleanup, root-cause cluster, and reproduction inputs required by the "
                    "downstream report generator.",
                    "An executor-derived report readiness receipt; zero ready findings is recorded honestly and "
                    "produces no report, while still allowing an exhausted research loop to stop.",
                    gain=0.54,
                )
            ]
        report_ready = "program-report-readiness-review" in state.executed_catalog_actions
        if (
            round_index >= 3
            and not pending_research
            and research_prerequisites_done
            and model_is_current
            and hypothesis_review_done
            and evidence_done
            and critic_done
            and report_ready
            and role is AgentRole.COORDINATOR
        ):
            return [
                self._action(
                    "program-finish",
                    round_index,
                    role,
                    "budobugs-controller",
                    ActionKind.FINISH,
                    "Stop because every currently derivable scoped experiment is executed or durably blocked "
                    "and evidence review is complete.",
                    "An explicit exhausted-catalog stop receipt with unfinished HOLD candidates persisted "
                    "for the next run.",
                    gain=0.1,
                )
            ]
        return []

    def _program_has_pending_research(self, state: AgentLoopState, round_index: int) -> bool:
        completed = {*state.executed_catalog_actions, *state.blocked_catalog_actions}
        roles = (
            AgentRole.RECON_RESEARCHER,
            AgentRole.BROWSER_EXPLORER,
            AgentRole.AUTHORIZATION_SPECIALIST,
            AgentRole.BUSINESS_LOGIC_SPECIALIST,
            AgentRole.API_AUTH_SPECIALIST,
            AgentRole.WEB_CLIENT_SPECIALIST,
        )
        return any(
            action.catalog_action_id not in completed
            for role in roles
            for action in self._program_research_actions(role, round_index, state)
        )

    def _program_research_actions(
        self,
        role: AgentRole,
        round_index: int,
        state: AgentLoopState,
    ) -> list[ActionProposal]:
        """Return only program research actions, excluding review/model/finish recursion."""

        base = self.engagement.root_targets[0].uri.rstrip("/")
        accounts = list(self.engagement.testing_accounts_secret_refs) or ["anonymous"]
        if role is AgentRole.RECON_RESEARCHER:
            return self._recon_actions("program", round_index, role, base, state)
        if role is AgentRole.BROWSER_EXPLORER:
            return self._navigation_actions(
                "program", round_index, role, "web-attack-surface", state=state, accounts=accounts
            )
        if role is AgentRole.AUTHORIZATION_SPECIALIST:
            role_actions = self._replay_actions("program", round_index, role, "authz-business-logic", state=state)
            role_actions.extend(self._program_validation_actions(role, round_index))
            return role_actions or [
                self._domain_review_action(
                    role,
                    round_index,
                    "authz-business-logic",
                    "authorization",
                )
            ]
        role_actions = []
        if role is AgentRole.API_AUTH_SPECIALIST:
            role_actions.extend(
                self._direct_get_actions(
                    "program", round_index, role, "api-auth-session", state=state, accounts=accounts
                )
            )
        role_actions.extend(self._program_validation_actions(role, round_index))
        if role_actions:
            return role_actions
        domain_skills = {
            AgentRole.BUSINESS_LOGIC_SPECIALIST: ("authz-business-logic", "business-logic"),
            AgentRole.API_AUTH_SPECIALIST: ("api-auth-session", "authentication-session"),
            AgentRole.WEB_CLIENT_SPECIALIST: ("client-file-workflows", "web-client-file"),
        }
        if role in domain_skills:
            skill, domain = domain_skills[role]
            return [self._domain_review_action(role, round_index, skill, domain)]
        return []

    def _program_validation_actions(
        self,
        role: AgentRole,
        round_index: int,
    ) -> list[ActionProposal]:
        by_hypothesis = {item.hypothesis_id: item for item in self.hypotheses}
        result: list[ActionProposal] = []
        for plan in self.program_validation_plans:
            if plan.specialist_role != role.value:
                continue
            hypothesis = by_hypothesis.get(plan.hypothesis_id)
            if hypothesis is None:
                continue
            result.append(
                self._action(
                    f"program-validate--{hypothesis.hypothesis_id}",
                    round_index,
                    role,
                    hypothesis.skill_name,
                    ActionKind.VALIDATOR_RUN,
                    f"Execute hypothesis with bound real controls: {hypothesis.title}",
                    "The same hypothesis ID in the persisted taxonomy, proposal, observation, and outcome.",
                    validator_id=plan.validator_id,
                    candidate_id=hypothesis.hypothesis_id,
                    mutation_scope=(
                        "read-only" if plan.control_source == "observed-object-differential" else "self-owned"
                    ),
                    gain=plan.expected_information_gain,
                )
            )
        return result

    def _tool_probe_action(
        self,
        prefix: str,
        round_index: int,
        role: AgentRole,
        base: str,
    ) -> ActionProposal:
        return self._action(
            f"{prefix}-registered-http-probe",
            round_index,
            role,
            "tool-operator",
            ActionKind.TOOL_TASK,
            "Run the registered, version-pinned HTTP probe once against the engagement-injected root "
            "through the no-shell wrapper.",
            "A tool receipt and bounded root technology/status observation, or a durable unavailable-tool observation.",
            tool_name="budo-http-probe",
            tool_arguments={"arguments": [], "target": base},
            gain=0.68,
        )

    def _recon_actions(
        self,
        prefix: str,
        round_index: int,
        role: AgentRole,
        base: str,
        state: AgentLoopState,
    ) -> list[ActionProposal]:
        passive_id = f"{prefix}-passive-history-inventory"
        if not self._has_executed(state, passive_id):
            return [
                self._action(
                    passive_id,
                    round_index,
                    role,
                    "passive-recon",
                    ActionKind.PROXY_SEARCH,
                    "Refresh the scoped passive history inventory and retain only declared-root JavaScript, "
                    "API, login, and business entry-point observations.",
                    "A provenance-linked scoped history observation; passive hits remain signals, not findings.",
                    gain=0.73,
                )
            ]
        return [self._tool_probe_action(prefix, round_index, role, base)]

    def _domain_review_action(
        self,
        role: AgentRole,
        round_index: int,
        skill: str,
        domain: str,
    ) -> ActionProposal:
        return self._action(
            f"program-{role.value}-{domain}-input-review",
            round_index,
            role,
            skill,
            ActionKind.EVIDENCE_REVIEW,
            f"Inventory the actually observed {domain} traffic, hypotheses, plans, and outcomes when no "
            "executor-bound experiment is currently derivable.",
            "An executor-derived zero-or-more input summary; it creates no placeholder candidate, HOLD, or "
            "vulnerability claim.",
            gain=0.52,
        )

    def _navigation_actions(
        self,
        prefix: str,
        round_index: int,
        role: AgentRole,
        skill: str,
        *,
        state: AgentLoopState,
        accounts: list[str],
    ) -> list[ActionProposal]:
        urls = self._observed_urls(state)
        alias = accounts[0] if accounts else "anonymous"
        return [
            self._action(
                f"{prefix}-navigate-{index}-{self._slug(urlsplit(url).path)}",
                round_index,
                role,
                skill,
                ActionKind.BROWSER_NAVIGATE,
                f"Open one newly observed scoped page in the persistent {alias} context and capture its "
                "rendered state.",
                "A scoped final URL, DOM/screenshot artifact, and any newly captured read-only exchange.",
                target_url=url,
                accounts=[alias],
                gain=0.74,
            )
            for index, url in enumerate(urls[:6], start=1)
        ]

    def _replay_actions(
        self,
        prefix: str,
        round_index: int,
        role: AgentRole,
        skill: str,
        *,
        state: AgentLoopState,
    ) -> list[ActionProposal]:
        actions: list[ActionProposal] = []
        seen: set[str] = set()
        limit = 1 if prefix == "lab" else 6
        for observation in state.observations:
            raw = observation.details.get("replayable_exchanges")
            if not isinstance(raw, list):
                continue
            for item in raw:
                if not isinstance(item, dict):
                    continue
                exchange_id = item.get("exchange_id")
                method = item.get("method")
                alias = item.get("account_alias")
                if (
                    not isinstance(exchange_id, str)
                    or not 1 <= len(exchange_id) <= 128
                    or exchange_id in seen
                    or method not in {"GET", "OPTIONS"}
                    or alias is not None
                    and not isinstance(alias, str)
                ):
                    continue
                seen.add(exchange_id)
                actions.append(
                    self._action(
                        f"{prefix}-replay-{len(actions) + 1}-{self._slug(exchange_id)}",
                        round_index,
                        role,
                        skill,
                        ActionKind.PROXY_REPLAY,
                        "Replay one previously observed read-only scoped exchange through the selected proxy backend.",
                        "A fresh backend-linked response that can be compared with the original observation.",
                        method=cast(Literal["GET", "OPTIONS"], method),
                        accounts=[alias] if alias else [],
                        base_exchange_id=exchange_id,
                        gain=0.72,
                    )
                )
                if len(actions) >= limit:
                    return actions
        return actions

    def _direct_get_actions(
        self,
        prefix: str,
        round_index: int,
        role: AgentRole,
        skill: str,
        *,
        state: AgentLoopState,
        accounts: list[str],
    ) -> list[ActionProposal]:
        alias = accounts[0] if accounts else "anonymous"
        limit = 1 if prefix == "lab" else 4
        return [
            self._action(
                f"{prefix}-direct-get-{index}-{self._slug(urlsplit(url).path)}",
                round_index,
                role,
                skill,
                ActionKind.HTTP_REQUEST,
                f"Collect a fresh typed GET baseline for one observed scoped URL in the {alias} account context.",
                "A direct-backend exchange available to later account/session/control comparisons.",
                target_url=url,
                method="GET",
                accounts=[alias],
                gain=0.7,
            )
            for index, url in enumerate(self._observed_urls(state)[:limit], start=1)
        ]

    def _observed_urls(self, state: AgentLoopState) -> list[str]:
        blocked_words = {"logout", "delete", "remove", "payment", "purchase", "destroy", "unsubscribe"}
        result: list[str] = []
        base = self.engagement.root_targets[0].uri.rstrip("/")
        for observation in state.observations:
            for raw in observation.discovered_urls:
                try:
                    parsed = urlsplit(raw)
                    safe = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
                except ValueError:
                    continue
                if (
                    parsed.username is not None
                    or parsed.password is not None
                    or safe.rstrip("/") == base
                    or any(word in safe.lower() for word in blocked_words)
                    or not target_allowed(self.engagement, safe).allowed
                    or safe in result
                ):
                    continue
                result.append(safe)
        return result

    @staticmethod
    def _slug(value: str) -> str:
        slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._")
        return (slug or "root")[:48]

    @staticmethod
    def _needs_traffic_refresh(state: AgentLoopState) -> bool:
        last_model = max(
            (index for index, turn in enumerate(state.turns) if turn.proposal.kind is ActionKind.TRAFFIC_MODEL),
            default=-1,
        )
        refresh_kinds = {
            ActionKind.BROWSER_EXPLORE,
            ActionKind.BROWSER_NAVIGATE,
            ActionKind.BROWSER_FORM,
            ActionKind.PROXY_REPLAY,
            ActionKind.HTTP_REQUEST,
            ActionKind.VALIDATOR_RUN,
        }
        return any(
            turn.observation.status.value == "executed" and turn.proposal.kind in refresh_kinds
            for turn in state.turns[last_model + 1 :]
        )

    @staticmethod
    def _has_executed(state: AgentLoopState, *action_ids: str) -> bool:
        """Require completed observations; blocked/advertised actions never unlock dependants."""

        completed = set(state.executed_catalog_actions)
        return all(action_id in completed for action_id in action_ids)
