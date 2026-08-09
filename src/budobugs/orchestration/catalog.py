"""Scope-derived action catalogs from which specialists select the next experiment."""

from __future__ import annotations

from budobugs.core.identifiers import new_id
from budobugs.models import (
    ActionKind,
    ActionProposal,
    AgentLoopState,
    AgentRole,
    Engagement,
    EngagementMode,
)


class ActionCatalogBuilder:
    """Build safe actions; target content never supplies commands or raw arguments."""

    LAB_SCHEDULE: dict[int, tuple[AgentRole, ...]] = {
        1: (
            AgentRole.COORDINATOR,
            AgentRole.BROWSER_EXPLORER,
            AgentRole.TRAFFIC_MODELER,
        ),
        2: (
            AgentRole.AUTHORIZATION_SPECIALIST,
            AgentRole.AUTHORIZATION_SPECIALIST,
            AgentRole.AUTHORIZATION_SPECIALIST,
            AgentRole.AUTHORIZATION_SPECIALIST,
            AgentRole.AUTHORIZATION_SPECIALIST,
            AgentRole.BUSINESS_LOGIC_SPECIALIST,
            AgentRole.API_AUTH_SPECIALIST,
            AgentRole.WEB_CLIENT_SPECIALIST,
        ),
        3: (
            AgentRole.EVIDENCE_VALIDATOR,
            AgentRole.ADVERSARIAL_CRITIC,
            AgentRole.COORDINATOR,
        ),
    }
    PROGRAM_SCHEDULE: dict[int, tuple[AgentRole, ...]] = {
        1: (
            AgentRole.COORDINATOR,
            AgentRole.BROWSER_EXPLORER,
            AgentRole.TRAFFIC_MODELER,
        ),
        2: (
            AgentRole.AUTHORIZATION_SPECIALIST,
            AgentRole.BUSINESS_LOGIC_SPECIALIST,
            AgentRole.API_AUTH_SPECIALIST,
            AgentRole.WEB_CLIENT_SPECIALIST,
        ),
        3: (
            AgentRole.EVIDENCE_VALIDATOR,
            AgentRole.ADVERSARIAL_CRITIC,
            AgentRole.COORDINATOR,
        ),
    }

    def __init__(self, engagement: Engagement) -> None:
        self.engagement = engagement

    def schedule(self, round_index: int) -> tuple[AgentRole, ...]:
        schedule = self.LAB_SCHEDULE if self.engagement.selected_mode is EngagementMode.LAB else self.PROGRAM_SCHEDULE
        return schedule.get(round_index, ())

    def actions(
        self,
        role: AgentRole,
        round_index: int,
        state: AgentLoopState,
    ) -> list[ActionProposal]:
        candidates = (
            self._lab_actions(role, round_index)
            if self.engagement.selected_mode is EngagementMode.LAB
            else self._program_actions(role, round_index)
        )
        return [item for item in candidates if item.catalog_action_id not in state.executed_catalog_actions]

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
        method: str | None = None,
        accounts: list[str] | None = None,
        validator_id: str | None = None,
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
            method=method,  # type: ignore[arg-type]
            account_aliases=accounts or [],
            validator_id=validator_id,
            mutation_scope=mutation_scope,  # type: ignore[arg-type]
            expected_observation=expected,
            expected_information_gain=gain,
        )

    def _lab_actions(self, role: AgentRole, round_index: int) -> list[ActionProposal]:
        base = self.engagement.root_targets[0].uri.rstrip("/")
        if round_index == 1 and role is AgentRole.COORDINATOR:
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
                )
            ],
        }
        if round_index == 2 and role in validators:
            return [
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
        if round_index == 3 and role is AgentRole.EVIDENCE_VALIDATOR:
            return [
                self._action(
                    "fixture-false-control-suite",
                    3,
                    role,
                    "evidence-critic",
                    ActionKind.VALIDATOR_RUN,
                    "Attempt to falsify public-object, owner-enforced, and escaped-client lookalikes.",
                    "At least three artifact-backed KILL decisions if the controls behave safely.",
                    validator_id="fixture-false-control-suite",
                    gain=0.82,
                )
            ]
        if round_index == 3 and role is AgentRole.ADVERSARIAL_CRITIC:
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
        if round_index == 3 and role is AgentRole.COORDINATOR:
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

    def _program_actions(self, role: AgentRole, round_index: int) -> list[ActionProposal]:
        base = self.engagement.root_targets[0].uri.rstrip("/")
        accounts = list(self.engagement.testing_accounts_secret_refs) or ["anonymous"]
        if round_index == 1 and role is AgentRole.COORDINATOR:
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
        program_validators = {
            AgentRole.AUTHORIZATION_SPECIALIST: (
                "program-authorization-differential",
                "authz-business-logic",
                "Execute the highest bounty-score account/role/tenant/object differential that has two "
                "self-owned controls.",
            ),
            AgentRole.BUSINESS_LOGIC_SPECIALIST: (
                "program-business-workflow",
                "authz-business-logic",
                "Execute the highest-value reversible state-order, replay, revoke, or expiry experiment on "
                "a self-owned object.",
            ),
            AgentRole.API_AUTH_SPECIALIST: (
                "program-api-auth-session",
                "api-auth-session",
                "Execute the best-supported REST/GraphQL/WebSocket or session lifecycle differential "
                "without credential guessing.",
            ),
            AgentRole.WEB_CLIENT_SPECIALIST: (
                "program-client-file",
                "client-file-workflows",
                "Execute an inert browser source-to-sink or file/share lifecycle experiment with a safe control.",
            ),
        }
        if round_index == 2 and role in program_validators:
            validator_id, skill, objective = program_validators[role]
            return [
                self._action(
                    validator_id,
                    2,
                    role,
                    skill,
                    ActionKind.VALIDATOR_RUN,
                    objective,
                    "A typed outcome or HOLD with the exact missing control; no third-party expansion.",
                    validator_id=validator_id,
                    mutation_scope="self-owned",
                    gain=0.88,
                )
            ]
        if round_index == 3 and role is AgentRole.EVIDENCE_VALIDATOR:
            return [
                self._action(
                    "program-evidence-review",
                    3,
                    role,
                    "evidence-critic",
                    ActionKind.EVIDENCE_REVIEW,
                    "Recompute controls and evidence closure for all program candidates.",
                    "CONFIRMED, HOLD, or KILL per candidate with missing tests made explicit.",
                    gain=0.65,
                )
            ]
        if round_index == 3 and role is AgentRole.ADVERSARIAL_CRITIC:
            return [
                self._action(
                    "program-adversarial-review",
                    3,
                    role,
                    "evidence-critic",
                    ActionKind.EVIDENCE_REVIEW,
                    "Attempt to falsify every candidate and test same-fix duplication.",
                    "A conservative independent review bound to observed artifacts.",
                    gain=0.55,
                )
            ]
        if round_index == 3 and role is AgentRole.COORDINATOR:
            return [
                self._action(
                    "program-finish",
                    3,
                    role,
                    "budobugs-controller",
                    ActionKind.FINISH,
                    "Stop only if remaining information gain is below threshold or the current budget is exhausted.",
                    "An explicit stop reason and unfinished candidates persisted for the next run.",
                    gain=0.1,
                )
            ]
        return []
