"""Recoverable plan-execute-observe agent orchestration."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

from budobugs.agents.router import ModelRouter
from budobugs.agents.runner import CodexTaskRunner
from budobugs.core.identifiers import new_id
from budobugs.core.io import atomic_write_json
from budobugs.core.redaction import redact_text
from budobugs.knowledge.vendor import RootCauseDeduper
from budobugs.models import (
    ActionKind,
    ActionProposal,
    AgentInvocation,
    AgentLoopState,
    AgentLoopStatus,
    AgentRole,
    AgentRouteReceipt,
    AgentTurnReceipt,
    ControlExperiment,
    Engagement,
    Finding,
    HttpExchange,
    Observation,
    ObservationStatus,
    PhaseName,
    RootCauseCluster,
    VendorKnowledge,
)
from budobugs.models.base import utc_now
from budobugs.orchestration.catalog import ActionCatalogBuilder
from budobugs.orchestration.executor import TypedActionExecutor
from budobugs.orchestration.service import RepositoryService


@dataclass(frozen=True, slots=True)
class AgentLoopExecution:
    state: AgentLoopState
    findings: list[Finding]
    controls_by_finding: dict[str, list[ControlExperiment]]
    exchanges: list[HttpExchange]
    browser_artifacts: list[str]
    root_cause_clusters: list[RootCauseCluster]
    state_path: str
    receipt_path: str


class AgentLoopInterrupted(RuntimeError):
    """Raised after a persisted turn limit to prove continuation of the same chain."""

    def __init__(self, execution: AgentLoopExecution) -> None:
        super().__init__("agent loop intentionally interrupted after persisted typed turns")
        self.execution = execution


class _CoordinatorRouteRejected(RuntimeError):
    """The model responded, but its route was not valid for the safe catalog."""


def _turn_executed_successfully(turn: AgentTurnReceipt) -> bool:
    if turn.observation.status is not ObservationStatus.EXECUTED:
        return False
    return turn.proposal.kind is not ActionKind.TOOL_TASK or turn.observation.details.get("status") == "completed"


class _AgentChoice(BaseModel):
    """A complete catalog proposal encoded as a flat structured-output string.

    A recursive object schema (and later a long enum of full proposal strings)
    caused fresh Codex threads to time out while sampling. ``proposal_json``
    preserves the entire typed ActionProposal as output evidence without asking
    structured output to sample its model schema. The provider still re-binds
    every policy-critical field to the catalog before an executor sees it.
    """

    model_config = ConfigDict(extra="forbid")

    proposal_json: str = Field(min_length=2, max_length=20_000)
    rationale: str = Field(min_length=1, max_length=4000)
    expected_information_gain: float = Field(ge=0, le=1)
    follow_up: str = Field(min_length=1, max_length=2000)
    _proposal: ActionProposal | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def require_complete_proposal(self) -> _AgentChoice:
        try:
            proposal = ActionProposal.model_validate_json(self.proposal_json)
        except ValueError as exc:
            raise ValueError(f"proposal_json is not a valid ActionProposal: {exc}") from exc
        missing = sorted(set(ActionProposal.model_fields).difference(proposal.model_fields_set))
        if missing:
            raise ValueError(f"proposal must include every ActionProposal field; missing: {', '.join(missing)}")
        self._proposal = proposal
        return self

    @property
    def proposal(self) -> ActionProposal:
        if self._proposal is None:  # pragma: no cover - guarded by the after validator
            raise RuntimeError("validated AgentChoice has no ActionProposal")
        return self._proposal


class _AgentRouteChoice(BaseModel):
    model_config = ConfigDict(extra="forbid")

    selected_role: AgentRole
    rationale: str = Field(min_length=1, max_length=4000)
    expected_information_gain: float = Field(ge=0, le=1)
    follow_up: str = Field(min_length=1, max_length=2000)


class _CodexInvocationLedgerEntry(BaseModel):
    """Durable raw runner result, including selections that never become turns."""

    model_config = ConfigDict(extra="forbid")

    entry_id: str
    role: AgentRole
    skill_name: str
    thread_id: str | None = None
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cached_input_tokens: int = Field(default=0, ge=0)
    events_path: str | None = None
    status: Literal["PENDING", "PASS", "INVALID_OUTPUT"]
    detail: str = ""
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class _CodexInvocationLedger(BaseModel):
    """Run-scoped recovery ledger kept separate from successful typed receipts."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    run_id: str
    engagement_id: str
    entries: list[_CodexInvocationLedgerEntry] = Field(default_factory=list)


class PolicyProposalProvider:
    """Deterministic provider used for offline verification of the same typed loop."""

    async def propose(
        self,
        *,
        role: AgentRole,
        skill_instruction: str,
        skill_workflow: str,
        candidates: list[ActionProposal],
        state: AgentLoopState,
    ) -> tuple[ActionProposal, AgentInvocation]:
        del skill_instruction, skill_workflow, state
        if not candidates:
            raise RuntimeError(f"no safe catalog action is available for {role.value}")
        selected = max(candidates, key=lambda item: (item.expected_information_gain, item.catalog_action_id))
        invocation = AgentInvocation(
            invocation_id=new_id("agent-invocation"),
            role=role,
            skill_name=selected.skill_name,
            provider="policy",
            model="local-policy",
            status="PASS",
            detail="selected the highest expected-information-gain safe catalog action",
        )
        return selected, invocation

    async def route(
        self,
        *,
        candidates_by_role: dict[AgentRole, list[ActionProposal]],
        state: AgentLoopState,
        skill_instruction: str,
        skill_workflow: str,
    ) -> tuple[AgentRole, str, float, AgentInvocation]:
        """Choose a role from live catalog availability using durable observations."""

        del skill_instruction, skill_workflow
        if not candidates_by_role:
            raise RuntimeError("no safe specialist route is available")
        latest = state.observations[-1] if state.observations else None

        def score(item: tuple[AgentRole, list[ActionProposal]]) -> tuple[float, str]:
            role, candidates = item
            value = max(candidate.expected_information_gain for candidate in candidates)
            if latest is not None:
                observed_candidates = set(latest.candidate_ids)
                if any(observed_candidates.intersection(candidate.depends_on) for candidate in candidates):
                    value += 0.2
                if latest.information_gain < 0.12 and state.turns and state.turns[-1].proposal.agent_role is role:
                    value -= 0.25
            return value, role.value

        role, candidates = max(candidates_by_role.items(), key=score)
        gain = max(candidate.expected_information_gain for candidate in candidates)
        invocation = AgentInvocation(
            invocation_id=new_id("agent-invocation"),
            role=AgentRole.COORDINATOR,
            skill_name="budobugs-controller",
            provider="policy",
            model="local-policy",
            status="PASS",
            detail=f"routed to {role.value} from the currently available safe catalog",
        )
        return role, invocation.detail, gain, invocation


class CodexProposalProvider:
    """Use one resumable Codex thread per specialist to select the next typed action."""

    # CLI usage is cumulative within a resumed thread.  Rotate before the next
    # invocation once the raw input and output context reaches this boundary.
    THREAD_ROTATION_CUMULATIVE_TOKEN_LIMIT = 200_000

    def __init__(
        self,
        *,
        service: RepositoryService,
        router: ModelRouter,
        runner: CodexTaskRunner,
        profile: str,
        run_id: str,
        engagement_token_budget: int,
    ) -> None:
        self.service = service
        self.router = router
        self.runner = runner
        self.profile = profile
        self.run_id = run_id
        self.engagement_token_budget = engagement_token_budget

    async def route(
        self,
        *,
        candidates_by_role: dict[AgentRole, list[ActionProposal]],
        state: AgentLoopState,
        skill_instruction: str,
        skill_workflow: str,
    ) -> tuple[AgentRole, str, float, AgentInvocation]:
        """Ask the coordinator to choose only among roles with live safe actions."""

        if not candidates_by_role:
            raise RuntimeError("no safe specialist route is available")
        ledger = self._load_ledger(state)
        used = self._engagement_used_tokens(ledger)
        if used >= self.engagement_token_budget:
            raise RuntimeError("engagement agent token budget exhausted")
        try:
            selection = self.router.select("coordinator", profile=self.profile)
        except ValueError:
            selection = self.router.select("analysis", profile=self.profile)
        remaining = self.engagement_token_budget - used
        selection = selection.__class__(
            profile=selection.profile,
            task_class=selection.task_class,
            candidates=selection.candidates,
            reasoning_effort=selection.reasoning_effort,
            token_budget=min(selection.token_budget, remaining),
        )
        catalog_payload = {
            role.value: [
                {
                    "catalog_action_id": candidate.catalog_action_id,
                    "kind": candidate.kind.value,
                    "objective": candidate.objective,
                    "expected_observation": candidate.expected_observation,
                    "expected_information_gain": candidate.expected_information_gain,
                    "depends_on": candidate.depends_on,
                }
                for candidate in candidates
            ]
            for role, candidates in candidates_by_role.items()
        }
        recent = [
            {
                "round": turn.round_index,
                "agent": turn.proposal.agent_role.value,
                "action": turn.proposal.catalog_action_id,
                "status": turn.observation.status.value,
                "summary": turn.observation.summary,
                "information_gain": turn.observation.information_gain,
                "candidate_ids": turn.observation.candidate_ids,
            }
            for turn in state.turns[-12:]
        ]
        coordinator_contract = (skill_instruction + "\n\n" + skill_workflow).strip()
        instruction = (
            "Act as the research coordinator. Select exactly one specialist role from AVAILABLE_SAFE_ROUTES. "
            "Every listed role currently has executor-built typed actions. You may not invent a role, action, "
            "URL, request, payload, credential, command, or tool argument. Route toward the highest-value open "
            "evidence gap using the durable observations; the selected specialist will choose its own action.\n\n"
            f"REVIEWED_COORDINATOR_SKILL_CONTRACT:\n{coordinator_contract[:30000]}"
        )
        untrusted = (
            redact_text(
                json.dumps(
                    {
                        "available_safe_routes": catalog_payload,
                        "prior_observations": recent,
                        "round": state.current_round,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
            or "{}"
        )
        thread_id = self._thread_for_next_invocation(
            state,
            ledger,
            AgentRole.COORDINATOR,
            "budobugs-controller",
        )
        invocation_id = new_id("agent-invocation")
        previous_usage = self._thread_cumulative_usage(ledger, thread_id)
        result, cost = await self.runner.run(
            selection,
            task_instruction=instruction,
            untrusted_target_summary=untrusted,
            run_id=self.run_id,
            phase=PhaseName.NORMAL_BROWSER_EXPLORATION,
            output_schema=self._route_schema([role.value for role in candidates_by_role]),
            agent_role=AgentRole.COORDINATOR.value,
            skill_name="budobugs-controller",
            thread_id=thread_id,
            turn_id=new_id("route-turn"),
        )
        resolved_thread = result.thread_id or thread_id
        if resolved_thread != thread_id:
            previous_usage = self._thread_cumulative_usage(ledger, resolved_thread)
        ledger.entries.append(
            _CodexInvocationLedgerEntry(
                entry_id=invocation_id,
                role=AgentRole.COORDINATOR,
                skill_name="budobugs-controller",
                thread_id=resolved_thread,
                input_tokens=result.input_tokens,
                output_tokens=result.output_tokens,
                cached_input_tokens=result.cached_input_tokens,
                events_path=result.events_path,
                status="PENDING",
            )
        )
        self._save_ledger(ledger)
        self.service.save_cost(
            cost.model_copy(
                update={
                    "input_tokens": max(0, result.input_tokens - previous_usage[0]),
                    "output_tokens": max(0, result.output_tokens - previous_usage[1]),
                    "cached_input_tokens": max(0, result.cached_input_tokens - previous_usage[2]),
                }
            )
        )
        try:
            choice = _AgentRouteChoice.model_validate_json(result.output)
        except ValueError as exc:
            self._mark_ledger_invalid(ledger, invocation_id, f"invalid coordinator route: {exc}")
            raise _CoordinatorRouteRejected(f"Codex returned invalid coordinator route: {exc}") from exc
        if choice.selected_role not in candidates_by_role:
            self._mark_ledger_invalid(ledger, invocation_id, "selected a role outside the available safe routes")
            raise _CoordinatorRouteRejected("Codex selected a role outside the available safe routes")
        invocation = AgentInvocation(
            invocation_id=invocation_id,
            role=AgentRole.COORDINATOR,
            skill_name="budobugs-controller",
            provider="codex",
            model=result.model,
            thread_id=resolved_thread,
            resumed_thread=thread_id is not None,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            cached_input_tokens=result.cached_input_tokens,
            events_path=result.events_path,
            status="PASS",
            detail=choice.follow_up,
        )
        self._mark_ledger_pass(ledger, invocation_id, choice.follow_up)
        return choice.selected_role, choice.rationale, choice.expected_information_gain, invocation

    async def propose(
        self,
        *,
        role: AgentRole,
        skill_instruction: str,
        skill_workflow: str,
        candidates: list[ActionProposal],
        state: AgentLoopState,
    ) -> tuple[ActionProposal, AgentInvocation]:
        if not candidates:
            raise RuntimeError(f"no safe catalog action is available for {role.value}")
        ledger = self._load_ledger(state)
        used = self._engagement_used_tokens(ledger)
        if used >= self.engagement_token_budget:
            raise RuntimeError("engagement agent token budget exhausted")
        task_class = self._task_class(role)
        try:
            selection = self.router.select(task_class, profile=self.profile)
        except ValueError:
            if task_class != "coordinator":
                raise
            selection = self.router.select("analysis", profile=self.profile)
        remaining = self.engagement_token_budget - used
        selection = selection.__class__(
            profile=selection.profile,
            task_class=selection.task_class,
            candidates=selection.candidates,
            reasoning_effort=selection.reasoning_effort,
            token_budget=min(selection.token_budget, remaining),
        )
        # Keep a complete, canonical proposal string in the model-visible
        # catalog. The flat response schema intentionally does not enumerate
        # these long strings; canonical post-parse binding is the fail-closed
        # execution boundary.
        candidate_jsons = [self._canonical_json(item.model_dump(mode="json")) for item in candidates]
        catalog_payload = [{"proposal_json": value} for value in candidate_jsons]
        recent = [
            {
                "round": turn.round_index,
                "agent": turn.proposal.agent_role.value,
                "action": turn.proposal.catalog_action_id,
                "status": turn.observation.status.value,
                "summary": turn.observation.summary,
                "information_gain": turn.observation.information_gain,
                "candidate_ids": turn.observation.candidate_ids,
            }
            for turn in state.turns[-12:]
        ]
        skill_text = (skill_instruction + "\n\n" + skill_workflow).strip()
        instruction = (
            "Select exactly one action from SAFE_ACTION_CATALOG. Return exactly these four fields: `proposal_json`, "
            "`rationale`, `expected_information_gain`, and `follow_up`. Copy proposal_json byte-for-byte from one "
            "catalog entry; it is the complete typed ActionProposal, including nulls, empty collections, and the "
            "catalog default rationale/gain. Express judgment only through the separate rationale and "
            "expected_information_gain fields. You may not invent or alter a URL, request method, payload, account, "
            "credential, command, tool argument, mutation, validator, dependency, or any other policy-critical field. "
            "The typed executor owns scope and execution. Choose the action that best advances the Skill workflow "
            "given prior observations.\n\n"
            f"REVIEWED_SKILL_CONTRACT:\n{skill_text[:30000]}"
        )
        untrusted = (
            redact_text(
                json.dumps(
                    {
                        "safe_action_catalog": catalog_payload,
                        "prior_observations": recent,
                        "round": state.current_round,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
            or "{}"
        )
        thread_id = self._thread_for_next_invocation(state, ledger, role, candidates[0].skill_name)
        turn_id = new_id("turn")
        invocation_id = new_id("agent-invocation")
        previous_usage = self._thread_cumulative_usage(ledger, thread_id)
        result, cost = await self.runner.run(
            selection,
            task_instruction=instruction,
            untrusted_target_summary=untrusted,
            run_id=self.run_id,
            phase=PhaseName.NORMAL_BROWSER_EXPLORATION,
            output_schema=self._schema(candidates),
            agent_role=role.value,
            skill_name=candidates[0].skill_name,
            thread_id=thread_id,
            turn_id=turn_id,
        )
        resolved_thread = result.thread_id or thread_id
        if resolved_thread != thread_id:
            previous_usage = self._thread_cumulative_usage(ledger, resolved_thread)
        ledger_entry = _CodexInvocationLedgerEntry(
            entry_id=invocation_id,
            role=role,
            skill_name=candidates[0].skill_name,
            thread_id=resolved_thread,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            cached_input_tokens=result.cached_input_tokens,
            events_path=result.events_path,
            status="PENDING",
        )
        ledger.entries.append(ledger_entry)
        # Persist before parsing the untrusted selection.  Invalid model output
        # is still a billed, resumable Codex thread rather than an invisible call.
        self._save_ledger(ledger)
        # Codex reports usage cumulatively for a resumed thread.  Keep that raw
        # value on the invocation for recovery, but charge only this turn's delta.
        self.service.save_cost(
            cost.model_copy(
                update={
                    "input_tokens": max(0, result.input_tokens - previous_usage[0]),
                    "output_tokens": max(0, result.output_tokens - previous_usage[1]),
                    "cached_input_tokens": max(0, result.cached_input_tokens - previous_usage[2]),
                }
            )
        )
        try:
            choice = _AgentChoice.model_validate_json(result.output)
        except ValueError as exc:
            self._mark_ledger_invalid(ledger, invocation_id, f"invalid typed action selection: {exc}")
            raise RuntimeError(f"Codex returned invalid typed action selection: {exc}") from exc
        by_id = {item.catalog_action_id: item for item in candidates}
        if choice.proposal.catalog_action_id not in by_id:
            self._mark_ledger_invalid(ledger, invocation_id, "selected an action outside the safe catalog")
            raise RuntimeError("Codex selected an action outside the safe catalog")
        catalog_action = by_id[choice.proposal.catalog_action_id]
        policy_fields = catalog_action.model_dump(
            mode="json",
            exclude={"rationale", "expected_information_gain"},
        )
        proposed_fields = choice.proposal.model_dump(
            mode="json",
            exclude={"rationale", "expected_information_gain"},
        )
        if self._canonical_json(proposed_fields) != self._canonical_json(policy_fields):
            self._mark_ledger_invalid(
                ledger,
                invocation_id,
                "proposal differs from the catalog's policy-critical fields",
            )
            raise RuntimeError("Codex proposal differs from the catalog's policy-critical fields")
        selected = ActionProposal.model_validate(
            {
                **catalog_action.model_dump(mode="json"),
                "rationale": choice.rationale,
                "expected_information_gain": choice.expected_information_gain,
            }
        )
        invocation = AgentInvocation(
            invocation_id=invocation_id,
            role=role,
            skill_name=selected.skill_name,
            provider="codex",
            model=result.model,
            thread_id=resolved_thread,
            resumed_thread=thread_id is not None,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            cached_input_tokens=result.cached_input_tokens,
            events_path=result.events_path,
            status="PASS",
            detail=choice.follow_up,
        )
        self._mark_ledger_pass(ledger, invocation_id, choice.follow_up)
        return selected, invocation

    def _ledger_path(self) -> Path:
        return self.service.paths.runs / self.run_id / "artifacts" / "agent-loop" / "invocation-ledger.json"

    def _load_ledger(self, state: AgentLoopState) -> _CodexInvocationLedger:
        """Load the raw invocation ledger and backfill older receipt-only runs."""

        path = self._ledger_path()
        if path.is_file():
            ledger = _CodexInvocationLedger.model_validate_json(path.read_text(encoding="utf-8"))
            if ledger.run_id != self.run_id or ledger.engagement_id != state.engagement_id:
                raise RuntimeError("Codex invocation ledger does not match the active run and engagement")
        else:
            ledger = _CodexInvocationLedger(run_id=self.run_id, engagement_id=state.engagement_id)
        known = {entry.entry_id for entry in ledger.entries}
        durable_invocations = [receipt.invocation for receipt in state.route_receipts]
        durable_invocations.extend(turn.invocation for turn in state.turns)
        for invocation in durable_invocations:
            if invocation.provider != "codex" or invocation.invocation_id in known:
                continue
            ledger.entries.append(
                _CodexInvocationLedgerEntry(
                    entry_id=invocation.invocation_id,
                    role=invocation.role,
                    skill_name=invocation.skill_name,
                    thread_id=invocation.thread_id,
                    input_tokens=invocation.input_tokens,
                    output_tokens=invocation.output_tokens,
                    cached_input_tokens=invocation.cached_input_tokens,
                    events_path=invocation.events_path,
                    status="PASS" if invocation.status == "PASS" else "INVALID_OUTPUT",
                    detail=invocation.detail,
                )
            )
            known.add(invocation.invocation_id)
        self._save_ledger(ledger)
        return ledger

    def _save_ledger(self, ledger: _CodexInvocationLedger) -> None:
        atomic_write_json(self._ledger_path(), ledger.model_dump(mode="json"))

    def _mark_ledger_invalid(self, ledger: _CodexInvocationLedger, entry_id: str, detail: str) -> None:
        self._update_ledger_entry(ledger, entry_id, status="INVALID_OUTPUT", detail=detail)

    def _mark_ledger_pass(self, ledger: _CodexInvocationLedger, entry_id: str, detail: str) -> None:
        self._update_ledger_entry(ledger, entry_id, status="PASS", detail=detail)

    def _update_ledger_entry(
        self,
        ledger: _CodexInvocationLedger,
        entry_id: str,
        *,
        status: Literal["PASS", "INVALID_OUTPUT"],
        detail: str,
    ) -> None:
        for entry in ledger.entries:
            if entry.entry_id == entry_id:
                entry.status = status
                entry.detail = redact_text(detail) or "invalid Codex selection"
                entry.updated_at = utc_now()
                self._save_ledger(ledger)
                return
        raise RuntimeError("Codex invocation ledger entry was not persisted")

    @staticmethod
    def _engagement_used_tokens(ledger: _CodexInvocationLedger | AgentLoopState) -> int:
        """Count Codex CLI's cumulative thread usage once per thread.

        Calls without a thread ID have no cumulative identity, so each is charged
        independently.  Invocations retain the original CLI values to make this
        calculation valid after a persisted run is resumed.
        """

        if isinstance(ledger, AgentLoopState):
            # Compatibility for callers inspecting pre-ledger receipt-only state.
            durable_invocations = [receipt.invocation for receipt in ledger.route_receipts]
            durable_invocations.extend(turn.invocation for turn in ledger.turns)
            ledger = _CodexInvocationLedger(
                run_id=ledger.run_id,
                engagement_id=ledger.engagement_id,
                entries=[
                    _CodexInvocationLedgerEntry(
                        entry_id=invocation.invocation_id,
                        role=invocation.role,
                        skill_name=invocation.skill_name,
                        thread_id=invocation.thread_id,
                        input_tokens=invocation.input_tokens,
                        output_tokens=invocation.output_tokens,
                        cached_input_tokens=invocation.cached_input_tokens,
                        events_path=invocation.events_path,
                        status="PASS",
                        detail=invocation.detail,
                    )
                    for invocation in durable_invocations
                    if invocation.provider == "codex"
                ],
            )
        by_thread: dict[str, tuple[int, int]] = {}
        threadless = 0
        for entry in ledger.entries:
            if entry.thread_id is None:
                threadless += entry.input_tokens + entry.output_tokens
                continue
            previous = by_thread.get(entry.thread_id, (0, 0))
            by_thread[entry.thread_id] = (
                max(previous[0], entry.input_tokens),
                max(previous[1], entry.output_tokens),
            )
        return threadless + sum(input_tokens + output_tokens for input_tokens, output_tokens in by_thread.values())

    @staticmethod
    def _thread_cumulative_usage(ledger: _CodexInvocationLedger, thread_id: str | None) -> tuple[int, int, int]:
        """Return the highest raw cumulative usage already observed for one thread."""

        if thread_id is None:
            return (0, 0, 0)
        input_tokens = output_tokens = cached_input_tokens = 0
        for entry in ledger.entries:
            if entry.thread_id == thread_id:
                input_tokens = max(input_tokens, entry.input_tokens)
                output_tokens = max(output_tokens, entry.output_tokens)
                cached_input_tokens = max(cached_input_tokens, entry.cached_input_tokens)
        return input_tokens, output_tokens, cached_input_tokens

    @classmethod
    def _thread_for_next_invocation(
        cls,
        state: AgentLoopState,
        ledger: _CodexInvocationLedger,
        role: AgentRole,
        skill_name: str,
    ) -> str | None:
        """Resume only the matching role-and-skill thread within its context limit.

        Older state snapshots recorded only ``role_thread_ids``.  They remain a
        last-resort recovery source when there is no ledger history for that
        role.  Once ledger data exists, its skill identity is authoritative, so
        a coordinator routing thread can never become an engagement-intake or
        other specialist thread merely because it shares the coordinator role.
        """

        # The ledger is preferred because it records billed invalid outputs
        # before a typed receipt can update state, so recovery resumes that
        # thread instead of discarding its durable invocation history.
        thread_id = cls._latest_role_thread(ledger, role, skill_name)
        if thread_id is None and not any(entry.role is role for entry in ledger.entries):
            thread_id = state.role_thread_ids.get(role.value)
        input_tokens, output_tokens, _ = cls._thread_cumulative_usage(ledger, thread_id)
        if input_tokens + output_tokens >= cls.THREAD_ROTATION_CUMULATIVE_TOKEN_LIMIT:
            return None
        return thread_id

    @staticmethod
    def _latest_role_thread(ledger: _CodexInvocationLedger, role: AgentRole, skill_name: str) -> str | None:
        for entry in reversed(ledger.entries):
            if entry.role is role and entry.skill_name == skill_name and entry.thread_id:
                return entry.thread_id
        return None

    @staticmethod
    def _task_class(role: AgentRole) -> str:
        if role is AgentRole.COORDINATOR:
            return "coordinator"
        if role in {AgentRole.EVIDENCE_VALIDATOR, AgentRole.ADVERSARIAL_CRITIC}:
            return "critical_judgment"
        return "analysis"

    @staticmethod
    def _canonical_json(value: object) -> str:
        """Compare JSON values independent of object-key order, never by identity."""

        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _schema(candidates: list[ActionProposal]) -> dict[str, object]:
        """Flat Draft 2020-12 schema: no refs, unions, nested action, or long enum.

        ``proposal_json`` is bounded but deliberately not enumerated: full
        candidate enum values caused real fresh-thread sampling timeouts. The
        post-parse canonical catalog equality is the authoritative boundary.
        """

        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "proposal_json": {
                    "type": "string",
                    "minLength": 2,
                    "maxLength": 20_000,
                },
                "rationale": {"type": "string", "minLength": 1, "maxLength": 4000},
                "expected_information_gain": {"type": "number", "minimum": 0, "maximum": 1},
                "follow_up": {"type": "string", "minLength": 1, "maxLength": 2000},
            },
            "required": ["proposal_json", "rationale", "expected_information_gain", "follow_up"],
        }

    @staticmethod
    def _route_schema(role_values: list[str]) -> dict[str, object]:
        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "selected_role": {"type": "string", "enum": role_values},
                "rationale": {"type": "string", "minLength": 1, "maxLength": 4000},
                "expected_information_gain": {"type": "number", "minimum": 0, "maximum": 1},
                "follow_up": {"type": "string", "minLength": 1, "maxLength": 2000},
            },
            "required": ["selected_role", "rationale", "expected_information_gain", "follow_up"],
        }


ProposalProvider = PolicyProposalProvider | CodexProposalProvider


class AgentOrchestrator:
    """Continue planning from persisted observations until gain, budget, or catalog stop."""

    def __init__(
        self,
        *,
        engagement: Engagement,
        run_id: str,
        artifact_root: Path,
        executor: TypedActionExecutor,
        provider: ProposalProvider,
        knowledge: VendorKnowledge | None = None,
        max_rounds: int = 8,
        low_gain_threshold: float = 0.12,
        low_gain_patience: int = 3,
    ) -> None:
        self.engagement = engagement
        self.run_id = run_id
        self.artifact_root = artifact_root.resolve()
        self.executor = executor
        self.provider = provider
        self.max_rounds = max_rounds
        self.low_gain_threshold = low_gain_threshold
        self.low_gain_patience = low_gain_patience
        self.catalog = ActionCatalogBuilder(
            engagement=engagement,
            safe_experiments=executor.safe_experiments,
            safe_websocket_experiments=getattr(executor, "safe_websocket_experiments", []),
            knowledge=knowledge,
            hypotheses=getattr(executor, "hypotheses", []),
            program_validation_plans=getattr(executor, "program_validation_plans", []),
        )
        self.state_path = self.artifact_root / "agent-loop" / "state.json"
        self.receipt_path = self.artifact_root / "agent-loop" / "receipt.json"

    async def run(
        self,
        *,
        resume: bool,
        max_new_turns: int | None = None,
    ) -> AgentLoopExecution:
        """Run one recoverable research session and always retire live browsers.

        The executor keeps contexts alive for all turns in this invocation, but
        persistent profiles make a resumed process safely continue its login
        state.  This ``finally`` also closes traces/HARs and executes the
        engagement-declared harmless-object cleanup on interruption.
        """

        execution: AgentLoopExecution | None = None
        try:
            execution = await self._run(resume=resume, max_new_turns=max_new_turns)
            return execution
        finally:
            close_browser = getattr(self.executor, "close_browser", None)
            if callable(close_browser):
                await close_browser()
            # Browser shutdown finalizes HAR/trace and object-cleanup receipts.
            # Rewrite the loop receipt only after those paths are durable.
            if execution is not None:
                self._write_receipt(execution.state)
            elif self.state_path.is_file():
                self._write_receipt(self._load_state())

    async def _run(
        self,
        *,
        resume: bool,
        max_new_turns: int | None = None,
    ) -> AgentLoopExecution:
        state = self._load_state() if resume else self._new_state()
        if state.status is AgentLoopStatus.COMPLETED:
            return self._execution(state)
        if resume:
            failed_actions = {
                turn.proposal.catalog_action_id
                for turn in state.turns
                if turn.observation.status is ObservationStatus.FAILED
            }
            state.blocked_catalog_actions = [
                action_id
                for action_id in state.blocked_catalog_actions
                if action_id not in failed_actions or action_id in state.executed_catalog_actions
            ]
        if resume and (state.turns or state.status is not AgentLoopStatus.ACTIVE):
            state.resume_count += 1
        state.status = AgentLoopStatus.ACTIVE
        self._restore_legacy_schedule_cursor(state)
        turns_started = 0
        start_round = state.current_round
        stop_selected = False
        for round_index in range(start_round, self.max_rounds + 1):
            state.current_round = round_index
            schedule = self.catalog.schedule(round_index)
            routable_roles = self._routable_roles(schedule, round_index)
            available = self._available_candidates(routable_roles, round_index, state)
            if not schedule and not available:
                state.status = AgentLoopStatus.COMPLETED
                state.stop_reason = "safe action catalog exhausted"
                break
            dynamic_routing = callable(getattr(self.provider, "route", None))
            while True:
                if max_new_turns is not None and turns_started >= max_new_turns:
                    state.status = AgentLoopStatus.INTERRUPTED
                    state.stop_reason = "configured turn checkpoint reached after durable observation writes"
                    self._persist(state)
                    raise AgentLoopInterrupted(self._execution(state))
                pending_route = self._pending_route(state, round_index)
                if pending_route is not None:
                    role = pending_route.selected_role
                    live = self.catalog.actions(role, round_index, state)
                    allowed_ids = set(pending_route.candidate_action_ids[role.value])
                    candidates = [item for item in live if item.catalog_action_id in allowed_ids]
                    if not candidates:
                        raise RuntimeError("pending coordinator route no longer has its typed catalog action")
                    route_receipt = pending_route
                else:
                    available = self._available_candidates(routable_roles, round_index, state)
                    if not available:
                        break
                    if not dynamic_routing:
                        fallback = self._next_static_fallback(schedule, round_index, state, available)
                        if fallback is None:
                            break
                        role, candidates = fallback
                        route_receipt = self._fallback_route_receipt(role, candidates, available, round_index)
                    else:
                        try:
                            route_receipt = await self._coordinator_route(available, state, round_index)
                        except Exception as exc:
                            if isinstance(exc, _CoordinatorRouteRejected) or (
                                "engagement agent token budget exhausted" in str(exc).casefold()
                            ):
                                state.status = (
                                    AgentLoopStatus.BUDGET_EXHAUSTED
                                    if "engagement agent token budget exhausted" in str(exc).casefold()
                                    else AgentLoopStatus.FAILED
                                )
                                state.stop_reason = self._failure_stop_reason(exc)
                                state.updated_at = utc_now()
                                self._persist(state)
                                raise
                            fallback = self._next_static_fallback(schedule, round_index, state, available)
                            if fallback is None:
                                raise
                            role, candidates = fallback
                            route_receipt = self._fallback_route_receipt(
                                role,
                                candidates,
                                available,
                                round_index,
                                detail=(
                                    f"coordinator model unavailable; static fallback: {self._failure_stop_reason(exc)}"
                                ),
                            )
                        else:
                            role = route_receipt.selected_role
                            candidates = available[role]
                    state.route_receipts.append(route_receipt)
                    if route_receipt.invocation.thread_id:
                        state.role_thread_ids[AgentRole.COORDINATOR.value] = route_receipt.invocation.thread_id
                    if AgentRole.COORDINATOR not in state.participating_agents:
                        state.participating_agents.append(AgentRole.COORDINATOR)
                    if route_receipt.invocation.skill_name not in state.invoked_skills:
                        state.invoked_skills.append(route_receipt.invocation.skill_name)
                    state.updated_at = utc_now()
                    # Persist the coordinator choice before invoking the
                    # specialist. Recovery therefore reuses this exact route.
                    self._persist(state)
                contract = self.executor.skill_runtime.load(candidates[0].skill_name)
                started = utc_now()
                try:
                    proposal, invocation = await self.provider.propose(
                        role=role,
                        skill_instruction=contract.instruction,
                        skill_workflow=contract.workflow,
                        candidates=candidates,
                        state=state,
                    )
                    allowed_action_ids = {item.catalog_action_id for item in candidates}
                    if proposal.agent_role is not role or proposal.catalog_action_id not in allowed_action_ids:
                        raise RuntimeError("specialist selected an action outside its routed safe catalog")
                    if invocation.thread_id:
                        state.role_thread_ids[role.value] = invocation.thread_id
                    observation = await self.executor.execute(proposal)
                except AgentLoopInterrupted:
                    # An intentional checkpoint is already durable and remains a
                    # distinct, resumable state from an unexpected failure.
                    raise
                except Exception as exc:
                    state.status = (
                        AgentLoopStatus.BUDGET_EXHAUSTED
                        if "engagement agent token budget exhausted" in str(exc).casefold()
                        else AgentLoopStatus.FAILED
                    )
                    state.stop_reason = self._failure_stop_reason(exc)
                    state.updated_at = utc_now()
                    self._persist(state)
                    raise
                receipt = AgentTurnReceipt(
                    turn_id=new_id("agent-turn"),
                    round_index=round_index,
                    proposal=proposal,
                    invocation=invocation,
                    observation=observation,
                    started_at=started,
                    completed_at=utc_now(),
                )
                state.turns.append(receipt)
                state.observations.append(observation)
                if role not in state.participating_agents:
                    state.participating_agents.append(role)
                if proposal.skill_name not in state.invoked_skills:
                    state.invoked_skills.append(proposal.skill_name)
                if self.executor.proxy.selected not in state.proxy_backends:
                    state.proxy_backends.append(self.executor.proxy.selected)
                if observation.status is ObservationStatus.EXECUTED:
                    state.executed_catalog_actions.append(proposal.catalog_action_id)
                elif observation.status in {ObservationStatus.BLOCKED, ObservationStatus.SKIPPED}:
                    state.blocked_catalog_actions.append(proposal.catalog_action_id)
                if observation.information_gain < self.low_gain_threshold:
                    state.consecutive_low_gain += 1
                else:
                    state.consecutive_low_gain = 0
                existing_outcomes = {item.outcome_id for item in state.validation_outcomes}
                state.validation_outcomes.extend(
                    result.outcome
                    for result in self.executor.validator_results
                    if result.outcome.outcome_id not in existing_outcomes
                )
                state.updated_at = utc_now()
                if proposal.kind is ActionKind.FINISH and observation.status is ObservationStatus.EXECUTED:
                    state.status = AgentLoopStatus.COMPLETED
                    state.stop_reason = str(
                        observation.details.get("stop_reason", "coordinator selected the typed finish action")
                    )
                    stop_selected = True
                route_completed = False
                if observation.status is ObservationStatus.FAILED:
                    self._record_route_observation(
                        state,
                        route_receipt.route_id,
                        proposal.catalog_action_id,
                        observation.observation_id,
                    )
                else:
                    route_completed, completion_reason = self._should_complete_route(
                        route_receipt,
                        role,
                        round_index,
                        state,
                        routable_roles,
                        observation,
                        stop_selected=stop_selected,
                    )
                    self._record_route_observation(
                        state,
                        route_receipt.route_id,
                        proposal.catalog_action_id,
                        observation.observation_id,
                        complete=route_completed,
                        completion_reason=completion_reason,
                    )
                    if route_completed and route_receipt.fallback:
                        state.schedule_cursor += 1
                self._persist(state)
                turns_started += 1
                if observation.status is ObservationStatus.FAILED:
                    state.status = AgentLoopStatus.FAILED
                    state.stop_reason = (
                        f"typed action {proposal.catalog_action_id} failed after its observation was persisted"
                    )
                    state.updated_at = utc_now()
                    self._persist(state)
                    raise RuntimeError(state.stop_reason)
                if stop_selected:
                    break
            state.current_round = round_index + 1
            state.schedule_cursor = 0
            self._persist(state)
            if stop_selected:
                break
            if round_index >= 3 and state.consecutive_low_gain >= self.low_gain_patience:
                state.status = AgentLoopStatus.STALLED
                state.stop_reason = "information gain remained below threshold"
                break
        else:
            state.status = AgentLoopStatus.BUDGET_EXHAUSTED
            state.stop_reason = "maximum safe planning rounds reached"
        if state.status in {AgentLoopStatus.ACTIVE, AgentLoopStatus.STALLED}:
            state.status = AgentLoopStatus.COMPLETED
        state.updated_at = utc_now()
        self._persist(state)
        return self._execution(state)

    def _available_candidates(
        self,
        schedule: tuple[AgentRole, ...] | list[AgentRole],
        round_index: int,
        state: AgentLoopState,
    ) -> dict[AgentRole, list[ActionProposal]]:
        """Return live executor-built candidates, deduplicating schedule order."""

        roles = tuple(dict.fromkeys(schedule))
        return {role: candidates for role in roles if (candidates := self.catalog.actions(role, round_index, state))}

    def _routable_roles(
        self,
        fallback_schedule: tuple[AgentRole, ...] | list[AgentRole],
        round_index: int,
    ) -> tuple[AgentRole, ...]:
        route_roles = getattr(self.catalog, "routable_roles", None)
        if callable(route_roles):
            return tuple(route_roles(round_index))
        # Test adapters and state written before dynamic routing expose only a
        # schedule; its order is ignored here and remains relevant only to fallback.
        return tuple(dict.fromkeys(fallback_schedule))

    async def _coordinator_route(
        self,
        available: dict[AgentRole, list[ActionProposal]],
        state: AgentLoopState,
        round_index: int,
    ) -> AgentRouteReceipt:
        route = self.provider.route
        contract = self.executor.skill_runtime.load("budobugs-controller")
        role, rationale, gain, invocation = await route(
            candidates_by_role=available,
            state=state,
            skill_instruction=contract.instruction,
            skill_workflow=contract.workflow,
        )
        if role not in available:
            raise RuntimeError("coordinator selected a role without a current safe catalog action")
        return AgentRouteReceipt(
            route_id=new_id("agent-route"),
            round_index=round_index,
            available_roles=list(available),
            candidate_action_ids={
                candidate_role.value: [item.catalog_action_id for item in candidates]
                for candidate_role, candidates in available.items()
            },
            selected_role=role,
            rationale=rationale,
            expected_information_gain=gain,
            invocation=invocation,
        )

    def _next_static_fallback(
        self,
        schedule: tuple[AgentRole, ...] | list[AgentRole],
        round_index: int,
        state: AgentLoopState,
        available: dict[AgentRole, list[ActionProposal]],
    ) -> tuple[AgentRole, list[ActionProposal]] | None:
        while state.schedule_cursor < len(schedule):
            role = schedule[state.schedule_cursor]
            candidates = available.get(role)
            if candidates:
                return role, candidates
            state.schedule_cursor += 1
            state.updated_at = utc_now()
            self._persist(state)
        return None

    @staticmethod
    def _fallback_route_receipt(
        role: AgentRole,
        candidates: list[ActionProposal],
        available: dict[AgentRole, list[ActionProposal]],
        round_index: int,
        *,
        detail: str = "deterministic policy provider uses the recoverable static route fallback",
    ) -> AgentRouteReceipt:
        invocation = AgentInvocation(
            invocation_id=new_id("agent-invocation"),
            role=AgentRole.COORDINATOR,
            skill_name="budobugs-controller",
            provider="policy",
            model="static-route-fallback",
            status="PASS",
            detail=detail,
        )
        return AgentRouteReceipt(
            route_id=new_id("agent-route"),
            round_index=round_index,
            available_roles=list(available),
            candidate_action_ids={
                candidate_role.value: [item.catalog_action_id for item in role_candidates]
                for candidate_role, role_candidates in available.items()
            },
            selected_role=role,
            rationale=detail,
            expected_information_gain=max(item.expected_information_gain for item in candidates),
            invocation=invocation,
            fallback=True,
        )

    @staticmethod
    def _pending_route(state: AgentLoopState, round_index: int) -> AgentRouteReceipt | None:
        for receipt in reversed(state.route_receipts):
            if receipt.round_index == round_index and receipt.status == "pending":
                return receipt
        return None

    def _should_complete_route(
        self,
        receipt: AgentRouteReceipt,
        role: AgentRole,
        round_index: int,
        state: AgentLoopState,
        routable_roles: tuple[AgentRole, ...],
        observation: Observation,
        *,
        stop_selected: bool,
    ) -> tuple[bool, str | None]:
        if stop_selected:
            return True, "typed finish action completed"
        if observation.status in {ObservationStatus.BLOCKED, ObservationStatus.SKIPPED}:
            return True, f"typed action was {observation.status.value}"
        if observation.information_gain < self.low_gain_threshold:
            return True, "latest observation fell below the information-gain threshold"
        live_same_role = self.catalog.actions(role, round_index, state)
        if not live_same_role:
            return True, "selected specialist exhausted its safe catalog candidates"
        live_catalog = self._available_candidates(routable_roles, round_index, state)
        snapshot_ids = {action_id for action_ids in receipt.candidate_action_ids.values() for action_id in action_ids}
        live_ids = {candidate.catalog_action_id for candidates in live_catalog.values() for candidate in candidates}
        if live_ids - snapshot_ids:
            return True, "durable observations introduced new safe catalog dependencies"
        return False, None

    @staticmethod
    def _record_route_observation(
        state: AgentLoopState,
        route_id: str,
        action_id: str,
        observation_id: str,
        *,
        complete: bool = False,
        completion_reason: str | None = None,
    ) -> None:
        for index, receipt in enumerate(state.route_receipts):
            if receipt.route_id != route_id:
                continue
            state.route_receipts[index] = AgentRouteReceipt.model_validate(
                {
                    **receipt.model_dump(mode="json"),
                    "status": "completed" if complete else "pending",
                    "selected_action_ids": [*receipt.selected_action_ids, action_id],
                    "observation_ids": [*receipt.observation_ids, observation_id],
                    "selected_action_id": action_id,
                    "completion_reason": completion_reason if complete else None,
                    "completed_at": utc_now() if complete else None,
                }
            )
            return
        raise RuntimeError("coordinator route receipt was not persisted")

    def _new_state(self) -> AgentLoopState:
        state = AgentLoopState(
            loop_id=new_id("agent-loop"),
            run_id=self.run_id,
            engagement_id=self.engagement.engagement_id,
        )
        self._persist(state)
        return state

    def _restore_legacy_schedule_cursor(self, state: AgentLoopState) -> None:
        """Recover the pending role once for state files predating the cursor.

        Older loops only recorded the current round.  Within a round their
        receipts are ordered by the static schedule, so the last durable turn
        identifies the next role.  A failed typed observation remains pending
        and is retried; an earlier successful role is never needlessly replayed.
        A provider failure has no receipt and therefore intentionally retains
        cursor zero (there is no durable evidence of which role it was in).
        """

        if "schedule_cursor" in state.model_fields_set:
            return
        schedule = self.catalog.schedule(state.current_round)
        matching_turns = [
            turn
            for turn in state.turns
            if turn.round_index == state.current_round and turn.proposal.agent_role in schedule
        ]
        if not matching_turns:
            return
        last_turn = matching_turns[-1]
        role_index = schedule.index(last_turn.proposal.agent_role)
        state.schedule_cursor = role_index
        if last_turn.observation.status is not ObservationStatus.FAILED:
            state.schedule_cursor += 1
        state.updated_at = utc_now()
        self._persist(state)

    @staticmethod
    def _failure_stop_reason(exc: Exception) -> str:
        """Persist a useful but bounded, redacted failure reason for recovery."""

        reason = redact_text(f"{type(exc).__name__}: {exc}") or type(exc).__name__
        return " ".join(reason.split())[:500]

    def _load_state(self) -> AgentLoopState:
        if not self.state_path.is_file():
            return self._new_state()
        state = AgentLoopState.model_validate_json(self.state_path.read_text(encoding="utf-8"))
        if state.run_id != self.run_id or state.engagement_id != self.engagement.engagement_id:
            raise RuntimeError("agent loop state does not match the active run and engagement")
        return state

    def _persist(self, state: AgentLoopState) -> None:
        atomic_write_json(self.state_path, state.model_dump(mode="json"))
        self._write_receipt(state)

    def _write_receipt(self, state: AgentLoopState) -> None:
        confirmed = [item for item in state.validation_outcomes if item.decision.value == "CONFIRMED"]
        killed = [item for item in state.validation_outcomes if item.decision.value == "KILL"]
        clusters = RootCauseDeduper.cluster(state.validation_outcomes)
        confirmed_candidate_ids = {item.candidate_id for item in confirmed}
        confirmed_merged_clusters = [
            {
                **cluster.model_dump(mode="json"),
                "confirmed_candidate_ids": [
                    candidate_id for candidate_id in cluster.candidate_ids if candidate_id in confirmed_candidate_ids
                ],
            }
            for cluster in clusters
            if sum(candidate_id in confirmed_candidate_ids for candidate_id in cluster.candidate_ids) >= 2
        ]
        rounds = sorted({turn.round_index for turn in state.turns})
        executed_kinds = sorted({turn.proposal.kind.value for turn in state.turns if _turn_executed_successfully(turn)})
        route_summaries = [
            {
                "route_id": item.route_id,
                "round_index": item.round_index,
                "selected_role": item.selected_role.value,
                "provider": item.invocation.provider,
                "model": item.invocation.model,
                "fallback": item.fallback,
                "status": item.status,
                "selected_action_ids": item.selected_action_ids,
                "observation_ids": item.observation_ids,
                "action_count": len(item.selected_action_ids),
                "observation_count": len(item.observation_ids),
                "completion_reason": item.completion_reason,
            }
            for item in state.route_receipts
        ]
        # ``participating_agents`` is a useful high-level summary, but it is
        # not sufficient evidence that a named specialist actually received a
        # typed proposal and executed it.  Keep a deliberately bounded
        # per-turn receipt so the release gate can distinguish a coordinator
        # route from an executed specialist turn without exposing prompts,
        # credentials, or raw traffic.
        agent_execution_receipts = [
            {
                "agent_role": turn.proposal.agent_role.value,
                "invocation_role": turn.invocation.role.value,
                "provider": turn.invocation.provider,
                "invocation_status": turn.invocation.status,
                "skill_name": turn.proposal.skill_name,
                "catalog_action_id": turn.proposal.catalog_action_id,
                "observation_id": turn.observation.observation_id,
                "observation_status": turn.observation.status.value,
            }
            for turn in state.turns
        ]
        successful_turns = [turn for turn in state.turns if _turn_executed_successfully(turn)]
        executed_agents = list(dict.fromkeys(turn.proposal.agent_role for turn in successful_turns))
        executed_skills = list(dict.fromkeys(turn.proposal.skill_name for turn in successful_turns))
        object_ledger_path = getattr(self.executor, "self_owned_object_ledger_path", None)
        receipt = {
            "schema_version": 1,
            "loop_id": state.loop_id,
            "run_id": state.run_id,
            "engagement_id": state.engagement_id,
            "engagement_mode": self.engagement.selected_mode.value,
            "status": state.status.value,
            "stop_reason": state.stop_reason,
            "resume_count": state.resume_count,
            "plan_execute_observe_rounds": rounds,
            "round_count": len(rounds),
            "turn_count": len(state.turns),
            "executed_turn_count": sum(_turn_executed_successfully(turn) for turn in state.turns),
            "participating_agents": [item.value for item in executed_agents],
            "participating_agent_count": len(executed_agents),
            "invoked_skills": executed_skills,
            "proxy_backends": state.proxy_backends,
            "typed_action_kinds_executed": executed_kinds,
            "network_or_browser_actions_executed": [
                turn.proposal.catalog_action_id
                for turn in state.turns
                if _turn_executed_successfully(turn)
                and (
                    turn.observation.exchange_ids
                    or turn.proposal.kind.value
                    in {"browser_explore", "browser_navigate", "browser_form", "proxy_replay", "http_request"}
                )
            ],
            "confirmed_outcomes": [item.model_dump(mode="json") for item in confirmed],
            "killed_outcomes": [item.model_dump(mode="json") for item in killed],
            "confirmed_vulnerability_classes": sorted({item.vulnerability_class for item in confirmed}),
            "root_cause_clusters": [item.model_dump(mode="json") for item in clusters],
            "same_fix_merged_clusters": [
                item.model_dump(mode="json") for item in clusters if len(item.candidate_ids) > 1
            ],
            "same_fix_merged_confirmed_clusters": confirmed_merged_clusters,
            "same_role_resumed_threads": sorted(
                {
                    turn.invocation.role.value
                    for turn in state.turns
                    if turn.invocation.provider == "codex" and turn.invocation.resumed_thread
                }
            ),
            "role_thread_ids": state.role_thread_ids,
            "coordinator_routes": [item.model_dump(mode="json") for item in state.route_receipts],
            "coordinator_route_summary": route_summaries,
            "agent_execution_receipts": agent_execution_receipts,
            "coordinator_route_count": len(state.route_receipts),
            "dynamic_coordinator_route_count": sum(
                not item.fallback and item.invocation.provider == "codex" for item in state.route_receipts
            ),
            "policy_coordinator_route_count": sum(
                not item.fallback and item.invocation.provider == "policy" for item in state.route_receipts
            ),
            "fallback_coordinator_route_count": sum(item.fallback for item in state.route_receipts),
            "self_owned_object_ledger": (
                str(object_ledger_path)
                if isinstance(object_ledger_path, Path) and object_ledger_path.is_file()
                else None
            ),
        }
        atomic_write_json(self.receipt_path, receipt)

    def _execution(self, state: AgentLoopState) -> AgentLoopExecution:
        findings = [result.finding for result in self.executor.validator_results]
        controls = {result.finding.finding_id: result.controls for result in self.executor.validator_results}
        return AgentLoopExecution(
            state=state,
            findings=findings,
            controls_by_finding=controls,
            exchanges=self.executor.exchanges,
            browser_artifacts=self.executor.browser_artifacts,
            root_cause_clusters=self.executor.root_cause_clusters,
            state_path=str(self.state_path),
            receipt_path=str(self.receipt_path),
        )
