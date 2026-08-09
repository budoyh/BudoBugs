"""Recoverable plan-execute-observe agent orchestration."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from budobugs.agents.router import ModelRouter
from budobugs.agents.runner import CodexTaskRunner
from budobugs.core.identifiers import new_id
from budobugs.core.io import atomic_write_json
from budobugs.core.redaction import redact_text
from budobugs.knowledge.vendor import RootCauseDeduper
from budobugs.models import (
    ActionProposal,
    AgentInvocation,
    AgentLoopState,
    AgentLoopStatus,
    AgentRole,
    AgentTurnReceipt,
    ControlExperiment,
    Engagement,
    Finding,
    HttpExchange,
    ObservationStatus,
    PhaseName,
    RootCauseCluster,
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


class _AgentChoice(BaseModel):
    model_config = ConfigDict(extra="forbid")

    catalog_action_id: str
    rationale: str = Field(min_length=1, max_length=4000)
    expected_information_gain: float = Field(ge=0, le=1)
    follow_up: str = Field(min_length=1, max_length=2000)


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


class CodexProposalProvider:
    """Use one resumable Codex thread per specialist to select the next typed action."""

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
        used = sum(turn.invocation.input_tokens + turn.invocation.output_tokens for turn in state.turns)
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
        catalog_payload = [
            {
                "catalog_action_id": item.catalog_action_id,
                "kind": item.kind.value,
                "objective": item.objective,
                "expected_observation": item.expected_observation,
                "expected_information_gain": item.expected_information_gain,
                "mutation_scope": item.mutation_scope,
                "depends_on": item.depends_on,
            }
            for item in candidates
        ]
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
            "Select exactly one action from SAFE_ACTION_CATALOG. You may not invent a URL, request, payload, "
            "credential, command, tool argument, or mutation. The typed executor owns scope and execution. "
            "Choose the action that best advances the Skill workflow given prior observations. Explain the "
            "evidence gap and expected information gain.\n\n"
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
        thread_id = state.role_thread_ids.get(role.value)
        turn_id = new_id("turn")
        result, cost = await self.runner.run(
            selection,
            task_instruction=instruction,
            untrusted_target_summary=untrusted,
            run_id=self.run_id,
            phase=PhaseName.NORMAL_BROWSER_EXPLORATION,
            output_schema=self._schema([item.catalog_action_id for item in candidates]),
            agent_role=role.value,
            skill_name=candidates[0].skill_name,
            thread_id=thread_id,
            turn_id=turn_id,
        )
        self.service.save_cost(cost)
        try:
            choice = _AgentChoice.model_validate_json(result.output)
        except ValueError as exc:
            raise RuntimeError(f"Codex returned invalid typed action selection: {exc}") from exc
        by_id = {item.catalog_action_id: item for item in candidates}
        if choice.catalog_action_id not in by_id:
            raise RuntimeError("Codex selected an action outside the safe catalog")
        selected = ActionProposal.model_validate(
            {
                **by_id[choice.catalog_action_id].model_dump(mode="json"),
                "rationale": choice.rationale,
                "expected_information_gain": choice.expected_information_gain,
            }
        )
        resolved_thread = result.thread_id or thread_id
        invocation = AgentInvocation(
            invocation_id=new_id("agent-invocation"),
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
        return selected, invocation

    @staticmethod
    def _task_class(role: AgentRole) -> str:
        if role is AgentRole.COORDINATOR:
            return "coordinator"
        if role in {AgentRole.EVIDENCE_VALIDATOR, AgentRole.ADVERSARIAL_CRITIC}:
            return "critical_judgment"
        return "analysis"

    @staticmethod
    def _schema(action_ids: list[str]) -> dict[str, object]:
        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "catalog_action_id": {"type": "string", "enum": action_ids},
                "rationale": {"type": "string", "minLength": 1, "maxLength": 4000},
                "expected_information_gain": {"type": "number", "minimum": 0, "maximum": 1},
                "follow_up": {"type": "string", "minLength": 1, "maxLength": 2000},
            },
            "required": ["catalog_action_id", "rationale", "expected_information_gain", "follow_up"],
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
        self.catalog = ActionCatalogBuilder(engagement)
        self.state_path = self.artifact_root / "agent-loop" / "state.json"
        self.receipt_path = self.artifact_root / "agent-loop" / "receipt.json"

    async def run(
        self,
        *,
        resume: bool,
        max_new_turns: int | None = None,
    ) -> AgentLoopExecution:
        state = self._load_state() if resume else self._new_state()
        if state.status is AgentLoopStatus.COMPLETED:
            return self._execution(state)
        if resume and state.turns:
            state.resume_count += 1
        state.status = AgentLoopStatus.ACTIVE
        turns_started = 0
        start_round = state.current_round
        for round_index in range(start_round, self.max_rounds + 1):
            state.current_round = round_index
            schedule = self.catalog.schedule(round_index)
            if not schedule:
                state.status = AgentLoopStatus.COMPLETED
                state.stop_reason = "safe action catalog exhausted"
                break
            for role in schedule:
                candidates = self.catalog.actions(role, round_index, state)
                if not candidates:
                    continue
                if max_new_turns is not None and turns_started >= max_new_turns:
                    state.status = AgentLoopStatus.INTERRUPTED
                    state.stop_reason = "configured turn checkpoint reached after durable observation writes"
                    self._persist(state)
                    raise AgentLoopInterrupted(self._execution(state))
                contract = self.executor.skill_runtime.load(candidates[0].skill_name)
                started = utc_now()
                proposal, invocation = await self.provider.propose(
                    role=role,
                    skill_instruction=contract.instruction,
                    skill_workflow=contract.workflow,
                    candidates=candidates,
                    state=state,
                )
                if invocation.thread_id:
                    state.role_thread_ids[role.value] = invocation.thread_id
                observation = await self.executor.execute(proposal)
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
                else:
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
                self._persist(state)
                turns_started += 1
            state.current_round = round_index + 1
            self._persist(state)
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

    def _new_state(self) -> AgentLoopState:
        state = AgentLoopState(
            loop_id=new_id("agent-loop"),
            run_id=self.run_id,
            engagement_id=self.engagement.engagement_id,
        )
        self._persist(state)
        return state

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
        rounds = sorted({turn.round_index for turn in state.turns})
        executed_kinds = sorted(
            {turn.proposal.kind.value for turn in state.turns if turn.observation.status is ObservationStatus.EXECUTED}
        )
        receipt = {
            "schema_version": 1,
            "loop_id": state.loop_id,
            "run_id": state.run_id,
            "engagement_id": state.engagement_id,
            "status": state.status.value,
            "stop_reason": state.stop_reason,
            "resume_count": state.resume_count,
            "plan_execute_observe_rounds": rounds,
            "round_count": len(rounds),
            "turn_count": len(state.turns),
            "executed_turn_count": state.executed_turn_count,
            "participating_agents": [item.value for item in state.participating_agents],
            "participating_agent_count": len(state.participating_agents),
            "invoked_skills": state.invoked_skills,
            "proxy_backends": state.proxy_backends,
            "typed_action_kinds_executed": executed_kinds,
            "network_or_browser_actions_executed": [
                turn.proposal.catalog_action_id
                for turn in state.turns
                if turn.observation.status is ObservationStatus.EXECUTED
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
            "same_role_resumed_threads": sorted(
                {
                    turn.invocation.role.value
                    for turn in state.turns
                    if turn.invocation.provider == "codex" and turn.invocation.resumed_thread
                }
            ),
            "role_thread_ids": state.role_thread_ids,
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
