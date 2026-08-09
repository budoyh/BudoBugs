"""Typed contracts for the recoverable agent research loop."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import Field, JsonValue, field_validator, model_validator

from budobugs.models.base import BudoModel, utc_now


class AgentRole(StrEnum):
    COORDINATOR = "coordinator"
    BROWSER_EXPLORER = "browser-explorer"
    TRAFFIC_MODELER = "traffic-modeler"
    AUTHORIZATION_SPECIALIST = "authorization-specialist"
    BUSINESS_LOGIC_SPECIALIST = "business-logic-specialist"
    API_AUTH_SPECIALIST = "api-auth-specialist"
    WEB_CLIENT_SPECIALIST = "web-client-specialist"
    EVIDENCE_VALIDATOR = "evidence-validator"
    ADVERSARIAL_CRITIC = "adversarial-critic"
    RECON_RESEARCHER = "recon-researcher"
    SOURCE_REVIEWER = "source-reviewer"
    REPORT_WRITER = "report-writer"


class ActionKind(StrEnum):
    BROWSER_EXPLORE = "browser_explore"
    BROWSER_NAVIGATE = "browser_navigate"
    BROWSER_FORM = "browser_form"
    PROXY_SEARCH = "proxy_search"
    PROXY_REPLAY = "proxy_replay"
    HTTP_REQUEST = "http_request"
    VALIDATOR_RUN = "validator_run"
    TRAFFIC_MODEL = "traffic_model"
    EVIDENCE_REVIEW = "evidence_review"
    TOOL_TASK = "tool_task"
    FINISH = "finish"


class ObservationStatus(StrEnum):
    EXECUTED = "executed"
    BLOCKED = "blocked"
    FAILED = "failed"
    SKIPPED = "skipped"


class AgentLoopStatus(StrEnum):
    ACTIVE = "active"
    INTERRUPTED = "interrupted"
    COMPLETED = "completed"
    STALLED = "stalled"
    BUDGET_EXHAUSTED = "budget_exhausted"
    FAILED = "failed"


class CandidateDecision(StrEnum):
    CONFIRMED = "CONFIRMED"
    HOLD = "HOLD"
    KILL = "KILL"


class ActionProposal(BudoModel):
    """A specialist-selected action after scope policy has built a safe catalog."""

    proposal_id: str
    catalog_action_id: str
    round_index: int = Field(ge=1)
    agent_role: AgentRole
    skill_name: str = Field(min_length=1, max_length=100)
    kind: ActionKind
    objective: str = Field(min_length=1, max_length=2000)
    target_url: str | None = Field(default=None, max_length=4096)
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] | None = None
    account_aliases: list[str] = Field(default_factory=list, max_length=8)
    headers: dict[str, str] = Field(default_factory=dict)
    body: JsonValue | None = None
    base_exchange_id: str | None = Field(default=None, max_length=128)
    validator_id: str | None = Field(default=None, max_length=100)
    tool_name: str | None = Field(default=None, max_length=100)
    tool_arguments: dict[str, JsonValue] = Field(default_factory=dict)
    candidate_id: str | None = Field(default=None, max_length=128)
    mutation_scope: Literal["read-only", "self-owned", "reversible-fixture"] = "read-only"
    cleanup_action_id: str | None = Field(default=None, max_length=128)
    expected_observation: str = Field(min_length=1, max_length=2000)
    expected_information_gain: float = Field(default=0.5, ge=0, le=1)
    rationale: str = Field(default="policy catalog action", max_length=4000)
    depends_on: list[str] = Field(default_factory=list, max_length=64)

    @field_validator("headers")
    @classmethod
    def reject_transport_and_secret_headers(cls, value: dict[str, str]) -> dict[str, str]:
        forbidden = {
            "authorization",
            "cookie",
            "proxy-authorization",
            "host",
            "content-length",
            "connection",
            "transfer-encoding",
        }
        if any(name.lower() in forbidden for name in value):
            raise ValueError("proposal headers cannot carry credentials or transport framing")
        return value

    @model_validator(mode="after")
    def validate_action_shape(self) -> ActionProposal:
        network = {ActionKind.HTTP_REQUEST, ActionKind.BROWSER_NAVIGATE, ActionKind.BROWSER_FORM}
        if self.kind in network and self.target_url is None:
            raise ValueError(f"{self.kind.value} requires target_url")
        if self.kind is ActionKind.HTTP_REQUEST and self.method is None:
            raise ValueError("http_request requires method")
        if self.kind is ActionKind.PROXY_REPLAY and self.base_exchange_id is None:
            raise ValueError("proxy_replay requires base_exchange_id")
        if self.kind is ActionKind.VALIDATOR_RUN and self.validator_id is None:
            raise ValueError("validator_run requires validator_id")
        if self.kind is ActionKind.TOOL_TASK and self.tool_name is None:
            raise ValueError("tool_task requires tool_name")
        mutating = self.method in {"POST", "PUT", "PATCH", "DELETE"}
        if mutating and self.mutation_scope == "read-only":
            raise ValueError("mutating requests require self-owned or reversible-fixture scope")
        return self


class AgentInvocation(BudoModel):
    invocation_id: str
    role: AgentRole
    skill_name: str
    provider: Literal["codex", "policy"]
    model: str
    thread_id: str | None = None
    resumed_thread: bool = False
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cached_input_tokens: int = Field(default=0, ge=0)
    events_path: str | None = None
    status: Literal["PASS", "DEGRADED", "INVALID_OUTPUT", "BUDGET_EXHAUSTED"]
    detail: str = ""


class Observation(BudoModel):
    observation_id: str
    proposal_id: str
    round_index: int = Field(ge=1)
    status: ObservationStatus
    summary: str = Field(min_length=1, max_length=8000)
    information_gain: float = Field(default=0, ge=0, le=1)
    exchange_ids: list[str] = Field(default_factory=list, max_length=1000)
    artifact_refs: list[str] = Field(default_factory=list, max_length=1000)
    discovered_urls: list[str] = Field(default_factory=list, max_length=1000)
    state_changes: list[str] = Field(default_factory=list, max_length=100)
    candidate_ids: list[str] = Field(default_factory=list, max_length=100)
    follow_up_hints: list[str] = Field(default_factory=list, max_length=100)
    backend: str | None = Field(default=None, max_length=100)
    data_scope: str = Field(default="authorized test data only", max_length=1000)
    details: dict[str, JsonValue] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class ValidationOutcome(BudoModel):
    outcome_id: str
    validator_id: str
    candidate_id: str
    decision: CandidateDecision
    vulnerability_class: str
    title: str
    root_cause_key: str
    repair_boundary: str
    finding_id: str
    control_ids: list[str] = Field(default_factory=list)
    exchange_ids: list[str] = Field(default_factory=list)
    capability_delta: str
    strongest_benign_explanation: str
    repeated: bool
    normal_control_passed: bool
    negative_control_passed: bool
    cleanup_completed: bool
    evidence_closed: bool
    confidence: float = Field(ge=0, le=1)


class RootCauseCluster(BudoModel):
    cluster_id: str
    root_cause_key: str
    repair_boundary: str
    primary_candidate_id: str
    candidate_ids: list[str]
    finding_ids: list[str]
    merged_entry_points: list[str] = Field(default_factory=list)
    same_fix: bool = True


class AgentTurnReceipt(BudoModel):
    turn_id: str
    round_index: int = Field(ge=1)
    proposal: ActionProposal
    invocation: AgentInvocation
    observation: Observation
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime = Field(default_factory=utc_now)


class AgentLoopState(BudoModel):
    schema_version: int = 1
    loop_id: str
    run_id: str
    engagement_id: str
    status: AgentLoopStatus = AgentLoopStatus.ACTIVE
    current_round: int = Field(default=1, ge=1)
    turns: list[AgentTurnReceipt] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    validation_outcomes: list[ValidationOutcome] = Field(default_factory=list)
    participating_agents: list[AgentRole] = Field(default_factory=list)
    invoked_skills: list[str] = Field(default_factory=list)
    proxy_backends: list[str] = Field(default_factory=list)
    role_thread_ids: dict[str, str] = Field(default_factory=dict)
    executed_catalog_actions: list[str] = Field(default_factory=list)
    blocked_catalog_actions: list[str] = Field(default_factory=list)
    consecutive_low_gain: int = Field(default=0, ge=0)
    stop_reason: str | None = None
    resume_count: int = Field(default=0, ge=0)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @property
    def executed_turn_count(self) -> int:
        return sum(turn.observation.status is ObservationStatus.EXECUTED for turn in self.turns)


class OutcomeStatus(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    DOWNGRADED = "downgraded"


class PlatformOutcome(BudoModel):
    outcome_id: str
    finding_id: str
    vendor_key: str
    status: OutcomeStatus
    reward: float = Field(default=0, ge=0)
    reason: str = Field(min_length=1, max_length=4000)
    recorded_at: datetime = Field(default_factory=utc_now)


class VendorKnowledge(BudoModel):
    schema_version: int = 1
    vendor_key: str
    platform: str
    vendor: str
    product_features: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    object_types: list[str] = Field(default_factory=list)
    states: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    parameters: list[str] = Field(default_factory=list)
    javascript_api_clues: list[str] = Field(default_factory=list)
    api_schema_clues: list[str] = Field(default_factory=list)
    change_observations: list[str] = Field(default_factory=list)
    tested_candidate_ids: list[str] = Field(default_factory=list)
    anomalous_behaviors: list[str] = Field(default_factory=list)
    unfinished_candidate_ids: list[str] = Field(default_factory=list)
    confirmed_finding_ids: list[str] = Field(default_factory=list)
    rejected_finding_ids: list[str] = Field(default_factory=list)
    duplicate_finding_ids: list[str] = Field(default_factory=list)
    regression_finding_ids: list[str] = Field(default_factory=list)
    false_positive_rules: list[str] = Field(default_factory=list)
    root_cause_keys: list[str] = Field(default_factory=list)
    outcomes: list[PlatformOutcome] = Field(default_factory=list)
    acceptance_prior: float = Field(default=0.55, ge=0.05, le=0.95)
    duplicate_risk_prior: float = Field(default=0.35, ge=0.05, le=0.95)
    impact_multiplier: float = Field(default=1.0, ge=0.25, le=2.0)
    updated_at: datetime = Field(default_factory=utc_now)


class BountyScore(BudoModel):
    candidate_id: str
    expected_reward: float = Field(ge=0)
    confirmation_probability: float = Field(ge=0.01, le=1)
    business_impact: float = Field(ge=0.01, le=2)
    uniqueness: float = Field(ge=0.01, le=2)
    duplicate_risk: float = Field(ge=0.01, le=1)
    request_cost: float = Field(ge=0.01)
    token_cost: float = Field(ge=0.01)
    research_cost: float = Field(ge=0.01)
    score: float = Field(ge=0)
