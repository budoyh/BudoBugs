"""Pydantic schemas for the complete BudoBugs evidence lifecycle."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, JsonValue, field_validator, model_validator

from budobugs.models.base import BudoModel, utc_now
from budobugs.models.enums import (
    AuthorizationStatus,
    CandidateStatus,
    CriticVerdict,
    EngagementMode,
    PhaseName,
    Severity,
)

_SAFE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}$")


class Target(BudoModel):
    """One authorized network or source target."""

    uri: str = Field(min_length=1, max_length=2048)
    label: str = Field(default="primary", min_length=1, max_length=120)
    kind: Literal["web", "api", "source"] = "web"

    @field_validator("uri")
    @classmethod
    def validate_uri(cls, value: str) -> str:
        if any(char in value for char in ("\x00", "\r", "\n")):
            raise ValueError("target contains a control character")
        if value != value.strip():
            raise ValueError("target must not contain surrounding whitespace")
        return value


class Engagement(BudoModel):
    """User authorization statement and the sole source of target scope."""

    schema_version: int = 1
    engagement_id: str
    platform: str = Field(min_length=1, max_length=100)
    vendor: str = Field(min_length=1, max_length=200)
    user_authorization_attestation: str = Field(min_length=20, max_length=4000)
    root_targets: list[Target] = Field(min_length=1)
    optional_allowed_subdomains: list[str] = Field(default_factory=list)
    excluded_targets: list[str] = Field(default_factory=list)
    testing_accounts_secret_refs: dict[str, str] = Field(default_factory=dict)
    selected_mode: EngagementMode
    optional_rate_profile: str | None = Field(default=None, max_length=100)
    optional_notes: str | None = Field(default=None, max_length=10000)
    authorization_status: AuthorizationStatus = AuthorizationStatus.DRAFT
    created_at: datetime = Field(default_factory=utc_now)
    authorized_at: datetime | None = None

    @field_validator("engagement_id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not _SAFE_ID.fullmatch(value):
            raise ValueError("engagement_id must be 3-64 safe filename characters")
        return value

    @field_validator("optional_allowed_subdomains", "excluded_targets")
    @classmethod
    def validate_host_patterns(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            item = value.strip().lower().rstrip(".")
            if not item or any(char in item for char in ("/", "\\", "\x00", "\r", "\n")):
                raise ValueError(f"invalid host pattern: {value!r}")
            normalized.append(item)
        return list(dict.fromkeys(normalized))

    @model_validator(mode="after")
    def validate_target_kinds(self) -> Engagement:
        if self.selected_mode in {EngagementMode.LAB, EngagementMode.PROGRAM}:
            for target in self.root_targets:
                parsed = urlsplit(target.uri)
                try:
                    port = parsed.port
                except ValueError as exc:
                    raise ValueError("lab/program root_targets contain an invalid port") from exc
                if (
                    parsed.scheme not in {"http", "https"}
                    or not parsed.hostname
                    or parsed.username is not None
                    or parsed.password is not None
                    or port is not None
                    and not 1 <= port <= 65535
                ):
                    raise ValueError("lab/program root_targets must be credential-free absolute HTTP(S) URLs")
        if self.authorization_status is AuthorizationStatus.AUTHORIZED and self.authorized_at is None:
            raise ValueError("authorized engagement requires authorized_at")
        return self


class AccountIdentity(BudoModel):
    account_id: str
    alias: str
    secret_ref: str
    role_ids: list[str] = Field(default_factory=list)
    tenant_id: str | None = None
    owned_object_ids: list[str] = Field(default_factory=list)


class PhaseRecord(BudoModel):
    name: PhaseName
    status: Literal["pending", "running", "completed", "blocked", "failed"] = "pending"
    attempt: int = Field(default=0, ge=0)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    input_artifacts: list[str] = Field(default_factory=list)
    output_artifacts: list[str] = Field(default_factory=list)
    receipt_id: str | None = None
    error: str | None = None


class Run(BudoModel):
    run_id: str
    engagement_id: str
    selected_mode: EngagementMode
    current_phase: PhaseName = PhaseName.INIT
    phases: list[PhaseRecord] = Field(default_factory=list)
    status: Literal["created", "running", "completed", "blocked", "failed", "interrupted"] = "created"
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    resume_count: int = Field(default=0, ge=0)
    codex_thread_ids: list[str] = Field(default_factory=list)


class ToolInvocation(BudoModel):
    invocation_id: str
    run_id: str
    engagement_id: str
    tool_name: str
    target: str | None = None
    arguments: list[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    exit_code: int | None = None
    status: Literal["planned", "running", "completed", "blocked", "failed", "timeout"] = "planned"
    receipt_path: str | None = None


class HttpExchange(BudoModel):
    exchange_id: str
    engagement_id: str
    run_id: str | None = None
    method: str = Field(pattern=r"^[A-Z]+$")
    url: str
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str | None = None
    response_status: int = Field(ge=0, le=999)
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str | None = None
    http_version: Literal["HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"] | None = None
    elapsed_ms: float | None = Field(default=None, ge=0)
    account_alias: str | None = None
    role_id: str | None = None
    tenant_id: str | None = None
    source: Literal["har", "caido", "burp", "zap", "playwright", "direct", "fixture"]
    captured_at: datetime = Field(default_factory=utc_now)
    untrusted_content: bool = True
    request_hash: str | None = None
    response_hash: str | None = None


class EndpointFamily(BudoModel):
    family_id: str
    host: str
    method: str
    path_template: str
    exchange_ids: list[str] = Field(default_factory=list)
    parameter_names: list[str] = Field(default_factory=list)
    status_baseline: dict[int, int] = Field(default_factory=dict)
    response_length_baseline: tuple[int, int] | None = None
    anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0)


class Parameter(BudoModel):
    name: str
    location: Literal["path", "query", "header", "cookie", "body", "graphql"]
    inferred_type: str
    sample_values: list[str] = Field(default_factory=list)
    dynamic_kind: Literal["stable", "id", "uuid", "timestamp", "pagination", "random", "secret"]
    sensitive: bool = False


class ObjectReference(BudoModel):
    object_id: str
    object_type: str
    owner_account_alias: str | None = None
    tenant_id: str | None = None
    source_exchange_ids: list[str] = Field(default_factory=list)


class Role(BudoModel):
    role_id: str
    name: str
    privileges: list[str] = Field(default_factory=list)


class Tenant(BudoModel):
    tenant_id: str
    name: str
    account_aliases: list[str] = Field(default_factory=list)


class StateTransition(BudoModel):
    transition_id: str
    object_type: str
    from_state: str
    to_state: str
    endpoint_family_id: str
    required_roles: list[str] = Field(default_factory=list)
    reversible: bool = False


class SecurityInvariant(BudoModel):
    invariant_id: str
    statement: str
    protected_asset: str
    trust_boundary: str
    enforcement_point: str
    violation_signal: str


class Hypothesis(BudoModel):
    hypothesis_id: str
    engagement_id: str
    title: str
    vulnerability_class: str
    endpoint_family_id: str
    invariant_id: str
    rationale: str
    attacker_prerequisites: list[str] = Field(default_factory=list)
    proposed_single_variable_change: str
    expected_control: str
    status: CandidateStatus = CandidateStatus.HYPOTHESIS
    priority: int = Field(default=50, ge=0, le=100)


class ControlExperiment(BudoModel):
    control_id: str
    kind: Literal["normal", "negative", "refutation"]
    description: str
    request_exchange_ids: list[str] = Field(default_factory=list)
    observed_result: str
    supports_finding: bool
    artifact_refs: list[str] = Field(default_factory=list)


class ValidationPlan(BudoModel):
    plan_id: str
    hypothesis_id: str
    mode: EngagementMode
    steps: list[str] = Field(min_length=1)
    mutation_scope: str
    cleanup_steps: list[str] = Field(default_factory=list)
    controls: list[ControlExperiment] = Field(default_factory=list)
    allowed_tool_names: list[str] = Field(default_factory=list)


class Evidence(BudoModel):
    evidence_id: str
    kind: Literal[
        "request",
        "response",
        "screenshot",
        "trace",
        "control",
        "tool-output",
        "receipt",
        "critique",
    ]
    artifact_path: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    captured_at: datetime = Field(default_factory=utc_now)
    step: str
    account_alias: str | None = None
    redacted: bool = False


class Critique(BudoModel):
    critique_id: str
    finding_id: str
    strongest_supporting_evidence: list[str]
    strongest_opposing_evidence: list[str]
    unresolved_benign_explanations: list[str]
    additional_tests_needed: list[str]
    impact_overstated: bool
    test_pollution_detected: bool
    third_party_data_involved: bool
    verdict: CriticVerdict
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    created_at: datetime = Field(default_factory=utc_now)


class Finding(BudoModel):
    finding_id: str
    engagement_id: str
    title: str
    vulnerability_class: str
    affected_asset: str
    affected_feature: str
    endpoint_family: str
    attacker_prerequisites: list[str]
    victim_conditions: list[str]
    security_invariant: str
    protected_asset: str
    trust_boundary: str
    enforcement_point: str
    observed_behavior: str
    expected_behavior: str
    capability_before: str
    capability_after: str
    capability_delta: str
    normal_control: str
    negative_control: str
    strongest_benign_explanation: str
    refutation_attempts: list[str]
    reproduction_steps: list[str]
    requests: list[str]
    responses: list[str]
    screenshots: list[str] = Field(default_factory=list)
    evidence_hashes: dict[str, str] = Field(default_factory=dict)
    data_exposure_scope: str
    mutation_scope: str
    cleanup_status: str
    impact: str
    severity: Severity
    cvss: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    duplicate_risk: str
    reportability: Literal["not-ready", "hold", "submission-ready"] = "not-ready"
    critic_verdict: CriticVerdict | None = None
    human_review_status: Literal["not-ready", "pending", "approved", "rejected"] = "not-ready"
    status: CandidateStatus = CandidateStatus.HYPOTHESIS
    evidence_ids: list[str] = Field(default_factory=list)
    gate_receipt_path: str | None = None
    timestamps: dict[str, datetime] = Field(default_factory=lambda: {"created_at": utc_now()})

    @property
    def is_submission_ready(self) -> bool:
        return (
            self.status is CandidateStatus.READY_FOR_HUMAN_REVIEW
            and self.critic_verdict is CriticVerdict.CONFIRMED
            and self.reportability == "submission-ready"
        )


class Report(BudoModel):
    report_id: str
    finding_id: str
    platform: str
    markdown_path: str
    html_path: str
    manifest_path: str
    human_review_checklist_path: str
    generated_at: datetime = Field(default_factory=utc_now)
    redaction_scan_status: Literal["PASS", "FAIL"]
    submission_ready: bool


class CostRecord(BudoModel):
    cost_id: str
    run_id: str
    phase: PhaseName
    candidate_id: str | None = None
    model: str
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    cached_input_tokens: int = Field(default=0, ge=0)
    elapsed_ms: int = Field(ge=0)
    estimated_cost_usd: float | None = Field(default=None, ge=0)
    created_at: datetime = Field(default_factory=utc_now)


class AuditEvent(BudoModel):
    event_id: str
    event_type: str
    engagement_id: str | None = None
    run_id: str | None = None
    actor: str
    message: str
    details: dict[str, JsonValue] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utc_now)


def as_jsonable(value: BudoModel) -> dict[str, Any]:
    """Return a stable JSON-compatible representation for storage."""

    return value.model_dump(mode="json", exclude_none=False)
