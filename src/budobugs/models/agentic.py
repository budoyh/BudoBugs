"""Typed contracts for the recoverable agent research loop."""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import Field, JsonValue, field_validator, model_validator

from budobugs.models.base import BudoModel, utc_now
from budobugs.models.enums import Severity


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


class HarmlessMultipartUpload(BudoModel):
    """A tiny generated fixture upload, never a path or caller-supplied file."""

    file_field: str = Field(default="file", pattern=r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")
    filename: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,59}\.(?:txt|json)$")
    fixture_kind: Literal["text", "json"]
    marker: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    form_fields: dict[str, str] = Field(default_factory=dict, max_length=8)

    @model_validator(mode="after")
    def require_bounded_safe_fixture(self) -> HarmlessMultipartUpload:
        if self.filename.endswith(".txt") != (self.fixture_kind == "text"):
            raise ValueError("text multipart fixtures require a .txt filename")
        if self.filename.endswith(".json") != (self.fixture_kind == "json"):
            raise ValueError("JSON multipart fixtures require a .json filename")
        forbidden = {"authorization", "cookie", "credential", "password", "secret", "token", "api_key", "apikey"}
        for name, value in self.form_fields.items():
            normalized = name.casefold().replace("-", "_")
            if normalized in forbidden or any(part in normalized for part in {"password", "secret", "credential"}):
                raise ValueError("multipart form fields cannot contain credentials")
            if (
                re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", name) is None
                or name == self.file_field
                or len(value) > 80
                or any(character in name or character in value for character in ("\x00", "\r", "\n", "/", "\\"))
            ):
                raise ValueError(
                    "multipart form fields must be unique from the file field, identifier-safe, short, "
                    "path-free, and control-character-free"
                )
        return self


class SafeHttpAction(BudoModel):
    """One exact engagement-declared request in a self-owned control experiment."""

    action_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
    account_alias: str = Field(pattern=r"^(anonymous|[A-Za-z][A-Za-z0-9_-]{1,31})$")
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    target_url: str = Field(min_length=1, max_length=4096)
    headers: dict[str, str] = Field(default_factory=dict, max_length=20)
    body: JsonValue | None = None
    multipart_upload: HarmlessMultipartUpload | None = None
    expected_statuses: list[int] = Field(min_length=1, max_length=20)
    expected_response_headers: dict[str, str] = Field(default_factory=dict, max_length=20)
    operation_boundary: str | None = Field(default=None, min_length=3, max_length=500)
    object_boundary: str | None = Field(default=None, min_length=3, max_length=500)

    @field_validator("headers")
    @classmethod
    def reject_secret_and_transport_headers(cls, value: dict[str, str]) -> dict[str, str]:
        forbidden = {
            "authorization",
            "cookie",
            "proxy-authorization",
            "host",
            "content-length",
            "connection",
            "transfer-encoding",
        }
        for name, header_value in value.items():
            if name.lower() in forbidden:
                raise ValueError("safe experiment headers cannot contain credentials or transport framing")
            if any(char in name or char in header_value for char in ("\x00", "\r", "\n")):
                raise ValueError("safe experiment headers cannot contain control characters")
        return value

    @field_validator("expected_statuses")
    @classmethod
    def validate_statuses(cls, values: list[int]) -> list[int]:
        if any(value < 100 or value > 599 for value in values):
            raise ValueError("expected statuses must be valid HTTP status codes")
        return list(dict.fromkeys(values))

    @field_validator("expected_response_headers")
    @classmethod
    def validate_expected_response_headers(cls, value: dict[str, str]) -> dict[str, str]:
        """Require exact, case-insensitive response-header assertions when declared.

        These are observations rather than request headers, so credentials are
        not meaningful here.  Keeping the values exact makes CORS assertions
        (notably ACAO and ACAC) mechanically reproducible in a safe experiment.
        """

        for name, header_value in value.items():
            if not name.strip() or any(char in name or char in header_value for char in ("\x00", "\r", "\n")):
                raise ValueError("expected response headers cannot contain empty names or control characters")
        return value

    @model_validator(mode="after")
    def require_unambiguous_request_body(self) -> SafeHttpAction:
        if self.multipart_upload is None:
            return self
        if self.body is not None:
            raise ValueError("multipart upload cannot be combined with a JSON body")
        if self.method not in {"POST", "PUT", "PATCH"}:
            raise ValueError("multipart upload requires POST, PUT, or PATCH")
        if any(name.lower() == "content-type" for name in self.headers):
            raise ValueError("multipart upload Content-Type is generated by the executor")
        return self


class SelfOwnedObjectRecipe(BudoModel):
    """One pre-authorized, reversible object lifecycle for a declared test account.

    This deliberately lives beside ``SafeExperimentTemplate``: it is a bounded
    setup primitive for exploration, not an agent-authored mutation.  Its exact
    URLs and JSON bodies are supplied before the one-time engagement approval.
    """

    recipe_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
    account_alias: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_-]{1,31}$")
    object_description: str = Field(min_length=3, max_length=500)
    create: SafeHttpAction
    verification: SafeHttpAction
    cleanup: SafeHttpAction
    cleanup_verification: SafeHttpAction

    @model_validator(mode="after")
    def require_exact_reversible_self_owned_lifecycle(self) -> SelfOwnedObjectRecipe:
        actions = (self.create, self.verification, self.cleanup, self.cleanup_verification)
        if any(action.account_alias != self.account_alias for action in actions):
            raise ValueError("self-owned object recipe actions must use its declared account alias")
        if self.create.method not in {"POST", "PUT"} or self.create.body is None:
            raise ValueError("self-owned object recipe create must be POST/PUT with a JSON body")
        if self.verification.method != "GET":
            raise ValueError("self-owned object recipe verification must be GET")
        if self.cleanup.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("self-owned object recipe cleanup must be a bounded mutation")
        if self.cleanup_verification.method != "GET":
            raise ValueError("self-owned object recipe cleanup verification must be GET")
        return self


class SafeExperimentTemplate(BudoModel):
    """Normal/repeat/negative/cleanup contract authorized once for self-owned program data."""

    template_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
    specialist_role: Literal[
        "authorization-specialist",
        "business-logic-specialist",
        "api-auth-specialist",
        "web-client-specialist",
    ]
    title: str = Field(min_length=5, max_length=300)
    vulnerability_class: str = Field(min_length=3, max_length=120)
    affected_feature: str = Field(min_length=3, max_length=500)
    security_invariant: str = Field(min_length=10, max_length=2000)
    root_cause_key: str = Field(min_length=3, max_length=500)
    repair_boundary: str = Field(min_length=3, max_length=1000)
    capability_before: str = Field(min_length=3, max_length=1000)
    capability_after: str = Field(min_length=3, max_length=1000)
    capability_delta: str = Field(min_length=3, max_length=1000)
    strongest_benign_explanation: str = Field(min_length=3, max_length=2000)
    impact: str = Field(min_length=3, max_length=2000)
    severity: Severity = Severity.MEDIUM
    normal_control: SafeHttpAction
    experiment: SafeHttpAction
    negative_control: SafeHttpAction
    effect_observation: SafeHttpAction
    effect_json_pointer: str = Field(min_length=2, max_length=300)
    expected_effect_sequence: list[JsonValue] = Field(min_length=3, max_length=4)
    cleanup: list[SafeHttpAction] = Field(min_length=1, max_length=8)
    cleanup_verification: SafeHttpAction
    repeat_count: int = Field(default=2, ge=2, le=3)
    repeat_relation: Literal["both-succeed", "same-response"] = "both-succeed"
    negative_relation: Literal["deny-status", "different-response", "same-as-normal"] = "deny-status"
    expected_information_gain: float = Field(default=0.9, ge=0, le=1)

    @model_validator(mode="after")
    def require_bounded_reversible_lifecycle(self) -> SafeExperimentTemplate:
        if self.normal_control.method not in {"GET", "OPTIONS"}:
            raise ValueError("safe experiment normal control must be read-only")
        if self.experiment.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("safe experiment must validate a mutating HTTP action")
        if not any(item.method in {"POST", "PUT", "PATCH", "DELETE"} for item in self.cleanup):
            raise ValueError("safe experiment cleanup must include an explicit lifecycle mutation")
        if self.cleanup_verification.method not in {"GET", "OPTIONS"}:
            raise ValueError("safe experiment cleanup verification must be read-only")
        if self.effect_observation.method not in {"GET", "OPTIONS"}:
            raise ValueError("safe experiment effect observation must be read-only")
        if self.experiment.account_alias == "anonymous":
            raise ValueError("safe experiment mutation must use a declared self-owned account")
        if self.normal_control.account_alias != self.experiment.account_alias:
            raise ValueError("normal control and experiment must use the same self-owned account")
        if any(item.account_alias != self.experiment.account_alias for item in self.cleanup):
            raise ValueError("cleanup must use the same self-owned account as the experiment")
        if self.effect_observation.account_alias != self.experiment.account_alias:
            raise ValueError("effect observation must use the same self-owned account as the experiment")
        if not self.experiment.operation_boundary or not self.experiment.object_boundary:
            raise ValueError("safe experiment must declare its operation and object boundaries")
        if (
            self.negative_control.operation_boundary != self.experiment.operation_boundary
            or self.negative_control.object_boundary != self.experiment.object_boundary
        ):
            raise ValueError("negative control must bind to the same operation and object boundaries")
        if self.normal_control.object_boundary != self.experiment.object_boundary:
            raise ValueError("normal control must bind to the experiment object boundary")
        if self.effect_observation.object_boundary != self.experiment.object_boundary:
            raise ValueError("effect observation must bind to the experiment object boundary")
        if self.negative_control.method in {"POST", "PUT", "PATCH", "DELETE"} and (
            self.negative_control.account_alias != self.experiment.account_alias
            or self.negative_relation != "deny-status"
        ):
            raise ValueError("mutating negative controls must use the same account and a deny-status relation")
        normal_identity = self._action_identity(self.normal_control)
        if self._action_identity(self.cleanup_verification) != normal_identity:
            raise ValueError("cleanup verification must repeat the exact normal control request")
        if self._action_identity(self.effect_observation) != normal_identity:
            raise ValueError("effect observation must repeat the exact normal control request")
        if self._action_identity(self.negative_control) == self._action_identity(self.experiment):
            raise ValueError("negative control must be independent from the experiment request")
        if self.negative_relation == "deny-status" and any(
            status < 400 or status > 499 for status in self.negative_control.expected_statuses
        ):
            raise ValueError("deny-status negative controls must expect only HTTP 4xx statuses")
        if self.experiment.method == "DELETE" and not any(
            item.method in {"POST", "PUT", "PATCH"} for item in self.cleanup
        ):
            raise ValueError("DELETE experiments require a non-DELETE restoration action")
        if not self.effect_json_pointer.startswith("/") or any(
            character in self.effect_json_pointer for character in ("\x00", "\r", "\n")
        ):
            raise ValueError("effect_json_pointer must be a non-empty JSON pointer")
        if len(self.expected_effect_sequence) != self.repeat_count + 1:
            raise ValueError("expected effect sequence must contain the baseline and one value per repeat")
        actions = [
            self.normal_control,
            self.experiment,
            self.negative_control,
            self.effect_observation,
            *self.cleanup,
            self.cleanup_verification,
        ]
        action_ids = [item.action_id for item in actions]
        if len(action_ids) != len(set(action_ids)):
            raise ValueError("safe experiment action IDs must be unique")
        return self

    @staticmethod
    def _action_identity(action: SafeHttpAction) -> tuple[object, ...]:
        return (
            action.account_alias,
            action.method,
            action.target_url,
            tuple(sorted(action.headers.items())),
            str(action.body),
            str(action.multipart_upload),
        )


class SafeWebSocketAction(BudoModel):
    """One exact, credential-free WebSocket interaction declared before authorization.

    Authentication comes only from the persistent browser context for the
    declared account.  The action deliberately has no header/cookie fields so
    a template cannot smuggle credentials into evidence or a replay log.
    """

    action_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
    account_alias: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_-]{1,31}$")
    target_url: str = Field(min_length=1, max_length=4096)
    send_text: str | None = Field(default=None, max_length=8192)
    expected_event: Literal["message", "close"] = "message"
    expected_handshake_status: Literal[101] = 101
    expected_close_codes: list[int] = Field(default_factory=list, max_length=8)
    expected_json_pointer: str | None = Field(default=None, min_length=2, max_length=300)
    expected_json_value: JsonValue | None = None

    @field_validator("target_url")
    @classmethod
    def require_websocket_url(cls, value: str) -> str:
        from urllib.parse import parse_qsl, urlsplit

        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"ws", "wss"} or not parsed.hostname:
            raise ValueError("safe websocket action target_url must use WS or WSS")
        if (
            parsed.username is not None
            or parsed.password is not None
            or any(char in value for char in ("\x00", "\r", "\n"))
        ):
            raise ValueError("safe websocket action target_url must be credential-free")
        sensitive_query_names = {
            "token",
            "access_token",
            "id_token",
            "auth",
            "authorization",
            "api_key",
            "apikey",
            "key",
            "signature",
            "sig",
            "cookie",
            "session",
        }
        query_items = parse_qsl(parsed.query, keep_blank_values=True)
        if any(name.casefold() in sensitive_query_names for name, _value in query_items):
            raise ValueError("safe websocket action target_url cannot contain credential-like query parameters")
        return value

    @field_validator("send_text")
    @classmethod
    def reject_control_text(cls, value: str | None) -> str | None:
        if value is not None and any(char in value for char in ("\x00", "\r", "\n")):
            raise ValueError("safe websocket send_text cannot contain control characters")
        return value

    @field_validator("expected_close_codes")
    @classmethod
    def validate_close_codes(cls, values: list[int]) -> list[int]:
        if any(value < 1000 or value > 4999 for value in values):
            raise ValueError("WebSocket close codes must be between 1000 and 4999")
        return list(dict.fromkeys(values))

    @model_validator(mode="after")
    def require_event_predicate_shape(self) -> SafeWebSocketAction:
        if self.expected_event == "close" and not self.expected_close_codes:
            raise ValueError("close event controls require expected_close_codes")
        if self.expected_event == "message" and self.expected_close_codes:
            raise ValueError("message event controls cannot declare close codes")
        if self.expected_json_pointer is not None and not self.expected_json_pointer.startswith("/"):
            raise ValueError("expected_json_pointer must be a JSON pointer")
        if self.expected_json_value is not None and self.expected_json_pointer is None:
            raise ValueError("expected_json_value requires expected_json_pointer")
        return self


class SafeWebSocketExperimentTemplate(BudoModel):
    """Normal/repeat/negative WebSocket contract for a declared program account."""

    template_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
    specialist_role: Literal["api-auth-specialist"] = "api-auth-specialist"
    title: str = Field(min_length=5, max_length=300)
    vulnerability_class: str = Field(min_length=3, max_length=120)
    affected_feature: str = Field(min_length=3, max_length=500)
    security_invariant: str = Field(min_length=10, max_length=2000)
    root_cause_key: str = Field(min_length=3, max_length=500)
    repair_boundary: str = Field(min_length=3, max_length=1000)
    capability_before: str = Field(min_length=3, max_length=1000)
    capability_after: str = Field(min_length=3, max_length=1000)
    capability_delta: str = Field(min_length=3, max_length=1000)
    strongest_benign_explanation: str = Field(min_length=3, max_length=2000)
    impact: str = Field(min_length=3, max_length=2000)
    severity: Severity = Severity.MEDIUM
    normal_control: SafeWebSocketAction
    experiment: SafeWebSocketAction
    negative_control: SafeWebSocketAction
    repeat_count: int = Field(default=2, ge=2, le=3)
    expected_information_gain: float = Field(default=0.9, ge=0, le=1)

    @model_validator(mode="after")
    def require_bounded_controls(self) -> SafeWebSocketExperimentTemplate:
        actions = (self.normal_control, self.experiment, self.negative_control)
        aliases = {item.account_alias for item in actions}
        if len(aliases) != 1:
            raise ValueError("WebSocket normal, experiment, and negative controls use one declared account")
        if self.normal_control.expected_event != "message":
            raise ValueError("WebSocket normal control must establish a message baseline")
        if self.experiment.expected_event != "message":
            raise ValueError("WebSocket experiment must prove a message-level result")
        if self.negative_control.expected_event != "close":
            raise ValueError("WebSocket negative control must prove a denied close")
        action_ids = [item.action_id for item in actions]
        if len(action_ids) != len(set(action_ids)):
            raise ValueError("safe websocket action IDs must be unique")
        if self._identity(self.normal_control) == self._identity(self.experiment):
            raise ValueError("WebSocket normal control must be independent from the experiment")
        if self._identity(self.negative_control) == self._identity(self.experiment):
            raise ValueError("WebSocket negative control must be independent from the experiment")
        return self

    @staticmethod
    def _identity(action: SafeWebSocketAction) -> tuple[str, str, str | None]:
        return action.account_alias, action.target_url, action.send_text


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


class ProgramValidationPlan(BudoModel):
    """One taxonomy hypothesis bound to controls the executor can actually run."""

    plan_id: str
    hypothesis_id: str
    endpoint_family_id: str
    validator_id: str
    specialist_role: Literal[
        "authorization-specialist",
        "business-logic-specialist",
        "api-auth-specialist",
        "web-client-specialist",
    ]
    control_source: Literal["observed-object-differential", "engagement-safe-experiment"]
    control_ids: list[str] = Field(min_length=1)
    parameter_name: str | None = None
    parameter_location: Literal["path", "query", "body", "graphql"] | None = None
    endpoint_host: str | None = None
    endpoint_method: Literal["GET", "POST"] | None = None
    endpoint_path_template: str | None = None
    safe_experiment_template_id: str | None = None
    expected_information_gain: float = Field(default=0.8, ge=0, le=1)

    @model_validator(mode="after")
    def bind_template_source(self) -> ProgramValidationPlan:
        if self.control_source == "engagement-safe-experiment" and self.safe_experiment_template_id is None:
            raise ValueError("safe-experiment plans require a template ID")
        if self.control_source == "observed-object-differential" and self.safe_experiment_template_id is not None:
            raise ValueError("object-differential plans cannot reference a safe experiment")
        if self.control_source == "observed-object-differential" and not all(
            (
                self.parameter_name,
                self.parameter_location,
                self.endpoint_host,
                self.endpoint_method,
                self.endpoint_path_template,
            )
        ):
            raise ValueError("object-differential plans require an exact parameter and stable endpoint selector")
        if self.control_source == "observed-object-differential" and len(self.control_ids) != 2:
            raise ValueError("object-differential plans require exactly two observed account controls")
        if self.control_source == "engagement-safe-experiment" and any(
            (
                self.parameter_name,
                self.parameter_location,
                self.endpoint_host,
                self.endpoint_method,
                self.endpoint_path_template,
            )
        ):
            raise ValueError("safe-experiment plans cannot contain object-differential selectors")
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
    affected_feature: str = Field(default="unknown", max_length=500)
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


class AgentRouteReceipt(BudoModel):
    """Durable coordinator choice constrained to the current safe catalog."""

    route_id: str
    round_index: int = Field(ge=1)
    available_roles: list[AgentRole] = Field(min_length=1)
    candidate_action_ids: dict[str, list[str]]
    selected_role: AgentRole
    rationale: str = Field(min_length=1, max_length=4000)
    expected_information_gain: float = Field(ge=0, le=1)
    invocation: AgentInvocation
    fallback: bool = False
    status: Literal["pending", "completed"] = "pending"
    selected_action_ids: list[str] = Field(default_factory=list)
    observation_ids: list[str] = Field(default_factory=list)
    completion_reason: str | None = Field(default=None, min_length=1, max_length=1000)
    # Kept for schema-1 state compatibility; new readers should use
    # ``selected_action_ids`` for the full role-assignment history.
    selected_action_id: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None

    @model_validator(mode="after")
    def bind_route_to_available_catalog(self) -> AgentRouteReceipt:
        if self.selected_role not in self.available_roles:
            raise ValueError("selected route must be one of the available safe-catalog roles")
        available_values = {role.value for role in self.available_roles}
        if set(self.candidate_action_ids) != available_values:
            raise ValueError("route candidate map must exactly match the available roles")
        if any(not action_ids for action_ids in self.candidate_action_ids.values()):
            raise ValueError("each available route must contain at least one typed catalog action")
        if self.invocation.role is not AgentRole.COORDINATOR:
            raise ValueError("route decisions must be issued by the coordinator")
        selected_ids = self.candidate_action_ids[self.selected_role.value]
        if any(action_id not in selected_ids for action_id in self.selected_action_ids):
            raise ValueError("route action history must stay inside its selected-role catalog snapshot")
        if self.selected_action_id is not None and self.selected_action_id not in selected_ids:
            raise ValueError("route must reference an action from its selected-role catalog snapshot")
        if self.status == "completed" and not (self.selected_action_ids or self.selected_action_id):
            raise ValueError("completed route must contain at least one selected action")
        if self.status == "pending" and self.completion_reason is not None:
            raise ValueError("pending route cannot contain a completion reason")
        return self


class AgentLoopState(BudoModel):
    schema_version: int = 1
    loop_id: str
    run_id: str
    engagement_id: str
    status: AgentLoopStatus = AgentLoopStatus.ACTIVE
    current_round: int = Field(default=1, ge=1)
    # Index of the next specialist in ``ActionCatalogBuilder.schedule`` for
    # ``current_round``.  This is persisted independently of turns because a
    # role can have no candidates, or fail before it produces a turn receipt.
    # A default keeps state files written before cursor support readable.
    schedule_cursor: int = Field(default=0, ge=0)
    route_receipts: list[AgentRouteReceipt] = Field(default_factory=list)
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


class DuplicateAssessmentDecision(StrEnum):
    """Keep investigation clusters distinct from a platform disposition."""

    SAME_FIX_RESEARCH_CLUSTER = "same-fix-research-cluster"
    PLATFORM_DUPLICATE = "platform-duplicate"
    REGRESSION = "regression"
    SEPARATE_INSTANCE = "separate-instance"
    HOLD = "hold"


class OutcomePrior(BudoModel):
    """Small, scoped feedback accumulator; absent fields retain global defaults."""

    observations: int = Field(default=0, ge=0)
    accepted: int = Field(default=0, ge=0)
    rejected: int = Field(default=0, ge=0)
    duplicates: int = Field(default=0, ge=0)
    downgraded: int = Field(default=0, ge=0)
    reward_total: float = Field(default=0, ge=0)
    reward_count: int = Field(default=0, ge=0)


class PlatformOutcome(BudoModel):
    outcome_id: str
    finding_id: str
    vendor_key: str
    status: OutcomeStatus
    reward: float = Field(default=0, ge=0)
    reason: str = Field(min_length=1, max_length=4000)
    vulnerability_class: str | None = Field(default=None, max_length=120)
    root_cause_key: str | None = Field(default=None, max_length=500)
    feature_key: str | None = Field(default=None, max_length=500)
    endpoint_family: str | None = Field(default=None, max_length=500)
    exploitation_method: str | None = Field(default=None, max_length=120)
    previously_fixed: bool = False
    recorded_at: datetime = Field(default_factory=utc_now)


class HistoricalDuplicateAssessment(BudoModel):
    """An explainable historical comparison, never a synthetic platform decision."""

    assessment_id: str
    finding_id: str
    historical_finding_id: str | None = None
    decision: DuplicateAssessmentDecision
    same_vulnerability_class: bool = False
    same_feature: bool = False
    same_root_cause: bool = False
    same_exploitation_method: bool = False
    rationale: str = Field(min_length=1, max_length=2000)
    assessed_at: datetime = Field(default_factory=utc_now)


class VendorKnowledge(BudoModel):
    schema_version: int = 2
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
    outcome_priors: dict[str, OutcomePrior] = Field(default_factory=dict)
    scoped_false_positive_rules: dict[str, list[str]] = Field(default_factory=dict)
    historical_duplicate_assessments: list[HistoricalDuplicateAssessment] = Field(default_factory=list)
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
