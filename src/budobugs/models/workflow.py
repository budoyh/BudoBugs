"""Typed, engagement-declared multi-step program experiments."""

from __future__ import annotations

import json
from typing import Literal
from urllib.parse import parse_qsl, urlsplit

from pydantic import Field, JsonValue, model_validator

from budobugs.models.agentic import AgentRole, SafeExperimentTemplate, SafeHttpAction
from budobugs.models.base import BudoModel
from budobugs.models.enums import Severity


class WorkflowSlotCapture(BudoModel):
    """Capture one short-lived scalar without placing its value in artifacts."""

    slot_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_-]{1,31}$")
    source: Literal["json", "header"]
    json_pointer: str | None = Field(default=None, min_length=1, max_length=300)
    header_name: str | None = Field(default=None, min_length=1, max_length=100)

    @model_validator(mode="after")
    def require_exact_source(self) -> WorkflowSlotCapture:
        if self.source == "json":
            if self.json_pointer is None or self.header_name is not None:
                raise ValueError("JSON slot capture requires only json_pointer")
            if not self.json_pointer.startswith("/"):
                raise ValueError("slot capture json_pointer must be a non-empty JSON pointer")
        elif self.header_name is None or self.json_pointer is not None:
            raise ValueError("header slot capture requires only header_name")
        return self


class WorkflowSlotInjection(BudoModel):
    """Inject a previously captured scalar into one exact request location."""

    slot_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_-]{1,31}$")
    destination: Literal["authorization", "header", "query", "json"]
    name: str | None = Field(default=None, min_length=1, max_length=100)
    json_pointer: str | None = Field(default=None, min_length=1, max_length=300)
    prefix: str = Field(default="", max_length=40)

    @model_validator(mode="after")
    def require_exact_destination(self) -> WorkflowSlotInjection:
        if any(character in self.prefix for character in ("\x00", "\r", "\n")):
            raise ValueError("slot injection prefix cannot contain control characters")
        if self.destination == "authorization":
            if self.name is not None or self.json_pointer is not None:
                raise ValueError("authorization injection cannot declare name or json_pointer")
            return self
        if self.destination in {"header", "query"}:
            if self.name is None or self.json_pointer is not None:
                raise ValueError(f"{self.destination} injection requires only name")
            if self.destination == "header" and self.name.lower() in {
                "authorization",
                "cookie",
                "proxy-authorization",
                "host",
                "content-length",
                "connection",
                "transfer-encoding",
            }:
                raise ValueError("custom header injection cannot target credential or transport headers")
            return self
        if self.json_pointer is None or self.name is not None or not self.json_pointer.startswith("/"):
            raise ValueError("JSON injection requires only a non-empty json_pointer")
        return self


class WorkflowStep(BudoModel):
    """One exact request plus machine-checkable predicates and slot wiring."""

    action: SafeHttpAction
    captures: list[WorkflowSlotCapture] = Field(default_factory=list, max_length=8)
    injections: list[WorkflowSlotInjection] = Field(default_factory=list, max_length=8)
    expected_json_pointer: str | None = Field(default=None, min_length=1, max_length=300)
    expected_json_value: JsonValue | None = None

    @model_validator(mode="after")
    def validate_step_shape(self) -> WorkflowStep:
        if self.expected_json_pointer is not None and not self.expected_json_pointer.startswith("/"):
            raise ValueError("workflow predicate must use a non-empty JSON pointer")
        if self.expected_json_pointer is None and self.expected_json_value is not None:
            raise ValueError("expected_json_value requires expected_json_pointer")
        query_names = [
            name for name, _value in parse_qsl(urlsplit(self.action.target_url).query, keep_blank_values=True)
        ]
        for injection in self.injections:
            if injection.destination == "query" and query_names.count(str(injection.name)) != 1:
                raise ValueError("query slot injection requires one exact predeclared query parameter")
            if injection.destination == "json" and self.action.body is None:
                raise ValueError("JSON slot injection requires a predeclared JSON body")
        return self


class SafeWorkflowExperimentTemplate(BudoModel):
    """A reversible, repeated, multi-step program validation contract."""

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
    normal_steps: list[WorkflowStep] = Field(min_length=1, max_length=12)
    experiment_steps: list[WorkflowStep] = Field(min_length=1, max_length=12)
    negative_steps: list[WorkflowStep] = Field(min_length=1, max_length=12)
    cleanup_steps: list[WorkflowStep] = Field(min_length=1, max_length=12)
    cleanup_verification_steps: list[WorkflowStep] = Field(min_length=1, max_length=12)
    repeat_count: int = Field(default=2, ge=2, le=3)
    expected_information_gain: float = Field(default=0.95, ge=0, le=1)

    @model_validator(mode="after")
    def require_closed_reversible_workflow(self) -> SafeWorkflowExperimentTemplate:
        phases = self.phase_steps()
        all_steps = [step for steps in phases.values() for step in steps]
        action_ids = [step.action.action_id for step in all_steps]
        if len(action_ids) != len(set(action_ids)):
            raise ValueError("workflow action IDs must be unique")
        mutations = [step for step in all_steps if step.action.method in {"POST", "PUT", "PATCH", "DELETE"}]
        if not any(step.action.method in {"POST", "PUT", "PATCH", "DELETE"} for step in self.experiment_steps):
            raise ValueError("workflow experiment must contain a bounded mutation")
        if not any(step.action.method in {"POST", "PUT", "PATCH", "DELETE"} for step in self.cleanup_steps):
            raise ValueError("workflow cleanup must contain an explicit mutation")
        for step in mutations:
            action = step.action
            if action.account_alias == "anonymous":
                raise ValueError("workflow mutations require a declared self-owned account")
            if not action.operation_boundary or not action.object_boundary:
                raise ValueError("workflow mutations require exact operation and object boundaries")
        if any(step.action.method not in {"GET", "OPTIONS"} for step in self.cleanup_verification_steps):
            raise ValueError("workflow cleanup verification must be read-only")

        experiment_mutations = [
            step.action for step in self.experiment_steps if step.action.method in {"POST", "PUT", "PATCH", "DELETE"}
        ]
        experiment_objects = {str(action.object_boundary) for action in experiment_mutations}
        normal_mutation_objects = {
            str(step.action.object_boundary)
            for step in self.normal_steps
            if step.action.method in {"POST", "PUT", "PATCH", "DELETE"}
        }
        negative_success_mutation_objects = {
            str(step.action.object_boundary)
            for step in self.negative_steps
            if step.action.method in {"POST", "PUT", "PATCH", "DELETE"}
            and not all(400 <= status <= 499 for status in step.action.expected_statuses)
        }
        mutated_objects_requiring_cleanup = (
            experiment_objects | normal_mutation_objects | negative_success_mutation_objects
        )
        experiment_pairs = {
            (str(action.operation_boundary), str(action.object_boundary)) for action in experiment_mutations
        }
        normal_objects = {str(step.action.object_boundary) for step in self.normal_steps if step.action.object_boundary}
        if not experiment_objects <= normal_objects:
            raise ValueError("normal workflow must cover every experiment object boundary")
        negative_pairs = {
            (str(step.action.operation_boundary), str(step.action.object_boundary))
            for step in self.negative_steps
            if step.action.operation_boundary and step.action.object_boundary
        }
        if not negative_pairs or not negative_pairs <= experiment_pairs:
            raise ValueError("negative workflow must bind to an experiment operation and object boundary")
        cleanup_objects = {
            str(step.action.object_boundary)
            for step in self.cleanup_steps
            if step.action.method in {"POST", "PUT", "PATCH", "DELETE"} and step.action.object_boundary
        }
        if not mutated_objects_requiring_cleanup <= cleanup_objects:
            raise ValueError("cleanup mutations must cover every possibly successful workflow mutation object")
        cleanup_verification_objects = {
            str(step.action.object_boundary) for step in self.cleanup_verification_steps if step.action.object_boundary
        }
        if not mutated_objects_requiring_cleanup <= cleanup_verification_objects:
            raise ValueError("cleanup verification must cover every possibly successful workflow mutation object")

        captured: set[str] = set()
        for phase, steps in phases.items():
            for step in steps:
                for injection in step.injections:
                    if injection.slot_name not in captured:
                        raise ValueError(f"workflow slot {injection.slot_name} is injected before capture")
                if phase != "normal":
                    if step.captures:
                        raise ValueError("workflow slots must be captured during normal controls")
                    continue
                for capture in step.captures:
                    if capture.slot_name in captured:
                        raise ValueError("workflow slot names must be unique")
                    captured.add(capture.slot_name)
        return self

    def phase_steps(self) -> dict[str, list[WorkflowStep]]:
        return {
            "normal": self.normal_steps,
            "experiment": self.experiment_steps,
            "negative": self.negative_steps,
            "cleanup": self.cleanup_steps,
            "cleanup_verification": self.cleanup_verification_steps,
        }

    def all_actions(self) -> list[SafeHttpAction]:
        return [step.action for steps in self.phase_steps().values() for step in steps]

    @property
    def agent_role(self) -> AgentRole:
        return AgentRole(self.specialist_role)


def workflow_control_ids(template: SafeWorkflowExperimentTemplate) -> list[str]:
    """Return stable control IDs without exposing bodies, headers, or slots."""

    return [action.action_id for action in template.all_actions()]


ProgramExperimentTemplate = SafeExperimentTemplate | SafeWorkflowExperimentTemplate


def parse_program_experiment_template(raw: str) -> ProgramExperimentTemplate:
    """Load old single-action and new workflow contracts without ambiguous coercion."""

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("program experiment must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("program experiment must be a JSON object")
    if "normal_steps" in payload or "experiment_steps" in payload:
        return SafeWorkflowExperimentTemplate.model_validate(payload)
    return SafeExperimentTemplate.model_validate(payload)


def program_experiment_actions(template: ProgramExperimentTemplate) -> list[SafeHttpAction]:
    if isinstance(template, SafeWorkflowExperimentTemplate):
        return template.all_actions()
    return [
        template.normal_control,
        template.experiment,
        template.negative_control,
        template.effect_observation,
        *template.cleanup,
        template.cleanup_verification,
    ]
