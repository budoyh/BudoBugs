"""Recoverable execution for engagement-declared HTTP workflow experiments."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from budobugs.core.identifiers import new_id
from budobugs.core.io import atomic_write_json
from budobugs.core.policy import require_allowed, target_allowed
from budobugs.core.redaction import redact_text
from budobugs.models import (
    CandidateDecision,
    CandidateStatus,
    ControlExperiment,
    Engagement,
    EngagementMode,
    Finding,
    HttpExchange,
    SafeWorkflowExperimentTemplate,
    Severity,
    ValidationOutcome,
    WorkflowSlotCapture,
    WorkflowSlotInjection,
    WorkflowStep,
)
from budobugs.orchestration.multipart import build_harmless_multipart
from budobugs.proxy import DirectProxyBackend
from budobugs.validation.executors import ValidatorResult


@dataclass(frozen=True)
class WorkflowExecution:
    decision: CandidateDecision
    exchanges: list[HttpExchange]
    controls: list[ControlExperiment]
    repeated: bool
    normal_passed: bool
    negative_passed: bool
    cleanup_completed: bool
    evidence_closed: bool
    receipt_path: str
    error_summaries: list[str]


class SafeWorkflowRunner:
    """Run a bounded workflow and atomically checkpoint every completed step."""

    def __init__(
        self,
        *,
        engagement: Engagement,
        run_id: str,
        artifact_root: Path,
        direct: DirectProxyBackend,
        account_headers: dict[str, dict[str, str]],
    ) -> None:
        self.engagement = engagement
        self.run_id = run_id
        self.artifact_root = artifact_root
        self.direct = direct
        self.account_headers = account_headers

    async def run(self, template: SafeWorkflowExperimentTemplate) -> WorkflowExecution:
        if self.engagement.selected_mode is not EngagementMode.PROGRAM:
            raise RuntimeError("safe workflow experiments are available only in program mode")
        receipt_path = self.artifact_root / "workflow-experiments" / template.template_id / "receipt.json"
        prior = self._load_receipt(receipt_path, template.template_id)
        attempt_number = int(prior.get("attempt_count", 0)) + 1
        receipt: dict[str, Any] = {
            "schema_version": 1,
            "engagement_id": self.engagement.engagement_id,
            "run_id": self.run_id,
            "template_id": template.template_id,
            "status": "RUNNING",
            "attempt_count": attempt_number,
            "resumed": bool(prior),
            "prior_attempts": list(prior.get("prior_attempts", []))[-7:],
            "steps": [],
            "captured_slot_names": [],
        }
        if prior:
            receipt["prior_attempts"].append(
                {
                    "attempt": prior.get("attempt_count"),
                    "status": prior.get("status"),
                    "steps": prior.get("steps", []),
                }
            )
        self._write_receipt(receipt_path, receipt)

        slots: dict[str, str] = {}
        exchanges: list[HttpExchange] = []
        phase_passes: dict[str, list[bool]] = {
            "normal": [],
            "experiment": [],
            "negative": [],
            "cleanup": [],
            "cleanup_verification": [],
        }
        errors: list[str] = []
        interrupted: BaseException | None = None

        try:
            await self._run_phase(
                template.normal_steps,
                "normal",
                1,
                slots,
                exchanges,
                phase_passes,
                receipt,
                receipt_path,
            )
            if all(phase_passes["normal"]):
                for repeat_index in range(1, template.repeat_count + 1):
                    await self._run_phase(
                        template.experiment_steps,
                        "experiment",
                        repeat_index,
                        slots,
                        exchanges,
                        phase_passes,
                        receipt,
                        receipt_path,
                    )
                await self._run_phase(
                    template.negative_steps,
                    "negative",
                    1,
                    slots,
                    exchanges,
                    phase_passes,
                    receipt,
                    receipt_path,
                )
        except Exception as exc:
            errors.append(self._safe_error(exc, slots))
        except BaseException as exc:
            interrupted = exc
            errors.append(self._safe_error(exc, slots))
        finally:
            for phase, steps in (
                ("cleanup", template.cleanup_steps),
                ("cleanup_verification", template.cleanup_verification_steps),
            ):
                for step in steps:
                    try:
                        await self._run_phase(
                            [step],
                            phase,
                            1,
                            slots,
                            exchanges,
                            phase_passes,
                            receipt,
                            receipt_path,
                        )
                    except Exception as exc:
                        errors.append(self._safe_error(exc, slots))
                    except BaseException as exc:
                        errors.append(self._safe_error(exc, slots))
                        interrupted = interrupted or exc

        normal_passed = self._phase_closed(phase_passes["normal"], template.normal_steps)
        experiment_expected = len(template.experiment_steps) * template.repeat_count
        repeated = len(phase_passes["experiment"]) == experiment_expected and all(phase_passes["experiment"])
        negative_passed = self._phase_closed(phase_passes["negative"], template.negative_steps)
        cleanup_completed = self._phase_closed(phase_passes["cleanup"], template.cleanup_steps) and self._phase_closed(
            phase_passes["cleanup_verification"], template.cleanup_verification_steps
        )
        controls_closed = not errors and normal_passed and repeated and negative_passed and cleanup_completed
        decision = CandidateDecision.CONFIRMED if controls_closed else CandidateDecision.HOLD
        receipt.update(
            {
                "status": "INTERRUPTED" if interrupted is not None else decision.value,
                "errors": errors,
                "normal_passed": normal_passed,
                "experiment_repeated": repeated,
                "negative_passed": negative_passed,
                "cleanup_completed": cleanup_completed,
                "evidence_closed": controls_closed,
            }
        )
        self._write_receipt(receipt_path, receipt)
        if interrupted is not None:
            raise interrupted

        controls = self._controls(template, receipt, phase_passes, exchanges)
        return WorkflowExecution(
            decision=decision,
            exchanges=exchanges,
            controls=controls,
            repeated=repeated,
            normal_passed=normal_passed,
            negative_passed=negative_passed,
            cleanup_completed=cleanup_completed,
            evidence_closed=controls_closed,
            receipt_path=str(receipt_path),
            error_summaries=errors,
        )

    async def _run_phase(
        self,
        steps: list[WorkflowStep],
        phase: str,
        repeat_index: int,
        slots: dict[str, str],
        exchanges: list[HttpExchange],
        phase_passes: dict[str, list[bool]],
        receipt: dict[str, Any],
        receipt_path: Path,
    ) -> None:
        for step in steps:
            try:
                exchange, passed, captured_names = await self._execute_step(step, slots)
            except BaseException as exc:
                receipt["steps"].append(
                    {
                        "phase": phase,
                        "repeat_index": repeat_index,
                        "action_id": step.action.action_id,
                        "status": "FAILED",
                        "error_type": type(exc).__name__,
                        "captured_slot_names": [],
                        "injected_slot_names": [item.slot_name for item in step.injections],
                    }
                )
                self._write_receipt(receipt_path, receipt)
                raise
            exchanges.append(exchange)
            phase_passes[phase].append(passed)
            receipt["steps"].append(
                {
                    "phase": phase,
                    "repeat_index": repeat_index,
                    "action_id": step.action.action_id,
                    "exchange_id": exchange.exchange_id,
                    "status": "PASSED" if passed else "PREDICATE_FAILED",
                    "predicate_passed": passed,
                    "captured_slot_names": captured_names,
                    "injected_slot_names": [item.slot_name for item in step.injections],
                }
            )
            receipt["captured_slot_names"] = sorted(slots)
            self._write_receipt(receipt_path, receipt)
            if not passed:
                raise RuntimeError(f"workflow predicate failed for {phase}:{step.action.action_id}")

    async def _execute_step(
        self,
        step: WorkflowStep,
        slots: dict[str, str],
    ) -> tuple[HttpExchange, bool, list[str]]:
        action = step.action
        require_allowed(target_allowed(self.engagement, action.target_url))
        if action.account_alias == "anonymous":
            headers = dict(action.headers)
            alias: str | None = None
        else:
            if action.account_alias not in self.engagement.testing_accounts_secret_refs:
                raise RuntimeError(f"workflow account is not engagement-declared: {action.account_alias}")
            if action.account_alias not in self.account_headers:
                raise RuntimeError(f"workflow account is unresolved: {action.account_alias}")
            headers = {**action.headers, **self.account_headers[action.account_alias]}
            alias = action.account_alias
        url = action.target_url
        body: object = copy.deepcopy(action.body)
        for injection in step.injections:
            value = slots.get(injection.slot_name)
            if value is None:
                raise RuntimeError(f"workflow slot is unresolved: {injection.slot_name}")
            url, headers, body = self._inject(injection, value, url, headers, body)
        require_allowed(target_allowed(self.engagement, url))
        content: str | bytes | None = None
        if action.multipart_upload is not None:
            content, content_type = build_harmless_multipart(action.multipart_upload)
            headers["Content-Type"] = content_type
        elif body is not None:
            content = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
            headers.setdefault("Content-Type", "application/json")
        raw = await self.direct.send(
            self.engagement,
            action.method,
            url,
            headers=headers,
            content=content,
            account_alias=alias,
            source="direct",
        )
        captured_names: list[str] = []
        for capture in step.captures:
            value = self._capture(raw, capture)
            slots[capture.slot_name] = value
            captured_names.append(capture.slot_name)
        passed = self._step_passes(raw, step)
        return self._redact_slots(raw, slots), passed, captured_names

    @classmethod
    def _capture(cls, exchange: HttpExchange, capture: WorkflowSlotCapture) -> str:
        if capture.source == "header":
            headers = {name.lower(): value for name, value in exchange.response_headers.items()}
            value: object = headers.get(str(capture.header_name).lower())
        else:
            found, value = cls._json_pointer(exchange.response_body, str(capture.json_pointer))
            if not found:
                value = None
        if not isinstance(value, str) or not 8 <= len(value) <= 4096:
            raise RuntimeError(f"workflow slot capture {capture.slot_name} did not produce a bounded string")
        return value

    @classmethod
    def _step_passes(cls, exchange: HttpExchange, step: WorkflowStep) -> bool:
        action = step.action
        if exchange.response_status not in action.expected_statuses:
            return False
        headers = {name.lower(): value for name, value in exchange.response_headers.items()}
        if any(headers.get(name.lower()) != value for name, value in action.expected_response_headers.items()):
            return False
        if step.expected_json_pointer is None:
            return True
        found, value = cls._json_pointer(exchange.response_body, step.expected_json_pointer)
        return found and value == step.expected_json_value

    @staticmethod
    def _inject(
        injection: WorkflowSlotInjection,
        value: str,
        url: str,
        headers: dict[str, str],
        body: object,
    ) -> tuple[str, dict[str, str], object]:
        injected = f"{injection.prefix}{value}"
        if injection.destination == "authorization":
            headers["Authorization"] = injected
        elif injection.destination == "header":
            headers[str(injection.name)] = injected
        elif injection.destination == "query":
            parsed = urlsplit(url)
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            pairs = [(name, injected if name == injection.name else current) for name, current in pairs]
            url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(pairs, doseq=True), parsed.fragment))
        else:
            SafeWorkflowRunner._set_json_pointer(body, str(injection.json_pointer), injected)
        return url, headers, body

    @staticmethod
    def _set_json_pointer(document: object, pointer: str, value: str) -> None:
        tokens = SafeWorkflowRunner._pointer_tokens(pointer)
        if not tokens:
            raise RuntimeError("workflow cannot replace the JSON document root")
        current = document
        for token in tokens[:-1]:
            if isinstance(current, dict) and token in current:
                current = current[token]
            elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
                current = current[int(token)]
            else:
                raise RuntimeError("workflow JSON injection pointer does not exist")
        final = tokens[-1]
        if isinstance(current, dict) and final in current:
            current[final] = value
        elif isinstance(current, list) and final.isdigit() and int(final) < len(current):
            current[int(final)] = value
        else:
            raise RuntimeError("workflow JSON injection pointer does not exist")

    @staticmethod
    def _json_pointer(body: str | None, pointer: str) -> tuple[bool, object]:
        try:
            value: object = json.loads(body or "")
        except (TypeError, json.JSONDecodeError):
            return False, None
        if pointer == "":
            return True, value
        for token in SafeWorkflowRunner._pointer_tokens(pointer):
            if isinstance(value, dict) and token in value:
                value = value[token]
            elif isinstance(value, list) and token.isdigit() and int(token) < len(value):
                value = value[int(token)]
            else:
                return False, None
        return True, value

    @staticmethod
    def _pointer_tokens(pointer: str) -> list[str]:
        return [token.replace("~1", "/").replace("~0", "~") for token in pointer.removeprefix("/").split("/")]

    @staticmethod
    def _redact_slots(exchange: HttpExchange, slots: dict[str, str]) -> HttpExchange:
        replacements = {value: f"<REDACTED:workflow-slot:{name}>" for name, value in slots.items()}

        def scrub(value: str | None) -> str | None:
            if value is None:
                return None
            for secret, replacement in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
                value = value.replace(secret, replacement)
            return value

        return exchange.model_copy(
            update={
                "url": scrub(exchange.url),
                "request_headers": {name: scrub(value) or "" for name, value in exchange.request_headers.items()},
                "request_body": scrub(exchange.request_body),
                "response_headers": {name: scrub(value) or "" for name, value in exchange.response_headers.items()},
                "response_body": scrub(exchange.response_body),
            }
        )

    @staticmethod
    def _phase_closed(results: list[bool], steps: list[WorkflowStep]) -> bool:
        return len(results) == len(steps) and all(results)

    @staticmethod
    def _safe_error(exc: BaseException, slots: dict[str, str]) -> str:
        detail = f"{type(exc).__name__}: {str(exc)[:300]}"
        for name, value in slots.items():
            detail = detail.replace(value, f"<REDACTED:workflow-slot:{name}>")
        return redact_text(detail) or type(exc).__name__

    @staticmethod
    def _load_receipt(path: Path, template_id: str) -> dict[str, Any]:
        if not path.is_file():
            return {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"workflow receipt is invalid: {path}") from exc
        if not isinstance(payload, dict) or payload.get("template_id") != template_id:
            raise RuntimeError(f"workflow receipt identity mismatch: {path}")
        return payload

    @staticmethod
    def _write_receipt(path: Path, payload: dict[str, Any]) -> None:
        atomic_write_json(path, payload)

    @staticmethod
    def _controls(
        template: SafeWorkflowExperimentTemplate,
        receipt: dict[str, Any],
        phase_passes: dict[str, list[bool]],
        exchanges: list[HttpExchange],
    ) -> list[ControlExperiment]:
        exchange_ids = [item.exchange_id for item in exchanges]
        controls: list[ControlExperiment] = []
        for phase, steps in template.phase_steps().items():
            expected = len(steps) * (template.repeat_count if phase == "experiment" else 1)
            passed = len(phase_passes[phase]) == expected and all(phase_passes[phase])
            phase_exchange_ids = [
                str(item["exchange_id"])
                for item in receipt.get("steps", [])
                if isinstance(item, dict) and item.get("phase") == phase and "exchange_id" in item
            ]
            controls.append(
                ControlExperiment(
                    control_id=new_id("control"),
                    kind="negative" if phase == "negative" else "normal" if phase == "normal" else "refutation",
                    description=f"Execute every engagement-declared {phase} workflow step.",
                    request_exchange_ids=phase_exchange_ids,
                    observed_result=f"steps={len(phase_passes[phase])}/{expected}; predicates_passed={passed}",
                    supports_finding=passed,
                )
            )
        controls.append(
            ControlExperiment(
                control_id=new_id("control"),
                kind="refutation",
                description="Require executor evidence rather than a template-authored verdict.",
                request_exchange_ids=exchange_ids,
                observed_result=(
                    f"receipt_status={receipt.get('status')}; evidence_closed={receipt.get('evidence_closed')}"
                ),
                supports_finding=receipt.get("evidence_closed") is True,
            )
        )
        return controls


def build_workflow_validator_result(
    template: SafeWorkflowExperimentTemplate,
    execution: WorkflowExecution,
    engagement: Engagement,
    candidate_id: str | None,
) -> ValidatorResult:
    """Build a finding solely from executor-generated workflow evidence."""

    confirmed = execution.decision is CandidateDecision.CONFIRMED
    first = template.experiment_steps[0].action
    parsed = urlsplit(first.target_url)
    status = CandidateStatus.VALIDATING if confirmed else CandidateStatus.HOLD
    severity = template.severity if confirmed else Severity.INFO
    capability_delta = (
        template.capability_delta
        if confirmed
        else "none; the repeated workflow, negative control, or cleanup evidence did not close"
    )
    phase_summary = [
        f"normal={execution.normal_passed}",
        f"repeated={execution.repeated}",
        f"negative={execution.negative_passed}",
        f"cleanup={execution.cleanup_completed}",
    ]
    finding = Finding(
        finding_id=new_id("finding"),
        engagement_id=engagement.engagement_id,
        title=template.title if confirmed else f"HOLD: {template.title}",
        vulnerability_class=template.vulnerability_class,
        affected_asset=urlunsplit((parsed.scheme, parsed.netloc, "", "", "")),
        affected_feature=template.affected_feature,
        endpoint_family="; ".join(
            f"{step.action.method} {urlsplit(step.action.target_url).path}" for step in template.experiment_steps
        ),
        attacker_prerequisites=[
            "only engagement-declared self-owned test accounts",
            "one pre-authorized exact workflow template",
        ],
        victim_conditions=["only disposable self-owned objects and sessions are used"],
        security_invariant=template.security_invariant,
        protected_asset="the exact self-owned session, tenant, role, or share lifecycle declared by the template",
        trust_boundary="engagement-declared accounts, URLs, methods, bodies, predicates, and cleanup",
        enforcement_point=template.affected_feature,
        observed_behavior="; ".join(phase_summary + [f"errors={execution.error_summaries}"]),
        expected_behavior=(
            "The protected workflow must reject the repeated capability after its invalidating state change."
        ),
        capability_before=template.capability_before,
        capability_after=template.capability_after if confirmed else template.capability_before,
        capability_delta=capability_delta,
        normal_control=f"All {len(template.normal_steps)} declared normal steps passed={execution.normal_passed}.",
        negative_control=(
            f"All {len(template.negative_steps)} declared negative steps passed={execution.negative_passed}."
        ),
        strongest_benign_explanation=template.strongest_benign_explanation,
        refutation_attempts=[
            "machine-checked normal predicates",
            f"full experiment workflow repeated {template.repeat_count} times",
            "independent negative workflow",
            "cleanup mutation and post-cleanup verification",
        ],
        reproduction_steps=[
            "Run normal steps: " + ", ".join(step.action.action_id for step in template.normal_steps),
            f"Repeat experiment steps {template.repeat_count} times: "
            + ", ".join(step.action.action_id for step in template.experiment_steps),
            "Run negative steps: " + ", ".join(step.action.action_id for step in template.negative_steps),
            "Run cleanup in finally: " + ", ".join(step.action.action_id for step in template.cleanup_steps),
            "Verify cleanup: " + ", ".join(step.action.action_id for step in template.cleanup_verification_steps),
        ],
        requests=[],
        responses=[],
        data_exposure_scope="Only exact engagement-declared self-owned accounts and objects.",
        mutation_scope="Only exact pre-authorized reversible POST/PUT/PATCH/DELETE workflow steps.",
        cleanup_status=(
            "All cleanup and cleanup-verification predicates passed."
            if execution.cleanup_completed
            else "Cleanup is incomplete; candidate remains HOLD."
        ),
        impact=template.impact if confirmed else "No reportable capability increment while evidence remains open.",
        severity=severity,
        confidence=0.96 if confirmed else 0.3,
        duplicate_risk=f"Deduplicate by repair boundary: {template.repair_boundary}",
        status=status,
    )
    outcome = ValidationOutcome(
        outcome_id=new_id("validation"),
        validator_id=f"program-workflow--{template.template_id}",
        candidate_id=candidate_id or new_id("candidate"),
        decision=execution.decision,
        vulnerability_class=template.vulnerability_class,
        title=finding.title,
        affected_feature=template.affected_feature,
        root_cause_key=template.root_cause_key,
        repair_boundary=template.repair_boundary,
        finding_id=finding.finding_id,
        control_ids=[item.control_id for item in execution.controls],
        exchange_ids=[item.exchange_id for item in execution.exchanges],
        capability_delta=capability_delta,
        strongest_benign_explanation=template.strongest_benign_explanation,
        repeated=execution.repeated,
        normal_control_passed=execution.normal_passed,
        negative_control_passed=execution.negative_passed,
        cleanup_completed=execution.cleanup_completed,
        evidence_closed=execution.evidence_closed,
        confidence=finding.confidence,
    )
    return ValidatorResult(
        outcome,
        finding,
        execution.controls,
        execution.exchanges,
        [execution.receipt_path],
    )
