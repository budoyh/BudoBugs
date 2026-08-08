"""Artifact-backed local hunting pipeline and recoverable phase ledger."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, replace
from pathlib import Path
from time import perf_counter
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import yaml

from budobugs.agents.router import ModelRouter
from budobugs.agents.runner import CodexTaskRunner
from budobugs.analysis.source_scan import SourceScanCoordinator
from budobugs.browser.session import BrowserSessionManager
from budobugs.core.identifiers import new_id
from budobugs.core.io import atomic_write_json, atomic_write_text, sha256_bytes, sha256_file
from budobugs.core.policy import require_allowed, target_allowed
from budobugs.core.redaction import redact_text
from budobugs.core.state_machine import block_phase, complete_phase, initialize_phases, start_phase
from budobugs.evidence.pack import EvidencePackBuilder
from budobugs.hypotheses.generator import generate_hypotheses
from budobugs.models import (
    AuthorizationStatus,
    CandidateStatus,
    ControlExperiment,
    CostRecord,
    CriticVerdict,
    Critique,
    EndpointFamily,
    Engagement,
    EngagementMode,
    Finding,
    HttpExchange,
    Hypothesis,
    ObjectReference,
    Parameter,
    PhaseName,
    Role,
    Run,
    SecurityInvariant,
    Severity,
    StateTransition,
    Tenant,
    ValidationPlan,
)
from budobugs.models.base import BudoModel
from budobugs.orchestration.service import RepositoryService
from budobugs.proxy.direct import DirectProxyBackend
from budobugs.reporting.generator import ReportGenerator
from budobugs.storage.secrets import SecretStore
from budobugs.traffic.modeler import TrafficModel, build_traffic_model
from budobugs.traffic.normalization import normalized_json_structure
from budobugs.validation.critic import AdversarialCritic
from budobugs.validation.gates import EvidenceGate


@dataclass(frozen=True, slots=True)
class HuntResult:
    run: Run
    confirmed_finding_id: str | None = None
    killed_finding_id: str | None = None
    report_markdown: str | None = None
    report_html: str | None = None


class HuntEngine:
    """Run mode-aware, artifact-backed research under one authorized engagement."""

    def __init__(
        self,
        service: RepositoryService,
        *,
        agent_mode: str | None = None,
        model_router: ModelRouter | None = None,
        agent_runner: CodexTaskRunner | None = None,
    ) -> None:
        self.service = service
        self.agent_mode = (agent_mode or os.environ.get("BUDOBUGS_AGENT_MODE", "disabled")).lower()
        if self.agent_mode not in {"disabled", "codex"}:
            raise ValueError("agent_mode must be disabled or codex")
        self.model_profile = os.environ.get("BUDOBUGS_MODEL_PROFILE", "quality-first")
        self.model_router = model_router
        self.agent_runner = agent_runner
        if self.agent_mode == "codex":
            self.model_router = self.model_router or ModelRouter.load(
                self.service.paths.root / "config" / "models.yaml"
            )
            local_codex = (
                self.service.paths.root / "node_modules" / ".bin" / ("codex.cmd" if os.name == "nt" else "codex")
            )
            self.agent_runner = self.agent_runner or CodexTaskRunner(
                self.service.paths.runs,
                executable=str(local_codex) if local_codex.is_file() else "codex",
            )

    def _engagement_token_budget(self) -> int:
        defaults = yaml.safe_load((self.service.paths.root / "config" / "defaults.yaml").read_text(encoding="utf-8"))
        cost = defaults.get("cost", {}) if isinstance(defaults, dict) else {}
        budget = cost.get("engagement_token_budget") if isinstance(cost, dict) else None
        if not isinstance(budget, int) or budget <= 0:
            raise ValueError("cost.engagement_token_budget must be a positive integer")
        return budget

    def estimate(self, engagement: Engagement) -> dict[str, object]:
        model_calls = 0 if self.agent_mode == "disabled" or engagement.selected_mode is EngagementMode.LAB else 2
        routes: dict[str, object] = {}
        model_token_ceiling = 0
        if model_calls and self.model_router is not None:
            for task_class in ("analysis", "critical_judgment"):
                selection = self.model_router.select(task_class, profile=self.model_profile)
                routes[task_class] = {
                    "candidates": list(selection.candidates),
                    "reasoning_effort": selection.reasoning_effort,
                    "phase_token_budget": selection.token_budget,
                }
                model_token_ceiling += selection.token_budget
        engagement_ceiling = self._engagement_token_budget()
        model_token_ceiling = min(model_token_ceiling, engagement_ceiling)
        network_upper_bound = {
            EngagementMode.LAB: 9,
            EngagementMode.PROGRAM: len(engagement.root_targets)
            + max(0, len(engagement.testing_accounts_secret_refs) * 4),
            EngagementMode.SOURCE: 0,
        }[engagement.selected_mode]
        return {
            "status": "DRY_RUN",
            "engagement_id": engagement.engagement_id,
            "authorization_status": engagement.authorization_status.value,
            "mode": engagement.selected_mode.value,
            "phases": [phase.value for phase in PhaseName],
            "network_request_upper_bound": network_upper_bound,
            "agent_mode": self.agent_mode,
            "planned_model_call_upper_bound": model_calls,
            "model_token_ceiling": model_token_ceiling,
            "estimated_cost_usd": None if model_calls else 0.0,
            "cost_note": (
                "Provider prices are not guessed; actual tokens/elapsed time are persisted and provider billing "
                "receipts remain authoritative."
            ),
            "routes": routes,
            "active_hunt_or_target_network_performed": False,
        }

    async def run(
        self,
        engagement: Engagement,
        *,
        resume: bool = False,
        stop_after: PhaseName | None = None,
    ) -> HuntResult:
        if engagement.authorization_status is not AuthorizationStatus.AUTHORIZED:
            raise PermissionError("engagement must be explicitly authorized before hunt")
        existing = self.service.latest_run(engagement.engagement_id) if resume else None
        if existing is not None and existing.status == "completed":
            findings = self.service.list_findings(engagement.engagement_id)
            confirmed = next(
                (item for item in findings if item.critic_verdict is CriticVerdict.CONFIRMED),
                None,
            )
            killed = next((item for item in findings if item.status is CandidateStatus.KILL), None)
            report = self.service.paths.findings / confirmed.finding_id / "report" if confirmed else None
            return HuntResult(
                existing,
                confirmed.finding_id if confirmed else None,
                killed.finding_id if killed else None,
                str(report / "report.md") if report else None,
                str(report / "report.html") if report else None,
            )
        run = existing or Run(
            run_id=new_id("run"),
            engagement_id=engagement.engagement_id,
            selected_mode=engagement.selected_mode,
            phases=initialize_phases(),
        )
        context: dict[str, Any]
        if existing is not None:
            run.resume_count += 1
            seen_incomplete = False
            for phase_record in run.phases:
                if phase_record.status == "completed":
                    if seen_incomplete:
                        raise RuntimeError("run contains a non-contiguous completed phase ledger")
                    continue
                seen_incomplete = True
                phase_record.status = "pending"
                phase_record.started_at = None
                phase_record.completed_at = None
                phase_record.output_artifacts = []
                phase_record.receipt_id = None
                phase_record.error = None
            context = self._load_resume_context(run)
        else:
            context = {}
        self.service.save_run(run)
        self.service.audit(
            "hunt.resumed" if existing is not None else "hunt.started",
            "coordinator",
            engagement_id=engagement.engagement_id,
            run_id=run.run_id,
            details={"resume_count": run.resume_count, "strategy": "validated-phase-context-snapshot"},
        )
        artifacts_dir = self.service.paths.runs / run.run_id / "artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        for phase in PhaseName:
            record = next(item for item in run.phases if item.name is phase)
            if record.status == "completed":
                continue
            start_phase(run, phase)
            self.service.save_run(run)
            phase_started = perf_counter()
            try:
                outputs = await self._execute_phase(phase, engagement, run, artifacts_dir, context)
                context_path = self._save_context_snapshot(run, phase, context)
                outputs.append(str(context_path))
            except Exception as exc:
                cost_path = self._record_phase_cost(run, phase, context, phase_started, status="failed")
                block_phase(run, phase, f"{type(exc).__name__}: {exc}")
                record.output_artifacts = [str(cost_path)]
                self.service.save_run(run)
                self.service.audit(
                    "phase.blocked",
                    "coordinator",
                    engagement_id=engagement.engagement_id,
                    run_id=run.run_id,
                    details={"phase": phase.value, "error_type": type(exc).__name__},
                )
                raise
            cost_path = self._record_phase_cost(run, phase, context, phase_started, status="completed")
            outputs.append(str(cost_path))
            receipt_id = new_id("phase-receipt")
            receipt_path = artifacts_dir / "phase-receipts" / f"{phase.value}.json"
            atomic_write_json(
                receipt_path,
                {
                    "receipt_id": receipt_id,
                    "phase": phase.value,
                    "run_id": run.run_id,
                    "observed_artifacts": outputs,
                    "context_snapshot": {
                        "path": str(context_path),
                        "sha256": sha256_file(context_path),
                    },
                    "status": "completed",
                },
            )
            outputs.append(str(receipt_path))
            complete_phase(run, phase, outputs, receipt_id)
            self.service.save_run(run)
            self.service.audit(
                "phase.completed",
                "coordinator",
                engagement_id=engagement.engagement_id,
                run_id=run.run_id,
                details={"phase": phase.value, "artifacts": outputs},
            )
            if stop_after is phase and phase is not tuple(PhaseName)[-1]:
                run.status = "interrupted"
                self.service.save_run(run)
                self.service.audit(
                    "hunt.interrupted",
                    "coordinator",
                    engagement_id=engagement.engagement_id,
                    run_id=run.run_id,
                    details={"completed_through": phase.value},
                )
                return HuntResult(run=run)
        valid = context.get("valid_finding")
        killed = context.get("killed_finding")
        report = context.get("report")
        self.service.audit(
            "hunt.completed",
            "coordinator",
            engagement_id=engagement.engagement_id,
            run_id=run.run_id,
        )
        return HuntResult(
            run=run,
            confirmed_finding_id=valid.finding_id if isinstance(valid, Finding) else None,
            killed_finding_id=killed.finding_id if isinstance(killed, Finding) else None,
            report_markdown=str(report["markdown"]) if isinstance(report, dict) else None,
            report_html=str(report["html"]) if isinstance(report, dict) else None,
        )

    def _record_phase_cost(
        self,
        run: Run,
        phase: PhaseName,
        context: dict[str, Any],
        started: float,
        *,
        status: str,
    ) -> Path:
        finding = context.get("valid_finding")
        cost = CostRecord(
            cost_id=new_id("cost"),
            run_id=run.run_id,
            phase=phase,
            candidate_id=finding.finding_id if isinstance(finding, Finding) else None,
            model="local-deterministic",
            input_tokens=0,
            output_tokens=0,
            cached_input_tokens=0,
            elapsed_ms=max(0, round((perf_counter() - started) * 1000)),
            estimated_cost_usd=0.0,
        )
        self.service.save_cost(cost)
        record = next(item for item in run.phases if item.name is phase)
        path = (
            self.service.paths.runs
            / run.run_id
            / "artifacts"
            / "costs"
            / f"{phase.value}-attempt-{record.attempt}.json"
        )
        atomic_write_json(path, {"status": status, "cost": cost.model_dump(mode="json")})
        return path

    @staticmethod
    def _rank_with_advisory(
        hypotheses: list[Hypothesis], advisory: dict[str, Any] | None
    ) -> tuple[list[Hypothesis], bool]:
        ranked_ids = advisory.get("ranked_hypothesis_ids") if isinstance(advisory, dict) else None
        expected_ids = [item.hypothesis_id for item in hypotheses]
        if not (
            isinstance(ranked_ids, list)
            and all(isinstance(item, str) for item in ranked_ids)
            and len(ranked_ids) == len(expected_ids)
            and set(ranked_ids) == set(expected_ids)
        ):
            return hypotheses, False
        by_id = {item.hypothesis_id: item for item in hypotheses}
        return [by_id[item] for item in ranked_ids], True

    @staticmethod
    def _apply_advisory_veto(critique: Critique, advisory: dict[str, Any] | None) -> Critique:
        if critique.verdict is not CriticVerdict.CONFIRMED or not isinstance(advisory, dict):
            return critique
        try:
            advisory_verdict = CriticVerdict(str(advisory.get("verdict", "")).upper())
        except ValueError:
            return critique
        if advisory_verdict not in {CriticVerdict.HOLD, CriticVerdict.KILL}:
            return critique
        raw_confidence = advisory.get("confidence")
        advisory_confidence = critique.confidence
        if isinstance(raw_confidence, int | float) and not isinstance(raw_confidence, bool):
            advisory_confidence = min(1.0, max(0.0, float(raw_confidence)))
        rationale = redact_text(str(advisory.get("rationale", "")))
        return critique.model_copy(
            update={
                "verdict": advisory_verdict,
                "confidence": min(critique.confidence, advisory_confidence),
                "rationale": (
                    "Independent Codex critic vetoed deterministic confirmation. "
                    + (rationale or "Additional validation is required.")[:1000]
                ),
                "additional_tests_needed": [
                    *critique.additional_tests_needed,
                    "Resolve the independent critic veto before reporting.",
                ],
                "strongest_opposing_evidence": [
                    *critique.strongest_opposing_evidence,
                    "Independent advisory identified an unresolved objection.",
                ],
            }
        )

    @staticmethod
    def _agent_output_schema(task_class: str) -> dict[str, object]:
        if task_class == "analysis":
            properties: dict[str, object] = {
                "ranked_hypothesis_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "uniqueItems": True,
                },
                "rationale": {"type": "string", "maxLength": 2000},
            }
            required = ["ranked_hypothesis_ids", "rationale"]
        elif task_class == "critical_judgment":
            properties = {
                "verdict": {"type": "string", "enum": ["CONFIRMED", "HOLD", "KILL"]},
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "rationale": {"type": "string", "maxLength": 4000},
            }
            required = ["verdict", "confidence", "rationale"]
        else:
            raise ValueError(f"unsupported agent output schema task class: {task_class}")
        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": False,
            "properties": properties,
            "required": required,
        }

    def _write_agent_advisory(
        self,
        run: Run,
        phase: PhaseName,
        context: dict[str, Any],
        payload: dict[str, Any],
    ) -> Path:
        advisory_path = self.service.paths.runs / run.run_id / "artifacts" / "agent-advisories" / f"{phase.value}.json"
        atomic_write_json(advisory_path, payload)
        advisories = context.setdefault("agent_advisories", {})
        if not isinstance(advisories, dict):
            raise RuntimeError("agent advisory context is invalid")
        advisories[phase.value] = str(advisory_path)
        return advisory_path

    async def _agent_advisory(
        self,
        *,
        task_class: str,
        task_instruction: str,
        untrusted_payload: object,
        run: Run,
        phase: PhaseName,
        context: dict[str, Any],
        candidate_id: str | None = None,
    ) -> dict[str, Any] | None:
        if self.agent_mode != "codex" or self.model_router is None or self.agent_runner is None:
            return None
        selection = self.model_router.select(task_class, profile=self.model_profile)
        summary = redact_text(json.dumps(untrusted_payload, ensure_ascii=False, sort_keys=True, default=str)) or ""
        cache_material = json.dumps(
            {
                "task_class": task_class,
                "task_instruction": task_instruction,
                "summary": summary,
                "candidate_id": candidate_id,
                "profile": selection.profile,
                "candidates": selection.candidates,
                "reasoning_effort": selection.reasoning_effort,
            },
            ensure_ascii=False,
            sort_keys=True,
        ).encode("utf-8")
        cache_key = sha256_bytes(cache_material)
        cache_path = self.service.paths.runs / run.run_id / "artifacts" / "agent-cache" / f"{cache_key}.json"
        if cache_path.is_file() and not cache_path.is_symlink() and cache_path.stat().st_size <= 2 * 1024 * 1024:
            try:
                cached = json.loads(cache_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                cached = None
            cached_output = cached.get("parsed_output") if isinstance(cached, dict) else None
            if (
                isinstance(cached_output, dict)
                and cached.get("status") == "PASS"
                and cached.get("cache_key") == cache_key
                and cached.get("task_class") == task_class
            ):
                self._write_agent_advisory(
                    run,
                    phase,
                    context,
                    {
                        "status": "CACHE_HIT",
                        "task_class": task_class,
                        "cache_key": cache_key,
                        "cache_source": str(cache_path),
                        "parsed_output": cached_output,
                    },
                )
                return cached_output
        engagement_budget = self._engagement_token_budget()
        spent_tokens = sum(
            item.input_tokens + item.output_tokens for item in self.service.list_costs(run_id=run.run_id)
        )
        remaining_tokens = max(0, engagement_budget - spent_tokens)
        if remaining_tokens == 0:
            budget_payload: dict[str, Any] = {
                "status": "BUDGET_EXHAUSTED",
                "reason": "engagement token budget was exhausted before this advisory",
                "task_class": task_class,
                "cache_key": cache_key,
                "budget": {
                    "engagement_token_budget": engagement_budget,
                    "spent_tokens": spent_tokens,
                    "remaining_tokens": 0,
                },
            }
            self._write_agent_advisory(run, phase, context, budget_payload)
            return None
        selection = replace(selection, token_budget=min(selection.token_budget, remaining_tokens))
        try:
            result, cost = await self.agent_runner.run(
                selection,
                task_instruction=task_instruction,
                untrusted_target_summary=summary,
                run_id=run.run_id,
                phase=phase,
                candidate_id=candidate_id,
                output_schema=self._agent_output_schema(task_class),
            )
        except RuntimeError as exc:
            payload: dict[str, Any] = {
                "status": "DEGRADED",
                "reason": "configured Codex advisory was unavailable",
                "error": (redact_text(str(exc)) or "agent advisory failed")[-500:],
                "task_class": task_class,
                "cache_key": cache_key,
                "budget": {
                    "engagement_token_budget": engagement_budget,
                    "spent_before_call": spent_tokens,
                    "call_token_budget": selection.token_budget,
                },
            }
            parsed = None
        else:
            self.service.save_cost(cost)
            if result.thread_id and result.thread_id not in run.codex_thread_ids:
                run.codex_thread_ids.append(result.thread_id)
                self.service.save_run(run)
            try:
                decoded = json.loads(redact_text(result.output) or "")
            except json.JSONDecodeError:
                decoded = None
            actual_tokens = result.input_tokens + result.output_tokens
            within_budget = actual_tokens <= selection.token_budget
            parsed = decoded if isinstance(decoded, dict) and within_budget else None
            payload = {
                "status": (
                    "PASS" if parsed is not None else "BUDGET_EXCEEDED" if not within_budget else "INVALID_OUTPUT"
                ),
                "model": result.model,
                "task_class": task_class,
                "cache_key": cache_key,
                "thread_id": result.thread_id,
                "usage": {
                    "input_tokens": result.input_tokens,
                    "output_tokens": result.output_tokens,
                    "cached_input_tokens": result.cached_input_tokens,
                },
                "events_path": result.events_path,
                "parsed_output": parsed,
                "cost_record": cost.model_dump(mode="json"),
                "budget": {
                    "engagement_token_budget": engagement_budget,
                    "spent_before_call": spent_tokens,
                    "call_token_budget": selection.token_budget,
                    "actual_call_tokens": actual_tokens,
                    "remaining_after_call": max(0, remaining_tokens - actual_tokens),
                },
            }
        self._write_agent_advisory(run, phase, context, payload)
        if payload.get("status") == "PASS":
            atomic_write_json(cache_path, payload)
        return parsed

    def _save_context_snapshot(self, run: Run, phase: PhaseName, context: dict[str, Any]) -> Path:
        known = {
            "exchanges",
            "browser_artifacts",
            "traffic_model",
            "invariants",
            "hypotheses",
            "valid_finding",
            "killed_finding",
            "valid_controls",
            "killed_controls",
            "builder",
            "valid_pack",
            "killed_pack",
            "report",
            "source_scan",
            "source_inventory",
            "validation_plans",
            "validation_exchanges",
            "agent_advisories",
        }
        unexpected = set(context) - known
        if unexpected:
            raise RuntimeError(f"hunt context contains unsupported keys: {sorted(unexpected)}")

        payload: dict[str, object] = {}
        list_models: dict[str, type[BudoModel]] = {
            "exchanges": HttpExchange,
            "invariants": SecurityInvariant,
            "hypotheses": Hypothesis,
            "valid_controls": ControlExperiment,
            "killed_controls": ControlExperiment,
            "validation_plans": ValidationPlan,
            "validation_exchanges": HttpExchange,
        }
        for key, model in list_models.items():
            value = context.get(key)
            if value is None:
                continue
            if not isinstance(value, list) or not all(isinstance(item, model) for item in value):
                raise RuntimeError(f"hunt context {key} is not a typed list")
            payload[key] = [item.model_dump(mode="json") for item in value]
        for key in ("valid_finding", "killed_finding"):
            value = context.get(key)
            if value is not None:
                if not isinstance(value, Finding):
                    raise RuntimeError(f"hunt context {key} is not a Finding")
                payload[key] = value.model_dump(mode="json")
        for key in ("browser_artifacts",):
            value = context.get(key)
            if value is not None:
                if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                    raise RuntimeError(f"hunt context {key} is not a string list")
                payload[key] = value
        for key in ("valid_pack", "killed_pack"):
            value = context.get(key)
            if value is not None:
                if not isinstance(value, (str, Path)):
                    raise RuntimeError(f"hunt context {key} is not a path")
                payload[key] = str(value)
        for key in ("source_scan", "source_inventory", "report", "agent_advisories"):
            value = context.get(key)
            if value is not None:
                if not isinstance(value, dict):
                    raise RuntimeError(f"hunt context {key} is not an object")
                payload[key] = value
        traffic_model = context.get("traffic_model")
        if traffic_model is not None:
            if not isinstance(traffic_model, TrafficModel):
                raise RuntimeError("hunt context traffic_model is not typed")
            payload["traffic_model"] = traffic_model.as_dict()

        path = self.service.paths.runs / run.run_id / "artifacts" / "context" / f"{phase.value}.json"
        atomic_write_json(
            path,
            {
                "schema_version": 1,
                "run_id": run.run_id,
                "phase": phase.value,
                "context": payload,
            },
        )
        return path

    def _load_resume_context(self, run: Run) -> dict[str, Any]:
        completed = [record for record in run.phases if record.status == "completed"]
        if not completed:
            return {}
        phase = completed[-1].name
        path = self.service.paths.runs / run.run_id / "artifacts" / "context" / f"{phase.value}.json"
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"cannot safely resume without a valid context snapshot: {path}") from exc
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema_version") != 1
            or envelope.get("run_id") != run.run_id
            or envelope.get("phase") != phase.value
            or not isinstance(envelope.get("context"), dict)
        ):
            raise RuntimeError("resume context snapshot identity/schema mismatch")
        payload = envelope["context"]
        receipt_path = self.service.paths.runs / run.run_id / "artifacts" / "phase-receipts" / f"{phase.value}.json"
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("resume phase receipt is missing or invalid") from exc
        snapshot = receipt.get("context_snapshot") if isinstance(receipt, dict) else None
        if (
            not isinstance(snapshot, dict)
            or receipt.get("receipt_id") != completed[-1].receipt_id
            or receipt.get("run_id") != run.run_id
            or receipt.get("phase") != phase.value
            or snapshot.get("path") != str(path)
            or snapshot.get("sha256") != sha256_file(path)
        ):
            raise RuntimeError("resume context snapshot does not match its completed phase receipt")
        context: dict[str, Any] = {}
        list_models: dict[str, type[BudoModel]] = {
            "exchanges": HttpExchange,
            "invariants": SecurityInvariant,
            "hypotheses": Hypothesis,
            "valid_controls": ControlExperiment,
            "killed_controls": ControlExperiment,
            "validation_plans": ValidationPlan,
            "validation_exchanges": HttpExchange,
        }
        try:
            for key, model in list_models.items():
                if key in payload:
                    value = payload[key]
                    if not isinstance(value, list):
                        raise ValueError(f"{key} is not a list")
                    context[key] = [model.model_validate(item) for item in value]
            for key in ("valid_finding", "killed_finding"):
                if key in payload:
                    context[key] = Finding.model_validate(payload[key])
            allowed_keys = {
                *list_models,
                "valid_finding",
                "killed_finding",
                "browser_artifacts",
                "valid_pack",
                "killed_pack",
                "source_scan",
                "source_inventory",
                "report",
                "traffic_model",
                "agent_advisories",
            }
            if set(payload) - allowed_keys:
                raise ValueError("context snapshot contains unknown fields")
            if "browser_artifacts" in payload:
                value = payload["browser_artifacts"]
                if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                    raise ValueError("browser_artifacts is not a string list")
                run_root = (self.service.paths.runs / run.run_id).resolve()
                if any(not Path(item).resolve().is_relative_to(run_root) for item in value):
                    raise ValueError("browser artifact escapes the active run")
                context["browser_artifacts"] = value
            for key in ("valid_pack", "killed_pack"):
                if key in payload:
                    value = payload[key]
                    if not isinstance(value, str):
                        raise ValueError(f"{key} is not a path string")
                    pack = Path(value).resolve()
                    if not pack.is_relative_to(self.service.paths.findings.resolve()):
                        raise ValueError(f"{key} escapes the findings root")
                    context[key] = pack
            for key in ("source_scan", "source_inventory", "report"):
                if key in payload:
                    value = payload[key]
                    if not isinstance(value, dict):
                        raise ValueError(f"{key} is not an object")
                    context[key] = value
            if "agent_advisories" in payload:
                value = payload["agent_advisories"]
                run_root = (self.service.paths.runs / run.run_id).resolve()
                if (
                    not isinstance(value, dict)
                    or not all(isinstance(key, str) and isinstance(item, str) for key, item in value.items())
                    or any(not Path(item).resolve().is_relative_to(run_root) for item in value.values())
                ):
                    raise ValueError("agent advisory paths are invalid")
                context["agent_advisories"] = value
            if "traffic_model" in payload:
                context["traffic_model"] = self._load_traffic_model(payload["traffic_model"])
        except (TypeError, ValueError) as exc:
            raise RuntimeError("resume context snapshot failed typed validation") from exc
        return context

    @staticmethod
    def _load_traffic_model(payload: object) -> TrafficModel:
        if not isinstance(payload, dict):
            raise ValueError("traffic model is not an object")
        families_value = payload.get("endpoint_families")
        parameters_value = payload.get("parameters")
        objects_value = payload.get("objects")
        differences_value = payload.get("account_differences")
        roles_value = payload.get("roles", [])
        tenants_value = payload.get("tenants", [])
        transitions_value = payload.get("state_transitions", [])
        response_schemas_value = payload.get("response_schemas", {})
        frontend_links_value = payload.get("frontend_api_links", [])
        schema_clues_value = payload.get("api_schema_clues", [])
        historical_urls_value = payload.get("historical_urls", [])
        discarded_static_value = payload.get("discarded_static_exchange_ids", [])
        if (
            not isinstance(families_value, list)
            or not isinstance(parameters_value, dict)
            or not isinstance(objects_value, list)
            or not isinstance(differences_value, list)
            or not isinstance(roles_value, list)
            or not isinstance(tenants_value, list)
            or not isinstance(transitions_value, list)
            or not isinstance(response_schemas_value, dict)
            or not isinstance(frontend_links_value, list)
            or not isinstance(schema_clues_value, list)
            or not isinstance(historical_urls_value, list)
            or not isinstance(discarded_static_value, list)
            or not all(isinstance(item, dict) for item in differences_value)
            or not all(isinstance(item, dict) for item in frontend_links_value)
            or not all(isinstance(item, dict) for item in schema_clues_value)
            or not all(isinstance(item, str) for item in historical_urls_value)
            or not all(isinstance(item, str) for item in discarded_static_value)
            or not all(isinstance(item, dict) for item in response_schemas_value.values())
            or not all(isinstance(value, list) for value in parameters_value.values())
        ):
            raise ValueError("traffic model fields are invalid")
        return TrafficModel(
            endpoint_families=[EndpointFamily.model_validate(item) for item in families_value],
            parameters={
                str(key): [Parameter.model_validate(item) for item in value] for key, value in parameters_value.items()
            },
            objects=[ObjectReference.model_validate(item) for item in objects_value],
            account_differences=[dict(item) for item in differences_value],
            roles=[Role.model_validate(item) for item in roles_value],
            tenants=[Tenant.model_validate(item) for item in tenants_value],
            state_transitions=[StateTransition.model_validate(item) for item in transitions_value],
            response_schemas={str(key): dict(value) for key, value in response_schemas_value.items()},
            frontend_api_links=[{str(key): str(value) for key, value in item.items()} for item in frontend_links_value],
            api_schema_clues=[{str(key): str(value) for key, value in item.items()} for item in schema_clues_value],
            historical_urls=list(historical_urls_value),
            discarded_static_exchange_ids=list(discarded_static_value),
        )

    async def _execute_phase(
        self,
        phase: PhaseName,
        engagement: Engagement,
        run: Run,
        artifacts_dir: Path,
        context: dict[str, Any],
    ) -> list[str]:
        if engagement.selected_mode is not EngagementMode.LAB:
            return await self._execute_nonlab_phase(phase, engagement, run, artifacts_dir, context)
        phase_path = artifacts_dir / f"{phase.value.lower()}.json"
        if phase is PhaseName.INIT:
            atomic_write_json(phase_path, {"mode": engagement.selected_mode.value, "authorized": True})
        elif phase is PhaseName.TASK_MODEL:
            atomic_write_json(phase_path, engagement.model_dump(mode="json"))
        elif phase is PhaseName.PASSIVE_RECON:
            atomic_write_json(
                phase_path,
                {"targets": [item.uri for item in engagement.root_targets], "network_calls": 0},
            )
        elif phase is PhaseName.SURFACE_MAP:
            atomic_write_json(
                phase_path,
                {
                    "fixture_routes": [
                        "/api/objects/{id}",
                        "/api/secure-objects/{id}",
                        "/api/public/{id}",
                        "/api/files/{id}",
                        "/api/workflows/{id}/transition",
                        "/preview",
                    ]
                },
            )
        elif phase is PhaseName.NORMAL_BROWSER_EXPLORATION:
            browser_root = artifacts_dir / "browser"
            browser = BrowserSessionManager(browser_root, engagement)
            browser_artifacts: list[str] = []
            try:
                for alias in ("alice", "bob"):
                    page = await browser.open(
                        alias,
                        f"{engagement.root_targets[0].uri.rstrip('/')}/preview?value={alias}-fixture",
                    )
                    screenshot = await browser.screenshot(alias, page, "normal-preview")
                    browser_artifacts.append(str(screenshot))
                    await page.close()
            finally:
                await browser.stop()
            for alias in ("alice", "bob"):
                account_root = browser_root / alias
                browser_artifacts.extend(
                    str(path)
                    for path in (
                        account_root / "traffic.har",
                        account_root / "trace.zip",
                        account_root / "steps.jsonl",
                    )
                    if path.is_file()
                )
                for pattern in ("dom/*.html", "screenshots/*.metadata.json"):
                    browser_artifacts.extend(str(path) for path in sorted(account_root.glob(pattern)) if path.is_file())
            exchanges = await self._capture_fixture_traffic(engagement)
            context["exchanges"] = exchanges
            context["browser_artifacts"] = browser_artifacts
            atomic_write_json(
                phase_path,
                {
                    "browser_artifacts": browser_artifacts,
                    "proxy_exchanges": [item.model_dump(mode="json") for item in exchanges],
                },
            )
        elif phase is PhaseName.TRAFFIC_MODEL:
            exchanges = self._exchanges(context)
            model = build_traffic_model(exchanges)
            context["traffic_model"] = model
            atomic_write_json(phase_path, model.as_dict())
        elif phase is PhaseName.INVARIANT_MODEL:
            model = context["traffic_model"]
            invariants, hypotheses = generate_hypotheses(engagement.engagement_id, model)
            context["invariants"] = invariants
            context["hypotheses"] = hypotheses
            atomic_write_json(phase_path, {"invariants": [item.model_dump(mode="json") for item in invariants]})
        elif phase is PhaseName.HYPOTHESIS_GENERATION:
            hypotheses = context["hypotheses"]
            atomic_write_json(phase_path, [item.model_dump(mode="json") for item in hypotheses])
        elif phase is PhaseName.PRIORITIZATION:
            hypotheses = context["hypotheses"]
            atomic_write_json(
                phase_path,
                {
                    "ordered_ids": [item.hypothesis_id for item in hypotheses],
                    "method": "deterministic priority",
                },
            )
        elif phase is PhaseName.VALIDATION:
            valid, killed, valid_controls, killed_controls = self._make_findings(engagement, self._exchanges(context))
            valid.screenshots = [
                item for item in context.get("browser_artifacts", []) if str(item).lower().endswith(".png")
            ]
            context.update(
                valid_finding=valid,
                killed_finding=killed,
                valid_controls=valid_controls,
                killed_controls=killed_controls,
            )
            atomic_write_json(
                phase_path,
                {
                    "valid_candidate": valid.finding_id,
                    "public_control_candidate": killed.finding_id,
                },
            )
        elif phase is PhaseName.NEGATIVE_CONTROL:
            controls = [*context["valid_controls"], *context["killed_controls"]]
            atomic_write_json(phase_path, [item.model_dump(mode="json") for item in controls])
        elif phase is PhaseName.REFUTATION:
            atomic_write_json(
                phase_path,
                {
                    "private_candidate": (
                        "anonymous denial and secure endpoint owner denial do not explain cross-account success"
                    ),
                    "public_candidate": "documented anonymous access establishes intentional public design",
                },
            )
        elif phase is PhaseName.EVIDENCE_PACK:
            builder = EvidencePackBuilder(self.service.paths.findings)
            valid = context["valid_finding"]
            killed = context["killed_finding"]
            assert isinstance(valid, Finding)
            assert isinstance(killed, Finding)
            browser_artifact_paths = [Path(item) for item in context.get("browser_artifacts", [])]
            valid_pack = builder.build(
                valid,
                self._exchanges(context)[:5],
                context["valid_controls"],
                browser_artifacts=browser_artifact_paths,
            )
            killed_pack = builder.build(killed, self._exchanges(context)[5:], context["killed_controls"])
            context.update(builder=builder, valid_pack=valid_pack, killed_pack=killed_pack)
            atomic_write_json(phase_path, {"packs": [str(valid_pack), str(killed_pack)]})
        elif phase is PhaseName.INDEPENDENT_CRITIC:
            gate = EvidenceGate()
            critic = AdversarialCritic()
            valid = context["valid_finding"]
            killed = context["killed_finding"]
            assert isinstance(valid, Finding)
            assert isinstance(killed, Finding)
            valid_pre = gate.evaluate(valid, context["valid_pack"], require_critic=False)
            killed_pre = gate.evaluate(killed, context["killed_pack"], require_critic=False)
            valid_critique = critic.review(valid, valid_pre)
            killed_critique = critic.review(killed, killed_pre)
            if valid_critique.verdict is not CriticVerdict.CONFIRMED:
                raise RuntimeError(f"fixture vulnerability was not confirmed: {valid_critique.rationale}")
            if killed_critique.verdict is not CriticVerdict.KILL:
                raise RuntimeError(f"public false candidate was not killed: {killed_critique.rationale}")
            valid.critic_verdict = CriticVerdict.CONFIRMED
            valid.status = CandidateStatus.READY_FOR_HUMAN_REVIEW
            valid.reportability = "submission-ready"
            valid.human_review_status = "pending"
            killed.critic_verdict = CriticVerdict.KILL
            killed.status = CandidateStatus.KILL
            restored_builder = context.get("builder")
            if not isinstance(restored_builder, EvidencePackBuilder):
                restored_builder = EvidencePackBuilder(self.service.paths.findings)
                context["builder"] = restored_builder
            restored_builder.build(
                valid,
                self._exchanges(context)[:5],
                context["valid_controls"],
                critique=valid_critique,
                browser_artifacts=[Path(item) for item in context.get("browser_artifacts", [])],
            )
            restored_builder.build(
                killed,
                self._exchanges(context)[5:],
                context["killed_controls"],
                critique=killed_critique,
            )
            final_receipt = gate.evaluate(valid, context["valid_pack"], require_critic=True)
            if not final_receipt.passed:
                raise RuntimeError("confirmed fixture finding failed final evidence gates")
            valid.gate_receipt_path = str(Path(context["valid_pack"]) / "gate-receipt.json")
            self._write_finding_manifest(Path(context["valid_pack"]), valid)
            self._write_finding_manifest(Path(context["killed_pack"]), killed)
            self.service.save_finding(valid)
            self.service.save_finding(killed)
            atomic_write_json(
                phase_path,
                {
                    "confirmed": valid_critique.model_dump(mode="json"),
                    "killed": killed_critique.model_dump(mode="json"),
                },
            )
        elif phase is PhaseName.REPORT_DRAFT:
            valid = context["valid_finding"]
            assert isinstance(valid, Finding)
            template_root = Path(__file__).parents[1] / "reporting" / "templates"
            report = ReportGenerator(template_root).generate(
                valid,
                Path(context["valid_pack"]),
                vendor=engagement.vendor,
                engagement_platform=engagement.platform,
            )
            self.service.store.save("report", report.report_id, report)
            context["report"] = {"markdown": report.markdown_path, "html": report.html_path}
            atomic_write_json(phase_path, report.model_dump(mode="json"))
        elif phase is PhaseName.HUMAN_REVIEW_READY:
            valid = context["valid_finding"]
            killed = context["killed_finding"]
            assert isinstance(valid, Finding)
            assert isinstance(killed, Finding)
            atomic_write_json(
                phase_path,
                {
                    "submission_ready": valid.finding_id,
                    "human_submission_required": True,
                    "killed_false_candidate": killed.finding_id,
                },
            )
        else:
            atomic_write_json(phase_path, {"phase": phase.value})
        outputs = [str(phase_path)]
        if phase is PhaseName.NORMAL_BROWSER_EXPLORATION:
            outputs.extend(context.get("browser_artifacts", []))
        return outputs

    async def _execute_nonlab_phase(
        self,
        phase: PhaseName,
        engagement: Engagement,
        run: Run,
        artifacts_dir: Path,
        context: dict[str, Any],
    ) -> list[str]:
        phase_path = artifacts_dir / f"{phase.value.lower()}.json"
        mode = engagement.selected_mode
        if phase is PhaseName.INIT:
            atomic_write_json(
                phase_path,
                {
                    "mode": mode.value,
                    "authorized": True,
                    "execution_boundary": "engagement-root-only",
                },
            )
        elif phase is PhaseName.TASK_MODEL:
            atomic_write_json(phase_path, engagement.model_dump(mode="json"))
        elif phase is PhaseName.PASSIVE_RECON:
            if mode is EngagementMode.SOURCE:
                scan = await SourceScanCoordinator(self.service.paths.root, artifacts_dir).run(
                    engagement,
                    run.run_id,
                )
                context["source_scan"] = scan
                atomic_write_json(phase_path, scan)
            else:
                exchanges = self._load_imported_traffic(engagement)
                context["exchanges"] = exchanges
                atomic_write_json(
                    phase_path,
                    {
                        "root_targets": [item.uri for item in engagement.root_targets],
                        "imported_exchanges": len(exchanges),
                        "active_network_calls": 0,
                    },
                )
        elif phase is PhaseName.SURFACE_MAP:
            if mode is EngagementMode.SOURCE:
                inventory = self._source_inventory(engagement)
                context["source_inventory"] = inventory
                atomic_write_json(phase_path, inventory)
            else:
                exchanges = self._exchanges_or_empty(context)
                atomic_write_json(
                    phase_path,
                    {
                        "observed_hosts": sorted({urlsplit(item.url).netloc for item in exchanges}),
                        "observed_routes": sorted({urlsplit(item.url).path for item in exchanges}),
                        "source": "authorized imported traffic only",
                    },
                )
        elif phase is PhaseName.NORMAL_BROWSER_EXPLORATION:
            if mode is EngagementMode.SOURCE:
                atomic_write_json(phase_path, {"applicable": False, "reason": "source-only engagement"})
            else:
                browser_artifacts, exchanges = await self._program_exploration(engagement, artifacts_dir)
                combined = [*self._exchanges_or_empty(context), *exchanges]
                context["exchanges"] = self._deduplicate_exchanges(combined)
                context["browser_artifacts"] = browser_artifacts
                atomic_write_json(
                    phase_path,
                    {
                        "browser_artifacts": browser_artifacts,
                        "proxy_exchanges": [item.model_dump(mode="json") for item in context["exchanges"]],
                    },
                )
        elif phase is PhaseName.TRAFFIC_MODEL:
            model = build_traffic_model(self._exchanges_or_empty(context))
            context["traffic_model"] = model
            atomic_write_json(phase_path, model.as_dict())
        elif phase is PhaseName.INVARIANT_MODEL:
            if mode is EngagementMode.SOURCE:
                invariants, hypotheses = self._source_hypotheses(engagement, context.get("source_scan", {}))
            else:
                traffic_model_value = context.get("traffic_model")
                if not isinstance(traffic_model_value, TrafficModel):
                    raise RuntimeError("traffic model is unavailable")
                invariants, hypotheses = generate_hypotheses(engagement.engagement_id, traffic_model_value)
            context["invariants"] = invariants
            context["hypotheses"] = hypotheses
            atomic_write_json(
                phase_path,
                {"invariants": [item.model_dump(mode="json") for item in invariants]},
            )
        elif phase is PhaseName.HYPOTHESIS_GENERATION:
            hypotheses = self._hypotheses(context)
            atomic_write_json(phase_path, [item.model_dump(mode="json") for item in hypotheses])
        elif phase is PhaseName.PRIORITIZATION:
            hypotheses = sorted(self._hypotheses(context), key=lambda item: item.priority, reverse=True)
            advisory = await self._agent_advisory(
                task_class="analysis",
                task_instruction=(
                    'Return exactly one JSON object with keys "ranked_hypothesis_ids" and "rationale". '
                    "Rank every supplied hypothesis ID exactly once by authorization, business impact, "
                    "source reachability, and expected information gain. Do not add IDs or facts."
                ),
                untrusted_payload={
                    "mode": mode.value,
                    "hypotheses": [item.model_dump(mode="json") for item in hypotheses],
                },
                run=run,
                phase=phase,
                context=context,
            )
            hypotheses, advisory_applied = self._rank_with_advisory(hypotheses, advisory)
            context["hypotheses"] = hypotheses
            atomic_write_json(
                phase_path,
                {
                    "ordered_ids": [item.hypothesis_id for item in hypotheses],
                    "method": (
                        "deterministic priority with validated Codex advisory permutation"
                        if advisory_applied
                        else "deterministic authorization/business-impact/source-reachability information gain"
                    ),
                },
            )
        elif phase is PhaseName.VALIDATION:
            plans = self._validation_plans(mode, self._hypotheses(context))
            context["validation_plans"] = plans
            finding_bundle = (
                await self._validate_program_idor(engagement, context) if mode is EngagementMode.PROGRAM else None
            )
            if finding_bundle is not None:
                finding, controls, evidence_exchanges = finding_bundle
                finding.screenshots = [
                    item for item in context.get("browser_artifacts", []) if str(item).lower().endswith(".png")
                ]
                context.update(
                    valid_finding=finding,
                    valid_controls=controls,
                    validation_exchanges=evidence_exchanges,
                )
            atomic_write_json(
                phase_path,
                {
                    "plans": [item.model_dump(mode="json") for item in plans],
                    "validated_finding": (
                        context["valid_finding"].finding_id
                        if isinstance(context.get("valid_finding"), Finding)
                        else None
                    ),
                    "boundary": "GET-only single-variable replay for two self-owned accounts",
                },
            )
        elif phase is PhaseName.NEGATIVE_CONTROL:
            controls = context.get("valid_controls", [])
            atomic_write_json(
                phase_path,
                [item.model_dump(mode="json") for item in controls if isinstance(item, ControlExperiment)],
            )
        elif phase is PhaseName.REFUTATION:
            atomic_write_json(
                phase_path,
                {
                    "tested": bool(context.get("valid_finding")),
                    "required_explanations": [
                        "public or shared object",
                        "cache or mock response",
                        "same-account ownership",
                        "redirect or third-party expansion",
                    ],
                },
            )
        elif phase is PhaseName.EVIDENCE_PACK:
            pack_finding_value = context.get("valid_finding")
            if isinstance(pack_finding_value, Finding):
                builder = EvidencePackBuilder(self.service.paths.findings)
                pack = builder.build(
                    pack_finding_value,
                    self._validation_exchanges(context),
                    context["valid_controls"],
                    browser_artifacts=[Path(item) for item in context.get("browser_artifacts", [])],
                )
                context.update(builder=builder, valid_pack=pack)
                atomic_write_json(phase_path, {"packs": [str(pack)]})
            else:
                atomic_write_json(
                    phase_path,
                    {"packs": [], "reason": "no candidate has artifact-backed validation evidence"},
                )
        elif phase is PhaseName.INDEPENDENT_CRITIC:
            critic_finding_value = context.get("valid_finding")
            if isinstance(critic_finding_value, Finding):
                pack = Path(context["valid_pack"])
                gate = EvidenceGate()
                precritic = gate.evaluate(critic_finding_value, pack, require_critic=False)
                critique = AdversarialCritic().review(critic_finding_value, precritic)
                advisory = await self._agent_advisory(
                    task_class="critical_judgment",
                    task_instruction=(
                        'Return exactly one JSON object with keys "verdict", "confidence", and "rationale". '
                        "The verdict must be CONFIRMED, HOLD, or KILL. Try to falsify the candidate using only "
                        "the supplied finding, gate receipt, and deterministic critique. Missing evidence requires "
                        "HOLD; intentional public behavior or no capability delta requires KILL."
                    ),
                    untrusted_payload={
                        "finding": critic_finding_value.model_dump(mode="json"),
                        "precritic_gate": precritic.model_dump(mode="json"),
                        "deterministic_critique": critique.model_dump(mode="json"),
                    },
                    run=run,
                    phase=phase,
                    context=context,
                    candidate_id=critic_finding_value.finding_id,
                )
                critique = self._apply_advisory_veto(critique, advisory)
                if critique.verdict is CriticVerdict.CONFIRMED:
                    critic_finding_value.critic_verdict = CriticVerdict.CONFIRMED
                    critic_finding_value.status = CandidateStatus.READY_FOR_HUMAN_REVIEW
                    critic_finding_value.reportability = "submission-ready"
                    critic_finding_value.human_review_status = "pending"
                else:
                    critic_finding_value.critic_verdict = critique.verdict
                    critic_finding_value.status = (
                        CandidateStatus.HOLD if critique.verdict is CriticVerdict.HOLD else CandidateStatus.KILL
                    )
                    critic_finding_value.reportability = "hold"
                restored_builder = context.get("builder")
                if not isinstance(restored_builder, EvidencePackBuilder):
                    restored_builder = EvidencePackBuilder(self.service.paths.findings)
                    context["builder"] = restored_builder
                restored_builder.build(
                    critic_finding_value,
                    self._validation_exchanges(context),
                    context["valid_controls"],
                    critique=critique,
                    browser_artifacts=[Path(item) for item in context.get("browser_artifacts", [])],
                )
                final_gate = gate.evaluate(critic_finding_value, pack, require_critic=True)
                if critic_finding_value.critic_verdict is CriticVerdict.CONFIRMED and not final_gate.passed:
                    raise RuntimeError("critic-confirmed program finding failed final evidence gates")
                critic_finding_value.gate_receipt_path = str(pack / "gate-receipt.json")
                self._write_finding_manifest(pack, critic_finding_value)
                self.service.save_finding(critic_finding_value)
                atomic_write_json(phase_path, critique.model_dump(mode="json"))
            else:
                atomic_write_json(
                    phase_path,
                    {
                        "verdict": "HOLD",
                        "reason": "scanner/hypothesis output is not vulnerability evidence",
                    },
                )
        elif phase is PhaseName.REPORT_DRAFT:
            report_finding = context.get("valid_finding")
            if isinstance(report_finding, Finding) and report_finding.is_submission_ready:
                template_root = Path(__file__).parents[1] / "reporting" / "templates"
                report = ReportGenerator(template_root).generate(
                    report_finding,
                    Path(context["valid_pack"]),
                    vendor=engagement.vendor,
                    engagement_platform=engagement.platform,
                )
                self.service.store.save("report", report.report_id, report)
                context["report"] = {"markdown": report.markdown_path, "html": report.html_path}
                atomic_write_json(phase_path, report.model_dump(mode="json"))
            else:
                atomic_write_json(
                    phase_path,
                    {"submission_ready": False, "reason": "no critic-confirmed finding"},
                )
        elif phase is PhaseName.HUMAN_REVIEW_READY:
            ready_finding = context.get("valid_finding")
            atomic_write_json(
                phase_path,
                {
                    "submission_ready": ready_finding.finding_id
                    if isinstance(ready_finding, Finding) and ready_finding.is_submission_ready
                    else None,
                    "human_submission_required": True,
                    "unresolved_hypotheses": [item.hypothesis_id for item in self._hypotheses(context)],
                },
            )
        else:
            atomic_write_json(phase_path, {"phase": phase.value})
        outputs = [str(phase_path)]
        if phase is PhaseName.NORMAL_BROWSER_EXPLORATION:
            outputs.extend(context.get("browser_artifacts", []))
        if phase is PhaseName.PASSIVE_RECON and mode is EngagementMode.SOURCE:
            source_summary = artifacts_dir / "source-scan-summary.json"
            if source_summary.is_file():
                outputs.append(str(source_summary))
        advisories = context.get("agent_advisories")
        if isinstance(advisories, dict):
            advisory_path = advisories.get(phase.value)
            if isinstance(advisory_path, str):
                outputs.append(advisory_path)
        return outputs

    def _load_imported_traffic(self, engagement: Engagement) -> list[HttpExchange]:
        directory = self.service.paths.runtime_home / "imports" / engagement.engagement_id
        exchanges: list[HttpExchange] = []
        if not directory.is_dir():
            return exchanges
        for path in sorted(directory.glob("*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"invalid imported traffic artifact: {path.name}") from exc
            if not isinstance(payload, list):
                raise RuntimeError(f"imported traffic must be a list: {path.name}")
            for item in payload:
                exchange = HttpExchange.model_validate(item)
                if exchange.engagement_id != engagement.engagement_id:
                    raise RuntimeError(f"imported exchange has the wrong engagement: {exchange.exchange_id}")
                require_allowed(target_allowed(engagement, exchange.url))
                exchanges.append(exchange)
        return self._deduplicate_exchanges(exchanges)

    async def _program_exploration(
        self,
        engagement: Engagement,
        artifacts_dir: Path,
    ) -> tuple[list[str], list[HttpExchange]]:
        browser_root = artifacts_dir / "browser"
        browser = BrowserSessionManager(browser_root, engagement)
        browser_artifacts: list[str] = []
        direct = DirectProxyBackend(timeout=20)
        exchanges: list[HttpExchange] = []
        try:
            for index, target in enumerate(engagement.root_targets, start=1):
                page = await browser.open("anonymous", target.uri)
                screenshot = await browser.screenshot("anonymous", page, f"root-{index}")
                browser_artifacts.append(str(screenshot))
                await page.close()
                exchanges.append(
                    await direct.send(
                        engagement,
                        "GET",
                        target.uri,
                        account_alias="anonymous",
                        source="direct",
                    )
                )
        finally:
            await browser.stop()
        account_root = browser_root / "anonymous"
        for path in (account_root / "traffic.har", account_root / "trace.zip", account_root / "steps.jsonl"):
            if path.is_file():
                browser_artifacts.append(str(path))
        for pattern in ("dom/*.html", "screenshots/*.metadata.json"):
            browser_artifacts.extend(str(path) for path in sorted(account_root.glob(pattern)) if path.is_file())
        return browser_artifacts, exchanges

    @staticmethod
    def _source_inventory(engagement: Engagement) -> dict[str, object]:
        excluded = {".git", ".venv", ".budobugs", "node_modules", "runs", "findings", "engagements"}
        suffixes: dict[str, int] = {}
        manifests: list[str] = []
        file_count = 0
        for target in engagement.root_targets:
            root = Path(target.uri).resolve()
            for current, directories, files in os.walk(root, followlinks=False):
                directories[:] = [name for name in directories if name not in excluded]
                current_path = Path(current)
                for name in files:
                    path = current_path / name
                    if path.is_symlink():
                        continue
                    file_count += 1
                    suffix = path.suffix.lower() or "<none>"
                    suffixes[suffix] = suffixes.get(suffix, 0) + 1
                    if name.lower() in {
                        "pyproject.toml",
                        "uv.lock",
                        "package.json",
                        "pnpm-lock.yaml",
                        "requirements.txt",
                        "go.mod",
                        "cargo.toml",
                        "dockerfile",
                    }:
                        manifests.append(str(path.relative_to(root)))
        return {
            "file_count": file_count,
            "suffix_counts": dict(sorted(suffixes.items(), key=lambda item: (-item[1], item[0]))[:100]),
            "dependency_manifests": sorted(manifests),
            "symlink_directories_followed": False,
        }

    @staticmethod
    def _source_hypotheses(
        engagement: Engagement,
        scan: object,
    ) -> tuple[list[SecurityInvariant], list[Hypothesis]]:
        results = scan.get("results", []) if isinstance(scan, dict) else []
        invariants: list[SecurityInvariant] = []
        hypotheses: list[Hypothesis] = []
        for item in results if isinstance(results, list) else []:
            if not isinstance(item, dict) or not isinstance(item.get("finding_count"), int):
                continue
            count = int(item["finding_count"])
            if count <= 0:
                continue
            tool = str(item.get("tool", "source-tool"))
            invariant = SecurityInvariant(
                invariant_id=new_id("inv"),
                statement=(
                    "Source-derived security signals must be reachable and violate an explicit security boundary."
                ),
                protected_asset="authorized source and its deployed runtime",
                trust_boundary="untrusted input to privileged source/runtime behavior",
                enforcement_point=f"{tool} reported source locations",
                violation_signal=f"{count} scanner signals require source-to-sink and runtime validation",
            )
            invariants.append(invariant)
            hypotheses.append(
                Hypothesis(
                    hypothesis_id=new_id("hyp"),
                    engagement_id=engagement.engagement_id,
                    title=f"{tool} source signals require reachability review",
                    vulnerability_class="source-security-signal",
                    endpoint_family_id=f"source:{tool}",
                    invariant_id=invariant.invariant_id,
                    rationale=f"{tool} produced {count} signals; scanner output alone is not a vulnerability.",
                    attacker_prerequisites=["attacker-controlled input reaches the reported code path"],
                    proposed_single_variable_change="trace one reported source to its sink and compare a safe control",
                    expected_control="unreachable or correctly validated paths are KILLed",
                    status=CandidateStatus.HYPOTHESIS,
                    priority=min(95, 50 + count),
                )
            )
        return invariants, hypotheses

    @staticmethod
    def _validation_plans(mode: EngagementMode, hypotheses: list[Hypothesis]) -> list[ValidationPlan]:
        plans: list[ValidationPlan] = []
        for hypothesis in hypotheses:
            if mode is EngagementMode.PROGRAM:
                steps = [
                    "select two self-owned test accounts and one object per account",
                    "hold account B constant and replace only the object identifier with account A's object",
                    "repeat the cross-account GET and compare content, ownership, and response structure",
                    "run anonymous/public and own-object controls; stop on third-party data",
                ]
                mutation_scope = "GET-only, one identifier variable, no third-party expansion"
            else:
                steps = [
                    "open the scanner artifact at the exact source location",
                    "trace untrusted source to security-sensitive sink and identify enforcement",
                    "prove runtime reachability with a local non-destructive fixture",
                    "run an unreachable/validated negative control before any finding is confirmed",
                ]
                mutation_scope = "authorized local source and local runtime only"
            plans.append(
                ValidationPlan(
                    plan_id=new_id("plan"),
                    hypothesis_id=hypothesis.hypothesis_id,
                    mode=mode,
                    steps=steps,
                    mutation_scope=mutation_scope,
                    controls=[],
                    allowed_tool_names=[],
                )
            )
        return plans

    async def _validate_program_idor(
        self,
        engagement: Engagement,
        context: dict[str, Any],
    ) -> tuple[Finding, list[ControlExperiment], list[HttpExchange]] | None:
        exchanges = self._exchanges_or_empty(context)
        model = context.get("traffic_model")
        if not isinstance(model, TrafficModel) or len(engagement.testing_accounts_secret_refs) < 2:
            return None
        headers_by_alias = self._account_headers(engagement)
        if len(headers_by_alias) < 2:
            return None
        for family in model.endpoint_families:
            if family.method != "GET" or "{id}" not in family.path_template and "{uuid}" not in family.path_template:
                continue
            members = [item for item in exchanges if item.exchange_id in family.exchange_ids]
            by_alias: dict[str, HttpExchange] = {}
            for item in members:
                if item.account_alias in headers_by_alias:
                    by_alias.setdefault(str(item.account_alias), item)
            aliases = sorted(by_alias)
            if len(aliases) < 2:
                continue
            owner_alias, attacker_alias = aliases[0], aliases[1]
            owner_exchange = by_alias[owner_alias]
            attacker_exchange = by_alias[attacker_alias]
            owner_identifier = self._path_identifier(owner_exchange.url)
            if owner_identifier is None or self._path_identifier(attacker_exchange.url) == owner_identifier:
                continue
            cross_url = self._replace_path_identifier(attacker_exchange.url, owner_identifier)
            require_allowed(target_allowed(engagement, cross_url))
            backend = DirectProxyBackend(timeout=20)
            attacker_headers = headers_by_alias[attacker_alias]
            own = await backend.send(
                engagement,
                "GET",
                attacker_exchange.url,
                headers=attacker_headers,
                account_alias=attacker_alias,
                source="direct",
            )
            cross_first = await backend.send(
                engagement,
                "GET",
                cross_url,
                headers=attacker_headers,
                account_alias=attacker_alias,
                source="direct",
            )
            cross_second = await backend.send(
                engagement,
                "GET",
                cross_url,
                headers=attacker_headers,
                account_alias=attacker_alias,
                source="direct",
            )
            anonymous = await backend.send(
                engagement,
                "GET",
                cross_url,
                account_alias="anonymous",
                source="direct",
            )
            cross_repeated = (
                200 <= cross_first.response_status < 300
                and cross_second.response_status == cross_first.response_status
                and self._comparable_content(cross_first.response_body)
                == self._comparable_content(cross_second.response_body)
            )
            owner_match = self._comparable_content(cross_first.response_body) == self._comparable_content(
                owner_exchange.response_body
            )
            anonymous_denied = anonymous.response_status in {401, 403, 404} or normalized_json_structure(
                anonymous.response_body
            ) != normalized_json_structure(cross_first.response_body)
            own_is_distinct = self._comparable_content(own.response_body) != self._comparable_content(
                cross_first.response_body
            )
            if not (cross_repeated and owner_match and anonymous_denied and own_is_distinct):
                continue
            controls = [
                ControlExperiment(
                    control_id=new_id("control"),
                    kind="normal",
                    description=f"{attacker_alias} accesses its own imported test object.",
                    request_exchange_ids=[own.exchange_id],
                    observed_result=f"own-object response status {own.response_status}",
                    supports_finding=True,
                ),
                ControlExperiment(
                    control_id=new_id("control"),
                    kind="negative",
                    description="Anonymous access does not reproduce the authenticated cross-account response.",
                    request_exchange_ids=[anonymous.exchange_id],
                    observed_result=f"anonymous response status {anonymous.response_status} and content differs",
                    supports_finding=True,
                ),
            ]
            finding = Finding(
                finding_id=new_id("finding"),
                engagement_id=engagement.engagement_id,
                title=f"{family.path_template} 对象级授权缺失导致跨测试账号读取",
                vulnerability_class="IDOR/BOLA",
                affected_asset=urlunsplit((*urlsplit(cross_url)[:2], "", "", "")),
                affected_feature=f"GET {family.path_template}",
                endpoint_family=f"GET {family.path_template}",
                attacker_prerequisites=[f"自有低权限测试账号 {attacker_alias}", "另一个自有测试账号的对象 ID"],
                victim_conditions=[f"测试对象由自有账号 {owner_alias} 创建或持有"],
                security_invariant="已认证账号只能读取明确授权给自己的私有对象。",
                protected_asset=f"{owner_alias} 的一个自有测试对象",
                trust_boundary=f"两个自有测试账号 {owner_alias}/{attacker_alias}",
                enforcement_point=f"GET {family.path_template}",
                observed_behavior=(
                    f"保持 {attacker_alias} 身份不变，仅替换对象 ID 后，两次返回与 {owner_alias} 正常响应一致的内容。"
                ),
                expected_behavior="服务端应拒绝非所有者访问，或返回不泄露对象存在性的等价响应。",
                capability_before=f"{attacker_alias} 只能读取自己的测试对象。",
                capability_after=f"{attacker_alias} 可读取 {owner_alias} 的一个自有测试对象。",
                capability_delta="跨越一个自有测试账号边界读取一个私有对象",
                normal_control=f"{attacker_alias} 读取自己的对象得到 {own.response_status}。",
                negative_control=f"匿名请求得到 {anonymous.response_status} 且未复现相同对象内容。",
                strongest_benign_explanation="对象可能公开或共享；匿名内容差异和两个账号的对象归属记录排除了该解释。",
                refutation_attempts=[
                    "重复同一单变量跨账号请求",
                    "比较对象所有者账号的正常响应",
                    "执行匿名/公开访问对照",
                    "比较攻击者自有对象响应",
                ],
                reproduction_steps=[
                    f"使用 {attacker_alias} 读取其自有测试对象并保存正常响应。",
                    f"保持方法、身份和其余参数不变，仅将对象 ID 替换为 {owner_alias} 的自有对象 ID。",
                    "重复该跨账号 GET 请求并比较两次结构化响应。",
                    "以匿名身份请求同一对象，确认公开访问不能解释结果。",
                ],
                requests=[],
                responses=[],
                data_exposure_scope=f"仅验证 {owner_alias} 的一个自有测试对象；未访问第三方对象。",
                mutation_scope="GET-only；仅改变一个对象标识符；无状态修改。",
                cleanup_status="只读验证，无需清理；测试对象归测试账号所有。",
                impact="低权限测试账号可越过对象所有权边界读取另一个测试账号的私有对象。",
                severity=Severity.MEDIUM,
                cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
                confidence=0.95,
                duplicate_risk=f"按 GET {family.path_template} 的同一缺失所有权检查语义去重。",
                status=CandidateStatus.VALIDATING,
            )
            return finding, controls, [own, cross_first, cross_second, anonymous]
        return None

    def _account_headers(self, engagement: Engagement) -> dict[str, dict[str, str]]:
        store = SecretStore(self.service.paths.runtime_home / "secrets" / "fallback.json")
        result: dict[str, dict[str, str]] = {}
        for alias, reference in engagement.testing_accounts_secret_refs.items():
            secret = store.get(reference)
            if not secret:
                continue
            try:
                payload = json.loads(secret)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"account secret for {alias} must be JSON") from exc
            headers = payload.get("headers") if isinstance(payload, dict) else None
            if not isinstance(headers, dict) or not all(
                isinstance(name, str) and isinstance(value, str) for name, value in headers.items()
            ):
                raise RuntimeError(f"account secret for {alias} must contain string headers")
            forbidden = {"host", "content-length", "connection", "transfer-encoding", "proxy-authorization"}
            if any(name.lower() in forbidden for name in headers):
                raise RuntimeError(f"account secret for {alias} contains a forbidden transport header")
            result[alias] = dict(headers)
        return result

    @staticmethod
    def _path_identifier(url: str) -> str | None:
        for segment in reversed([item for item in urlsplit(url).path.split("/") if item]):
            if segment.isdigit() or (len(segment) == 36 and segment.count("-") == 4):
                return segment
        return None

    @staticmethod
    def _replace_path_identifier(url: str, replacement: str) -> str:
        parsed = urlsplit(url)
        segments = parsed.path.split("/")
        for index in range(len(segments) - 1, -1, -1):
            segment = segments[index]
            if segment.isdigit() or (len(segment) == 36 and segment.count("-") == 4):
                segments[index] = replacement
                return urlunsplit((parsed.scheme, parsed.netloc, "/".join(segments), parsed.query, ""))
        raise RuntimeError("endpoint family has no replaceable object identifier")

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

    @staticmethod
    def _deduplicate_exchanges(exchanges: list[HttpExchange]) -> list[HttpExchange]:
        values: dict[tuple[str, str, str | None, str | None], HttpExchange] = {}
        for exchange in exchanges:
            key = (exchange.method, exchange.url, exchange.account_alias, exchange.response_hash)
            values.setdefault(key, exchange)
        return list(values.values())

    @staticmethod
    def _hypotheses(context: dict[str, Any]) -> list[Hypothesis]:
        value = context.get("hypotheses", [])
        if not isinstance(value, list) or not all(isinstance(item, Hypothesis) for item in value):
            raise RuntimeError("hypothesis stage did not produce typed hypotheses")
        return value

    @staticmethod
    def _exchanges_or_empty(context: dict[str, Any]) -> list[HttpExchange]:
        value = context.get("exchanges", [])
        if not isinstance(value, list) or not all(isinstance(item, HttpExchange) for item in value):
            raise RuntimeError("traffic context contains non-typed exchanges")
        return value

    @staticmethod
    def _validation_exchanges(context: dict[str, Any]) -> list[HttpExchange]:
        value = context.get("validation_exchanges", [])
        if not isinstance(value, list) or not all(isinstance(item, HttpExchange) for item in value):
            raise RuntimeError("validation did not produce typed exchanges")
        return value

    @staticmethod
    def _exchanges(context: dict[str, Any]) -> list[HttpExchange]:
        exchanges = context.get("exchanges")
        if not isinstance(exchanges, list) or not all(isinstance(item, HttpExchange) for item in exchanges):
            raise RuntimeError("traffic capture did not produce typed exchanges")
        return exchanges

    @staticmethod
    async def _capture_fixture_traffic(engagement: Engagement) -> list[HttpExchange]:
        base = engagement.root_targets[0].uri.rstrip("/")
        backend = DirectProxyBackend(timeout=5)
        return [
            await backend.send(
                engagement,
                "GET",
                f"{base}/api/objects/2",
                headers={"Authorization": "Fixture bob"},
                account_alias="bob",
                source="fixture",
            ),
            await backend.send(
                engagement,
                "GET",
                f"{base}/api/objects/1",
                headers={"Authorization": "Fixture bob"},
                account_alias="bob",
                source="fixture",
            ),
            await backend.send(
                engagement,
                "GET",
                f"{base}/api/objects/1",
                headers={"Authorization": "Fixture bob"},
                account_alias="bob",
                source="fixture",
            ),
            await backend.send(
                engagement,
                "GET",
                f"{base}/api/objects/1",
                account_alias="anonymous",
                source="fixture",
            ),
            await backend.send(
                engagement,
                "GET",
                f"{base}/api/secure-objects/1",
                headers={"Authorization": "Fixture bob"},
                account_alias="bob",
                source="fixture",
            ),
            await backend.send(
                engagement,
                "GET",
                f"{base}/api/public/101",
                account_alias="anonymous",
                source="fixture",
            ),
            await backend.send(
                engagement,
                "GET",
                f"{base}/api/public/101",
                headers={"Authorization": "Fixture bob"},
                account_alias="bob",
                source="fixture",
            ),
        ]

    @staticmethod
    def _make_findings(
        engagement: Engagement,
        exchanges: list[HttpExchange],
    ) -> tuple[Finding, Finding, list[ControlExperiment], list[ControlExperiment]]:
        base = engagement.root_targets[0].uri.rstrip("/")
        valid_controls = [
            ControlExperiment(
                control_id=new_id("control"),
                kind="normal",
                description="Bob reads Bob's own object and receives 200.",
                request_exchange_ids=[exchanges[0].exchange_id],
                observed_result="own object returned 200",
                supports_finding=True,
            ),
            ControlExperiment(
                control_id=new_id("control"),
                kind="negative",
                description="Anonymous and owner-enforcing routes deny Alice's private object.",
                request_exchange_ids=[exchanges[3].exchange_id, exchanges[4].exchange_id],
                observed_result="anonymous returned 401 and secure route returned 403",
                supports_finding=True,
            ),
        ]
        valid = Finding(
            finding_id=new_id("finding"),
            engagement_id=engagement.engagement_id,
            title="本地测试夹具对象级授权缺失导致跨账号读取",
            vulnerability_class="IDOR/BOLA",
            affected_asset=base,
            affected_feature="TEST FIXTURE object API",
            endpoint_family="GET /api/objects/{id}",
            attacker_prerequisites=["本地测试夹具低权限账号 bob", "另一个自有测试对象 ID"],
            victim_conditions=["对象属于本地夹具账号 alice"],
            security_invariant="已认证账号只能读取明确授权给自己的私有对象。",
            protected_asset="本地夹具私有对象字段",
            trust_boundary="alice 与 bob 两个自有夹具账号",
            enforcement_point="GET /api/objects/{id}",
            observed_behavior="bob 仅替换对象 ID 后两次获得 alice 私有对象，HTTP 200。",
            expected_behavior="服务端应返回 403 或等价拒绝。",
            capability_before="bob 只能读取自己的对象 2。",
            capability_after="bob 可以读取 alice 的对象 1。",
            capability_delta="跨越账号边界读取一个明确的自有测试对象",
            normal_control="bob 读取自己的对象 2 返回 200。",
            negative_control="匿名访问返回 401；带所有权检查的等价端点返回 403。",
            strongest_benign_explanation="可能是公开对象，但匿名拒绝和 secure 路由的所有权拒绝已推翻该解释。",
            refutation_attempts=["匿名请求", "等价 secure 路由跨账号请求", "重复同一单变量请求"],
            reproduction_steps=[
                "使用夹具账号 bob 正常读取对象 2。",
                "保持账号和请求不变，仅将对象 ID 改为 1。",
                "重复跨账号请求并记录第二份响应。",
                "执行匿名与 secure 路由负对照。",
            ],
            requests=[],
            responses=[],
            data_exposure_scope="仅本地夹具中一个 alice 自有对象；未外推其他范围。",
            mutation_scope="只读，无目标状态改变。",
            cleanup_status="无需清理；全部数据为仓库 TEST FIXTURE。",
            impact="低权限夹具账号可读取另一个夹具账号的私有对象内容。",
            severity=Severity.MEDIUM,
            cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
            confidence=0.99,
            duplicate_risk="仅与同一对象 API 的所有权缺失重复；未发现其他报告语义。",
            status=CandidateStatus.VALIDATING,
        )
        killed_controls = [
            ControlExperiment(
                control_id=new_id("control"),
                kind="normal",
                description="Anonymous user accesses documented public object.",
                request_exchange_ids=[exchanges[5].exchange_id],
                observed_result="anonymous access returned 200",
                supports_finding=False,
            ),
            ControlExperiment(
                control_id=new_id("control"),
                kind="refutation",
                description="Authenticated and anonymous responses have the same public schema.",
                request_exchange_ids=[exchanges[5].exchange_id, exchanges[6].exchange_id],
                observed_result="both responses identify visibility as public",
                supports_finding=False,
            ),
        ]
        killed = Finding(
            finding_id=new_id("finding"),
            engagement_id=engagement.engagement_id,
            title="伪候选：公开夹具对象可匿名读取",
            vulnerability_class="IDOR/BOLA",
            affected_asset=base,
            affected_feature="documented public TEST FIXTURE API",
            endpoint_family="GET /api/public/{id}",
            attacker_prerequisites=["无"],
            victim_conditions=["对象被明确标记 public"],
            security_invariant="公开对象允许匿名读取。",
            protected_asset="公开夹具文档",
            trust_boundary="不存在私有账号边界",
            enforcement_point="GET /api/public/{id}",
            observed_behavior="匿名和已认证请求均返回公开对象。",
            expected_behavior="公开对象应允许匿名读取。",
            capability_before="匿名用户可以读取公开对象。",
            capability_after="匿名用户仍只能读取公开对象。",
            capability_delta="none",
            normal_control="匿名访问返回明确标记 visibility=public 的对象。",
            negative_control="认证状态变化没有扩大可见字段或对象范围。",
            strongest_benign_explanation="CONTROL_RESULT: INTENTIONALLY_PUBLIC，接口设计就是公开读取。",
            refutation_attempts=["比较匿名与认证响应", "检查 visibility 字段"],
            reproduction_steps=["匿名读取对象 101。", "以 bob 身份读取同一对象并比较。"],
            requests=[],
            responses=[],
            data_exposure_scope="公开夹具对象，无私有数据。",
            mutation_scope="只读。",
            cleanup_status="无需清理。",
            impact="没有新增攻击能力或安全影响。",
            severity=Severity.INFO,
            confidence=0.99,
            duplicate_risk="不应形成报告。",
            status=CandidateStatus.VALIDATING,
        )
        return valid, killed, valid_controls, killed_controls

    @staticmethod
    def _write_finding_manifest(pack: Path, finding: Finding) -> None:
        atomic_write_text(
            pack / "finding.yaml",
            yaml.safe_dump(
                finding.model_dump(mode="json", exclude_none=False),
                allow_unicode=True,
                sort_keys=False,
            ),
        )
