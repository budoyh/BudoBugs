"""Artifact-backed local hunting pipeline and recoverable phase ledger."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, replace
from pathlib import Path
from time import perf_counter
from typing import Any
from urllib.parse import urlsplit

import yaml

from budobugs.agents.router import ModelRouter
from budobugs.agents.runner import CodexTaskRunner
from budobugs.analysis.source_scan import SourceScanCoordinator
from budobugs.core.identifiers import new_id
from budobugs.core.io import atomic_write_json, atomic_write_text, sha256_bytes, sha256_file
from budobugs.core.policy import require_allowed, target_allowed
from budobugs.core.redaction import redact_text
from budobugs.core.state_machine import block_phase, complete_phase, initialize_phases, start_phase
from budobugs.evidence.pack import EvidencePackBuilder
from budobugs.hypotheses.generator import generate_hypotheses
from budobugs.knowledge.vendor import VendorKnowledgeBase
from budobugs.models import (
    AgentLoopState,
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
    RootCauseCluster,
    Run,
    SecurityInvariant,
    StateTransition,
    Tenant,
    ValidationOutcome,
    ValidationPlan,
)
from budobugs.models.base import BudoModel
from budobugs.orchestration.agent_loop import (
    AgentLoopExecution,
    AgentLoopInterrupted,
    AgentOrchestrator,
    CodexProposalProvider,
    PolicyProposalProvider,
    ProposalProvider,
)
from budobugs.orchestration.executor import TypedActionExecutor
from budobugs.orchestration.service import RepositoryService
from budobugs.proxy import ProxyBackendFactory
from budobugs.reporting.generator import ReportGenerator
from budobugs.storage.secrets import SecretStore
from budobugs.traffic.modeler import TrafficModel, build_traffic_model
from budobugs.validation.critic import AdversarialCritic
from budobugs.validation.gates import EvidenceGate


@dataclass(frozen=True, slots=True)
class HuntResult:
    run: Run
    confirmed_finding_id: str | None = None
    killed_finding_id: str | None = None
    report_markdown: str | None = None
    report_html: str | None = None
    confirmed_finding_ids: tuple[str, ...] = ()
    killed_finding_ids: tuple[str, ...] = ()
    report_markdowns: tuple[str, ...] = ()
    report_htmls: tuple[str, ...] = ()
    agent_loop_receipt: str | None = None


class HuntEngine:
    """Run mode-aware, artifact-backed research under one authorized engagement."""

    def __init__(
        self,
        service: RepositoryService,
        *,
        agent_mode: str | None = None,
        model_router: ModelRouter | None = None,
        agent_runner: CodexTaskRunner | None = None,
        proxy_backend: str = "auto",
        har_path: Path | None = None,
        interactive_login: bool = False,
        headless: bool = True,
        agent_stop_after_turns: int | None = None,
    ) -> None:
        self.service = service
        self.agent_mode = (agent_mode or os.environ.get("BUDOBUGS_AGENT_MODE", "disabled")).lower()
        if self.agent_mode not in {"disabled", "codex"}:
            raise ValueError("agent_mode must be disabled or codex")
        self.model_profile = os.environ.get("BUDOBUGS_MODEL_PROFILE", "quality-first")
        self.proxy_backend = proxy_backend
        self.har_path = har_path
        self.interactive_login = interactive_login
        self.headless = headless
        self.agent_stop_after_turns = agent_stop_after_turns
        if agent_stop_after_turns is not None and agent_stop_after_turns < 1:
            raise ValueError("agent_stop_after_turns must be positive")
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
                working_directory=self.service.paths.root,
            )

    def _engagement_token_budget(self) -> int:
        defaults = yaml.safe_load((self.service.paths.root / "config" / "defaults.yaml").read_text(encoding="utf-8"))
        cost = defaults.get("cost", {}) if isinstance(defaults, dict) else {}
        budget = cost.get("engagement_token_budget") if isinstance(cost, dict) else None
        if not isinstance(budget, int) or budget <= 0:
            raise ValueError("cost.engagement_token_budget must be a positive integer")
        return budget

    def estimate(self, engagement: Engagement) -> dict[str, object]:
        scheduled_calls = {
            EngagementMode.LAB: 14,
            EngagementMode.PROGRAM: 10,
            EngagementMode.SOURCE: 2,
        }[engagement.selected_mode]
        model_calls = scheduled_calls if self.agent_mode == "codex" else 0
        routes: dict[str, object] = {}
        model_token_ceiling = 0
        if model_calls and self.model_router is not None:
            task_counts = (
                {"coordinator": 2, "analysis": 10, "critical_judgment": 2}
                if engagement.selected_mode is EngagementMode.LAB
                else {"coordinator": 2, "analysis": 6, "critical_judgment": 2}
                if engagement.selected_mode is EngagementMode.PROGRAM
                else {"analysis": 1, "critical_judgment": 1}
            )
            for task_class, count in task_counts.items():
                try:
                    selection = self.model_router.select(task_class, profile=self.model_profile)
                except ValueError:
                    if task_class != "coordinator":
                        raise
                    selection = self.model_router.select("analysis", profile=self.model_profile)
                routes[task_class] = {
                    "candidates": list(selection.candidates),
                    "reasoning_effort": selection.reasoning_effort,
                    "phase_token_budget": selection.token_budget,
                    "maximum_calls": count,
                }
                model_token_ceiling += selection.token_budget * count
        engagement_ceiling = self._engagement_token_budget()
        model_token_ceiling = min(model_token_ceiling, engagement_ceiling)
        network_upper_bound = {
            EngagementMode.LAB: 96,
            EngagementMode.PROGRAM: len(engagement.root_targets) * 12
            + max(0, len(engagement.testing_accounts_secret_refs) * 24),
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
            confirmed_findings = [item for item in findings if item.critic_verdict is CriticVerdict.CONFIRMED]
            killed_findings = [item for item in findings if item.status is CandidateStatus.KILL]
            confirmed = confirmed_findings[0] if confirmed_findings else None
            killed = killed_findings[0] if killed_findings else None
            report = self.service.paths.findings / confirmed.finding_id / "report" if confirmed else None
            report_markdowns = tuple(
                str(path)
                for item in confirmed_findings
                if (path := self.service.paths.findings / item.finding_id / "report" / "report.md").is_file()
            )
            report_htmls = tuple(
                str(path)
                for item in confirmed_findings
                if (path := self.service.paths.findings / item.finding_id / "report" / "report.html").is_file()
            )
            loop_receipt = self.service.paths.runs / existing.run_id / "artifacts" / "agent-loop" / "receipt.json"
            return HuntResult(
                existing,
                confirmed.finding_id if confirmed else None,
                killed.finding_id if killed else None,
                str(report / "report.md") if report else None,
                str(report / "report.html") if report else None,
                tuple(item.finding_id for item in confirmed_findings),
                tuple(item.finding_id for item in killed_findings),
                report_markdowns,
                report_htmls,
                str(loop_receipt) if loop_receipt.is_file() else None,
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
            except AgentLoopInterrupted as exc:
                record.status = "pending"
                record.started_at = None
                record.completed_at = None
                record.error = None
                record.output_artifacts = [exc.execution.state_path, exc.execution.receipt_path]
                run.status = "interrupted"
                self.service.save_run(run)
                self.service.audit(
                    "agent-loop.interrupted",
                    "coordinator",
                    engagement_id=engagement.engagement_id,
                    run_id=run.run_id,
                    details={
                        "phase": phase.value,
                        "turns": len(exc.execution.state.turns),
                        "state_path": exc.execution.state_path,
                    },
                )
                return HuntResult(run=run, agent_loop_receipt=exc.execution.receipt_path)
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
        findings = context.get("findings", [])
        confirmed_findings = [
            item for item in findings if isinstance(item, Finding) and item.critic_verdict is CriticVerdict.CONFIRMED
        ]
        killed_findings = [
            item for item in findings if isinstance(item, Finding) and item.status is CandidateStatus.KILL
        ]
        reports = context.get("reports", {})
        report_markdowns = (
            tuple(
                str(value["markdown"])
                for value in reports.values()
                if isinstance(value, dict) and isinstance(value.get("markdown"), str)
            )
            if isinstance(reports, dict)
            else ()
        )
        report_htmls = (
            tuple(
                str(value["html"])
                for value in reports.values()
                if isinstance(value, dict) and isinstance(value.get("html"), str)
            )
            if isinstance(reports, dict)
            else ()
        )
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
            confirmed_finding_ids=tuple(item.finding_id for item in confirmed_findings),
            killed_finding_ids=tuple(item.finding_id for item in killed_findings),
            report_markdowns=report_markdowns,
            report_htmls=report_htmls,
            agent_loop_receipt=(
                str(context["agent_loop_receipt"]) if isinstance(context.get("agent_loop_receipt"), str) else None
            ),
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
            "findings",
            "controls_by_finding",
            "validation_outcomes",
            "root_cause_clusters",
            "agent_loop_state",
            "agent_loop_receipt",
            "finding_packs",
            "reports",
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
            "findings": Finding,
            "validation_outcomes": ValidationOutcome,
            "root_cause_clusters": RootCauseCluster,
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
        for key in ("source_scan", "source_inventory", "report", "agent_advisories", "reports"):
            value = context.get(key)
            if value is not None:
                if not isinstance(value, dict):
                    raise RuntimeError(f"hunt context {key} is not an object")
                payload[key] = value
        controls_by_finding = context.get("controls_by_finding")
        if controls_by_finding is not None:
            if not isinstance(controls_by_finding, dict) or not all(
                isinstance(key, str)
                and isinstance(value, list)
                and all(isinstance(item, ControlExperiment) for item in value)
                for key, value in controls_by_finding.items()
            ):
                raise RuntimeError("hunt context controls_by_finding is invalid")
            payload["controls_by_finding"] = {
                key: [item.model_dump(mode="json") for item in value] for key, value in controls_by_finding.items()
            }
        agent_loop_state = context.get("agent_loop_state")
        if agent_loop_state is not None:
            if not isinstance(agent_loop_state, AgentLoopState):
                raise RuntimeError("hunt context agent_loop_state is invalid")
            payload["agent_loop_state"] = agent_loop_state.model_dump(mode="json")
        agent_loop_receipt = context.get("agent_loop_receipt")
        if agent_loop_receipt is not None:
            if not isinstance(agent_loop_receipt, str):
                raise RuntimeError("hunt context agent_loop_receipt is invalid")
            payload["agent_loop_receipt"] = agent_loop_receipt
        finding_packs = context.get("finding_packs")
        if finding_packs is not None:
            if not isinstance(finding_packs, dict) or not all(
                isinstance(key, str) and isinstance(value, (str, Path)) for key, value in finding_packs.items()
            ):
                raise RuntimeError("hunt context finding_packs is invalid")
            payload["finding_packs"] = {key: str(value) for key, value in finding_packs.items()}
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
            "findings": Finding,
            "validation_outcomes": ValidationOutcome,
            "root_cause_clusters": RootCauseCluster,
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
                "controls_by_finding",
                "agent_loop_state",
                "agent_loop_receipt",
                "finding_packs",
                "reports",
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
            if "finding_packs" in payload:
                value = payload["finding_packs"]
                if not isinstance(value, dict) or not all(
                    isinstance(key, str) and isinstance(item, str) for key, item in value.items()
                ):
                    raise ValueError("finding_packs is invalid")
                packs = {key: Path(item).resolve() for key, item in value.items()}
                if any(not item.is_relative_to(self.service.paths.findings.resolve()) for item in packs.values()):
                    raise ValueError("finding_packs escapes the findings root")
                context["finding_packs"] = packs
            if "controls_by_finding" in payload:
                value = payload["controls_by_finding"]
                if not isinstance(value, dict) or not all(isinstance(item, list) for item in value.values()):
                    raise ValueError("controls_by_finding is invalid")
                context["controls_by_finding"] = {
                    str(key): [ControlExperiment.model_validate(item) for item in values]
                    for key, values in value.items()
                }
            if "agent_loop_state" in payload:
                context["agent_loop_state"] = AgentLoopState.model_validate(payload["agent_loop_state"])
            if "agent_loop_receipt" in payload:
                value = payload["agent_loop_receipt"]
                if not isinstance(value, str):
                    raise ValueError("agent_loop_receipt is not a path string")
                receipt_path = Path(value).resolve()
                if not receipt_path.is_relative_to((self.service.paths.runs / run.run_id).resolve()):
                    raise ValueError("agent_loop_receipt escapes the active run")
                context["agent_loop_receipt"] = value
            for key in ("source_scan", "source_inventory", "report", "reports"):
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

    async def _run_agent_loop(
        self,
        engagement: Engagement,
        run: Run,
        artifacts_dir: Path,
        context: dict[str, Any],
    ) -> AgentLoopExecution:
        loop_root = artifacts_dir
        proxy = await ProxyBackendFactory(
            self.service.paths.root,
            self.service.paths.runtime_home,
        ).select(
            engagement,
            requested=self.proxy_backend,
            receipt_path=loop_root / "agent-loop" / "proxy-selection.json",
            har_path=self.har_path,
        )
        account_headers, login_urls = self._account_metadata(engagement)
        executor = TypedActionExecutor(
            repository_root=self.service.paths.root,
            runtime_home=self.service.paths.runtime_home,
            artifact_root=loop_root,
            engagement=engagement,
            run_id=run.run_id,
            proxy=proxy,
            account_headers=account_headers,
            account_login_urls=login_urls,
            interactive_login=self.interactive_login,
            headless=self.headless,
        )
        executor.ingest_exchanges(self._exchanges_or_empty(context))
        provider: ProposalProvider = PolicyProposalProvider()
        if self.agent_mode == "codex":
            if self.model_router is None or self.agent_runner is None:
                raise RuntimeError("Codex agent mode lacks a configured model router or runner")
            provider = CodexProposalProvider(
                service=self.service,
                router=self.model_router,
                runner=self.agent_runner,
                profile=self.model_profile,
                run_id=run.run_id,
                engagement_token_budget=self._engagement_token_budget(),
            )
        orchestrator = AgentOrchestrator(
            engagement=engagement,
            run_id=run.run_id,
            artifact_root=loop_root,
            executor=executor,
            provider=provider,
        )
        execution = await orchestrator.run(
            resume=(loop_root / "agent-loop" / "state.json").is_file(),
            max_new_turns=self.agent_stop_after_turns,
        )
        for thread_id in execution.state.role_thread_ids.values():
            if thread_id not in run.codex_thread_ids:
                run.codex_thread_ids.append(thread_id)
        self.service.save_run(run)
        return execution

    def _account_metadata(self, engagement: Engagement) -> tuple[dict[str, dict[str, str]], dict[str, str]]:
        store = SecretStore(self.service.paths.runtime_home / "secrets" / "fallback.json")
        headers_by_alias: dict[str, dict[str, str]] = {}
        login_urls: dict[str, str] = {}
        forbidden = {"host", "content-length", "connection", "transfer-encoding", "proxy-authorization"}
        for alias, reference in engagement.testing_accounts_secret_refs.items():
            secret = store.get(reference)
            if not secret:
                continue
            try:
                payload = json.loads(secret)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"account secret for {alias} must be JSON") from exc
            if not isinstance(payload, dict):
                raise RuntimeError(f"account secret for {alias} must be a JSON object")
            headers = payload.get("headers", {})
            if not isinstance(headers, dict) or not all(
                isinstance(name, str) and isinstance(value, str) for name, value in headers.items()
            ):
                raise RuntimeError(f"account secret for {alias} headers must be a string mapping")
            if any(str(name).lower() in forbidden for name in headers):
                raise RuntimeError(f"account secret for {alias} contains a forbidden transport header")
            headers_by_alias[alias] = {str(name): str(value) for name, value in headers.items()}
            login_url = payload.get("login_url")
            if login_url is not None:
                if not isinstance(login_url, str):
                    raise RuntimeError(f"account secret for {alias} login_url must be a string")
                require_allowed(target_allowed(engagement, login_url))
                login_urls[alias] = login_url
        return headers_by_alias, login_urls

    def _apply_agent_execution(self, context: dict[str, Any], execution: AgentLoopExecution) -> None:
        findings = execution.findings
        outcomes = execution.state.validation_outcomes
        by_finding = {item.finding_id: item for item in findings}
        confirmed = [item for item in outcomes if item.decision.value == "CONFIRMED"]
        killed = [item for item in outcomes if item.decision.value == "KILL"]
        primary_confirmed_ids: list[str] = []
        by_candidate = {item.candidate_id: item for item in outcomes}
        for cluster in execution.root_cause_clusters:
            primary = by_candidate.get(cluster.primary_candidate_id)
            if primary is not None and primary.decision.value == "CONFIRMED":
                primary_confirmed_ids.append(primary.finding_id)
        if not primary_confirmed_ids:
            primary_confirmed_ids = [item.finding_id for item in confirmed]
        valid = next((by_finding[item] for item in primary_confirmed_ids if item in by_finding), None)
        killed_finding = next((by_finding[item.finding_id] for item in killed if item.finding_id in by_finding), None)
        combined_exchanges = self._deduplicate_exchanges([*self._exchanges_or_empty(context), *execution.exchanges])
        context.update(
            exchanges=combined_exchanges,
            validation_exchanges=combined_exchanges,
            browser_artifacts=execution.browser_artifacts,
            findings=findings,
            controls_by_finding=execution.controls_by_finding,
            validation_outcomes=outcomes,
            root_cause_clusters=execution.root_cause_clusters,
            agent_loop_state=execution.state,
            agent_loop_receipt=execution.receipt_path,
        )
        if valid is not None:
            context["valid_finding"] = valid
            context["valid_controls"] = execution.controls_by_finding.get(valid.finding_id, [])
        if killed_finding is not None:
            context["killed_finding"] = killed_finding
            context["killed_controls"] = execution.controls_by_finding.get(killed_finding.finding_id, [])

    @staticmethod
    def _finding_exchanges(
        finding: Finding,
        outcomes: list[ValidationOutcome],
        exchanges: list[HttpExchange],
    ) -> list[HttpExchange]:
        exchange_ids = {
            exchange_id
            for outcome in outcomes
            if outcome.finding_id == finding.finding_id
            for exchange_id in outcome.exchange_ids
        }
        return [item for item in exchanges if item.exchange_id in exchange_ids]

    @staticmethod
    def _primary_report_findings(
        findings: list[Finding],
        outcomes: list[ValidationOutcome],
        clusters: list[RootCauseCluster],
    ) -> list[Finding]:
        by_candidate = {item.candidate_id: item for item in outcomes}
        by_finding = {item.finding_id: item for item in findings}
        primary_ids: list[str] = []
        for cluster in clusters:
            outcome = by_candidate.get(cluster.primary_candidate_id)
            if outcome is not None and outcome.decision.value == "CONFIRMED":
                primary_ids.append(outcome.finding_id)
        if not primary_ids:
            primary_ids = [item.finding_id for item in outcomes if item.decision.value == "CONFIRMED"]
        return [by_finding[finding_id] for finding_id in dict.fromkeys(primary_ids) if finding_id in by_finding]

    @staticmethod
    def _finalize_agent_receipt(context: dict[str, Any]) -> None:
        receipt_value = context.get("agent_loop_receipt")
        if not isinstance(receipt_value, str):
            return
        path = Path(receipt_value)
        try:
            receipt = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(receipt, dict):
            return
        packs = context.get("finding_packs", {})
        reports = context.get("reports", {})
        pack_receipts: dict[str, dict[str, object]] = {}
        if isinstance(packs, dict):
            for finding_id, value in packs.items():
                pack = Path(value)
                gate_path = pack / "gate-receipt.json"
                gate_passed = False
                if gate_path.is_file():
                    try:
                        gate_payload = json.loads(gate_path.read_text(encoding="utf-8"))
                    except (OSError, json.JSONDecodeError):
                        gate_payload = None
                    gate_passed = isinstance(gate_payload, dict) and gate_payload.get("passed") is True
                pack_receipts[str(finding_id)] = {
                    "path": str(pack),
                    "finding_manifest": (pack / "finding.yaml").is_file(),
                    "gate_receipt": str(gate_path) if gate_path.is_file() else None,
                    "gate_passed": gate_passed,
                }
        report_receipts: dict[str, dict[str, object]] = {}
        if isinstance(reports, dict):
            for finding_id, value in reports.items():
                if not isinstance(value, dict):
                    continue
                report_receipts[str(finding_id)] = {
                    "markdown": value.get("markdown"),
                    "html": value.get("html"),
                    "markdown_exists": isinstance(value.get("markdown"), str) and Path(value["markdown"]).is_file(),
                    "html_exists": isinstance(value.get("html"), str) and Path(value["html"]).is_file(),
                }
        confirmed = receipt.get("confirmed_outcomes", [])
        killed = receipt.get("killed_outcomes", [])
        classes = receipt.get("confirmed_vulnerability_classes", [])
        merged = receipt.get("same_fix_merged_clusters", [])
        acceptance = {
            "at_least_six_specialists": int(receipt.get("participating_agent_count", 0)) >= 6,
            "at_least_three_plan_execute_observe_rounds": int(receipt.get("round_count", 0)) >= 3,
            "typed_network_or_browser_action_executed": bool(receipt.get("network_or_browser_actions_executed")),
            "at_least_four_vulnerability_classes_confirmed": isinstance(classes, list) and len(classes) >= 4,
            "at_least_three_false_candidates_killed": isinstance(killed, list) and len(killed) >= 3,
            "same_fix_candidates_merged": isinstance(merged, list) and bool(merged),
            "evidence_packs_complete": isinstance(confirmed, list)
            and all(
                isinstance(item, dict)
                and isinstance(item.get("finding_id"), str)
                and pack_receipts.get(item["finding_id"], {}).get("gate_passed") is True
                for item in confirmed
            ),
            "reports_complete_for_primary_root_causes": bool(report_receipts)
            and all(
                value["markdown_exists"] is True and value["html_exists"] is True for value in report_receipts.values()
            ),
            "interrupted_chain_resumed": int(receipt.get("resume_count", 0)) >= 1,
        }
        receipt.update(
            {
                "evidence_packs": pack_receipts,
                "reports": report_receipts,
                "acceptance_checks": acceptance,
                "acceptance_passed": all(acceptance.values()),
            }
        )
        atomic_write_json(path, receipt)

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
                        "/api/shares/{token}",
                        "/api/session/{operation}",
                        "/graphql",
                        "/ws/objects/{id}",
                        "/api/workflows/{id}/transition",
                        "/preview",
                    ]
                },
            )
        elif phase is PhaseName.NORMAL_BROWSER_EXPLORATION:
            execution = await self._run_agent_loop(engagement, run, artifacts_dir, context)
            self._apply_agent_execution(context, execution)
            atomic_write_json(
                phase_path,
                {
                    "agent_loop_state": execution.state_path,
                    "agent_loop_receipt": execution.receipt_path,
                    "browser_artifacts": execution.browser_artifacts,
                    "proxy_exchanges": len(execution.exchanges),
                    "participating_agents": [item.value for item in execution.state.participating_agents],
                    "executed_turns": execution.state.executed_turn_count,
                },
            )
        elif phase is PhaseName.TRAFFIC_MODEL:
            exchanges = self._exchanges(context)
            model = build_traffic_model(exchanges)
            context["traffic_model"] = model
            VendorKnowledgeBase(self.service.store).update_from_traffic(
                engagement,
                model,
                candidate_ids=(item.candidate_id for item in context.get("validation_outcomes", [])),
            )
            atomic_write_json(phase_path, model.as_dict())
        elif phase is PhaseName.INVARIANT_MODEL:
            model = context["traffic_model"]
            knowledge = VendorKnowledgeBase(self.service.store).load(engagement)
            invariants, hypotheses = generate_hypotheses(engagement.engagement_id, model, knowledge)
            context["invariants"] = invariants
            context["hypotheses"] = hypotheses
            atomic_write_json(phase_path, {"invariants": [item.model_dump(mode="json") for item in invariants]})
        elif phase is PhaseName.HYPOTHESIS_GENERATION:
            hypotheses = context["hypotheses"]
            atomic_write_json(phase_path, [item.model_dump(mode="json") for item in hypotheses])
        elif phase is PhaseName.PRIORITIZATION:
            hypotheses = sorted(context["hypotheses"], key=lambda item: item.bounty_score, reverse=True)
            context["hypotheses"] = hypotheses
            atomic_write_json(
                phase_path,
                {
                    "ordered_ids": [item.hypothesis_id for item in hypotheses],
                    "method": (
                        "bounty-first reward-probability-impact-uniqueness divided by "
                        "duplicate/request/token/research cost"
                    ),
                },
            )
        elif phase is PhaseName.VALIDATION:
            findings = [item for item in context.get("findings", []) if isinstance(item, Finding)]
            outcomes = [item for item in context.get("validation_outcomes", []) if isinstance(item, ValidationOutcome)]
            VendorKnowledgeBase(self.service.store).update_from_validation(engagement, outcomes)
            atomic_write_json(
                phase_path,
                {
                    "confirmed": [item.finding_id for item in outcomes if item.decision.value == "CONFIRMED"],
                    "killed": [item.finding_id for item in outcomes if item.decision.value == "KILL"],
                    "hold": [item.finding_id for item in outcomes if item.decision.value == "HOLD"],
                    "finding_count": len(findings),
                },
            )
        elif phase is PhaseName.NEGATIVE_CONTROL:
            controls = [
                control
                for values in context.get("controls_by_finding", {}).values()
                for control in values
                if isinstance(control, ControlExperiment)
            ]
            atomic_write_json(phase_path, [item.model_dump(mode="json") for item in controls])
        elif phase is PhaseName.REFUTATION:
            atomic_write_json(
                phase_path,
                {
                    "strongest_benign_explanations": {
                        item.finding_id: item.strongest_benign_explanation
                        for item in context.get("findings", [])
                        if isinstance(item, Finding)
                    },
                    "required_checks": [
                        "public/shared design",
                        "cache/mock response",
                        "same-account ownership",
                        "state pollution",
                        "third-party expansion",
                        "same-fix root-cause duplication",
                    ],
                },
            )
        elif phase is PhaseName.EVIDENCE_PACK:
            builder = EvidencePackBuilder(self.service.paths.findings)
            findings = [item for item in context.get("findings", []) if isinstance(item, Finding)]
            outcomes = [item for item in context.get("validation_outcomes", []) if isinstance(item, ValidationOutcome)]
            exchanges = self._exchanges(context)
            controls_by_finding = context.get("controls_by_finding", {})
            browser_artifacts = [Path(item) for item in context.get("browser_artifacts", [])]
            packs: dict[str, Path] = {}
            for finding in findings:
                finding_exchanges = self._finding_exchanges(finding, outcomes, exchanges)
                controls = controls_by_finding.get(finding.finding_id, [])
                relevant_browser = browser_artifacts if finding.vulnerability_class == "client-side-xss" else []
                packs[finding.finding_id] = builder.build(
                    finding,
                    finding_exchanges,
                    controls,
                    browser_artifacts=relevant_browser,
                )
            context.update(builder=builder, finding_packs=packs)
            valid = context.get("valid_finding")
            killed = context.get("killed_finding")
            if isinstance(valid, Finding):
                context["valid_pack"] = packs[valid.finding_id]
            if isinstance(killed, Finding):
                context["killed_pack"] = packs[killed.finding_id]
            atomic_write_json(phase_path, {"packs": {key: str(value) for key, value in packs.items()}})
        elif phase is PhaseName.INDEPENDENT_CRITIC:
            gate = EvidenceGate()
            critic = AdversarialCritic()
            findings = [item for item in context.get("findings", []) if isinstance(item, Finding)]
            outcomes = [item for item in context.get("validation_outcomes", []) if isinstance(item, ValidationOutcome)]
            packs = context.get("finding_packs", {})
            controls_by_finding = context.get("controls_by_finding", {})
            exchanges = self._exchanges(context)
            restored_builder = context.get("builder")
            if not isinstance(restored_builder, EvidencePackBuilder):
                restored_builder = EvidencePackBuilder(self.service.paths.findings)
                context["builder"] = restored_builder
            critiques: dict[str, object] = {}
            for finding in findings:
                pack = Path(packs[finding.finding_id])
                precritic = gate.evaluate(finding, pack, require_critic=False)
                critique = critic.review(finding, precritic)
                expected = next((item for item in outcomes if item.finding_id == finding.finding_id), None)
                if expected is not None and expected.decision.value == "CONFIRMED":
                    if critique.verdict is not CriticVerdict.CONFIRMED:
                        raise RuntimeError(f"fixture candidate failed independent critic: {finding.finding_id}")
                    finding.critic_verdict = CriticVerdict.CONFIRMED
                    finding.status = CandidateStatus.READY_FOR_HUMAN_REVIEW
                    finding.reportability = "submission-ready"
                    finding.human_review_status = "pending"
                elif expected is not None and expected.decision.value == "KILL":
                    finding.critic_verdict = CriticVerdict.KILL
                    finding.status = CandidateStatus.KILL
                    finding.reportability = "hold"
                else:
                    finding.critic_verdict = CriticVerdict.HOLD
                    finding.status = CandidateStatus.HOLD
                    finding.reportability = "hold"
                restored_builder.build(
                    finding,
                    self._finding_exchanges(finding, outcomes, exchanges),
                    controls_by_finding.get(finding.finding_id, []),
                    critique=critique,
                    browser_artifacts=(
                        [Path(item) for item in context.get("browser_artifacts", [])]
                        if finding.vulnerability_class == "client-side-xss"
                        else []
                    ),
                )
                if finding.critic_verdict is CriticVerdict.CONFIRMED:
                    final_receipt = gate.evaluate(finding, pack, require_critic=True)
                    if not final_receipt.passed:
                        raise RuntimeError(f"critic-confirmed fixture finding failed gates: {finding.finding_id}")
                    finding.gate_receipt_path = str(pack / "gate-receipt.json")
                self._write_finding_manifest(pack, finding)
                self.service.save_finding(finding)
                critiques[finding.finding_id] = critique.model_dump(mode="json")
            atomic_write_json(
                phase_path,
                critiques,
            )
        elif phase is PhaseName.REPORT_DRAFT:
            template_root = Path(__file__).parents[1] / "reporting" / "templates"
            findings = [item for item in context.get("findings", []) if isinstance(item, Finding)]
            outcomes = [item for item in context.get("validation_outcomes", []) if isinstance(item, ValidationOutcome)]
            clusters = [item for item in context.get("root_cause_clusters", []) if isinstance(item, RootCauseCluster)]
            primary_findings = self._primary_report_findings(findings, outcomes, clusters)
            reports: dict[str, dict[str, str]] = {}
            for finding in primary_findings:
                if not finding.is_submission_ready:
                    continue
                report = ReportGenerator(template_root).generate(
                    finding,
                    Path(context["finding_packs"][finding.finding_id]),
                    vendor=engagement.vendor,
                    engagement_platform=engagement.platform,
                )
                self.service.store.save("report", report.report_id, report)
                reports[finding.finding_id] = {
                    "markdown": report.markdown_path,
                    "html": report.html_path,
                    "manifest": report.manifest_path,
                }
            context["reports"] = reports
            if reports:
                first = next(iter(reports.values()))
                context["report"] = {"markdown": first["markdown"], "html": first["html"]}
            atomic_write_json(phase_path, reports)
        elif phase is PhaseName.HUMAN_REVIEW_READY:
            findings = [item for item in context.get("findings", []) if isinstance(item, Finding)]
            self._finalize_agent_receipt(context)
            atomic_write_json(
                phase_path,
                {
                    "submission_ready": [item.finding_id for item in findings if item.is_submission_ready],
                    "human_submission_required": True,
                    "killed_false_candidates": [
                        item.finding_id for item in findings if item.status is CandidateStatus.KILL
                    ],
                    "agent_loop_receipt": context.get("agent_loop_receipt"),
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
                execution = await self._run_agent_loop(engagement, run, artifacts_dir, context)
                self._apply_agent_execution(context, execution)
                atomic_write_json(
                    phase_path,
                    {
                        "agent_loop_state": execution.state_path,
                        "agent_loop_receipt": execution.receipt_path,
                        "browser_artifacts": execution.browser_artifacts,
                        "proxy_exchanges": len(execution.exchanges),
                        "participating_agents": [item.value for item in execution.state.participating_agents],
                    },
                )
        elif phase is PhaseName.TRAFFIC_MODEL:
            model = build_traffic_model(self._exchanges_or_empty(context))
            context["traffic_model"] = model
            if mode is EngagementMode.PROGRAM:
                VendorKnowledgeBase(self.service.store).update_from_traffic(
                    engagement,
                    model,
                    candidate_ids=(item.candidate_id for item in context.get("validation_outcomes", [])),
                )
            atomic_write_json(phase_path, model.as_dict())
        elif phase is PhaseName.INVARIANT_MODEL:
            if mode is EngagementMode.SOURCE:
                invariants, hypotheses = self._source_hypotheses(engagement, context.get("source_scan", {}))
            else:
                traffic_model_value = context.get("traffic_model")
                if not isinstance(traffic_model_value, TrafficModel):
                    raise RuntimeError("traffic model is unavailable")
                knowledge = VendorKnowledgeBase(self.service.store).load(engagement)
                invariants, hypotheses = generate_hypotheses(
                    engagement.engagement_id,
                    traffic_model_value,
                    knowledge,
                )
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
            hypotheses = sorted(self._hypotheses(context), key=lambda item: item.bounty_score, reverse=True)
            advisory_applied = False
            if mode is EngagementMode.SOURCE:
                advisory = await self._agent_advisory(
                    task_class="analysis",
                    task_instruction=(
                        'Return exactly one JSON object with keys "ranked_hypothesis_ids" and "rationale". '
                        "Rank every supplied source hypothesis ID exactly once. Do not add IDs or facts."
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
                        else "bounty-first reward/probability/impact/uniqueness divided by duplicate and costs"
                    ),
                },
            )
        elif phase is PhaseName.VALIDATION:
            plans = self._validation_plans(mode, self._hypotheses(context))
            context["validation_plans"] = plans
            outcomes = [item for item in context.get("validation_outcomes", []) if isinstance(item, ValidationOutcome)]
            if mode is EngagementMode.PROGRAM:
                VendorKnowledgeBase(self.service.store).update_from_validation(engagement, outcomes)
            atomic_write_json(
                phase_path,
                {
                    "plans": [item.model_dump(mode="json") for item in plans],
                    "confirmed": [item.finding_id for item in outcomes if item.decision.value == "CONFIRMED"],
                    "killed": [item.finding_id for item in outcomes if item.decision.value == "KILL"],
                    "hold": [item.finding_id for item in outcomes if item.decision.value == "HOLD"],
                    "boundary": "typed self-owned, reversible, engagement-scoped experiments",
                },
            )
        elif phase is PhaseName.NEGATIVE_CONTROL:
            controls = [
                control
                for values in context.get("controls_by_finding", {}).values()
                for control in values
                if isinstance(control, ControlExperiment)
            ]
            atomic_write_json(
                phase_path,
                [item.model_dump(mode="json") for item in controls],
            )
        elif phase is PhaseName.REFUTATION:
            atomic_write_json(
                phase_path,
                {
                    "tested": bool(context.get("validation_outcomes")),
                    "required_explanations": [
                        "public or shared object",
                        "cache or mock response",
                        "same-account ownership",
                        "redirect or third-party expansion",
                        "state pollution and same-fix duplication",
                    ],
                },
            )
        elif phase is PhaseName.EVIDENCE_PACK:
            findings = [item for item in context.get("findings", []) if isinstance(item, Finding)]
            if findings:
                builder = EvidencePackBuilder(self.service.paths.findings)
                outcomes = [
                    item for item in context.get("validation_outcomes", []) if isinstance(item, ValidationOutcome)
                ]
                exchanges = self._exchanges_or_empty(context)
                controls_by_finding = context.get("controls_by_finding", {})
                browser_artifacts = [Path(item) for item in context.get("browser_artifacts", [])]
                packs: dict[str, Path] = {}
                for finding in findings:
                    packs[finding.finding_id] = builder.build(
                        finding,
                        self._finding_exchanges(finding, outcomes, exchanges),
                        controls_by_finding.get(finding.finding_id, []),
                        browser_artifacts=(
                            browser_artifacts if finding.vulnerability_class == "client-side-xss" else []
                        ),
                    )
                context.update(builder=builder, finding_packs=packs)
                atomic_write_json(phase_path, {"packs": {key: str(value) for key, value in packs.items()}})
            else:
                atomic_write_json(
                    phase_path,
                    {"packs": [], "reason": "no candidate has artifact-backed validation evidence"},
                )
        elif phase is PhaseName.INDEPENDENT_CRITIC:
            findings = [item for item in context.get("findings", []) if isinstance(item, Finding)]
            if findings:
                gate = EvidenceGate()
                outcomes = [
                    item for item in context.get("validation_outcomes", []) if isinstance(item, ValidationOutcome)
                ]
                packs = context.get("finding_packs", {})
                controls_by_finding = context.get("controls_by_finding", {})
                exchanges = self._exchanges_or_empty(context)
                restored_builder = context.get("builder")
                if not isinstance(restored_builder, EvidencePackBuilder):
                    restored_builder = EvidencePackBuilder(self.service.paths.findings)
                    context["builder"] = restored_builder
                critiques: dict[str, object] = {}
                for finding in findings:
                    pack = Path(packs[finding.finding_id])
                    precritic = gate.evaluate(finding, pack, require_critic=False)
                    critique = AdversarialCritic().review(finding, precritic)
                    outcome = next((item for item in outcomes if item.finding_id == finding.finding_id), None)
                    if outcome is not None and outcome.decision.value == "CONFIRMED" and not precritic.passed:
                        finding.critic_verdict = CriticVerdict.HOLD
                        finding.status = CandidateStatus.HOLD
                    elif outcome is not None and outcome.decision.value == "CONFIRMED":
                        finding.critic_verdict = CriticVerdict.CONFIRMED
                        finding.status = CandidateStatus.READY_FOR_HUMAN_REVIEW
                        finding.reportability = "submission-ready"
                        finding.human_review_status = "pending"
                    elif outcome is not None and outcome.decision.value == "KILL":
                        finding.critic_verdict = CriticVerdict.KILL
                        finding.status = CandidateStatus.KILL
                        finding.reportability = "hold"
                    else:
                        finding.critic_verdict = CriticVerdict.HOLD
                        finding.status = CandidateStatus.HOLD
                        finding.reportability = "hold"
                    restored_builder.build(
                        finding,
                        self._finding_exchanges(finding, outcomes, exchanges),
                        controls_by_finding.get(finding.finding_id, []),
                        critique=critique,
                    )
                    if finding.critic_verdict is CriticVerdict.CONFIRMED:
                        final_gate = gate.evaluate(finding, pack, require_critic=True)
                        if not final_gate.passed:
                            finding.critic_verdict = CriticVerdict.HOLD
                            finding.status = CandidateStatus.HOLD
                            finding.reportability = "hold"
                        else:
                            finding.gate_receipt_path = str(pack / "gate-receipt.json")
                    self._write_finding_manifest(pack, finding)
                    self.service.save_finding(finding)
                    critiques[finding.finding_id] = critique.model_dump(mode="json")
                atomic_write_json(phase_path, critiques)
            else:
                atomic_write_json(
                    phase_path,
                    {
                        "verdict": "HOLD",
                        "reason": "scanner/hypothesis output is not vulnerability evidence",
                    },
                )
        elif phase is PhaseName.REPORT_DRAFT:
            findings = [item for item in context.get("findings", []) if isinstance(item, Finding)]
            outcomes = [item for item in context.get("validation_outcomes", []) if isinstance(item, ValidationOutcome)]
            clusters = [item for item in context.get("root_cause_clusters", []) if isinstance(item, RootCauseCluster)]
            primary_findings = self._primary_report_findings(findings, outcomes, clusters)
            if primary_findings:
                template_root = Path(__file__).parents[1] / "reporting" / "templates"
                reports: dict[str, dict[str, str]] = {}
                for finding in primary_findings:
                    if not finding.is_submission_ready:
                        continue
                    report = ReportGenerator(template_root).generate(
                        finding,
                        Path(context["finding_packs"][finding.finding_id]),
                        vendor=engagement.vendor,
                        engagement_platform=engagement.platform,
                    )
                    self.service.store.save("report", report.report_id, report)
                    reports[finding.finding_id] = {
                        "markdown": report.markdown_path,
                        "html": report.html_path,
                        "manifest": report.manifest_path,
                    }
                context["reports"] = reports
                if reports:
                    first = next(iter(reports.values()))
                    context["report"] = {"markdown": first["markdown"], "html": first["html"]}
                atomic_write_json(phase_path, reports)
            else:
                atomic_write_json(
                    phase_path,
                    {"submission_ready": False, "reason": "no critic-confirmed finding"},
                )
        elif phase is PhaseName.HUMAN_REVIEW_READY:
            findings = [item for item in context.get("findings", []) if isinstance(item, Finding)]
            self._finalize_agent_receipt(context)
            atomic_write_json(
                phase_path,
                {
                    "submission_ready": [item.finding_id for item in findings if item.is_submission_ready],
                    "human_submission_required": True,
                    "unresolved_hypotheses": [item.hypothesis_id for item in self._hypotheses(context)],
                    "agent_loop_receipt": context.get("agent_loop_receipt"),
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
    def _exchanges(context: dict[str, Any]) -> list[HttpExchange]:
        exchanges = context.get("exchanges")
        if not isinstance(exchanges, list) or not all(isinstance(item, HttpExchange) for item in exchanges):
            raise RuntimeError("traffic capture did not produce typed exchanges")
        return exchanges

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
