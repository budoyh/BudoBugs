"""Mechanical A-I evidence gate evaluation from real artifact state."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import Field

from budobugs.core.io import atomic_write_json, sha256_file
from budobugs.models import CriticVerdict, Finding
from budobugs.models.base import BudoModel, utc_now


class GateResult(BudoModel):
    gate: str
    passed: bool
    evidence: list[str] = Field(default_factory=list)
    reason: str


class GateReceipt(BudoModel):
    schema_version: int = 1
    finding_id: str
    evaluated_at: str = Field(default_factory=lambda: utc_now().isoformat())
    gates: list[GateResult]
    passed: bool


class EvidenceGate:
    """Recompute report readiness; never accept a caller's pass flag."""

    def evaluate(self, finding: Finding, pack: Path, *, require_critic: bool) -> GateReceipt:
        results = [
            self._gate_a(finding, pack),
            self._gate_b(finding, pack),
            self._gate_c(finding),
            self._gate_d(finding, pack),
            self._gate_e(finding),
            self._gate_f(finding),
            self._gate_g(finding, pack),
            self._gate_h(finding),
            self._gate_i(finding, pack, required=require_critic),
        ]
        receipt = GateReceipt(
            finding_id=finding.finding_id,
            gates=results,
            passed=all(item.passed for item in results),
        )
        atomic_write_json(pack / "gate-receipt.json", json.loads(receipt.model_dump_json()))
        return receipt

    @staticmethod
    def _exists(pack: Path, relative_paths: list[str]) -> list[str]:
        return [value for value in relative_paths if (pack / value).is_file()]

    def _gate_a(self, finding: Finding, pack: Path) -> GateResult:
        linked = bool(finding.engagement_id and finding.affected_asset and (pack / "finding.yaml").is_file())
        return GateResult(
            gate="A_TASK_ASSET",
            passed=linked,
            evidence=["finding.yaml"] if linked else [],
            reason="finding is linked to an engagement and affected asset" if linked else "task linkage missing",
        )

    def _gate_b(self, finding: Finding, pack: Path) -> GateResult:
        request_files = self._exists(pack, finding.requests)
        response_files = self._exists(pack, finding.responses)
        passed = len(request_files) >= 2 and len(response_files) >= 2 and len(finding.reproduction_steps) >= 2
        return GateResult(
            gate="B_REPRODUCIBILITY",
            passed=passed,
            evidence=request_files + response_files,
            reason="two or more recorded attempts exist" if passed else "repeat reproduction artifacts are missing",
        )

    @staticmethod
    def _gate_c(finding: Finding) -> GateResult:
        delta = finding.capability_delta.strip()
        passed = bool(delta) and delta.lower() not in {"none", "no change", "unknown"}
        return GateResult(
            gate="C_CAPABILITY_DELTA",
            passed=passed,
            evidence=[f"before={finding.capability_before}", f"after={finding.capability_after}"],
            reason="non-empty attacker capability increase is recorded" if passed else "no capability increase",
        )

    @staticmethod
    def _gate_d(finding: Finding, pack: Path) -> GateResult:
        controls = list((pack / "controls").glob("*.json")) if (pack / "controls").is_dir() else []
        passed = bool(finding.normal_control.strip() and finding.negative_control.strip() and len(controls) >= 2)
        return GateResult(
            gate="D_CONTROLS",
            passed=passed,
            evidence=[str(item.relative_to(pack)) for item in controls],
            reason="normal and negative controls are artifact-backed" if passed else "control artifacts are incomplete",
        )

    @staticmethod
    def _gate_e(finding: Finding) -> GateResult:
        explanation = finding.strongest_benign_explanation.strip().lower()
        passed = bool(finding.refutation_attempts) and explanation not in {
            "",
            "unresolved",
            "not tested",
        }
        return GateResult(
            gate="E_BENIGN_EXPLANATION",
            passed=passed,
            evidence=finding.refutation_attempts,
            reason="a concrete benign explanation was tested" if passed else "benign explanation remains unresolved",
        )

    @staticmethod
    def _gate_f(finding: Finding) -> GateResult:
        passed = all(
            value.strip().lower() not in {"", "unknown", "theoretical"}
            for value in (finding.impact, finding.data_exposure_scope)
        )
        return GateResult(
            gate="F_IMPACT",
            passed=passed,
            evidence=[finding.impact, finding.data_exposure_scope],
            reason="impact and conservative scope are recorded" if passed else "impact is only theoretical",
        )

    @staticmethod
    def _gate_g(finding: Finding, pack: Path) -> GateResult:
        mismatches: list[str] = []
        verified: list[str] = []
        for relative, expected in finding.evidence_hashes.items():
            path = pack / relative
            if not path.is_file() or sha256_file(path) != expected:
                mismatches.append(relative)
            else:
                verified.append(relative)
        passed = bool(verified) and not mismatches
        reason = "all declared evidence hashes match" if passed else f"missing/mismatched: {mismatches}"
        return GateResult(gate="G_EVIDENCE_INTEGRITY", passed=passed, evidence=verified, reason=reason)

    @staticmethod
    def _gate_h(finding: Finding) -> GateResult:
        passed = finding.duplicate_risk.strip().lower() not in {"", "unknown", "not assessed"}
        return GateResult(
            gate="H_DUPLICATE_RISK",
            passed=passed,
            evidence=[finding.duplicate_risk] if passed else [],
            reason="duplicate semantics were assessed" if passed else "duplicate risk was not assessed",
        )

    @staticmethod
    def _gate_i(finding: Finding, pack: Path, *, required: bool) -> GateResult:
        critique_files = list((pack / "critique").glob("*.json")) if (pack / "critique").is_dir() else []
        passed = finding.critic_verdict is CriticVerdict.CONFIRMED and bool(critique_files) if required else True
        return GateResult(
            gate="I_INDEPENDENT_CRITIC",
            passed=passed,
            evidence=[str(item.relative_to(pack)) for item in critique_files],
            reason=(
                "independent critic confirmed"
                if required and passed
                else "critic gate deferred until A-H evaluation"
                if not required
                else "independent critic did not confirm"
            ),
        )
