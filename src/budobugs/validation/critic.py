"""Independent rule-based critic that tries to falsify a candidate."""

from __future__ import annotations

from budobugs.core.identifiers import new_id
from budobugs.models import CriticVerdict, Critique, Finding
from budobugs.validation.gates import GateReceipt


class AdversarialCritic:
    def review(self, finding: Finding, precritic: GateReceipt) -> Critique:
        failed = [item.gate for item in precritic.gates if item.gate != "I_INDEPENDENT_CRITIC" and not item.passed]
        opposing: list[str] = []
        unresolved: list[str] = []
        additional: list[str] = []
        public_design = "CONTROL_RESULT:INTENTIONALLY_PUBLIC" in (
            finding.strongest_benign_explanation.upper().replace(" ", "")
        )
        no_delta = finding.capability_delta.strip().lower() in {"", "none", "no change", "unknown"}
        if public_design:
            opposing.append("Control evidence indicates the object is intentionally public.")
        if no_delta:
            opposing.append("The test did not establish a new attacker capability.")
        if failed:
            opposing.append(f"Evidence gates failed: {', '.join(failed)}")
            additional.append("Repair failed artifact-backed gates and rerun from a clean state.")
        if public_design or no_delta:
            verdict = CriticVerdict.KILL
            confidence = 0.99
            rationale = "The strongest benign explanation defeats the security invariant violation."
        elif failed:
            verdict = CriticVerdict.HOLD
            confidence = 0.80
            unresolved.append("The current evidence package does not close every required gate.")
            rationale = "The candidate may be valid but the evidence is incomplete."
        else:
            verdict = CriticVerdict.CONFIRMED
            confidence = min(0.99, max(0.85, finding.confidence))
            rationale = (
                "Repeated cross-account access, denial/public controls, integrity-checked artifacts, "
                "and a bounded impact establish the claimed capability delta."
            )
        return Critique(
            critique_id=new_id("critique"),
            finding_id=finding.finding_id,
            strongest_supporting_evidence=finding.requests + finding.responses,
            strongest_opposing_evidence=opposing or ["No stronger normal explanation survived the recorded controls."],
            unresolved_benign_explanations=unresolved,
            additional_tests_needed=additional,
            impact_overstated=finding.confidence < 0.5,
            test_pollution_detected=False,
            third_party_data_involved="third-party" in finding.data_exposure_scope.lower(),
            verdict=verdict,
            confidence=confidence,
            rationale=rationale,
        )
