"""High-signal authorization and business-object hypothesis generation."""

from __future__ import annotations

from budobugs.core.identifiers import new_id
from budobugs.models import Hypothesis, SecurityInvariant
from budobugs.traffic.modeler import TrafficModel


def generate_hypotheses(
    engagement_id: str,
    model: TrafficModel,
) -> tuple[list[SecurityInvariant], list[Hypothesis]]:
    invariants: list[SecurityInvariant] = []
    hypotheses: list[Hypothesis] = []
    for family in model.endpoint_families:
        if "{id}" not in family.path_template and "{uuid}" not in family.path_template:
            continue
        invariant = SecurityInvariant(
            invariant_id=new_id("inv"),
            statement="An authenticated account may access only objects explicitly authorized for it.",
            protected_asset=f"object represented by {family.path_template}",
            trust_boundary="authenticated account or tenant boundary",
            enforcement_point=f"{family.method} {family.path_template}",
            violation_signal="a different account obtains protected object content after only the object id changes",
        )
        invariants.append(invariant)
        status_codes = set(family.status_baseline)
        if 200 not in status_codes:
            continue
        cross_account = [item for item in model.account_differences if item["endpoint_family_id"] == family.family_id]
        rationale = (
            "Object identifier is present and at least one request returned success. "
            "A controlled two-account exchange is required; HTTP 200 alone is not evidence."
        )
        priority = 90 if cross_account else 70
        hypotheses.append(
            Hypothesis(
                hypothesis_id=new_id("hyp"),
                engagement_id=engagement_id,
                title=f"Cross-account object access candidate on {family.path_template}",
                vulnerability_class="IDOR/BOLA",
                endpoint_family_id=family.family_id,
                invariant_id=invariant.invariant_id,
                rationale=rationale,
                attacker_prerequisites=[
                    "authenticated low-privilege test account",
                    "another self-owned test object",
                ],
                proposed_single_variable_change="replace only the object identifier while holding account B constant",
                expected_control=(
                    "account B receives denial for account A private objects but can access documented public objects"
                ),
                priority=priority,
            )
        )
    return invariants, sorted(hypotheses, key=lambda item: item.priority, reverse=True)
