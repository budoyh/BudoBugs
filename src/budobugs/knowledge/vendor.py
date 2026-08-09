"""Persistent vendor learning and same-fix candidate de-duplication."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable

from budobugs.core.identifiers import new_id
from budobugs.models import (
    BountyScore,
    Engagement,
    PlatformOutcome,
    RootCauseCluster,
    ValidationOutcome,
    VendorKnowledge,
)
from budobugs.models.base import utc_now
from budobugs.storage.state import StateStore
from budobugs.traffic.modeler import TrafficModel

_SAFE_PART = re.compile(r"[^a-z0-9._-]+")


def vendor_key(platform: str, vendor: str) -> str:
    """Create a stable, non-secret key without conflating similarly named platforms."""

    left = _SAFE_PART.sub("-", platform.strip().lower()).strip("-._") or "platform"
    right = _SAFE_PART.sub("-", vendor.strip().lower()).strip("-._") or "vendor"
    return f"{left[:48]}--{right[:72]}"


def _merge(existing: list[str], additions: Iterable[str], *, limit: int = 5000) -> list[str]:
    values = list(existing)
    seen = set(values)
    for value in additions:
        normalized = str(value).strip()
        if normalized and normalized not in seen:
            values.append(normalized)
            seen.add(normalized)
            if len(values) >= limit:
                break
    return values


class VendorKnowledgeBase:
    """SQLite-backed knowledge that is reused across all runs for one vendor."""

    def __init__(self, store: StateStore) -> None:
        self.store = store

    def load(self, engagement: Engagement) -> VendorKnowledge:
        key = vendor_key(engagement.platform, engagement.vendor)
        current = self.store.load("vendor-knowledge", key, VendorKnowledge)
        if current is not None:
            return current
        return VendorKnowledge(
            vendor_key=key,
            platform=engagement.platform,
            vendor=engagement.vendor,
        )

    def save(self, knowledge: VendorKnowledge) -> VendorKnowledge:
        knowledge.updated_at = utc_now()
        self.store.save("vendor-knowledge", knowledge.vendor_key, knowledge)
        return knowledge

    def update_from_traffic(
        self,
        engagement: Engagement,
        model: TrafficModel,
        *,
        candidate_ids: Iterable[str] = (),
    ) -> VendorKnowledge:
        knowledge = self.load(engagement)
        knowledge.endpoints = _merge(
            knowledge.endpoints,
            (f"{item.method} {item.host}{item.path_template}" for item in model.endpoint_families),
        )
        knowledge.parameters = _merge(
            knowledge.parameters,
            (
                f"{family_id}:{parameter.location}:{parameter.name}"
                for family_id, parameters in model.parameters.items()
                for parameter in parameters
                if not parameter.sensitive
            ),
        )
        knowledge.object_types = _merge(knowledge.object_types, (item.object_type for item in model.objects))
        knowledge.roles = _merge(knowledge.roles, (item.name for item in model.roles))
        knowledge.states = _merge(
            knowledge.states,
            (state for transition in model.state_transitions for state in (transition.from_state, transition.to_state)),
        )
        knowledge.javascript_api_clues = _merge(
            knowledge.javascript_api_clues,
            (item.get("value", "") for item in model.api_schema_clues if item.get("kind") == "javascript-endpoint"),
        )
        knowledge.api_schema_clues = _merge(
            knowledge.api_schema_clues,
            (f"{item.get('kind', 'schema')}:{item.get('value', '')}" for item in model.api_schema_clues),
        )
        knowledge.unfinished_candidate_ids = _merge(knowledge.unfinished_candidate_ids, candidate_ids)
        return self.save(knowledge)

    def update_from_validation(
        self,
        engagement: Engagement,
        outcomes: Iterable[ValidationOutcome],
    ) -> VendorKnowledge:
        knowledge = self.load(engagement)
        for outcome in outcomes:
            knowledge.tested_candidate_ids = _merge(knowledge.tested_candidate_ids, [outcome.candidate_id])
            knowledge.root_cause_keys = _merge(knowledge.root_cause_keys, [outcome.root_cause_key])
            if outcome.decision.value == "CONFIRMED":
                knowledge.confirmed_finding_ids = _merge(knowledge.confirmed_finding_ids, [outcome.finding_id])
                knowledge.unfinished_candidate_ids = [
                    item for item in knowledge.unfinished_candidate_ids if item != outcome.candidate_id
                ]
            elif outcome.decision.value == "KILL":
                knowledge.rejected_finding_ids = _merge(knowledge.rejected_finding_ids, [outcome.finding_id])
                rule = (
                    f"{outcome.validator_id}: {outcome.strongest_benign_explanation}"
                    if outcome.strongest_benign_explanation
                    else outcome.validator_id
                )
                knowledge.false_positive_rules = _merge(knowledge.false_positive_rules, [rule])
            else:
                knowledge.unfinished_candidate_ids = _merge(
                    knowledge.unfinished_candidate_ids,
                    [outcome.candidate_id],
                )
        return self.save(knowledge)

    def record_outcome(self, engagement: Engagement, outcome: PlatformOutcome) -> VendorKnowledge:
        knowledge = self.load(engagement)
        if outcome.vendor_key != knowledge.vendor_key:
            raise ValueError("platform outcome vendor key does not match engagement")
        if any(item.outcome_id == outcome.outcome_id for item in knowledge.outcomes):
            return knowledge
        knowledge.outcomes.append(outcome)
        if outcome.status.value == "accepted":
            knowledge.acceptance_prior = min(0.95, knowledge.acceptance_prior + 0.08)
            knowledge.duplicate_risk_prior = max(0.05, knowledge.duplicate_risk_prior - 0.03)
        elif outcome.status.value == "rejected":
            knowledge.acceptance_prior = max(0.05, knowledge.acceptance_prior - 0.10)
            knowledge.rejected_finding_ids = _merge(knowledge.rejected_finding_ids, [outcome.finding_id])
            knowledge.false_positive_rules = _merge(knowledge.false_positive_rules, [outcome.reason])
        elif outcome.status.value == "duplicate":
            knowledge.duplicate_risk_prior = min(0.95, knowledge.duplicate_risk_prior + 0.12)
            knowledge.duplicate_finding_ids = _merge(knowledge.duplicate_finding_ids, [outcome.finding_id])
        else:
            knowledge.impact_multiplier = max(0.25, knowledge.impact_multiplier * 0.9)
        return self.save(knowledge)


class BountyPrioritizer:
    """Reward-first score with vendor feedback and explicit cost denominators."""

    CATEGORY_MULTIPLIERS = {
        "authorization": (1.35, 1.25),
        "business-logic": (1.45, 1.35),
        "file-workflow": (1.30, 1.25),
        "authentication-session": (1.40, 1.35),
        "new-or-edge-feature": (1.35, 1.40),
        "client-side": (0.85, 0.80),
        "scanner-noise": (0.35, 0.35),
    }

    @classmethod
    def score(
        cls,
        candidate_id: str,
        *,
        category: str,
        expected_reward: float,
        confirmation_probability: float,
        business_impact: float,
        uniqueness: float,
        duplicate_risk: float,
        request_cost: float,
        token_cost: float,
        research_cost: float,
        knowledge: VendorKnowledge | None = None,
    ) -> BountyScore:
        confirmation_multiplier, impact_multiplier = cls.CATEGORY_MULTIPLIERS.get(category, (1.0, 1.0))
        if knowledge is not None:
            confirmation_probability = (confirmation_probability + knowledge.acceptance_prior) / 2
            duplicate_risk = (duplicate_risk + knowledge.duplicate_risk_prior) / 2
            impact_multiplier *= knowledge.impact_multiplier
        probability = min(1.0, max(0.01, confirmation_probability * confirmation_multiplier))
        impact = min(2.0, max(0.01, business_impact * impact_multiplier))
        uniqueness_value = min(2.0, max(0.01, uniqueness))
        duplicate = min(1.0, max(0.01, duplicate_risk))
        request = max(0.01, request_cost)
        token = max(0.01, token_cost)
        research = max(0.01, research_cost)
        score = expected_reward * probability * impact * uniqueness_value / (duplicate * request * token * research)
        return BountyScore(
            candidate_id=candidate_id,
            expected_reward=expected_reward,
            confirmation_probability=probability,
            business_impact=impact,
            uniqueness=uniqueness_value,
            duplicate_risk=duplicate,
            request_cost=request,
            token_cost=token,
            research_cost=research,
            score=round(score, 6),
        )


class RootCauseDeduper:
    """Merge entry points only when the same repair boundary fixes all of them."""

    @staticmethod
    def cluster(outcomes: Iterable[ValidationOutcome]) -> list[RootCauseCluster]:
        groups: dict[tuple[str, str], list[ValidationOutcome]] = defaultdict(list)
        for outcome in outcomes:
            groups[(outcome.root_cause_key.strip().lower(), outcome.repair_boundary.strip().lower())].append(outcome)
        clusters: list[RootCauseCluster] = []
        for (root_cause, repair_boundary), members in sorted(groups.items()):
            ordered = sorted(
                members,
                key=lambda item: (
                    item.decision.value != "CONFIRMED",
                    -item.confidence,
                    item.candidate_id,
                ),
            )
            clusters.append(
                RootCauseCluster(
                    cluster_id=new_id("root-cause"),
                    root_cause_key=root_cause,
                    repair_boundary=repair_boundary,
                    primary_candidate_id=ordered[0].candidate_id,
                    candidate_ids=[item.candidate_id for item in ordered],
                    finding_ids=list(dict.fromkeys(item.finding_id for item in ordered)),
                    merged_entry_points=list(dict.fromkeys(item.validator_id for item in ordered)),
                    same_fix=True,
                )
            )
        return clusters
