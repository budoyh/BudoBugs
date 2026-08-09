"""Persistent vendor learning and same-fix candidate de-duplication."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable

from budobugs.core.identifiers import new_id
from budobugs.models import (
    BountyScore,
    DuplicateAssessmentDecision,
    Engagement,
    HistoricalDuplicateAssessment,
    OutcomePrior,
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


def _new_values(existing: Iterable[str], values: Iterable[str]) -> list[str]:
    known = set(existing)
    return [value for value in _merge([], values) if value not in known]


def feature_key(value: str | None) -> str | None:
    """Normalize a non-secret feature label used to scope learned feedback."""

    if not value:
        return None
    normalized = _SAFE_PART.sub("-", value.strip().lower()).strip("-._")
    return normalized[:180] or None


def _scope_keys(
    vulnerability_class: str | None,
    root_cause_key: str | None,
    feature: str | None,
) -> list[str]:
    vulnerability = feature_key(vulnerability_class)
    root = feature_key(root_cause_key)
    scoped_feature = feature_key(feature)
    keys = ["global"]
    if vulnerability:
        keys.append(f"class:{vulnerability}")
    if root:
        keys.append(f"root:{root}")
    if scoped_feature:
        keys.append(f"feature:{scoped_feature}")
    if vulnerability and root:
        keys.append(f"class-root:{vulnerability}:{root}")
    if vulnerability and scoped_feature:
        keys.append(f"class-feature:{vulnerability}:{scoped_feature}")
    if vulnerability and root and scoped_feature:
        keys.append(f"class-root-feature:{vulnerability}:{root}:{scoped_feature}")
    return keys


def _traffic_features(model: TrafficModel) -> list[str]:
    features: list[str] = []
    for family in model.endpoint_families:
        parts = [part for part in family.path_template.split("/") if part and not part.startswith("{")]
        if parts:
            features.append(f"route:{'/'.join(parts[:2])}")
    features.extend(f"object:{item.object_type}" for item in model.objects)
    features.extend(f"state:{transition.to_state}" for transition in model.state_transitions)
    return features


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
        # Pydantic defaults make v1 records readable; the next write upgrades them.
        knowledge.schema_version = 2
        knowledge.updated_at = utc_now()
        self.store.save("vendor-knowledge", knowledge.vendor_key, knowledge)
        return knowledge

    @staticmethod
    def prior_for(
        knowledge: VendorKnowledge,
        *,
        vulnerability_class: str | None = None,
        root_cause_key: str | None = None,
        feature: str | None = None,
    ) -> OutcomePrior | None:
        """Return the most specific observed feedback bucket, never a guessed one."""

        for key in reversed(_scope_keys(vulnerability_class, root_cause_key, feature)):
            prior = knowledge.outcome_priors.get(key)
            if prior is not None and prior.observations:
                return prior
        return None

    def update_from_traffic(
        self,
        engagement: Engagement,
        model: TrafficModel,
        *,
        candidate_ids: Iterable[str] = (),
    ) -> VendorKnowledge:
        knowledge = self.load(engagement)
        endpoint_values = [f"{item.method} {item.host}{item.path_template}" for item in model.endpoint_families]
        javascript_values = [
            item.get("value", "") for item in model.api_schema_clues if item.get("kind") == "javascript-endpoint"
        ]
        schema_values = [f"{item.get('kind', 'schema')}:{item.get('value', '')}" for item in model.api_schema_clues]
        features = _traffic_features(model)
        changes = [
            *(f"new-endpoint:{item}" for item in _new_values(knowledge.endpoints, endpoint_values)),
            *(f"new-feature:{item}" for item in _new_values(knowledge.product_features, features)),
            *(f"new-javascript-api:{item}" for item in _new_values(knowledge.javascript_api_clues, javascript_values)),
            *(f"new-api-schema:{item}" for item in _new_values(knowledge.api_schema_clues, schema_values)),
        ]
        anomalies = [
            f"endpoint-anomaly:{item.method} {item.path_template}"
            for item in model.endpoint_families
            if item.anomaly_score >= 0.5
        ]
        anomalies.extend(
            f"account-difference:{item.get('endpoint_family_id', 'unknown')}"
            for item in model.account_differences
            if item.get("left_status") != item.get("right_status") or item.get("same_response_hash") is False
        )
        knowledge.endpoints = _merge(
            knowledge.endpoints,
            endpoint_values,
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
            javascript_values,
        )
        knowledge.api_schema_clues = _merge(
            knowledge.api_schema_clues,
            schema_values,
        )
        knowledge.product_features = _merge(knowledge.product_features, features)
        knowledge.change_observations = _merge(knowledge.change_observations, changes)
        knowledge.anomalous_behaviors = _merge(knowledge.anomalous_behaviors, anomalies)
        tested = list(candidate_ids)
        knowledge.tested_candidate_ids = _merge(knowledge.tested_candidate_ids, tested)
        knowledge.unfinished_candidate_ids = [item for item in knowledge.unfinished_candidate_ids if item not in tested]
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
            assessment = RootCauseDeduper.assess_historical(outcome, knowledge)
            if assessment is not None:
                knowledge.historical_duplicate_assessments = [
                    *knowledge.historical_duplicate_assessments[-499:],
                    assessment,
                ]
                if assessment.decision is DuplicateAssessmentDecision.REGRESSION:
                    knowledge.regression_finding_ids = _merge(knowledge.regression_finding_ids, [outcome.finding_id])
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
        scope_keys = _scope_keys(
            outcome.vulnerability_class,
            outcome.root_cause_key,
            outcome.feature_key or outcome.endpoint_family,
        )
        for key in scope_keys:
            prior = knowledge.outcome_priors.setdefault(key, OutcomePrior())
            prior.observations += 1
            if outcome.reward > 0:
                prior.reward_total += outcome.reward
                prior.reward_count += 1
        if outcome.status.value == "accepted":
            knowledge.acceptance_prior = min(0.95, knowledge.acceptance_prior + 0.08)
            knowledge.duplicate_risk_prior = max(0.05, knowledge.duplicate_risk_prior - 0.03)
            for key in scope_keys:
                knowledge.outcome_priors[key].accepted += 1
        elif outcome.status.value == "rejected":
            knowledge.acceptance_prior = max(0.05, knowledge.acceptance_prior - 0.10)
            knowledge.rejected_finding_ids = _merge(knowledge.rejected_finding_ids, [outcome.finding_id])
            for key in scope_keys:
                knowledge.outcome_priors[key].rejected += 1
            # Platform feedback is evidence only for the affected feature/class/root scope.
            # Keeping it out of the legacy global list avoids suppressing unrelated work.
            scoped_key = scope_keys[-1]
            existing_rules = knowledge.scoped_false_positive_rules.get(scoped_key, [])
            knowledge.scoped_false_positive_rules[scoped_key] = _merge(existing_rules, [outcome.reason], limit=100)
        elif outcome.status.value == "duplicate":
            knowledge.duplicate_risk_prior = min(0.95, knowledge.duplicate_risk_prior + 0.12)
            knowledge.duplicate_finding_ids = _merge(knowledge.duplicate_finding_ids, [outcome.finding_id])
            for key in scope_keys:
                knowledge.outcome_priors[key].duplicates += 1
        else:
            knowledge.impact_multiplier = max(0.25, knowledge.impact_multiplier * 0.9)
            for key in scope_keys:
                knowledge.outcome_priors[key].downgraded += 1
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
        vulnerability_class: str | None = None,
        root_cause_key: str | None = None,
        feature: str | None = None,
    ) -> BountyScore:
        confirmation_multiplier, impact_multiplier = cls.CATEGORY_MULTIPLIERS.get(category, (1.0, 1.0))
        if knowledge is not None:
            confirmation_probability = (confirmation_probability + knowledge.acceptance_prior) / 2
            duplicate_risk = (duplicate_risk + knowledge.duplicate_risk_prior) / 2
            impact_multiplier *= knowledge.impact_multiplier
            prior = VendorKnowledgeBase.prior_for(
                knowledge,
                vulnerability_class=vulnerability_class or category,
                root_cause_key=root_cause_key,
                feature=feature,
            )
            if prior is not None:
                acceptance = (prior.accepted + 1) / (prior.observations + 2)
                duplicate = (prior.duplicates + 1) / (prior.observations + 2)
                confirmation_probability = (confirmation_probability + acceptance) / 2
                duplicate_risk = (duplicate_risk + duplicate) / 2
                if prior.downgraded:
                    impact_multiplier *= max(0.5, 1 - prior.downgraded / prior.observations * 0.25)
                if prior.reward_count:
                    historical_reward = prior.reward_total / prior.reward_count
                    expected_reward = (expected_reward + historical_reward) / 2
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

    @staticmethod
    def assess_historical(
        outcome: ValidationOutcome,
        knowledge: VendorKnowledge,
    ) -> HistoricalDuplicateAssessment | None:
        """Compare a confirmed local result with prior platform feedback.

        ``cluster`` is intentionally broader: it groups entry points that warrant one
        repair investigation.  A platform duplicate needs the stricter target/method
        comparison below, and a previously fixed match is preserved as a regression.
        """

        if outcome.decision.value != "CONFIRMED":
            return None
        for historical in reversed(knowledge.outcomes):
            same_class = bool(
                historical.vulnerability_class
                and feature_key(historical.vulnerability_class) == feature_key(outcome.vulnerability_class)
            )
            same_root = bool(
                historical.root_cause_key
                and feature_key(historical.root_cause_key) == feature_key(outcome.root_cause_key)
            )
            same_feature = bool(
                historical.feature_key and feature_key(historical.feature_key) == feature_key(outcome.affected_feature)
            )
            same_method = bool(
                historical.exploitation_method
                and feature_key(historical.exploitation_method) == feature_key(outcome.validator_id)
            )
            if not (same_class and same_root and same_feature):
                continue
            if historical.previously_fixed:
                decision = DuplicateAssessmentDecision.REGRESSION
                rationale = "same class, feature, and root cause were recorded as previously fixed"
            elif same_method:
                decision = DuplicateAssessmentDecision.PLATFORM_DUPLICATE
                rationale = "same class, feature, root cause, and exploitation method as historical platform outcome"
            else:
                decision = DuplicateAssessmentDecision.HOLD
                rationale = (
                    "same class, feature, and root cause but exploitation method differs; retain as a separate review"
                )
            return HistoricalDuplicateAssessment(
                assessment_id=new_id("duplicate-assessment"),
                finding_id=outcome.finding_id,
                historical_finding_id=historical.finding_id,
                decision=decision,
                same_vulnerability_class=same_class,
                same_feature=same_feature,
                same_root_cause=same_root,
                same_exploitation_method=same_method,
                rationale=rationale,
            )
        return HistoricalDuplicateAssessment(
            assessment_id=new_id("duplicate-assessment"),
            finding_id=outcome.finding_id,
            decision=DuplicateAssessmentDecision.SEPARATE_INSTANCE,
            rationale="no historical platform outcome matched class, feature, and root cause",
        )
