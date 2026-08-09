"""Bounty-first, multi-protocol hypothesis generation from observed behavior."""

from __future__ import annotations

from math import log10

from budobugs.core.identifiers import new_id
from budobugs.knowledge.vendor import BountyPrioritizer
from budobugs.models import Hypothesis, Parameter, SecurityInvariant, VendorKnowledge
from budobugs.traffic.modeler import TrafficModel

_AUTHZ_WORDS = {"admin", "role", "permission", "privilege", "member", "owner"}
_TENANT_WORDS = {"tenant", "organization", "org", "workspace", "team", "company"}
_FILE_WORDS = {"file", "upload", "download", "attachment", "preview", "share", "invite"}
_AUTH_WORDS = {"auth", "login", "logout", "session", "jwt", "token", "oauth", "mfa", "recovery", "revoke"}
_FLOW_WORDS = {
    "order",
    "checkout",
    "approve",
    "confirm",
    "cancel",
    "redeem",
    "refund",
    "transition",
    "workflow",
    "expire",
}
_CLIENT_WORDS = {"preview", "render", "search", "message", "redirect", "callback", "template"}


def _contains(material: str, words: set[str]) -> bool:
    return any(word in material for word in words)


def _priority(score: float) -> int:
    return min(99, max(1, round(35 + log10(score + 1) * 12)))


def _score(
    candidate_id: str,
    category: str,
    *,
    knowledge: VendorKnowledge | None,
    reward: float,
    probability: float,
    impact: float,
    uniqueness: float = 1.0,
    duplicate: float = 0.35,
    request_cost: float = 1.0,
    token_cost: float = 1.0,
    research_cost: float = 1.0,
) -> float:
    return BountyPrioritizer.score(
        candidate_id,
        category=category,
        expected_reward=reward,
        confirmation_probability=probability,
        business_impact=impact,
        uniqueness=uniqueness,
        duplicate_risk=duplicate,
        request_cost=request_cost,
        token_cost=token_cost,
        research_cost=research_cost,
        knowledge=knowledge,
    ).score


def generate_hypotheses(
    engagement_id: str,
    model: TrafficModel,
    knowledge: VendorKnowledge | None = None,
) -> tuple[list[SecurityInvariant], list[Hypothesis]]:
    """Create falsifiable candidates across identity, state, protocol, file, and client boundaries."""

    invariants: list[SecurityInvariant] = []
    hypotheses: list[Hypothesis] = []
    seen: set[tuple[str, str]] = set()

    def add(
        *,
        family_id: str,
        title: str,
        vulnerability_class: str,
        statement: str,
        protected_asset: str,
        trust_boundary: str,
        enforcement_point: str,
        violation_signal: str,
        rationale: str,
        prerequisites: list[str],
        change: str,
        control: str,
        category: str,
        validator_id: str,
        skill_name: str,
        protocol: str,
        parameter_location: str,
        root_cause_hint: str,
        reward: float,
        probability: float,
        impact: float,
        uniqueness: float = 1.0,
        duplicate: float = 0.35,
        request_cost: float = 1.0,
        token_cost: float = 1.0,
        research_cost: float = 1.0,
    ) -> None:
        dedupe_key = (family_id, vulnerability_class)
        if dedupe_key in seen:
            return
        seen.add(dedupe_key)
        invariant = SecurityInvariant(
            invariant_id=new_id("inv"),
            statement=statement,
            protected_asset=protected_asset,
            trust_boundary=trust_boundary,
            enforcement_point=enforcement_point,
            violation_signal=violation_signal,
        )
        candidate_id = new_id("hyp")
        bounty_score = _score(
            candidate_id,
            category,
            knowledge=knowledge,
            reward=reward,
            probability=probability,
            impact=impact,
            uniqueness=uniqueness,
            duplicate=duplicate,
            request_cost=request_cost,
            token_cost=token_cost,
            research_cost=research_cost,
        )
        invariants.append(invariant)
        hypotheses.append(
            Hypothesis(
                hypothesis_id=candidate_id,
                engagement_id=engagement_id,
                title=title,
                vulnerability_class=vulnerability_class,
                endpoint_family_id=family_id,
                invariant_id=invariant.invariant_id,
                rationale=rationale,
                attacker_prerequisites=prerequisites,
                proposed_single_variable_change=change,
                expected_control=control,
                protocol=protocol,  # type: ignore[arg-type]
                parameter_location=parameter_location,  # type: ignore[arg-type]
                validator_id=validator_id,
                skill_name=skill_name,
                root_cause_hint=root_cause_hint,
                bounty_score=bounty_score,
                priority=_priority(bounty_score),
            )
        )

    for family in model.endpoint_families:
        route = family.path_template.lower()
        material = " ".join([route, *family.parameter_names]).lower()
        parameters = model.parameters.get(family.family_id, [])
        identity_parameters = [
            item
            for item in parameters
            if item.dynamic_kind in {"id", "uuid"}
            or any(marker in item.name.lower() for marker in ("id", "uuid", "key", "file", "token"))
        ]
        successful = any(200 <= status < 300 for status in family.status_baseline)
        cross_account = any(item.get("endpoint_family_id") == family.family_id for item in model.account_differences)
        parameter = identity_parameters[0] if identity_parameters else None
        location = parameter.location if isinstance(parameter, Parameter) else "none"

        if identity_parameters and successful:
            add(
                family_id=family.family_id,
                title=f"Object-bound authorization candidate on {family.path_template}",
                vulnerability_class="horizontal-authorization",
                statement="An account may access only objects explicitly authorized for that account and tenant.",
                protected_asset=f"object represented by {family.path_template}",
                trust_boundary="account, role, tenant, and object ownership boundary",
                enforcement_point=f"{family.method} {family.path_template}",
                violation_signal=(
                    "one account obtains a second self-owned account's private object after one identifier changes"
                ),
                rationale=(
                    "An observed object-shaped parameter and successful baseline justify a two-account "
                    "differential test; "
                    "HTTP success alone is not evidence."
                ),
                prerequisites=["two self-owned test accounts", "one harmless object owned by each account"],
                change=f"change only {location} parameter {parameter.name if parameter else '<identifier>'}",
                control="own-object success, cross-object denial, anonymous/public control, and exact repeat",
                category="authorization",
                validator_id="authorization-differential",
                skill_name="authz-business-logic",
                protocol="graphql" if location == "graphql" else "rest",
                parameter_location=location,
                root_cause_hint=f"object-policy:{family.path_template}",
                reward=1500,
                probability=0.72 if cross_account else 0.52,
                impact=1.25,
                duplicate=0.30,
            )

        if _contains(material, _AUTHZ_WORDS) and successful:
            add(
                family_id=family.family_id,
                title=f"Role/function authorization candidate on {family.path_template}",
                vulnerability_class="vertical-authorization",
                statement=(
                    "Low-privilege roles must not invoke privileged functions hidden or denied by product policy."
                ),
                protected_asset=f"privileged function {family.path_template}",
                trust_boundary="low-privilege to administrative role boundary",
                enforcement_point=f"{family.method} {family.path_template}",
                violation_signal="a low-privilege account reproduces the privileged account's capability",
                rationale=(
                    "The route or parameter semantics indicate a role-sensitive function that merits "
                    "an A/B role control."
                ),
                prerequisites=["self-owned low-privilege and privileged test accounts"],
                change="change only the authenticated role while keeping request and test object constant",
                control="privileged normal flow and low-privilege equivalent denial",
                category="authorization",
                validator_id="vertical-authorization",
                skill_name="authz-business-logic",
                protocol="rest",
                parameter_location=location,
                root_cause_hint=f"role-policy:{family.path_template}",
                reward=2200,
                probability=0.52,
                impact=1.45,
                uniqueness=1.15,
            )

        if _contains(material, _TENANT_WORDS):
            add(
                family_id=family.family_id,
                title=f"Cross-tenant isolation candidate on {family.path_template}",
                vulnerability_class="cross-tenant-authorization",
                statement="Objects and functions must remain isolated between explicitly distinct test tenants.",
                protected_asset=f"tenant-bound resource at {family.path_template}",
                trust_boundary="tenant boundary",
                enforcement_point=f"{family.method} {family.path_template}",
                violation_signal=(
                    "tenant B accesses tenant A's self-owned test resource after only tenant/object context changes"
                ),
                rationale=(
                    "Tenant-like semantics were observed and require server-side rather than client-side "
                    "isolation proof."
                ),
                prerequisites=["two self-controlled tenants", "one harmless resource per tenant"],
                change="change one tenant or tenant-owned object reference",
                control="same-tenant normal flow, cross-tenant denial, repeat, and public/share refutation",
                category="authorization",
                validator_id="cross-tenant-authorization",
                skill_name="authz-business-logic",
                protocol="rest",
                parameter_location=location,
                root_cause_hint=f"tenant-policy:{family.path_template}",
                reward=2800,
                probability=0.48,
                impact=1.6,
                uniqueness=1.25,
            )

        if _contains(material, _FILE_WORDS):
            add(
                family_id=family.family_id,
                title=f"File/share lifecycle authorization candidate on {family.path_template}",
                vulnerability_class="file-share-authorization",
                statement=(
                    "Upload, download, preview, share, invite, revoke, and expiry must enforce the same owner policy."
                ),
                protected_asset="self-owned test file and its sharing metadata",
                trust_boundary="file owner, recipient, role, tenant, and revoked-share boundary",
                enforcement_point=f"{family.method} {family.path_template}",
                violation_signal="an unauthorized or revoked test identity can still consume a private file capability",
                rationale=(
                    "File/share vocabulary is high-value because authorization frequently diverges across "
                    "lifecycle entry points."
                ),
                prerequisites=["two self-owned accounts", "one harmless text fixture"],
                change="change one file/share identifier or one share lifecycle state",
                control="owner access, unauthorized denial, revoked/expired denial, repeat, and cleanup",
                category="file-workflow",
                validator_id="file-share-lifecycle",
                skill_name="client-file-workflows",
                protocol="rest",
                parameter_location=location,
                root_cause_hint=f"file-policy:{family.path_template}",
                reward=1800,
                probability=0.58,
                impact=1.3,
                uniqueness=1.15,
                request_cost=1.15,
            )

        if _contains(material, _AUTH_WORDS):
            add(
                family_id=family.family_id,
                title=f"Authentication/session lifecycle candidate on {family.path_template}",
                vulnerability_class="authentication-session",
                statement=(
                    "Revocation, logout, expiry, role changes, and recovery must invalidate prior capabilities "
                    "consistently."
                ),
                protected_asset="authenticated session and role-bound capabilities",
                trust_boundary="anonymous, authenticated, refreshed, revoked, and recovered states",
                enforcement_point=f"{family.method} {family.path_template}",
                violation_signal="an old test session retains a protected capability after explicit invalidation",
                rationale=(
                    "Authentication/session vocabulary merits a state-before/state-after control, without "
                    "credential guessing."
                ),
                prerequisites=["one self-owned test account and its disposable session"],
                change="change only session lifecycle state, protocol version, or role assignment",
                control=(
                    "fresh session normal flow, explicit revoke/logout, repeated old-session denial, "
                    "and new-session recovery"
                ),
                category="authentication-session",
                validator_id="session-lifecycle",
                skill_name="api-auth-session",
                protocol="rest",
                parameter_location=location,
                root_cause_hint=f"session-policy:{family.path_template}",
                reward=2400,
                probability=0.50,
                impact=1.5,
                uniqueness=1.2,
            )

        transition = next(
            (item for item in model.state_transitions if item.endpoint_family_id == family.family_id),
            None,
        )
        if family.method in {"POST", "PUT", "PATCH", "DELETE"} and (
            transition is not None or _contains(material, _FLOW_WORDS)
        ):
            add(
                family_id=family.family_id,
                title=f"Workflow order/replay invariant candidate on {family.path_template}",
                vulnerability_class="business-logic-workflow",
                statement=(
                    "Multi-step operations must enforce prerequisites, allowed transitions, replay, "
                    "revocation, and expiry."
                ),
                protected_asset=f"business state changed by {family.path_template}",
                trust_boundary="workflow state and actor capability boundary",
                enforcement_point=f"{family.method} {family.path_template}",
                violation_signal=(
                    "a self-owned object reaches an otherwise impossible state or repeats a one-time effect"
                ),
                rationale=(
                    "Observed mutation/state semantics justify safe reversible state-order and idempotency checks."
                ),
                prerequisites=["one self-owned disposable test object", "documented normal workflow"],
                change="skip, reorder, replay, revoke, or expire exactly one workflow step",
                control=(
                    "documented sequence, invalid sequence denial, repeat, strongest normal explanation, and cleanup"
                ),
                category="business-logic",
                validator_id="business-workflow",
                skill_name="authz-business-logic",
                protocol="rest",
                parameter_location=location,
                root_cause_hint=f"workflow-policy:{family.path_template}",
                reward=2600,
                probability=0.55,
                impact=1.55,
                uniqueness=1.35,
                request_cost=1.3,
                research_cost=1.4,
            )

        if family.method == "GET" and _contains(material, _CLIENT_WORDS):
            add(
                family_id=family.family_id,
                title=f"Client trust-boundary candidate on {family.path_template}",
                vulnerability_class="client-side-trust",
                statement=(
                    "Untrusted values must not reach an executable DOM, navigation, messaging, or API trust sink."
                ),
                protected_asset="test browser origin and authenticated client state",
                trust_boundary="untrusted input to browser execution/navigation boundary",
                enforcement_point=f"browser rendering of {family.path_template}",
                violation_signal="an inert marker reaches a proven sink while an escaped negative control does not",
                rationale=(
                    "Client-facing render semantics require a browser source-to-sink proof; "
                    "reflection alone will be KILLed."
                ),
                prerequisites=["isolated Playwright context", "inert marker"],
                change="replace one rendered input with an inert DOM marker",
                control=(
                    "escaped rendering, repeat DOM observation, CSP/CORS/CSRF preconditions, and no external callback"
                ),
                category="client-side",
                validator_id="client-trust",
                skill_name="client-file-workflows",
                protocol="browser",
                parameter_location=location,
                root_cause_hint=f"client-sink:{family.path_template}",
                reward=900,
                probability=0.38,
                impact=0.85,
                duplicate=0.55,
            )

    websocket_links = [
        item["api_or_route_url"]
        for item in model.frontend_api_links
        if item.get("api_or_route_url", "").startswith(("ws://", "wss://"))
    ]
    for url in websocket_links:
        family_id = f"websocket:{url}"
        add(
            family_id=family_id,
            title=f"WebSocket authentication/authorization candidate on {url}",
            vulnerability_class="websocket-authorization",
            statement=(
                "WebSocket handshakes and every message must preserve session, origin, object, "
                "and tenant authorization."
            ),
            protected_asset="WebSocket subscription and message data",
            trust_boundary="HTTP session/origin to persistent WebSocket channel",
            enforcement_point=url,
            violation_signal="a revoked or unauthorized test identity receives another test object's message",
            rationale="A browser-observed WebSocket endpoint requires handshake and message-level controls.",
            prerequisites=["two self-owned accounts or one disposable revoked session"],
            change="change one account, object subscription, origin, or revocation state",
            control="authorized subscription, unauthorized denial, repeat, and connection teardown",
            category="authentication-session",
            validator_id="websocket-session-authorization",
            skill_name="api-auth-session",
            protocol="websocket",
            parameter_location="none",
            root_cause_hint=f"websocket-policy:{url}",
            reward=1900,
            probability=0.42,
            impact=1.3,
            uniqueness=1.3,
            research_cost=1.3,
        )

    return invariants, sorted(hypotheses, key=lambda item: (item.bounty_score, item.priority), reverse=True)
