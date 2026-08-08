"""Authorization-bound target and tool policy decisions."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from budobugs.core.identifiers import new_id
from budobugs.models import Engagement, EngagementMode, MutationLevel, ResourceRisk, ToolDefinition

_MUTATION_ORDER = {
    MutationLevel.NONE: 0,
    MutationLevel.LOW: 1,
    MutationLevel.MEDIUM: 2,
    MutationLevel.HIGH: 3,
}
_RISK_ORDER = {ResourceRisk.LOW: 0, ResourceRisk.MEDIUM: 1, ResourceRisk.HIGH: 2}


class PolicyDenied(PermissionError):
    """Raised when a target or tool exceeds the active engagement."""


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    decision_id: str
    allowed: bool
    reason: str


def _origin(value: str) -> tuple[str, str, int] | None:
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    effective_port = port or (443 if parsed.scheme.lower() == "https" else 80)
    return parsed.scheme.lower(), parsed.hostname.lower().rstrip("."), effective_port


def _is_loopback_or_private(host: str) -> bool:
    if host in {"localhost", "host.docker.internal"} or "." not in host:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host.endswith((".localhost", ".local", ".test"))
    return address.is_loopback or address.is_private or address.is_link_local


def target_allowed(engagement: Engagement, target: str) -> PolicyDecision:
    """Evaluate a URL or source path without DNS expansion."""

    decision_id = new_id("policy")
    if engagement.selected_mode is EngagementMode.SOURCE:
        requested = Path(target).resolve()
        for root in engagement.root_targets:
            allowed_root = Path(root.uri).resolve()
            if requested == allowed_root or allowed_root in requested.parents:
                return PolicyDecision(decision_id, True, "source path is under an authorized root")
        return PolicyDecision(decision_id, False, "source path escapes authorized roots")

    parsed_target = urlsplit(target)
    if parsed_target.scheme.lower() not in {"http", "https"}:
        return PolicyDecision(decision_id, False, "network target must use HTTP or HTTPS")
    target_origin = _origin(target)
    if target_origin is None:
        return PolicyDecision(decision_id, False, "network target must be a credential-free absolute HTTP(S) URL")
    target_scheme, target_host, target_port = target_origin
    if any(target_host == excluded or target_host.endswith(f".{excluded}") for excluded in engagement.excluded_targets):
        return PolicyDecision(decision_id, False, "target matches excluded_targets")
    root_origins = {_origin(item.uri) for item in engagement.root_targets}
    if target_origin in root_origins:
        allowed = True
    else:
        host_allowed = any(
            target_host == suffix or target_host.endswith(f".{suffix}")
            for suffix in engagement.optional_allowed_subdomains
        )
        allowed = host_allowed and any(
            origin is not None and (target_scheme, target_port) == (origin[0], origin[2]) for origin in root_origins
        )
    if not allowed:
        return PolicyDecision(decision_id, False, "target is outside engagement roots")
    if engagement.selected_mode is EngagementMode.LAB and not _is_loopback_or_private(target_host):
        return PolicyDecision(decision_id, False, "lab mode blocks public network targets")
    return PolicyDecision(decision_id, True, "target is inside the authorized engagement")


def tool_allowed(
    engagement: Engagement,
    tool: ToolDefinition,
    target: str | None,
) -> PolicyDecision:
    decision_id = new_id("policy")
    if engagement.selected_mode not in tool.supported_modes:
        return PolicyDecision(decision_id, False, "tool does not support the selected mode")
    if target is not None:
        scope = target_allowed(engagement, target)
        if not scope.allowed:
            return scope
    if engagement.selected_mode is EngagementMode.PROGRAM:
        if _MUTATION_ORDER[tool.mutation_level] > _MUTATION_ORDER[MutationLevel.LOW]:
            return PolicyDecision(decision_id, False, "program mode blocks medium/high mutation")
        if _RISK_ORDER[tool.resource_risk] > _RISK_ORDER[ResourceRisk.MEDIUM]:
            return PolicyDecision(decision_id, False, "program mode blocks high resource risk")
        if tool.profile == "lab-ai":
            return PolicyDecision(decision_id, False, "program mode blocks lab-ai autonomous execution")
    return PolicyDecision(decision_id, True, "tool request satisfies mode and scope policy")


def require_allowed(decision: PolicyDecision) -> None:
    if not decision.allowed:
        raise PolicyDenied(f"{decision.decision_id}: {decision.reason}")
