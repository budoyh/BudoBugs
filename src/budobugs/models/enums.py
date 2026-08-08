"""Closed enums shared by storage, policy, tools, and reports."""

from enum import StrEnum


class EngagementMode(StrEnum):
    LAB = "lab"
    PROGRAM = "program"
    SOURCE = "source"


class AuthorizationStatus(StrEnum):
    DRAFT = "draft"
    AUTHORIZED = "authorized"
    REVOKED = "revoked"


class MutationLevel(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ResourceRisk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class CandidateStatus(StrEnum):
    SIGNAL = "SIGNAL"
    HYPOTHESIS = "HYPOTHESIS"
    TEST_PLANNED = "TEST_PLANNED"
    VALIDATING = "VALIDATING"
    THEORETICAL = "THEORETICAL"
    CONFIRMED = "CONFIRMED"
    REFUTED = "REFUTED"
    HOLD = "HOLD"
    KILL = "KILL"
    OUT_OF_TASK = "OUT_OF_TASK"
    READY_FOR_HUMAN_REVIEW = "READY_FOR_HUMAN_REVIEW"
    ARCHIVED = "ARCHIVED"


class PhaseName(StrEnum):
    INIT = "INIT"
    TASK_MODEL = "TASK_MODEL"
    PASSIVE_RECON = "PASSIVE_RECON"
    SURFACE_MAP = "SURFACE_MAP"
    NORMAL_BROWSER_EXPLORATION = "NORMAL_BROWSER_EXPLORATION"
    TRAFFIC_MODEL = "TRAFFIC_MODEL"
    INVARIANT_MODEL = "INVARIANT_MODEL"
    HYPOTHESIS_GENERATION = "HYPOTHESIS_GENERATION"
    PRIORITIZATION = "PRIORITIZATION"
    VALIDATION = "VALIDATION"
    NEGATIVE_CONTROL = "NEGATIVE_CONTROL"
    REFUTATION = "REFUTATION"
    EVIDENCE_PACK = "EVIDENCE_PACK"
    INDEPENDENT_CRITIC = "INDEPENDENT_CRITIC"
    REPORT_DRAFT = "REPORT_DRAFT"
    HUMAN_REVIEW_READY = "HUMAN_REVIEW_READY"


class CriticVerdict(StrEnum):
    CONFIRMED = "CONFIRMED"
    HOLD = "HOLD"
    KILL = "KILL"


class Severity(StrEnum):
    INFO = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HealthStatus(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    NEEDS_RUNTIME = "NEEDS_RUNTIME"
    NEEDS_CREDENTIAL = "NEEDS_CREDENTIAL"
    NEEDS_LICENSE = "NEEDS_LICENSE"
    UNSUPPORTED = "UNSUPPORTED"


class ToolCategory(StrEnum):
    RUNTIME = "runtime"
    PASSIVE_RECON = "passive-recon"
    ACTIVE_RECON = "active-recon"
    BROWSER = "browser"
    PROXY = "proxy"
    SOURCE = "source"
    SUPPLY_CHAIN = "supply-chain"
    DATA = "data"
    LAB = "lab"
    LAB_AI = "lab-ai"
