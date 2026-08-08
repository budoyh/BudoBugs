"""Tool registry and executor receipt contracts."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import Field, field_validator

from budobugs.models.base import BudoModel, utc_now
from budobugs.models.enums import (
    EngagementMode,
    HealthStatus,
    MutationLevel,
    ResourceRisk,
    ToolCategory,
)


class ToolDefinition(BudoModel):
    name: str
    category: ToolCategory
    source: str
    version: str
    commit: str | None = None
    license: str
    install_method: Literal["bundled", "release", "python", "go", "node", "container", "manual"]
    profile: Literal["core", "extended", "lab-ai"]
    executable: str | None = None
    container_image: str | None = None
    supported_platforms: list[Literal["windows", "linux", "wsl", "container"]]
    required_secrets: list[str] = Field(default_factory=list)
    network_behavior: list[str] = Field(default_factory=list)
    mutation_level: MutationLevel
    resource_risk: ResourceRisk
    supported_modes: list[EngagementMode]
    timeout: int = Field(default=120, ge=1, le=86400)
    concurrency: int = Field(default=1, ge=1, le=128)
    parser: str
    healthcheck: list[str] = Field(min_length=1)
    output_schema: str
    redaction_rules: list[str] = Field(default_factory=list)
    target_argument: str | None = None
    retry_count: int = Field(default=0, ge=0, le=3)
    official_checksum_url: str | None = None
    fixed_arguments: list[str] = Field(default_factory=list)
    allowed_argument_patterns: list[str] = Field(default_factory=list)

    @field_validator("allowed_argument_patterns")
    @classmethod
    def validate_argument_patterns(cls, patterns: list[str]) -> list[str]:
        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"invalid argument pattern: {pattern}") from exc
        return patterns


class ToolRequest(BudoModel):
    invocation_id: str
    run_id: str
    engagement_id: str
    tool_name: str
    target: str | None = None
    arguments: list[str] = Field(default_factory=list)
    purpose: str = Field(min_length=3, max_length=1000)
    output_directory: str
    preserve_raw_output: bool = False

    @field_validator("arguments")
    @classmethod
    def reject_control_characters(cls, arguments: list[str]) -> list[str]:
        for argument in arguments:
            if any(char in argument for char in ("\x00", "\r", "\n")):
                raise ValueError("tool arguments must not contain control characters")
        return arguments


class ToolExecutionReceipt(BudoModel):
    schema_version: int = 1
    receipt_id: str
    invocation_id: str
    run_id: str
    engagement_id: str
    tool_name: str
    executable: str
    arguments: list[str]
    target: str | None
    started_at: datetime
    completed_at: datetime = Field(default_factory=utc_now)
    exit_code: int | None
    timed_out: bool
    attempt_count: int = Field(ge=1)
    stdout_artifact: str
    stderr_artifact: str
    raw_stdout_artifact: str | None = None
    raw_stderr_artifact: str | None = None
    normalized_output_artifact: str | None = None
    stdout_sha256: str
    stderr_sha256: str
    redaction_applied: bool
    policy_decision_id: str
    status: Literal["completed", "failed", "timeout", "blocked"]
    observations: list[str] = Field(default_factory=list)


class ToolHealth(BudoModel):
    tool_name: str
    status: HealthStatus
    version: str | None = None
    message: str
    checked_at: datetime = Field(default_factory=utc_now)
