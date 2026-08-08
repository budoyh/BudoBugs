from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from budobugs.core.paths import PathBoundaryError, safe_join
from budobugs.core.policy import target_allowed
from budobugs.core.redaction import contains_unredacted_secret, redact_headers, redact_text
from budobugs.models import Engagement, EngagementMode, HealthStatus, Target, ToolRequest
from budobugs.tools.health import check_tool
from budobugs.tools.registry import ToolRegistry


def test_engagement_schema_rejects_unsafe_identifiers_and_unapproved_urls() -> None:
    base = {
        "platform": "local",
        "vendor": "fixture",
        "user_authorization_attestation": "explicit local test authorization",
        "root_targets": [Target(uri="http://127.0.0.1:8765")],
        "selected_mode": EngagementMode.LAB,
    }
    with pytest.raises(ValidationError):
        Engagement(engagement_id="../escape", **base)
    with pytest.raises(ValidationError):
        Engagement(
            engagement_id="safe-id",
            root_targets=[Target(uri="relative/path")],
            **{key: value for key, value in base.items() if key != "root_targets"},
        )


def test_lab_target_isolation_blocks_public_and_excluded_hosts(lab_engagement: Engagement) -> None:
    assert target_allowed(lab_engagement, "http://127.0.0.1:8765/api/objects/1").allowed
    assert not target_allowed(lab_engagement, "https://example.com").allowed
    excluded = lab_engagement.model_copy(update={"excluded_targets": ["127.0.0.1"]})
    assert not target_allowed(excluded, "http://127.0.0.1:8765/api/objects/1").allowed


def test_safe_join_prevents_artifact_path_traversal(tmp_path: Path) -> None:
    assert safe_join(tmp_path, "evidence", "receipt.json").is_relative_to(tmp_path.resolve())
    with pytest.raises(PathBoundaryError):
        safe_join(tmp_path, "..", "outside.txt")


def test_redaction_removes_headers_tokens_and_pii() -> None:
    text = "Bearer abcdefghijklmnop user@example.com"
    redacted = redact_text(text)
    assert redacted is not None
    assert "abcdefghijklmnop" not in redacted
    assert contains_unredacted_secret(redacted) == []
    assert "fixture-cookie" not in redact_headers({"Cookie": "fixture-cookie"})["Cookie"]


def test_secret_scan_does_not_classify_digit_windows_inside_opaque_tokens() -> None:
    sha256_like = "a1f48b13912345678c06b7e2d50d579e41612345678901234506eced931f"
    assert contains_unredacted_secret(sha256_like) == []


def test_redaction_detects_contextual_high_entropy_credentials_without_breaking_the_key() -> None:
    payload = '"access_token":"Z4G6z7pWQ92axYt5vLmE3sR8"'
    redacted = redact_text(payload)
    assert redacted is not None
    assert '"access_token":' in redacted
    assert "Z4G6z7pWQ92axYt5vLmE3sR8" not in redacted
    assert contains_unredacted_secret(payload) == ["credential"]


def test_tool_request_rejects_command_newline_injection() -> None:
    with pytest.raises(ValidationError):
        ToolRequest(
            invocation_id="invoke-001",
            run_id="run-001",
            engagement_id="lab-fixture-001",
            tool_name="fixture",
            arguments=["--flag\nmalicious"],
            purpose="safe test",
            output_directory="tool-output",
        )


async def test_manual_tool_health_prioritizes_license_over_credentials(repository_root: Path) -> None:
    registry = ToolRegistry.load(repository_root / "tools" / "registry")
    kali = registry.get("kali-mcp")
    caido = registry.get("caido")

    assert (await check_tool(kali)).status is HealthStatus.NEEDS_LICENSE
    assert (await check_tool(caido)).status is HealthStatus.NEEDS_CREDENTIAL
