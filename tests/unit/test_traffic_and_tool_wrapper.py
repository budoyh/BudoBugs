from __future__ import annotations

import sys
from pathlib import Path

import pytest
from tests.conftest import make_exchange

from budobugs.core.policy import PolicyDenied
from budobugs.models import Engagement, EngagementMode, ToolDefinition, ToolRequest
from budobugs.tools.registry import ToolRegistry
from budobugs.tools.wrapper import ToolExecutionError, ToolRunner
from budobugs.traffic.modeler import build_traffic_model


def test_traffic_model_groups_endpoint_family_and_id_parameter() -> None:
    model = build_traffic_model(
        [
            make_exchange(exchange_id="exchange-001", url="http://127.0.0.1:8765/api/objects/1"),
            make_exchange(exchange_id="exchange-002", url="http://127.0.0.1:8765/api/objects/2"),
        ]
    )
    assert model.endpoint_families[0].path_template == "/api/objects/{id}"
    assert {item.object_id for item in model.objects} == {"1", "2"}


def test_traffic_model_builds_roles_tenants_transitions_schemas_and_frontend_links() -> None:
    transition = make_exchange(
        exchange_id="exchange-transition",
        url="http://127.0.0.1:8765/api/workflows/1/transition",
        response='{"previous":"draft","current":"paid"}',
    ).model_copy(
        update={
            "method": "POST",
            "request_body": '{"state":"paid"}',
            "role_id": "member",
            "tenant_id": "tenant-red",
            "account_alias": "alice",
        }
    )
    html = make_exchange(
        exchange_id="exchange-html",
        url="http://127.0.0.1:8765/app",
        response="<!doctype html><script>fetch('/api/objects/1')</script>",
    ).model_copy(update={"response_headers": {"content-type": "text/html"}})
    graphql = make_exchange(
        exchange_id="exchange-graphql",
        url="http://127.0.0.1:8765/graphql",
        response='{"data":{"viewer":{"id":1}}}',
    ).model_copy(
        update={
            "method": "POST",
            "request_body": (
                '{"operationName":"Viewer","query":"query Viewer { viewer { id } }","variables":{"object_id":1}}'
            ),
        }
    )
    openapi = make_exchange(
        exchange_id="exchange-openapi",
        url="http://127.0.0.1:8765/openapi.json",
        response='{"openapi":"3.1.0","paths":{}}',
    )
    static = make_exchange(
        exchange_id="exchange-static",
        url="http://127.0.0.1:8765/site.css",
        response="body{}",
    ).model_copy(update={"response_headers": {"content-type": "text/css"}})

    model = build_traffic_model([transition, html, graphql, openapi, static])
    assert model.roles[0].role_id == "member"
    assert model.tenants[0].account_aliases == ["alice"]
    assert [(item.from_state, item.to_state) for item in model.state_transitions] == [("draft", "paid")]
    assert model.response_schemas
    assert any(item["api_or_route_url"].endswith("/api/objects/1") for item in model.frontend_api_links)
    assert {item["kind"] for item in model.api_schema_clues} >= {"graphql-operation", "openapi"}
    assert model.discarded_static_exchange_ids == ["exchange-static"]
    graphql_family = next(item for item in model.endpoint_families if item.path_template == "/graphql")
    assert {item.location for item in model.parameters[graphql_family.family_id]} >= {"graphql"}


def _definition(
    *,
    target_argument: str | None = None,
    allowed_argument_patterns: list[str] | None = None,
) -> ToolDefinition:
    return ToolDefinition(
        name="python-fixture",
        category="runtime",
        source="pytest",
        version="1",
        license="Apache-2.0",
        install_method="bundled",
        profile="core",
        executable=sys.executable,
        supported_platforms=["windows", "linux"],
        mutation_level="none",
        resource_risk="low",
        supported_modes=[EngagementMode.LAB],
        timeout=5,
        concurrency=1,
        parser="text",
        healthcheck=["--version"],
        output_schema="text",
        target_argument=target_argument,
        allowed_argument_patterns=allowed_argument_patterns or [],
    )


@pytest.mark.asyncio
async def test_tool_runner_uses_argument_vector_and_redacts_receipts(
    tmp_path: Path, lab_engagement: Engagement
) -> None:
    runner = ToolRunner(
        ToolRegistry([_definition(allowed_argument_patterns=[r"-c", r"print\('Bearer [a-z]+'\)"])]), tmp_path
    )
    receipt = await runner.run(
        ToolRequest(
            invocation_id="invoke-001",
            run_id="run-001",
            engagement_id=lab_engagement.engagement_id,
            tool_name="python-fixture",
            arguments=["-c", "print('Bearer abcdefghijklmnop')"],
            purpose="emit redaction fixture",
            output_directory="tool-output",
            preserve_raw_output=True,
        ),
        lab_engagement,
    )
    output = (tmp_path / receipt.stdout_artifact).read_text(encoding="utf-8")
    raw = (tmp_path / receipt.raw_stdout_artifact).read_text(encoding="utf-8")
    assert receipt.status == "completed"
    assert receipt.redaction_applied
    assert "abcdefghijklmnop" not in output
    assert "abcdefghijklmnop" in raw


@pytest.mark.asyncio
async def test_tool_runner_rejects_argument_scope_override(tmp_path: Path, lab_engagement: Engagement) -> None:
    runner = ToolRunner(ToolRegistry([_definition(allowed_argument_patterns=[r".*"])]), tmp_path)
    request = ToolRequest(
        invocation_id="invoke-unsafe",
        run_id="run-001",
        engagement_id=lab_engagement.engagement_id,
        tool_name="python-fixture",
        arguments=["--url", "https://example.com"],
        purpose="reject hidden scope override",
        output_directory="out",
    )
    with pytest.raises(ToolExecutionError, match="controlled by the wrapper"):
        await runner.run(request, lab_engagement)


@pytest.mark.asyncio
async def test_tool_runner_rejects_unregistered_target_injection(tmp_path: Path, lab_engagement: Engagement) -> None:
    runner = ToolRunner(ToolRegistry([_definition()]), tmp_path)
    request = ToolRequest(
        invocation_id="invoke-002",
        run_id="run-001",
        engagement_id=lab_engagement.engagement_id,
        tool_name="python-fixture",
        target="http://127.0.0.1:8765",
        purpose="target injection",
        output_directory="out",
    )
    with pytest.raises(ToolExecutionError, match="target injection"):
        await runner.run(request, lab_engagement)


@pytest.mark.asyncio
async def test_tool_runner_enforces_target_scope_before_execution(tmp_path: Path, lab_engagement: Engagement) -> None:
    runner = ToolRunner(ToolRegistry([_definition(target_argument="--target")]), tmp_path)
    request = ToolRequest(
        invocation_id="invoke-003",
        run_id="run-001",
        engagement_id=lab_engagement.engagement_id,
        tool_name="python-fixture",
        target="https://example.com",
        purpose="scope check",
        output_directory="out",
    )
    with pytest.raises(PolicyDenied):
        await runner.run(request, lab_engagement)
