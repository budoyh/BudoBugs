from __future__ import annotations

from pathlib import Path

import pytest

from budobugs.core.policy import PolicyDenied, require_allowed, target_allowed, tool_allowed
from budobugs.core.state_machine import (
    PHASE_ORDER,
    InvalidTransition,
    block_phase,
    complete_phase,
    initialize_phases,
    start_phase,
    transition_candidate,
)
from budobugs.models import (
    CandidateStatus,
    Engagement,
    EngagementMode,
    MutationLevel,
    ResourceRisk,
    Run,
    Target,
    ToolDefinition,
)
from budobugs.traffic.normalization import (
    canonicalize_url,
    classify_value,
    extract_graphql_operation,
    infer_json_schema,
    is_static_asset,
    normalized_json_structure,
    path_template,
    structure_similarity,
)


def _engagement(mode: EngagementMode, target: str, **updates: object) -> Engagement:
    values = {
        "engagement_id": f"{mode.value}-policy-001",
        "platform": "local-test",
        "vendor": "BudoBugs policy fixture",
        "user_authorization_attestation": "I explicitly authorize this isolated policy test target.",
        "root_targets": [Target(uri=target, kind="source" if mode is EngagementMode.SOURCE else "web")],
        "selected_mode": mode,
    }
    values.update(updates)
    return Engagement.model_validate(values)


def _tool(
    *,
    modes: list[EngagementMode],
    mutation: MutationLevel = MutationLevel.NONE,
    risk: ResourceRisk = ResourceRisk.LOW,
    profile: str = "core",
) -> ToolDefinition:
    return ToolDefinition(
        name="policy-fixture",
        category="runtime",
        source="https://example.test/policy-fixture",
        version="1",
        license="Apache-2.0",
        install_method="bundled",
        profile=profile,
        executable="python",
        supported_platforms=["windows", "linux"],
        mutation_level=mutation,
        resource_risk=risk,
        supported_modes=modes,
        timeout=5,
        concurrency=1,
        parser="text",
        healthcheck=["--version"],
        output_schema="text",
    )


def test_source_and_network_scope_decisions_are_origin_bound(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = _engagement(EngagementMode.SOURCE, str(source_root))
    assert target_allowed(source, str(source_root / "package" / "module.py")).allowed
    assert not target_allowed(source, str(tmp_path / "outside.py")).allowed

    program = _engagement(
        EngagementMode.PROGRAM,
        "https://app.example.com",
        optional_allowed_subdomains=["example.com"],
        excluded_targets=["blocked.example.com"],
    )
    assert target_allowed(program, "https://api.example.com/v1").allowed
    assert not target_allowed(program, "http://api.example.com/v1").allowed
    assert not target_allowed(program, "https://api.example.com:444/v1").allowed
    assert not target_allowed(program, "https://blocked.example.com/v1").allowed
    assert not target_allowed(program, "ftp://app.example.com/file").allowed
    assert not target_allowed(program, "https://user:password@app.example.com/").allowed
    assert not target_allowed(program, "https://app.example.com:invalid/").allowed


def test_lab_scope_accepts_local_names_but_blocks_public_origins() -> None:
    for target in ("http://fixture:8765", "http://service.test:8765", "http://10.0.0.2:8765"):
        engagement = _engagement(EngagementMode.LAB, target)
        assert target_allowed(engagement, target).allowed
    public = _engagement(EngagementMode.LAB, "https://8.8.8.8")
    assert not target_allowed(public, "https://8.8.8.8").allowed
    arbitrary = _engagement(EngagementMode.LAB, "http://arbitrary-single-label:8765")
    assert not target_allowed(arbitrary, "http://arbitrary-single-label:8765").allowed
    multicast_dns = _engagement(EngagementMode.LAB, "http://device.local:8765")
    assert not target_allowed(multicast_dns, "http://device.local:8765").allowed
    public_looking_alias = _engagement(EngagementMode.LAB, "https://api.mypremiumdealership.com")
    assert not target_allowed(public_looking_alias, "https://api.mypremiumdealership.com").allowed


def test_program_tool_policy_rejects_each_unsafe_capability() -> None:
    engagement = _engagement(EngagementMode.PROGRAM, "https://app.example.com")
    assert not tool_allowed(engagement, _tool(modes=[EngagementMode.LAB]), None).allowed
    assert not tool_allowed(
        engagement,
        _tool(modes=[EngagementMode.PROGRAM], mutation=MutationLevel.MEDIUM),
        None,
    ).allowed
    assert not tool_allowed(
        engagement,
        _tool(modes=[EngagementMode.PROGRAM], risk=ResourceRisk.HIGH),
        None,
    ).allowed
    assert not tool_allowed(
        engagement,
        _tool(modes=[EngagementMode.PROGRAM], profile="lab-ai"),
        None,
    ).allowed
    assert not tool_allowed(
        engagement,
        _tool(modes=[EngagementMode.PROGRAM]),
        "https://outside.example.net",
    ).allowed
    allowed = tool_allowed(
        engagement,
        _tool(modes=[EngagementMode.PROGRAM], mutation=MutationLevel.LOW, risk=ResourceRisk.MEDIUM),
        "https://app.example.com/api",
    )
    require_allowed(allowed)
    with pytest.raises(PolicyDenied):
        require_allowed(tool_allowed(engagement, _tool(modes=[EngagementMode.LAB]), None))


def test_source_tool_policy_requires_an_offline_network_contract(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    engagement = _engagement(EngagementMode.SOURCE, str(root))
    unspecified = _tool(modes=[EngagementMode.SOURCE])
    assert not tool_allowed(engagement, unspecified, str(root)).allowed
    offline = unspecified.model_copy(update={"network_behavior": ["none"]})
    assert tool_allowed(engagement, offline, str(root)).allowed
    online = offline.model_copy(update={"network_behavior": ["downloads vulnerability database"]})
    assert not tool_allowed(engagement, online, str(root)).allowed


def test_phase_state_machine_enforces_order_supports_retry_and_completion() -> None:
    run = Run(
        run_id="run-policy-001",
        engagement_id="lab-policy-001",
        selected_mode=EngagementMode.LAB,
        phases=initialize_phases(),
    )
    with pytest.raises(InvalidTransition, match="previous phase"):
        start_phase(run, PHASE_ORDER[1])
    start_phase(run, PHASE_ORDER[0])
    assert run.phases[0].attempt == 1
    with pytest.raises(InvalidTransition, match="not running"):
        complete_phase(run, PHASE_ORDER[1], [], "receipt-invalid")
    complete_phase(run, PHASE_ORDER[0], ["init.json"], "receipt-init")
    assert start_phase(run, PHASE_ORDER[0]) is run

    start_phase(run, PHASE_ORDER[1])
    block_phase(run, PHASE_ORDER[1], "controlled interruption")
    assert run.status == "blocked"
    start_phase(run, PHASE_ORDER[1])
    assert run.phases[1].attempt == 2
    assert run.phases[1].error is None

    final = run.phases[-1]
    final.status = "running"
    complete_phase(run, PHASE_ORDER[-1], ["report.md"], "receipt-final")
    assert run.status == "completed"


def test_candidate_state_machine_rejects_gate_bypass() -> None:
    assert transition_candidate(CandidateStatus.SIGNAL, CandidateStatus.HYPOTHESIS) is CandidateStatus.HYPOTHESIS
    with pytest.raises(InvalidTransition):
        transition_candidate(CandidateStatus.SIGNAL, CandidateStatus.CONFIRMED)
    with pytest.raises(InvalidTransition):
        transition_candidate(CandidateStatus.ARCHIVED, CandidateStatus.HOLD)


def test_normalization_covers_dynamic_values_graphql_and_schema_shapes() -> None:
    assert canonicalize_url("HTTPS://Example.COM.:443//v1/items?b=2&a=1#fragment") == (
        "https://example.com/v1/items?a=1&b=2"
    )
    assert path_template("https://example.test/a/123/550e8400-e29b-41d4-a716-446655440000/a1b2c3d4e5f6g7h8i9j0") == (
        "/a/{id}/{uuid}/{token}"
    )
    assert is_static_asset("https://example.test/app.CSS")
    assert is_static_asset("https://example.test/download", "image/png")
    assert not is_static_asset("https://example.test/api", "application/json")

    assert classify_value("4", "page") == "pagination"
    assert classify_value("value", "password") == "secret"
    assert classify_value("550e8400-e29b-41d4-a716-446655440000") == "uuid"
    assert classify_value("2026-08-08", "created") == "timestamp"
    assert classify_value("42", "object_id") == "id"
    assert classify_value("a1b2c3d4e5f6g7h8i9j0") == "random"
    assert classify_value("ordinary") == "stable"

    schema = infer_json_schema({"items": [1, "two"], "active": True, "missing": None, "ratio": 1.5})
    assert schema["type"] == "object"
    assert infer_json_schema([]) == {"type": "array", "items": {}}
    assert infer_json_schema(object()) == {"type": "unknown"}

    assert extract_graphql_operation('{"operationName":"GetUser","query":"query GetUser { user { id } }"}') == (
        "GetUser",
        "query",
    )
    assert extract_graphql_operation("mutation UpdateUser { updateUser { id } }") == ("UpdateUser", "mutation")
    assert extract_graphql_operation("{ viewer { id } }") == (None, None)
    assert extract_graphql_operation(None) == (None, None)

    assert normalized_json_structure('{"trace_id":"volatile","value":1,"nested":[{"timestamp":2}]}') == {
        "nested": [{}],
        "value": 1,
    }
    assert normalized_json_structure("created=1730000000") == "created={timestamp}"
    assert structure_similarity('{"a":1,"requestId":"x"}', '{"a":1,"requestId":"y"}') == 1.0
    assert structure_similarity('{"a":1,"b":2}', '{"a":9,"c":3}') == pytest.approx(1 / 3)
    assert structure_similarity("one", "two") == 0.0
