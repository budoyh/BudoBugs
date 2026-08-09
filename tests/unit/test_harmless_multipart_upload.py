from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

import pytest

from budobugs.core.identifiers import new_id
from budobugs.models import (
    CandidateDecision,
    Engagement,
    EngagementMode,
    HarmlessMultipartUpload,
    HttpExchange,
    SafeExperimentTemplate,
    SafeHttpAction,
    SafeWorkflowExperimentTemplate,
    WorkflowStep,
)
from budobugs.orchestration.executor import TypedActionExecutor
from budobugs.orchestration.multipart import build_harmless_multipart
from budobugs.orchestration.workflow import SafeWorkflowRunner
from budobugs.proxy import DirectProxyBackend, ProxySelection
from budobugs.traffic.normalization import normalize_exchange


class LocalMultipartFixture:
    """An in-process fixture that accepts only the generated multipart contract."""

    def __init__(self) -> None:
        self.count = 0
        self.requests: list[tuple[str, bytes | None, str | None]] = []

    async def send(
        self,
        engagement: Engagement,
        method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        url: str,
        *,
        headers: dict[str, str] | None = None,
        content: str | bytes | None = None,
        account_alias: str | None = None,
        source: Literal["direct"] = "direct",
    ) -> HttpExchange:
        request_body = content.encode() if isinstance(content, str) else content
        content_type = (headers or {}).get("Content-Type")
        self.requests.append((url, request_body, content_type))
        path = url.removeprefix("http://127.0.0.1:8765")
        status = 200
        if path == "/uploads" and method == "POST":
            if not content_type or not content_type.startswith("multipart/form-data; boundary="):
                status = 415
            elif request_body is None or b"BudoBugs harmless multipart fixture" not in request_body:
                status = 422
            else:
                self.count += 1
        elif path == "/uploads" and method == "GET":
            pass
        elif path == "/uploads/negative" and method == "GET":
            status = 403
        elif path == "/uploads/reset" and method == "POST":
            self.count = 0
        else:
            status = 404
        return normalize_exchange(
            HttpExchange(
                exchange_id=new_id("http"),
                engagement_id=engagement.engagement_id,
                method=method,
                url=url,
                request_headers=headers or {},
                request_body=request_body.decode("utf-8") if request_body else None,
                response_status=status,
                response_headers={"content-type": "application/json"},
                response_body=json.dumps({"count": self.count}),
                http_version="HTTP/1.1",
                account_alias=account_alias,
                source=source,
            )
        )


def _upload() -> HarmlessMultipartUpload:
    return HarmlessMultipartUpload(
        file_field="attachment",
        filename="control-proof.txt",
        fixture_kind="text",
        marker="program-control-001",
        form_fields={"purpose": "authorization-control", "scope": "self-owned"},
    )


def _action(
    action_id: str,
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    path: str,
    statuses: list[int],
    **kwargs: Any,
) -> SafeHttpAction:
    return SafeHttpAction(
        action_id=action_id,
        account_alias="alice",
        method=method,
        target_url=f"http://127.0.0.1:8765{path}",
        expected_statuses=statuses,
        operation_boundary="one declared harmless fixture upload",
        object_boundary="local disposable upload counter",
        **kwargs,
    )


def _metadata(**updates: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "template_id": "harmless-multipart-control",
        "specialist_role": "authorization-specialist",
        "title": "Declared harmless multipart upload control",
        "vulnerability_class": "upload-authorization",
        "affected_feature": "self-owned fixture attachment upload",
        "security_invariant": "Only the predeclared harmless attachment fixture is sent to the exact route.",
        "root_cause_key": "fixture-upload-contract",
        "repair_boundary": "upload request contract",
        "capability_before": "declared account reads its own fixture counter",
        "capability_after": "declared account uploads one generated harmless fixture",
        "capability_delta": "one bounded generated fixture upload",
        "strongest_benign_explanation": "the local fixture increments only when its multipart contract matches",
        "impact": "test evidence is limited to the local fixture counter",
    }
    values.update(updates)
    return values


def _experiment_template() -> SafeExperimentTemplate:
    normal = _action("read-upload-count", "GET", "/uploads", [200])
    return SafeExperimentTemplate(
        **_metadata(),
        normal_control=normal,
        experiment=_action("upload-harmless-control", "POST", "/uploads", [200], multipart_upload=_upload()),
        negative_control=_action("deny-unrelated-upload-read", "GET", "/uploads/negative", [403]),
        effect_observation=normal.model_copy(update={"action_id": "observe-upload-count"}),
        effect_json_pointer="/count",
        expected_effect_sequence=[0, 1, 2],
        cleanup=[_action("reset-upload-count", "POST", "/uploads/reset", [200])],
        cleanup_verification=normal.model_copy(update={"action_id": "verify-upload-reset"}),
    )


def _workflow_template() -> SafeWorkflowExperimentTemplate:
    normal = _action("workflow-read-upload-count", "GET", "/uploads", [200])
    return SafeWorkflowExperimentTemplate(
        **_metadata(template_id="workflow-harmless-multipart-control"),
        normal_steps=[WorkflowStep(action=normal, expected_json_pointer="/count", expected_json_value=0)],
        experiment_steps=[
            WorkflowStep(
                action=_action(
                    "workflow-upload-harmless-control",
                    "POST",
                    "/uploads",
                    [200],
                    multipart_upload=_upload(),
                )
            )
        ],
        negative_steps=[WorkflowStep(action=_action("workflow-deny-unrelated", "GET", "/uploads/negative", [403]))],
        cleanup_steps=[WorkflowStep(action=_action("workflow-reset-upload", "POST", "/uploads/reset", [200]))],
        cleanup_verification_steps=[
            WorkflowStep(
                action=normal.model_copy(update={"action_id": "workflow-verify-upload-reset"}),
                expected_json_pointer="/count",
                expected_json_value=0,
            )
        ],
    )


def _program(engagement: Engagement) -> Engagement:
    return engagement.model_copy(
        update={
            "selected_mode": EngagementMode.PROGRAM,
            "testing_accounts_secret_refs": {"alice": "keyring://fixture/alice"},
        }
    )


def test_harmless_multipart_model_rejects_paths_credentials_controls_and_ambiguous_bodies() -> None:
    with pytest.raises(ValueError, match="filename"):
        HarmlessMultipartUpload(filename="../proof.txt", fixture_kind="text", marker="safe-marker")
    with pytest.raises(ValueError, match="credentials"):
        HarmlessMultipartUpload(
            filename="proof.txt", fixture_kind="text", marker="safe-marker", form_fields={"password": "nope"}
        )
    with pytest.raises(ValueError, match="multipart form fields"):
        HarmlessMultipartUpload(
            filename="proof.txt",
            fixture_kind="text",
            marker="safe-marker",
            form_fields={'bad"; filename="injected.txt': "self-owned"},
        )
    with pytest.raises(ValueError, match="multipart form fields"):
        HarmlessMultipartUpload(
            filename="proof.txt",
            fixture_kind="text",
            marker="safe-marker",
            form_fields={"file": "self-owned"},
        )
    with pytest.raises(ValueError, match="marker"):
        HarmlessMultipartUpload(filename="proof.txt", fixture_kind="text", marker="line\nbreak")
    with pytest.raises(ValueError, match="cannot be combined"):
        _action("ambiguous-upload", "POST", "/uploads", [200], body={"not": "allowed"}, multipart_upload=_upload())
    with pytest.raises(ValueError, match="requires POST"):
        _action("read-upload", "GET", "/uploads", [200], multipart_upload=_upload())
    with pytest.raises(ValueError, match="Content-Type"):
        _action(
            "typed-upload",
            "POST",
            "/uploads",
            [200],
            headers={"Content-Type": "application/json"},
            multipart_upload=_upload(),
        )


def test_harmless_multipart_exact_request_is_deterministic_and_generated_only() -> None:
    first, content_type = build_harmless_multipart(_upload())
    second, repeated_content_type = build_harmless_multipart(_upload())

    assert first == second
    assert content_type == repeated_content_type == "multipart/form-data; boundary=----BudoBugsHarmlessMultipartV1"
    assert b'filename="control-proof.txt"' in first
    assert b"program-control-001" in first
    assert b"C:\\" not in first
    assert len(first) <= 2048


@pytest.mark.asyncio
async def test_safe_experiment_and_workflow_run_generated_multipart_against_local_fixture(
    repository_root: Path,
    tmp_path: Path,
    lab_engagement: Engagement,
) -> None:
    engagement = _program(lab_engagement)
    fixture = LocalMultipartFixture()
    account_headers = {"alice": {"Authorization": "Fixture alice"}}
    executor = TypedActionExecutor(
        repository_root=repository_root,
        runtime_home=tmp_path / "runtime",
        artifact_root=tmp_path / "experiment",
        engagement=engagement,
        run_id="run-harmless-multipart",
        proxy=ProxySelection(
            backend=DirectProxyBackend(),
            requested="direct",
            selected="direct",
            ready=True,
            detail="local fixture",
            attempted=(),
            receipt_path=str(tmp_path / "proxy.json"),
        ),
        account_headers=account_headers,
    )
    executor.direct = fixture  # type: ignore[assignment]
    experiment = await executor._run_safe_program_experiment(_experiment_template())

    workflow_fixture = LocalMultipartFixture()
    workflow = await SafeWorkflowRunner(
        engagement=engagement,
        run_id="run-harmless-multipart-workflow",
        artifact_root=tmp_path / "workflow",
        direct=workflow_fixture,  # type: ignore[arg-type]
        account_headers=account_headers,
    ).run(_workflow_template())

    assert experiment.outcome.decision is CandidateDecision.CONFIRMED
    assert workflow.decision is CandidateDecision.CONFIRMED
    for _url, body, content_type in [item for item in fixture.requests + workflow_fixture.requests if item[1]]:
        assert content_type == "multipart/form-data; boundary=----BudoBugsHarmlessMultipartV1"
        assert body is not None
        assert b"BudoBugs harmless multipart fixture" in body
    receipt = Path(workflow.receipt_path).read_text(encoding="utf-8")
    exchanges = json.dumps([item.model_dump(mode="json") for item in workflow.exchanges])
    assert "Fixture alice" not in receipt
    assert "Fixture alice" not in exchanges
    assert "C:\\" not in receipt
