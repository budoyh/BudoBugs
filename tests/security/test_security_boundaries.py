from __future__ import annotations

import subprocess
import tomllib
from pathlib import Path

import pytest
from pydantic import ValidationError
from scripts import secret_scan

from budobugs.browser.session import BrowserSessionManager
from budobugs.core.policy import target_allowed, websocket_target_allowed
from budobugs.labs.manager import LabManager
from budobugs.models import Engagement, EngagementMode, PhaseName, Target
from budobugs.orchestration.engine import HuntEngine
from budobugs.proxy.base import require_local_control_plane


def test_gitleaks_source_scan_excludes_vcs_metadata(repository_root: Path) -> None:
    with (repository_root / ".gitleaks.toml").open("rb") as handle:
        config = tomllib.load(handle)

    excluded_paths = config["allowlists"][0]["paths"]
    assert r"^\.git/" in excluded_paths


def test_secret_scan_passes_a_repository_relative_source(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: list[str] = []

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        observed.extend(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(secret_scan.shutil, "which", lambda _name: "gitleaks")
    monkeypatch.setattr(secret_scan.subprocess, "run", run)

    assert secret_scan.main(["--path", "."]) == 0
    assert observed[observed.index("--source") + 1] == "."


def test_network_scope_is_origin_bound_and_rejects_url_credentials(lab_engagement: Engagement) -> None:
    assert target_allowed(lab_engagement, "http://127.0.0.1:8765/inside").allowed
    assert not target_allowed(lab_engagement, "http://127.0.0.1:9999/other-service").allowed
    assert not target_allowed(lab_engagement, "https://127.0.0.1:8765/scheme-change").allowed
    assert not target_allowed(lab_engagement, "http://user@127.0.0.1:8765/credential-smuggling").allowed
    assert not target_allowed(lab_engagement, "file:///etc/passwd").allowed
    assert websocket_target_allowed(lab_engagement, "ws://127.0.0.1:8765/ws/objects/1").allowed
    assert not websocket_target_allowed(lab_engagement, "wss://example.com/ws").allowed


def test_engagement_rejects_credentials_and_invalid_ports_in_roots() -> None:
    common = {
        "engagement_id": "scope-test-001",
        "platform": "local",
        "vendor": "fixture",
        "user_authorization_attestation": "I authorize this isolated URL validation fixture only.",
        "selected_mode": EngagementMode.LAB,
    }
    with pytest.raises(ValidationError):
        Engagement(root_targets=[Target(uri="http://user:pass@127.0.0.1:8765")], **common)
    with pytest.raises(ValidationError):
        Engagement(root_targets=[Target(uri="http://127.0.0.1:70000")], **common)


@pytest.mark.asyncio
async def test_browser_route_guard_blocks_every_cross_scope_subresource(
    tmp_path: Path, lab_engagement: Engagement
) -> None:
    manager = BrowserSessionManager(tmp_path, lab_engagement)

    class Request:
        def __init__(self, url: str) -> None:
            self.url = url

    class Route:
        def __init__(self, url: str) -> None:
            self.request = Request(url)
            self.action: str | None = None

        async def continue_(self) -> None:
            self.action = "continue"

        async def abort(self, _reason: str) -> None:
            self.action = "abort"

    allowed = Route("http://127.0.0.1:8765/app.js")
    allowed_websocket = Route("ws://127.0.0.1:8765/ws/objects/1")
    blocked = Route("https://example.com/tracker.js")
    await manager._scope_route(allowed)  # type: ignore[arg-type]
    await manager._scope_route(allowed_websocket)  # type: ignore[arg-type]
    await manager._scope_route(blocked)  # type: ignore[arg-type]
    assert allowed.action == "continue"
    assert allowed_websocket.action == "continue"
    assert blocked.action == "abort"


def test_proxy_control_planes_default_to_loopback_and_reject_embedded_credentials() -> None:
    assert require_local_control_plane("http://127.0.0.1:8090/") == "http://127.0.0.1:8090"
    assert require_local_control_plane("https://[::1]:9443/") == "https://[::1]:9443"
    with pytest.raises(ValueError, match="localhost/loopback"):
        require_local_control_plane("https://proxy.example.com")
    with pytest.raises(ValueError, match="credential-free"):
        require_local_control_plane("http://token@127.0.0.1:8090")


def test_lab_manager_refuses_to_terminate_an_unowned_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(LabManager, "_process_command_line", staticmethod(lambda _pid: "unrelated.exe --serve"))
    assert not LabManager._terminate_owned_process(4242, required_tokens=("uvicorn", "fixture_app"))


async def test_resume_rejects_a_tampered_context_snapshot(service, lab_engagement: Engagement) -> None:
    service.save_engagement(lab_engagement)
    engagement = service.authorize_engagement(lab_engagement.engagement_id)
    interrupted = await HuntEngine(service).run(engagement, stop_after=PhaseName.INIT)
    snapshot = service.paths.runs / interrupted.run.run_id / "artifacts" / "context" / f"{PhaseName.INIT.value}.json"
    snapshot.write_text(
        snapshot.read_text(encoding="utf-8").replace('"schema_version": 1', '"schema_version": 2'), encoding="utf-8"
    )

    with pytest.raises(RuntimeError, match="snapshot"):
        await HuntEngine(service).run(engagement, resume=True)
