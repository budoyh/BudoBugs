"""Browser credential boundary tests for the agent-visible run tree."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from budobugs.browser.session import BrowserSessionManager, browser_artifact_paths
from budobugs.models import Engagement, EngagementMode, Target
from budobugs.orchestration.executor import TypedActionExecutor
from budobugs.proxy.direct import DirectProxyBackend
from budobugs.proxy.factory import ProxySelection


def _engagement() -> Engagement:
    return Engagement(
        engagement_id="private-browser-fixture",
        platform="local-test",
        vendor="BudoBugs TEST FIXTURE",
        user_authorization_attestation="I authorize only this local test fixture for browser privacy validation.",
        root_targets=[Target(uri="http://127.0.0.1:8765", label="fixture")],
        selected_mode=EngagementMode.PROGRAM,
        testing_accounts_secret_refs={"alice": "keyring://fixture/alice"},
    )


def test_private_browser_material_is_outside_codex_visible_run_artifacts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Raw cookies/tokens stay in private runtime material, never in ``runs``."""

    repository = tmp_path / "repository"
    public_browser = repository / "runs" / "run-private-browser" / "artifacts" / "browser"
    # Keep the explicit private root short enough to exercise the accepted
    # Windows override path without writing state outside pytest's temp tree.
    private_home = tmp_path.parent / "p"
    monkeypatch.setenv("BUDOBUGS_PRIVATE_HOME", str(private_home))
    engagement = _engagement()
    executor = TypedActionExecutor(
        repository_root=repository,
        runtime_home=repository / ".budobugs",
        artifact_root=public_browser.parent,
        engagement=engagement,
        run_id="run-private-browser",
        proxy=ProxySelection(
            backend=DirectProxyBackend(),
            requested="direct",
            selected="direct",
            ready=True,
            detail="test direct backend",
            attempted=(),
            receipt_path=str(tmp_path / "proxy.json"),
        ),
    )
    private_browser = executor._private_browser_root()
    assert not private_browser.is_relative_to(repository)
    assert executor.validator_registry.private_root == private_browser / "validators"
    monkeypatch.setenv("BUDOBUGS_PRIVATE_HOME", str(repository / "operator-private-home"))
    assert not executor._private_browser_root().is_relative_to(repository)
    monkeypatch.setenv("BUDOBUGS_PRIVATE_HOME", str(private_home))

    manager = BrowserSessionManager(public_browser, engagement, private_root=private_browser)
    private_account = private_browser / "alice"
    (private_account / "profile").mkdir(parents=True)
    (private_account / "storage-state.json").write_text(
        '{"cookies":[{"name":"session","value":"super-secret-cookie"}]}', encoding="utf-8"
    )
    (private_account / "login-complete.json").write_text('{"account_alias":"alice"}', encoding="utf-8")
    assert manager.has_completed_login("alice")

    raw_har = private_account / "traffic.har"
    raw_har.write_text(
        json.dumps(
            {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "url": "http://127.0.0.1:8765/api/me?access_token=super-secret-token",
                                "headers": [
                                    {"name": "Cookie", "value": "session=super-secret-cookie"},
                                    {"name": "Authorization", "value": "Bearer super-secret-token"},
                                ],
                                "postData": {"text": "token=super-secret-token"},
                            },
                            "response": {
                                "headers": [{"name": "Set-Cookie", "value": "session=super-secret-cookie"}],
                                "content": {"text": '{"access_token":"super-secret-token"}'},
                            },
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    public_har = public_browser / "alice" / "traffic.har"
    manager._export_sanitized_har(raw_har, public_har)
    executor._add_exchanges(executor._import_browser_har(raw_har, "alice"))
    # Public DOM, console, response and step artifacts share the same explicit
    # query/body redaction path as the HAR projection.
    audit_text = "<div>token=super-secret-token</div> <script>cookie=super-secret-cookie</script>"
    (public_browser / "alice" / "dom").mkdir(parents=True)
    (public_browser / "alice" / "dom" / "0001-audit.html").write_text(
        manager._redact_har_text(audit_text), encoding="utf-8"
    )
    (public_browser / "alice" / "steps.jsonl").write_text(
        manager._redact_har_url("http://127.0.0.1:8765/app?token=super-secret-token"), encoding="utf-8"
    )

    visible = browser_artifact_paths(public_browser)
    assert visible == [
        str(public_har),
        str(public_browser / "alice" / "steps.jsonl"),
        str(public_browser / "alice" / "dom" / "0001-audit.html"),
    ]
    assert all(not Path(path).is_relative_to(private_browser) for path in visible)
    assert not (public_browser / "alice" / "profile").exists()
    assert not (public_browser / "alice" / "storage-state.json").exists()
    public_text = "\n".join(path.read_text(encoding="utf-8") for path in public_browser.rglob("*") if path.is_file())
    assert "super-secret-cookie" not in public_text
    assert "super-secret-token" not in public_text
    exchange_ledger = (public_browser.parent / "exchanges" / "ledger.json").read_text(encoding="utf-8")
    assert "super-secret-cookie" not in exchange_ledger
    assert "super-secret-token" not in exchange_ledger


@pytest.mark.skipif(os.name != "nt", reason="Windows Chromium path budget")
def test_windows_private_browser_root_uses_short_fallback_for_deep_external_runtime(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Windows Chromium profiles must not inherit a deep external runtime path."""

    repository = tmp_path / "repository"
    deep_runtime = tmp_path / ("runtime-" + "x" * 120) / ("nested-" + "y" * 120)
    monkeypatch.delenv("BUDOBUGS_PRIVATE_HOME", raising=False)
    private_home = Path(os.environ["LOCALAPPDATA"]) / "BudoBugs"
    executor = TypedActionExecutor(
        repository_root=repository,
        runtime_home=deep_runtime,
        artifact_root=repository / "runs" / "run-long-private" / "artifacts",
        engagement=_engagement(),
        run_id="run-long-private",
        proxy=ProxySelection(DirectProxyBackend(), "direct", "direct", True, "test", (), str(tmp_path / "proxy.json")),
    )

    root = executor._private_browser_root()
    assert not root.is_relative_to(deep_runtime)
    assert root.is_relative_to(private_home)
    assert executor._windows_profile_path_is_safe(root)
    monkeypatch.setenv("BUDOBUGS_PRIVATE_HOME", str(deep_runtime))
    assert executor._private_browser_root().is_relative_to(private_home)
