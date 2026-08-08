from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from budobugs.labs.manager import LabManager


@pytest.mark.docker
def test_docker_fixture_and_zap_automation_are_real(repository_root: Path, tmp_path: Path) -> None:
    """CI-sized integration: isolated fixture plus a real ZAP Automation run."""

    if os.environ.get("BUDOBUGS_RUN_DOCKER_TESTS") != "1":
        pytest.skip("NEEDS_RUNTIME: set BUDOBUGS_RUN_DOCKER_TESTS=1 for Docker integration")
    if not LabManager.docker_ready():
        pytest.skip("NEEDS_RUNTIME: Docker daemon is unavailable")
    manager = LabManager(repository_root, tmp_path / "runtime")
    config = subprocess.run(manager._compose_command("config"), capture_output=True, timeout=60, check=False)
    assert config.returncode == 0, manager._decode(config.stderr)
    start = subprocess.run(
        manager._compose_command("up", "-d", "--build", "--wait", "fixture"),
        cwd=repository_root,
        capture_output=True,
        timeout=600,
        check=False,
    )
    try:
        assert start.returncode == 0, manager._decode(start.stderr)
        published = subprocess.run(
            manager._compose_command("ps", "--format", "json", "fixture"),
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert published.returncode == 0
        container = json.loads(manager._decode(published.stdout))
        assert all(item.get("PublishedPort", 0) == 0 for item in container["Publishers"])
        scan = subprocess.run(
            manager._compose_command(
                "--profile",
                "zap-automation",
                "run",
                "--rm",
                "zap-automation",
            ),
            cwd=repository_root,
            capture_output=True,
            timeout=600,
            check=False,
        )
        assert scan.returncode == 0, manager._decode(scan.stderr or scan.stdout)
        report = repository_root / ".budobugs" / "zap" / "zap-report.json"
        assert report.is_file()
        assert '"site"' in report.read_text(encoding="utf-8")
    finally:
        subprocess.run(
            manager._compose_command("down", "--remove-orphans"),
            cwd=repository_root,
            capture_output=True,
            timeout=300,
            check=False,
        )


@pytest.mark.docker
def test_full_docker_lab_lifecycle_and_zap_automation_are_real(repository_root: Path, tmp_path: Path) -> None:
    """Opt-in integration: start every pinned lab, execute ZAP, and cleanly stop it."""

    if os.environ.get("BUDOBUGS_RUN_FULL_DOCKER_TESTS") != "1":
        pytest.skip("NEEDS_RUNTIME: set BUDOBUGS_RUN_FULL_DOCKER_TESTS=1 for the full lab integration")
    if not LabManager.docker_ready():
        pytest.skip("NEEDS_RUNTIME: Docker daemon is unavailable")
    manager = LabManager(repository_root, tmp_path / "runtime")
    config = subprocess.run(manager._compose_command("config"), capture_output=True, timeout=60, check=False)
    assert config.returncode == 0, manager._decode(config.stderr)
    status = manager.up(extended=True)
    try:
        assert status.running
        assert status.backend.startswith("docker")
        assert status.services == {
            "fixture": True,
            "juice-shop": True,
            "webgoat": True,
            "crapi": True,
            "zap": True,
        }
        for port in (8765, 3000, 8080, 9090, 8888, 8090):
            published = subprocess.run(
                manager._compose_command("port", "loopback-proxy", str(port)),
                capture_output=True,
                timeout=30,
                check=False,
            )
            assert published.returncode == 0, manager._decode(published.stderr)
            assert manager._decode(published.stdout).strip().startswith("127.0.0.1:")
        zap = manager.zap_scan()
        assert zap["status"] == "PASS"
        assert zap["sites"] == 1
        assert Path(zap["report"]).is_file()
    finally:
        stopped = manager.down()
    assert not stopped.running
    assert stopped.backend == "none"
    remaining = subprocess.run(
        manager._compose_command("--profile", "extended", "ps", "-aq"),
        cwd=repository_root,
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert remaining.returncode == 0, manager._decode(remaining.stderr)
    assert not manager._decode(remaining.stdout).strip()
