"""Truthful tool health checks with platform, version, and runtime probes."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import sys
from pathlib import Path

from platformdirs import user_data_path

from budobugs.models.enums import HealthStatus
from budobugs.models.tools import ToolDefinition, ToolHealth

_WSL_DISTRO = "BudoBugs-Ubuntu-24.04"


def current_platform() -> str:
    if os.name == "nt":
        return "windows"
    try:
        release = Path("/proc/sys/kernel/osrelease").read_text(encoding="utf-8").lower()
    except OSError:
        release = ""
    return "wsl" if "microsoft" in release else "linux"


def resolve_executable(name: str) -> str | None:
    if name == "python":
        return sys.executable
    candidates: list[str | None] = []
    executable_suffixes = (".exe", ".cmd", ".bat") if os.name == "nt" else ("",)
    candidate_roots = [
        Path(user_data_path("budobugs")) / "bin",
        Path(sys.executable).parent,
    ]
    for root in candidate_roots:
        for suffix in executable_suffixes:
            candidates.append(str(root / f"{name}{suffix}"))
    candidates.append(shutil.which(name))
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    return None


async def _run(command: list[str], *, timeout: int = 20) -> tuple[int, str]:
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return 127, f"executable not found: {command[0]}"
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        process.kill()
        await process.communicate()
        return 124, "healthcheck timeout"
    text = (stdout + stderr).decode("utf-8", errors="replace").replace("\x00", "").strip()
    return process.returncode or 0, text


def _wsl_command(*arguments: str) -> list[str]:
    return ["wsl.exe", "-d", _WSL_DISTRO, "-u", "root", "--", *arguments]


async def _docker_run(*arguments: str) -> tuple[int, str, str]:
    executable = resolve_executable("docker")
    if executable is not None:
        code, output = await _run([executable, *arguments])
        if code == 0:
            return code, output, "native"
    if os.name == "nt" and shutil.which("wsl.exe"):
        code, output = await _run(_wsl_command("docker", *arguments), timeout=40)
        return code, output, "wsl"
    return 127, "Docker daemon is not available", "none"


async def _docker_health(definition: ToolDefinition) -> ToolHealth:
    code, output, backend = await _docker_run("info", "--format", "{{.ServerVersion}}")
    if code != 0:
        return ToolHealth(
            tool_name=definition.name,
            status=HealthStatus.NEEDS_RUNTIME,
            message=f"Docker CLI found but daemon probe failed: {output[:300]}",
        )
    versions = re.findall(r"\b\d+\.\d+\.\d+\b", output)
    daemon_version = versions[-1] if versions else None
    return ToolHealth(
        tool_name=definition.name,
        status=HealthStatus.PASS,
        version=daemon_version,
        message=f"Docker daemon healthcheck passed via {backend}: {daemon_version or output[:120]}",
    )


async def _semgrep_wsl_health(definition: ToolDefinition) -> ToolHealth:
    executable = "/opt/budobugs/semgrep-1.172.0/bin/semgrep"
    code, output = await _run(_wsl_command(executable, "--version"), timeout=30)
    status = HealthStatus.PASS if code == 0 and "1.172.0" in output else HealthStatus.NEEDS_RUNTIME
    return ToolHealth(
        tool_name=definition.name,
        status=status,
        version="1.172.0" if status is HealthStatus.PASS else None,
        message=(output or "Semgrep WSL runtime is not installed")[:300],
    )


async def _chromium_health(definition: ToolDefinition) -> ToolHealth:
    probe = (
        "from playwright.sync_api import sync_playwright; "
        "p=sync_playwright().start(); b=p.chromium.launch(headless=True); "
        "v=b.version; b.close(); p.stop(); print(v)"
    )
    code, output = await _run([sys.executable, "-c", probe], timeout=40)
    return ToolHealth(
        tool_name=definition.name,
        status=HealthStatus.PASS if code == 0 else HealthStatus.FAIL,
        version=definition.version if code == 0 else None,
        message=f"Chromium launch/close probe: {output[:260]}",
    )


async def _hexstrike_health(definition: ToolDefinition) -> ToolHealth:
    command = [
        sys.executable,
        str(Path.cwd() / "scripts" / "hexstrike_lab_ai.py"),
        "status",
    ]
    code, output = await _run(command, timeout=20)
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        payload = {}
    running = code == 0 and isinstance(payload, dict) and payload.get("running") is True
    return ToolHealth(
        tool_name=definition.name,
        status=HealthStatus.PASS if running else HealthStatus.NEEDS_RUNTIME,
        version=definition.version if running else None,
        message=(output or "HexStrike bounded localhost adapter is not running")[:300],
    )


def _expected_version_token(version: str) -> str | None:
    match = re.search(r"\d+(?:\.\d+){1,3}", version)
    return match.group(0) if match else None


async def check_tool(definition: ToolDefinition) -> ToolHealth:
    if definition.name == "docker":
        return await _docker_health(definition)
    if definition.name == "semgrep" and os.name == "nt":
        return await _semgrep_wsl_health(definition)
    if definition.name == "chromium":
        return await _chromium_health(definition)
    if definition.name == "hexstrike-ai":
        return await _hexstrike_health(definition)
    if definition.install_method == "manual":
        if "burp" in definition.name or definition.license == "audit-required":
            status = HealthStatus.NEEDS_LICENSE
            reason = "manual component requires a verified license before use"
        elif definition.required_secrets:
            status = HealthStatus.NEEDS_CREDENTIAL
            reason = "manual component requires user-supplied credentials"
        else:
            status = HealthStatus.NEEDS_RUNTIME
            reason = "manual component runtime is not installed"
        return ToolHealth(tool_name=definition.name, status=status, message=reason)
    if definition.container_image and definition.executable is None:
        code, output, backend = await _docker_run(
            "image",
            "inspect",
            definition.container_image,
            "--format",
            "{{json .RepoDigests}}",
        )
        if code != 0:
            return ToolHealth(
                tool_name=definition.name,
                status=HealthStatus.NEEDS_RUNTIME,
                message=f"container image is not locally verified: {output[:240]}",
            )
        return ToolHealth(
            tool_name=definition.name,
            status=HealthStatus.PASS,
            version=definition.version,
            message=f"local image inspected via {backend}: {output[:240]}",
        )
    if current_platform() not in definition.supported_platforms:
        return ToolHealth(
            tool_name=definition.name,
            status=HealthStatus.UNSUPPORTED,
            message=f"unsupported on {current_platform()}; supported={definition.supported_platforms}",
        )
    if definition.executable is None:
        return ToolHealth(
            tool_name=definition.name,
            status=HealthStatus.NEEDS_RUNTIME,
            message="no host executable declared",
        )
    executable = resolve_executable(definition.executable)
    if executable is None:
        return ToolHealth(
            tool_name=definition.name,
            status=HealthStatus.FAIL,
            message=f"executable not found: {definition.executable}",
        )
    code, output = await _run([executable, *definition.healthcheck])
    if code != 0:
        return ToolHealth(
            tool_name=definition.name,
            status=HealthStatus.FAIL,
            message=f"healthcheck exit {code}: {output[:300]}",
        )
    expected = _expected_version_token(definition.version)
    version_evidence = output
    if expected and expected not in output:
        go = resolve_executable("go")
        if go is not None:
            build_code, build_output = await _run([go, "version", "-m", executable])
            if build_code == 0:
                version_evidence = f"{output}\n{build_output}".strip()
        if expected not in version_evidence and definition.install_method == "python":
            uv = resolve_executable("uv")
            if uv is not None:
                list_code, list_output = await _run([uv, "tool", "list"])
                if list_code == 0:
                    version_evidence = f"{version_evidence}\n{list_output}".strip()
    if expected and expected not in version_evidence:
        return ToolHealth(
            tool_name=definition.name,
            status=HealthStatus.WARN,
            message=f"healthcheck passed but pinned version {expected} was not observed: {version_evidence[:260]}",
        )
    return ToolHealth(
        tool_name=definition.name,
        status=HealthStatus.PASS,
        version=definition.version,
        message=f"{executable}: {version_evidence[:260] or 'healthcheck passed'}",
    )
