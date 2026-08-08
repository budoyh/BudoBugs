"""Environment and tool diagnostics based on executed observations."""

from __future__ import annotations

import asyncio
import os
import platform
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from budobugs.models.enums import HealthStatus
from budobugs.models.tools import ToolHealth
from budobugs.tools.health import check_tool, resolve_executable
from budobugs.tools.registry import ToolRegistry


@dataclass(frozen=True, slots=True)
class EnvironmentObservation:
    name: str
    status: str
    observation: str


async def doctor(root: Path, *, profile: str | None = None) -> dict[str, object]:
    registry = ToolRegistry.load(root / "tools" / "registry")
    tools = registry.list(profile)
    health = await asyncio.gather(*(check_tool(item) for item in tools))
    observations = _environment_observations(root)
    statuses = [item.status for item in health]
    overall = (
        "FAIL"
        if HealthStatus.FAIL in statuses
        else "WARN"
        if any(item not in {HealthStatus.PASS} for item in statuses)
        else "PASS"
    )
    return {
        "overall": overall,
        "environment": [asdict(item) for item in observations],
        "tools": [item.model_dump(mode="json") for item in health],
    }


def _environment_observations(root: Path) -> list[EnvironmentObservation]:
    values = [
        EnvironmentObservation("os", "PASS", f"{platform.system()} {platform.release()} {platform.machine()}"),
        _command_observation(
            "python",
            [
                str(root / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")),
                "--version",
            ],
        ),
        _command_observation("uv", ["uv", "--version"]),
        _command_observation("node", ["node", "--version"]),
        _command_observation("pnpm", ["pnpm", "--version"]),
        _command_observation("go", ["go", "version"]),
        _command_observation("java", ["java", "-version"]),
        _docker_observation(),
    ]
    usage = shutil.disk_usage(root)
    values.append(EnvironmentObservation("disk", "PASS", f"free_bytes={usage.free}"))
    values.append(_memory_observation())
    values.append(_wsl_observation())
    return values


def _command_observation(name: str, command: list[str]) -> EnvironmentObservation:
    resolved = resolve_executable(command[0])
    if resolved is not None:
        command = [resolved, *command[1:]]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return EnvironmentObservation(name, "WARN", str(exc))
    output = (result.stdout + result.stderr).strip().splitlines()
    return EnvironmentObservation(
        name,
        "PASS" if result.returncode == 0 else "WARN",
        output[0][:300] if output else f"exit={result.returncode}",
    )


def _docker_observation() -> EnvironmentObservation:
    if shutil.which("docker") is not None:
        native = _command_observation("docker", ["docker", "info", "--format", "{{.ServerVersion}}"])
        if native.status == "PASS":
            return native
    if os.name == "nt" and shutil.which("wsl.exe"):
        try:
            result = subprocess.run(
                [
                    "wsl.exe",
                    "-d",
                    "BudoBugs-Ubuntu-24.04",
                    "-u",
                    "root",
                    "--",
                    "docker",
                    "info",
                    "--format",
                    "{{.ServerVersion}}",
                ],
                capture_output=True,
                timeout=20,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return EnvironmentObservation("docker", "WARN", str(exc))
        output = result.stdout.decode("utf-8", errors="replace").replace("\x00", "").strip()
        if result.returncode == 0 and output:
            return EnvironmentObservation("docker", "PASS", f"WSL daemon {output.splitlines()[-1]}")
    return EnvironmentObservation("docker", "WARN", "Docker daemon is unavailable")


def _wsl_observation() -> EnvironmentObservation:
    if os.name != "nt":
        return EnvironmentObservation("wsl", "PASS", "not applicable on native Linux")
    try:
        result = subprocess.run(
            ["wsl.exe", "--list", "--quiet"],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return EnvironmentObservation("wsl", "WARN", str(exc))
    output = result.stdout.decode("utf-16-le", errors="replace").replace("\x00", "").strip()
    if result.returncode == 0 and output:
        return EnvironmentObservation("wsl", "PASS", f"distributions={output!r}")
    return EnvironmentObservation("wsl", "WARN", "WSL has no usable installed distribution")


def _memory_observation() -> EnvironmentObservation:
    if os.name == "nt":
        try:
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-Command",
                    "(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                check=False,
            )
            value = int(result.stdout.strip()) * 1024
            return EnvironmentObservation("memory", "PASS", f"free_bytes={value}")
        except (ValueError, OSError, subprocess.TimeoutExpired):
            pass
    return EnvironmentObservation("memory", "WARN", "free memory could not be measured")


def failing_health(payload: dict[str, object]) -> list[ToolHealth]:
    values = payload.get("tools")
    if not isinstance(values, list):
        return []
    return [
        ToolHealth.model_validate(item)
        for item in values
        if isinstance(item, dict) and item.get("status") == HealthStatus.FAIL
    ]
