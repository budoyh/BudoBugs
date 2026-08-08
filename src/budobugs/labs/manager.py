"""Docker-first, truthful local lab lifecycle with a native fixture fallback."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from budobugs.core.io import atomic_write_json


@dataclass(frozen=True, slots=True)
class LabStatus:
    running: bool
    backend: str
    detail: str
    services: dict[str, bool]


class LabManager:
    """Start Docker Compose when available; otherwise expose only the native fixture."""

    def __init__(self, root: Path, runtime_home: Path, *, fixture_port: int = 8765) -> None:
        self.root = root.resolve()
        self.runtime_home = runtime_home.resolve()
        self.fixture_port = fixture_port
        self.state_file = self.runtime_home / "lab" / "state.json"
        self.log_file = self.runtime_home / "lab" / "fixture.log"

    wsl_distro = "BudoBugs-Ubuntu-24.04"

    @staticmethod
    def _native_docker_ready() -> bool:
        try:
            result = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0 and bool(result.stdout.strip())

    @classmethod
    def _wsl_docker_ready(cls) -> bool:
        if sys.platform != "win32":
            return False
        try:
            result = subprocess.run(
                [
                    "wsl.exe",
                    "-d",
                    cls.wsl_distro,
                    "-u",
                    "root",
                    "--",
                    "docker",
                    "info",
                    "--format",
                    "{{.ServerVersion}}",
                ],
                capture_output=True,
                timeout=15,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0 and bool(result.stdout.strip())

    @classmethod
    def docker_ready(cls) -> bool:
        return cls._native_docker_ready() or cls._wsl_docker_ready()

    def _compose_command(self, *arguments: str) -> list[str]:
        compose_file = self.root / "docker" / "compose.yaml"
        if self._native_docker_ready():
            return ["docker", "compose", "-f", str(compose_file), *arguments]
        if self._wsl_docker_ready() and compose_file.drive:
            drive = compose_file.drive[0].lower()
            tail = compose_file.as_posix()[2:]
            wsl_path = f"/mnt/{drive}{tail}"
            return [
                "wsl.exe",
                "-d",
                self.wsl_distro,
                "-u",
                "root",
                "--",
                "docker",
                "compose",
                "-f",
                wsl_path,
                *arguments,
            ]
        raise RuntimeError("Docker daemon is not available")

    @classmethod
    def _start_wsl_keepalive(cls) -> int | None:
        """Keep the dedicated distro alive while Docker lab containers are running."""

        if sys.platform != "win32":
            return None
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
        process = subprocess.Popen(
            ["wsl.exe", "-d", cls.wsl_distro, "--", "sleep", "infinity"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )
        time.sleep(0.5)
        if process.poll() is not None:
            raise RuntimeError(f"WSL keepalive exited with code {process.returncode}")
        return process.pid

    def up(self, *, native_only: bool = False, extended: bool = False) -> LabStatus:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        if not native_only and self.docker_ready():
            previous = self._read_state()
            current = self.status()
            if (
                current.running
                and str(previous.get("backend", "")).startswith("docker")
                and (not extended or previous.get("extended") is True)
            ):
                return current
            existing_keepalive = previous.get("wsl_keepalive_pid")
            keepalive_pid = (
                None
                if self._native_docker_ready()
                else existing_keepalive
                if isinstance(existing_keepalive, int)
                else self._start_wsl_keepalive()
            )
            started_keepalive = keepalive_pid is not None and keepalive_pid != existing_keepalive
            profile = ["--profile", "extended"] if extended else []
            backend = "docker-native" if self._native_docker_ready() else "docker-wsl"
            atomic_write_json(
                self.state_file,
                {
                    "backend": backend,
                    "extended": extended,
                    "wsl_keepalive_pid": keepalive_pid,
                    "starting": True,
                },
            )
            result = subprocess.run(
                self._compose_command(*profile, "up", "-d", "--build", "--wait"),
                cwd=self.root,
                capture_output=True,
                timeout=600,
                check=False,
            )
            if result.returncode != 0:
                if started_keepalive and keepalive_pid is not None:
                    self._terminate_owned_process(
                        keepalive_pid,
                        required_tokens=(self.wsl_distro.lower(), "sleep", "infinity"),
                    )
                raise RuntimeError(f"docker compose up failed: {self._decode(result.stderr)[-2000:]}")
            atomic_write_json(
                self.state_file,
                {
                    "backend": backend,
                    "extended": extended,
                    "wsl_keepalive_pid": keepalive_pid,
                    "starting": False,
                },
            )
            return self.status()
        current = self.status()
        if current.running:
            return current
        log = self.log_file.open("ab")
        creationflags: int = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "budobugs.labs.fixture_app:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(self.fixture_port),
                "--no-access-log",
            ],
            cwd=self.root,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=creationflags,
        )
        log.close()
        atomic_write_json(self.state_file, {"backend": "native", "pid": process.pid, "port": self.fixture_port})
        for _ in range(50):
            if self._fixture_health():
                process.returncode = 0
                return self.status()
            if process.poll() is not None:
                raise RuntimeError(f"native fixture exited with code {process.returncode}; see {self.log_file}")
            time.sleep(0.1)
        self.down()
        raise RuntimeError("native fixture did not become healthy")

    def down(self) -> LabStatus:
        state = self._read_state()
        if str(state.get("backend", "")).startswith("docker"):
            if self.docker_ready():
                profile = ["--profile", "extended"] if state.get("extended") is True else []
                result = subprocess.run(
                    self._compose_command(*profile, "down", "--remove-orphans"),
                    cwd=self.root,
                    capture_output=True,
                    timeout=300,
                    check=False,
                )
                if result.returncode != 0:
                    raise RuntimeError(f"docker compose down failed: {self._decode(result.stderr)[-2000:]}")
            keepalive_pid = state.get("wsl_keepalive_pid")
            if isinstance(keepalive_pid, int):
                self._terminate_owned_process(
                    keepalive_pid,
                    required_tokens=(self.wsl_distro.lower(), "sleep", "infinity"),
                )
        elif state.get("backend") == "native" and isinstance(state.get("pid"), int):
            pid_value = state.get("pid")
            assert isinstance(pid_value, int)
            pid = pid_value
            self._terminate_owned_process(
                pid,
                required_tokens=("budobugs.labs.fixture_app", str(state.get("port", self.fixture_port))),
            )
        self.state_file.unlink(missing_ok=True)
        return self.status()

    def clean(self) -> LabStatus:
        status = self.down()
        if self.docker_ready():
            subprocess.run(
                self._compose_command("down", "--volumes", "--remove-orphans"),
                cwd=self.root,
                capture_output=True,
                timeout=300,
                check=False,
            )
        return status

    def status(self) -> LabStatus:
        state = self._read_state()
        fixture = self._fixture_health()
        backend = str(state.get("backend", "none"))
        services = {"fixture": fixture}
        if backend.startswith("docker") and self.docker_ready():
            for name, port in {"juice-shop": 3000, "webgoat": 8080, "crapi": 8888}.items():
                services[name] = self._http_health(port)
            if state.get("extended") is True:
                services["zap"] = self._http_health(8090, "/JSON/core/view/version/")
        complete = all(services.values()) and backend.startswith("docker")
        detail = (
            "all pinned Docker lab services are healthy"
            if complete
            else "native TEST FIXTURE is healthy; Docker-only labs are unavailable"
            if fixture
            else "lab is not running"
        )
        return LabStatus(running=fixture, backend=backend, detail=detail, services=services)

    def zap_scan(self) -> dict[str, object]:
        """Run the pinned ZAP Automation Framework job against the Docker-only fixture."""

        state = self._read_state()
        if not str(state.get("backend", "")).startswith("docker") or not self._fixture_health():
            raise RuntimeError("the Docker lab must be running before a ZAP automation scan")
        report_path = self._prepare_zap_output()
        result = subprocess.run(
            self._compose_command(
                "--profile",
                "zap-automation",
                "run",
                "--rm",
                "zap-automation",
            ),
            cwd=self.root,
            capture_output=True,
            timeout=600,
            check=False,
        )
        if result.returncode != 0:
            detail = self._decode(result.stderr or result.stdout)[-2000:]
            raise RuntimeError(f"ZAP automation failed: {detail}")
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("ZAP completed without a valid JSON report") from exc
        if not isinstance(report, dict):
            raise RuntimeError("ZAP JSON report must be an object")
        sites = report.get("site")
        alert_count = 0
        if isinstance(sites, list):
            for site in sites:
                if not isinstance(site, dict):
                    continue
                alerts = site.get("alerts")
                if isinstance(alerts, list):
                    alert_count += len(alerts)
        receipt = {
            "status": "PASS",
            "target": "http://fixture:8765",
            "image": (
                "ghcr.io/zaproxy/zaproxy:2.17.0@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef"
            ),
            "report": str(report_path),
            "sites": len(sites) if isinstance(sites, list) else 0,
            "alerts": alert_count,
            "exit_code": result.returncode,
        }
        atomic_write_json(report_path.parent / "automation-receipt.json", receipt)
        return receipt

    def _prepare_zap_output(self) -> Path:
        """Prepare the host/container report handoff without changing repository permissions."""

        output_dir = self.root / ".budobugs" / "zap"
        output_dir.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            # The pinned ZAP image runs as a different non-root UID. The sticky bit
            # confines this world-writable handoff to its ignored runtime directory.
            output_dir.chmod(0o1777)
        report_path = output_dir / "zap-report.json"
        report_path.unlink(missing_ok=True)
        return report_path

    def _read_state(self) -> dict[str, object]:
        try:
            value = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _process_command_line(pid: int) -> str | None:
        if pid <= 0:
            return None
        if sys.platform == "win32":
            script = f'$p=Get-CimInstance Win32_Process -Filter "ProcessId={pid}"; if ($p) {{ $p.CommandLine }}'
            try:
                result = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-Command", script],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=10,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                return None
            return result.stdout.strip().lower() if result.returncode == 0 else None
        try:
            return (
                Path(f"/proc/{pid}/cmdline")
                .read_bytes()
                .replace(b"\x00", b" ")
                .decode("utf-8", errors="replace")
                .lower()
            )
        except OSError:
            return None

    @classmethod
    def _terminate_owned_process(cls, pid: int, *, required_tokens: tuple[str, ...]) -> bool:
        command_line = cls._process_command_line(pid)
        if not command_line or not all(token.lower() in command_line for token in required_tokens):
            return False
        try:
            if sys.platform == "win32":
                result = subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    capture_output=True,
                    timeout=20,
                    check=False,
                )
                return result.returncode == 0
            os.kill(pid, signal.SIGTERM)
            return True
        except (OSError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def _decode(value: bytes | str | None) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        return value.decode("utf-8", errors="replace").replace("\x00", "")

    def _fixture_health(self) -> bool:
        return self._http_health(self.fixture_port, "/healthz")

    @staticmethod
    def _http_health(port: int, path: str = "/") -> bool:
        try:
            response = httpx.get(f"http://127.0.0.1:{port}{path}", timeout=0.8, trust_env=False)
        except httpx.HTTPError:
            return False
        return response.status_code < 500
