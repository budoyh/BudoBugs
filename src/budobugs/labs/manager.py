"""Docker-first, truthful local lab lifecycle with a native fixture fallback."""

from __future__ import annotations

import ctypes
import json
import os
import secrets
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
        ownership_token = secrets.token_hex(16)
        creationflags = 0
        if sys.platform == "win32":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0
            )
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "budobugs.labs.fixture_runner",
                "--port",
                str(self.fixture_port),
                "--ownership-token",
                ownership_token,
            ],
            cwd=self.root,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=creationflags,
            start_new_session=sys.platform != "win32",
        )
        log.close()
        state: dict[str, object] = {
            "schema_version": 2,
            "backend": "native",
            "pid": process.pid,
            "port": self.fixture_port,
            "ownership_token": ownership_token,
            "owned_pids": [process.pid],
        }
        atomic_write_json(self.state_file, state)
        for _ in range(50):
            if self._fixture_health():
                state["owned_pids"] = sorted(
                    {process.pid, *self._matching_process_ids(self._native_required_tokens(state))}
                )
                atomic_write_json(self.state_file, state)
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
        elif state.get("backend") == "native":
            self._stop_native_fixture(state)
        elif not state and self._fixture_health():
            raise RuntimeError("native fixture is healthy but no ownership state exists; refusing an unowned stop")
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
    def _native_required_tokens(state: dict[str, object]) -> tuple[str, ...]:
        port = state.get("port")
        ownership_token = state.get("ownership_token")
        if isinstance(ownership_token, str) and ownership_token and isinstance(port, int):
            return (
                "budobugs.labs.fixture_runner",
                "--port",
                str(port),
                "--ownership-token",
                ownership_token,
            )
        # Schema-v1 state used uvicorn directly. Keep the original command-token
        # verification so an interrupted pre-upgrade run remains recoverable.
        return ("budobugs.labs.fixture_app", f"--port {port}")

    @classmethod
    def _process_snapshot(cls) -> dict[int, tuple[int, str]]:
        """Return PID -> (parent PID, normalized command line) without shell interpolation."""

        if sys.platform == "win32":
            return {
                pid: (0, command_line)
                for pid in cls._windows_process_ids()
                if (command_line := cls._windows_process_command_line(pid))
            }

        snapshot = {}
        proc_root = Path("/proc")
        try:
            entries = list(proc_root.iterdir())
        except OSError:
            return cls._posix_ps_snapshot()
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                command = (
                    (entry / "cmdline")
                    .read_bytes()
                    .replace(b"\x00", b" ")
                    .decode("utf-8", errors="replace")
                    .strip()
                    .lower()
                )
                status_lines = (entry / "status").read_text(encoding="utf-8", errors="replace").splitlines()
                ppid_line = next(line for line in status_lines if line.startswith("PPid:"))
                ppid = int(ppid_line.split(":", 1)[1].strip())
            except (OSError, StopIteration, ValueError):
                continue
            snapshot[int(entry.name)] = (ppid, command)
        return snapshot or cls._posix_ps_snapshot()

    @staticmethod
    def _posix_ps_snapshot() -> dict[int, tuple[int, str]]:
        try:
            result = subprocess.run(
                ["ps", "-axo", "pid=,ppid=,command="],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return {}
        if result.returncode != 0:
            return {}
        snapshot: dict[int, tuple[int, str]] = {}
        for line in result.stdout.splitlines():
            columns = line.strip().split(maxsplit=2)
            if len(columns) != 3:
                continue
            try:
                pid = int(columns[0])
                ppid = int(columns[1])
            except ValueError:
                continue
            snapshot[pid] = (ppid, columns[2].lower())
        return snapshot

    @staticmethod
    def _windows_process_ids() -> set[int]:
        """Enumerate PIDs through PSAPI without relying on the WMI service."""

        if sys.platform != "win32":
            return set()
        from ctypes import wintypes

        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        enum_processes = psapi.EnumProcesses
        enum_processes.argtypes = (
            ctypes.POINTER(wintypes.DWORD),
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        )
        enum_processes.restype = wintypes.BOOL
        capacity = 1024
        while capacity <= 65536:
            process_ids = (wintypes.DWORD * capacity)()
            bytes_returned = wintypes.DWORD()
            if not enum_processes(process_ids, ctypes.sizeof(process_ids), ctypes.byref(bytes_returned)):
                return set()
            count = bytes_returned.value // ctypes.sizeof(wintypes.DWORD)
            if count < capacity:
                return {int(pid) for pid in process_ids[:count] if pid > 0}
            capacity *= 2
        return set()

    @staticmethod
    def _windows_process_command_line(pid: int) -> str | None:
        """Read a same-user process command line via NtQueryInformationProcess."""

        if sys.platform != "win32" or pid <= 0:
            return None
        from ctypes import wintypes

        process_query_limited_information = 0x1000
        process_query_information = 0x0400
        process_vm_read = 0x0010
        process_command_line_information = 60
        status_info_length_mismatch = ctypes.c_long(0xC0000004).value
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        open_process = kernel32.OpenProcess
        open_process.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        open_process.restype = wintypes.HANDLE
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL
        query_process = ntdll.NtQueryInformationProcess
        query_process.argtypes = (
            wintypes.HANDLE,
            wintypes.ULONG,
            wintypes.LPVOID,
            wintypes.ULONG,
            ctypes.POINTER(wintypes.ULONG),
        )
        query_process.restype = wintypes.LONG

        for access in (process_query_limited_information, process_query_information | process_vm_read):
            handle = open_process(access, False, pid)
            if not handle:
                continue
            try:
                length = wintypes.ULONG()
                status = query_process(
                    handle,
                    process_command_line_information,
                    None,
                    0,
                    ctypes.byref(length),
                )
                if status != status_info_length_mismatch or length.value == 0:
                    continue
                buffer = ctypes.create_string_buffer(length.value)
                status = query_process(
                    handle,
                    process_command_line_information,
                    buffer,
                    length.value,
                    ctypes.byref(length),
                )
                if status != 0:
                    continue
                unicode_length = int.from_bytes(buffer.raw[0:2], "little")
                pointer_size = ctypes.sizeof(ctypes.c_void_p)
                pointer_offset = 8 if pointer_size == 8 else 4
                pointer = int.from_bytes(buffer.raw[pointer_offset : pointer_offset + pointer_size], "little")
                if unicode_length <= 0 or pointer == 0:
                    return None
                return ctypes.wstring_at(pointer, unicode_length // 2).strip().lower()
            finally:
                close_handle(handle)
        return None

    @classmethod
    def _matching_process_ids(cls, required_tokens: tuple[str, ...]) -> set[int]:
        normalized = tuple(token.lower() for token in required_tokens)
        return {
            pid
            for pid, (_ppid, command_line) in cls._process_snapshot().items()
            if command_line and all(token in command_line for token in normalized)
        }

    @staticmethod
    def _listener_process_ids(port: int) -> set[int]:
        """Return TCP listener PIDs; callers must independently prove ownership."""

        if sys.platform != "win32":
            return set()
        try:
            result = subprocess.run(
                ["netstat", "-ano", "-p", "tcp"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return set()
        if result.returncode != 0:
            return set()
        listeners: set[int] = set()
        for line in result.stdout.splitlines():
            columns = line.split()
            if len(columns) < 5 or columns[0].lower() != "tcp" or columns[3].lower() != "listening":
                continue
            try:
                local_port = int(columns[1].rsplit(":", 1)[1])
                pid = int(columns[4])
            except (IndexError, ValueError):
                continue
            if local_port == port and pid > 0:
                listeners.add(pid)
        return listeners

    @classmethod
    def _command_matches_tokens(cls, pid: int, required_tokens: tuple[str, ...]) -> bool:
        """Re-read one PID and require its full signature immediately before use."""

        normalized = tuple(token.lower() for token in required_tokens)
        for attempt in range(3):
            command_line = cls._process_command_line(pid)
            if command_line:
                return all(token in command_line for token in normalized)
            snapshot_command = cls._process_snapshot().get(pid, (0, ""))[1]
            if snapshot_command:
                return all(token in snapshot_command for token in normalized)
            if attempt < 2:
                time.sleep(0.05)
        return False

    @classmethod
    def _owned_listener_process_ids(cls, port: int, required_tokens: tuple[str, ...]) -> set[int]:
        return {pid for pid in cls._listener_process_ids(port) if cls._command_matches_tokens(pid, required_tokens)}

    def _stop_native_fixture(self, state: dict[str, object]) -> None:
        """Stop every exactly-owned native fixture process and verify postconditions."""

        port = state.get("port")
        if not isinstance(port, int):
            raise RuntimeError("native fixture ownership state has no valid port; state was retained")
        required_tokens = self._native_required_tokens(state)
        matching = self._matching_process_ids(required_tokens)
        stored_pids = state.get("owned_pids")
        expected_pids = {pid for pid in stored_pids if isinstance(pid, int)} if isinstance(stored_pids, list) else set()
        root_pid = state.get("pid")
        if isinstance(root_pid, int):
            expected_pids.add(root_pid)
        # Recorded PIDs are evidence, never authority by themselves: every live
        # process is revalidated against the full command signature before kill.
        live_expected = {pid for pid in expected_pids if self._command_matches_tokens(pid, required_tokens)}
        matching.update(live_expected)
        healthy = self._http_health(port, "/healthz", timeout=0.25)
        if healthy:
            matching.update(self._owned_listener_process_ids(port, required_tokens))
        if matching:
            termination_results = [
                self._terminate_owned_process(pid, required_tokens=required_tokens) for pid in sorted(matching)
            ]
            stopped_any = any(termination_results)
            if not stopped_any:
                raise RuntimeError(
                    "native fixture ownership validation or process-tree termination failed; state retained"
                )

        deadline = time.monotonic() + 8.0
        remaining = self._matching_process_ids(required_tokens)
        healthy = self._http_health(port, "/healthz", timeout=0.25)
        while (remaining or healthy) and time.monotonic() < deadline:
            if healthy:
                listener_owned = self._owned_listener_process_ids(port, required_tokens)
                remaining.update(listener_owned)
                for pid in sorted(listener_owned):
                    self._terminate_owned_process(pid, required_tokens=required_tokens)
            time.sleep(0.1)
            remaining = self._matching_process_ids(required_tokens)
            healthy = self._http_health(port, "/healthz", timeout=0.25)
        if remaining:
            for pid in sorted(remaining):
                self._force_terminate_owned_process(pid, required_tokens=required_tokens)
            time.sleep(0.2)
            remaining = self._matching_process_ids(required_tokens)
            healthy = self._http_health(port, "/healthz", timeout=0.25)
        if remaining or healthy:
            details = f"remaining_pids={sorted(remaining)}, health={healthy}, port={port}"
            raise RuntimeError(f"native fixture shutdown postcondition failed ({details}); state retained")

    @staticmethod
    def _process_command_line(pid: int) -> str | None:
        if pid <= 0:
            return None
        if sys.platform == "win32":
            return LabManager._windows_process_command_line(pid)
        try:
            return (
                Path(f"/proc/{pid}/cmdline")
                .read_bytes()
                .replace(b"\x00", b" ")
                .decode("utf-8", errors="replace")
                .lower()
            )
        except OSError:
            try:
                result = subprocess.run(
                    ["ps", "-p", str(pid), "-o", "command="],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=10,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                return None
            command_line = result.stdout.strip().lower()
            return command_line if result.returncode == 0 and command_line else None

    @classmethod
    def _terminate_owned_process(cls, pid: int, *, required_tokens: tuple[str, ...]) -> bool:
        return cls._signal_owned_process(pid, required_tokens=required_tokens, force=False)

    @classmethod
    def _force_terminate_owned_process(cls, pid: int, *, required_tokens: tuple[str, ...]) -> bool:
        return cls._signal_owned_process(pid, required_tokens=required_tokens, force=True)

    @classmethod
    def _signal_owned_process(cls, pid: int, *, required_tokens: tuple[str, ...], force: bool) -> bool:
        if not cls._command_matches_tokens(pid, required_tokens):
            return False
        try:
            if sys.platform == "win32":
                return cls._windows_terminate_process(pid)
            process_group = os.getpgid(pid)
            selected_signal = signal.SIGKILL if force else signal.SIGTERM
            if process_group == pid:
                os.killpg(process_group, selected_signal)
            else:
                os.kill(pid, selected_signal)
            return True
        except (OSError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def _windows_terminate_process(pid: int) -> bool:
        """Terminate one exact PID through the Win32 process handle API."""

        from ctypes import wintypes

        process_terminate = 0x0001
        synchronize = 0x00100000
        wait_object_0 = 0x00000000
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        open_process = kernel32.OpenProcess
        open_process.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        open_process.restype = wintypes.HANDLE
        terminate_process = kernel32.TerminateProcess
        terminate_process.argtypes = (wintypes.HANDLE, wintypes.UINT)
        terminate_process.restype = wintypes.BOOL
        wait_for_single_object = kernel32.WaitForSingleObject
        wait_for_single_object.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        wait_for_single_object.restype = wintypes.DWORD
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL
        handle = open_process(process_terminate | synchronize, False, pid)
        if not handle:
            return False
        try:
            if not terminate_process(handle, 1):
                return False
            wait_result = int(wait_for_single_object(handle, 5000))
            return wait_result == wait_object_0
        finally:
            close_handle(handle)

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
    def _http_health(port: int, path: str = "/", *, timeout: float = 2.5) -> bool:
        try:
            response = httpx.get(f"http://127.0.0.1:{port}{path}", timeout=timeout, trust_env=False)
        except httpx.HTTPError:
            return False
        return response.status_code < 500
