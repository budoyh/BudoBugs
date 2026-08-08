"""No-shell subprocess wrapper with policy, timeout, redaction, and receipts."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from budobugs.core.identifiers import new_id
from budobugs.core.io import atomic_write_bytes, atomic_write_json, atomic_write_text, sha256_bytes
from budobugs.core.paths import safe_join
from budobugs.core.policy import require_allowed, tool_allowed
from budobugs.core.redaction import redact_text
from budobugs.models import Engagement, ToolExecutionReceipt, ToolRequest
from budobugs.tools.health import resolve_executable
from budobugs.tools.registry import ToolRegistry


class ToolExecutionError(RuntimeError):
    """Raised when a registered executable cannot be safely launched."""


class ToolRunner:
    def __init__(
        self,
        registry: ToolRegistry,
        artifact_root: Path,
        *,
        workspace_root: Path | None = None,
        output_limit_bytes: int = 10 * 1024 * 1024,
    ) -> None:
        self.registry = registry
        self.artifact_root = artifact_root.resolve()
        self.workspace_root = (workspace_root or Path.cwd()).resolve()
        self.output_limit_bytes = output_limit_bytes
        self._semaphores: dict[str, asyncio.Semaphore] = {}

    async def run(
        self,
        request: ToolRequest,
        engagement: Engagement,
        *,
        secret_environment: dict[str, str] | None = None,
    ) -> ToolExecutionReceipt:
        definition = self.registry.get(request.tool_name)
        decision = tool_allowed(engagement, definition, request.target)
        require_allowed(decision)
        if definition.executable is None:
            raise ToolExecutionError(f"{definition.name} is container/manual only")
        executable = resolve_executable(definition.executable)
        if executable is None:
            raise ToolExecutionError(f"registered executable not found: {definition.executable}")
        output_dir = safe_join(self.artifact_root, request.output_directory)
        output_dir.mkdir(parents=True, exist_ok=True)
        arguments = list(request.arguments)
        self._validate_arguments(arguments, definition.allowed_argument_patterns)
        target = request.target
        fixed_arguments = self._expand_fixed_arguments(definition.fixed_arguments, output_dir, self.workspace_root)
        command_prefix = [executable]
        if os.name == "nt" and definition.name == "semgrep":
            wsl = resolve_executable("wsl") or resolve_executable("wsl.exe")
            if wsl is None:
                raise ToolExecutionError("Semgrep requires the dedicated WSL runtime on Windows")
            command_prefix = [
                wsl,
                "-d",
                "BudoBugs-Ubuntu-24.04",
                "-u",
                "root",
                "--",
                "/opt/budobugs/semgrep-1.172.0/bin/semgrep",
            ]
            fixed_arguments = [self._windows_to_wsl_path(item) for item in fixed_arguments]
            target = self._windows_to_wsl_path(target) if target is not None else None
        if target is not None:
            if definition.target_argument is None:
                raise ToolExecutionError("tool manifest does not declare target injection")
            if definition.target_argument:
                arguments.extend((definition.target_argument, target))
            else:
                arguments.append(target)
        command = [*command_prefix, *fixed_arguments, *arguments]
        environment = self._environment(definition.required_secrets, secret_environment or {})
        semaphore = self._semaphores.setdefault(definition.name, asyncio.Semaphore(definition.concurrency))
        async with semaphore:
            return await self._attempts(
                command=command,
                request=request,
                timeout=definition.timeout,
                retries=definition.retry_count,
                environment=environment,
                output_dir=output_dir,
                policy_decision_id=decision.decision_id,
                preserve_raw=request.preserve_raw_output and engagement.selected_mode.value in {"lab", "source"},
            )

    @staticmethod
    def _validate_arguments(arguments: list[str], allowed_patterns: list[str]) -> None:
        scope_or_path_flags = {
            "-d",
            "--domain",
            "-host",
            "--host",
            "-l",
            "--list",
            "-o",
            "--output",
            "-proxy",
            "--proxy",
            "-target",
            "--target",
            "-u",
            "--url",
            "-w",
            "--wordlist",
            "-config",
            "--config",
        }
        for argument in arguments:
            flag = argument.split("=", 1)[0].lower()
            if flag in scope_or_path_flags or "://" in argument:
                raise ToolExecutionError(f"scope/path override is controlled by the wrapper: {flag}")
            if not any(re.fullmatch(pattern, argument) for pattern in allowed_patterns):
                raise ToolExecutionError(f"argument is not allowed by the tool manifest: {argument!r}")

    @staticmethod
    def _environment(required: list[str], supplied: dict[str, str]) -> dict[str, str]:
        missing = [name for name in required if not supplied.get(name)]
        if missing:
            raise ToolExecutionError(f"missing required secret environment: {', '.join(missing)}")
        allowed_names = {"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "LANG", "LC_ALL"}
        environment = {name: value for name, value in os.environ.items() if name.upper() in allowed_names}
        environment.update({name: supplied[name] for name in required})
        return environment

    @staticmethod
    def _expand_fixed_arguments(arguments: list[str], output_dir: Path, workspace_root: Path) -> list[str]:
        return [
            item.replace("{output_dir}", str(output_dir)).replace("{workspace_root}", str(workspace_root))
            for item in arguments
        ]

    @staticmethod
    def _windows_to_wsl_path(value: str) -> str:
        path = Path(value)
        if not path.is_absolute() or not path.drive:
            return value
        drive = path.drive[0].lower()
        tail = path.as_posix()[2:]
        return f"/mnt/{drive}{tail}"

    async def _attempts(
        self,
        *,
        command: list[str],
        request: ToolRequest,
        timeout: int,
        retries: int,
        environment: dict[str, str],
        output_dir: Path,
        policy_decision_id: str,
        preserve_raw: bool,
    ) -> ToolExecutionReceipt:
        started_at = datetime.now(UTC)
        stdout = b""
        stderr = b""
        exit_code: int | None = None
        timed_out = False
        attempts = 0
        for attempt in range(retries + 1):
            attempts = attempt + 1
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=environment,
                cwd=output_dir,
            )
            try:
                stdout, stderr, output_exceeded = await asyncio.wait_for(
                    self._read_process(process),
                    timeout=timeout,
                )
                exit_code = await process.wait()
                timed_out = False
                if output_exceeded and exit_code == 0:
                    exit_code = 125
            except TimeoutError:
                process.kill()
                await process.wait()
                timed_out = True
                exit_code = None
            if not timed_out and exit_code == 0:
                break
        redacted_stdout = redact_text(stdout.decode("utf-8", errors="replace")) or ""
        redacted_stderr = redact_text(stderr.decode("utf-8", errors="replace")) or ""
        stdout_path = output_dir / "stdout.txt"
        stderr_path = output_dir / "stderr.txt"
        atomic_write_text(stdout_path, redacted_stdout)
        atomic_write_text(stderr_path, redacted_stderr)
        raw_stdout: Path | None = None
        raw_stderr: Path | None = None
        if preserve_raw:
            raw_stdout = output_dir / "stdout.raw"
            raw_stderr = output_dir / "stderr.raw"
            atomic_write_bytes(raw_stdout, stdout)
            atomic_write_bytes(raw_stderr, stderr)
            for path in (raw_stdout, raw_stderr):
                with contextlib.suppress(OSError):
                    path.chmod(0o600)
        normalized_path = output_dir / "normalized.json"
        atomic_write_json(
            normalized_path,
            {
                "exit_code": exit_code,
                "timed_out": timed_out,
                "stdout": redacted_stdout,
                "stderr": redacted_stderr,
            },
        )
        if timed_out:
            status: Literal["completed", "failed", "timeout", "blocked"] = "timeout"
        elif exit_code == 0:
            status = "completed"
        else:
            status = "failed"
        receipt = ToolExecutionReceipt(
            receipt_id=new_id("receipt"),
            invocation_id=request.invocation_id,
            run_id=request.run_id,
            engagement_id=request.engagement_id,
            tool_name=request.tool_name,
            executable=command[0],
            arguments=[redact_text(item) or "" for item in command[1:]],
            target=request.target,
            started_at=started_at,
            completed_at=datetime.now(UTC),
            exit_code=exit_code,
            timed_out=timed_out,
            attempt_count=attempts,
            stdout_artifact=str(stdout_path.relative_to(self.artifact_root)),
            stderr_artifact=str(stderr_path.relative_to(self.artifact_root)),
            raw_stdout_artifact=(str(raw_stdout.relative_to(self.artifact_root)) if raw_stdout is not None else None),
            raw_stderr_artifact=(str(raw_stderr.relative_to(self.artifact_root)) if raw_stderr is not None else None),
            normalized_output_artifact=str(normalized_path.relative_to(self.artifact_root)),
            stdout_sha256=sha256_bytes(stdout),
            stderr_sha256=sha256_bytes(stderr),
            redaction_applied=redacted_stdout != stdout.decode("utf-8", errors="replace")
            or redacted_stderr != stderr.decode("utf-8", errors="replace"),
            policy_decision_id=policy_decision_id,
            status=status,
            observations=[
                f"attempts={attempts}",
                f"exit_code={exit_code}",
                f"timed_out={timed_out}",
            ],
        )
        atomic_write_json(output_dir / "receipt.json", json.loads(receipt.model_dump_json()))
        return receipt

    async def _read_process(
        self,
        process: asyncio.subprocess.Process,
    ) -> tuple[bytes, bytes, bool]:
        exceeded = asyncio.Event()

        async def consume(stream: asyncio.StreamReader | None) -> bytes:
            if stream is None:
                return b""
            output = bytearray()
            while True:
                chunk = await stream.read(65536)
                if not chunk:
                    break
                remaining = self.output_limit_bytes - len(output)
                if remaining > 0:
                    output.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    exceeded.set()
                    if process.returncode is None:
                        process.kill()
            return bytes(output)

        stdout, stderr = await asyncio.gather(consume(process.stdout), consume(process.stderr))
        return stdout, stderr, exceeded.is_set()
