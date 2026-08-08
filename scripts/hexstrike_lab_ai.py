"""Install and operate the bounded HexStrike AI lab adapter on host loopback."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import subprocess
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from platformdirs import user_data_path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_URL = "https://github.com/0x4m4/hexstrike-ai.git"
SOURCE_COMMIT = "d689933ff579d839c676c82b231f8e98326c5f04"
PORT = 18889
BASE_URL = f"http://127.0.0.1:{PORT}"
RUNTIME_ROOT = Path(user_data_path("budobugs", ensure_exists=True)) / "lab-ai" / "hexstrike"
SOURCE_ROOT = RUNTIME_ROOT / "source"
VENV_ROOT = RUNTIME_ROOT / ".venv"
STATE_FILE = RUNTIME_ROOT / "state.json"
LOG_FILE = RUNTIME_ROOT / "hexstrike.log"
LOCK_FILE = ROOT / "integrations" / "external-agents" / "hexstrike" / "requirements.lock"


class AdapterError(RuntimeError):
    """Raised when the fail-closed adapter cannot establish a verified state."""


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _python() -> Path:
    relative = Path("Scripts/python.exe") if os.name == "nt" else Path("bin/python")
    return VENV_ROOT / relative


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    temporary.replace(path)


def _run(command: list[str], *, cwd: Path | None = None, timeout: int = 1800) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise AdapterError(f"command failed to start: {command[0]}: {exc}") from exc
    output = (result.stdout + result.stderr).strip()
    if result.returncode != 0:
        raise AdapterError(f"command failed ({result.returncode}): {command[0]}: {output[-800:]}")
    return output


def _patch_loopback_binding() -> None:
    server = SOURCE_ROOT / "hexstrike_server.py"
    text = server.read_text(encoding="utf-8")
    unsafe = 'app.run(host="0.0.0.0", port=API_PORT, debug=DEBUG_MODE)'
    safe = "app.run(host=API_HOST, port=API_PORT, debug=DEBUG_MODE)"
    if safe not in text:
        if text.count(unsafe) != 1:
            raise AdapterError("pinned HexStrike binding statement changed; refusing an unreviewed patch")
        text = text.replace(unsafe, safe)
    health_marker = '@app.route("/budobugs-health", methods=["GET"])'
    if health_marker not in text:
        anchor = '# API Routes\n\n@app.route("/health", methods=["GET"])'
        bounded_health = (
            "# API Routes\n\n"
            f"{health_marker}\n"
            "def budobugs_health():\n"
            '    """Constant-time health endpoint added by the bounded BudoBugs adapter."""\n'
            '    return jsonify({"status": "healthy", "version": "6.0.0", "adapter": "budobugs"})\n\n'
            '@app.route("/health", methods=["GET"])'
        )
        if text.count(anchor) != 1:
            raise AdapterError("pinned HexStrike route anchor changed; refusing an unreviewed patch")
        text = text.replace(anchor, bounded_health)
    server.write_text(text, encoding="utf-8")


def install() -> dict[str, object]:
    RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)
    if not SOURCE_ROOT.exists():
        _run(["git", "clone", "--filter=blob:none", "--no-checkout", SOURCE_URL, str(SOURCE_ROOT)])
        _run(["git", "checkout", "--detach", SOURCE_COMMIT], cwd=SOURCE_ROOT)
    head = _run(["git", "rev-parse", "HEAD"], cwd=SOURCE_ROOT)
    if head != SOURCE_COMMIT:
        raise AdapterError(f"unexpected HexStrike commit: {head}")
    license_text = (SOURCE_ROOT / "LICENSE").read_text(encoding="utf-8")
    if not license_text.startswith("MIT License"):
        raise AdapterError("HexStrike license no longer matches the reviewed MIT text")
    _patch_loopback_binding()
    if not LOCK_FILE.is_file():
        raise AdapterError(f"dependency lock is missing: {LOCK_FILE}")
    if not _python().is_file():
        _run(["uv", "venv", str(VENV_ROOT), "--python", "3.12"])
    _run(["uv", "pip", "sync", "--python", str(_python()), str(LOCK_FILE)])
    receipt = {
        "component": "hexstrike-ai",
        "status": "PASS",
        "source": SOURCE_URL,
        "commit": SOURCE_COMMIT,
        "license": "MIT",
        "binding": BASE_URL,
        "dependency_lock": str(LOCK_FILE),
        "installed_at": _now(),
    }
    _write_json(RUNTIME_ROOT / "install-receipt.json", receipt)
    return receipt


def _read_state() -> dict[str, object]:
    try:
        payload = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _health() -> tuple[bool, dict[str, object]]:
    try:
        response = httpx.get(f"{BASE_URL}/budobugs-health", timeout=3, trust_env=False)
        payload = response.json()
    except (httpx.HTTPError, ValueError):
        return False, {}
    return response.status_code == 200 and isinstance(payload, dict), payload if isinstance(payload, dict) else {}


def up() -> dict[str, object]:
    healthy, payload = _health()
    if healthy:
        return {"status": "PASS", "message": "already running", "health": payload}
    if not _python().is_file() or not (RUNTIME_ROOT / "install-receipt.json").is_file():
        install()
    environment = os.environ.copy()
    environment.update(
        {
            "HEXSTRIKE_HOST": "127.0.0.1",
            "HEXSTRIKE_PORT": str(PORT),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
        }
    )
    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    log_handle = LOG_FILE.open("ab")
    process = subprocess.Popen(
        [str(_python()), str(SOURCE_ROOT / "hexstrike_server.py"), "--port", str(PORT)],
        cwd=SOURCE_ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        creationflags=creationflags,
    )
    log_handle.close()
    state = {
        "pid": process.pid,
        "command": str(SOURCE_ROOT / "hexstrike_server.py"),
        "base_url": BASE_URL,
        "started_at": _now(),
    }
    _write_json(STATE_FILE, state)
    for _ in range(120):
        healthy, payload = _health()
        if healthy:
            return {"status": "PASS", "pid": process.pid, "health": payload}
        if process.poll() is not None:
            STATE_FILE.unlink(missing_ok=True)
            raise AdapterError(f"HexStrike exited with code {process.returncode}; see {LOG_FILE}")
        time.sleep(0.25)
    down()
    raise AdapterError(f"HexStrike did not become healthy; see {LOG_FILE}")


def down() -> dict[str, object]:
    state = _read_state()
    pid = state.get("pid")
    command = state.get("command")
    if not isinstance(pid, int) or pid <= 0 or command != str(SOURCE_ROOT / "hexstrike_server.py"):
        STATE_FILE.unlink(missing_ok=True)
        return {"status": "PASS", "message": "not running"}
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, check=False)
    else:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGTERM)
    STATE_FILE.unlink(missing_ok=True)
    return {"status": "PASS", "message": "stopped", "pid": pid}


def status() -> dict[str, object]:
    healthy, payload = _health()
    receipt = RUNTIME_ROOT / "install-receipt.json"
    return {
        "status": "PASS" if healthy else "NEEDS_RUNTIME",
        "installed": receipt.is_file(),
        "running": healthy,
        "base_url": BASE_URL,
        "commit": SOURCE_COMMIT if receipt.is_file() else None,
        "health": payload,
    }


def validate(target: str) -> dict[str, object]:
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise AdapterError("lab-ai validation target must be an explicit localhost HTTP(S) URL")
    healthy, _ = _health()
    if not healthy:
        up()
    response = httpx.post(
        f"{BASE_URL}/api/intelligence/analyze-target",
        json={"target": target, "analysis_type": "bounded-local-adapter"},
        timeout=20,
        trust_env=False,
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise AdapterError("HexStrike returned an invalid validation result")
    receipt = {
        "receipt_id": f"hexstrike-{uuid.uuid4()}",
        "framework": "hexstrike-ai",
        "commit": SOURCE_COMMIT,
        "mode": "lab",
        "target": target,
        "operation": "intelligence/analyze-target",
        "arbitrary_command_endpoint_used": False,
        "result": payload,
        "completed_at": _now(),
    }
    receipt_path = RUNTIME_ROOT / "receipts" / f"{receipt['receipt_id']}.json"
    _write_json(receipt_path, receipt)
    return {"status": "PASS", "receipt": str(receipt_path), "result": payload}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "up", "down", "status", "validate"))
    parser.add_argument("--target", default="http://127.0.0.1:8765/healthz")
    args = parser.parse_args()
    try:
        result = {
            "install": install,
            "up": up,
            "down": down,
            "status": status,
            "validate": lambda: validate(args.target),
        }[args.action]()
    except (AdapterError, httpx.HTTPError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, ensure_ascii=False, indent=2))
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
