from __future__ import annotations

import json
from pathlib import Path

import pytest

from budobugs.labs import fixture_runner
from budobugs.labs.manager import LabManager


def _write_native_state(manager: LabManager, *, token: str = "owned-token-001") -> dict[str, object]:
    state: dict[str, object] = {
        "schema_version": 2,
        "backend": "native",
        "pid": 4242,
        "port": manager.fixture_port,
        "ownership_token": token,
        "owned_pids": [4242, 4343],
    }
    manager.state_file.parent.mkdir(parents=True, exist_ok=True)
    manager.state_file.write_text(json.dumps(state), encoding="utf-8")
    return state


def test_native_state_uses_exact_runner_port_and_ownership_tokens(tmp_path: Path) -> None:
    manager = LabManager(tmp_path, tmp_path / "runtime", fixture_port=49123)
    state = _write_native_state(manager)

    assert manager._native_required_tokens(state) == (
        "budobugs.labs.fixture_runner",
        "--port",
        "49123",
        "--ownership-token",
        "owned-token-001",
    )


def test_native_down_retains_state_when_owned_termination_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = LabManager(tmp_path, tmp_path / "runtime", fixture_port=49124)
    _write_native_state(manager)
    command = "python -m budobugs.labs.fixture_runner --port 49124 --ownership-token owned-token-001"
    monkeypatch.setattr(LabManager, "_matching_process_ids", classmethod(lambda _cls, _tokens: {4242}))
    monkeypatch.setattr(LabManager, "_process_command_line", staticmethod(lambda _pid: command))
    monkeypatch.setattr(LabManager, "_terminate_owned_process", classmethod(lambda _cls, _pid, **_kwargs: False))

    with pytest.raises(RuntimeError, match="termination failed"):
        manager.down()

    assert manager.state_file.is_file()


def test_native_down_retains_state_when_health_survives_without_an_owned_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = LabManager(tmp_path, tmp_path / "runtime", fixture_port=49125)
    _write_native_state(manager)
    clock = iter((0.0, 9.0))
    monkeypatch.setattr(LabManager, "_matching_process_ids", classmethod(lambda _cls, _tokens: set()))
    monkeypatch.setattr(LabManager, "_process_command_line", staticmethod(lambda _pid: None))
    monkeypatch.setattr(LabManager, "_process_snapshot", classmethod(lambda _cls: {}))
    monkeypatch.setattr(LabManager, "_listener_process_ids", staticmethod(lambda _port: set()))
    monkeypatch.setattr("budobugs.labs.manager.time.monotonic", lambda: next(clock))
    monkeypatch.setattr("budobugs.labs.manager.time.sleep", lambda _seconds: None)
    monkeypatch.setattr(LabManager, "_http_health", staticmethod(lambda *_args, **_kwargs: True))

    with pytest.raises(RuntimeError, match="postcondition failed"):
        manager.down()

    assert manager.state_file.is_file()


def test_native_down_deletes_state_only_after_process_and_health_postconditions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = LabManager(tmp_path, tmp_path / "runtime", fixture_port=49126)
    _write_native_state(manager)
    matching_results = iter(({4242}, set()))
    command = "python -m budobugs.labs.fixture_runner --port 49126 --ownership-token owned-token-001"
    monkeypatch.setattr(
        LabManager,
        "_matching_process_ids",
        classmethod(lambda _cls, _tokens: next(matching_results)),
    )
    monkeypatch.setattr(LabManager, "_process_command_line", staticmethod(lambda _pid: command))
    monkeypatch.setattr(LabManager, "_terminate_owned_process", classmethod(lambda _cls, _pid, **_kwargs: True))
    monkeypatch.setattr(LabManager, "_http_health", staticmethod(lambda *_args, **_kwargs: False))

    status = manager.down()

    assert not status.running
    assert status.backend == "none"
    assert not manager.state_file.exists()


def test_native_down_reaps_a_token_owned_child_after_the_recorded_root_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = LabManager(tmp_path, tmp_path / "runtime", fixture_port=49128)
    _write_native_state(manager)
    matching_results = iter(({4343}, set()))
    command = "python -m budobugs.labs.fixture_runner --port 49128 --ownership-token owned-token-001"
    terminated: list[int] = []
    monkeypatch.setattr(
        LabManager,
        "_matching_process_ids",
        classmethod(lambda _cls, _tokens: next(matching_results)),
    )
    monkeypatch.setattr(
        LabManager,
        "_process_command_line",
        staticmethod(lambda pid: command if pid == 4343 else None),
    )
    monkeypatch.setattr(LabManager, "_process_snapshot", classmethod(lambda _cls: {}))
    monkeypatch.setattr("budobugs.labs.manager.time.sleep", lambda _seconds: None)

    def terminate(_cls: type[LabManager], pid: int, **_kwargs: object) -> bool:
        terminated.append(pid)
        return True

    monkeypatch.setattr(LabManager, "_terminate_owned_process", classmethod(terminate))
    monkeypatch.setattr(LabManager, "_http_health", staticmethod(lambda *_args, **_kwargs: False))

    status = manager.down()

    assert terminated == [4343]
    assert not status.running
    assert not manager.state_file.exists()


def test_native_down_recovers_listener_child_when_wmi_is_transiently_empty_and_state_missed_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = LabManager(tmp_path, tmp_path / "runtime", fixture_port=49130)
    state = _write_native_state(manager)
    state["owned_pids"] = [4242]
    manager.state_file.write_text(json.dumps(state), encoding="utf-8")
    command = "python -m budobugs.labs.fixture_runner --port 49130 --ownership-token owned-token-001"
    health_results = iter((True, False, False))
    terminated: list[int] = []
    monkeypatch.setattr(LabManager, "_matching_process_ids", classmethod(lambda _cls, _tokens: set()))
    monkeypatch.setattr(LabManager, "_process_snapshot", classmethod(lambda _cls: {}))
    monkeypatch.setattr(
        LabManager,
        "_process_command_line",
        staticmethod(lambda pid: command if pid == 4343 else None),
    )
    monkeypatch.setattr(
        LabManager, "_listener_process_ids", staticmethod(lambda port: {4343} if port == 49130 else set())
    )
    monkeypatch.setattr("budobugs.labs.manager.time.sleep", lambda _seconds: None)
    monkeypatch.setattr(
        LabManager,
        "_http_health",
        staticmethod(lambda *_args, **_kwargs: next(health_results)),
    )

    def terminate(_cls: type[LabManager], pid: int, **_kwargs: object) -> bool:
        terminated.append(pid)
        return True

    monkeypatch.setattr(LabManager, "_terminate_owned_process", classmethod(terminate))

    status = manager.down()

    assert terminated == [4343]
    assert not status.running
    assert not manager.state_file.exists()


def test_native_down_waits_for_health_to_clear_after_the_owned_process_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = LabManager(tmp_path, tmp_path / "runtime", fixture_port=49131)
    _write_native_state(manager)
    command = "python -m budobugs.labs.fixture_runner --port 49131 --ownership-token owned-token-001"
    first_match = True
    health_results = iter((True, True, True, False, False))

    def matching(_cls: type[LabManager], _tokens: tuple[str, ...]) -> set[int]:
        nonlocal first_match
        if first_match:
            first_match = False
            return {4242}
        return set()

    monkeypatch.setattr(LabManager, "_matching_process_ids", classmethod(matching))
    monkeypatch.setattr(LabManager, "_process_command_line", staticmethod(lambda _pid: command))
    monkeypatch.setattr(LabManager, "_listener_process_ids", staticmethod(lambda _port: set()))
    monkeypatch.setattr(LabManager, "_terminate_owned_process", classmethod(lambda _cls, _pid, **_kwargs: True))
    monkeypatch.setattr("budobugs.labs.manager.time.sleep", lambda _seconds: None)
    monkeypatch.setattr(
        LabManager,
        "_http_health",
        staticmethod(lambda *_args, **_kwargs: next(health_results)),
    )

    status = manager.down()

    assert not status.running
    assert not manager.state_file.exists()


def test_native_down_refuses_a_healthy_fixture_without_ownership_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = LabManager(tmp_path, tmp_path / "runtime", fixture_port=49127)
    monkeypatch.setattr(LabManager, "_http_health", staticmethod(lambda *_args, **_kwargs: True))

    with pytest.raises(RuntimeError, match="no ownership state"):
        manager.down()


def test_fixture_runner_passes_only_the_local_fixture_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, object] = {}
    monkeypatch.setattr(
        "sys.argv",
        ["fixture_runner", "--port", "49129", "--ownership-token", "owned-token-002"],
    )
    monkeypatch.setattr(fixture_runner.uvicorn, "run", lambda app, **kwargs: observed.update(app=app, **kwargs))

    fixture_runner.main()

    assert observed == {
        "app": "budobugs.labs.fixture_app:app",
        "host": "127.0.0.1",
        "port": 49129,
        "access_log": False,
    }
