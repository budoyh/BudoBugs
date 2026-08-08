from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from scripts import generate_license_inventory, hexstrike_lab_ai


def test_python_license_inventory_reuses_only_exact_committed_metadata(tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / "licenses"
    output.mkdir()
    (output / "python-production.json").write_text(
        json.dumps(
            {
                "packages": [
                    {
                        "name": "Conditional-Package",
                        "version": "1.2.3",
                        "declared_license": "MIT",
                        "license_expression": "MIT",
                        "license_classifiers": [],
                        "notice_files": ["LICENSE"],
                        "homepage": "https://example.invalid/conditional-package",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(generate_license_inventory, "OUTPUT", output)
    monkeypatch.setattr(
        generate_license_inventory,
        "production_python_versions",
        lambda: {"conditional-package": "1.2.3"},
    )
    monkeypatch.setattr(generate_license_inventory.importlib.metadata, "distributions", list)

    inventory = generate_license_inventory.python_inventory()

    assert inventory["packages"] == [
        {
            "name": "Conditional-Package",
            "version": "1.2.3",
            "declared_license": "MIT",
            "license_expression": "MIT",
            "license_classifiers": [],
            "notice_files": ["LICENSE"],
            "homepage": "https://example.invalid/conditional-package",
            "metadata_source": "committed-exact-version",
        }
    ]


class _FixtureProcess:
    pid = 12345
    returncode: int | None = None

    def poll(self) -> int | None:
        return self.returncode


def _configure_hexstrike_runtime(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(hexstrike_lab_ai, "RUNTIME_ROOT", tmp_path)
    monkeypatch.setattr(hexstrike_lab_ai, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(hexstrike_lab_ai, "LOG_FILE", tmp_path / "hexstrike.log")
    monkeypatch.setattr(hexstrike_lab_ai, "_python", lambda: Path(sys.executable))
    monkeypatch.setattr(hexstrike_lab_ai.time, "sleep", lambda _seconds: None)
    (tmp_path / "install-receipt.json").write_text("{}\n", encoding="utf-8")


def test_hexstrike_background_process_forces_utf8(tmp_path: Path, monkeypatch) -> None:
    _configure_hexstrike_runtime(tmp_path, monkeypatch)
    health = iter([(False, {}), (True, {"status": "healthy"})])
    monkeypatch.setattr(hexstrike_lab_ai, "_health", lambda: next(health))
    observed: dict[str, object] = {}

    def popen(*args: object, **kwargs: object) -> _FixtureProcess:
        observed.update(kwargs)
        return _FixtureProcess()

    monkeypatch.setattr(hexstrike_lab_ai.subprocess, "Popen", popen)

    result = hexstrike_lab_ai.up()

    environment = observed["env"]
    assert isinstance(environment, dict)
    assert environment["PYTHONIOENCODING"] == "utf-8"
    assert environment["PYTHONUTF8"] == "1"
    assert result["status"] == "PASS"


def test_hexstrike_early_exit_removes_stale_state(tmp_path: Path, monkeypatch) -> None:
    _configure_hexstrike_runtime(tmp_path, monkeypatch)
    monkeypatch.setattr(hexstrike_lab_ai, "_health", lambda: (False, {}))
    process = _FixtureProcess()
    process.returncode = 1
    monkeypatch.setattr(hexstrike_lab_ai.subprocess, "Popen", lambda *_args, **_kwargs: process)

    with pytest.raises(hexstrike_lab_ai.AdapterError, match="exited with code 1"):
        hexstrike_lab_ai.up()

    assert not hexstrike_lab_ai.STATE_FILE.exists()
