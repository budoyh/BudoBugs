from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from scripts import (
    generate_fixture_vex,
    generate_license_inventory,
    generate_release_metadata,
    hexstrike_lab_ai,
    verify_release,
)


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


def test_release_provenance_rejects_changed_source_snapshot(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "src" / "budobugs"
    source.mkdir(parents=True)
    module = source / "feature.py"
    module.write_text("VALUE = 1\n", encoding="utf-8")
    for relative in (
        ".github/workflows/ci.yml",
        "config/semgrep.yml",
        "docs/operations/TESTING.md",
        "scripts/check_release.py",
        "tests/unit/test_feature.py",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("checked input\n", encoding="utf-8")
    monkeypatch.setattr(generate_release_metadata, "ROOT", tmp_path)
    monkeypatch.setattr(verify_release, "ROOT", tmp_path)
    provenance = {"source_snapshot": generate_release_metadata.source_snapshot(tmp_path)}

    assert {
        ".github/workflows/ci.yml",
        "config/semgrep.yml",
        "docs/operations/TESTING.md",
        "scripts/check_release.py",
        "src/budobugs/feature.py",
        "tests/unit/test_feature.py",
    }.issubset(provenance["source_snapshot"]["included_paths"])

    verify_release.validate_source_snapshot(provenance)

    module.write_text("VALUE = 2\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="1"):
        verify_release.validate_source_snapshot(provenance)


def test_release_snapshot_normalizes_text_newlines_but_not_binary_bytes(tmp_path: Path) -> None:
    source = tmp_path / "src" / "budobugs"
    source.mkdir(parents=True)
    text_file = source / "feature.py"
    text_file.write_bytes(b"VALUE = 1\nNEXT = 2\n")
    lf_snapshot = generate_release_metadata.source_snapshot(tmp_path)

    text_file.write_bytes(b"VALUE = 1\r\nNEXT = 2\r\n")
    crlf_snapshot = generate_release_metadata.source_snapshot(tmp_path)

    assert lf_snapshot == crlf_snapshot
    assert lf_snapshot["schema_version"] == 2

    binary_file = source / "payload.bin"
    binary_file.write_bytes(b"prefix\x00line\r\n")
    first_binary_snapshot = generate_release_metadata.source_snapshot(tmp_path)
    binary_file.write_bytes(b"prefix\x00line\n")

    assert generate_release_metadata.source_snapshot(tmp_path)["sha256"] != first_binary_snapshot["sha256"]


def test_release_provenance_snapshot_excludes_its_own_artifacts(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "src" / "budobugs"
    source.mkdir(parents=True)
    (source / "feature.py").write_text("VALUE = 1\n", encoding="utf-8")
    release_artifact = tmp_path / "release" / "provenance.json"
    release_artifact.parent.mkdir()
    release_artifact.write_text('{"first": true}\n', encoding="utf-8")
    monkeypatch.setattr(verify_release, "ROOT", tmp_path)
    snapshot = generate_release_metadata.source_snapshot(tmp_path)
    provenance = {"source_snapshot": snapshot}

    release_artifact.write_text('{"second": true}\n', encoding="utf-8")

    assert all(not path.startswith("release/") for path in snapshot["included_paths"])
    verify_release.validate_source_snapshot(provenance)


def _write_fixture_build_context(root: Path) -> tuple[Path, Path, Path, Path]:
    dockerfile = root / "docker" / "labs" / "fixture" / "Dockerfile"
    requirements = root / "docker" / "labs" / "fixture" / "requirements.lock"
    fixture = root / "src" / "budobugs" / "labs" / "fixture_app.py"
    license_file = root / "LICENSE"
    dockerfile.parent.mkdir(parents=True)
    fixture.parent.mkdir(parents=True)
    dockerfile.write_text(
        "COPY docker/labs/fixture/requirements.lock ./requirements.lock\n"
        "COPY src/budobugs/labs/fixture_app.py ./fixture_app.py\n"
        "COPY LICENSE /licenses/BudoBugs/LICENSE\n",
        encoding="utf-8",
    )
    requirements.write_text("fastapi==1\n", encoding="utf-8")
    fixture.write_text("app = object()\n", encoding="utf-8")
    license_file.write_text("Apache-2.0\n", encoding="utf-8")
    return dockerfile, requirements, fixture, license_file


def test_fixture_vex_build_input_snapshot_rejects_a_tampered_copy_source(tmp_path: Path, monkeypatch) -> None:
    _dockerfile, requirements, _fixture, _license_file = _write_fixture_build_context(tmp_path)
    monkeypatch.setattr(generate_fixture_vex, "ROOT", tmp_path)
    monkeypatch.setattr(verify_release, "ROOT", tmp_path)
    review = {"fixture_build_inputs": generate_fixture_vex.fixture_build_input_snapshot(tmp_path)}

    verify_release.validate_fixture_build_inputs(review)

    requirements.write_text("fastapi==2\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="1"):
        verify_release.validate_fixture_build_inputs(review)


def test_fixture_vex_rejects_second_product_with_different_subcomponent() -> None:
    products = [
        {"@id": "budobugs/fixture:local", "subcomponents": [{"@id": "pkg:apk/alpine/python@3"}]},
        {"@id": "pkg:oci/fixture@sha256%3Aabc", "subcomponents": [{"@id": "pkg:apk/alpine/sqlite@3"}]},
    ]
    with pytest.raises(SystemExit, match="1"):
        verify_release.validate_vex_products(products, "CVE-2026-0000")
