"""Generate machine-verifiable production dependency license inventories."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import tempfile
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "release" / "licenses"


def canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=path.parent, delete=False) as handle:
        handle.write(text)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def production_python_names() -> set[str]:
    with (ROOT / "uv.lock").open("rb") as handle:
        lock = tomllib.load(handle)
    packages = {canonical_name(package["name"]): package for package in lock["package"]}
    root = packages["budobugs"]
    pending = [canonical_name(item["name"]) for item in root.get("dependencies", [])]
    selected: set[str] = set()
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        package = packages.get(name)
        if package is None:
            raise SystemExit(f"uv.lock references an unknown production package: {name}")
        selected.add(name)
        pending.extend(canonical_name(item["name"]) for item in package.get("dependencies", []))
    return selected


def production_python_versions() -> dict[str, str]:
    with (ROOT / "uv.lock").open("rb") as handle:
        lock = tomllib.load(handle)
    selected = production_python_names()
    versions: dict[str, str] = {}
    for package in lock["package"]:
        name = canonical_name(package["name"])
        if name in selected:
            version = package.get("version")
            if not isinstance(version, str) or name in versions:
                raise SystemExit(f"uv.lock has an ambiguous production version for: {name}")
            versions[name] = version
    if set(versions) != selected:
        raise SystemExit("uv.lock production package version closure is incomplete")
    return versions


def python_inventory() -> dict[str, Any]:
    locked_versions = production_python_versions()
    installed = {
        canonical_name(distribution.metadata["Name"]): distribution
        for distribution in importlib.metadata.distributions()
        if distribution.metadata.get("Name")
    }
    committed_path = OUTPUT / "python-production.json"
    committed_records: dict[str, dict[str, Any]] = {}
    if committed_path.is_file():
        try:
            committed_payload = json.loads(committed_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SystemExit("committed Python license inventory is invalid JSON") from exc
        packages = committed_payload.get("packages") if isinstance(committed_payload, dict) else None
        if isinstance(packages, list):
            committed_records = {
                canonical_name(str(item.get("name"))): item for item in packages if isinstance(item, dict)
            }
    records: list[dict[str, Any]] = []
    missing: list[str] = []
    unresolved: list[str] = []
    for name, locked_version in sorted(locked_versions.items()):
        distribution = installed.get(name)
        if distribution is None:
            committed = committed_records.get(name)
            declared = str(committed.get("declared_license", "")).strip() if committed else ""
            if (
                committed is None
                or committed.get("version") != locked_version
                or declared.upper() in {"", "UNKNOWN", "NONE", "UNRESOLVED"}
            ):
                missing.append(name)
                continue
            records.append(
                {
                    "name": committed.get("name", name),
                    "version": locked_version,
                    "declared_license": declared,
                    "license_expression": committed.get("license_expression"),
                    "license_classifiers": committed.get("license_classifiers", []),
                    "notice_files": committed.get("notice_files", []),
                    "homepage": committed.get("homepage"),
                    "metadata_source": "committed-exact-version",
                }
            )
            continue
        if distribution.version != locked_version:
            raise SystemExit(
                "installed Python package version differs from uv.lock: "
                f"{name}={distribution.version} != {locked_version}"
            )
        metadata = distribution.metadata
        expression = metadata.get("License-Expression")
        license_text = metadata.get("License")
        classifiers = [
            value.removeprefix("License :: ")
            for value in metadata.get_all("Classifier", [])
            if value.startswith("License :: ")
        ]
        declared = expression or license_text or "; ".join(classifiers)
        if not declared or declared.strip().upper() in {"UNKNOWN", "NONE"}:
            unresolved.append(name)
        notice_files = sorted(
            str(path)
            for path in distribution.files or []
            if any(token in Path(str(path)).name.lower() for token in ("license", "copying", "notice"))
        )
        records.append(
            {
                "name": metadata["Name"],
                "version": distribution.version,
                "declared_license": declared or "UNRESOLVED",
                "license_expression": expression,
                "license_classifiers": classifiers,
                "notice_files": notice_files,
                "homepage": metadata.get("Home-page") or metadata.get("Project-URL"),
                "metadata_source": "installed-distribution",
            }
        )
    if missing or unresolved:
        raise SystemExit(f"Python license metadata incomplete; missing={missing}; unresolved={unresolved}")
    return {"schema_version": 1, "ecosystem": "python", "scope": "production", "packages": records}


def production_node_versions() -> dict[str, set[str]]:
    lock = yaml.safe_load((ROOT / "pnpm-lock.yaml").read_text(encoding="utf-8"))
    snapshots = lock.get("snapshots", {})
    importers = lock.get("importers", {})
    if not isinstance(snapshots, dict) or not isinstance(importers, dict):
        raise SystemExit("pnpm-lock.yaml has no importers/snapshots dependency graph")

    def resolve(name: str, reference: str) -> str:
        if reference.startswith(("link:", "workspace:")):
            raise SystemExit(f"production Node workspace link is unsupported: {name}={reference}")
        base = reference if reference.startswith("@") and "@" in reference[1:] else f"{name}@{reference}"
        candidates = [key for key in snapshots if key == base or key.startswith(f"{base}(")]
        if len(candidates) != 1:
            raise SystemExit(f"cannot resolve production Node lock entry: {name}={reference}")
        return candidates[0]

    pending: list[str] = []
    for importer in importers.values():
        for name, dependency in (importer.get("dependencies", {}) or {}).items():
            reference = dependency["version"] if isinstance(dependency, dict) else dependency
            pending.append(resolve(str(name), str(reference)))

    selected: set[str] = set()
    while pending:
        key = pending.pop()
        if key in selected:
            continue
        selected.add(key)
        snapshot = snapshots[key]
        for group in ("dependencies", "optionalDependencies"):
            for name, reference in (snapshot.get(group, {}) or {}).items():
                pending.append(resolve(str(name), str(reference)))

    versions: dict[str, set[str]] = {}
    for key in selected:
        base = key.split("(", 1)[0]
        name, version = base.rsplit("@", 1)
        versions.setdefault(name, set()).add(version)
    return versions


def node_inventory() -> dict[str, Any]:
    pnpm = shutil.which("pnpm.cmd" if os.name == "nt" else "pnpm")
    if pnpm is None:
        raise SystemExit("pnpm executable is unavailable")
    result = subprocess.run(
        [pnpm, "licenses", "list", "--prod", "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        shell=False,
    )
    if result.returncode:
        raise SystemExit(f"pnpm license inventory failed: {(result.stdout + result.stderr).strip()}")
    grouped = json.loads(result.stdout)
    if not isinstance(grouped, dict):
        raise SystemExit("pnpm license inventory is not a JSON object")
    locked_versions = production_node_versions()
    records: list[dict[str, Any]] = []
    for license_id, packages in sorted(grouped.items()):
        if str(license_id).upper() in {"UNKNOWN", "UNLICENSED", "NONE"} or not isinstance(packages, list):
            raise SystemExit(f"Node license metadata incomplete for group: {license_id}")
        for package in packages:
            name = str(package["name"])
            versions = locked_versions.get(name)
            if not versions:
                raise SystemExit(f"pnpm reported an unexpected production package: {name}")
            records.append(
                {
                    "name": name,
                    "versions": sorted(versions),
                    "declared_license": license_id,
                    "author": package.get("author"),
                    "homepage": package.get("homepage"),
                }
            )
    if {record["name"] for record in records} != set(locked_versions):
        missing = sorted(set(locked_versions) - {record["name"] for record in records})
        raise SystemExit(f"pnpm license metadata omitted production package names: {missing}")
    return {"schema_version": 1, "ecosystem": "node", "scope": "production", "packages": records}


def validate_committed() -> tuple[int, int]:
    paths = {
        "python": OUTPUT / "python-production.json",
        "node": OUTPUT / "node-production.json",
        "summary": OUTPUT / "summary.json",
    }
    for path in paths.values():
        if not path.is_file():
            raise SystemExit(f"missing committed license inventory: {path.relative_to(ROOT)}")
    python = json.loads(paths["python"].read_text(encoding="utf-8"))
    node = json.loads(paths["node"].read_text(encoding="utf-8"))
    summary = json.loads(paths["summary"].read_text(encoding="utf-8"))
    if (python.get("schema_version"), python.get("ecosystem"), python.get("scope")) != (1, "python", "production"):
        raise SystemExit("committed Python license inventory identity is invalid")
    if (node.get("schema_version"), node.get("ecosystem"), node.get("scope")) != (1, "node", "production"):
        raise SystemExit("committed Node license inventory identity is invalid")

    python_packages = python.get("packages")
    if not isinstance(python_packages, list):
        raise SystemExit("committed Python license packages must be a list")
    python_records = {canonical_name(str(item.get("name"))): item for item in python_packages if isinstance(item, dict)}
    expected_python = production_python_versions()
    if len(python_records) != len(python_packages) or set(python_records) != set(expected_python):
        raise SystemExit("committed Python license package closure does not match uv.lock")
    for name, version in expected_python.items():
        record = python_records[name]
        declared = str(record.get("declared_license", "")).strip().upper()
        if record.get("version") != version or declared in {"", "UNKNOWN", "NONE", "UNRESOLVED"}:
            raise SystemExit(f"committed Python license metadata is invalid for: {name}")

    node_packages = node.get("packages")
    if not isinstance(node_packages, list):
        raise SystemExit("committed Node license packages must be a list")
    node_records = {str(item.get("name")): item for item in node_packages if isinstance(item, dict)}
    expected_node = production_node_versions()
    if len(node_records) != len(node_packages) or set(node_records) != set(expected_node):
        raise SystemExit("committed Node license package closure does not match pnpm-lock.yaml")
    for name, versions in expected_node.items():
        record = node_records[name]
        declared = str(record.get("declared_license", "")).strip().upper()
        if record.get("versions") != sorted(versions) or declared in {"", "UNKNOWN", "NONE", "UNLICENSED"}:
            raise SystemExit(f"committed Node license metadata is invalid for: {name}")

    expected_counts = {
        "python": {"packages": len(python_records), "unresolved": 0},
        "node": {"packages": len(node_records), "unresolved": 0},
    }
    if summary.get("schema_version") != 1 or summary.get("status") != "PASS":
        raise SystemExit("committed license inventory summary identity is invalid")
    if summary.get("inventories") != expected_counts or not str(summary.get("boundary", "")).strip():
        raise SystemExit("committed license inventory summary is stale")
    return len(python_records), len(node_records)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate committed inventories against the locked production dependency closures",
    )
    args = parser.parse_args()
    if args.check:
        python_count, node_count = validate_committed()
        print(f"validated production license inventory: python={python_count}; node={node_count}")
        return 0
    python = python_inventory()
    node = node_inventory()
    generated_at = datetime.now(UTC).isoformat()
    python["generated_at"] = generated_at
    node["generated_at"] = generated_at
    summary = {
        "schema_version": 1,
        "generated_at": generated_at,
        "status": "PASS",
        "inventories": {
            "python": {"packages": len(python["packages"]), "unresolved": 0},
            "node": {"packages": len(node["packages"]), "unresolved": 0},
        },
        "boundary": (
            "Production package metadata only. External tools, lab images, downloaded Chromium, and scanner databases "
            "remain governed by THIRD_PARTY_NOTICES.md and docs/research/LICENSE_MATRIX.md."
        ),
    }
    payloads = {
        "python-production.json": python,
        "node-production.json": node,
        "summary.json": summary,
    }
    for name, payload in payloads.items():
        write_json(OUTPUT / name, payload)
    print(f"generated production license inventory: python={len(python['packages'])}; node={len(node['packages'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
