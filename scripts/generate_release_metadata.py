"""Derive release summary and provenance from scanner-produced artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import tempfile
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from budobugs.release_snapshot import source_snapshot

ROOT = Path(__file__).resolve().parents[1]
SCAN_DIR = ROOT / "release" / "scans"
RAW_ARTIFACTS = {
    "sbom": ROOT / "release" / "sbom" / "source.cdx.json",
    "gitleaks": SCAN_DIR / "gitleaks.json",
    "semgrep": SCAN_DIR / "semgrep.json",
    "osv": SCAN_DIR / "osv.json",
    "trivy_fs": SCAN_DIR / "trivy-fs.json",
    "trivy_fixture": SCAN_DIR / "trivy-fixture.json",
    "grype_fixture_raw": SCAN_DIR / "grype-fixture-raw.json",
    "fixture_vex": SCAN_DIR / "fixture.openvex.json",
    "fixture_vex_review": SCAN_DIR / "fixture-vex-review.json",
    "grype_fixture": SCAN_DIR / "grype-fixture.json",
    "license_python": ROOT / "release" / "licenses" / "python-production.json",
    "license_node": ROOT / "release" / "licenses" / "node-production.json",
    "license_summary": ROOT / "release" / "licenses" / "summary.json",
    "hexstrike_validation": ROOT / "release" / "validation" / "hexstrike-localhost.json",
}
SEVERE = {"HIGH", "CRITICAL"}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=path.parent, delete=False) as handle:
        handle.write(text)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def count_osv(payload: dict[str, Any]) -> int:
    return sum(
        len(group.get("ids", []) or [])
        for result in payload.get("results", []) or []
        for package in result.get("packages", []) or []
        for group in package.get("groups", []) or []
    )


def count_trivy(payload: dict[str, Any]) -> tuple[int, int]:
    severe = 0
    secrets = 0
    for result in payload.get("Results", []) or []:
        severe += sum(
            str(finding.get("Severity", "")).upper() in SEVERE for finding in result.get("Vulnerabilities", []) or []
        )
        severe += sum(
            str(finding.get("Severity", "")).upper() in SEVERE for finding in result.get("Misconfigurations", []) or []
        )
        secrets += len(result.get("Secrets", []) or [])
    return severe, secrets


def severe_grype_matches(payload: dict[str, Any], key: str = "matches") -> list[dict[str, Any]]:
    return [
        match
        for match in payload.get(key, []) or []
        if str(match.get("vulnerability", {}).get("severity", "")).upper() in SEVERE
    ]


def match_key(match: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(match.get("artifact", {}).get("name", "")),
        str(match.get("artifact", {}).get("version", "")),
        str(match.get("vulnerability", {}).get("id", "")),
    )


def validate_license_inventory(
    python: dict[str, Any], node: dict[str, Any], summary: dict[str, Any]
) -> dict[str, dict[str, int]]:
    inventories: dict[str, dict[str, int]] = {}
    for ecosystem, payload in (("python", python), ("node", node)):
        packages = payload.get("packages")
        if (
            payload.get("schema_version") != 1
            or payload.get("ecosystem") != ecosystem
            or payload.get("scope") != "production"
            or not isinstance(packages, list)
            or not packages
        ):
            raise SystemExit(f"invalid {ecosystem} production license inventory")
        unresolved = sum(
            not isinstance(item.get("declared_license"), str)
            or item["declared_license"].strip().upper() in {"", "UNKNOWN", "UNLICENSED", "UNRESOLVED", "NONE"}
            for item in packages
        )
        inventories[ecosystem] = {"packages": len(packages), "unresolved": unresolved}
    if summary.get("schema_version") != 1 or summary.get("status") != "PASS":
        raise SystemExit("production license summary is not PASS")
    if summary.get("inventories") != inventories or any(item["unresolved"] for item in inventories.values()):
        raise SystemExit("production license summary does not match package metadata")
    return inventories


def validate_hexstrike_receipt(payload: dict[str, Any], expected_commit: str) -> None:
    result = payload.get("result")
    if (
        payload.get("framework") != "hexstrike-ai"
        or payload.get("commit") != expected_commit
        or payload.get("mode") != "lab"
        or payload.get("target") != "http://127.0.0.1:8765/healthz"
        or payload.get("operation") != "intelligence/analyze-target"
        or payload.get("arbitrary_command_endpoint_used") is not False
        or not isinstance(result, dict)
        or result.get("success") is not True
    ):
        raise SystemExit("HexStrike localhost validation receipt is invalid")


def validate_vex_chain(raw: dict[str, Any], final: dict[str, Any], vex: dict[str, Any], review: dict[str, Any]) -> int:
    raw_matches = severe_grype_matches(raw)
    raw_keys = {match_key(match) for match in raw_matches}
    if len(raw_matches) != len(raw_keys):
        raise SystemExit("raw Grype report contains duplicate severe matches")
    review_keys = {
        (str(item.get("artifact", "")), str(item.get("version", "")), str(item.get("vulnerability", "")))
        for item in review.get("decisions", [])
    }
    vex_keys = {
        (str(component.get("@id", "")), str(statement.get("vulnerability", {}).get("name", "")))
        for statement in vex.get("statements", [])
        for product in statement.get("products", [])[:1]
        for component in product.get("subcomponents", [])
    }
    raw_purl_keys = {
        (str(match.get("artifact", {}).get("purl", "")), str(match.get("vulnerability", {}).get("id", "")))
        for match in raw_matches
    }
    final_ignored = severe_grype_matches(final, "ignoredMatches")
    final_ignored_keys = {match_key(match) for match in final_ignored}
    if raw_keys != review_keys or raw_purl_keys != vex_keys or raw_keys != final_ignored_keys:
        raise SystemExit("Grype raw, VEX review, OpenVEX, and final ignored severe sets do not match")
    raw_manifest = raw.get("source", {}).get("target", {}).get("manifestDigest")
    final_manifest = final.get("source", {}).get("target", {}).get("manifestDigest")
    if raw_manifest != final_manifest or review.get("image_manifest") != raw_manifest:
        raise SystemExit("Grype/VEX image manifest identities do not match")
    if severe_grype_matches(final):
        raise SystemExit("blocking severe matches remain after VEX")
    return len(raw_matches)


def main() -> int:
    missing = [path.relative_to(ROOT).as_posix() for path in RAW_ARTIFACTS.values() if not path.is_file()]
    if missing:
        raise SystemExit(f"missing raw release artifacts: {', '.join(missing)}")

    with (ROOT / "pyproject.toml").open("rb") as handle:
        version = tomllib.load(handle)["project"]["version"]
    tool_lock = yaml.safe_load((ROOT / "tools" / "lock" / "tool-lock.yaml").read_text(encoding="utf-8"))
    versions = tool_lock["versions"]
    commits = tool_lock["upstream_commits"]

    gitleaks = load_json(RAW_ARTIFACTS["gitleaks"])
    semgrep = load_json(RAW_ARTIFACTS["semgrep"])
    osv = load_json(RAW_ARTIFACTS["osv"])
    trivy_fs_severe, trivy_fs_secrets = count_trivy(load_json(RAW_ARTIFACTS["trivy_fs"]))
    trivy_fixture_severe, trivy_fixture_secrets = count_trivy(load_json(RAW_ARTIFACTS["trivy_fixture"]))
    grype_raw = load_json(RAW_ARTIFACTS["grype_fixture_raw"])
    grype = load_json(RAW_ARTIFACTS["grype_fixture"])
    fixture_vex = load_json(RAW_ARTIFACTS["fixture_vex"])
    fixture_vex_review = load_json(RAW_ARTIFACTS["fixture_vex_review"])
    vex_reviewed = validate_vex_chain(grype_raw, grype, fixture_vex, fixture_vex_review)
    license_inventory = validate_license_inventory(
        load_json(RAW_ARTIFACTS["license_python"]),
        load_json(RAW_ARTIFACTS["license_node"]),
        load_json(RAW_ARTIFACTS["license_summary"]),
    )
    validate_hexstrike_receipt(load_json(RAW_ARTIFACTS["hexstrike_validation"]), commits["hexstrike-ai"])

    observations = {
        "gitleaks": len(gitleaks),
        "semgrep": len(semgrep.get("results", [])),
        "osv": count_osv(osv),
        "trivy_fs_severe": trivy_fs_severe,
        "trivy_fs_secrets": trivy_fs_secrets,
        "trivy_fixture_severe": trivy_fixture_severe,
        "trivy_fixture_secrets": trivy_fixture_secrets,
        "grype_fixture_severe": sum(
            str(match.get("vulnerability", {}).get("severity", "")).upper() in SEVERE
            for match in grype.get("matches", [])
        ),
    }
    reviewed_observations = {
        "grype_fixture_raw_severe": len(severe_grype_matches(grype_raw)),
        "grype_fixture_vex_reviewed": vex_reviewed,
    }
    generated_at = datetime.now(UTC).isoformat()
    summary = {
        "schema_version": 1,
        "project": "BudoBugs",
        "version": version,
        "generated_at": generated_at,
        "status": "PASS" if not any(observations.values()) else "FAIL",
        "observations": observations,
        "reviewed_observations": reviewed_observations,
        "license_inventory": license_inventory,
        "validated_integrations": {
            "hexstrike-ai": {
                "commit": commits["hexstrike-ai"],
                "mode": "lab",
                "target": "loopback",
                "arbitrary_command_endpoint_used": False,
            }
        },
        "scanner_versions": {
            "gitleaks": versions["gitleaks"],
            "semgrep": versions["semgrep"],
            "osv-scanner": versions["osv-scanner"],
            "trivy": versions["trivy"],
            "syft": versions["syft"],
            "grype": versions["grype"],
        },
        "evidence_boundary": (
            "Counts are recomputed from the adjacent raw JSON artifacts; release verification independently "
            "recomputes them and fails on scanner errors, secrets, unexplained high/critical findings, "
            "or any mismatch across the unfiltered Grype report, source-bound VEX review, and final report."
        ),
    }
    write_json(SCAN_DIR / "summary.json", summary)

    material_paths = [
        *RAW_ARTIFACTS.values(),
        ROOT / "uv.lock",
        ROOT / "pnpm-lock.yaml",
        ROOT / "docker" / "compose.yaml",
        ROOT / "docker" / "labs" / "fixture" / "Dockerfile",
        ROOT / "docker" / "labs" / "fixture" / "requirements.lock",
        ROOT / "docker" / "labs" / "loopback-proxy" / "Dockerfile",
        ROOT / "config" / "semgrep.yml",
        ROOT / ".gitleaks.toml",
        ROOT / "tools" / "lock" / "tool-lock.yaml",
    ]
    provenance = {
        "schema_version": 2,
        "project": "BudoBugs",
        "version": version,
        "generated_at": generated_at,
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "materials": {
            path.relative_to(ROOT).as_posix(): sha256(path)
            for path in sorted(material_paths, key=lambda item: item.as_posix())
        },
        "source_snapshot": source_snapshot(ROOT),
        "commands": [
            "syft scan dir:. --exclude ./.git/** --exclude ./.budobugs/** --exclude ./.venv/** "
            "--exclude ./node_modules/** --exclude ./dist/** --exclude ./engagements/** "
            "--exclude ./findings/** --exclude ./runs/** --exclude ./release/** "
            "--source-name budobugs-source --source-version 2026.8.8 "
            "--output cyclonedx-json=release/sbom/source.cdx.json",
            "gitleaks detect --source . --no-git --redact --config .gitleaks.toml "
            "--report-format json --report-path release/scans/gitleaks.json",
            "semgrep scan --config config/semgrep.yml --json --output release/scans/semgrep.json "
            "--metrics off src tests scripts .agents integrations",
            "osv-scanner scan source --lockfile uv.lock --lockfile pnpm-lock.yaml "
            "--format json --output-file release/scans/osv.json",
            "trivy fs --format json --scanners vuln,secret,misconfig --severity HIGH,CRITICAL "
            "--skip-dirs .git --skip-dirs .budobugs --skip-dirs .venv --skip-dirs node_modules "
            "--skip-dirs dist --skip-dirs engagements --skip-dirs findings --skip-dirs runs "
            "--skip-dirs release --output release/scans/trivy-fs.json .",
            "trivy image --input .budobugs/fixture-release.tar --format json "
            "--output release/scans/trivy-fixture.json --scanners vuln,secret,misconfig "
            "--severity HIGH,CRITICAL",
            "grype docker-archive:.budobugs/fixture-release.tar --output json "
            "--file release/scans/grype-fixture-raw.json",
            "python scripts/generate_fixture_vex.py",
            "grype docker-archive:.budobugs/fixture-release.tar --vex release/scans/fixture.openvex.json "
            "--fail-on high --output json --file release/scans/grype-fixture.json",
            "python scripts/generate_license_inventory.py",
        ],
    }
    write_json(ROOT / "release" / "provenance.json", provenance)
    print(f"generated release metadata: status={summary['status']}; observations={observations}")
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
