"""Fail-closed release verification without contacting a research target."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_REMOTE = "https://github.com/budoyh/BudoBugs.git"
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}$")
ACTION_RE = re.compile(r"^[^/\s]+/[^@\s]+@[0-9a-f]{40}$")
PLACEHOLDER_RE = re.compile(r"\b(?:" + "TO" + "DO|FIX" + "ME" + r")\b")
SEVERE = {"HIGH", "CRITICAL"}

RELEASE_ARTIFACTS = {
    "sbom": ROOT / "release" / "sbom" / "source.cdx.json",
    "gitleaks": ROOT / "release" / "scans" / "gitleaks.json",
    "semgrep": ROOT / "release" / "scans" / "semgrep.json",
    "osv": ROOT / "release" / "scans" / "osv.json",
    "trivy_fs": ROOT / "release" / "scans" / "trivy-fs.json",
    "trivy_fixture": ROOT / "release" / "scans" / "trivy-fixture.json",
    "grype_fixture_raw": ROOT / "release" / "scans" / "grype-fixture-raw.json",
    "fixture_vex": ROOT / "release" / "scans" / "fixture.openvex.json",
    "fixture_vex_review": ROOT / "release" / "scans" / "fixture-vex-review.json",
    "grype_fixture": ROOT / "release" / "scans" / "grype-fixture.json",
    "license_python": ROOT / "release" / "licenses" / "python-production.json",
    "license_node": ROOT / "release" / "licenses" / "node-production.json",
    "license_summary": ROOT / "release" / "licenses" / "summary.json",
    "hexstrike_validation": ROOT / "release" / "validation" / "hexstrike-localhost.json",
    "summary": ROOT / "release" / "scans" / "summary.json",
    "provenance": ROOT / "release" / "provenance.json",
}


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def run_git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode:
        fail(f"git {' '.join(args)} failed: {(result.stdout + result.stderr).strip()}")
    return result.stdout.strip()


def load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        fail(f"invalid YAML {path.relative_to(ROOT)}: {exc}")


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid JSON {path.relative_to(ROOT)}: {exc}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_required_files() -> None:
    required = [
        "AGENTS.md",
        "README.md",
        "README_EN.md",
        "SECURITY.md",
        "THIRD_PARTY_NOTICES.md",
        "pyproject.toml",
        "uv.lock",
        "package.json",
        "pnpm-lock.yaml",
        ".github/workflows/ci.yml",
        ".github/dependabot.yml",
        ".dockerignore",
        ".gitattributes",
        ".gitleaks.toml",
        ".pre-commit-config.yaml",
        "config/semgrep.yml",
        "docker/compose.yaml",
        "tools/lock/tool-lock.yaml",
    ]
    missing = [name for name in required if not (ROOT / name).is_file()]
    missing.extend(path.relative_to(ROOT).as_posix() for path in RELEASE_ARTIFACTS.values() if not path.is_file())
    if missing:
        fail(f"required release inputs are missing: {', '.join(sorted(missing))}")


def validate_package_sources() -> None:
    source_files = sorted((ROOT / "src" / "budobugs").rglob("*.py"))
    if not source_files:
        fail("Python package source tree is empty")
    for path in source_files:
        relative = path.relative_to(ROOT).as_posix()
        result = subprocess.run(
            ["git", "check-ignore", "--no-index", "-q", "--", relative],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            fail(f"Python package source is excluded by Git ignore rules: {relative}")
        if result.returncode != 1:
            fail(f"git check-ignore failed for package source: {relative}")


def validate_metadata() -> tuple[str, int]:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)
    package = load_json(ROOT / "package.json")
    version = project.get("project", {}).get("version")
    if not isinstance(version, str) or not version:
        fail("pyproject project.version is missing")
    if not isinstance(package, dict) or package.get("version") != version:
        fail("package.json and pyproject.toml versions must match")
    if package.get("packageManager") != "pnpm@11.1.3":
        fail("package.json must exactly pin pnpm@11.1.3")

    lock = load_yaml(ROOT / "tools" / "lock" / "tool-lock.yaml")
    if not isinstance(lock, dict) or not isinstance(lock.get("versions"), dict):
        fail("tool lock must contain a versions mapping")
    versions = lock["versions"]

    seen: set[str] = set()
    registry_versions: dict[str, str] = {}
    for path in sorted((ROOT / "tools" / "registry").glob("*.yaml")):
        payload = load_yaml(path)
        if not isinstance(payload, dict) or not isinstance(payload.get("tools"), list):
            fail(f"{path.relative_to(ROOT)} must contain a tools list")
        for item in payload["tools"]:
            if not isinstance(item, dict):
                fail(f"{path.relative_to(ROOT)} contains a non-mapping tool")
            name, item_version = item.get("name"), item.get("version")
            source, license_id = item.get("source"), item.get("license")
            if not isinstance(name, str) or not name:
                fail(f"{path.relative_to(ROOT)} contains a tool without a name")
            if name in seen:
                fail(f"duplicate tool definition: {name}")
            if not isinstance(item_version, str) or not item_version:
                fail(f"tool {name} has no immutable version input")
            if not isinstance(source, str) or not source.startswith("https://"):
                fail(f"tool {name} has no HTTPS upstream source")
            if not isinstance(license_id, str) or not license_id:
                fail(f"tool {name} has no license decision")
            seen.add(name)
            registry_versions[name] = item_version

    for name, item_version in registry_versions.items():
        locked = versions.get(name)
        if locked != item_version:
            fail(f"tool lock version mismatch for {name}: {locked!r} != {item_version!r}")
    for name, locked in versions.items():
        if not isinstance(name, str) or not isinstance(locked, str) or not locked:
            fail("tool lock contains an invalid version entry")
    return version, len(seen)


def validate_containers() -> None:
    compose_path = ROOT / "docker" / "compose.yaml"
    compose = load_yaml(compose_path)
    if not isinstance(compose, dict) or not isinstance(compose.get("services"), dict):
        fail("docker/compose.yaml has no services mapping")
    raw = compose_path.read_text(encoding="utf-8")
    if "privileged: true" in raw or "/var/run/docker.sock" in raw:
        fail("compose file contains a prohibited privileged host boundary")
    lab_network = compose.get("networks", {}).get("lab", {})
    if not isinstance(lab_network, dict) or lab_network.get("internal") is not True:
        fail("compose lab network must be internal")

    for name, service in compose["services"].items():
        if not isinstance(service, dict):
            fail(f"compose service {name} is not a mapping")
        image = service.get("image")
        if not isinstance(image, str) or not image:
            fail(f"compose service {name} has no image identity")
        if service.get("build") is None and not SHA256_RE.search(image):
            fail(f"external image for service {name} is not pinned by sha256 digest: {image}")
        for port in service.get("ports", []) or []:
            published = str(port) if not isinstance(port, dict) else str(port.get("host_ip", ""))
            if isinstance(port, dict):
                if published not in {"127.0.0.1", "::1"}:
                    fail(f"service {name} publishes a non-loopback port: {port}")
            elif not published.startswith(("127.0.0.1:", "[::1]:")):
                fail(f"service {name} publishes a non-loopback port: {port}")

    for dockerfile in sorted((ROOT / "docker").rglob("Dockerfile")):
        text = dockerfile.read_text(encoding="utf-8")
        lines = text.splitlines()
        syntax_lines = [line for line in lines if line.startswith("# syntax=")]
        if syntax_lines and not SHA256_RE.search(syntax_lines[0]):
            fail(f"{dockerfile.relative_to(ROOT)} has an unpinned Dockerfile frontend")
        for line in lines:
            if not line.upper().startswith("FROM "):
                continue
            image = line.split()[1]
            if image.lower() != "scratch" and not SHA256_RE.search(image):
                fail(f"{dockerfile.relative_to(ROOT)} has an unpinned base image: {image}")


def validate_actions() -> None:
    for workflow in sorted((ROOT / ".github" / "workflows").glob("*.y*ml")):
        for line_number, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), 1):
            match = re.search(r"\buses:\s*([^\s#]+)", line)
            if not match:
                continue
            action = match.group(1).strip("'\"")
            if action.startswith("./"):
                continue
            if not ACTION_RE.fullmatch(action):
                fail(f"{workflow.relative_to(ROOT)}:{line_number} action is not pinned to a 40-char commit: {action}")


def validate_no_placeholders() -> None:
    suffixes = {".py", ".ts", ".js", ".yaml", ".yml", ".toml", ".md", ".sh", ".ps1", ".json", ".j2"}
    ignored_roots = {".git", ".venv", "node_modules", ".budobugs", "release"}
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        if any(part in ignored_roots for part in path.relative_to(ROOT).parts):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if PLACEHOLDER_RE.search(text):
            fail(f"placeholder marker remains in {path.relative_to(ROOT)}")
        if path.suffix == ".py":
            tree = ast.parse(text, filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    body = node.body
                    only_statement = body[0] if len(body) == 1 else None
                    is_ellipsis = (
                        isinstance(only_statement, ast.Expr)
                        and isinstance(only_statement.value, ast.Constant)
                        and only_statement.value.value is Ellipsis
                    )
                    if isinstance(only_statement, ast.Pass) or is_ellipsis:
                        fail(f"empty implementation {node.name} in {path.relative_to(ROOT)}:{node.lineno}")
                if (
                    isinstance(node, ast.Raise)
                    and isinstance(node.exc, ast.Call)
                    and isinstance(node.exc.func, ast.Name)
                    and node.exc.func.id == "NotImplementedError"
                ):
                    fail(f"NotImplementedError remains in {path.relative_to(ROOT)}:{node.lineno}")


def count_osv(payload: Any) -> int:
    if not isinstance(payload, dict):
        fail("OSV report is not a JSON object")
    total = 0
    for result in payload.get("results", []) or []:
        for package in result.get("packages", []) or []:
            for group in package.get("groups", []) or []:
                total += len(group.get("ids", []) or [])
    return total


def count_trivy(payload: Any) -> tuple[int, int]:
    if not isinstance(payload, dict):
        fail("Trivy report is not a JSON object")
    severe = 0
    secrets = 0
    for result in payload.get("Results", []) or []:
        for finding in result.get("Vulnerabilities", []) or []:
            if str(finding.get("Severity", "")).upper() in SEVERE:
                severe += 1
        for finding in result.get("Misconfigurations", []) or []:
            if str(finding.get("Severity", "")).upper() in SEVERE:
                severe += 1
        secrets += len(result.get("Secrets", []) or [])
    return severe, secrets


def severe_grype_matches(payload: dict[str, Any], key: str = "matches") -> list[dict[str, Any]]:
    return [
        match
        for match in payload.get(key, []) or []
        if str(match.get("vulnerability", {}).get("severity", "")).upper() in SEVERE
    ]


def grype_match_key(match: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(match.get("artifact", {}).get("name", "")),
        str(match.get("artifact", {}).get("version", "")),
        str(match.get("vulnerability", {}).get("id", "")),
    )


def canonical_package_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def expected_python_production() -> dict[str, str]:
    with (ROOT / "uv.lock").open("rb") as handle:
        lock = tomllib.load(handle)
    packages: dict[str, dict[str, Any]] = {}
    for package in lock.get("package", []):
        name = canonical_package_name(str(package.get("name", "")))
        if name in packages:
            fail(f"uv.lock contains duplicate normalized package identity: {name}")
        packages[name] = package
    root = packages.get("budobugs")
    if root is None:
        fail("uv.lock has no BudoBugs root package")
    pending = [canonical_package_name(str(item["name"])) for item in root.get("dependencies", [])]
    selected: dict[str, str] = {}
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        package = packages.get(name)
        if package is None or not isinstance(package.get("version"), str):
            fail(f"uv.lock production dependency is unresolved: {name}")
        selected[name] = package["version"]
        pending.extend(canonical_package_name(str(item["name"])) for item in package.get("dependencies", []))
    return selected


def expected_node_production() -> dict[str, set[str]]:
    lock = load_yaml(ROOT / "pnpm-lock.yaml")
    if not isinstance(lock, dict):
        fail("pnpm-lock.yaml is not a mapping")
    snapshots = lock.get("snapshots")
    importers = lock.get("importers")
    if not isinstance(snapshots, dict) or not isinstance(importers, dict):
        fail("pnpm-lock.yaml has no importers/snapshots dependency graph")

    def resolve(name: str, reference: str) -> str:
        if reference.startswith(("link:", "workspace:")):
            fail(f"production Node workspace link is unsupported: {name}={reference}")
        base = reference if reference.startswith("@") and "@" in reference[1:] else f"{name}@{reference}"
        candidates = [key for key in snapshots if key == base or str(key).startswith(f"{base}(")]
        if len(candidates) != 1:
            fail(f"cannot resolve production Node lock entry: {name}={reference}")
        return str(candidates[0])

    pending: list[str] = []
    for importer in importers.values():
        if not isinstance(importer, dict):
            fail("pnpm-lock.yaml contains an invalid importer")
        for name, dependency in (importer.get("dependencies", {}) or {}).items():
            reference = dependency["version"] if isinstance(dependency, dict) else dependency
            pending.append(resolve(str(name), str(reference)))
    selected: set[str] = set()
    while pending:
        key = pending.pop()
        if key in selected:
            continue
        selected.add(key)
        snapshot = snapshots.get(key)
        if not isinstance(snapshot, dict):
            fail(f"pnpm production snapshot is invalid: {key}")
        for group in ("dependencies", "optionalDependencies"):
            for name, reference in (snapshot.get(group, {}) or {}).items():
                pending.append(resolve(str(name), str(reference)))
    versions: dict[str, set[str]] = {}
    for key in selected:
        name, version = key.split("(", 1)[0].rsplit("@", 1)
        versions.setdefault(name, set()).add(version)
    return versions


def validate_license_inventory() -> dict[str, dict[str, int]]:
    python = load_json(RELEASE_ARTIFACTS["license_python"])
    node = load_json(RELEASE_ARTIFACTS["license_node"])
    summary = load_json(RELEASE_ARTIFACTS["license_summary"])
    for ecosystem, payload in (("python", python), ("node", node)):
        if (
            not isinstance(payload, dict)
            or payload.get("schema_version") != 1
            or payload.get("ecosystem") != ecosystem
            or payload.get("scope") != "production"
            or not isinstance(payload.get("packages"), list)
            or not payload["packages"]
        ):
            fail(f"invalid {ecosystem} production license inventory")
        for item in payload["packages"]:
            declared = item.get("declared_license") if isinstance(item, dict) else None
            if not isinstance(declared, str) or declared.strip().upper() in {
                "",
                "UNKNOWN",
                "UNLICENSED",
                "UNRESOLVED",
                "NONE",
            }:
                fail(f"unresolved {ecosystem} production license metadata")

    python_actual = {
        canonical_package_name(str(item.get("name", ""))): str(item.get("version", "")) for item in python["packages"]
    }
    if len(python_actual) != len(python["packages"]) or python_actual != expected_python_production():
        fail("Python production license inventory does not exactly match uv.lock")
    node_actual = {str(item.get("name", "")): set(item.get("versions", [])) for item in node["packages"]}
    if len(node_actual) != len(node["packages"]) or node_actual != expected_node_production():
        fail("Node production license inventory does not exactly match pnpm-lock.yaml")

    inventories = {
        "python": {"packages": len(python_actual), "unresolved": 0},
        "node": {"packages": len(node_actual), "unresolved": 0},
    }
    if (
        not isinstance(summary, dict)
        or summary.get("schema_version") != 1
        or summary.get("status") != "PASS"
        or summary.get("inventories") != inventories
    ):
        fail("production license summary does not match the locked dependency inventories")
    return inventories


def validate_hexstrike_receipt() -> dict[str, object]:
    receipt = load_json(RELEASE_ARTIFACTS["hexstrike_validation"])
    tool_lock = load_yaml(ROOT / "tools" / "lock" / "tool-lock.yaml")
    expected_commit = tool_lock.get("upstream_commits", {}).get("hexstrike-ai") if isinstance(tool_lock, dict) else None
    result = receipt.get("result") if isinstance(receipt, dict) else None
    if (
        not isinstance(receipt, dict)
        or receipt.get("framework") != "hexstrike-ai"
        or receipt.get("commit") != expected_commit
        or receipt.get("mode") != "lab"
        or receipt.get("target") != "http://127.0.0.1:8765/healthz"
        or receipt.get("operation") != "intelligence/analyze-target"
        or receipt.get("arbitrary_command_endpoint_used") is not False
        or not isinstance(result, dict)
        or result.get("success") is not True
    ):
        fail("HexStrike localhost validation receipt is invalid or exceeds the bounded adapter")
    return {
        "commit": expected_commit,
        "mode": "lab",
        "target": "loopback",
        "arbitrary_command_endpoint_used": False,
    }


def validate_vex_evidence() -> int:
    raw = load_json(RELEASE_ARTIFACTS["grype_fixture_raw"])
    final = load_json(RELEASE_ARTIFACTS["grype_fixture"])
    vex = load_json(RELEASE_ARTIFACTS["fixture_vex"])
    review = load_json(RELEASE_ARTIFACTS["fixture_vex_review"])
    for label, payload in (("raw", raw), ("final", final)):
        if not isinstance(payload, dict) or not isinstance(payload.get("matches"), list):
            fail(f"Grype {label} report has no matches list")
        if label == "final" and not isinstance(payload.get("ignoredMatches"), list):
            fail(f"Grype {label} report has no ignoredMatches list")

    raw_configuration = raw.get("descriptor", {}).get("configuration", {})
    if (
        raw_configuration.get("only-fixed")
        or raw_configuration.get("only-notfixed")
        or raw_configuration.get("ignore-wontfix")
        or raw_configuration.get("exclude")
        or raw_configuration.get("vex-documents")
    ):
        fail("raw Grype report was produced with a vulnerability-hiding filter")
    raw_severe = severe_grype_matches(raw)
    raw_keys = {grype_match_key(match) for match in raw_severe}
    if not raw_keys or len(raw_keys) != len(raw_severe):
        fail("raw Grype severe set is empty or contains duplicate package/CVE keys")
    if severe_grype_matches(raw, "ignoredMatches"):
        fail("raw Grype report suppresses severe matches")

    if not isinstance(review, dict) or review.get("schema_version") != 1:
        fail("fixture VEX review has an unsupported schema")
    fixture_source = ROOT / str(review.get("fixture_source", ""))
    expected_source = ROOT / "src" / "budobugs" / "labs" / "fixture_app.py"
    if fixture_source.resolve() != expected_source.resolve() or not fixture_source.is_file():
        fail("fixture VEX review is not bound to fixture_app.py")
    if review.get("fixture_source_sha256") != sha256(fixture_source):
        fail("fixture source changed after the VEX reachability review")
    decisions = review.get("decisions")
    if not isinstance(decisions, list):
        fail("fixture VEX review has no decisions list")
    review_keys: set[tuple[str, str, str]] = set()
    review_purl_keys: set[tuple[str, str]] = set()
    for decision in decisions:
        if not isinstance(decision, dict):
            fail("fixture VEX review contains a non-object decision")
        key = (
            str(decision.get("artifact", "")),
            str(decision.get("version", "")),
            str(decision.get("vulnerability", "")),
        )
        purl = str(decision.get("purl", ""))
        references = decision.get("references")
        if (
            decision.get("status") != "not_affected"
            or not str(decision.get("justification", ""))
            or not str(decision.get("impact_statement", ""))
            or not isinstance(references, list)
            or not references
            or any(not isinstance(reference, str) or not reference.startswith("https://") for reference in references)
            or not purl.startswith("pkg:")
        ):
            fail(f"fixture VEX review decision is incomplete: {key}")
        review_keys.add(key)
        review_purl_keys.add((purl, key[2]))
    if len(review_keys) != len(decisions):
        fail("fixture VEX review contains duplicate decisions")

    if not isinstance(vex, dict) or vex.get("@context") != "https://openvex.dev/ns/v0.2.0":
        fail("fixture OpenVEX document has an unsupported context")
    statements = vex.get("statements")
    if not isinstance(statements, list):
        fail("fixture OpenVEX document has no statements")
    vex_purl_keys: set[tuple[str, str]] = set()
    for statement in statements:
        if not isinstance(statement, dict):
            fail("fixture OpenVEX contains a non-object statement")
        vulnerability = str(statement.get("vulnerability", {}).get("name", ""))
        products = statement.get("products")
        if (
            statement.get("status") != "not_affected"
            or not str(statement.get("justification", ""))
            or not str(statement.get("impact_statement", ""))
            or not isinstance(products, list)
            or len(products) != 2
        ):
            fail(f"fixture OpenVEX statement is incomplete: {vulnerability}")
        identifiers = {str(product.get("@id", "")) for product in products}
        has_digest_product = any(item.startswith("pkg:oci/fixture@sha256%3A") for item in identifiers)
        if "budobugs/fixture:local" not in identifiers or not has_digest_product:
            fail(f"fixture OpenVEX product identity is incomplete: {vulnerability}")
        for product in products[:1]:
            subcomponents = product.get("subcomponents")
            if not isinstance(subcomponents, list) or len(subcomponents) != 1:
                fail(f"fixture OpenVEX statement must name one exact subcomponent: {vulnerability}")
            vex_purl_keys.add((str(subcomponents[0].get("@id", "")), vulnerability))

    raw_purl_keys = {
        (str(match.get("artifact", {}).get("purl", "")), str(match.get("vulnerability", {}).get("id", "")))
        for match in raw_severe
    }
    final_severe = severe_grype_matches(final)
    final_ignored = severe_grype_matches(final, "ignoredMatches")
    final_ignored_keys = {grype_match_key(match) for match in final_ignored}
    if final_severe:
        fail(f"blocking severe Grype matches remain after VEX: {len(final_severe)}")
    if raw_keys != review_keys or raw_purl_keys != review_purl_keys or raw_purl_keys != vex_purl_keys:
        fail("raw Grype, review, and OpenVEX severe sets do not match")
    if raw_keys != final_ignored_keys or len(final_ignored_keys) != len(final_ignored):
        fail("final Grype VEX-suppressed set does not equal the raw severe set")
    for match in final_ignored:
        rules = match.get("appliedIgnoreRules", [])
        if not any(rule.get("namespace") == "vex" and rule.get("vex-status") == "not_affected" for rule in rules):
            fail(f"final Grype suppression is not attributable to OpenVEX: {grype_match_key(match)}")

    raw_manifest = raw.get("source", {}).get("target", {}).get("manifestDigest")
    final_manifest = final.get("source", {}).get("target", {}).get("manifestDigest")
    if (
        not isinstance(raw_manifest, str)
        or not SHA256_RE.fullmatch(raw_manifest)
        or final_manifest != raw_manifest
        or review.get("image_manifest") != raw_manifest
    ):
        fail("raw Grype, final Grype, and VEX review image manifests do not match")
    return len(raw_severe)


def validate_release_artifacts(version: str) -> dict[str, int]:
    sbom = load_json(RELEASE_ARTIFACTS["sbom"])
    if not isinstance(sbom, dict) or not str(sbom.get("bomFormat", "")).startswith("CycloneDX"):
        fail("release SBOM is not CycloneDX JSON")
    components = sbom.get("components")
    if not isinstance(components, list) or not components:
        fail("release SBOM contains no components")
    metadata_component = sbom.get("metadata", {}).get("component", {})
    if metadata_component.get("name") != "budobugs-source" or metadata_component.get("version") != version:
        fail("release SBOM metadata does not identify this BudoBugs version")
    license_inventory = validate_license_inventory()
    hexstrike_validation = validate_hexstrike_receipt()

    gitleaks = load_json(RELEASE_ARTIFACTS["gitleaks"])
    if not isinstance(gitleaks, list):
        fail("Gitleaks report is not a JSON list")
    semgrep = load_json(RELEASE_ARTIFACTS["semgrep"])
    if not isinstance(semgrep, dict) or not isinstance(semgrep.get("results"), list):
        fail("Semgrep report has no results list")
    semgrep_errors = [item for item in semgrep.get("errors", []) if item.get("level") == "error"]
    if semgrep_errors:
        fail(f"Semgrep report contains scanner errors: {len(semgrep_errors)}")
    osv_count = count_osv(load_json(RELEASE_ARTIFACTS["osv"]))
    trivy_fs_severe, trivy_fs_secrets = count_trivy(load_json(RELEASE_ARTIFACTS["trivy_fs"]))
    trivy_image_severe, trivy_image_secrets = count_trivy(load_json(RELEASE_ARTIFACTS["trivy_fixture"]))
    grype_reviewed = validate_vex_evidence()
    grype = load_json(RELEASE_ARTIFACTS["grype_fixture"])
    grype_severe = len(severe_grype_matches(grype))

    counts = {
        "gitleaks": len(gitleaks),
        "semgrep": len(semgrep["results"]),
        "osv": osv_count,
        "trivy_fs_severe": trivy_fs_severe,
        "trivy_fs_secrets": trivy_fs_secrets,
        "trivy_fixture_severe": trivy_image_severe,
        "trivy_fixture_secrets": trivy_image_secrets,
        "grype_fixture_severe": grype_severe,
    }
    if any(counts.values()):
        fail(f"release security findings remain: {counts}")

    reviewed_counts = {
        "grype_fixture_raw_severe": grype_reviewed,
        "grype_fixture_vex_reviewed": grype_reviewed,
    }

    summary = load_json(RELEASE_ARTIFACTS["summary"])
    if not isinstance(summary, dict) or summary.get("schema_version") != 1:
        fail("release scan summary has an unsupported schema")
    if summary.get("observations") != counts:
        fail("release scan summary does not match recomputed raw observations")
    if summary.get("reviewed_observations") != reviewed_counts or summary.get("status") != "PASS":
        fail("release scan summary does not match recomputed VEX-reviewed observations")
    if summary.get("license_inventory") != license_inventory:
        fail("release scan summary does not match locked production license inventories")
    if summary.get("validated_integrations") != {"hexstrike-ai": hexstrike_validation}:
        fail("release scan summary does not match the bounded HexStrike validation receipt")

    provenance = load_json(RELEASE_ARTIFACTS["provenance"])
    if not isinstance(provenance, dict) or provenance.get("schema_version") != 1:
        fail("release provenance has an unsupported schema")
    if provenance.get("project") != "BudoBugs" or provenance.get("version") != version:
        fail("release provenance identifies a different project version")
    materials = provenance.get("materials")
    if not isinstance(materials, dict):
        fail("release provenance has no materials mapping")
    for name, path in RELEASE_ARTIFACTS.items():
        if name in {"provenance", "summary"}:
            continue
        relative = path.relative_to(ROOT).as_posix()
        if materials.get(relative) != sha256(path):
            fail(f"release provenance digest mismatch: {relative}")
    return {
        **counts,
        **reviewed_counts,
        "license_python_packages": license_inventory["python"]["packages"],
        "license_node_packages": license_inventory["node"]["packages"],
    }


def validate_skills() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "verify_skills.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode:
        fail(f"skill verification failed: {(result.stdout + result.stderr).strip()}")


def validate_pre_commit_pins() -> None:
    payload = load_yaml(ROOT / ".pre-commit-config.yaml")
    if not isinstance(payload, dict) or not isinstance(payload.get("repos"), list):
        fail(".pre-commit-config.yaml has no repos list")
    for item in payload["repos"]:
        if not isinstance(item, dict) or item.get("repo") == "local":
            continue
        revision = item.get("rev")
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
            fail(f"pre-commit dependency is not pinned to a 40-char commit: {item.get('repo')}")


def validate_git_release() -> str:
    head = run_git("rev-parse", "HEAD")
    if run_git("branch", "--show-current") != "main":
        fail("release must be verified from local main")
    if run_git("status", "--porcelain=v1", "--untracked-files=all"):
        fail("release worktree is not clean")
    remote = run_git("remote", "get-url", "origin").rstrip("/")
    if remote.removesuffix(".git") != EXPECTED_REMOTE.removesuffix(".git"):
        fail(f"origin is not the expected BudoBugs repository: {remote}")
    remote_head = run_git("rev-parse", "refs/remotes/origin/main")
    if remote_head != head:
        fail(f"local main and origin/main differ: {head} != {remote_head}")
    return head


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        action="store_true",
        help="verify committed release inputs without requiring local main/origin/main equality",
    )
    args = parser.parse_args()

    validate_required_files()
    validate_package_sources()
    version, registry_count = validate_metadata()
    validate_containers()
    validate_actions()
    validate_no_placeholders()
    counts = validate_release_artifacts(version)
    validate_skills()
    validate_pre_commit_pins()
    run_git("diff", "--check")

    if args.source:
        print(
            f"PASS: source release inputs validated; version={version}; "
            f"registry_tools={registry_count}; scan_observations={counts}"
        )
        return
    head = validate_git_release()
    print(
        f"PASS: release validated; version={version}; commit={head}; "
        f"registry_tools={registry_count}; scan_observations={counts}"
    )


if __name__ == "__main__":
    main()
