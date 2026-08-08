"""Fail-closed structural validation for repository-owned Agent Skills."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / ".agents" / "skills"
EXPECTED_SKILLS = {
    "api-auth-session",
    "authz-business-logic",
    "budobugs-controller",
    "butian-report",
    "client-file-workflows",
    "engagement-intake",
    "evidence-critic",
    "hypothesis-and-validation",
    "lab-evaluation",
    "passive-recon",
    "source-secret-supply-chain",
    "tool-operator",
    "traffic-object-model",
    "web-attack-surface",
}
NAME_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_mapping(path: Path, *, label: str) -> dict[str, object]:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        fail(f"{label}: invalid YAML: {exc}")
    if not isinstance(payload, dict):
        fail(f"{label}: expected a mapping")
    return payload


def skill_frontmatter(path: Path, *, label: str) -> dict[str, object]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"{label}: cannot read SKILL.md: {exc}")
    lines = text.splitlines()
    if len(lines) < 4 or lines[0] != "---":
        fail(f"{label}: SKILL.md must begin with YAML frontmatter")
    try:
        boundary = lines.index("---", 1)
    except ValueError:
        fail(f"{label}: SKILL.md frontmatter is not closed")
    try:
        payload = yaml.safe_load("\n".join(lines[1:boundary]))
    except yaml.YAMLError as exc:
        fail(f"{label}: invalid SKILL.md frontmatter: {exc}")
    if not isinstance(payload, dict):
        fail(f"{label}: SKILL.md frontmatter must be a mapping")
    if len(lines) > 220:
        fail(f"{label}: SKILL.md exceeds the progressive-disclosure limit")
    return payload


def main() -> None:
    if not SKILLS.is_dir():
        fail(f"skills directory is missing: {SKILLS}")

    skill_dirs = sorted(path for path in SKILLS.iterdir() if path.is_dir())
    if not skill_dirs:
        fail("no repository skills were found")
    names = {path.name for path in skill_dirs}
    if names != EXPECTED_SKILLS:
        fail(
            "skill set mismatch: "
            f"missing={sorted(EXPECTED_SKILLS - names)}, unexpected={sorted(names - EXPECTED_SKILLS)}"
        )

    for skill in skill_dirs:
        if not NAME_PATTERN.fullmatch(skill.name) or len(skill.name) > 64:
            fail(f"{skill.name}: directory name is not Agent Skills compatible")
        for path in skill.rglob("*"):
            if path.is_symlink():
                fail(f"{skill.name}: symlinks are not allowed in repository skills")
        skill_file = skill / "SKILL.md"
        if not skill_file.is_file() or not skill_file.read_text(encoding="utf-8").strip():
            fail(f"{skill.name}: SKILL.md is missing or empty")
        metadata = skill_frontmatter(skill_file, label=skill.name)
        description = metadata.get("description")
        if metadata.get("name") != skill.name:
            fail(f"{skill.name}: frontmatter name must equal the directory name")
        if not isinstance(description, str) or not 20 <= len(description) <= 500 or "\n" in description:
            fail(f"{skill.name}: frontmatter description must be one concise line")

        openai_path = skill / "agents" / "openai.yaml"
        if not openai_path.is_file():
            fail(f"{skill.name}: agents/openai.yaml is missing")
        openai = load_mapping(openai_path, label=f"{skill.name}/agents/openai.yaml")
        interface = openai.get("interface")
        if not isinstance(interface, dict):
            fail(f"{skill.name}: openai.yaml interface is missing")
        for field in ("display_name", "short_description", "default_prompt"):
            if not isinstance(interface.get(field), str) or not interface[field].strip():
                fail(f"{skill.name}: openai.yaml interface.{field} is missing")
        if f"${skill.name}" not in str(interface["default_prompt"]):
            fail(f"{skill.name}: default_prompt must explicitly invoke ${skill.name}")

        tests = list((skill / "tests").glob("test_*.py")) if (skill / "tests").is_dir() else []
        if not tests:
            fail(f"{skill.name}: no skill test was found")

        validator = skill / "scripts" / "validate_input.py"
        references = list((skill / "references").glob("*.md")) if (skill / "references").is_dir() else []
        if not validator.is_file() or not references:
            fail(f"{skill.name}: validator or progressive-disclosure reference is missing")

        example_path = skill / "assets" / "example.json"
        contract_path = skill / "assets" / "contract.schema.json"
        if not example_path.is_file() or not contract_path.is_file():
            fail(f"{skill.name}: example or input/output contract schema is missing")
        try:
            example = json.loads(example_path.read_text(encoding="utf-8"))
            contract = json.loads(contract_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            fail(f"{skill.name}: invalid contract asset: {exc}")
        if not isinstance(example, dict) or not isinstance(example.get("expected_output"), dict):
            fail(f"{skill.name}: example must contain expected_output")
        if (
            not isinstance(contract, dict)
            or not isinstance(contract.get("input"), dict)
            or not isinstance(contract.get("output"), dict)
        ):
            fail(f"{skill.name}: contract must contain input and output JSON Schemas")
        try:
            Draft202012Validator.check_schema(contract["input"])
            Draft202012Validator.check_schema(contract["output"])
            input_example = {key: value for key, value in example.items() if key != "expected_output"}
            Draft202012Validator(contract["input"]).validate(input_example)
            Draft202012Validator(contract["output"]).validate(example["expected_output"])
        except Exception as exc:
            fail(f"{skill.name}: example does not satisfy its contract: {exc}")

        for script in sorted((skill / "scripts").glob("*.py")) if (skill / "scripts").is_dir() else []:
            try:
                compile(script.read_text(encoding="utf-8"), str(script), "exec")
            except SyntaxError as exc:
                fail(f"{skill.name}: invalid Python helper {script.name}: {exc}")

        for asset in sorted((skill / "assets").glob("*.json")) if (skill / "assets").is_dir() else []:
            try:
                json.loads(asset.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                fail(f"{skill.name}: invalid JSON asset {asset.name}: {exc}")

    print(f"PASS: validated {len(skill_dirs)} repository skills")


if __name__ == "__main__":
    main()
