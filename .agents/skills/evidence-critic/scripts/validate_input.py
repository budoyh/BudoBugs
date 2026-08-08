#!/usr/bin/env python3
"""Validate the minimal structured input contract for this BudoBugs Skill."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REQUIRED = ["finding_id", "pack_path"]


def validate(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise ValueError("input root must be a JSON object")
    missing = [key for key in REQUIRED if key not in payload]
    if missing:
        raise ValueError(f"missing required fields: {', '.join(missing)}")
    return {"valid": True, "skill": Path(__file__).parents[1].name, "required_fields": REQUIRED}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_input.py INPUT.json", file=sys.stderr)
        return 2
    try:
        payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        print(json.dumps(validate(payload), ensure_ascii=False, sort_keys=True))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
