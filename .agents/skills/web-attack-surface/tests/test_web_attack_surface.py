"""Contract test generated with the Skill scaffold."""

import json
import runpy
from pathlib import Path


def test_example_satisfies_contract() -> None:
    root = Path(__file__).parents[1]
    namespace = runpy.run_path(str(root / "scripts" / "validate_input.py"))
    payload = json.loads((root / "assets" / "example.json").read_text(encoding="utf-8"))
    result = namespace["validate"](payload)
    assert result["valid"] is True
    assert result["skill"] == "web-attack-surface"
