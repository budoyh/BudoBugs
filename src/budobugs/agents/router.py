"""Configuration-driven Sol/Terra/Luna route selection and fallback."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from budobugs.core.config import read_yaml


@dataclass(frozen=True, slots=True)
class RouteSelection:
    profile: str
    task_class: str
    candidates: tuple[str, ...]
    reasoning_effort: str
    token_budget: int


class ModelRouter:
    def __init__(self, config: dict[str, object]) -> None:
        self.config = config

    @classmethod
    def load(cls, path: Path) -> ModelRouter:
        return cls(read_yaml(path))

    def select(self, task_class: str, *, profile: str = "quality-first") -> RouteSelection:
        profiles = self.config.get("profiles")
        reasoning = self.config.get("reasoning")
        if not isinstance(profiles, dict) or profile not in profiles:
            raise ValueError(f"unknown model profile: {profile}")
        selected = profiles[profile]
        if not isinstance(selected, dict):
            raise ValueError("model profile must be a mapping")
        candidates = selected.get(task_class)
        if not isinstance(candidates, list) or not candidates or not all(isinstance(item, str) for item in candidates):
            raise ValueError(f"unknown task class: {task_class}")
        effort = reasoning.get(task_class, "high") if isinstance(reasoning, dict) else "high"
        budget = selected.get("phase_token_budget", 100000)
        return RouteSelection(
            profile=profile,
            task_class=task_class,
            candidates=tuple(candidates),
            reasoning_effort=str(effort),
            token_budget=int(budget),
        )
