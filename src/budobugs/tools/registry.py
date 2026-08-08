"""Versioned tool manifest loader."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import yaml

from budobugs.models import ToolDefinition


class ToolRegistryError(ValueError):
    """Raised for duplicate or malformed tool manifests."""


class ToolRegistry:
    def __init__(self, definitions: Iterable[ToolDefinition]) -> None:
        self._tools: dict[str, ToolDefinition] = {}
        for definition in definitions:
            if definition.name in self._tools:
                raise ToolRegistryError(f"duplicate tool definition: {definition.name}")
            self._tools[definition.name] = definition

    @classmethod
    def load(cls, directory: Path) -> ToolRegistry:
        definitions: list[ToolDefinition] = []
        for path in sorted((*directory.glob("*.yaml"), *directory.glob("*.yml"))):
            try:
                payload = yaml.safe_load(path.read_text(encoding="utf-8"))
            except (OSError, yaml.YAMLError) as exc:
                raise ToolRegistryError(f"cannot parse {path}: {exc}") from exc
            items = payload.get("tools") if isinstance(payload, dict) else None
            if not isinstance(items, list):
                raise ToolRegistryError(f"{path} must contain a tools list")
            for item in items:
                try:
                    definitions.append(ToolDefinition.model_validate(item))
                except ValueError as exc:
                    raise ToolRegistryError(f"invalid tool in {path}: {exc}") from exc
        if not definitions:
            raise ToolRegistryError(f"no tool manifests found in {directory}")
        return cls(definitions)

    def get(self, name: str) -> ToolDefinition:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ToolRegistryError(f"unknown tool: {name}") from exc

    def list(self, profile: str | None = None) -> list[ToolDefinition]:
        values: Iterable[ToolDefinition] = self._tools.values()
        if profile is not None:
            values = (item for item in values if item.profile == profile)
        return sorted(values, key=lambda item: item.name)
