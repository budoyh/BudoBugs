"""YAML configuration loading with explicit schemas and no code execution."""

from __future__ import annotations

from pathlib import Path
from typing import Any, TypeVar

import yaml
from pydantic import BaseModel

from budobugs.core.io import atomic_write_text

ModelT = TypeVar("ModelT", bound=BaseModel)


class ConfigurationError(ValueError):
    """Raised when a YAML document violates its declared schema."""


def read_yaml(path: Path) -> dict[str, Any]:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"cannot read YAML {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigurationError(f"YAML root must be a mapping: {path}")
    return payload


def load_yaml_model(path: Path, model: type[ModelT]) -> ModelT:
    try:
        return model.model_validate(read_yaml(path))
    except ValueError as exc:
        raise ConfigurationError(f"invalid {model.__name__} in {path}: {exc}") from exc


def write_yaml_model(path: Path, value: BaseModel) -> None:
    payload = value.model_dump(mode="json", exclude_none=False)
    content = yaml.safe_dump(payload, allow_unicode=True, sort_keys=False)
    atomic_write_text(path, content)
