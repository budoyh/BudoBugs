"""Workspace and runtime paths with traversal-safe joins."""

from __future__ import annotations

import os
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path


class PathBoundaryError(ValueError):
    """Raised when a requested artifact escapes its declared root."""


def safe_join(root: Path, *parts: str) -> Path:
    """Resolve a child and require that it remains under root."""

    resolved_root = root.resolve()
    candidate = resolved_root.joinpath(*parts).resolve()
    if candidate != resolved_root and resolved_root not in candidate.parents:
        raise PathBoundaryError(f"path escapes root: {candidate}")
    return candidate


def ensure_private_directory(path: Path) -> Path:
    """Create a runtime directory and apply owner-only mode where supported."""

    path.mkdir(parents=True, exist_ok=True)
    with suppress(OSError):
        os.chmod(path, 0o700)
    return path


@dataclass(frozen=True, slots=True)
class WorkspacePaths:
    root: Path
    runtime_home: Path
    engagements: Path
    runs: Path
    findings: Path
    state: Path
    events: Path

    @classmethod
    def discover(cls, start: Path | None = None) -> WorkspacePaths:
        """Find the repository root and honor a scoped BUDOBUGS_HOME override."""

        cursor = (start or Path.cwd()).resolve()
        for candidate in (cursor, *cursor.parents):
            if (candidate / "pyproject.toml").is_file():
                root = candidate
                break
        else:
            raise FileNotFoundError("BudoBugs repository root not found")
        configured = os.environ.get("BUDOBUGS_HOME", ".budobugs")
        runtime_home = Path(configured)
        if not runtime_home.is_absolute():
            runtime_home = root / runtime_home
        runtime_home = runtime_home.resolve()
        return cls(
            root=root,
            runtime_home=runtime_home,
            engagements=root / "engagements",
            runs=root / "runs",
            findings=root / "findings",
            state=runtime_home / "state",
            events=runtime_home / "events",
        )

    def initialize(self) -> None:
        for path in (
            self.runtime_home,
            self.engagements,
            self.runs,
            self.findings,
            self.state,
            self.events,
        ):
            ensure_private_directory(path)
