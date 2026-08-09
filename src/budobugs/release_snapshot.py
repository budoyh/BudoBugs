"""Deterministic source-tree identity for release provenance.

The release directory contains the provenance document itself and scanner output, so
it is deliberately outside this snapshot. Runtime and credential-bearing paths are
excluded for the same reason they are excluded from local release scans.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

SNAPSHOT_SCHEMA_VERSION = 2
EXCLUDED_TOP_LEVEL_DIRECTORIES = frozenset(
    {
        ".budobugs",
        ".git",
        ".mypy_cache",
        ".playwright",
        ".pnpm-store",
        ".pytest_cache",
        ".ruff_cache",
        ".tools",
        ".venv",
        "browser-data",
        "build",
        "dist",
        "downloads",
        "engagements",
        "findings",
        "fixtures-runtime",
        "htmlcov",
        "install-receipts",
        "node_modules",
        "playwright-report",
        "release",
        "runs",
        "secrets",
        "test-results",
        "traffic",
    }
)
EXCLUDED_DIRECTORY_NAMES = frozenset({"__pycache__"})
EXCLUDED_FILE_NAMES = frozenset({".coverage", "coverage.xml", "Thumbs.db"})
EXCLUDED_SUFFIXES = (".har", ".pcap", ".pem", ".p12", ".pyc", ".pyo", ".trace.zip")


def _is_excluded(relative: Path) -> bool:
    if not relative.parts:
        return False
    if relative.parts[0] in EXCLUDED_TOP_LEVEL_DIRECTORIES:
        return True
    if any(part in EXCLUDED_DIRECTORY_NAMES for part in relative.parts[:-1]):
        return True
    name = relative.name
    if name in EXCLUDED_FILE_NAMES or name.endswith(EXCLUDED_SUFFIXES):
        return True
    # Keep the checked-in template, but never bind a local environment file.
    return name.startswith(".env") and name != ".env.example"


def included_source_paths(root: Path) -> list[Path]:
    """Return regular, non-symlink files that define the releasable source tree."""

    paths: list[Path] = []
    for current, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories[:] = [
            name
            for name in directories
            if not _is_excluded((current_path / name).relative_to(root)) and not (current_path / name).is_symlink()
        ]
        for name in filenames:
            path = current_path / name
            relative = path.relative_to(root)
            if _is_excluded(relative) or path.is_symlink() or not path.is_file():
                continue
            paths.append(relative)
    return sorted(paths, key=lambda path: path.as_posix())


def _portable_content(path: Path) -> bytes:
    """Normalize checkout CRLF in NUL-free UTF-8 content; preserve other bytes."""

    content = path.read_bytes()
    if b"\x00" in content:
        return content
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return content
    return text.replace("\r\n", "\n").encode("utf-8")


def source_snapshot(root: Path) -> dict[str, Any]:
    """Build a portable identity from paths and checkout-stable file content."""

    paths = included_source_paths(root)
    digest = hashlib.sha256()
    for relative in paths:
        encoded_path = relative.as_posix().encode("utf-8")
        content = _portable_content(root / relative)
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    top_level_roots = sorted({relative.parts[0] for relative in paths if len(relative.parts) > 1})
    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "included_roots": top_level_roots,
        "included_paths": [path.as_posix() for path in paths],
        "file_count": len(paths),
        "sha256": digest.hexdigest(),
    }
