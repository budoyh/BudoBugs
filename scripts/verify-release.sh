#!/usr/bin/env bash
# Local, offline-target release checks. Dependency resolution may use configured package caches.
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
command -v uv >/dev/null 2>&1 || { echo 'required command is unavailable: uv' >&2; exit 127; }
command -v pnpm >/dev/null 2>&1 || { echo 'required command is unavailable: pnpm' >&2; exit 127; }

uv lock --check
pnpm install --frozen-lockfile
uv run python scripts/verify_skills.py
uv run python scripts/verify_release.py
uv run python scripts/secret_scan.py --path .
