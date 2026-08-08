#!/usr/bin/env bash
# Reproducible project dependency bootstrap.
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'required command is unavailable: %s\n' "$1" >&2
    exit 127
  }
}

require_command uv
require_command pnpm

uv sync --frozen --extra dev
pnpm install --frozen-lockfile
uv run python scripts/verify_skills.py
uv run python scripts/verify_release.py --source

printf '%s\n' 'Project dependencies and local verification are ready.'
printf '%s\n' 'Run scripts/doctor.sh to execute tool and runtime health checks.'
