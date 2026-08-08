#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(dirname -- "$script_dir")"
action="${1:-status}"
target="${2:-http://127.0.0.1:8765/healthz}"
exec uv run --project "$project_root" python "$script_dir/hexstrike_lab_ai.py" "$action" --target "$target"
