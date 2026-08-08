#!/usr/bin/env bash
# Exit non-zero unless the application's executed doctor report is PASS.
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
command -v uv >/dev/null 2>&1 || { echo 'required command is unavailable: uv' >&2; exit 127; }

result_file="$(mktemp)"
trap 'rm -f "$result_file"' EXIT
uv run budo doctor --json >"$result_file"
cat "$result_file"
uv run python - "$result_file" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if payload.get("overall") != "PASS":
    raise SystemExit("doctor is not PASS; missing or unverified tools were not treated as ready")
PY
