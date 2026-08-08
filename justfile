set shell := ["pwsh", "-NoLogo", "-NoProfile", "-Command"]

sync:
    uv sync --frozen --extra dev
    pnpm install --frozen-lockfile

lint:
    uv run ruff check .
    uv run ruff format --check .

typecheck:
    uv run mypy src
    pnpm run check

test:
    uv run pytest tests/unit tests/integration tests/security --cov --cov-report=term-missing

verify:
    uv run python scripts/verify_skills.py
    uv run python scripts/verify_release.py
    uv run python scripts/secret_scan.py --path .

security:
    uv run python scripts/secret_scan.py --path .

skills:
    uv run python scripts/verify_skills.py
