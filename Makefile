.PHONY: sync lint type test security skills release verify

sync:
	uv sync --frozen --extra dev
	pnpm install --frozen-lockfile

lint:
	uv run ruff check .
	uv run ruff format --check .

type:
	uv run mypy src
	pnpm run check

test:
	uv run pytest tests/unit tests/integration tests/security --cov --cov-report=term-missing

security:
	uv run python scripts/secret_scan.py --path .

skills:
	uv run python scripts/verify_skills.py

release:
	uv run python scripts/verify_release.py

verify: lint type test skills release security
