# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM ghcr.io/astral-sh/uv:0.13.0@sha256:cdc6093146eb3ff6a40107b38f008b789e050e77ad87865e381d9917da55a168 AS uv
FROM python:3.12.13-alpine3.23@sha256:601d3d3797e90e2534782e69c85fafb7971b43f24c7b1b079b7e48dd435e458d

COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
COPY docker/labs/fixture/requirements.lock ./requirements.lock
RUN uv venv /app/.venv \
    && uv pip sync --python /app/.venv/bin/python --require-hashes /app/requirements.lock \
    && rm /usr/local/bin/uv
COPY src/budobugs/labs/fixture_app.py ./fixture_app.py
COPY LICENSE /licenses/BudoBugs/LICENSE
RUN chown -R 65532:65532 /app /licenses/BudoBugs

USER 65532:65532
EXPOSE 8765
HEALTHCHECK --interval=5s --timeout=3s --retries=20 CMD ["/app/.venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/healthz', timeout=2)"]
CMD ["/app/.venv/bin/uvicorn", "fixture_app:app", "--host", "0.0.0.0", "--port", "8765", "--no-access-log"]
