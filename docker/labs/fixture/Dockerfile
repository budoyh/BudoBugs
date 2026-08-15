# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM ghcr.io/astral-sh/uv:0.11.26@sha256:3d868e555f8f1dbc324afa005066cd11e1053fc4743b9808ca8025283e65efa5 AS uv
FROM python:3.14.7-alpine3.23@sha256:6b8f06d04d5305c1d1288435388df9165ab41e681fae6439d6349d8053cc3f83

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
