"""BudoBugs local TEST FIXTURE.

This deliberately vulnerable application is only for loopback/container E2E tests.
Its static fixture identities are not credentials for any real system.
"""

from __future__ import annotations

from html import escape
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

app = FastAPI(title="BudoBugs TEST FIXTURE", docs_url=None, redoc_url=None)

_IDENTITIES = {"Fixture alice": "alice", "Fixture bob": "bob"}
_OBJECTS = {
    1: {"id": 1, "owner": "alice", "tenant": "red", "secret": "alice-private-note"},
    2: {"id": 2, "owner": "bob", "tenant": "blue", "secret": "bob-private-note"},
}
_PUBLIC = {101: {"id": 101, "title": "documented public fixture", "visibility": "public"}}
_FILES = {
    1: {"id": 1, "owner": "alice", "name": "alice-proof.txt", "content": "alice-private-file"},
    2: {"id": 2, "owner": "bob", "name": "bob-proof.txt", "content": "bob-private-file"},
}
_WORKFLOWS: dict[int, str] = {1: "draft"}


class TransitionRequest(BaseModel):
    state: str


def _identity(authorization: Annotated[str | None, Header()] = None) -> str:
    if authorization not in _IDENTITIES:
        raise HTTPException(status_code=401, detail="fixture identity required")
    return _IDENTITIES[authorization]


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "fixture": "BudoBugs local only"}


@app.get("/", response_class=HTMLResponse)
def fixture_index() -> str:
    """A crawlable landing page for the isolated ZAP Automation test."""

    return (
        "<!doctype html><title>BudoBugs TEST FIXTURE</title>"
        "<h1>BudoBugs local TEST FIXTURE</h1>"
        "<a href='/healthz'>health</a>"
        "<a href='/preview?value=fixture'>preview</a>"
        "<a href='/api/public/101'>public control</a>"
    )


@app.get("/api/objects/{object_id}")
def vulnerable_object(object_id: int, authorization: Annotated[str | None, Header()] = None) -> dict[str, object]:
    """TEST FIXTURE: authenticated user can read another fixture user's object."""

    actor = _identity(authorization)
    item = _OBJECTS.get(object_id)
    if item is None:
        raise HTTPException(status_code=404, detail="not found")
    return {**item, "requested_by": actor, "fixture_issue": "missing object authorization"}


@app.get("/api/secure-objects/{object_id}")
def secure_object(object_id: int, authorization: Annotated[str | None, Header()] = None) -> dict[str, object]:
    actor = _identity(authorization)
    item = _OBJECTS.get(object_id)
    if item is None:
        raise HTTPException(status_code=404, detail="not found")
    if item["owner"] != actor:
        raise HTTPException(status_code=403, detail="owner mismatch")
    return item


@app.get("/api/public/{object_id}")
def public_object(object_id: int) -> dict[str, object]:
    """Intentional public control; it must be KILLed as a vulnerability candidate."""

    item = _PUBLIC.get(object_id)
    if item is None:
        raise HTTPException(status_code=404, detail="not found")
    return item


@app.get("/api/files/{file_id}", response_class=PlainTextResponse)
def vulnerable_file(file_id: int, authorization: Annotated[str | None, Header()] = None) -> str:
    """TEST FIXTURE: file owner check is intentionally absent."""

    _identity(authorization)
    item = _FILES.get(file_id)
    if item is None:
        raise HTTPException(status_code=404, detail="not found")
    return str(item["content"])


@app.post("/api/workflows/{workflow_id}/transition")
def vulnerable_transition(
    workflow_id: int,
    payload: TransitionRequest,
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, str]:
    """TEST FIXTURE: accepts an invalid draft-to-paid transition."""

    _identity(authorization)
    if workflow_id not in _WORKFLOWS:
        raise HTTPException(status_code=404, detail="not found")
    previous = _WORKFLOWS[workflow_id]
    _WORKFLOWS[workflow_id] = payload.state
    return {
        "previous": previous,
        "current": payload.state,
        "fixture_issue": "transition not constrained",
    }


@app.get("/preview", response_class=HTMLResponse)
def vulnerable_preview(value: str = "fixture") -> str:
    """TEST FIXTURE: explicit front-end injection marker in an isolated response."""

    safe_label = escape(value)
    return (
        "<!doctype html><title>BudoBugs fixture</title>"
        f"<p id='safe'>{safe_label}</p>"
        f"<script>document.querySelector('#safe').innerHTML={value!r}</script>"
    )
