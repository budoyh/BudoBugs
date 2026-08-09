"""BudoBugs local TEST FIXTURE.

Every weakness is intentional and reachable only in a user-started localhost/container lab.
Static fixture identities and sessions are not credentials for any real system.
"""

from __future__ import annotations

from html import escape
from typing import Annotated, Any

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Response, WebSocket
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field

app = FastAPI(title="BudoBugs TEST FIXTURE", docs_url=None, redoc_url=None)

_IDENTITIES = {
    "Fixture alice": {"alias": "alice", "role": "user", "tenant": "red"},
    "Fixture bob": {"alias": "bob", "role": "user", "tenant": "blue"},
    "Fixture admin": {"alias": "admin", "role": "admin", "tenant": "red"},
}
_BROWSER_SESSIONS = {f"browser-{item['alias']}": item for item in _IDENTITIES.values()}
_OBJECTS: dict[int, dict[str, object]] = {}
_PUBLIC = {101: {"id": 101, "title": "documented public fixture", "visibility": "public"}}
_FILES = {
    1: {"id": 1, "owner": "alice", "tenant": "red", "name": "alice-proof.txt", "content": "alice-private-file"},
    2: {"id": 2, "owner": "bob", "tenant": "blue", "name": "bob-proof.txt", "content": "bob-private-file"},
}
_SHARES: dict[str, dict[str, object]] = {}
_WORKFLOWS: dict[int, str] = {}
_ORDERS: dict[int, dict[str, object]] = {}
_API_SESSIONS: dict[str, str] = {}
_REVOKED_SESSIONS: set[str] = set()


def _reset_state() -> None:
    _OBJECTS.clear()
    _OBJECTS.update(
        {
            1: {"id": 1, "owner": "alice", "tenant": "red", "secret": "alice-private-note"},
            2: {"id": 2, "owner": "bob", "tenant": "blue", "secret": "bob-private-note"},
        }
    )
    _SHARES.clear()
    _SHARES.update(
        {
            "alice-share": {"file_id": 1, "owner": "alice", "recipient": "bob", "revoked": False},
            "revoked-share": {"file_id": 1, "owner": "alice", "recipient": "bob", "revoked": True},
        }
    )
    _WORKFLOWS.clear()
    _WORKFLOWS.update({1: "draft"})
    _ORDERS.clear()
    _ORDERS.update(
        {
            1: {"id": 1, "owner": "alice", "state": "draft", "confirm_count": 0},
            2: {"id": 2, "owner": "bob", "state": "draft", "confirm_count": 0},
        }
    )
    _API_SESSIONS.clear()
    _REVOKED_SESSIONS.clear()


_reset_state()


class TransitionRequest(BaseModel):
    state: str


class ObjectCreateRequest(BaseModel):
    label: str = Field(min_length=1, max_length=80)


class GraphqlRequest(BaseModel):
    query: str = Field(min_length=1, max_length=2000)
    variables: dict[str, Any] = Field(default_factory=dict)
    operationName: str | None = Field(default=None, max_length=100)  # noqa: N815


class ShareRequest(BaseModel):
    file_id: int
    recipient: str


def _identity(
    authorization: Annotated[str | None, Header()] = None,
    fixture_session: Annotated[str | None, Cookie()] = None,
) -> dict[str, str]:
    if authorization in _IDENTITIES:
        return _IDENTITIES[authorization]
    if fixture_session in _BROWSER_SESSIONS:
        return _BROWSER_SESSIONS[fixture_session]
    raise HTTPException(status_code=401, detail="fixture identity required")


def _object(object_id: int) -> dict[str, object]:
    item = _OBJECTS.get(object_id)
    if item is None:
        raise HTTPException(status_code=404, detail="not found")
    return item


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "fixture": "BudoBugs local only"}


@app.post("/__fixture__/reset")
def reset_fixture(x_budo_fixture: Annotated[str | None, Header()] = None) -> dict[str, str]:
    if x_budo_fixture != "reset-local-test-state":
        raise HTTPException(status_code=403, detail="local reset marker required")
    _reset_state()
    return {"status": "reset", "scope": "local-test-fixture"}


@app.get("/", response_class=HTMLResponse)
def fixture_index() -> str:
    return (
        "<!doctype html><title>BudoBugs TEST FIXTURE</title>"
        "<h1>BudoBugs local TEST FIXTURE</h1>"
        "<nav><a href='/login/alice'>alice login</a><a href='/login/bob'>bob login</a>"
        "<a href='/preview?value=fixture'>preview</a><a href='/safe-preview?value=fixture'>safe preview</a>"
        "<a href='/api/public/101'>public control</a></nav>"
        "<script>window.BUDO_API_SCHEMA='/openapi-fixture.json';window.BUDO_WS='/ws/objects/1';</script>"
    )


@app.get("/login/{alias}")
def fixture_login(alias: str) -> RedirectResponse:
    if alias not in {"alice", "bob", "admin"}:
        raise HTTPException(status_code=404, detail="unknown fixture account")
    response = RedirectResponse("/app", status_code=303)
    response.set_cookie(
        "fixture_session",
        f"browser-{alias}",
        httponly=True,
        samesite="strict",
    )
    return response


@app.get("/app", response_class=HTMLResponse)
def fixture_app(identity: Annotated[dict[str, str], Depends(_identity)]) -> str:
    alias = escape(identity["alias"])
    return (
        "<!doctype html><title>BudoBugs fixture app</title>"
        f"<h1 id='identity'>Signed in as {alias}</h1>"
        "<nav><a href='/app/files'>Files</a><a href='/app/orders'>Orders</a>"
        "<a href='/safe-preview?value=dashboard'>Safe preview</a></nav>"
        "<form id='create-object' data-budobugs-safe-create='true'>"
        "<label>Harmless note <input name='label' maxlength='80'></label>"
        "<button type='submit'>Create harmless test object</button></form>"
        "<output id='created'></output>"
        "<script>"
        "document.querySelector('#create-object').addEventListener('submit',async(event)=>{"
        "event.preventDefault();const label=new FormData(event.target).get('label');"
        "const response=await fetch('/api/objects',{method:'POST',headers:{'Content-Type':'application/json'},"
        "body:JSON.stringify({label})});document.querySelector('#created').textContent=await response.text();});"
        "</script>"
    )


@app.get("/app/files", response_class=HTMLResponse)
def files_page(identity: Annotated[dict[str, str], Depends(_identity)]) -> str:
    return (
        "<!doctype html><title>Files</title>"
        f"<h1>{escape(identity['alias'])} files</h1>"
        "<a href='/api/files/1'>file 1</a><a href='/api/files/2'>file 2</a>"
        "<a href='/api/shares/revoked-share'>revoked share</a>"
    )


@app.get("/app/orders", response_class=HTMLResponse)
def orders_page(identity: Annotated[dict[str, str], Depends(_identity)]) -> str:
    return (
        "<!doctype html><title>Orders</title>"
        f"<h1>{escape(identity['alias'])} orders</h1>"
        "<form action='/api/orders/1/preview' method='post'><button type='submit'>Preview</button></form>"
    )


@app.get("/openapi-fixture.json")
def fixture_schema() -> dict[str, object]:
    return {
        "openapi": "3.1.0",
        "info": {"title": "BudoBugs local fixture", "version": "fixture"},
        "paths": {
            "/api/objects/{object_id}": {"get": {}},
            "/graphql": {"post": {}},
            "/api/files/{file_id}": {"get": {}},
            "/api/orders/{order_id}/confirm": {"post": {}},
            "/api/session/revoke": {"post": {}},
        },
    }


@app.post("/api/objects")
def create_object(
    payload: ObjectCreateRequest,
    identity: Annotated[dict[str, str], Depends(_identity)],
) -> dict[str, object]:
    object_id = max(_OBJECTS) + 1
    item = {
        "id": object_id,
        "owner": identity["alias"],
        "tenant": identity["tenant"],
        "secret": payload.label,
    }
    _OBJECTS[object_id] = item
    return {**item, "fixture_state_change": "harmless-object-created"}


@app.get("/api/objects/{object_id}")
def vulnerable_object(
    object_id: int,
    identity: Annotated[dict[str, str], Depends(_identity)],
) -> dict[str, object]:
    """TEST FIXTURE: the shared object resolver omits owner/tenant enforcement."""

    item = _object(object_id)
    return {
        **item,
        "requested_by": identity["alias"],
        "fixture_issue": "missing shared object authorization",
        "root_cause": "object-resolver-policy-omitted",
    }


@app.get("/api/object-query")
def vulnerable_object_query(
    object_id: int,
    identity: Annotated[dict[str, str], Depends(_identity)],
) -> dict[str, object]:
    item = _object(object_id)
    return {
        **item,
        "requested_by": identity["alias"],
        "fixture_issue": "missing shared object authorization",
        "root_cause": "object-resolver-policy-omitted",
    }


@app.get("/api/secure-objects/{object_id}")
def secure_object(
    object_id: int,
    identity: Annotated[dict[str, str], Depends(_identity)],
) -> dict[str, object]:
    item = _object(object_id)
    if item["owner"] != identity["alias"]:
        raise HTTPException(status_code=403, detail="owner mismatch")
    return item


@app.post("/graphql")
def vulnerable_graphql(
    payload: GraphqlRequest,
    identity: Annotated[dict[str, str], Depends(_identity)],
) -> dict[str, object]:
    object_id = payload.variables.get("objectId")
    if not isinstance(object_id, int):
        raise HTTPException(status_code=400, detail="integer objectId required")
    item = _object(object_id)
    return {
        "data": {
            "object": {
                **item,
                "requested_by": identity["alias"],
                "root_cause": "object-resolver-policy-omitted",
            }
        }
    }


@app.get("/api/public/{object_id}")
def public_object(object_id: int) -> dict[str, object]:
    item = _PUBLIC.get(object_id)
    if item is None:
        raise HTTPException(status_code=404, detail="not found")
    return item


@app.get("/api/admin/audit")
def vulnerable_admin(identity: Annotated[dict[str, str], Depends(_identity)]) -> dict[str, str]:
    return {
        "requested_by": identity["alias"],
        "admin_capability": "audit-export",
        "fixture_issue": "missing function-level role authorization",
    }


@app.get("/api/secure-admin/audit")
def secure_admin(identity: Annotated[dict[str, str], Depends(_identity)]) -> dict[str, str]:
    if identity["role"] != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    return {"requested_by": identity["alias"], "admin_capability": "audit-export"}


@app.get("/api/tenant/{tenant}/settings")
def vulnerable_tenant(
    tenant: str,
    identity: Annotated[dict[str, str], Depends(_identity)],
) -> dict[str, str]:
    if tenant not in {"red", "blue"}:
        raise HTTPException(status_code=404, detail="tenant not found")
    return {
        "tenant": tenant,
        "requested_by": identity["alias"],
        "private_setting": f"{tenant}-private-setting",
        "fixture_issue": "tenant context not enforced",
    }


@app.get("/api/files/{file_id}", response_class=PlainTextResponse)
def vulnerable_file(
    file_id: int,
    identity: Annotated[dict[str, str], Depends(_identity)],
) -> str:
    del identity
    item = _FILES.get(file_id)
    if item is None:
        raise HTTPException(status_code=404, detail="not found")
    return str(item["content"])


@app.get("/api/secure-files/{file_id}", response_class=PlainTextResponse)
def secure_file(
    file_id: int,
    identity: Annotated[dict[str, str], Depends(_identity)],
) -> str:
    item = _FILES.get(file_id)
    if item is None:
        raise HTTPException(status_code=404, detail="not found")
    if item["owner"] != identity["alias"]:
        raise HTTPException(status_code=403, detail="file owner mismatch")
    return str(item["content"])


@app.post("/api/shares")
def create_share(
    payload: ShareRequest,
    identity: Annotated[dict[str, str], Depends(_identity)],
) -> dict[str, object]:
    item = _FILES.get(payload.file_id)
    if item is None or item["owner"] != identity["alias"]:
        raise HTTPException(status_code=403, detail="file owner required")
    token = f"share-{payload.file_id}-{payload.recipient}"
    _SHARES[token] = {
        "file_id": payload.file_id,
        "owner": identity["alias"],
        "recipient": payload.recipient,
        "revoked": False,
    }
    return {"token": token, "state": "active"}


@app.post("/api/shares/{token}/revoke")
def revoke_share(
    token: str,
    identity: Annotated[dict[str, str], Depends(_identity)],
) -> dict[str, str]:
    share = _SHARES.get(token)
    if share is None or share["owner"] != identity["alias"]:
        raise HTTPException(status_code=403, detail="share owner required")
    share["revoked"] = True
    return {"token": token, "state": "revoked"}


@app.get("/api/shares/{token}", response_class=PlainTextResponse)
def vulnerable_share(
    token: str,
    identity: Annotated[dict[str, str], Depends(_identity)],
) -> str:
    share = _SHARES.get(token)
    if share is None or share["recipient"] != identity["alias"]:
        raise HTTPException(status_code=403, detail="share recipient required")
    item = _FILES[int(share["file_id"])]
    return str(item["content"])


@app.get("/api/secure-shares/{token}", response_class=PlainTextResponse)
def secure_share(
    token: str,
    identity: Annotated[dict[str, str], Depends(_identity)],
) -> str:
    share = _SHARES.get(token)
    if share is None or share["recipient"] != identity["alias"] or share["revoked"] is True:
        raise HTTPException(status_code=403, detail="active share required")
    item = _FILES[int(share["file_id"])]
    return str(item["content"])


@app.post("/api/workflows/{workflow_id}/transition")
def vulnerable_transition(
    workflow_id: int,
    payload: TransitionRequest,
    identity: Annotated[dict[str, str], Depends(_identity)],
) -> dict[str, str]:
    del identity
    if workflow_id not in _WORKFLOWS:
        raise HTTPException(status_code=404, detail="not found")
    previous = _WORKFLOWS[workflow_id]
    _WORKFLOWS[workflow_id] = payload.state
    return {"previous": previous, "current": payload.state, "fixture_issue": "transition not constrained"}


@app.get("/api/orders/{order_id}")
def order_state(
    order_id: int,
    identity: Annotated[dict[str, str], Depends(_identity)],
) -> dict[str, object]:
    order = _ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="not found")
    if order["owner"] != identity["alias"]:
        raise HTTPException(status_code=403, detail="order owner required")
    return order


@app.post("/api/orders/{order_id}/preview")
def preview_order(
    order_id: int,
    identity: Annotated[dict[str, str], Depends(_identity)],
) -> dict[str, object]:
    order = _ORDERS.get(order_id)
    if order is None or order["owner"] != identity["alias"]:
        raise HTTPException(status_code=403, detail="order owner required")
    previous = str(order["state"])
    order["state"] = "reviewed"
    return {"previous": previous, "current": "reviewed"}


@app.post("/api/orders/{order_id}/confirm")
def vulnerable_confirm_order(
    order_id: int,
    identity: Annotated[dict[str, str], Depends(_identity)],
) -> dict[str, object]:
    order = _ORDERS.get(order_id)
    if order is None or order["owner"] != identity["alias"]:
        raise HTTPException(status_code=403, detail="order owner required")
    previous = str(order["state"])
    order["state"] = "confirmed"
    order["confirm_count"] = int(order["confirm_count"]) + 1
    return {
        "previous": previous,
        "current": "confirmed",
        "confirm_count": order["confirm_count"],
        "fixture_issue": "workflow prerequisite and one-time effect not enforced",
    }


@app.post("/api/secure-orders/{order_id}/confirm")
def secure_confirm_order(
    order_id: int,
    identity: Annotated[dict[str, str], Depends(_identity)],
) -> dict[str, object]:
    order = _ORDERS.get(order_id)
    if order is None or order["owner"] != identity["alias"]:
        raise HTTPException(status_code=403, detail="order owner required")
    if order["state"] != "reviewed" or order["confirm_count"] != 0:
        raise HTTPException(status_code=409, detail="reviewed one-time order required")
    order["state"] = "confirmed"
    order["confirm_count"] = 1
    return order


@app.post("/api/session/start")
def start_session(identity: Annotated[dict[str, str], Depends(_identity)]) -> dict[str, str]:
    token = f"fixture-api-{identity['alias']}-{len(_API_SESSIONS) + 1}"
    _API_SESSIONS[token] = identity["alias"]
    return {"session": token, "state": "authenticated", "fixture_secret": "local-only"}


def _api_session(x_fixture_api_session: Annotated[str | None, Header()] = None) -> tuple[str, str]:
    if not x_fixture_api_session or x_fixture_api_session not in _API_SESSIONS:
        raise HTTPException(status_code=401, detail="fixture API session required")
    return x_fixture_api_session, _API_SESSIONS[x_fixture_api_session]


@app.get("/api/session/me")
def vulnerable_session_me(session: Annotated[tuple[str, str], Depends(_api_session)]) -> dict[str, str]:
    token, alias = session
    return {
        "alias": alias,
        "state": "authenticated",
        "revoked": str(token in _REVOKED_SESSIONS).lower(),
        "fixture_issue": "revocation not enforced by session consumer",
    }


@app.get("/api/secure-session/me")
def secure_session_me(session: Annotated[tuple[str, str], Depends(_api_session)]) -> dict[str, str]:
    token, alias = session
    if token in _REVOKED_SESSIONS:
        raise HTTPException(status_code=401, detail="session revoked")
    return {"alias": alias, "state": "authenticated"}


@app.post("/api/session/revoke")
def revoke_session(session: Annotated[tuple[str, str], Depends(_api_session)]) -> dict[str, str]:
    token, _alias = session
    _REVOKED_SESSIONS.add(token)
    return {"state": "revoked"}


@app.get("/preview", response_class=HTMLResponse)
def vulnerable_preview() -> str:
    return (
        "<!doctype html><title>BudoBugs DOM fixture</title><p id='sink'></p>"
        "<script>const value=new URLSearchParams(location.search).get('value')||'fixture';"
        "document.querySelector('#sink').innerHTML=value;</script>"
    )


@app.get("/safe-preview", response_class=HTMLResponse)
def safe_preview(value: str = "fixture") -> str:
    return (
        "<!doctype html><title>BudoBugs safe fixture</title>"
        f"<p id='sink'>{escape(value)}</p>"
        "<script>document.querySelector('#sink').textContent="
        "new URLSearchParams(location.search).get('value')||'fixture';</script>"
    )


@app.options("/api/cors-control")
def cors_control(response: Response) -> dict[str, str]:
    response.headers["Access-Control-Allow-Origin"] = "https://trusted.fixture.invalid"
    response.headers["Vary"] = "Origin"
    return {"status": "intentional restricted CORS control"}


@app.websocket("/ws/objects/{object_id}")
async def vulnerable_object_websocket(websocket: WebSocket, object_id: int, actor: str = "bob") -> None:
    if actor not in {"alice", "bob"}:
        await websocket.close(code=4401)
        return
    item = _OBJECTS.get(object_id)
    if item is None:
        await websocket.close(code=4404)
        return
    await websocket.accept()
    await websocket.send_json(
        {
            **item,
            "requested_by": actor,
            "root_cause": "object-resolver-policy-omitted",
            "fixture_issue": "message-level object authorization omitted",
        }
    )
    await websocket.close()
