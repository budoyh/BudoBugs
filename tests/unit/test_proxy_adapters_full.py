from __future__ import annotations

import base64
import json
from pathlib import Path

import httpx
import pytest

from budobugs.models import Engagement
from budobugs.proxy.base import CredentialSubstitutedReplay, ProxyUnavailable
from budobugs.proxy.burp import BurpMcpAdapter, _body, _headers, _http_version, _rows
from budobugs.proxy.caido import CaidoClient, _decode_raw, _split_http
from budobugs.proxy.mcp import McpHttpClient, _decode_mcp_response
from budobugs.proxy.zap import ZapClient, _raw_headers, _request_method


def _b64(value: str) -> str:
    return base64.b64encode(value.encode()).decode()


def _caido_row(identifier: str = "caido-1", *, path: str = "/api/objects/1") -> dict[str, object]:
    return {
        "request": {
            "id": identifier,
            "method": "GET",
            "host": "127.0.0.1",
            "port": 8765,
            "path": path,
            "query": "",
            "isTls": False,
            "rawBase64": _b64(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:8765\r\nX-Test: one\r\n\r\n"),
        },
        "response": {
            "statusCode": 200,
            "roundtripTime": 4,
            "rawBase64": _b64('HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{"id":1}'),
        },
    }


@pytest.mark.asyncio
async def test_caido_backend_health_history_get_replay_and_export(
    repository_root: Path, tmp_path: Path, lab_engagement: Engagement, monkeypatch
) -> None:
    client = CaidoClient(
        "http://127.0.0.1:7777",
        "fixture-pat",
        repository_root=repository_root,
    )
    calls: list[str] = []
    bridge_requests: list[dict[str, object]] = []

    async def bridge(request: dict[str, object]) -> object:
        bridge_requests.append(request)
        action = str(request["action"])
        calls.append(action)
        if action == "health":
            return {"ready": True, "version": "test"}
        if action == "search":
            return [_caido_row(), "ignored"]
        if action == "get":
            return _caido_row("caido-get", path="/api/objects/2")
        if action == "replay":
            return {"exchange": _caido_row("caido-replay")}
        if action == "replay_with_request":
            return {"exchange": _caido_row("caido-substituted")}
        raise AssertionError(action)

    monkeypatch.setattr(client, "_bridge", bridge)
    ready, detail = await client.health()
    assert ready
    assert "version=test" in detail
    history = await client.search(
        lab_engagement,
        host="127.0.0.1",
        path="/api",
        method="get",
        status=200,
        content_type="json",
    )
    assert len(history) == 1
    assert (await client.get(history[0].exchange_id)).exchange_id == "caido-1"
    assert (await client.get("missing")).exchange_id == "caido-get"
    replayed = await client.replay(lab_engagement, history[0], account_alias="bob")
    assert replayed.account_alias == "bob"
    request = CredentialSubstitutedReplay.build(
        history[0].model_copy(
            update={"request_headers": {"Cookie": "history-secret", "Authorization": "history-secret"}}
        ),
        account_alias="bob",
        declared_account_headers={"Authorization": "Bearer declared-bob", "X-Account": "bob"},
    )
    substituted = await client.replay_with_request(lab_engagement, request)
    assert substituted.account_alias == "bob"
    bridge_request = next(item for item in bridge_requests if item["action"] == "replay_with_request")
    request_payload = bridge_request["request"]
    assert isinstance(request_payload, dict)
    assert request_payload["headers"] == {"Authorization": "Bearer declared-bob", "X-Account": "bob"}
    assert "history-secret" not in json.dumps(bridge_request)
    exported = await client.export(tmp_path / "caido.json")
    assert len(json.loads(exported.read_text(encoding="utf-8"))) == 4
    assert calls == ["health", "search", "get", "replay", "replay_with_request"]

    async def unavailable(_request: dict[str, object]) -> object:
        raise ProxyUnavailable("bridge absent")

    monkeypatch.setattr(client, "_bridge", unavailable)
    assert await client.health() == (False, "bridge absent")


def test_caido_raw_helpers_and_invalid_conversion() -> None:
    assert _decode_raw(_b64("hello")) == "hello"
    assert _decode_raw("not-base64") == ""
    assert _decode_raw(None) == ""
    headers, body = _split_http("GET / HTTP/1.1\r\nX-Test: yes\r\n\r\nbody")
    assert headers == {"X-Test": "yes"}
    assert body == "body"
    with pytest.raises(ProxyUnavailable, match="no request"):
        CaidoClient._convert({}, "engagement")


def _burp_row(identifier: str = "burp-1", *, url: str = "http://127.0.0.1:8765/api/objects/1") -> dict[str, object]:
    return {
        "id": identifier,
        "request": {
            "url": url,
            "method": "GET",
            "headers": {"X-Test": "one"},
            "body": "",
            "httpVersion": "HTTP/2.0",
        },
        "response": {
            "status": 200,
            "headers": [{"name": "content-type", "value": "application/json"}],
            "body": {"id": 1},
        },
    }


@pytest.mark.asyncio
async def test_burp_backend_capabilities_history_replay_repeater_and_export(
    tmp_path: Path, lab_engagement: Engagement
) -> None:
    adapter = BurpMcpAdapter("http://127.0.0.1:7778/mcp")
    called: list[str] = []
    requests: list[tuple[str, dict[str, object]]] = []

    class Client:
        async def initialize(self) -> dict[str, object]:
            return {"serverInfo": {"name": "Burp Test"}}

        async def list_tools(self) -> list[dict[str, object]]:
            return [
                {"name": "search_http_history"},
                {"name": "get_http_request_response"},
                {"name": "send_http_request"},
                {"name": "send_to_repeater"},
                {"name": "collaborator_poll"},
            ]

        async def call_tool(self, name: str, arguments: dict[str, object]) -> dict[str, object]:
            called.append(name)
            requests.append((name, arguments))
            if name == "search_http_history":
                return {"structuredContent": {"items": [_burp_row()]}}
            if name == "get_http_request_response":
                return {"content": [{"text": json.dumps({"exchange": _burp_row("burp-get")})}]}
            if name == "send_http_request":
                return {"structuredContent": {"exchange": _burp_row("burp-replay")}}
            if name == "send_to_repeater":
                return {"structuredContent": {"message": {"status": "created"}}}
            raise AssertionError((name, arguments))

    adapter.client = Client()  # type: ignore[assignment]
    ready, detail = await adapter.health()
    assert ready
    assert "Professional-capable" in detail
    history = await adapter.search(
        lab_engagement,
        host="127.0.0.1",
        path="objects",
        method="GET",
        status=200,
        content_type="json",
    )
    assert len(history) == 1
    assert history[0].http_version == "HTTP/2"
    assert await adapter.get("burp-1") == history[0]
    assert (await adapter.get("missing")).exchange_id == "burp-get"
    replayed = await adapter.replay(lab_engagement, history[0], account_alias="alice")
    assert replayed.account_alias == "alice"
    request = CredentialSubstitutedReplay.build(
        history[0].model_copy(
            update={"request_headers": {"Cookie": "history-secret", "Authorization": "history-secret"}}
        ),
        account_alias="alice",
        declared_account_headers={"Authorization": "Bearer declared-alice", "X-Account": "alice"},
    )
    substituted = await adapter.replay_with_request(lab_engagement, request)
    assert substituted.account_alias == "alice"
    _, arguments = requests[-1]
    assert arguments["headers"] == {"Authorization": "Bearer declared-alice", "X-Account": "alice"}
    assert "history-secret" not in json.dumps(arguments)
    assert "id" not in arguments
    assert (await adapter.create_repeater(lab_engagement, history[0]))["structuredContent"]
    exported = await adapter.export(tmp_path / "burp.json")
    assert exported.is_file()
    assert called == [
        "search_http_history",
        "get_http_request_response",
        "send_http_request",
        "send_http_request",
        "send_to_repeater",
    ]


@pytest.mark.asyncio
async def test_burp_helpers_and_missing_capability(lab_engagement: Engagement) -> None:
    assert _headers({"A": 1}) == {"A": "1"}
    assert _headers([{"name": "B", "value": "2"}, "ignored"]) == {"B": "2"}
    assert _headers("invalid") == {}
    assert _body(None) is None
    assert _body("") is None
    assert _body({"a": 1}) == '{"a": 1}'
    assert _http_version("HTTP/3") == "HTTP/3"
    assert _http_version("unknown") is None
    assert _rows({"content": [{"text": "not-json"}]}) == []
    assert _rows({"content": [{"text": '[{"id":"one"}]'}]}) == [{"id": "one"}]
    adapter = BurpMcpAdapter("http://127.0.0.1:7778/mcp")

    class EmptyClient:
        async def list_tools(self) -> list[dict[str, object]]:
            return []

    adapter.client = EmptyClient()  # type: ignore[assignment]
    with pytest.raises(ProxyUnavailable, match="lacks required"):
        await adapter.search(lab_engagement)


def _zap_message(identifier: str = "zap-1") -> dict[str, object]:
    return {
        "id": identifier,
        "method": "GET",
        "requestUrl": "http://127.0.0.1:8765/api/objects/1",
        "requestHeader": "GET /api/objects/1 HTTP/1.1\r\nX-Test: one\r\n",
        "responseHeader": "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n",
        "requestBody": "",
        "responseBody": '{"id":1}',
        "statusCode": "200",
        "rtt": "5",
    }


@pytest.mark.asyncio
async def test_zap_backend_health_history_get_replay_export_and_raw_guard(
    tmp_path: Path, lab_engagement: Engagement, monkeypatch
) -> None:
    client = ZapClient("http://127.0.0.1:7779", api_key="fixture")
    sent: list[str] = []

    async def get(path: str, params: dict[str, str] | None = None) -> dict[str, object]:
        if path.endswith("version/"):
            return {"version": "test"}
        if path.endswith("messages/"):
            return {"messages": [_zap_message("zap-1"), _zap_message("zap-2")]}
        if path.endswith("message/"):
            return {"message": _zap_message("zap-get")}
        if path.endswith("sendRequest/"):
            sent.append(str((params or {})["request"]))
            return {"Result": "OK"}
        raise AssertionError(path)

    monkeypatch.setattr(client, "_get", get)
    assert (await client.health())[0]
    history = await client.search(
        lab_engagement,
        host="127.0.0.1",
        path="/api/objects",
        method="GET",
        status=200,
        content_type="json",
    )
    assert len(history) == 2
    assert await client.get("zap-1") == history[0]
    assert (await client.get("missing")).exchange_id == "zap-get"
    replayed = await client.replay(lab_engagement, history[0], account_alias="bob")
    assert replayed.account_alias == "bob"
    assert sent
    assert sent[0].startswith("GET /api/objects/1 HTTP/1.1")
    request = CredentialSubstitutedReplay.build(
        history[0].model_copy(
            update={"request_headers": {"Cookie": "history-secret", "Authorization": "history-secret"}}
        ),
        account_alias="bob",
        declared_account_headers={"Authorization": "Bearer declared-bob", "X-Account": "bob"},
    )
    substituted = await client.replay_with_request(lab_engagement, request)
    assert substituted.account_alias == "bob"
    assert "Authorization: Bearer declared-bob" in sent[-1]
    assert "X-Account: bob" in sent[-1]
    assert "history-secret" not in sent[-1]
    assert "Cookie:" not in sent[-1]
    assert (await client.export(tmp_path / "zap.json")).is_file()
    with pytest.raises(ValueError, match="invalid or oversized"):
        await client.send_request("bad\x00request")
    assert _raw_headers("HTTP/1.1 200 OK\r\nA: one\r\n") == {"A": "one"}
    assert _request_method("POST / HTTP/1.1") == "POST"
    assert _request_method("") == "GET"


@pytest.mark.asyncio
async def test_mcp_http_client_json_sse_session_and_errors(monkeypatch) -> None:
    responses = [
        httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {"name": "test"}}},
            headers={"mcp-session-id": "session-1"},
        ),
        httpx.Response(
            200,
            text='event: message\ndata: {"jsonrpc":"2.0","id":2,"result":{"tools":[]}}\n\n',
            headers={"content-type": "text/event-stream"},
        ),
        httpx.Response(200, json={"jsonrpc": "2.0", "id": 3, "result": "scalar"}),
        httpx.Response(200, json={"jsonrpc": "2.0", "id": 4, "error": {"code": -1}}),
    ]
    observed_headers: list[dict[str, str]] = []

    class HttpClient:
        def __init__(self, **_kwargs: object) -> None:
            self.kwargs = _kwargs

        async def __aenter__(self) -> HttpClient:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def post(self, _url: str, *, json: object, headers: dict[str, str]) -> httpx.Response:
            del json
            observed_headers.append(headers)
            return responses.pop(0)

    monkeypatch.setattr("budobugs.proxy.mcp.httpx.AsyncClient", HttpClient)
    client = McpHttpClient("http://127.0.0.1:7780/mcp")
    assert (await client.initialize())["serverInfo"]
    assert await client.list_tools() == []
    assert await client.call_tool("fixture", {}) == {"value": "scalar"}
    assert observed_headers[1]["mcp-session-id"] == "session-1"
    with pytest.raises(ProxyUnavailable, match="MCP error"):
        await client.call_tool("fixture", {})

    response = httpx.Response(200, json=["not", "object"])
    with pytest.raises(ProxyUnavailable, match="not an object"):
        _decode_mcp_response(response)
    empty_sse = httpx.Response(200, text="event: message\n\n", headers={"content-type": "text/event-stream"})
    with pytest.raises(ProxyUnavailable, match="no JSON"):
        _decode_mcp_response(empty_sse)
