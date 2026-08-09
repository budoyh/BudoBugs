"""Burp official MCP backend with edition/capability detection and scoped replay."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from budobugs.core.identifiers import new_id
from budobugs.core.io import atomic_write_json
from budobugs.core.policy import require_allowed, target_allowed
from budobugs.models import Engagement, HttpExchange
from budobugs.proxy.base import CredentialSubstitutedReplay, ProxyBackend, ProxyCapabilities, ProxyUnavailable
from budobugs.proxy.mcp import McpHttpClient
from budobugs.traffic.normalization import normalize_exchange


class BurpMcpAdapter(ProxyBackend):
    name = "burp-mcp"
    capabilities = ProxyCapabilities(
        history=True,
        replay=True,
        http2=True,
        active_automation=False,
        export=True,
        credential_substitution_replay=True,
    )

    def __init__(self, url: str, *, timeout: float = 20.0) -> None:
        self.client = McpHttpClient(url, timeout=timeout)
        self._tools: set[str] | None = None
        self._history: dict[str, HttpExchange] = {}

    async def health(self) -> tuple[bool, str]:
        try:
            server = await self.client.initialize()
            tools = await self.client.list_tools()
        except (RuntimeError, ProxyUnavailable) as exc:
            return False, str(exc)
        self._tools = {str(item.get("name")) for item in tools if isinstance(item, dict)}
        info = server.get("serverInfo", {})
        name = info.get("name", "Burp MCP") if isinstance(info, dict) else "Burp MCP"
        edition = (
            "Professional-capable"
            if any("collaborator" in item.lower() for item in self._tools)
            else "Community/limited"
        )
        return True, f"{name}; edition={edition}; tools={len(self._tools)}"

    async def search(
        self,
        engagement: Engagement,
        *,
        host: str | None = None,
        path: str | None = None,
        method: str | None = None,
        status: int | None = None,
        content_type: str | None = None,
    ) -> list[HttpExchange]:
        arguments: dict[str, object] = {"limit": 500}
        if host:
            arguments["host"] = host
        if path:
            arguments["path"] = path
        if method:
            arguments["method"] = method.upper()
        if status is not None:
            arguments["status"] = status
        payload = await self.call_capability(
            ["search_http_history", "search_proxy_history", "get_proxy_history"],
            arguments,
        )
        rows = _rows(payload)
        result: list[HttpExchange] = []
        for row in rows:
            exchange = _to_exchange(row, engagement.engagement_id)
            require_allowed(target_allowed(engagement, exchange.url))
            parsed = urlsplit(exchange.url)
            if host and parsed.hostname != host:
                continue
            if path and path not in parsed.path:
                continue
            if method and exchange.method != method.upper():
                continue
            if status is not None and exchange.response_status != status:
                continue
            if content_type and content_type.lower() not in exchange.response_headers.get("content-type", "").lower():
                continue
            self._history[exchange.exchange_id] = exchange
            result.append(exchange)
        return result

    async def get(self, exchange_id: str) -> HttpExchange:
        if exchange_id in self._history:
            return self._history[exchange_id]
        payload = await self.call_capability(
            ["get_http_request_response", "get_proxy_history_item", "get_http_history_item"],
            {"id": exchange_id},
        )
        rows = _rows(payload)
        if not rows:
            raise KeyError(f"unknown Burp history item: {exchange_id}")
        exchange = _to_exchange(rows[0], "unassociated")
        self._history[exchange.exchange_id] = exchange
        return exchange

    async def replay(
        self,
        engagement: Engagement,
        exchange: HttpExchange,
        *,
        account_alias: str | None = None,
    ) -> HttpExchange:
        require_allowed(target_allowed(engagement, exchange.url))
        arguments = {
            "id": exchange.exchange_id,
            "method": exchange.method,
            "url": exchange.url,
            "headers": exchange.request_headers,
            "body": exchange.request_body or "",
            "httpVersion": exchange.http_version or "HTTP/1.1",
            "followRedirects": False,
        }
        payload = await self.call_capability(
            ["send_http_request", "repeat_http_request", "replay_http_request"],
            arguments,
        )
        rows = _rows(payload)
        if not rows:
            raise ProxyUnavailable("Burp MCP replay returned no request/response evidence")
        result = _to_exchange(rows[0], engagement.engagement_id).model_copy(
            update={"account_alias": account_alias or exchange.account_alias}
        )
        require_allowed(target_allowed(engagement, result.url))
        self._history[result.exchange_id] = result
        return result

    async def replay_with_request(
        self,
        engagement: Engagement,
        request: CredentialSubstitutedReplay,
    ) -> HttpExchange:
        """Use a Burp MCP sender with an explicit, substituted request payload."""

        exchange = request.exchange
        require_allowed(target_allowed(engagement, exchange.url))
        payload = await self.call_capability(
            ["send_http_request", "repeat_http_request", "replay_http_request"],
            {
                "method": exchange.method,
                "url": exchange.url,
                "headers": request.headers,
                "body": request.body or "",
                "httpVersion": exchange.http_version or "HTTP/1.1",
                "followRedirects": False,
            },
        )
        rows = _rows(payload)
        if not rows:
            raise ProxyUnavailable("Burp MCP credential-substituted replay returned no request/response evidence")
        result = _to_exchange(rows[0], engagement.engagement_id).model_copy(
            update={"account_alias": request.account_alias}
        )
        require_allowed(target_allowed(engagement, result.url))
        self._history[result.exchange_id] = result
        return result

    async def create_repeater(self, engagement: Engagement, exchange: HttpExchange) -> dict[str, Any]:
        require_allowed(target_allowed(engagement, exchange.url))
        return await self.call_capability(
            ["send_to_repeater", "create_repeater_tab"],
            {"id": exchange.exchange_id, "title": f"BudoBugs {exchange.exchange_id}"},
        )

    async def export(self, destination: Path) -> Path:
        atomic_write_json(destination, [item.model_dump(mode="json") for item in self._history.values()])
        return destination

    async def call_capability(self, candidates: list[str], arguments: dict[str, Any]) -> dict[str, Any]:
        if self._tools is None:
            self._tools = {str(item.get("name")) for item in await self.client.list_tools() if isinstance(item, dict)}
        for candidate in candidates:
            if candidate in self._tools:
                return await self.client.call_tool(candidate, arguments)
        raise ProxyUnavailable(f"Burp edition/server lacks required capability: {candidates}")


def _rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    structured = payload.get("structuredContent")
    value: Any = structured if structured is not None else payload
    if isinstance(value, dict):
        for key in ("items", "requests", "history", "results", "exchange", "message"):
            candidate = value.get(key)
            if isinstance(candidate, list):
                return [item for item in candidate if isinstance(item, dict)]
            if isinstance(candidate, dict):
                return [candidate]
    content = payload.get("content")
    if isinstance(content, list):
        for block in content:
            if not isinstance(block, dict) or not isinstance(block.get("text"), str):
                continue
            try:
                decoded = json.loads(block["text"])
            except json.JSONDecodeError:
                continue
            if isinstance(decoded, list):
                return [item for item in decoded if isinstance(item, dict)]
            if isinstance(decoded, dict):
                return _rows(decoded)
    return []


def _to_exchange(row: dict[str, Any], engagement_id: str) -> HttpExchange:
    request = row.get("request")
    if not isinstance(request, dict):
        request = row
    response = row.get("response")
    if not isinstance(response, dict):
        response = row
    url = str(request.get("url") or row.get("url") or "")
    method = str(request.get("method") or row.get("method") or "GET").upper()
    request_headers = _headers(request.get("headers") or request.get("requestHeaders"))
    response_headers = _headers(response.get("headers") or response.get("responseHeaders"))
    status_value = response.get("status") or response.get("statusCode") or row.get("status") or 0
    exchange = HttpExchange(
        exchange_id=str(row.get("id") or request.get("id") or new_id("burp")),
        engagement_id=engagement_id,
        method=method,
        url=url,
        request_headers=request_headers,
        request_body=_body(request.get("body") or request.get("requestBody")),
        response_status=int(status_value),
        response_headers=response_headers,
        response_body=_body(response.get("body") or response.get("responseBody")),
        http_version=_http_version(request.get("httpVersion") or row.get("httpVersion")),
        source="burp",
    )
    return normalize_exchange(exchange)


def _headers(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(name): str(item) for name, item in value.items()}
    if isinstance(value, list):
        headers: dict[str, str] = {}
        for item in value:
            if isinstance(item, dict) and "name" in item:
                headers[str(item["name"])] = str(item.get("value", ""))
        return headers
    return {}


def _body(value: Any) -> str | None:
    if value is None or value == "":
        return None
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def _http_version(value: Any) -> Literal["HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"] | None:
    normalized = str(value).upper().replace("HTTP/2.0", "HTTP/2") if value else ""
    if normalized == "HTTP/1.0":
        return "HTTP/1.0"
    if normalized == "HTTP/1.1":
        return "HTTP/1.1"
    if normalized == "HTTP/2":
        return "HTTP/2"
    if normalized == "HTTP/3":
        return "HTTP/3"
    return None
