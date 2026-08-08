"""Minimal JSON-RPC MCP client used by localhost proxy adapters."""

from __future__ import annotations

import json
from itertools import count
from typing import Any

import httpx

from budobugs.proxy.base import ProxyUnavailable, require_local_control_plane


class McpHttpClient:
    def __init__(self, url: str, *, timeout: float = 20.0, allow_remote: bool = False) -> None:
        self.url = require_local_control_plane(url, allow_remote=allow_remote)
        self.timeout = timeout
        self._ids = count(1)
        self._session_id: str | None = None

    async def initialize(self) -> dict[str, Any]:
        return await self._request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "budobugs", "version": "2026.8.8"},
            },
        )

    async def list_tools(self) -> list[dict[str, Any]]:
        result = await self._request("tools/list", {})
        tools = result.get("tools", [])
        return tools if isinstance(tools, list) else []

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return await self._request("tools/call", {"name": name, "arguments": arguments})

    async def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        request_id = next(self._ids)
        headers = {"accept": "application/json, text/event-stream"}
        if self._session_id:
            headers["mcp-session-id"] = self._session_id
        payload = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        try:
            async with httpx.AsyncClient(timeout=self.timeout, trust_env=False) as client:
                response = await client.post(self.url, json=payload, headers=headers)
        except httpx.HTTPError as exc:
            raise ProxyUnavailable(f"MCP transport failed: {exc}") from exc
        if response.status_code >= 400:
            raise ProxyUnavailable(f"MCP HTTP {response.status_code}: {response.text[:300]}")
        self._session_id = response.headers.get("mcp-session-id", self._session_id)
        message = _decode_mcp_response(response)
        if "error" in message:
            raise ProxyUnavailable(f"MCP error: {message['error']}")
        result = message.get("result", {})
        return result if isinstance(result, dict) else {"value": result}


def _decode_mcp_response(response: httpx.Response) -> dict[str, Any]:
    content_type = response.headers.get("content-type", "")
    if "text/event-stream" not in content_type:
        payload = response.json()
        if not isinstance(payload, dict):
            raise ProxyUnavailable("MCP response is not an object")
        return payload
    for line in response.text.splitlines():
        if line.startswith("data:"):
            payload = json.loads(line[5:].strip())
            if isinstance(payload, dict):
                return payload
    raise ProxyUnavailable("MCP SSE response contained no JSON data event")
