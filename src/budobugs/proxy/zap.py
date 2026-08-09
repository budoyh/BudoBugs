"""OWASP ZAP daemon/API backend with scoped history, replay, and export."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from budobugs.core.identifiers import new_id
from budobugs.core.io import atomic_write_json
from budobugs.core.policy import require_allowed, target_allowed
from budobugs.models import Engagement, HttpExchange
from budobugs.proxy.base import (
    CredentialSubstitutedReplay,
    ProxyBackend,
    ProxyCapabilities,
    ProxyUnavailable,
    require_local_control_plane,
)
from budobugs.traffic.normalization import normalize_exchange


class ZapClient(ProxyBackend):
    name = "zap"
    capabilities = ProxyCapabilities(
        history=True,
        replay=True,
        http2=False,
        active_automation=True,
        export=True,
        credential_substitution_replay=True,
    )

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        *,
        timeout: float = 20.0,
        allow_remote_control_plane: bool = False,
    ) -> None:
        self.base_url = require_local_control_plane(base_url, allow_remote=allow_remote_control_plane)
        self.api_key = api_key
        self.timeout = timeout
        self._history: dict[str, HttpExchange] = {}

    async def health(self) -> tuple[bool, str]:
        try:
            payload = await self._get("/JSON/core/view/version/")
        except ProxyUnavailable as exc:
            return False, str(exc)
        return True, f"ZAP {payload.get('version', 'unknown')}"

    async def messages(self, *, base_url: str, start: int = 0, count: int = 500) -> list[dict[str, Any]]:
        payload = await self._get(
            "/JSON/core/view/messages/",
            {"baseurl": base_url, "start": str(start), "count": str(count)},
        )
        messages = payload.get("messages", [])
        return [item for item in messages if isinstance(item, dict)] if isinstance(messages, list) else []

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
        collected: dict[str, HttpExchange] = {}
        for root in engagement.root_targets:
            if root.kind == "source":
                continue
            for message in await self.messages(base_url=root.uri):
                exchange = self._message_to_exchange(message, engagement.engagement_id)
                require_allowed(target_allowed(engagement, exchange.url))
                collected[exchange.exchange_id] = exchange
        self._history.update(collected)
        result: list[HttpExchange] = []
        for exchange in collected.values():
            parsed = urlsplit(exchange.url)
            if host and parsed.hostname != host:
                continue
            if path and path not in parsed.path:
                continue
            if method and exchange.method != method.upper():
                continue
            if status is not None and exchange.response_status != status:
                continue
            response_type = exchange.response_headers.get("content-type", "")
            if content_type and content_type.lower() not in response_type.lower():
                continue
            result.append(exchange)
        return result

    async def get(self, exchange_id: str) -> HttpExchange:
        if exchange_id in self._history:
            return self._history[exchange_id]
        payload = await self._get("/JSON/core/view/message/", {"id": exchange_id})
        message = payload.get("message")
        if not isinstance(message, dict):
            raise KeyError(f"unknown ZAP exchange: {exchange_id}")
        engagement_id = str(message.get("engagementId") or "unassociated")
        exchange = self._message_to_exchange(message, engagement_id)
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
        parsed = urlsplit(exchange.url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        headers = {
            name: value
            for name, value in exchange.request_headers.items()
            if name.lower() not in {"host", "content-length", "connection"}
        }
        header_rows = [f"Host: {parsed.netloc}", *(f"{name}: {value}" for name, value in headers.items())]
        raw = f"{exchange.method} {path} HTTP/1.1\r\n" + "\r\n".join(header_rows) + "\r\n\r\n"
        if exchange.request_body:
            raw += exchange.request_body
        await self.send_request(raw, follow_redirects=False)
        candidates = await self.search(
            engagement,
            host=parsed.hostname,
            path=parsed.path,
            method=exchange.method,
        )
        if not candidates:
            raise ProxyUnavailable("ZAP replay completed but no scoped history record was returned")
        latest = candidates[-1].model_copy(update={"account_alias": account_alias or exchange.account_alias})
        self._history[latest.exchange_id] = latest
        return latest

    async def replay_with_request(
        self,
        engagement: Engagement,
        request: CredentialSubstitutedReplay,
    ) -> HttpExchange:
        """Send an explicit request through ZAP's local control API."""

        exchange = request.exchange
        require_allowed(target_allowed(engagement, exchange.url))
        parsed = urlsplit(exchange.url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        # Host/framing are generated here from the scoped destination. They
        # cannot be inherited from captured traffic or caller headers.
        header_rows = [f"Host: {parsed.netloc}", *(f"{name}: {value}" for name, value in request.headers.items())]
        raw = f"{exchange.method} {path} HTTP/1.1\r\n" + "\r\n".join(header_rows) + "\r\n\r\n"
        if request.body:
            raw += request.body
        await self.send_request(raw, follow_redirects=False)
        candidates = await self.search(
            engagement,
            host=parsed.hostname,
            path=parsed.path,
            method=exchange.method,
        )
        if not candidates:
            raise ProxyUnavailable(
                "ZAP credential-substituted replay completed but no scoped history record was returned"
            )
        latest = candidates[-1].model_copy(update={"account_alias": request.account_alias})
        self._history[latest.exchange_id] = latest
        return latest

    async def export(self, destination: Path) -> Path:
        atomic_write_json(destination, [item.model_dump(mode="json") for item in self._history.values()])
        return destination

    async def send_request(self, raw_request: str, *, follow_redirects: bool = False) -> dict[str, Any]:
        if "\x00" in raw_request or len(raw_request.encode("utf-8")) > 2 * 1024 * 1024:
            raise ValueError("invalid or oversized raw request")
        return await self._get(
            "/JSON/core/action/sendRequest/",
            {"request": raw_request, "followRedirects": str(follow_redirects).lower()},
        )

    async def _get(self, path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        query = dict(params or {})
        if self.api_key:
            query["apikey"] = self.api_key
        try:
            async with httpx.AsyncClient(timeout=self.timeout, trust_env=False) as client:
                response = await client.get(f"{self.base_url}{path}", params=query)
        except httpx.HTTPError as exc:
            raise ProxyUnavailable(f"ZAP connection failed: {exc}") from exc
        if response.status_code >= 400:
            raise ProxyUnavailable(f"ZAP HTTP {response.status_code}")
        payload = response.json()
        if not isinstance(payload, dict):
            raise ProxyUnavailable("ZAP returned a non-object response")
        return payload

    @staticmethod
    def _message_to_exchange(message: dict[str, Any], engagement_id: str) -> HttpExchange:
        request_headers = _raw_headers(str(message.get("requestHeader", "")))
        response_headers = _raw_headers(str(message.get("responseHeader", "")))
        status_value = message.get("statusCode", 0)
        elapsed_value = message.get("rtt")
        try:
            response_status = int(status_value)
        except (TypeError, ValueError):
            response_status = 0
        try:
            elapsed_ms = float(elapsed_value) if elapsed_value is not None else None
        except (TypeError, ValueError):
            elapsed_ms = None
        exchange = HttpExchange(
            exchange_id=str(message.get("id") or new_id("zap")),
            engagement_id=engagement_id,
            method=str(message.get("method") or _request_method(str(message.get("requestHeader", "")))).upper(),
            url=str(message.get("requestUrl") or message.get("url") or ""),
            request_headers=request_headers,
            request_body=str(message.get("requestBody") or "") or None,
            response_status=response_status,
            response_headers=response_headers,
            response_body=str(message.get("responseBody") or "") or None,
            elapsed_ms=elapsed_ms,
            source="zap",
        )
        return normalize_exchange(exchange)


def _raw_headers(value: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in value.replace("\r\n", "\n").split("\n")[1:]:
        name, separator, item = line.partition(":")
        if separator and name.strip():
            headers[name.strip()] = item.strip()
    return headers


def _request_method(value: str) -> str:
    first = value.replace("\r\n", "\n").split("\n", 1)[0].split()
    return first[0] if first else "GET"
