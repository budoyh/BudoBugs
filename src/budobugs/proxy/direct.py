"""Controlled direct HTTP backend for fixtures and explicit single requests."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

import httpx

from budobugs.core.identifiers import new_id
from budobugs.core.io import atomic_write_json
from budobugs.core.policy import require_allowed, target_allowed
from budobugs.models import Engagement, HttpExchange
from budobugs.proxy.base import ProxyBackend, ProxyCapabilities
from budobugs.traffic.normalization import normalize_exchange


class DirectProxyBackend(ProxyBackend):
    name = "direct"
    capabilities = ProxyCapabilities(
        history=True,
        replay=True,
        http2=True,
        active_automation=False,
        export=True,
    )

    def __init__(self, *, timeout: float = 20.0) -> None:
        self.timeout = timeout
        self._history: dict[str, HttpExchange] = {}

    async def health(self) -> tuple[bool, str]:
        return True, "direct HTTP backend ready"

    async def send(
        self,
        engagement: Engagement,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        content: str | bytes | None = None,
        account_alias: str | None = None,
        source: str = "direct",
    ) -> HttpExchange:
        require_allowed(target_allowed(engagement, url))
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            http2=True,
            trust_env=False,
        ) as client:
            response = await client.request(method, url, headers=headers, content=content)
        exchange = HttpExchange(
            exchange_id=new_id("http"),
            engagement_id=engagement.engagement_id,
            method=method.upper(),
            url=str(response.request.url),
            request_headers=dict(response.request.headers),
            request_body=(
                response.request.content.decode("utf-8", errors="replace") if response.request.content else None
            ),
            response_status=response.status_code,
            response_headers=dict(response.headers),
            response_body=response.text,
            http_version=response.http_version,  # type: ignore[arg-type]
            elapsed_ms=response.elapsed.total_seconds() * 1000,
            account_alias=account_alias,
            source=source,  # type: ignore[arg-type]
        )
        normalized = normalize_exchange(exchange)
        self._history[normalized.exchange_id] = normalized
        return normalized

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
        result: list[HttpExchange] = []
        for item in self._history.values():
            require_allowed(target_allowed(engagement, item.url))
            parsed = urlsplit(item.url)
            response_type = item.response_headers.get("content-type", "")
            if host and parsed.hostname != host:
                continue
            if path and path not in parsed.path:
                continue
            if method and item.method != method.upper():
                continue
            if status is not None and item.response_status != status:
                continue
            if content_type and content_type.lower() not in response_type.lower():
                continue
            result.append(item)
        return result

    async def get(self, exchange_id: str) -> HttpExchange:
        try:
            return self._history[exchange_id]
        except KeyError as exc:
            raise KeyError(f"unknown exchange: {exchange_id}") from exc

    async def replay(
        self,
        engagement: Engagement,
        exchange: HttpExchange,
        *,
        account_alias: str | None = None,
    ) -> HttpExchange:
        return await self.send(
            engagement,
            exchange.method,
            exchange.url,
            headers=exchange.request_headers,
            content=exchange.request_body,
            account_alias=account_alias or exchange.account_alias,
        )

    async def export(self, destination: Path) -> Path:
        payload = [item.model_dump(mode="json") for item in self._history.values()]
        atomic_write_json(destination, payload)
        return destination
