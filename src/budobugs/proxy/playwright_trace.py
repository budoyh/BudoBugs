"""Playwright trace backend paired with the HAR captured by the same browser context."""

from __future__ import annotations

import zipfile
from pathlib import Path

from budobugs.models import Engagement, HttpExchange
from budobugs.proxy.base import ProxyBackend, ProxyCapabilities
from budobugs.proxy.har import HarProxyBackend


class PlaywrightTraceBackend(ProxyBackend):
    name = "playwright-trace"
    capabilities = ProxyCapabilities(history=True, replay=True, http2=True, active_automation=False, export=True)

    def __init__(self, trace_path: Path, har_path: Path, engagement: Engagement) -> None:
        self.trace_path = trace_path.resolve()
        self.har_path = har_path.resolve()
        self._har = HarProxyBackend(self.har_path, engagement)

    async def health(self) -> tuple[bool, str]:
        if not self.trace_path.is_file() or not zipfile.is_zipfile(self.trace_path):
            return False, "Playwright trace ZIP is missing or invalid"
        har_ready, detail = await self._har.health()
        return har_ready, f"Playwright trace ready; {detail}"

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
        return await self._har.search(
            engagement,
            host=host,
            path=path,
            method=method,
            status=status,
            content_type=content_type,
        )

    async def get(self, exchange_id: str) -> HttpExchange:
        return await self._har.get(exchange_id)

    async def replay(
        self,
        engagement: Engagement,
        exchange: HttpExchange,
        *,
        account_alias: str | None = None,
    ) -> HttpExchange:
        return await self._har.replay(engagement, exchange, account_alias=account_alias)

    async def export(self, destination: Path) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(self.trace_path, "trace.zip")
            archive.write(self.har_path, "traffic.har")
        return destination
