"""Read-only HAR history with controlled replay delegated to the direct backend."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from budobugs.core.io import atomic_write_bytes
from budobugs.models import Engagement, HttpExchange
from budobugs.proxy.base import ProxyBackend, ProxyCapabilities
from budobugs.proxy.direct import DirectProxyBackend
from budobugs.traffic.importer import import_har


class HarProxyBackend(ProxyBackend):
    name = "har"
    capabilities = ProxyCapabilities(
        history=True,
        replay=True,
        http2=False,
        active_automation=False,
        export=True,
    )

    def __init__(self, path: Path, engagement: Engagement) -> None:
        self.path = path
        self._items = {item.exchange_id: item for item in import_har(path, engagement)}
        self._direct = DirectProxyBackend()

    async def health(self) -> tuple[bool, str]:
        return True, f"loaded {len(self._items)} HAR exchanges"

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
        for item in self._items.values():
            parsed = urlsplit(item.url)
            if host and parsed.hostname != host:
                continue
            if path and path not in parsed.path:
                continue
            if method and item.method != method.upper():
                continue
            if status is not None and item.response_status != status:
                continue
            if content_type and content_type not in item.response_headers.get("content-type", ""):
                continue
            result.append(item)
        return result

    async def get(self, exchange_id: str) -> HttpExchange:
        return self._items[exchange_id]

    async def replay(
        self,
        engagement: Engagement,
        exchange: HttpExchange,
        *,
        account_alias: str | None = None,
    ) -> HttpExchange:
        return await self._direct.replay(engagement, exchange, account_alias=account_alias)

    async def export(self, destination: Path) -> Path:
        atomic_write_bytes(destination, self.path.read_bytes())
        return destination
