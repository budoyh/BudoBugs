"""Backend-neutral traffic history and controlled replay contract."""

from __future__ import annotations

import contextlib
import ipaddress
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from budobugs.models import Engagement, HttpExchange


class ProxyUnavailable(RuntimeError):
    """The selected proxy backend cannot satisfy the requested capability."""


@dataclass(frozen=True, slots=True)
class ProxyCapabilities:
    history: bool
    replay: bool
    http2: bool
    active_automation: bool
    export: bool


class ProxyBackend(ABC):
    name: str
    capabilities: ProxyCapabilities

    @abstractmethod
    async def health(self) -> tuple[bool, str]:
        raise ProxyUnavailable("concrete proxy backend does not implement health")

    @abstractmethod
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
        raise ProxyUnavailable("concrete proxy backend does not implement history search")

    @abstractmethod
    async def get(self, exchange_id: str) -> HttpExchange:
        raise ProxyUnavailable("concrete proxy backend does not implement exchange retrieval")

    @abstractmethod
    async def replay(
        self,
        engagement: Engagement,
        exchange: HttpExchange,
        *,
        account_alias: str | None = None,
    ) -> HttpExchange:
        raise ProxyUnavailable("concrete proxy backend does not implement controlled replay")

    @abstractmethod
    async def export(self, destination: Path) -> Path:
        raise ProxyUnavailable("concrete proxy backend does not implement export")

    async def mark_candidate(self, exchange_id: str, label: str) -> dict[str, str]:
        """Attach a local annotation without trusting a remote backend as finding evidence."""

        await self.get(exchange_id)
        annotations = getattr(self, "_budobugs_annotations", None)
        if not isinstance(annotations, dict):
            annotations = {}
            self._budobugs_annotations = annotations
        annotations[exchange_id] = label
        return {"exchange_id": exchange_id, "label": label}

    async def associate(
        self,
        exchange_id: str,
        *,
        account_alias: str,
        role_id: str | None = None,
    ) -> HttpExchange:
        exchange = await self.get(exchange_id)
        return exchange.model_copy(update={"account_alias": account_alias, "role_id": role_id})

    async def evidence_reference(self, exchange_id: str) -> dict[str, str | None]:
        exchange = await self.get(exchange_id)
        return {
            "exchange_id": exchange.exchange_id,
            "request_sha256": exchange.request_hash,
            "response_sha256": exchange.response_hash,
        }


def require_local_control_plane(url: str, *, allow_remote: bool = False) -> str:
    """Validate proxy/MCP control endpoints before any adapter network request."""

    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("proxy control URL must be credential-free absolute HTTP(S)")
    if allow_remote:
        return url.rstrip("/")
    host = parsed.hostname.lower().rstrip(".")
    local = host == "localhost"
    with contextlib.suppress(ValueError):
        local = local or ipaddress.ip_address(host).is_loopback
    if not local:
        raise ValueError("proxy control URL must use localhost/loopback unless explicitly enabled")
    return url.rstrip("/")
