"""Caido backend driven by the pinned official ``@caido/sdk-client`` bridge."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlunsplit

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


class CaidoClient(ProxyBackend):
    name = "caido"
    capabilities = ProxyCapabilities(
        history=True,
        replay=True,
        http2=True,
        active_automation=True,
        export=True,
        credential_substitution_replay=True,
    )

    def __init__(
        self,
        instance_url: str,
        pat: str,
        *,
        timeout: float = 20.0,
        allow_remote_control_plane: bool = False,
        repository_root: Path | None = None,
    ) -> None:
        self.instance_url = require_local_control_plane(instance_url, allow_remote=allow_remote_control_plane)
        if not pat:
            raise ValueError("Caido PAT must be supplied from keyring/environment")
        self._pat = pat
        self.timeout = timeout
        self.repository_root = (repository_root or Path(__file__).resolve().parents[3]).resolve()
        self.bridge = self.repository_root / "integrations" / "caido" / "src" / "bridge.ts"
        self._history: dict[str, HttpExchange] = {}

    async def health(self) -> tuple[bool, str]:
        try:
            payload = await self._bridge({"action": "health", "url": self.instance_url})
        except ProxyUnavailable as exc:
            return False, str(exc)
        ready = payload.get("ready")
        return ready is not False, f"Caido official SDK ready={ready}; version={payload.get('version', 'unknown')}"

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
        filters: dict[str, object] = {}
        if host:
            filters["host"] = host
        if path:
            filters["path"] = path
        if method:
            filters["method"] = method.upper()
        if status is not None:
            filters["status"] = status
        payload = await self._bridge({"action": "search", "url": self.instance_url, "filters": filters, "count": 500})
        if not isinstance(payload, list):
            raise ProxyUnavailable("Caido SDK search returned a non-list payload")
        result: list[HttpExchange] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            exchange = self._convert(item, engagement.engagement_id)
            require_allowed(target_allowed(engagement, exchange.url))
            if content_type and content_type.lower() not in exchange.response_headers.get("content-type", "").lower():
                continue
            self._history[exchange.exchange_id] = exchange
            result.append(exchange)
        return result

    async def get(self, exchange_id: str) -> HttpExchange:
        if exchange_id in self._history:
            return self._history[exchange_id]
        payload = await self._bridge({"action": "get", "url": self.instance_url, "id": exchange_id})
        if not isinstance(payload, dict):
            raise KeyError(f"unknown Caido request: {exchange_id}")
        exchange = self._convert(payload, "unassociated")
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
        payload = await self._bridge({"action": "replay", "url": self.instance_url, "id": exchange.exchange_id})
        replay = payload.get("exchange") if isinstance(payload, dict) else None
        if not isinstance(replay, dict):
            raise ProxyUnavailable(f"Caido replay did not return an exchange: {payload}")
        result = self._convert(replay, engagement.engagement_id).model_copy(
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
        """Ask the official SDK bridge to send the explicit fresh request."""

        exchange = request.exchange
        require_allowed(target_allowed(engagement, exchange.url))
        payload = await self._bridge(
            {
                "action": "replay_with_request",
                "url": self.instance_url,
                "history_id": exchange.exchange_id,
                "request": {
                    "method": exchange.method,
                    "url": exchange.url,
                    "headers": request.headers,
                    "body": request.body,
                },
            }
        )
        replay = payload.get("exchange") if isinstance(payload, dict) else None
        if not isinstance(replay, dict):
            raise ProxyUnavailable(f"Caido credential-substituted replay did not return an exchange: {payload}")
        result = self._convert(replay, engagement.engagement_id).model_copy(
            update={"account_alias": request.account_alias}
        )
        require_allowed(target_allowed(engagement, result.url))
        self._history[result.exchange_id] = result
        return result

    async def export(self, destination: Path) -> Path:
        atomic_write_json(destination, [item.model_dump(mode="json") for item in self._history.values()])
        return destination

    async def _bridge(self, request: dict[str, object]) -> Any:
        pnpm = shutil.which("pnpm") or shutil.which("pnpm.cmd")
        if pnpm is None or not self.bridge.is_file():
            raise ProxyUnavailable("Caido official SDK bridge runtime is not installed")
        with tempfile.TemporaryDirectory(prefix="budobugs-caido-") as directory:
            request_path = Path(directory) / "request.json"
            atomic_write_json(request_path, request)
            environment = {
                name: value
                for name, value in os.environ.items()
                if name.upper() in {"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME"}
            }
            environment["CAIDO_PAT"] = self._pat
            process = await asyncio.create_subprocess_exec(
                pnpm,
                "exec",
                "tsx",
                str(self.bridge),
                str(request_path),
                cwd=self.repository_root,
                env=environment,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout)
            except TimeoutError:
                process.kill()
                await process.wait()
                raise ProxyUnavailable("Caido SDK bridge timed out") from None
        if process.returncode != 0:
            detail = stderr.decode("utf-8", errors="replace")[-500:]
            raise ProxyUnavailable(f"Caido SDK bridge failed: {detail}")
        try:
            envelope = json.loads(stdout.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ProxyUnavailable("Caido SDK bridge returned invalid JSON") from exc
        if not isinstance(envelope, dict) or envelope.get("status") != "PASS":
            raise ProxyUnavailable(f"Caido SDK bridge returned failure: {envelope}")
        return envelope.get("result")

    @staticmethod
    def _convert(payload: dict[str, Any], engagement_id: str) -> HttpExchange:
        request = payload.get("request")
        response = payload.get("response")
        if not isinstance(request, dict):
            raise ProxyUnavailable("Caido item has no request")
        response = response if isinstance(response, dict) else {}
        request_raw = _decode_raw(request.get("rawBase64"))
        response_raw = _decode_raw(response.get("rawBase64"))
        request_headers, request_body = _split_http(request_raw)
        response_headers, response_body = _split_http(response_raw)
        scheme = "https" if request.get("isTls") is True else "http"
        host = str(request.get("host") or "")
        port = int(request.get("port") or (443 if scheme == "https" else 80))
        netloc = host if port in {80, 443} else f"{host}:{port}"
        url = urlunsplit((scheme, netloc, str(request.get("path") or "/"), str(request.get("query") or ""), ""))
        exchange = HttpExchange(
            exchange_id=str(request.get("id") or ""),
            engagement_id=engagement_id,
            method=str(request.get("method") or "GET").upper(),
            url=url,
            request_headers=request_headers,
            request_body=request_body,
            response_status=int(response.get("statusCode") or 0),
            response_headers=response_headers,
            response_body=response_body,
            elapsed_ms=float(response.get("roundtripTime") or 0),
            source="caido",
        )
        return normalize_exchange(exchange)


def _decode_raw(value: object) -> str:
    if not isinstance(value, str) or not value:
        return ""
    try:
        return base64.b64decode(value, validate=True).decode("utf-8", errors="replace")
    except (ValueError, TypeError):
        return ""


def _split_http(value: str) -> tuple[dict[str, str], str | None]:
    head, separator, body = value.replace("\r\n", "\n").partition("\n\n")
    headers: dict[str, str] = {}
    for line in head.split("\n")[1:]:
        name, colon, item = line.partition(":")
        if colon and name.strip():
            headers[name.strip()] = item.strip()
    return headers, body if separator and body else None
