"""Runtime selection of a backend that is used by the hunt execution chain."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from budobugs.core.io import atomic_write_json
from budobugs.models import Engagement
from budobugs.proxy.base import ProxyBackend, ProxyUnavailable
from budobugs.proxy.burp import BurpMcpAdapter
from budobugs.proxy.caido import CaidoClient
from budobugs.proxy.direct import DirectProxyBackend
from budobugs.proxy.har import HarProxyBackend
from budobugs.proxy.zap import ZapClient
from budobugs.storage.secrets import SecretStore


@dataclass(frozen=True, slots=True)
class ProxySelection:
    backend: ProxyBackend
    requested: str
    selected: str
    ready: bool
    detail: str
    attempted: tuple[dict[str, object], ...]
    receipt_path: str


class ProxyBackendFactory:
    """Choose an explicitly requested backend or an actually-ready configured one."""

    NAMES = {"auto", "direct", "har", "caido", "burp", "zap"}

    def __init__(self, repository_root: Path, runtime_home: Path) -> None:
        self.repository_root = repository_root.resolve()
        self.runtime_home = runtime_home.resolve()

    async def select(
        self,
        engagement: Engagement,
        *,
        requested: str,
        receipt_path: Path,
        har_path: Path | None = None,
    ) -> ProxySelection:
        requested = requested.lower()
        if requested not in self.NAMES:
            raise ValueError(f"unsupported proxy backend: {requested}")
        attempts: list[dict[str, object]] = []
        names = [requested] if requested != "auto" else self._auto_candidates(har_path)
        selected_backend: ProxyBackend | None = None
        selected_detail = ""
        for name in names:
            try:
                backend = self._construct(name, engagement, har_path)
                ready, detail = await backend.health()
            except (OSError, RuntimeError, ValueError, ProxyUnavailable, json.JSONDecodeError) as exc:
                attempts.append({"backend": name, "ready": False, "detail": str(exc)[:500]})
                continue
            attempts.append({"backend": name, "ready": ready, "detail": detail[:500]})
            if ready:
                selected_backend = backend
                selected_detail = detail
                break
        if selected_backend is None:
            if requested == "auto":
                selected_backend = DirectProxyBackend()
                selected_detail = "automatic selection fell back to the controlled direct backend"
                attempts.append({"backend": "direct", "ready": True, "detail": selected_detail})
            else:
                raise ProxyUnavailable(f"requested proxy backend is unavailable: {attempts}")
        receipt = {
            "status": "PASS",
            "requested": requested,
            "selected": selected_backend.name,
            "capabilities": {
                "history": selected_backend.capabilities.history,
                "replay": selected_backend.capabilities.replay,
                "http2": selected_backend.capabilities.http2,
                "active_automation": selected_backend.capabilities.active_automation,
                "export": selected_backend.capabilities.export,
            },
            "detail": selected_detail,
            "attempted": attempts,
        }
        atomic_write_json(receipt_path, receipt)
        return ProxySelection(
            backend=selected_backend,
            requested=requested,
            selected=selected_backend.name,
            ready=True,
            detail=selected_detail,
            attempted=tuple(attempts),
            receipt_path=str(receipt_path),
        )

    def _auto_candidates(self, har_path: Path | None) -> list[str]:
        names: list[str] = []
        if (self.runtime_home / "proxy" / "caido.json").is_file():
            names.append("caido")
        if os.environ.get("BUDOBUGS_BURP_MCP_URL"):
            names.append("burp")
        if os.environ.get("BUDOBUGS_ZAP_URL"):
            names.append("zap")
        if har_path is not None:
            names.append("har")
        names.append("direct")
        return names

    def _construct(
        self,
        name: str,
        engagement: Engagement,
        har_path: Path | None,
    ) -> ProxyBackend:
        if name == "direct":
            return DirectProxyBackend()
        if name == "har":
            if har_path is None:
                raise ValueError("HAR backend requires --har")
            return HarProxyBackend(har_path.resolve(), engagement)
        if name == "burp":
            url = os.environ.get("BUDOBUGS_BURP_MCP_URL", "http://127.0.0.1:9876/mcp")
            return BurpMcpAdapter(url)
        if name == "zap":
            url = os.environ.get("BUDOBUGS_ZAP_URL", "http://127.0.0.1:8090")
            return ZapClient(url, api_key=os.environ.get("BUDOBUGS_ZAP_API_KEY"))
        if name == "caido":
            path = self.runtime_home / "proxy" / "caido.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            reference = str(payload["pat_reference"])
            pat = SecretStore(self.runtime_home / "secrets" / "fallback.json").get(reference)
            if not pat:
                raise ProxyUnavailable("Caido PAT reference cannot be resolved")
            return CaidoClient(
                str(payload["url"]),
                pat,
                repository_root=self.repository_root,
            )
        raise ValueError(f"cannot construct proxy backend: {name}")
