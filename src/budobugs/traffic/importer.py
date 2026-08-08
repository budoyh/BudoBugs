"""Safe importers for HAR and sanitized fixture traffic."""

from __future__ import annotations

import json
from pathlib import Path

from budobugs.core.identifiers import new_id
from budobugs.core.policy import require_allowed, target_allowed
from budobugs.models import Engagement, HttpExchange
from budobugs.traffic.normalization import normalize_exchange


class TrafficImportError(ValueError):
    pass


def import_har(path: Path, engagement: Engagement, *, max_bytes: int = 100 * 1024 * 1024) -> list[HttpExchange]:
    if not path.is_file():
        raise TrafficImportError(f"HAR not found: {path}")
    if path.stat().st_size > max_bytes:
        raise TrafficImportError("HAR exceeds configured size limit")
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
        entries = payload["log"]["entries"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise TrafficImportError(f"invalid HAR: {exc}") from exc
    if not isinstance(entries, list):
        raise TrafficImportError("HAR entries must be a list")
    exchanges: list[HttpExchange] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request", {})
        response = entry.get("response", {})
        if not isinstance(request, dict) or not isinstance(response, dict):
            continue
        url = str(request.get("url", ""))
        require_allowed(target_allowed(engagement, url))
        request_headers = _headers(request.get("headers"))
        response_headers = _headers(response.get("headers"))
        request_body = _nested_text(request.get("postData"))
        response_body = _nested_text(response.get("content"))
        exchange = HttpExchange(
            exchange_id=new_id("http"),
            engagement_id=engagement.engagement_id,
            method=str(request.get("method", "GET")).upper(),
            url=url,
            request_headers=request_headers,
            request_body=request_body,
            response_status=int(response.get("status", 0)),
            response_headers=response_headers,
            response_body=response_body,
            elapsed_ms=float(entry.get("time", 0.0)),
            source="har",
        )
        exchanges.append(normalize_exchange(exchange))
    return exchanges


def _headers(value: object) -> dict[str, str]:
    if not isinstance(value, list):
        return {}
    result: dict[str, str] = {}
    for item in value:
        if isinstance(item, dict) and "name" in item:
            result[str(item["name"])] = str(item.get("value", ""))
    return result


def _nested_text(value: object) -> str | None:
    if isinstance(value, dict) and isinstance(value.get("text"), str):
        return str(value["text"])
    return None
