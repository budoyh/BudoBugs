"""Deterministic HTTP preprocessing before model-assisted analysis."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from budobugs.core.io import sha256_bytes
from budobugs.core.redaction import redact_headers, redact_text
from budobugs.models import HttpExchange

_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_INTEGER = re.compile(r"^\d{1,18}$")
_TIMESTAMP = re.compile(r"^(?:1\d{9}|1\d{12}|20\d{2}-\d{2}-\d{2}(?:T[^/]+)?)$")
_RANDOM = re.compile(r"^[A-Za-z0-9_-]{20,}$")
_STATIC_SUFFIXES = {
    ".css",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".map",
    ".png",
    ".svg",
    ".ttf",
    ".webp",
    ".woff",
    ".woff2",
}


def canonicalize_url(url: str) -> str:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower().rstrip(".")
    default_port = (scheme == "http" and parsed.port == 80) or (scheme == "https" and parsed.port == 443)
    netloc = hostname
    if parsed.port and not default_port:
        netloc = f"{hostname}:{parsed.port}"
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)), doseq=True)
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    return urlunsplit((scheme, netloc, path, query, ""))


def path_template(url: str) -> str:
    path = urlsplit(url).path or "/"
    templated: list[str] = []
    for segment in path.split("/"):
        if _UUID.fullmatch(segment):
            templated.append("{uuid}")
        elif _INTEGER.fullmatch(segment):
            templated.append("{id}")
        elif _RANDOM.fullmatch(segment) and not segment.isalpha():
            templated.append("{token}")
        else:
            templated.append(segment)
    return "/".join(templated)


def is_static_asset(url: str, content_type: str | None = None) -> bool:
    path = urlsplit(url).path.lower()
    if any(path.endswith(suffix) for suffix in _STATIC_SUFFIXES):
        return True
    if content_type:
        lowered = content_type.lower()
        return lowered.startswith(("image/", "font/", "text/css"))
    return False


def classify_value(value: str, name: str = "") -> str:
    lowered = name.lower()
    if lowered in {"page", "page_size", "offset", "limit", "cursor"}:
        return "pagination"
    if any(token in lowered for token in ("token", "secret", "password", "authorization", "cookie")):
        return "secret"
    if _UUID.fullmatch(value):
        return "uuid"
    if _TIMESTAMP.fullmatch(value):
        return "timestamp"
    if _INTEGER.fullmatch(value) and any(token in lowered for token in ("id", "uid", "object")):
        return "id"
    if _RANDOM.fullmatch(value):
        return "random"
    return "stable"


def infer_json_schema(value: object) -> dict[str, object]:
    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    if isinstance(value, str):
        return {"type": "string"}
    if isinstance(value, list):
        schemas = [infer_json_schema(item) for item in value[:20]]
        unique = {json.dumps(item, sort_keys=True) for item in schemas}
        items: dict[str, object]
        if len(unique) == 1 and schemas:
            items = schemas[0]
        elif schemas:
            items = {"anyOf": [json.loads(item) for item in sorted(unique)]}
        else:
            items = {}
        return {"type": "array", "items": items}
    if isinstance(value, dict):
        properties = {str(key): infer_json_schema(item) for key, item in sorted(value.items())}
        return {"type": "object", "properties": properties, "required": sorted(properties)}
    return {"type": "unknown"}


def extract_graphql_operation(body: str | None) -> tuple[str | None, str | None]:
    if not body:
        return None, None
    query = body
    try:
        decoded = json.loads(body)
        if isinstance(decoded, dict):
            operation_name = decoded.get("operationName")
            query = str(decoded.get("query", ""))
            if isinstance(operation_name, str):
                return operation_name, _graphql_kind(query)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)", query)
    return (match.group(2), match.group(1)) if match else (None, _graphql_kind(query))


def _graphql_kind(query: str) -> str | None:
    match = re.search(r"\b(query|mutation|subscription)\b", query)
    return match.group(1) if match else None


def normalize_exchange(exchange: HttpExchange) -> HttpExchange:
    """Canonicalize and redact an exchange while hashing the original representation."""

    request_material = json.dumps(
        {
            "method": exchange.method,
            "url": canonicalize_url(exchange.url),
            "headers": sorted(exchange.request_headers.items()),
            "body": exchange.request_body,
        },
        ensure_ascii=False,
        sort_keys=True,
    ).encode("utf-8")
    response_material = json.dumps(
        {
            "status": exchange.response_status,
            "headers": sorted(exchange.response_headers.items()),
            "body": exchange.response_body,
        },
        ensure_ascii=False,
        sort_keys=True,
    ).encode("utf-8")
    update = {
        "url": canonicalize_url(exchange.url),
        "request_headers": redact_headers(exchange.request_headers),
        "response_headers": redact_headers(exchange.response_headers),
        "request_body": redact_text(exchange.request_body),
        "response_body": redact_text(exchange.response_body),
        "request_hash": sha256_bytes(request_material),
        "response_hash": sha256_bytes(response_material),
        "untrusted_content": True,
    }
    return exchange.model_copy(update=update)


def normalized_json_structure(body: str | None) -> object:
    if body is None:
        return None
    try:
        return _drop_volatile(json.loads(body))
    except json.JSONDecodeError:
        return re.sub(r"\b\d{10,13}\b", "{timestamp}", body)


def _drop_volatile(value: object) -> object:
    if isinstance(value, dict):
        return {
            str(key): _drop_volatile(item)
            for key, item in sorted(value.items())
            if str(key).lower() not in {"timestamp", "requestid", "request_id", "traceid", "trace_id"}
        }
    if isinstance(value, list):
        return [_drop_volatile(item) for item in value]
    return value


def structure_similarity(first: str | None, second: str | None) -> float:
    left = normalized_json_structure(first)
    right = normalized_json_structure(second)
    if left == right:
        return 1.0
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        keys = set(left) | set(right)
        return 0.0 if not keys else len(set(left) & set(right)) / len(keys)
    return 0.0
