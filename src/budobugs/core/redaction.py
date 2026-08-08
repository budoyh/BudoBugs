"""Deterministic secret and PII redaction for logs and public artifacts."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from functools import partial

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    (
        "bearer",
        re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
    ),
    (
        "key",
        re.compile(
            r"\b(?:sk|gho|ghp|pat|xox[baprs]|AKIA)[-_A-Za-z0-9]{12,}\b",
            re.IGNORECASE,
        ),
    ),
    ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)),
    # Exclude alphanumeric boundaries so digit windows inside hashes, UUID-like
    # identifiers and other opaque tokens are not mistaken for phone numbers.
    ("phone", re.compile(r"(?<![A-Za-z0-9])(?:\+?86[- ]?)?1[3-9]\d{9}(?![A-Za-z0-9])")),
    # Require token boundaries so an 18-digit window inside a SHA-256 or opaque ID
    # is not misclassified as a Chinese resident identity number.
    ("cn-id", re.compile(r"(?<![A-Za-z0-9])\d{17}[0-9Xx](?![A-Za-z0-9])")),
)

_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)(?P<prefix>\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|secret)"
    r"\b[\"']?\s*[:=]\s*[\"']?)(?P<value>(?!<REDACTED)[A-Za-z0-9._~+/=-]{12,})"
)


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:10]


def _replacement(kind: str, value: str) -> str:
    return f"<REDACTED:{kind}:{_fingerprint(value)}>"


def _replace_match(match: re.Match[str], kind: str) -> str:
    return _replacement(kind, match.group(0))


def _replace_credential_assignment(match: re.Match[str]) -> str:
    return f"{match.group('prefix')}{_replacement('credential', match.group('value'))}"


def redact_text(text: str | None) -> str | None:
    """Redact common credentials and PII while retaining correlation fingerprints."""

    if text is None:
        return None
    result = _CREDENTIAL_ASSIGNMENT.sub(_replace_credential_assignment, text)
    for kind, pattern in _PATTERNS:
        result = pattern.sub(partial(_replace_match, kind=kind), result)
    return result


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in SENSITIVE_HEADER_NAMES:
            redacted[name] = _replacement("header", value)
        else:
            redacted[name] = redact_text(value) or ""
    return redacted


def contains_unredacted_secret(text: str) -> list[str]:
    """Return secret/PII pattern labels still present in a candidate export."""

    labels = [kind for kind, pattern in _PATTERNS if pattern.search(text)]
    if _CREDENTIAL_ASSIGNMENT.search(text):
        labels.append("credential")
    return labels
