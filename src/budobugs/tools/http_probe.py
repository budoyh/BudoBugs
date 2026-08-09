"""Small, bounded HTTP root probe for the registered tool runner."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

import httpx

from budobugs.core.redaction import redact_headers, redact_text

_HEADER_ALLOWLIST = ("content-type", "location", "server", "x-powered-by")
_TIMEOUT_SECONDS = 10.0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Perform one bounded GET request to an injected HTTP URL.")
    parser.add_argument("--url", required=True, help="HTTP(S) URL injected by the registered tool wrapper")
    return parser


def _safe_headers(headers: httpx.Headers) -> dict[str, str]:
    selected = {name: headers[name] for name in _HEADER_ALLOWLIST if name in headers}
    return {name: value[:512] for name, value in redact_headers(selected).items()}


def main(argv: Sequence[str] | None = None) -> int:
    """Emit bounded JSON without following redirects or retaining response bodies."""

    args = _parser().parse_args(argv)
    url = httpx.URL(args.url)
    if url.scheme not in {"http", "https"} or not url.host or url.username or url.password:
        _parser().error("--url must be an absolute credential-free HTTP(S) URL")
    try:
        with httpx.Client(timeout=_TIMEOUT_SECONDS, follow_redirects=False, trust_env=False) as client:
            response = client.get(url)
    except httpx.HTTPError as exc:
        error = redact_text(str(exc)) or ""
        sys.stdout.write(json.dumps({"url": redact_text(str(url)), "error": error[:512]}, sort_keys=True) + "\n")
        return 1
    payload = {
        "url": redact_text(str(response.url)),
        "status_code": response.status_code,
        "redirect_not_followed": 300 <= response.status_code < 400,
        "headers": _safe_headers(response.headers),
    }
    sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - module entry point
    sys.exit(main())
