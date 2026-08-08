"""Keyring-first secret references with an explicit private-file fallback."""

from __future__ import annotations

import json
import os
import re
from contextlib import suppress
from pathlib import Path

import keyring

from budobugs.core.io import atomic_write_json


class SecretStore:
    """Store credentials out of engagement YAML and ordinary logs."""

    def __init__(self, fallback_path: Path, *, allow_file_fallback: bool = False) -> None:
        self.fallback_path = fallback_path
        self.allow_file_fallback = allow_file_fallback

    @staticmethod
    def _service(namespace: str) -> str:
        return f"budobugs:{namespace}"

    def set(self, namespace: str, name: str, value: str) -> str:
        try:
            keyring.set_password(self._service(namespace), name, value)
            return f"keyring://{namespace}/{name}"
        except keyring.errors.KeyringError:
            if not self.allow_file_fallback:
                raise RuntimeError("system keyring unavailable and private-file fallback is disabled") from None
            payload = self._read_fallback()
            payload[f"{namespace}/{name}"] = value
            atomic_write_json(self.fallback_path, payload)
            with suppress(OSError):
                os.chmod(self.fallback_path, 0o600)
            return f"private-file://{namespace}/{name}"

    def get(self, reference: str) -> str | None:
        scheme, separator, location = reference.partition("://")
        if not separator:
            raise ValueError("invalid secret reference")
        if scheme == "env":
            if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", location):
                raise ValueError("invalid environment secret reference")
            return os.environ.get(location)
        if "/" not in location:
            raise ValueError("invalid secret reference")
        namespace, name = location.split("/", 1)
        if scheme == "keyring":
            return keyring.get_password(self._service(namespace), name)
        if scheme == "private-file" and self.allow_file_fallback:
            return self._read_fallback().get(f"{namespace}/{name}")
        raise ValueError("unsupported or disabled secret reference scheme")

    def _read_fallback(self) -> dict[str, str]:
        if not self.fallback_path.exists():
            return {}
        payload = json.loads(self.fallback_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in payload.items()
        ):
            raise ValueError("invalid private secret fallback file")
        return payload
