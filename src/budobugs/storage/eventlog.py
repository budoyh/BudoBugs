"""Append-only JSONL audit log with a verifiable hash chain."""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from budobugs.models import AuditEvent

_GENESIS = "0" * 64


class EventLogIntegrityError(ValueError):
    """Raised when an immutable event chain no longer verifies."""


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class EventLog:
    """Append and replay audit events without trusting materialized database state."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        last = _GENESIS
        if not self.path.exists():
            return last
        for envelope in self.replay(verify=True):
            last = str(envelope["event_hash"])
        return last

    def append(self, event: AuditEvent) -> dict[str, Any]:
        with self._lock:
            payload = event.model_dump(mode="json")
            material = {"previous_hash": self._last_hash, "event": payload}
            event_hash = hashlib.sha256(_canonical(material)).hexdigest()
            envelope = {**material, "event_hash": event_hash}
            line = json.dumps(envelope, ensure_ascii=False, sort_keys=True) + "\n"
            descriptor = os.open(self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                os.write(descriptor, line.encode("utf-8"))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self._last_hash = event_hash
            return envelope

    def replay(self, *, verify: bool = True) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        previous = _GENESIS
        with self.path.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                try:
                    envelope = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise EventLogIntegrityError(f"invalid JSONL at line {line_number}") from exc
                if verify:
                    if envelope.get("previous_hash") != previous:
                        raise EventLogIntegrityError(f"broken event chain at line {line_number}")
                    material = {
                        "previous_hash": envelope.get("previous_hash"),
                        "event": envelope.get("event"),
                    }
                    expected = hashlib.sha256(_canonical(material)).hexdigest()
                    if envelope.get("event_hash") != expected:
                        raise EventLogIntegrityError(f"event hash mismatch at line {line_number}")
                previous = str(envelope.get("event_hash"))
                yield envelope
