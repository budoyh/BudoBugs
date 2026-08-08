"""Opaque identifiers for auditable records."""

from __future__ import annotations

from uuid import uuid4


def new_id(prefix: str) -> str:
    """Return a compact non-secret identifier with a stable type prefix."""

    return f"{prefix}-{uuid4().hex[:20]}"
