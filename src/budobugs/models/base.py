"""Shared Pydantic behavior and time helpers."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict


def utc_now() -> datetime:
    """Return an aware UTC timestamp."""

    return datetime.now(UTC)


class BudoModel(BaseModel):
    """Reject unknown fields and validate assignments across all contracts."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        validate_default=True,
        ser_json_timedelta="iso8601",
    )
