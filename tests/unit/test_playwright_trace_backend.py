from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from budobugs.proxy.playwright_trace import PlaywrightTraceBackend


def _write_har(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "method": "GET",
                                "url": "http://127.0.0.1:8765/api/objects/1",
                                "headers": [],
                            },
                            "response": {
                                "status": 200,
                                "headers": [{"name": "content-type", "value": "application/json"}],
                                "content": {"text": '{"id":"1"}'},
                            },
                            "time": 5,
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )


@pytest.mark.asyncio
async def test_playwright_trace_backend_exposes_har_history_and_annotations(tmp_path: Path, lab_engagement) -> None:
    trace = tmp_path / "trace.zip"
    with zipfile.ZipFile(trace, "w") as archive:
        archive.writestr("trace.trace", "fixture")
    har = tmp_path / "traffic.har"
    _write_har(har)
    backend = PlaywrightTraceBackend(trace, har, lab_engagement)
    ready, detail = await backend.health()
    assert ready
    assert "loaded 1 HAR exchanges" in detail
    matches = await backend.search(lab_engagement, method="GET", status=200, content_type="json")
    assert len(matches) == 1
    exchange = matches[0]
    assert await backend.get(exchange.exchange_id) == exchange
    assert await backend.mark_candidate(exchange.exchange_id, "authorization") == {
        "exchange_id": exchange.exchange_id,
        "label": "authorization",
    }
    associated = await backend.associate(exchange.exchange_id, account_alias="alice", role_id="member")
    assert (associated.account_alias, associated.role_id) == ("alice", "member")
    reference = await backend.evidence_reference(exchange.exchange_id)
    assert reference["request_sha256"] is not None
    exported = await backend.export(tmp_path / "export" / "browser.zip")
    with zipfile.ZipFile(exported) as archive:
        assert set(archive.namelist()) == {"trace.zip", "traffic.har"}


@pytest.mark.asyncio
async def test_playwright_trace_backend_rejects_invalid_trace(tmp_path: Path, lab_engagement) -> None:
    trace = tmp_path / "trace.zip"
    trace.write_text("not a zip", encoding="utf-8")
    har = tmp_path / "traffic.har"
    _write_har(har)
    ready, detail = await PlaywrightTraceBackend(trace, har, lab_engagement).health()
    assert not ready
    assert "invalid" in detail
