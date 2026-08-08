from __future__ import annotations

from pathlib import Path

import pytest
from tests.conftest import make_exchange

from budobugs.proxy.direct import DirectProxyBackend
from budobugs.traffic.normalization import normalize_exchange


@pytest.mark.asyncio
async def test_direct_proxy_history_filters_gets_and_exports(tmp_path: Path, lab_engagement) -> None:
    backend = DirectProxyBackend()
    exchange = normalize_exchange(make_exchange(response='{"value":1}', exchange_id="exchange-001"))
    backend._history[exchange.exchange_id] = exchange
    ready, detail = await backend.health()
    assert ready
    assert "ready" in detail
    matches = await backend.search(lab_engagement, host="127.0.0.1", path="objects", method="get", status=200)
    assert matches == [exchange]
    assert await backend.get(exchange.exchange_id) == exchange
    assert (await backend.export(tmp_path / "history.json")).is_file()
    with pytest.raises(KeyError, match="unknown exchange"):
        await backend.get("missing")
