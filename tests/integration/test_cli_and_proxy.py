from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from budobugs.cli.app import app
from budobugs.mcp.doctor import probe_stdio
from budobugs.proxy.burp import BurpMcpAdapter
from budobugs.proxy.caido import CaidoClient
from budobugs.proxy.zap import ZapClient


def test_cli_read_only_smoke_commands(repository_root, monkeypatch) -> None:
    monkeypatch.chdir(repository_root)
    runner = CliRunner()
    result = runner.invoke(app, ["version", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["name"] == "budobugs"
    tools = runner.invoke(app, ["tools", "list", "--profile", "core", "--json"])
    assert tools.exit_code == 0
    assert json.loads(tools.stdout)


def test_hunt_dry_run_makes_no_run_or_cost_records(service, lab_engagement, monkeypatch) -> None:
    service.save_engagement(lab_engagement)
    monkeypatch.setattr("budobugs.cli.app._service", lambda: service)
    result = CliRunner().invoke(app, ["hunt", lab_engagement.engagement_id, "--dry-run", "--json"])
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["status"] == "DRY_RUN"
    assert payload["active_hunt_or_target_network_performed"] is False
    assert payload["planned_model_call_upper_bound"] == 0
    assert service.latest_run(lab_engagement.engagement_id) is None
    assert service.list_costs() == []


async def test_proxy_adapters_report_unavailable_local_endpoints_truthfully() -> None:
    caido_ready, caido_detail = await CaidoClient("http://127.0.0.1:1/graphql", "fixture", timeout=0.1).health()
    zap_ready, zap_detail = await ZapClient("http://127.0.0.1:1", timeout=0.1).health()
    burp_ready, burp_detail = await BurpMcpAdapter("http://127.0.0.1:1/mcp").health()
    assert not caido_ready
    assert any(label in caido_detail.lower() for label in ("failed", "timed out", "not installed"))
    assert not zap_ready
    assert "connection failed" in zap_detail.lower()
    assert not burp_ready
    assert burp_detail


async def test_mcp_stdio_doctor_performs_initialize_and_tool_discovery(repository_root: Path, tmp_path: Path) -> None:
    result = await probe_stdio(repository_root, tmp_path / "runtime")
    assert result["status"] == "PASS"
    assert result["transport"] == "stdio"
    assert result["server"] == "budobugs"
    assert set(result["tools"]) >= {"engagement_show", "status", "traffic_search", "finding_show"}
