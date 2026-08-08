"""Protocol-level stdio health probe for the local BudoBugs MCP server."""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path
from typing import TextIO, cast

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def probe_stdio(root: Path, runtime_home: Path) -> dict[str, object]:
    environment = {
        name: value
        for name, value in os.environ.items()
        if name.upper() in {"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME"}
    }
    environment["BUDOBUGS_HOME"] = str(runtime_home)
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "budobugs.mcp.server"],
        env=environment,
        cwd=root,
    )
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as errors:
        try:
            async with asyncio.timeout(20):
                async with stdio_client(parameters, errlog=cast(TextIO, errors)) as streams:
                    async with ClientSession(*streams) as session:
                        initialization = await session.initialize()
                        tools = await session.list_tools()
        except (TimeoutError, OSError, RuntimeError, ExceptionGroup) as exc:
            errors.seek(0)
            return {
                "status": "FAIL",
                "transport": "stdio",
                "error": str(exc),
                "stderr": errors.read()[-500:],
            }
    names = sorted(item.name for item in tools.tools)
    required = {"engagement_show", "status", "traffic_search", "finding_show"}
    missing = sorted(required - set(names))
    if missing:
        return {"status": "FAIL", "transport": "stdio", "missing_tools": missing, "tools": names}
    return {
        "status": "PASS",
        "transport": "stdio",
        "server": initialization.serverInfo.name,
        "protocol_version": initialization.protocolVersion,
        "tools": names,
        "bind": "no network listener",
    }
