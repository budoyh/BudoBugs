"""Fixed-map TCP ingress for exposing isolated lab services on host loopback."""

from __future__ import annotations

import asyncio
import os


def parse_mapping(value: str) -> dict[int, tuple[str, int]]:
    mapping: dict[int, tuple[str, int]] = {}
    for raw_item in value.replace("\n", "").split(","):
        item = raw_item.strip()
        if not item:
            continue
        listen_text, upstream = item.split("=", 1)
        host, port_text = upstream.rsplit(":", 1)
        listen_port = int(listen_text)
        upstream_port = int(port_text)
        if not host or not 1024 <= listen_port <= 65535 or not 1 <= upstream_port <= 65535:
            raise ValueError(f"invalid proxy mapping: {item!r}")
        mapping[listen_port] = (host, upstream_port)
    if not mapping:
        raise ValueError("BUDO_PROXY_MAP must contain at least one mapping")
    return mapping


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while chunk := await reader.read(65536):
            writer.write(chunk)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def forward(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_host: str,
    upstream_port: int,
) -> None:
    try:
        server_reader, server_writer = await asyncio.open_connection(upstream_host, upstream_port)
    except (TimeoutError, OSError):
        client_writer.close()
        await client_writer.wait_closed()
        return
    await asyncio.gather(
        pipe(client_reader, server_writer),
        pipe(server_reader, client_writer),
    )


async def main() -> None:
    mapping = parse_mapping(os.environ["BUDO_PROXY_MAP"])
    servers = []
    for listen_port, (host, port) in mapping.items():
        servers.append(
            await asyncio.start_server(
                lambda reader, writer, h=host, p=port: forward(reader, writer, h, p),
                host="0.0.0.0",
                port=listen_port,
            )
        )
    async with asyncio.TaskGroup() as group:
        for server in servers:
            group.create_task(server.serve_forever())


if __name__ == "__main__":
    asyncio.run(main())
