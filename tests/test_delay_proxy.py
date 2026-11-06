"""
The delaying link of the multi-host test (integration_tests/delay_proxy.py): what crosses it
arrives intact, in order, late by the delay in each direction, and jitter never reorders it.
"""

import asyncio
import time

from integration_tests.delay_proxy import Link, serve


async def _echo_server():
    async def echo(reader, writer):
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def test_a_round_trip_is_delayed_both_ways_and_kept_in_order():
    echo, echo_port = await _echo_server()
    proxy = await serve("127.0.0.1:0", f"127.0.0.1:{echo_port}", Link(0.05, 0.02, None))
    port = proxy.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    started = time.monotonic()
    writer.write(b"ping")
    await writer.drain()
    assert await reader.readexactly(4) == b"ping"
    assert time.monotonic() - started >= 0.06          # (≥ 2 × (50 − 20) ms)

    chunks = [bytes([i]) * 1000 for i in range(50)]
    for c in chunks:                                   # (separate writes, jittered separately)
        writer.write(c)
        await writer.drain()
    assert await reader.readexactly(50_000) == b"".join(chunks)
    writer.close()
    proxy.close()
    echo.close()


async def test_a_rate_cap_paces_what_crosses():
    echo, echo_port = await _echo_server()
    proxy = await serve("127.0.0.1:0", f"127.0.0.1:{echo_port}", Link(0.0, 0.0, mbps=8.0))
    port = proxy.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    started = time.monotonic()
    writer.write(b"x" * 200_000)                       # (1.6 Mbit at 8 Mbit/s, each way)
    await writer.drain()
    assert len(await reader.readexactly(200_000)) == 200_000
    assert time.monotonic() - started >= 0.15
    writer.close()
    proxy.close()
    echo.close()
