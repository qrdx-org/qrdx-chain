"""
A TCP relay that delays what crosses it, both ways: the network link in front of one node in the
multi-host test (integration_tests/multihost.py).

Latency is added here, in user space, because the kernels this test runs on may lack netem
(WSL2's does). Each chunk read from one side is written to the other ``delay`` (± ``jitter``)
after it arrived, never before a chunk that arrived earlier: jitter varies the delay, it never
reorders a stream. ``--mbps`` also caps each direction's rate.

    python -m integration_tests.delay_proxy --delay-ms 25 --jitter-ms 5 \\
        0.0.0.0:3407=172.31.0.10:3407 0.0.0.0:13407=172.31.0.10:13407
"""

import argparse
import asyncio
import random
import time
from typing import List, Optional, Tuple

CHUNK = 256 * 1024


class Link:
    def __init__(self, delay: float, jitter: float, mbps: Optional[float], seed: int = 0):
        self.delay = delay
        self.jitter = jitter
        self.bytes_per_second = mbps * 125_000 if mbps else None
        self._rng = random.Random(seed)

    def due(self) -> float:
        return time.monotonic() + max(0.0, self.delay + self._rng.uniform(-self.jitter, self.jitter))

    async def carry(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Everything ``reader`` gives, to ``writer``, late; then half-close ``writer``."""
        queue: "asyncio.Queue[Tuple[float, bytes]]" = asyncio.Queue()

        async def read() -> None:
            while True:
                try:
                    data = await reader.read(CHUNK)
                except (ConnectionError, OSError):
                    data = b""
                await queue.put((self.due(), data))
                if not data:
                    return

        async def write() -> None:
            last = 0.0
            sent_until = time.monotonic()
            while True:
                due, data = await queue.get()
                due = max(due, last)  # (in order)
                last = due
                wait = due - time.monotonic()
                if wait > 0:
                    await asyncio.sleep(wait)
                if not data:
                    try:
                        writer.write_eof()
                    except (OSError, RuntimeError):
                        pass
                    return
                if self.bytes_per_second:
                    sent_until = max(sent_until, time.monotonic()) + len(data) / self.bytes_per_second
                    pause = sent_until - time.monotonic()
                    if pause > 0:
                        await asyncio.sleep(pause)
                try:
                    writer.write(data)
                    await writer.drain()
                except (ConnectionError, OSError):
                    return

        await asyncio.gather(read(), write())


async def serve(listen: str, target: str, link: Link) -> asyncio.AbstractServer:
    host, port = listen.rsplit(":", 1)
    to_host, to_port = target.rsplit(":", 1)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            up_reader, up_writer = await asyncio.open_connection(to_host, int(to_port))
        except OSError:
            writer.close()
            return
        try:
            await asyncio.gather(link.carry(reader, up_writer), link.carry(up_reader, writer))
        finally:
            for w in (writer, up_writer):
                try:
                    w.close()
                except Exception:
                    pass

    return await asyncio.start_server(handle, host, int(port), limit=CHUNK)


async def main(argv: Optional[List[str]] = None) -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--delay-ms", type=float, default=25.0, help="one-way delay")
    p.add_argument("--jitter-ms", type=float, default=0.0)
    p.add_argument("--mbps", type=float, default=None, help="each direction's rate cap")
    p.add_argument("routes", nargs="+", help="listen_host:port=target_host:port")
    args = p.parse_args(argv)
    link = Link(args.delay_ms / 1000, args.jitter_ms / 1000, args.mbps)
    servers = []
    for route in args.routes:
        listen, target = route.split("=", 1)
        servers.append(await serve(listen, target, link))
    print(f"delaying {', '.join(args.routes)} by {args.delay_ms} ms ± {args.jitter_ms}", flush=True)
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    try:
        import uvloop

        uvloop.install()
    except ImportError:
        pass
    asyncio.run(main())
