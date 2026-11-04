"""
Throughput under load (docs/MAINNET_READINESS.md §4, "Performance": "profile it under the soak's
load before optimizing anything").

Funds a set of fresh post-quantum accounts from validator 0, then sends valid exchange
transactions (QRDX transfers between those accounts) at a series of target rates. For each rate
it reports:

* what the chain executed per second while the load lasted (counted from the accounts' nonces
  on the chain, so a transaction that never ran, or ran only after the step, is not counted);
* inclusion latency (submission to receipt, sampled);
* the block rate, against the rate before any load.

The step where the executed rate stops following the target is the network's throughput on
this machine.

    python -m integration_tests.load --force [--rates 10,25,50,100] [--seconds 30]
        [--profile]    # py-spy the proposer of node 0 at each step (needs py-spy)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import statistics
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger("load")

QRDX_PER_ACCOUNT = "2"  # covers well over a thousand transfers' fees
IN_FLIGHT = 256  # requests at once, across the nodes
FUND_WAVE = 200  # funding transfers in flight (below the mempool's 256 a sender)


@dataclass
class Step:
    target: float
    seconds: float
    sent: int = 0
    refused: int = 0
    executed: int = 0
    latencies: List[float] = field(default_factory=list)
    blocks_per_s: float = 0.0
    errors: Dict[str, int] = field(default_factory=dict)

    def line(self) -> str:
        lat = sorted(self.latencies)
        p50 = statistics.median(lat) if lat else float("nan")
        p95 = lat[int(0.95 * (len(lat) - 1))] if lat else float("nan")
        return (
            f"target {self.target:6.1f}/s  sent {self.sent / self.seconds:6.1f}/s  "
            f"executed {self.executed / self.seconds:6.1f}/s  refused {self.refused}  "
            f"latency p50 {p50:5.2f}s p95 {p95:5.2f}s  blocks {self.blocks_per_s:4.2f}/s"
        )


TRANSFER_AMOUNT = "0.000001"
# Transactions one JSON-RPC request carries (the node's MAX_BATCH_SIZE), and how often the
# generator sends what has come due. One request a transaction capped one Python process near a
# thousand a second; a hundred to a request is a few dozen requests a second at 4,000.
SEND_BATCH = 100
SEND_TICK = 0.02


class Account:
    def __init__(self, chain_id: int):
        from qrdx.crypto.pq.dilithium import PQPrivateKey

        self.key = PQPrivateKey.generate()
        self.address = self.key.public_key.to_address()
        self.nonce = 0
        self.chain_id = chain_id


def _transfer(chain_id: int, sender: str, nonce: int, to: str):
    from qrdx.exchange import ExchangeOpType, ExchangeTransaction
    from qrdx.exchange.transactions import EXCHANGE_GAS_COSTS

    return ExchangeTransaction(
        op_type=ExchangeOpType.TOKEN_TRANSFER,
        sender=sender,
        nonce=nonce,
        params={"token_address": "QRDX", "to": to, "amount": TRANSFER_AMOUNT},
        # What the operation costs. A block's gas and the base fee count the gas a
        # transaction declares: declaring five times the cost made blocks look five times
        # fuller, so the base fee rose past the generator's bid at a fifth of the capacity.
        gas_limit=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_TRANSFER],
        gas_price=10**9,
        chain_id=chain_id,
    )


def _sign_account(job) -> List[dict]:
    """One account's transfers for a step, signed (in a worker process): ``(secret hex, public
    hex, chain id, sender, [(nonce, recipient)])``."""
    from qrdx.crypto.pq.dilithium import PQPrivateKey

    secret, public, chain_id, sender, entries = job
    key = PQPrivateKey.from_hex(secret, public)
    public_bytes = key.public_key.to_bytes()
    out = []
    for nonce, to in entries:
        t = _transfer(chain_id, sender, nonce, to)
        t.public_key = public_bytes
        t.signature = key.sign(t.signing_bytes()).to_bytes()
        out.append(t.to_dict())
    return out


class Load:
    def __init__(self, urls: List[str], funder: dict):
        self.urls = urls
        self.funder = funder
        # At most IN_FLIGHT requests at once. httpcore matches each queued request to the pool's
        # connections by scanning both, so thousands queued on a large pool stalled the generator
        # itself above about 300 sends a second.
        self.http = httpx.AsyncClient(
            timeout=60,
            limits=httpx.Limits(max_connections=IN_FLIGHT, max_keepalive_connections=IN_FLIGHT),
        )
        self._in_flight = asyncio.Semaphore(IN_FLIGHT)
        # Everything but the load (nonces, heights, receipts, funding) on a client of its own, so
        # that the generator's queue of sends does not delay what measures the chain: read behind
        # it, the nonces at the end of a step counted a backlog the chain cleared minutes later.
        self.probe = httpx.AsyncClient(timeout=60, limits=httpx.Limits(max_connections=64))

    @staticmethod
    async def _call(client: httpx.AsyncClient, url: str, method: str, params: list):
        r = await client.post(
            f"{url}/rpc", json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        )
        body = r.json()
        if "error" in body:
            raise RuntimeError(body["error"].get("message", str(body["error"])))
        return body["result"]

    async def rpc(self, url: str, method: str, params: list):
        return await self._call(self.probe, url, method, params)

    async def submit(self, url: str, tx: dict):
        """Send one transaction of the load: (its hash, when it actually went out)."""
        async with self._in_flight:
            sent_at = time.monotonic()
            return await self._call(self.http, url, "exchange_sendTransaction", [tx]), sent_at

    async def submit_batch(
        self, url: str, txs: List[dict]
    ) -> List[Tuple[Optional[str], Optional[str]]]:
        """Send transactions of the load in one JSON-RPC batch: (hash, None) or (None, error)
        for each, in order."""
        calls = [
            {"jsonrpc": "2.0", "id": i, "method": "exchange_sendTransaction", "params": [tx]}
            for i, tx in enumerate(txs)
        ]
        async with self._in_flight:
            r = await self.http.post(f"{url}/rpc", json=calls)
        body = r.json()
        if isinstance(body, dict):  # (the whole batch refused)
            message = (body.get("error") or {}).get("message", str(body))
            return [(None, message)] * len(txs)
        by_id = {reply.get("id"): reply for reply in body}
        out: List[Tuple[Optional[str], Optional[str]]] = []
        for i in range(len(txs)):
            reply = by_id.get(i) or {}
            if "error" in reply and reply["error"]:
                out.append((None, str(reply["error"].get("message", reply["error"]))))
            else:
                out.append((reply.get("result"), None))
        return out

    async def _latency(self, step: Step, url: str, tx_hash: str, sent_at: float) -> None:
        try:
            r = await self.receipt(url, tx_hash, timeout=90)
        except Exception:  # (the generator's own timeouts are not the chain's)
            r = None
        if r:
            step.latencies.append(time.monotonic() - sent_at)

    async def height(self, url: str) -> int:
        r = await self.probe.get(f"{url}/get_mining_info")
        return int(r.json()["result"]["last_block"]["id"])

    async def block_rate(self, seconds: float) -> float:
        h0 = await self.height(self.urls[0])
        await asyncio.sleep(seconds)
        return (await self.height(self.urls[0]) - h0) / seconds

    async def receipt(self, url: str, tx_hash: str, timeout: float = 60.0) -> Optional[dict]:
        # Polled at 0.1 s, then less often (to 1 s): a backlog multiplied the pollers, and at a
        # constant 0.1 s they saturated the generator's own loop, so its sends timed out before
        # reaching a node. A send that never arrived left a nonce gap that stranded the account.
        deadline = time.monotonic() + timeout
        wait = 0.1
        while time.monotonic() < deadline:
            r = await self.rpc(url, "exchange_getTransactionReceipt", [tx_hash])
            if r:
                return r
            await asyncio.sleep(wait)
            wait = min(1.0, wait * 1.5)
        return None

    async def fund(self, accounts: List[Account]) -> None:
        """QRDX to each account from validator 0, FUND_WAVE transfers in flight at a time (a
        sender's queue in the mempool is bounded)."""
        from qrdx.crypto.pq.dilithium import PQPrivateKey

        key = PQPrivateKey.from_hex(self.funder["private_key"], self.funder["public_key"])
        nonce = int(await self.rpc(self.urls[0], "exchange_getNonce", [self.funder["address"]]))
        chain_id = accounts[0].chain_id
        for wave in range(0, len(accounts), FUND_WAVE):
            await self._fund_wave(key, accounts[wave : wave + FUND_WAVE], nonce + wave, chain_id)

    async def _fund_wave(self, key, accounts: List[Account], nonce: int, chain_id: int) -> None:
        from qrdx.exchange import ExchangeOpType, ExchangeTransaction
        from qrdx.exchange.transactions import EXCHANGE_GAS_COSTS

        signed = []
        for i, acct in enumerate(accounts):
            t = ExchangeTransaction(
                op_type=ExchangeOpType.TOKEN_TRANSFER,
                sender=self.funder["address"],
                nonce=nonce + i,
                params={"token_address": "QRDX", "to": acct.address, "amount": QRDX_PER_ACCOUNT},
                gas_limit=EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_TRANSFER],
                gas_price=10**9,
                chain_id=chain_id,
            )
            t.public_key = key.public_key.to_bytes()
            t.signature = key.sign(t.signing_bytes()).to_bytes()
            signed.append(t.to_dict())
        hashes = []
        for at in range(0, len(signed), SEND_BATCH):
            for h, err in await self.submit_batch(self.urls[0], signed[at : at + SEND_BATCH]):
                if err is not None:
                    raise RuntimeError(f"funding refused: {err}")
                hashes.append(h)
        for h in hashes:
            r = await self.receipt(self.urls[0], h, timeout=180)
            if not r or not r.get("success"):
                raise RuntimeError(f"funding failed: {r}")

    async def nonces(self, accounts: List[Account]) -> List[int]:
        """Each account's nonce on the chain (node 0), read a hundred to a request."""

        async def part(chunk: List[Account]) -> List[int]:
            calls = [
                {"jsonrpc": "2.0", "id": i, "method": "exchange_getNonce", "params": [a.address]}
                for i, a in enumerate(chunk)
            ]
            for attempt in range(3):
                try:
                    r = await self.probe.post(f"{self.urls[0]}/rpc", json=calls)
                    by_id = {reply["id"]: reply for reply in r.json()}
                    return [int(by_id[i]["result"]) for i in range(len(chunk))]
                except Exception:
                    if attempt == 2:
                        raise
                    await asyncio.sleep(0.5)
            return [0] * len(chunk)

        parts = await asyncio.gather(
            *[part(accounts[at : at + SEND_BATCH]) for at in range(0, len(accounts), SEND_BATCH)]
        )
        return [n for p in parts for n in p]

    async def executed(self, accounts: List[Account]) -> int:
        return sum(await self.nonces(accounts))

    def presign(self, accounts: List[Account], count: int) -> List[dict]:
        """``count`` transfers, signed before the clock starts, across processes (signing in the
        send loop capped the generator near 225 a second): transfer ``k`` from account
        ``k mod n``, at its next nonce."""
        from concurrent.futures import ProcessPoolExecutor

        n = len(accounts)
        jobs = []
        for i, a in enumerate(accounts):
            ks = range(i, count, n)
            entries = [(a.nonce + j, accounts[(k + 1) % n].address) for j, k in enumerate(ks)]
            jobs.append((a.key.to_hex(), a.key.public_key.to_hex(), a.chain_id, a.address, entries))
        with ProcessPoolExecutor(max_workers=min(16, os.cpu_count() or 4)) as pool:
            signed = list(pool.map(_sign_account, jobs, chunksize=8))
        txs: List[Optional[dict]] = [None] * count
        for i, part in enumerate(signed):
            for j, tx in enumerate(part):
                txs[i + j * n] = tx
            accounts[i].nonce += len(part)
        return [t for t in txs if t is not None]

    async def step(self, accounts: List[Account], target: float, seconds: float) -> Step:
        step = Step(target, seconds)
        txs = self.presign(accounts, int(target * seconds))
        before = await self.executed(accounts)
        h0 = await self.height(self.urls[0])
        start = time.monotonic()
        k = 0

        async def send(url: str, batch: List[Tuple[int, dict]]):
            sent_at = time.monotonic()
            try:
                replies = await self.submit_batch(url, [tx for _, tx in batch])
            except Exception as e:
                step.refused += len(batch)
                why = f"{type(e).__name__}: {e}"[:60]
                step.errors[why] = step.errors.get(why, 0) + len(batch)
                return  # (those accounts' later nonces wait: resynced after the step)
            samples = []
            for (n, _tx), (h, err) in zip(batch, replies, strict=True):
                if err is not None:
                    step.refused += 1
                    step.errors[err[:60]] = step.errors.get(err[:60], 0) + 1
                    continue
                step.sent += 1
                if n % 50 == 0:  # a sample of the latencies
                    samples.append(h)
            for h in samples:
                pending.append(asyncio.create_task(self._latency(step, url, h, sent_at)))

        pending: List[asyncio.Task] = []
        # Each account's transfers go to one node (account i to node i mod 4), so they arrive in
        # nonce order; what has come due goes every SEND_TICK, a batch a node.
        nodes = len(self.urls)
        while k < len(txs) and time.monotonic() - start < seconds:
            due = min(len(txs), int((time.monotonic() - start) * target) + 1)
            by_node: Dict[int, List[Tuple[int, dict]]] = {}
            for n in range(k, due):
                by_node.setdefault((n % len(accounts)) % nodes, []).append((n, txs[n]))
            k = due
            for node, items in by_node.items():
                for at in range(0, len(items), SEND_BATCH):
                    pending.append(
                        asyncio.create_task(send(self.urls[node], items[at : at + SEND_BATCH]))
                    )
            await asyncio.sleep(SEND_TICK)
        # What the chain executed while the load lasted (and a second for what was sent last to
        # get its block). Counting only after the latency samples' receipts, up to 90 s later,
        # credited a backlog the chain took a minute to clear to the 20 s of the step.
        await asyncio.sleep(1)
        step.executed = await self.executed(accounts) - before
        step.blocks_per_s = (await self.height(self.urls[0]) - h0) / (time.monotonic() - start)
        await asyncio.gather(*pending)
        await asyncio.sleep(5)  # (the backlog clears before the next step)
        # resync the local nonces with the chain's for the next step
        for a, nonce in zip(accounts, await self.nonces(accounts), strict=True):
            a.nonce = nonce
        return step


def _profile(pid: int, seconds: float, out: str) -> Optional[subprocess.Popen]:
    try:
        return subprocess.Popen(
            [
                "py-spy",
                "record",
                "--pid",
                str(pid),
                "--duration",
                str(int(seconds)),
                "--rate",
                "100",
                "--nonblocking",
                "--gil",
                "--format",
                "raw",
                "-o",
                out,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return None


async def run(args) -> int:
    from integration_tests.config import build_node_specs
    from integration_tests.orchestrator import TestnetOrchestrator

    # The load comes from one address: the nodes' per-address RPC limit would be all it measured.
    for name in ("QRDX_RPC_CLIENT_RPS", "QRDX_RPC_GLOBAL_RPS"):
        os.environ.setdefault(name, "100000")

    orch = TestnetOrchestrator(force_regenerate=args.force)
    try:
        await orch.setup()
        await orch.start_all_nodes()
        if not await orch.wait_network_ready():
            logger.error("network failed to reach ready state")
            return 1
        build_node_specs(orch.num_nodes, orch.num_validators)
        urls = [p.url for p in orch.node_processes]
        load = Load(urls, orch.get_wallet("Validator 0"))
        chain_id = int(await load.rpc(urls[0], "eth_chainId", []), 16)
        accounts = [Account(chain_id) for _ in range(args.accounts)]
        logger.info("funding %d accounts…", len(accounts))
        await load.fund(accounts)
        baseline = await load.block_rate(10)
        logger.info("baseline: %.2f blocks/s", baseline)
        results = []
        for target in args.rates:
            proc = None
            if args.profile:
                out = os.path.abspath(f"load-profile-{int(target)}.collapsed")
                proc = _profile(orch.node_processes[0].process.pid, args.seconds, out)
            step = await load.step(accounts, target, args.seconds)
            if proc:
                proc.wait(timeout=args.seconds + 30)
            logger.info(step.line())
            if step.errors:
                logger.info("  refused: %s", json.dumps(step.errors))
            results.append(step)
        print("\n── LOAD ──")
        print(
            f"baseline {baseline:.2f} blocks/s, {len(accounts)} accounts, "
            f"{args.seconds:.0f} s a step"
        )
        for s in results:
            print("  " + s.line())
        await load.http.aclose()
        await load.probe.aclose()
        return 0
    finally:
        await orch.stop_all_nodes()


def main() -> int:
    p = argparse.ArgumentParser(description="Throughput of a fresh 4-node network under load")
    p.add_argument("--force", action="store_true", help="regenerate wallets and genesis")
    p.add_argument(
        "--rates",
        type=lambda s: [float(x) for x in s.split(",")],
        default=[10.0, 25.0, 50.0, 100.0],
    )
    p.add_argument("--seconds", type=float, default=30.0)
    p.add_argument("--accounts", type=int, default=64)
    p.add_argument("--profile", action="store_true")
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    return asyncio.run(run(p.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
