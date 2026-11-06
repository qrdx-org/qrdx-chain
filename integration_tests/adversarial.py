"""
Attacks on a live network (docs/MAINNET_READINESS.md §3.4: "the adversarial harness").

The scenarios drive an honest network. These attacks do what honest nodes never do to it, then
check the network is still one network: every node at the same tip (within two blocks), the
same block a few heights below it, and blocks still coming.

* **equivocation**: validator 0 signs a second block for a slot it already proposed, and the
  copy goes to the other nodes. They must record the double-sign as evidence and carry it on
  the chain, so that every node holds it, identically. They must also keep a single chain.
* **slow_parse**: a block whose content is built to take seconds to parse. It must be refused
  unparsed, and the node must keep answering while it does.
* **flood**: thousands of transactions a node must refuse, all at once: forged signatures,
  unfunded payers, broken RLP. Junk RPC comes with them. Blocks must keep coming, the node must
  keep answering, and none of it may land.

    python -m integration_tests.run_scenarios --force --adversarial [--soak 600]

The attacker is this process. It has a peer identity of its own (any key will do, so the
attacks assume no other) and validator 0's wallet, which the equivocation needs.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional

import httpx

from integration_tests.config import GENESIS_FILE

logger = logging.getLogger("adversarial")


@dataclass
class AttackResult:
    name: str
    passed: bool
    detail: str = ""
    seconds: float = 0.0


@dataclass
class AdversarialReport:
    results: List[AttackResult] = field(default_factory=list)
    slashings: int = 0  # offences the attacks committed (a soak after them expects these)

    @property
    def passed(self) -> bool:
        return bool(self.results) and all(r.passed for r in self.results)

    def summary(self) -> str:
        lines = ["── ADVERSARIAL ──"]
        for r in self.results:
            lines.append(f"  {'✓' if r.passed else '✗'} {r.name} ({r.seconds:.0f}s): {r.detail}")
        lines.append("── ADVERSARIAL PASS ──" if self.passed else "── ADVERSARIAL FAIL ──")
        return "\n".join(lines)


class Adversary:
    def __init__(self, node_urls: List[str], db_paths: List[str], validator_wallet: dict):
        self.urls = node_urls
        self.db_paths = db_paths
        self.wallet = validator_wallet
        self.http: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "Adversary":
        from qrdx import chain_spec
        from qrdx.node import identity
        from qrdx.node.nodes_manager import NodeInterface

        genesis, spec = chain_spec.load_genesis_file(str(GENESIS_FILE))
        chain_spec.set_active(spec)  # (the block signing domain is the network's)
        genesis_hash = (genesis.get("block") or {}).get("block_hash")
        # A peer identity of its own, held in memory only.
        secret, public = identity.generate_new_keypair()
        identity._secret_key, identity._public_key = secret, public
        identity._node_id = identity._derive_node_id(public)

        async def _identity():
            return {"genesis_hash": genesis_hash}

        NodeInterface.network_identity_provider = _identity
        self.http = httpx.AsyncClient(timeout=60)
        return self

    async def __aexit__(self, *exc) -> None:
        if self.http:
            await self.http.aclose()

    # ── talking to the nodes ──────────────────────────────────────────────────────────────

    async def peer_rpc(self, url: str, method: str, params: list) -> Any:
        """A JSON-RPC call signed as a peer (as any node's calls are)."""
        from qrdx.node.nodes_manager import NodeInterface

        return await NodeInterface(url, client=self.http, db=None)._rpc_call(method, params)

    async def rpc(self, url: str, method: str, params: Optional[list] = None) -> Any:
        r = await self.http.post(
            f"{url}/rpc", json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}
        )
        return r.json()

    async def height(self, url: str) -> int:
        r = await self.http.get(f"{url}/get_mining_info")
        return int(r.json()["result"]["last_block"]["id"])

    async def block(self, url: str, height: int) -> Optional[dict]:
        r = await self.http.get(f"{url}/get_block", params={"block": str(height)})
        body = r.json()
        return body["result"]["block"] if body.get("ok") else None

    async def responsive(self, url: str) -> float:
        """Seconds a health check took (an error counts as 30)."""
        start = time.monotonic()
        try:
            r = await self.http.get(f"{url}/healthz", timeout=30)
            r.raise_for_status()
        except Exception:
            return 30.0
        return time.monotonic() - start

    async def converged(self, timeout: float = 120.0) -> str:
        """ "" once every node is within two blocks of the others and all hold the same block
        three below the lowest tip; otherwise why not, at the deadline."""
        deadline = time.monotonic() + timeout
        why = ""
        while time.monotonic() < deadline:
            try:
                tips = [await self.height(u) for u in self.urls]
                at = min(tips) - 3
                hashes = {(await self.block(u, at) or {}).get("hash") for u in self.urls}
                if max(tips) - min(tips) <= 2 and len(hashes) == 1 and None not in hashes:
                    return ""
                why = f"tips {tips}, {len(hashes)} different blocks at {at}"
            except Exception as e:
                why = f"{type(e).__name__}: {e}"
            await asyncio.sleep(2)
        return why

    async def block_rate(self, seconds: float) -> float:
        start = await self.height(self.urls[0])
        await asyncio.sleep(seconds)
        return (await self.height(self.urls[0]) - start) / seconds

    def slashing_rows(self, validator: str) -> List[List[tuple]]:
        """Each node's DOUBLE_SIGN evidence rows for ``validator`` (read-only, WAL-safe)."""
        out = []
        for path in self.db_paths:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
            try:
                rows = con.execute(
                    "SELECT slot, epoch, evidence FROM slashing_events "
                    "WHERE validator_address = ? AND condition = 'double_sign' ORDER BY slot",
                    (validator,),
                ).fetchall()
            finally:
                con.close()
            out.append(rows)
        return out


# ── the attacks ──────────────────────────────────────────────────────────────────────────


async def equivocation(adv: Adversary) -> AttackResult:
    """Nodes compare a block for their tip's height with the one they hold, so the second block
    has to arrive while the first is still the tip (a quarter of a second at 250 ms slots): the
    attacker watches node 0 and signs a twin of validator 0's block the moment one lands."""
    from qrdx.crypto.pq.dilithium import PQPrivateKey, sign
    from qrdx.validator.block_verification import (
        _parse_block_content,
        body_root,
        reconstruct_signing_root,
    )

    v0 = adv.wallet["address"]
    key = PQPrivateKey.from_hex(adv.wallet["private_key"], adv.wallet["public_key"])
    seen = -1
    sent: List[Dict[str, Any]] = []
    slots: List[int] = []
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        tip = await adv.height(adv.urls[0])
        if tip == seen:
            await asyncio.sleep(0.03)
            continue
        seen = tip
        row = await adv.block(adv.urls[0], tip)
        bc = _parse_block_content((row or {}).get("content") or "{}")
        # validator 0's, and nothing beside its content (so its body root is the content's own)
        if bc.get("proposer_address") != v0 or body_root(bc) != bc.get("body_root"):
            continue
        twin = dict(bc, graffiti=f"adversarial: a second block for slot {bc['slot']}")
        twin["body_root"] = body_root(twin)
        root = reconstruct_signing_root(twin)
        twin["proposer_signature"] = sign(key, root).to_bytes().hex()
        twin["hash"] = root.hex()
        payload = {
            "id": tip,
            "block_content": str(twin),
            "block_hash": root.hex(),
            "validator_address": v0,
            "timestamp": twin["timestamp"],
        }
        answers = await asyncio.gather(
            *[adv.peer_rpc(u, "p2p_submitBlock", [payload]) for u in adv.urls[1:]],
            return_exceptions=True,
        )
        sent.append(payload)
        slots.append(int(bc["slot"]))
        logger.info(
            "equivocation: slot %s (height %d) signed twice: %s… and %s… → %s",
            bc["slot"],
            tip,
            bc["hash"][:12],
            root.hex()[:12],
            [
                (
                    ((a or {}).get("result") or {}).get("error", "ok")
                    if isinstance(a, dict)
                    else type(a).__name__
                )
                for a in answers
            ],
        )
        await asyncio.sleep(1.0)
        if any(int(r[0]) in slots for node in adv.slashing_rows(v0) for r in node):
            break
    if not sent:
        return AttackResult("equivocation", False, "validator 0 proposed no block to twin")

    # Every node holds the evidence: the nodes that saw both blocks record it, and a proposer
    # carries it in a block (a self-validating proof), which every importer records.
    def evidence() -> List[List[tuple]]:
        return [[r for r in node if int(r[0]) in slots] for node in adv.slashing_rows(v0)]

    deadline = time.monotonic() + 180
    while time.monotonic() < deadline and not all(evidence()):
        await asyncio.sleep(3)
    held = evidence()
    if not any(held):
        return AttackResult(
            "equivocation", False, f"{len(sent)} twin(s) sent, no node recorded a double-sign"
        )
    if not all(held):
        return AttackResult(
            "equivocation",
            False,
            f"evidence on {sum(1 for h in held if h)}/{len(held)} nodes after "
            "180 s: it did not travel on the chain",
        )
    by_slot = [{int(r[0]): json.dumps(json.loads(r[2]), sort_keys=True) for r in h} for h in held]
    common = set.intersection(*(set(b) for b in by_slot))
    if not common or any(len({b[s] for b in by_slot}) != 1 for s in common):
        return AttackResult("equivocation", False, "the nodes hold different evidence")
    why = await adv.converged()
    if why:
        return AttackResult("equivocation", False, f"no single chain after: {why}")
    return AttackResult(
        "equivocation",
        True,
        f"{len(sent)} twin(s) sent; slot(s) {sorted(common)}: identical "
        f"evidence on all {len(held)} nodes; one chain",
    )


async def slow_parse(adv: Adversary) -> AttackResult:
    from qrdx.constants import MAX_BLOCK_CONTENT_SIZE

    target = adv.urls[1]
    height = await adv.height(target) + 1
    content = "{'a': [" + "1," * (MAX_BLOCK_CONTENT_SIZE // 2 - 8) + "]}"
    payload = {
        "id": height,
        "block_content": content,
        "block_hash": "ab" * 32,
        "validator_address": adv.wallet["address"],
    }
    probes: List[float] = []

    async def probe():
        for _ in range(5):
            probes.append(await adv.responsive(target))
            await asyncio.sleep(0.2)

    start = time.monotonic()
    answers = await asyncio.gather(
        *[adv.peer_rpc(target, "p2p_submitBlock", [payload]) for _ in range(4)], probe()
    )
    took = time.monotonic() - start
    refused = all(
        isinstance(a, dict) and not (a.get("result") or {}).get("ok", False) for a in answers[:4]
    )
    slowest = max(probes)
    if not refused:
        return AttackResult("slow_parse", False, f"accepted? {answers[0]}")
    if slowest > 1.0 or took > 10:
        return AttackResult(
            "slow_parse",
            False,
            f"the node stalled: health check {slowest:.2f} s, submits {took:.1f} s",
        )
    return AttackResult(
        "slow_parse", True, f"4 × 4 MB refused in {took:.2f} s; health checks ≤ {slowest:.2f} s"
    )


async def flood(adv: Adversary, seconds: float = 30.0) -> AttackResult:
    """Transactions a node must refuse, as fast as it takes them, from many connections."""
    from eth_account import Account

    from qrdx.crypto.pq.dilithium import PQPrivateKey
    from qrdx.exchange import ExchangeOpType, ExchangeTransaction

    target = adv.urls[2]
    base_rate = await adv.block_rate(10)
    chain_id = int((await adv.rpc(target, "eth_chainId"))["result"], 16)

    unfunded = PQPrivateKey.generate()
    addr = unfunded.public_key.to_address()

    def exchange_tx(n: int, forge: bool) -> Dict[str, Any]:
        tx = ExchangeTransaction(
            op_type=ExchangeOpType.CANCEL_ALL,
            sender=addr,
            nonce=n,
            params={},
            gas_limit=100_000,
            gas_price=10**9,
            chain_id=chain_id,
        )
        tx.public_key = unfunded.public_key.to_bytes()
        tx.signature = (b"\x00" * 3309) if forge else unfunded.sign(tx.signing_bytes()).to_bytes()
        return tx.to_dict()

    signed = [exchange_tx(n, False) for n in range(50)]  # (unfunded: refused at admission)
    forged = [exchange_tx(n, True) for n in range(50)]
    eth_key = Account.create()
    eth_txs = [
        Account.sign_transaction(
            {
                "nonce": n,
                "gas": 21_000,
                "gasPrice": 10**9,
                "to": eth_key.address,
                "value": 1,
                "chainId": chain_id,
            },
            eth_key.key,
        )
        for n in range(20)
    ]
    raw = [
        "0x" + bytes(getattr(t, "raw_transaction", None) or t.rawTransaction).hex() for t in eth_txs
    ]  # (unfunded too)
    junk = ["0x", "0x00", "0xf8", "0x51" + "00" * 64, "0x" + "ff" * 3000]

    sent = {"n": 0, "landed": 0}
    stop = time.monotonic() + seconds

    async def worker(i: int):
        while time.monotonic() < stop:
            try:
                k = sent["n"]
                sent["n"] += 1
                which = k % 5
                if which == 0:
                    r = await adv.rpc(target, "exchange_sendTransaction", [signed[k % 50]])
                elif which == 1:
                    r = await adv.rpc(target, "exchange_sendTransaction", [forged[k % 50]])
                elif which == 2:
                    r = await adv.rpc(target, "eth_sendRawTransaction", [raw[k % 20]])
                elif which == 3:
                    r = await adv.rpc(target, "eth_sendRawTransaction", [junk[k % 5]])
                else:
                    r = await adv.rpc(target, "no_such_method", [{"x": [1] * 100}])
                if isinstance(r, dict) and r.get("result") and which in (0, 1, 2, 3):
                    sent["landed"] += 1
            except Exception:
                pass

    probes: List[float] = []

    async def probe():
        while time.monotonic() < stop:
            probes.append(await adv.responsive(target))
            await asyncio.sleep(1)

    h0 = await adv.height(adv.urls[0])
    await asyncio.gather(*[worker(i) for i in range(32)], probe())
    produced = (await adv.height(adv.urls[0]) - h0) / seconds
    admitted = sent["landed"]
    why = await adv.converged()
    worst = max(probes) if probes else 30.0
    detail = (
        f"{sent['n']} requests in {seconds:.0f} s; {admitted} admitted; blocks "
        f"{produced:.2f}/s (before {base_rate:.2f}/s); health checks ≤ {worst:.2f} s"
    )
    ok = admitted == 0 and not why and worst < 5.0 and produced >= 0.5 * base_rate
    if why:
        detail += f"; not converged: {why}"
    return AttackResult("flood", ok, detail)


ATTACKS: Dict[str, Callable[[Adversary], Awaitable[AttackResult]]] = {
    "slow_parse": slow_parse,
    "flood": flood,
    "equivocation": equivocation,
}


async def run_adversarial_phase(
    node_urls: List[str],
    db_paths: List[str],
    validator_wallet: dict,
    only: Optional[List[str]] = None,
) -> AdversarialReport:
    report = AdversarialReport()
    async with Adversary(node_urls, db_paths, validator_wallet) as adv:
        why = await adv.converged()
        if why:
            report.results.append(AttackResult("start", False, f"not converged: {why}"))
            return report
        for name, attack in ATTACKS.items():
            if only and name not in only:
                continue
            start = time.monotonic()
            try:
                result = await attack(adv)
            except Exception as e:  # an attack that crashes the harness is a failure too
                logger.exception("attack %s", name)
                result = AttackResult(name, False, f"{type(e).__name__}: {e}")
            result.seconds = time.monotonic() - start
            logger.info("%s %s: %s", "✓" if result.passed else "✗", name, result.detail)
            report.results.append(result)
        report.slashings = max(
            (len(rows) for rows in adv.slashing_rows(validator_wallet["address"])), default=0
        )
    return report


async def _main(args) -> int:
    from integration_tests.config import build_node_specs
    from integration_tests.orchestrator import TestnetOrchestrator

    orch = TestnetOrchestrator(force_regenerate=args.force)
    try:
        await orch.setup()
        await orch.start_all_nodes()
        if not await orch.wait_network_ready():
            logger.error("network failed to reach ready state")
            return 1
        specs = build_node_specs(orch.num_nodes, orch.num_validators)
        report = await run_adversarial_phase(
            [p.url for p in orch.node_processes],
            [s.db_path for s in specs],
            orch.get_wallet("Validator 0"),
            only=args.only or None,
        )
        logger.info("\n" + report.summary())
        return 0 if report.passed else 1
    finally:
        await orch.stop_all_nodes()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Attack a fresh 4-node network (only the attacks)")
    parser.add_argument("--force", action="store_true", help="regenerate wallets and genesis")
    parser.add_argument("--only", action="append", choices=sorted(ATTACKS), help="run this attack")
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    raise SystemExit(asyncio.run(_main(parser.parse_args())))
