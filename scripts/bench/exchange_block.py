#!/usr/bin/env python3
"""
One block's exchange section, phase by phase, on a real SQLite database (docs/PERFORMANCE.md).

What a proposer does with K exchange transfers from N funded accounts, timed in phases: the
inclusion judgment, the balance pre-loads, execution, the flush to the database, the unified
state root, storing the block; then what an importer does with the same section (verification
and replay). Prints milliseconds per phase and per transaction.

    python scripts/bench/exchange_block.py [--txs 500] [--accounts 100] [--blocks 3]

``--workload orders`` times spot order flow instead (docs/EXCHANGE_ENGINE.md): one QRDX/token
book, resting orders on both sides, then blocks of 30% cancels, 30% orders that cross and 40%
that rest, run through the exchange's own ``process_transaction`` (no database: execution and
the exchange root only).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
import time
from collections import defaultdict
from contextlib import contextmanager
from types import SimpleNamespace

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)

T0 = 1_800_000_000


class Clock:
    def __init__(self) -> None:
        self.ms = defaultdict(float)

    @contextmanager
    def phase(self, name: str):
        start = time.perf_counter()
        yield
        self.ms[name] += (time.perf_counter() - start) * 1000


async def _setup(n_accounts: int):
    from qrdx.crypto.pq.dilithium import PQPrivateKey
    from qrdx.database_sqlite import DatabaseSQLite

    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    keys = [PQPrivateKey.generate() for _ in range(n_accounts)]
    await db.add_block(block_hash="00" * 32, block_height=0, block_content="",
                       validator_address="0xPQ" + "00" * 32, timestamp=T0)
    for i, k in enumerate(keys):
        await db.add_transaction(
            tx_hash=f"alloc-{i}", block_hash="00" * 32,
            tx_hex=json.dumps({"type": "genesis_allocation",
                               "recipient": k.public_key.to_address(), "amount": "1000000"}))
    await db.seed_genesis_account_state()
    await db.connection.commit()
    return db, path, keys


def _transfers(keys, count: int, nonces, chain_id: int):
    from qrdx.exchange import ExchangeOpType, ExchangeTransaction

    txs = []
    for i in range(count):
        k = keys[i % len(keys)]
        to = keys[(i + 1) % len(keys)].public_key.to_address()
        sender = k.public_key.to_address()
        t = ExchangeTransaction(op_type=ExchangeOpType.TOKEN_TRANSFER, sender=sender,
                                nonce=nonces[sender], params={"token_address": "QRDX", "to": to,
                                                              "amount": "0.001"},
                                gas_limit=200_000, gas_price=10**9, chain_id=chain_id)
        nonces[sender] += 1
        t.public_key = k.public_key.to_bytes()
        t.signature = k.sign(t.signing_bytes()).to_bytes()
        txs.append(t)
    return txs


async def run(args) -> None:
    from qrdx.constants import CHAIN_ID
    from qrdx.exchange import ExchangeStateManager
    from qrdx.exchange import block_processor as BP
    from qrdx.validator.node_integration import ValidatorNode

    import qrdx.contracts.evm_mempool  # noqa: F401  (the first base fee imports it: seconds)

    db, path, keys = await _setup(args.accounts)
    ExchangeStateManager.reset_instance()
    nonces = {k.public_key.to_address(): 0 for k in keys}
    clock = Clock()
    total = 0
    try:
        # (One untimed block first: the first use of each module imports it — the EVM's alone
        # takes seconds — and is no part of a block's cost.)
        for b in range(1, args.blocks + 2):
            if b == 2:
                clock.ms.clear()
                total = 0
            txs = _transfers(keys, args.txs, nonces, CHAIN_ID)
            ts = float(T0 + b)
            mgr = ExchangeStateManager.get_instance()
            with clock.phase("verify signatures"):
                for ok, why in await BP.verify_exchange_txs(txs):  # (threads, as imports do)
                    assert ok, why
            with clock.phase("proposer: inclusion judgment"):
                kept, refused = await BP.includable_exchange_txs(db, txs, b, ts, 10**8)
            assert not refused, refused[:1]
            with clock.phase("preload balances"):
                BP.apply_enforcement(mgr)
                await BP.preload_sender_balances(db, kept, mgr, b)
                await BP.preload_token_balances(db, kept, mgr)
            with clock.phase("execute"):
                ok, err, root = BP.process_exchange_transactions(b, ts, kept, mgr)
            assert ok, err
            with clock.phase("flush to the database"):
                mgr.commit_block()
                await BP.flush_exchange_balance_deltas(db, mgr, enforce=BP.ENFORCE_EXCHANGE_COLLATERAL)
                await BP.flush_token_balance_deltas(db, mgr)
                await BP.flush_validator_lifecycle_deltas(db, mgr, block_epoch=0, block_height=b)
            with clock.phase("unified state root"):
                await ValidatorNode._compute_unified_state_root(SimpleNamespace(db=db), b, b)
            with clock.phase("store the block"):
                bh = f"{b:064x}"
                await db.add_block(block_hash=bh, block_height=b, block_content="{}",
                                   validator_address="0xPQ" + "ab" * 32, timestamp=int(ts))
                await db.add_block_exchange_txs(bh, BP.encode_exchange_txs(kept))
                await db.connection.commit()
            total += len(kept)
    finally:
        await db.close()
        for p in (path, path + "-wal", path + "-shm"):
            if os.path.exists(p):
                os.remove(p)
    print(f"{args.blocks} blocks × {args.txs} transfers from {args.accounts} accounts "
          f"(after one untimed block)")
    whole = sum(clock.ms.values())
    for name, ms in clock.ms.items():
        print(f"  {name:32s} {ms / args.blocks:9.1f} ms a block  {1000 * ms / total:8.1f} µs a tx")
    print(f"  {'total':32s} {whole / args.blocks:9.1f} ms a block  {1000 * whole / total:8.1f} µs a tx"
          f"  → {total / (whole / 1000):,.0f} tx/s on one core")


def orders(args) -> None:
    """Spot order flow through the exchange (no database): execution and the exchange root."""
    import random
    from decimal import Decimal as D

    from qrdx.exchange import ExchangeOpType as Op
    from qrdx.exchange import ExchangeStateManager, ExchangeTransaction
    from qrdx.exchange import block_processor as BP
    from qrdx.exchange.tokens import NATIVE_ASSET

    traders = ["0xPQ" + f"{i:064x}" for i in range(1, args.accounts + 1)]
    issuer = "0xPQ" + "f" * 64
    nonces = {}

    def tx(sender, op, **params):
        n = nonces.get(sender, 0)
        nonces[sender] = n + 1
        return ExchangeTransaction(op_type=op, sender=sender, nonce=n, params=params,
                                   gas_limit=2_000_000, gas_price=10**9)

    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    BP.apply_enforcement(m)
    m.begin_block(1, float(T0))
    for who in traders + [issuer]:
        m.set_available_balance(who, D(10**9))
    r = m.process_transaction(tx(issuer, Op.TOKEN_DEPLOY, name="Tok", symbol="TOK",
                                 total_supply="1000000000"))
    token = r.data["token_address"]
    m.set_available_token_balance(issuer, token, D(10**9))
    for who in traders:
        m.set_available_token_balance(who, token, D(10**6))
    r = m.process_transaction(tx(issuer, Op.CREATE_POOL, token0="qrdx", token1=token,
                                 fee_tier=3000, pool_type="STANDARD", initial_price="2",
                                 stake_amount="10000"))
    holder = m.pool_holder_address(r.data["pool_id"])
    escrow = m.orderbook_escrow_address(f"{token}:{NATIVE_ASSET}")
    for who in (holder, escrow):
        m.set_available_balance(who, D(0))
        m.set_available_token_balance(who, token, D(0))
    pair = f"{token}:QRDX"
    m.commit_block()
    rng = random.Random(1)
    resting = []

    def place(who, crossing):
        side = rng.choice(["buy", "sell"])
        off = D(rng.randint(5, 150) if crossing else rng.randint(1, 200)) / 1000
        price = D(2) + off if (side == "buy") == crossing else D(2) - off
        return tx(who, Op.PLACE_ORDER, pair=pair, side=side, order_type="limit",
                  price=str(price), amount=str(rng.randint(1, 50)))

    def block(height, txs):
        m.begin_block(height, float(T0 + height))
        start = time.perf_counter()
        for t in txs:
            r = m.process_transaction(t)
            if r.success and t.op_type == Op.PLACE_ORDER and (r.data or {}).get("order_id"):
                resting.append((t.sender, r.data["order_id"]))
        ran = time.perf_counter() - start
        start = time.perf_counter()
        m.compute_state_root()
        root = time.perf_counter() - start
        m.commit_block()
        return ran, root

    block(2, [place(traders[i % len(traders)], False) for i in range(2 * args.txs)])
    ran_total = root_total = 0.0
    for h in range(3, 3 + args.blocks):
        txs = []
        for _ in range(args.txs):
            who, k = rng.choice(traders), rng.random()
            if k < 0.3 and resting:
                owner, oid = resting.pop(rng.randrange(len(resting)))
                txs.append(tx(owner, Op.CANCEL_ORDER, pair=pair, order_id=oid))
            else:
                txs.append(place(who, crossing=k < 0.6))
        ran, root = block(h, txs)
        ran_total, root_total = ran_total + ran, root_total + root
    n = args.txs * args.blocks
    print(f"{args.blocks} blocks × {args.txs} spot operations from {len(traders)} accounts "
          f"(30% cancels, 30% crossing, 40% resting; {2 * args.txs} resting before)")
    print(f"  execute          {1e3 * ran_total / args.blocks:9.1f} ms a block "
          f"{1e6 * ran_total / n:8.1f} µs an operation")
    print(f"  exchange root    {1e3 * root_total / args.blocks:9.1f} ms a block")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--txs", type=int, default=500)
    p.add_argument("--accounts", type=int, default=100)
    p.add_argument("--blocks", type=int, default=3)
    p.add_argument("--workload", choices=("transfers", "orders"), default="transfers")
    import logging

    logging.disable(logging.WARNING)
    args = p.parse_args()
    if args.workload == "orders":
        orders(args)
    else:
        asyncio.run(run(args))


if __name__ == "__main__":
    main()
