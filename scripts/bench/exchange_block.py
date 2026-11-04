#!/usr/bin/env python3
"""
One block's exchange section, phase by phase, on a real SQLite database (docs/PERFORMANCE.md).

What a proposer does with K exchange transfers from N funded accounts, timed in phases: the
inclusion judgment, the balance pre-loads, execution, the flush to the database, the unified
state root, storing the block; then what an importer does with the same section (verification
and replay). Prints milliseconds per phase and per transaction.

    python scripts/bench/exchange_block.py [--txs 500] [--accounts 100] [--blocks 3]
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


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--txs", type=int, default=500)
    p.add_argument("--accounts", type=int, default=100)
    p.add_argument("--blocks", type=int, default=3)
    import logging

    logging.disable(logging.WARNING)
    asyncio.run(run(p.parse_args()))


if __name__ == "__main__":
    main()
