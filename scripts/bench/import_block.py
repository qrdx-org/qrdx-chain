#!/usr/bin/env python3
"""
A block as an importing validator meets it, phase by phase (docs/PERFORMANCE.md): its
transactions first arrive from peers and are admitted, then the block names them and is
imported from the mempool's own copies (a compact block), on a real database.

* **admit**: each transaction's binary text from a peer, through the node's submitter and
  mempool (``ExchangeSubmitter.submit``: decoding, the signature in one batch, the payer's
  balance, the mempool's checks).
* **import**: the steps ``block_import._apply_exchange_section_on_import`` takes — decode and
  "already checked?", the balance pre-loads, execution with the exchange root, the flush — then
  the unified state root and storing the block.

    python scripts/bench/import_block.py [--txs 500] [--accounts 2048] [--blocks 3]
        [--profile admit|import]

``--profile``: cProfile over that part's timed phases only (setup and signing left out), the
functions it spends most in, by their own time.

The sibling ``exchange_block.py`` times what the proposer does.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from types import SimpleNamespace

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(__file__))

from exchange_block import T0, Clock, _setup, _transfers  # noqa: E402


async def run(args) -> None:
    import qrdx.contracts.evm_mempool  # noqa: F401  (the first base fee imports it: seconds)
    from qrdx.constants import CHAIN_ID
    from qrdx.exchange import ExchangeStateManager, block_processor as BP
    from qrdx.exchange.mempool import ExchangeMempool
    from qrdx.exchange.submission import ExchangeSubmitter
    from qrdx.validator.node_integration import ValidatorNode

    db, path, keys = await _setup(args.accounts)
    ExchangeStateManager.reset_instance()
    nonces = {k.public_key.to_address(): 0 for k in keys}
    mempool = ExchangeMempool(max_size=10**6, max_per_sender=10**6, max_nonce_gap=10**6)

    async def no_forward(*_a, **_k):
        return None

    submitter = ExchangeSubmitter(  # (as the node makes it: balances read a batch at a time)
        lambda: mempool,
        lambda: [],
        no_forward,
        get_balance=db.get_address_balance,
        get_balances=db.get_address_balances,
    )
    clock = Clock()
    total = 0
    import cProfile
    import pstats

    profiler = cProfile.Profile() if args.profile else None

    from contextlib import contextmanager

    @contextmanager
    def phase(name: str):
        on = profiler is not None and b >= 2 and args.profile in name
        with clock.phase(name):
            if on:
                profiler.enable()
            try:
                yield
            finally:
                if on:
                    profiler.disable()

    try:
        for b in range(1, args.blocks + 2):
            if b == 2:  # (the first block untimed: each module's first use imports it)
                clock.ms.clear()
                total = 0
            ts = float(T0 + b)
            texts = BP.encode_exchange_txs(_transfers(keys, args.txs, nonces, CHAIN_ID), b)

            with phase("admit (decode, check, mempool)"):
                replies = await asyncio.gather(
                    *[submitter.submit(t, propagated=True, origin="peer") for t in texts]
                )
            assert all(ok for ok, _e, _h in replies), [e for ok, e, _h in replies if not ok][:1]
            section = [mempool.get(h) for _ok, _e, h in replies]

            mgr = ExchangeStateManager.get_instance()
            with phase("import: decode, already checked?"):
                txs = BP.decode_exchange_txs(section)
                for ok, why in await BP.verify_exchange_txs(txs):
                    assert ok, why
            with phase("import: preload balances"):
                BP.apply_enforcement(mgr)
                known = await BP.preload_sender_balances(db, txs, mgr, b)
                await BP.preload_token_balances(db, txs, mgr, known=known)
            with phase("import: execute (with exchange root)"):
                ok, err, _root = BP.process_exchange_transactions(b, ts, txs, mgr)
            assert ok, err
            with phase("import: flush"):
                mgr.commit_block()
                await BP.flush_exchange_balance_deltas(
                    db, mgr, enforce=BP.ENFORCE_EXCHANGE_COLLATERAL
                )
                await BP.flush_token_balance_deltas(db, mgr)
                await BP.flush_validator_lifecycle_deltas(db, mgr, block_epoch=0, block_height=b)
            with phase("import: unified state root"):
                await ValidatorNode._compute_unified_state_root(SimpleNamespace(db=db), b, b)
            with phase("import: store the block"):
                bh = f"{b:064x}"
                await db.add_block(
                    block_hash=bh,
                    block_height=b,
                    block_content="{}",
                    validator_address="0xPQ" + "ab" * 32,
                    timestamp=int(ts),
                )
                await db.add_block_exchange_txs(bh, BP.encode_exchange_txs(txs, b), txs)
                await db.connection.commit()
            mempool.remove([t.tx_hash() for t in txs])
            total += len(txs)
    finally:
        await db.close()
        for p in (path, path + "-lck"):
            if os.path.exists(p):
                os.remove(p)
    if profiler is not None:
        stats = pstats.Stats(profiler)
        stats.sort_stats("tottime").print_stats(35)
        if os.environ.get("BENCH_CALLERS"):
            stats.print_callers(os.environ["BENCH_CALLERS"])
    print(
        f"{args.blocks} blocks × {args.txs} transfers from {args.accounts} accounts "
        f"(after one untimed block)"
    )
    whole = sum(clock.ms.values())
    for name, ms in clock.ms.items():
        print(f"  {name:38s} {ms / args.blocks:8.1f} ms a block  {1000 * ms / total:7.1f} µs a tx")
    print(
        f"  {'total':38s} {whole / args.blocks:8.1f} ms a block  {1000 * whole / total:7.1f} µs a tx"
    )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--txs", type=int, default=500)
    ap.add_argument("--accounts", type=int, default=2048)
    ap.add_argument("--blocks", type=int, default=3)
    ap.add_argument("--profile", help="profile the phases whose name has this in it")
    asyncio.run(run(ap.parse_args()))


if __name__ == "__main__":
    main()
