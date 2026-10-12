"""
Fast reorgs (qrdx/undo_journal.py, qrdx/derived_state_rebuild.py rebuild_to_tip).

A rollback used to rebuild every derived domain by replaying the chain from genesis — ~9 s after
a day of 250 ms blocks, on every reorg and every rejected block. Now each block's writes to the
derived tables are journaled under its height, and the exchange is checkpointed when a block opens
an epoch; a rollback undoes the journal back to the newest checkpoint at or below the new tip,
restores the exchange from it and replays only the blocks above it. What must hold:

  * the fast path yields EXACTLY what the full rebuild yields — every account, token, storage
    and registry row, the state commitments, and the exchange state (both roots) — after one
    reorg and after several in a row onto different branches;
  * it really is the fast path (it reports the checkpoint it started from);
  * a write to a journaled table outside any block makes the journal unable to vouch for
    exactness, and the rebuild falls back to the full replay rather than undo too little.
"""
import os
import random
import tempfile

import pytest

from qrdx import state_commitment as SC
from qrdx import undo_journal
from qrdx.constants import SLOTS_PER_EPOCH as S
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.derived_state_rebuild import (
    CHECKPOINTS, before_block, rebuild_derived_state_interleaved, rebuild_to_tip,
)
from qrdx.exchange import (
    ExchangeOpType, ExchangeStateManager, ExchangeTransaction, encode_exchange_txs,
)
from qrdx.exchange import block_processor as BP
from qrdx.exchange.amm import FeeTier, PoolType

TS0 = 1_700_000_000
SPACING = max(1, S // 3)  # slots between blocks: an epoch every ~3 blocks


def _sign(tx, key):
    tx.public_key = key.public_key.to_bytes()
    tx.signature = key.sign(tx.signing_bytes()).to_bytes()
    return tx


class Workload:
    """Two funded accounts and the exchange activity of test_reorg_rebuild_equivalence's rich
    chain — tokens, a traded perp market, a pool with liquidity — plus random transfers."""

    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.k1, self.k2 = PQPrivateKey.generate(), PQPrivateKey.generate()
        self.t1, self.t2 = self.k1.public_key.to_address(), self.k2.public_key.to_address()
        self.nonce = {self.t1: 0, self.t2: 0}
        self.tokenA = ExchangeStateManager.derive_token_address(self.t1, 0, "AAA")
        self.tokenB = ExchangeStateManager.derive_token_address(self.t1, 5, "BBB")

    def tx(self, key, op, **params):
        sender = key.public_key.to_address()
        n = self.nonce[sender]
        self.nonce[sender] += 1
        return _sign(ExchangeTransaction(op_type=op, sender=sender, nonce=n, params=params,
                                         gas_limit=2_000_000, gas_price=10**9), key)

    def script(self):
        k1, k2, t1, t2 = self.k1, self.k2, self.t1, self.t2
        sqrtp = "79228162514264337593543950336"
        return [
            [self.tx(k1, ExchangeOpType.TOKEN_DEPLOY, name="A", symbol="AAA",
                     total_supply="1000000", decimals=18)],
            [self.tx(k1, ExchangeOpType.TOKEN_TRANSFER, token_address=self.tokenA, to=t2,
                     amount="100000")],
            [self.tx(k1, ExchangeOpType.CREATE_MARKET, base_token="BTC", max_leverage="10",
                     initial_margin_rate="0.1", maintenance_margin_rate="0.05"),
             self.tx(k2, ExchangeOpType.UPDATE_ORACLE, pair="BTC:QRDX", price="30000")],
            [self.tx(k1, ExchangeOpType.PERP_DEPOSIT, amount="10000"),
             self.tx(k2, ExchangeOpType.PERP_DEPOSIT, amount="10000"),
             self.tx(k2, ExchangeOpType.PERP_ORDER, market_id="BTC-QRDX-PERP", side="sell",
                     size="1", price="30000"),
             self.tx(k1, ExchangeOpType.PERP_ORDER, market_id="BTC-QRDX-PERP", side="buy",
                     size="1", price="30000")],
            [self.tx(k1, ExchangeOpType.TOKEN_DEPLOY, name="B", symbol="BBB",
                     total_supply="1000000", decimals=18)],
            [self.tx(k1, ExchangeOpType.CREATE_POOL, token0=self.tokenA, token1=self.tokenB,
                     fee_tier=int(FeeTier.MEDIUM), pool_type=int(PoolType.STANDARD),
                     initial_sqrt_price=sqrtp, stake_amount="10000")],
            [self.tx(k1, ExchangeOpType.ADD_LIQUIDITY, pool_id="", token0=self.tokenA,
                     token1=self.tokenB, amount="1000", tick_lower="-887220",
                     tick_upper="887220")],
        ]

    def transfer(self):
        """A random token transfer between the two accounts (or a quiet block)."""
        if self.rng.random() < 0.4:
            return []
        key, to = (self.k1, self.t2) if self.rng.random() < 0.5 else (self.k2, self.t1)
        return [self.tx(key, ExchangeOpType.TOKEN_TRANSFER, token_address=self.tokenA, to=to,
                        amount=str(self.rng.randint(1, 500)))]


class Node:
    """A database applying blocks the way every import path does (before_block: checkpoint,
    then the journal recording the block's writes)."""

    @classmethod
    async def create(cls, w):
        n = cls()
        fd, n.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        n.db = await DatabaseSQLite.create(n.path)
        CHECKPOINTS.clear()
        from qrdx import derived_state_rebuild as D

        D._LAST_EPOCH.clear()
        bh = await n._store(0, 0, [], tag="g", alloc=[(w.t1, "1000000"), (w.t2, "1000000")])
        async with undo_journal.recording(n.db, 0):
            await n.db.seed_genesis_account_state()
        await n.db.connection.commit()
        ExchangeStateManager.reset_instance()
        n.mgr = ExchangeStateManager.get_instance()
        BP.apply_enforcement(n.mgr)
        n.genesis = bh
        return n

    async def close(self):
        await self.db.connection.close()
        os.remove(self.path)

    async def _store(self, height, slot, txs, tag, alloc=None):
        import json

        bh = f"{tag}{height:063x}"[:64]
        await self.db.add_block(block_hash=bh, block_height=height,
                                block_content=repr({"slot": slot, "epoch": slot // S}),
                                validator_address="0xPQ" + "00" * 32, timestamp=TS0 + slot)
        for i, (recipient, amount) in enumerate(alloc or []):
            await self.db.add_transaction(
                tx_hash=f"alloc-{i}-{recipient[:8]}",
                tx_hex=json.dumps({"type": "genesis_allocation", "recipient": recipient,
                                   "amount": str(amount)}), block_hash=bh)
        if txs:
            await self.db.add_block_exchange_txs(bh, encode_exchange_txs(txs))
        return bh

    async def apply(self, txs, tag="a"):
        """Apply and store the next block (its exchange section, then the block row)."""
        height = await self.db.get_next_block_id()
        slot = height * SPACING
        # The live instance, as every node path uses (a full rebuild replaces it).
        self.mgr = ExchangeStateManager.get_instance()
        async with await before_block(self.db, height, slot // S):
            if txs:
                await BP.preload_sender_balances(self.db, txs, self.mgr)
                await BP.preload_token_balances(self.db, txs, self.mgr)
                ok, err, _ = BP.process_exchange_transactions(height, float(TS0 + slot), txs,
                                                              self.mgr)
                assert ok, err
                self.mgr.commit_block()
                await BP.flush_exchange_balance_deltas(self.db, self.mgr,
                                                       enforce=BP.ENFORCE_EXCHANGE_COLLATERAL)
                await BP.flush_token_balance_deltas(self.db, self.mgr)
            else:
                BP.run_exchange_tick(height, float(TS0 + slot), self.mgr)
            await self._store(height, slot, txs, tag)
        await self.db.connection.commit()

    async def rollback(self, ancestor):
        await self.db.remove_blocks(ancestor + 1)
        return await rebuild_to_tip(self.db)

    async def state(self):
        c = self.db.connection
        out = {}
        for table, order in (("account_state", "address"),
                             ("contract_storage", "contract_address, storage_key"),
                             ("token_balances", "token_address, holder_address"),
                             ("token_registry", "token_address")):
            cur = await c.execute(f"SELECT * FROM {table} ORDER BY {order}")
            rows = [tuple(r) for r in await cur.fetchall()]
            if table in ("account_state", "token_balances", "token_registry"):
                rows = [r[:-2] if table == "account_state" else r for r in rows]  # (timestamps)
            out[table] = rows
        for d in SC.DOMAINS:
            assert await SC.stored_accumulator(c, d) == await SC.full_accumulator(c, d), d
            out["acc:" + d] = await SC.stored_accumulator(c, d)
        mgr = ExchangeStateManager.get_instance()
        out["exchange"] = (mgr._sequential_state_root(), mgr._incremental_state_root(),
                           mgr._current_block_height)
        out["journal"] = journal_view(mgr.journal)
        return out


def journal_view(j):
    """The journal as the API serves it, minus sequence numbers (never reused, so they differ
    between a journal that saw a reorg and one rebuilt from genesis)."""
    return (
        sorted((h, r["block_height"], r["op"], r["success"], r["error"]) for h, r in j.receipts.items()),
        [{k: v for k, v in e.items() if k != "seq"} for e in j.events],
        {name: ([{k: v for k, v in t.items() if k != "seq"} for t in m.trades],
                {sec: dict(c) for sec, c in m.candles.items()}, m.last_price, m.trade_count)
         for name, m in sorted(j.market.markets.items())},
        j.market.now,
        j.height,
    )


async def _full(node):
    await rebuild_derived_state_interleaved(node.db)
    return await node.state()


@pytest.mark.parametrize("seed", range(3))
async def test_the_fast_path_equals_the_full_rebuild_across_reorgs(seed):
    w = Workload(seed)
    node = await Node.create(w)
    try:
        for txs in w.script():
            await node.apply(txs)
        for _ in range(10):
            await node.apply(w.transfer())
        for round_ in range(3):
            tip = await node.db.get_next_block_id() - 1
            ancestor = tip - w.rng.randint(1, 6)
            res = await node.rollback(ancestor)
            assert "base" in res, f"round {round_}: the fast path did not run"
            fast = await node.state()
            assert fast == await _full(node), f"seed {seed} round {round_}"
            # a different branch on top, then the next round reorgs it away again
            for _ in range(w.rng.randint(3, 8)):
                await node.apply(w.transfer(), tag="bcd"[round_])
    finally:
        await node.close()


async def test_a_write_outside_any_block_forces_the_full_rebuild():
    w = Workload(9)
    node = await Node.create(w)
    try:
        for txs in w.script()[:2]:
            await node.apply(txs)
        for _ in range(8):
            await node.apply([])
        cur = await node.db.connection.execute(  # a write outside any block: unattributed
            "UPDATE account_state SET balance = '1' WHERE rowid = "
            "(SELECT MIN(rowid) FROM account_state)")
        assert cur.rowcount == 1
        await node.db.connection.commit()
        tip = await node.db.get_next_block_id() - 1
        res = await node.rollback(tip - 2)
        assert "base" not in res  # the full replay — which also discards the stray write
        assert await node.state() == await _full(node)
    finally:
        await node.close()


# ── Restarts (derived_state_rebuild.persist_checkpoint / load_persisted_checkpoint) ─────────
# A restart used to replay every derived domain from genesis: the exchange lives in memory. The
# finalized base checkpoint and the exchange journal are now persisted every
# PERSIST_INTERVAL_BLOCKS, and a restart takes the reorg fast path from it.

def _forget_everything_in_memory():
    from qrdx import derived_state_rebuild as D

    ExchangeStateManager.reset_instance()
    CHECKPOINTS.clear()
    D._LAST_EPOCH.clear()
    D._PERSISTED.clear()


async def test_a_restart_from_the_persisted_checkpoint_equals_the_full_replay(monkeypatch):
    from qrdx import derived_state_rebuild as D

    monkeypatch.setattr(D, "PERSIST_INTERVAL_BLOCKS", 4)
    w = Workload(5)
    node = await Node.create(w)
    try:
        for txs in w.script():
            await node.apply(txs)
        for _ in range(12):
            await node.apply(w.transfer())
        tip = await node.db.get_next_block_id() - 1
        await D.prune_reorg_state(node.db, tip - 3)          # finality: the base is persisted
        await node.db.connection.commit()
        persisted = D._PERSISTED["height"]
        for _ in range(7):                                   # blocks above the checkpoint
            await node.apply(w.transfer())
        before = await node.state()

        _forget_everything_in_memory()                       # the restart
        assert await D.load_persisted_checkpoint(node.db) == persisted
        res = await D.rebuild_to_tip(node.db)
        assert res["base"] == persisted and res["blocks"] < 12
        assert await node.state() == before
        assert await node.state() == await _full(node)
    finally:
        await node.close()


async def test_a_checkpoint_whose_block_was_orphaned_is_not_used(monkeypatch):
    from qrdx import derived_state_rebuild as D

    monkeypatch.setattr(D, "PERSIST_INTERVAL_BLOCKS", 1)
    w = Workload(6)
    node = await Node.create(w)
    try:
        for txs in w.script():
            await node.apply(txs)
        for _ in range(6):
            await node.apply(w.transfer())
        tip = await node.db.get_next_block_id() - 1
        await D.prune_reorg_state(node.db, tip)
        await node.db.connection.commit()
        persisted = D._PERSISTED["height"]
        await node.db.remove_blocks(persisted)               # its block left the chain
        for _ in range(4):
            await node.apply(w.transfer(), tag="z")
        _forget_everything_in_memory()
        assert await D.load_persisted_checkpoint(node.db) is None   # → the full rebuild
    finally:
        await node.close()



async def test_a_rejected_section_is_undone_by_the_fast_path():
    """No per-block revert point: a section applied and then refused (a wrong declared root) is
    undone by the restore every import path runs, rebuild_to_tip. The block is not stored, so
    the state at the tip is the state before it — databases, exchange and journal."""
    from qrdx.exchange.block_processor import apply_block_exchange_section

    w = Workload(8)
    node = await Node.create(w)
    try:
        for txs in w.script():
            await node.apply(txs)
        for _ in range(9):
            await node.apply(w.transfer())
        before = await node.state()
        height = await node.db.get_next_block_id()
        bad = [w.tx(w.k1, ExchangeOpType.TOKEN_TRANSFER, token_address=w.tokenA, to=w.t2,
                    amount="77")]
        async with await before_block(node.db, height, (height * SPACING) // S):
            await BP.preload_sender_balances(node.db, bad, node.mgr)
            await BP.preload_token_balances(node.db, bad, node.mgr)
            ok, err = apply_block_exchange_section(height, float(TS0 + height * SPACING),
                                                   encode_exchange_txs(bad), "ab" * 64, node.mgr)
        assert not ok and "mismatch" in err
        assert (await node.state())["exchange"] != before["exchange"]
        await rebuild_to_tip(node.db)
        assert await node.state() == before
    finally:
        await node.close()
