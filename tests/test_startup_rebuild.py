"""
A restarted node must hold the same derived state as one that never stopped.

Exchange state lives only in memory, so startup replays it from the chain. The old replay
ran the exchange sections alone, with every enforcement gate off and no balances loaded —
so an op the network REJECTED (here, a perp deposit the trader cannot afford) was
ACCEPTED on replay. The restarted node's exchange root then differed from the
network's, and it rejected every later block carrying an exchange section.

Startup now runs the interleaved rebuild (qrdx/derived_state_rebuild.py), which recomputes
each block's balances as it replays and so makes the network's decisions.
"""
import inspect
import logging
import os
from decimal import Decimal

from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import ExchangeOpType, ExchangeStateManager, encode_exchange_txs
from qrdx.exchange import block_processor as BP
from qrdx.node import main as node_main

from test_interleaved_rebuild_equivalence import _add_block, _db, _forward
from test_reorg_rebuild_equivalence import _sign, _tx


async def _chain_with_a_rejected_position(db, monkeypatch):
    """t1 opens a perp market and, as its configured oracle reporter, prices it; poor t2 then
    tries to deposit 3,000 QRDX of perp collateral holding 10. Forward application rejects
    that (enforced, balances pre-loaded); an unenforced replay would accept it."""
    from qrdx import constants
    k1, k2 = PQPrivateKey.generate(), PQPrivateKey.generate()
    t1, t2 = k1.public_key.to_address(), k2.public_key.to_address()
    monkeypatch.setattr(constants, "ORACLE_REPORTERS", (t1,))
    await _add_block(db, 0, genesis_alloc=[(t1, "1000000"), (t2, "10")])
    await _add_block(db, 1, encode_exchange_txs([
        _sign(_tx(ExchangeOpType.CREATE_MARKET, t1, 0,
                  {"base_token": "BTC", "max_leverage": "10", "initial_margin_rate": "0.1",
                   "maintenance_margin_rate": "0.05"}), k1),
        _sign(_tx(ExchangeOpType.UPDATE_ORACLE, t1, 1,
                  {"pair": "BTC:QRDX", "price": "30000"}), k1)]))
    await _add_block(db, 2, encode_exchange_txs([_sign(_tx(
        ExchangeOpType.PERP_DEPOSIT, t2, 0, {"amount": "3000"}), k2)]))
    # An affordable deposit too, so the clearinghouse carries real state on both paths.
    await _add_block(db, 3, encode_exchange_txs([_sign(_tx(
        ExchangeOpType.PERP_DEPOSIT, t1, 2, {"amount": "10000"}), k1)]))
    return t1, t2


async def _restart(db):
    """What a fresh process does: new exchange singleton, then the real startup hook."""
    ExchangeStateManager.reset_instance()
    saved = node_main.db, node_main.EVM_STATE_MANAGER
    node_main.db, node_main.EVM_STATE_MANAGER = db, None
    try:
        await node_main._rebuild_derived_state_on_startup()
    finally:
        node_main.db, node_main.EVM_STATE_MANAGER = saved
    return ExchangeStateManager.get_instance().compute_state_root()


async def test_restart_reproduces_the_forward_exchange_root(caplog, monkeypatch):
    db, path = await _db()
    try:
        t1, t2 = await _chain_with_a_rejected_position(db, monkeypatch)
        await _forward(db, 3)
        fwd_exchange = ExchangeStateManager.get_instance().compute_state_root()
        fwd_account = await db.get_account_state_root()
        fwd_token = await db.get_token_balances_root()
        fwd_balances = (await db.get_address_balance(t1), await db.get_address_balance(t2))
        assert fwd_balances[1] == Decimal("10"), "forward must reject t2's deposit"

        with caplog.at_level(logging.INFO):
            restart_exchange = await _restart(db)

        assert restart_exchange == fwd_exchange, (
            "a restarted node's exchange root differs from a node that never stopped")
        assert await db.get_account_state_root() == fwd_account
        assert await db.get_token_balances_root() == fwd_token
        assert (await db.get_address_balance(t1), await db.get_address_balance(t2)) == fwd_balances
        assert "[RESTART-REBUILD]" not in caplog.text, "durable state matched; no mismatch expected"
    finally:
        await db.close()
        os.remove(path)


async def test_the_old_exchange_only_replay_diverges_on_this_chain(monkeypatch):
    """Sensitivity: the chain really exposes the old replay (so the test above is not vacuous)."""
    db, path = await _db()
    try:
        await _chain_with_a_rejected_position(db, monkeypatch)
        await _forward(db, 3)
        fwd_exchange = ExchangeStateManager.get_instance().compute_state_root()

        ExchangeStateManager.reset_instance()
        assert await BP.rebuild_exchange_state_from_chain(db) != fwd_exchange
    finally:
        await db.close()
        os.remove(path)


async def test_a_durable_state_mismatch_is_reported_and_repaired(caplog, monkeypatch):
    """Every restart doubles as an equivalence check: a durable ledger that disagrees with
    the chain is logged as [RESTART-REBUILD] and replaced by the chain-derived state."""
    db, path = await _db()
    try:
        t1, _ = await _chain_with_a_rejected_position(db, monkeypatch)
        await _forward(db, 3)
        fwd_account = await db.get_account_state_root()

        await db.apply_account_balance_delta(t1, Decimal("123"))   # durable drift
        await db.connection.commit()
        assert await db.get_account_state_root() != fwd_account

        with caplog.at_level(logging.ERROR):
            await _restart(db)
        assert "[RESTART-REBUILD]" in caplog.text
        assert await db.get_account_state_root() == fwd_account
    finally:
        await db.close()
        os.remove(path)


def test_startup_initialises_evm_then_rebuilds_before_anything_consumes_state():
    src = inspect.getsource(node_main.startup)
    init = src.index("EVM_STATE_MANAGER = ContractStateManager(db)")
    rebuild = src.index("await _rebuild_derived_state_on_startup()")
    assert init < rebuild, "the rebuild replays EVM sections, so EVM must be initialised first"
    for consumer in ("initialize_validator_node(", "epoch_validator_update_loop(db)",
                     "chain_event_poller("):
        assert rebuild < src.index(consumer), (
            f"{consumer} starts before derived state is rebuilt — it would act on the "
            f"unreplayed exchange state")
    # The RPC modules share the one instance; a second ContractStateManager would leave
    # the consensus path and the RPC handler on different caches.
    assert src.count("ContractStateManager(db)") == 1


async def test_a_rebuild_interrupted_by_a_crash_is_repaired_at_the_next_start(caplog, monkeypatch):
    """
    A rebuild clears account_state and the token ledger (committed) before replaying. A node
    stopped in between — seen in a fault-injecting soak, where the orchestrator stopped a
    node one second into a reorg rebuild — is left with genesis balances and an empty token
    ledger. The old startup never rebuilt either, so that state was permanent. Now the next
    start reconstructs it from the chain.
    """
    db, path = await _db()
    try:
        t1, t2 = await _chain_with_a_rejected_position(db, monkeypatch)
        await _forward(db, 3)
        fwd_account = await db.get_account_state_root()
        fwd_token = await db.get_token_balances_root()

        # Exactly what the rebuild has committed when it is interrupted after its reset step.
        await db.clear_account_state()
        await db.seed_genesis_account_state()
        await db.connection.commit()
        await db.clear_token_balances()
        assert await db.get_account_state_root() != fwd_account

        with caplog.at_level(logging.ERROR):
            await _restart(db)
        assert "[RESTART-REBUILD]" in caplog.text
        assert await db.get_account_state_root() == fwd_account
        assert await db.get_token_balances_root() == fwd_token
    finally:
        await db.close()
        os.remove(path)
