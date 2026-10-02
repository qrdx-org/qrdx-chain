"""
An already-executed transaction must not be executable again.

The hole: nothing compared a transaction's nonce to the sender's ACCOUNT nonce during
execution. Mempool admission checked a nonce window, but against ``EVM_PENDING_NONCE`` —
an in-memory dict lost on restart — and the dedup cache was in-memory too. So after a node
restart an already-executed signed transaction could be re-submitted, re-admitted
(expected nonce back to 0), and **re-executed**, moving value a second time.

Two defences, both tested here:

  1. ``_ENFORCE_TX_NONCE`` in the shared execution path — the authoritative check. It is
     compared against the durable account nonce, so it survives restarts and is identical
     on every node replaying the same chain.
  2. ``_rehydrate_evm_pending_nonces`` at startup — restores the mempool's expectations
     from the durable nonces so a replay is refused at the door rather than only at
     execution, which also keeps it out of a proposer's selection.

A mismatched transaction is rejected as a **no-op**, not by invalidating its block. See the
comment on ``_ENFORCE_TX_NONCE`` for why, and docs/KNOWN_ISSUES.md for the trade-off.
"""
import os
import tempfile

import pytest
from eth_account import Account as EthAccount

from qrdx.contracts.state import ContractStateManager
from qrdx.crypto.account_id import to_account_id
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.node import main as node_main

WEI = 10 ** 18
SENDER_KEY = "0x" + "a1" * 32
RECIPIENT = "0x" + "cd" * 20


def _signed_tx(nonce, value=WEI, key=SENDER_KEY, gas=100_000):
    from eth_utils import to_checksum_address
    signed = EthAccount.sign_transaction(
        {"nonce": nonce, "gasPrice": 0, "gas": gas,
         "to": to_checksum_address(RECIPIENT), "value": value, "data": b"",
         "chainId": 1}, key)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    return "0x" + bytes(raw).hex()


def _sender_account():
    return to_account_id(EthAccount.from_key(SENDER_KEY).address)


async def _evm_env(funding_qrdx="100"):
    """
    A real DB + state manager + executor, wired into main's globals.

    Funding goes into ``account_state`` rather than only the EVM cache: the execution
    path calls ``prepare_execution`` → ``sync_address_to_evm``, which reads the durable
    balance and OVERWRITES the cached one, so a cache-only balance would be wiped to 0.
    This mirrors how genesis funds accounts.
    """
    from decimal import Decimal

    from qrdx.contracts.evm_executor_v2 import QRDXEVMExecutor

    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    await db.apply_account_balance_delta(_sender_account(), Decimal(funding_qrdx))
    await db.connection.commit()
    sm = ContractStateManager(db)
    saved = (node_main.db, node_main.EVM_STATE_MANAGER, node_main.EVM_EXECUTOR)
    node_main.db = db
    node_main.EVM_STATE_MANAGER = sm
    node_main.EVM_EXECUTOR = QRDXEVMExecutor(sm)
    return db, sm, saved


def _restore(saved):
    node_main.db, node_main.EVM_STATE_MANAGER, node_main.EVM_EXECUTOR = saved


async def _close(db, saved):
    _restore(saved)
    path = db.db_path
    await db.close()
    os.remove(path)


async def _execute(raw, height=1):
    return await node_main._execute_evm_raw_tx(
        raw, height, f"{height:064x}", 1_700_000_000 + height)


def test_the_gate_is_on():
    assert node_main._ENFORCE_TX_NONCE is True, (
        "nonce validity must stay ON — it is the only thing stopping a replayed "
        "transaction from executing twice")


# ── The replay itself ──────────────────────────────────────────────────────

async def test_replaying_an_executed_transaction_is_refused():
    """The core property: the same signed bytes cannot move value twice."""
    db, sm, saved = await _evm_env()
    try:
        raw = _signed_tx(0)
        first = await _execute(raw)
        assert first["success"], first.get("error")
        after_first = sm.get_balance_sync(RECIPIENT)
        assert after_first == WEI

        # Replay the identical bytes.
        second = await _execute(raw, height=2)
        assert not second["success"]
        assert "invalid nonce" in second["error"]
        assert "replay" in second["error"]
        assert sm.get_balance_sync(RECIPIENT) == after_first, (
            "a replayed transaction moved value a second time")
    finally:
        await _close(db, saved)


async def test_a_replay_leaves_the_senders_balance_untouched():
    db, sm, saved = await _evm_env()
    try:
        raw = _signed_tx(0)
        await _execute(raw)
        sender_after = sm.get_balance_sync(_sender_account())
        await _execute(raw, height=2)
        assert sm.get_balance_sync(_sender_account()) == sender_after
    finally:
        await _close(db, saved)


async def test_a_stale_nonce_from_further_back_is_refused():
    db, sm, saved = await _evm_env()
    try:
        for n in range(3):
            res = await _execute(_signed_tx(n), height=n + 1)
            assert res["success"], res.get("error")
        assert sm.get_nonce_sync(_sender_account()) == 3

        for stale in (0, 1, 2):
            res = await _execute(_signed_tx(stale), height=10)
            assert not res["success"], f"stale nonce {stale} was accepted"
            assert "replay" in res["error"]
    finally:
        await _close(db, saved)


async def test_a_future_nonce_is_refused_without_the_replay_wording():
    """A gap-ahead transaction is also invalid, but it is not a replay."""
    db, sm, saved = await _evm_env()
    try:
        res = await _execute(_signed_tx(7))
        assert not res["success"]
        assert "invalid nonce" in res["error"]
        assert "replay" not in res["error"]
        assert sm.get_balance_sync(RECIPIENT) == 0
    finally:
        await _close(db, saved)


async def test_the_correct_sequence_still_executes():
    """The check must not break ordinary use."""
    db, sm, saved = await _evm_env()
    try:
        for n in range(4):
            res = await _execute(_signed_tx(n), height=n + 1)
            assert res["success"], f"nonce {n} rejected: {res.get('error')}"
        assert sm.get_balance_sync(RECIPIENT) == 4 * WEI
        assert sm.get_nonce_sync(_sender_account()) == 4
    finally:
        await _close(db, saved)


async def test_a_rejected_transaction_reports_its_hash_so_the_block_still_imports():
    """
    Deliberate design choice: a mismatched nonce rejects the TRANSACTION, not the block.
    ``apply_block_evm_section`` rejects a block only when a transaction returns no
    tx_hash, so returning one keeps a nonce disagreement from becoming an import halt —
    and keeps a poisoned mempool entry from making a proposer drop its whole EVM section.
    State is untouched either way, identically on every node, so roots still agree.
    """
    db, sm, saved = await _evm_env()
    try:
        res = await _execute(_signed_tx(9))
        assert not res["success"]
        assert res["tx_hash"] is not None, (
            "a nonce rejection must not look like an un-executable tx, or it would "
            "reject the whole block")
    finally:
        await _close(db, saved)


async def test_two_senders_have_independent_nonce_sequences():
    db, sm, saved = await _evm_env()
    try:
        from decimal import Decimal
        other_key = "0x" + "b2" * 32
        other_account = to_account_id(EthAccount.from_key(other_key).address)
        await db.apply_account_balance_delta(other_account, Decimal("100"))
        await db.connection.commit()

        assert (await _execute(_signed_tx(0)))["success"]
        # The second sender's first transaction is still nonce 0.
        res = await _execute(_signed_tx(0, key=other_key), height=2)
        assert res["success"], res.get("error")
        assert sm.get_nonce_sync(_sender_account()) == 1
        assert sm.get_nonce_sync(other_account) == 1
    finally:
        await _close(db, saved)


# ── Startup rehydration ────────────────────────────────────────────────────

async def test_pending_nonces_are_rehydrated_from_durable_account_state():
    """
    Without this the mempool's expected nonce resets to 0 on restart, so a replay is
    admitted and only stopped at execution — after it has been gossiped and possibly
    selected by a proposer.
    """
    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    saved_db, saved_pending = node_main.db, dict(node_main.EVM_PENDING_NONCE)
    try:
        node_main.db = db
        node_main.EVM_PENDING_NONCE.clear()

        a, b, fresh = "0x" + "11" * 20, "0x" + "22" * 20, "0x" + "33" * 20
        for addr, nonce in ((a, 5), (b, 2), (fresh, 0)):
            await db.connection.execute(
                "INSERT INTO account_state (address, balance, nonce, created_at, "
                "updated_at, is_contract) VALUES (?, '0', ?, 0, 0, 0)", (addr, nonce))
        await db.connection.commit()

        loaded = await node_main._rehydrate_evm_pending_nonces()

        assert loaded == 2, "only non-zero nonces need restoring"
        assert node_main.EVM_PENDING_NONCE[a] == 5
        assert node_main.EVM_PENDING_NONCE[b] == 2
        assert fresh not in node_main.EVM_PENDING_NONCE
    finally:
        node_main.db = saved_db
        node_main.EVM_PENDING_NONCE.clear()
        node_main.EVM_PENDING_NONCE.update(saved_pending)
        path = db.db_path
        await db.close()
        os.remove(path)


async def test_rehydration_never_lowers_a_live_expectation():
    """A live in-memory expectation ahead of the durable nonce must win."""
    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    saved_db, saved_pending = node_main.db, dict(node_main.EVM_PENDING_NONCE)
    try:
        node_main.db = db
        addr = "0x" + "44" * 20
        node_main.EVM_PENDING_NONCE.clear()
        node_main.EVM_PENDING_NONCE[addr] = 9      # pending txs already queued
        await db.connection.execute(
            "INSERT INTO account_state (address, balance, nonce, created_at, updated_at, "
            "is_contract) VALUES (?, '0', 4, 0, 0, 0)", (addr,))
        await db.connection.commit()

        await node_main._rehydrate_evm_pending_nonces()
        assert node_main.EVM_PENDING_NONCE[addr] == 9
    finally:
        node_main.db = saved_db
        node_main.EVM_PENDING_NONCE.clear()
        node_main.EVM_PENDING_NONCE.update(saved_pending)
        path = db.db_path
        await db.close()
        os.remove(path)


async def test_rehydration_is_best_effort_and_does_not_raise():
    """Correctness rests on the execution check; a rehydrate failure must not crash boot."""
    class Broken:
        class connection:
            @staticmethod
            async def execute(*_a, **_k):
                raise RuntimeError("no such table")

    saved_db = node_main.db
    try:
        node_main.db = Broken()
        assert await node_main._rehydrate_evm_pending_nonces() == 0
    finally:
        node_main.db = saved_db


# ── Mempool interaction ────────────────────────────────────────────────────

def test_the_mempool_refuses_a_stale_nonce_once_expectations_are_restored():
    from qrdx.contracts.evm_mempool import EVMMempool

    account = _sender_account()
    mp = EVMMempool(nonce_provider=lambda addr: {account: 3}.get(addr.lower(), 0))
    ok, err, _ = mp.admit(_signed_tx(0))
    assert not ok and "nonce too low" in err
    ok, err, _ = mp.admit(_signed_tx(3))
    assert ok, err
