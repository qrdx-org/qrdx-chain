"""
A failed transaction must still cost gas and consume its nonce.

On failure `ExecutionContext.finalize_execution` reverts the EVM snapshot. That revert is
what makes a failure safe — no state changes survive — but it also rolled back the gas
charge and the nonce increment that `execute()` had applied. Only the *state changes*
should roll back.

The consequences of the old behaviour:

  * **free failed execution** — an attacker makes every node do the work and pays nothing;
  * **infinite retry at one nonce** — nothing advanced, so the same transaction could be
    resubmitted forever;
  * and it contradicted the importer's own documented assumption:
    `apply_block_evm_section`'s comment says a reverted transaction "is still validly
    included and still mutates state (nonce/gas)", which was untrue.

Gas charged is `min(gas_limit, max(consumed, intrinsic))` — the same rule as the success
path, so a failure is never cheaper than the floor and never exceeds what the sender
authorised.
"""
import os
import tempfile
from decimal import Decimal

import pytest
from eth_account import Account as EthAccount
from eth_utils import to_checksum_address

from qrdx.contracts.state import ContractStateManager
from qrdx.crypto.account_id import to_account_id
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.node import main as node_main

WEI = 10 ** 18
GWEI = 10 ** 9
KEY = "0x" + "c3" * 32
RECIPIENT = "0x" + "cd" * 20


def _account():
    return to_account_id(EthAccount.from_key(KEY).address)


def _raw(nonce, value=WEI, gas=100_000, gas_price=GWEI, data=b""):
    signed = EthAccount.sign_transaction(
        {"nonce": nonce, "gasPrice": gas_price, "gas": gas,
         "to": to_checksum_address(RECIPIENT), "value": value, "data": data,
         "chainId": 1}, KEY)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    return "0x" + bytes(raw).hex()


async def _env(funding_qrdx="10"):
    from qrdx.contracts.evm_executor_v2 import QRDXEVMExecutor

    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    await db.apply_account_balance_delta(_account(), Decimal(funding_qrdx))
    await db.connection.commit()
    sm = ContractStateManager(db)
    saved = (node_main.db, node_main.EVM_STATE_MANAGER, node_main.EVM_EXECUTOR,
             dict(node_main.EVM_PENDING_NONCE))
    node_main.db = db
    node_main.EVM_STATE_MANAGER = sm
    node_main.EVM_EXECUTOR = QRDXEVMExecutor(sm)
    node_main.EVM_PENDING_NONCE.clear()
    return db, sm, saved


async def _close(db, saved):
    (node_main.db, node_main.EVM_STATE_MANAGER, node_main.EVM_EXECUTOR,
     pending) = saved
    node_main.EVM_PENDING_NONCE.clear()
    node_main.EVM_PENDING_NONCE.update(pending)
    path = db.db_path
    await db.close()
    os.remove(path)


async def _balance(sm, address):
    """
    Read the balance the way the execution path sees it.

    ``get_balance_sync`` is cache-only and returns 0 from a cold cache, so a "before"
    reading taken with it would be 0 rather than the funded balance — the execution path
    warms the cache from ``account_state`` via ``prepare_execution``.
    """
    return await sm.get_balance(address)


async def _execute(raw, height=1):
    return await node_main._execute_evm_raw_tx(
        raw, height, f"{height:064x}", 1_700_000_000 + height)


def test_the_gate_is_on_by_default():
    """
    Pins the shipped default so flipping it is deliberate.

    This was briefly defaulted OFF on a suspicion that the charge amplified reorg churn; a
    controlled A/B refuted it (a flag-OFF run at the same 20 reorgs diverged WORSE — 19
    differing block hashes and a three-way token split, against 10 and a two-way split with
    the flag on). Failures track churn, not this flag. See "Block history did not converge" in docs/KNOWN_ISSUES.md.
    """
    import importlib
    import os

    saved = os.environ.pop("QRDX_ENFORCE_FAILED_TX_COSTS", None)
    try:
        importlib.reload(node_main)
        assert node_main._ENFORCE_FAILED_TX_COSTS is True
    finally:
        if saved is not None:
            os.environ["QRDX_ENFORCE_FAILED_TX_COSTS"] = saved
        importlib.reload(node_main)


@pytest.fixture(autouse=True)
def _force_the_gate_on(monkeypatch):
    """
    Pin the gate ON for the behaviour tests regardless of the ambient env var, so an
    operator running with QRDX_ENFORCE_FAILED_TX_COSTS=0 still exercises this code.
    """
    monkeypatch.setattr(node_main, "_ENFORCE_FAILED_TX_COSTS", True)


# ── A failure that cannot afford its value ─────────────────────────────────

async def test_an_overspending_transaction_still_pays_gas():
    """
    Sender holds 10 QRDX and tries to send 100. Execution fails, no value moves — but the
    attempt is not free.
    """
    db, sm, saved = await _env(funding_qrdx="10")
    try:
        before = await _balance(sm, _account())
        res = await _execute(_raw(0, value=100 * WEI))

        assert not res["success"]
        after = await _balance(sm, _account())
        assert after < before, "a failed transaction was free"
        assert sm.get_balance_sync(RECIPIENT) == 0, "a failed transaction moved value"
    finally:
        await _close(db, saved)


async def test_a_failure_consumes_its_nonce():
    """Otherwise the same transaction can be resubmitted forever."""
    db, sm, saved = await _env(funding_qrdx="10")
    try:
        assert sm.get_nonce_sync(_account()) == 0
        res = await _execute(_raw(0, value=100 * WEI))
        assert not res["success"]
        assert sm.get_nonce_sync(_account()) == 1, "a failed transaction left its nonce free"
    finally:
        await _close(db, saved)


async def test_the_same_failed_transaction_cannot_be_retried():
    """The nonce has moved on, so the replay check now refuses it."""
    db, sm, saved = await _env(funding_qrdx="10")
    try:
        raw = _raw(0, value=100 * WEI)
        first = await _execute(raw)
        assert not first["success"]
        balance_after_first = sm.get_balance_sync(_account())

        second = await _execute(raw, height=2)
        assert not second["success"]
        assert "invalid nonce" in second["error"], (
            "a failed transaction was resubmittable at the same nonce")
        # And the refused retry costs nothing extra (it is a no-op, not an execution).
        assert sm.get_balance_sync(_account()) == balance_after_first
    finally:
        await _close(db, saved)


async def test_the_gas_charged_is_at_least_the_intrinsic_floor():
    db, sm, saved = await _env(funding_qrdx="10")
    try:
        from qrdx.contracts.evm_mempool import intrinsic_gas_legacy

        before = await _balance(sm, _account())
        res = await _execute(_raw(0, value=100 * WEI, gas_price=GWEI))
        floor = intrinsic_gas_legacy(b"")
        charged = (before - await _balance(sm, _account())) // GWEI
        assert charged >= floor, f"charged {charged} gas, below the {floor} floor"
        assert res.get("gas_charged") is not None
    finally:
        await _close(db, saved)


async def test_the_charge_never_exceeds_the_authorised_gas_limit():
    db, sm, saved = await _env(funding_qrdx="10")
    try:
        limit = 30_000
        before = await _balance(sm, _account())
        await _execute(_raw(0, value=100 * WEI, gas=limit, gas_price=GWEI))
        charged = (before - await _balance(sm, _account())) // GWEI
        assert charged <= limit, f"charged {charged} gas against a {limit} limit"
    finally:
        await _close(db, saved)


async def test_a_sender_who_cannot_cover_the_gas_is_clamped_not_negative():
    """
    Clamping keeps this deterministic rather than raising mid-block. The affordability
    check belongs at admission.
    """
    db, sm, saved = await _env(funding_qrdx="10")
    try:
        # A gas price high enough that the fee alone exceeds the balance.
        await _execute(_raw(0, value=100 * WEI, gas=100_000, gas_price=10 ** 15))
        assert sm.get_balance_sync(_account()) >= 0, "balance went negative"
    finally:
        await _close(db, saved)


async def test_a_zero_gas_price_failure_still_consumes_the_nonce():
    """Cost can legitimately be zero; replayability must not be."""
    db, sm, saved = await _env(funding_qrdx="10")
    try:
        res = await _execute(_raw(0, value=100 * WEI, gas_price=0))
        assert not res["success"]
        assert sm.get_nonce_sync(_account()) == 1
    finally:
        await _close(db, saved)


# ── Successes are unaffected ───────────────────────────────────────────────

async def test_a_successful_transaction_is_unaffected():
    db, sm, saved = await _env(funding_qrdx="10")
    try:
        res = await _execute(_raw(0, value=WEI, gas_price=0))
        assert res["success"], res.get("error")
        assert sm.get_balance_sync(RECIPIENT) == WEI
        assert sm.get_nonce_sync(_account()) == 1
    finally:
        await _close(db, saved)


async def test_the_sender_can_continue_after_a_failure():
    """
    The nonce advanced by exactly one, so the sender's next transaction uses the next
    nonce and succeeds — no gap, no stuck account.
    """
    db, sm, saved = await _env(funding_qrdx="10")
    try:
        assert not (await _execute(_raw(0, value=100 * WEI, gas_price=0)))["success"]
        assert sm.get_nonce_sync(_account()) == 1

        ok = await _execute(_raw(1, value=WEI, gas_price=0), height=2)
        assert ok["success"], ok.get("error")
        assert sm.get_balance_sync(RECIPIENT) == WEI
        assert sm.get_nonce_sync(_account()) == 2
    finally:
        await _close(db, saved)


# ── Determinism ────────────────────────────────────────────────────────────

async def test_two_nodes_charge_a_failure_identically():
    """
    The charge lands in account_state and therefore in the declared account root, so two
    nodes executing the same failed transaction must agree exactly.
    """
    envs = [await _env(funding_qrdx="10"), await _env(funding_qrdx="10")]
    try:
        roots, balances, nonces = [], [], []
        for db, sm, saved in envs:
            node_main.db, node_main.EVM_STATE_MANAGER = db, sm
            from qrdx.contracts.evm_executor_v2 import QRDXEVMExecutor
            node_main.EVM_EXECUTOR = QRDXEVMExecutor(sm)
            await _execute(_raw(0, value=100 * WEI, gas_price=GWEI))
            await sm.commit(1)
            await db.connection.commit()
            roots.append(await db.get_account_state_root())
            balances.append(sm.get_balance_sync(_account()))
            nonces.append(sm.get_nonce_sync(_account()))

        assert balances[0] == balances[1], f"balances diverged: {balances}"
        assert nonces[0] == nonces[1] == 1
        assert roots[0] == roots[1], "account_state root diverged on a failed transaction"
    finally:
        for env in envs:
            await _close(env[0], env[2])


async def test_the_pending_nonce_tracker_advances_on_failure_too():
    """Otherwise the mempool would keep accepting the failed nonce."""
    db, sm, saved = await _env(funding_qrdx="10")
    try:
        await _execute(_raw(0, value=100 * WEI, gas_price=0))
        assert node_main.EVM_PENDING_NONCE.get(_account().lower()) == 1
    finally:
        await _close(db, saved)
