"""
Reorg equivalence for the validator-stake debit.

The stake debit rides ``flush_exchange_balance_deltas``, the same flush the reorg
rebuild re-applies — so a chain containing STAKE_DEPOSITs must rebuild to the SAME
``account_state`` root as incremental forward application. If it did not, a reorged
node would disagree with the network about every staker's balance at equal tip, which
is this codebase's most-repeated failure mode (a rebuild running with a different
enforce-flag set than the forward path).

Covers both outcomes, because they must BOTH replay identically:
  * an affordable deposit (debited on both paths);
  * an unaffordable deposit included in a canonical block (rejected on both paths —
    if the rebuild ran without ``enforce_validator_stake`` it would instead ACCEPT and
    debit, diverging).
"""
import json
import os
import tempfile
from decimal import Decimal

from exchange_fees import fee_of

from qrdx.constants import MIN_VALIDATOR_STAKE
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.exchange import (
    ExchangeOpType, ExchangeStateManager, ExchangeTransaction, encode_exchange_txs,
)
from qrdx.exchange import block_processor as BP


async def _db():
    path = tempfile.mktemp(suffix=".db")
    return await DatabaseSQLite.create(db_path=path), path


def _sign(tx, key):
    tx.public_key = key.public_key.to_bytes()
    tx.signature = key.sign(tx.signing_bytes()).to_bytes()
    return tx


def _tx(op, sender, nonce, params):
    return ExchangeTransaction(op_type=op, sender=sender, nonce=nonce, params=params,
                              gas_limit=2_000_000, gas_price=10**9)


async def _add_block(db, height, ex_section=None, genesis_alloc=None):
    bh = f"{height:064x}"
    await db.add_block(block_hash=bh, block_height=height, block_content="",
                       validator_address="0xPQ" + "00" * 32,
                       timestamp=1_700_000_000 + height)
    for i, (recipient, amount) in enumerate(genesis_alloc or []):
        await db.add_transaction(
            tx_hash=f"alloc-{height}-{i}",
            tx_hex=json.dumps({"type": "genesis_allocation",
                               "recipient": recipient, "amount": str(amount)}),
            block_hash=bh)
    if ex_section:
        await db.add_block_exchange_txs(bh, ex_section)
    return bh


def _set_flags(mgr):
    """The production enforcement set, through the one function every path uses."""
    BP.apply_enforcement(mgr)


async def _run_forward(db, tip):
    await db.seed_genesis_account_state()
    await db.connection.commit()
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    _set_flags(mgr)
    for h in range(tip + 1):
        bh = f"{h:064x}"
        section = await db.get_block_exchange_txs(bh)
        if not section:
            continue
        txs = BP.decode_exchange_txs(section)
        await BP.preload_sender_balances(db, txs, mgr)
        await BP.preload_token_balances(db, txs, mgr)
        BP.process_exchange_transactions(h, float(1_700_000_000 + h), txs, mgr)
        mgr.commit_block()
        await BP.flush_exchange_balance_deltas(
            db, mgr, enforce=BP.ENFORCE_EXCHANGE_COLLATERAL)
        await BP.flush_token_balance_deltas(db, mgr)
    await db.connection.commit()
    return await db.get_account_state_root()


async def _run_rebuild(db):
    await db.clear_account_state()
    await db.seed_genesis_account_state()
    await db.connection.commit()
    await db.clear_token_balances()
    ExchangeStateManager.reset_instance()
    await BP.rebuild_exchange_state_from_chain(db, flush_to_account_state=True)
    await db.connection.commit()
    return await db.get_account_state_root()


async def test_rebuild_matches_forward_with_staking_deposits():
    db, path = await _db()
    try:
        rich, poor = PQPrivateKey.generate(), PQPrivateKey.generate()
        rich_addr = rich.public_key.to_address()
        poor_addr = poor.public_key.to_address()

        # `rich` can afford the stake; `poor` cannot (its deposit is canonical but
        # must be REJECTED on both paths).
        await _add_block(db, 0, genesis_alloc=[(rich_addr, "1000000"),
                                               (poor_addr, "1000")])
        await _add_block(db, 1, encode_exchange_txs([_sign(_tx(
            ExchangeOpType.STAKE_DEPOSIT, rich_addr, 0,
            {"validator_public_key": rich.public_key.to_hex(),
             "stake_amount": str(MIN_VALIDATOR_STAKE)}), rich)]))
        await _add_block(db, 2, encode_exchange_txs([_sign(_tx(
            ExchangeOpType.STAKE_DEPOSIT, poor_addr, 0,
            {"validator_public_key": poor.public_key.to_hex(),
             "stake_amount": str(MIN_VALIDATOR_STAKE)}), poor)]))

        forward_root = await _run_forward(db, 2)
        forward_rich = await db.get_address_balance(rich_addr)
        forward_poor = await db.get_address_balance(poor_addr)

        # Forward path: the affordable stake is locked, the unaffordable one is not; both
        # executed, so both paid their gas.
        gas = fee_of(ExchangeOpType.STAKE_DEPOSIT)
        assert forward_rich == Decimal("1000000") - MIN_VALIDATOR_STAKE - gas
        assert forward_poor == Decimal("1000") - gas, "a rejected deposit takes only its gas"

        rebuild_root = await _run_rebuild(db)

        assert rebuild_root == forward_root, (
            f"account_state root diverges after rebuild with staking: "
            f"forward={forward_root[:16]} rebuild={rebuild_root[:16]}")
        assert await db.get_address_balance(rich_addr) == forward_rich
        assert await db.get_address_balance(poor_addr) == forward_poor
    finally:
        await db.close()
        os.remove(path)


async def test_the_debit_is_recorded_only_when_the_gate_is_on():
    """
    The gate must guard the DELTA RECORDING, not merely the flush.

    ``flush_exchange_balance_deltas`` is already enforced for collateral, so a debit
    recorded while this gate is off would be applied anyway — the stake would start
    moving the moment collateral enforcement was on, regardless of this gate. That is
    the exact mistake the pool-stake rollout hit, so it is pinned here: with the gate
    off nothing is recorded; with it on, exactly the stake is.
    """
    from types import SimpleNamespace

    from qrdx.exchange.transactions import ExchangeOpType as OT

    key = PQPrivateKey.generate()
    addr = key.public_key.to_address()
    tx = SimpleNamespace(
        sender=addr, nonce=0, op_type=OT.STAKE_DEPOSIT,
        params={"validator_public_key": key.public_key.to_hex(),
                "stake_amount": str(MIN_VALIDATOR_STAKE)})

    for gate in (False, True):
        mgr = ExchangeStateManager()
        mgr.enforce_collateral = True          # the shared flush is enforced
        mgr.enforce_validator_stake = gate
        mgr.begin_block(1, 0.0)
        mgr.set_available_balance(addr, Decimal("1000000"))
        res = mgr._op_stake_deposit(tx)
        mgr.commit_block()
        assert res.success, res.error
        deltas = dict(mgr.balance_deltas())
        if gate:
            assert deltas.get(addr) == -MIN_VALIDATOR_STAKE, (
                "gate ON must record exactly the stake as a debit")
        else:
            assert deltas == {}, (
                "gate OFF must record NO delta — the shared flush is already enforced, "
                "so a recorded delta would debit anyway")


async def test_a_deposit_is_still_registered_when_affordable_after_rebuild():
    """
    Sanity companion to the root check: rebuilding a chain whose deposit was affordable
    must leave the staker debited by exactly the stake, once — not twice (the rebuild
    re-applies the flush onto a freshly reseeded ledger, so a double-apply would show
    up as 2x the stake).
    """
    db, path = await _db()
    try:
        rich = PQPrivateKey.generate()
        addr = rich.public_key.to_address()
        await _add_block(db, 0, genesis_alloc=[(addr, "1000000")])
        await _add_block(db, 1, encode_exchange_txs([_sign(_tx(
            ExchangeOpType.STAKE_DEPOSIT, addr, 0,
            {"validator_public_key": rich.public_key.to_hex(),
             "stake_amount": str(MIN_VALIDATOR_STAKE)}), rich)]))

        await _run_forward(db, 1)
        await _run_rebuild(db)

        expected = Decimal("1000000") - MIN_VALIDATOR_STAKE - fee_of(ExchangeOpType.STAKE_DEPOSIT)
        assert await db.get_address_balance(addr) == expected, (
            "rebuild applied the stake debit a different number of times than forward")
    finally:
        await db.close()
        os.remove(path)
