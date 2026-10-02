"""
A validator's stake must be REAL.

A ``STAKE_DEPOSIT``'s claimed ``stake_amount`` becomes the validator's
``effective_stake`` in the consensus ``validators`` table, and that figure weights
BOTH stake-weighted proposer selection (``consensus.select_proposer``) and
fork-choice attesting weight. The join path previously checked neither ownership nor
the ``MIN_VALIDATOR_STAKE`` floor that the local registration API and epoch
activation already applied — so an account holding NOTHING could register with an
arbitrary stake and outweigh the entire honest set. That is consensus capture, not
an accounting error.

These tests pin the three properties that close it, plus the two that keep it safe
under this chain's failure modes:

  1. a deposit below ``MIN_VALIDATOR_STAKE`` is rejected;
  2. a deposit the sender cannot afford is rejected, and registers no validator;
  3. an affordable deposit is genuinely DEBITED from ``account_state``;
  4. rejection and debit are deterministic across independent nodes (the validators
     table and account_state must stay byte-identical);
  5. the principal comes back at the deterministic finalized exit epoch — and a
     SLASHED validator never gets it back.
"""
import os
import tempfile
from decimal import Decimal
from types import SimpleNamespace

import pytest

from qrdx.constants import MIN_VALIDATOR_STAKE
from qrdx.crypto.account_id import to_account_id
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.exchange.block_processor import (
    ENFORCE_EXCHANGE_COLLATERAL,
    ENFORCE_VALIDATOR_STAKE,
    flush_exchange_balance_deltas,
    flush_validator_lifecycle_deltas,
    preload_sender_balances,
)
from qrdx.exchange.state_manager import ExchangeStateManager
from qrdx.exchange.transactions import ExchangeOpType

from pq_addrs import pq


def _deposit_tx(sender, stake, pubkey="ab" * 100, nonce=0):
    return SimpleNamespace(
        sender=sender, nonce=nonce, op_type=ExchangeOpType.STAKE_DEPOSIT,
        params={"validator_public_key": pubkey, "stake_amount": str(stake)},
    )


def _exit_tx(sender, nonce=1):
    return SimpleNamespace(sender=sender, nonce=nonce,
                           op_type=ExchangeOpType.STAKE_EXIT, params={})


async def _node(funded=None, holder=None):
    """A fresh DB + manager with the production enforce flags."""
    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    if funded is not None and holder is not None:
        await db.apply_account_balance_delta(holder, Decimal(str(funded)))
        await db.connection.commit()
    mgr = ExchangeStateManager()
    mgr.enforce_collateral = ENFORCE_EXCHANGE_COLLATERAL
    mgr.enforce_validator_stake = ENFORCE_VALIDATOR_STAKE
    return db, mgr


async def _run_deposit(db, mgr, tx, block_epoch=0):
    mgr.begin_block(1, 0.0)
    await preload_sender_balances(db, [tx], mgr)
    res = mgr._op_stake_deposit(tx)
    mgr.commit_block()
    await flush_exchange_balance_deltas(db, mgr, enforce=ENFORCE_EXCHANGE_COLLATERAL)
    await flush_validator_lifecycle_deltas(db, mgr, block_epoch=block_epoch)
    await db.connection.commit()
    return res


async def _close(db):
    path = db.db_path
    await db.close()
    os.remove(path)


def test_the_gate_is_on():
    """If this ever flips to False the checks below stop protecting anything."""
    assert ENFORCE_VALIDATOR_STAKE is True, "validator-stake enforcement must stay ON"


# ── 1 + 2. Forged and undersized stakes are refused ────────────────────────

async def test_zero_balance_account_cannot_register_a_forged_stake():
    """
    The consensus-capture case: claim a stake larger than the honest set while
    holding nothing. Must be refused AND leave no validator row behind.
    """
    attacker = pq("attacker-nothing")
    db, mgr = await _node()
    try:
        res = await _run_deposit(db, mgr, _deposit_tx(attacker, "999999999"))
        assert not res.success
        assert "insufficient balance" in res.error
        assert await db.get_validators() == [], "a forged deposit registered a validator"
        assert await db.get_address_balance(attacker) == 0
    finally:
        await _close(db)


async def test_underfunded_deposit_is_refused():
    staker = pq("underfunded")
    db, mgr = await _node(funded="50000", holder=staker)
    try:
        res = await _run_deposit(db, mgr, _deposit_tx(staker, MIN_VALIDATOR_STAKE))
        assert not res.success and "insufficient balance" in res.error
        assert await db.get_validators() == []
        # Nothing was taken from a rejected deposit.
        assert await db.get_address_balance(staker) == Decimal("50000")
    finally:
        await _close(db)


async def test_deposit_below_the_minimum_is_refused():
    """
    MIN_VALIDATOR_STAKE was enforced by the local registration API and by epoch
    activation, but NOT by the consensus join path — so a 1-QRDX validator could join.
    """
    staker = pq("dust-staker")
    db, mgr = await _node(funded="500000", holder=staker)
    try:
        res = await _run_deposit(db, mgr, _deposit_tx(staker, "1000"))
        assert not res.success and "below minimum" in res.error
        assert await db.get_validators() == []
        assert await db.get_address_balance(staker) == Decimal("500000")
    finally:
        await _close(db)


@pytest.mark.parametrize("stake", ["0", "-1", "-100000"])
async def test_non_positive_stake_is_refused(stake):
    staker = pq(f"nonpositive-{stake}")
    db, mgr = await _node(funded="500000", holder=staker)
    try:
        res = await _run_deposit(db, mgr, _deposit_tx(staker, stake))
        assert not res.success
        assert await db.get_validators() == []
    finally:
        await _close(db)


async def test_unverifiable_balance_is_refused_rather_than_assumed_solvent():
    """
    If the sender's balance could not be pre-loaded the deposit must be refused, not
    waved through — admitting an unverified stake is the whole vulnerability.
    """
    staker = pq("no-preload")
    db, mgr = await _node(funded="500000", holder=staker)
    try:
        mgr.begin_block(1, 0.0)
        mgr.clear_available_balances()          # simulate a missing pre-load
        res = mgr._op_stake_deposit(_deposit_tx(staker, MIN_VALIDATOR_STAKE))
        mgr.commit_block()
        assert not res.success and "balance unavailable" in res.error
    finally:
        await _close(db)


# ── 3. An honest stake is genuinely locked ─────────────────────────────────

async def test_affordable_deposit_is_debited_and_registers_the_validator():
    staker = pq("honest-staker")
    db, mgr = await _node(funded="500000", holder=staker)
    try:
        res = await _run_deposit(db, mgr, _deposit_tx(staker, MIN_VALIDATOR_STAKE))
        assert res.success, res.error

        # The stake really left the account — it is at risk, and cannot be respent.
        assert await db.get_address_balance(staker) == Decimal("500000") - MIN_VALIDATOR_STAKE

        validators = await db.get_validators()
        assert len(validators) == 1
        row = validators[0]
        assert Decimal(str(row["stake"])) == MIN_VALIDATOR_STAKE
        assert Decimal(str(row["effective_stake"])) == MIN_VALIDATOR_STAKE
        assert row["status"] == "pending"
    finally:
        await _close(db)


async def test_the_debit_lands_on_the_canonical_account_row():
    """
    The debit must hit the same 20-byte account id the EVM and genesis use, not a
    separate PQ-keyed row — otherwise the stake would appear locked while remaining
    spendable through the other form.
    """
    staker = pq("canonical-staker")
    db, mgr = await _node(funded="500000", holder=staker)
    try:
        assert (await _run_deposit(db, mgr, _deposit_tx(staker, MIN_VALIDATOR_STAKE))).success
        expected = Decimal("500000") - MIN_VALIDATOR_STAKE
        assert await db.get_address_balance(staker) == expected
        assert await db.get_address_balance(to_account_id(staker)) == expected
        cur = await db.connection.execute("SELECT COUNT(*) FROM account_state")
        assert (await cur.fetchone())[0] == 1, "stake debit split the account into two rows"
    finally:
        await _close(db)


async def test_a_staker_cannot_double_spend_the_locked_stake():
    """Deposit the whole balance, then try to deposit again — nothing is left."""
    staker = pq("double-spender")
    db, mgr = await _node(funded=str(MIN_VALIDATOR_STAKE), holder=staker)
    try:
        assert (await _run_deposit(db, mgr, _deposit_tx(staker, MIN_VALIDATOR_STAKE))).success
        assert await db.get_address_balance(staker) == 0
        second = await _run_deposit(
            db, mgr, _deposit_tx(staker, MIN_VALIDATOR_STAKE, nonce=1))
        assert not second.success and "insufficient balance" in second.error
    finally:
        await _close(db)


# ── 4. Determinism across nodes ────────────────────────────────────────────

async def test_two_nodes_agree_on_the_debit_and_the_validator_set():
    """
    Eligibility is enforced off the validators table, so two nodes replaying the same
    deposit must end byte-identical in BOTH the table and account_state.
    """
    staker = pq("convergent-staker")
    db1, mgr1 = await _node(funded="500000", holder=staker)
    db2, mgr2 = await _node(funded="500000", holder=staker)
    try:
        r1 = await _run_deposit(db1, mgr1, _deposit_tx(staker, MIN_VALIDATOR_STAKE))
        r2 = await _run_deposit(db2, mgr2, _deposit_tx(staker, MIN_VALIDATOR_STAKE))
        assert r1.success and r2.success
        assert await db1.get_address_balance(staker) == await db2.get_address_balance(staker)
        assert await db1.get_validators_table_hash() == await db2.get_validators_table_hash()
        assert await db1.get_account_state_root() == await db2.get_account_state_root()
    finally:
        await _close(db1)
        await _close(db2)


async def test_two_nodes_agree_on_a_rejection():
    """A rejected deposit must change nothing, identically, on both nodes."""
    attacker = pq("convergent-attacker")
    db1, mgr1 = await _node(funded="1000", holder=attacker)
    db2, mgr2 = await _node(funded="1000", holder=attacker)
    try:
        r1 = await _run_deposit(db1, mgr1, _deposit_tx(attacker, "999999999"))
        r2 = await _run_deposit(db2, mgr2, _deposit_tx(attacker, "999999999"))
        assert not r1.success and not r2.success
        assert await db1.get_validators_table_hash() == await db2.get_validators_table_hash()
        assert await db1.get_account_state_root() == await db2.get_account_state_root()
        assert await db1.get_address_balance(attacker) == Decimal("1000")
    finally:
        await _close(db1)
        await _close(db2)


# ── 5. The stake comes back on exit — but not to a slashed validator ───────

async def test_exit_refunds_the_principal_at_the_finalized_exit_epoch():
    from qrdx.validator.epoch_loop import (
        _collect_exit_stake_refunds, _refund_exited_validator_stakes,
    )

    staker = pq("exiting-staker")
    db, mgr = await _node(funded="500000", holder=staker)
    try:
        assert (await _run_deposit(db, mgr, _deposit_tx(staker, MIN_VALIDATOR_STAKE))).success
        after_deposit = await db.get_address_balance(staker)
        assert after_deposit == Decimal("500000") - MIN_VALIDATOR_STAKE

        # Reach the exit: activate, then request exit.
        await db.connection.execute(
            "UPDATE validators SET status = 'exiting', exit_epoch = 5 WHERE address = ?",
            (staker,))
        await db.connection.commit()

        exiting = await db.get_validators_to_exit(5)
        assert exiting == [staker]
        refunds = await _collect_exit_stake_refunds(db, exiting)
        assert refunds == {staker: MIN_VALIDATOR_STAKE}
        await _refund_exited_validator_stakes(db, refunds, epoch=5)
        await db.connection.commit()

        # Supply-neutral: the principal is back, nothing minted.
        assert await db.get_address_balance(staker) == Decimal("500000")
    finally:
        await _close(db)


async def test_a_slashed_validator_forfeits_its_stake():
    """
    Slashing moves a validator to status 'slashed', which get_validators_to_exit does
    not select — so it is never refunded. That forfeiture is what makes the penalty
    real rather than a status label.
    """
    from qrdx.validator.epoch_loop import _collect_exit_stake_refunds

    slashed = pq("slashed-staker")
    db, mgr = await _node(funded="500000", holder=slashed)
    try:
        assert (await _run_deposit(db, mgr, _deposit_tx(slashed, MIN_VALIDATOR_STAKE))).success
        await db.connection.execute(
            "UPDATE validators SET status = 'slashed', exit_epoch = 5 WHERE address = ?",
            (slashed,))
        await db.connection.commit()

        assert await db.get_validators_to_exit(5) == [], "a slashed validator must not exit-refund"
        assert await _collect_exit_stake_refunds(db, await db.get_validators_to_exit(5)) == {}
        # The stake stays gone.
        assert await db.get_address_balance(slashed) == Decimal("500000") - MIN_VALIDATOR_STAKE
    finally:
        await _close(db)


async def test_refund_is_principal_only_not_accrued_rewards():
    """
    effective_stake also carries attestation rewards; refunding those would MINT them
    into account_state. The refund tracks the deposited principal so staking is exactly
    supply-neutral.
    """
    from qrdx.validator.epoch_loop import _collect_exit_stake_refunds

    staker = pq("rewarded-staker")
    db, mgr = await _node(funded="500000", holder=staker)
    try:
        assert (await _run_deposit(db, mgr, _deposit_tx(staker, MIN_VALIDATOR_STAKE))).success
        # Simulate accrued rewards inflating effective_stake well above principal.
        await db.connection.execute(
            "UPDATE validators SET status = 'exiting', exit_epoch = 5, "
            "effective_stake = ? WHERE address = ?",
            (str(MIN_VALIDATOR_STAKE + Decimal("77777")), staker))
        await db.connection.commit()

        refunds = await _collect_exit_stake_refunds(db, await db.get_validators_to_exit(5))
        assert refunds == {staker: MIN_VALIDATOR_STAKE}, "refund must not include rewards"
    finally:
        await _close(db)
