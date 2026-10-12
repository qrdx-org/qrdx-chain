"""
Staked principal must come back after a completed exit — inside block application.

The first refund lived in the epoch loop's incremental path, which the live configuration
never reaches, and it could not simply be moved: it credits account_state (bound into the
E-D4 unified root) from an asynchronous loop, so nodes would disagree on the root
depending on loop timing. Withdrawals are therefore computed and applied per block, from
chain-derived records only (qrdx/validator/withdrawals.py).

The properties that matter:
  * the payable set is a pure function of records from blocks BEFORE the current one plus
    the current block's epoch — the determinism the unified root depends on;
  * nothing is paid before the exit epoch, nothing is paid twice, and the amount is
    exactly what was deposited (supply-neutral) — forfeiture on slashing and the
    withdrawability delay are covered in test_withdrawal_delay_and_forfeit.py;
  * a rollback-rebuild ends with the same balances as forward application.
"""
import os
import tempfile
from decimal import Decimal

import pytest

from qrdx.constants import MIN_VALIDATOR_STAKE
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.validator import withdrawals as W

from pq_addrs import pq

STAKE = MIN_VALIDATOR_STAKE


@pytest.fixture(autouse=True)
def _gate_on(monkeypatch):
    monkeypatch.setattr(W, "ENFORCE_VALIDATOR_WITHDRAWALS", True)
    # These tests predate the withdrawability delay and are about other properties; the
    # delay has its own tests in test_withdrawal_delay_and_forfeit.py.
    monkeypatch.setattr(W, "WITHDRAWAL_DELAY_EPOCHS", 0)


async def _db():
    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    await W.ensure_tables(db)
    return db


async def _close(db):
    path = db.db_path
    await db.close()
    os.remove(path)


async def _stake(db, who, *, funded="500000", deposit_height=10, exit_height=20,
                 exit_epoch=30):
    """Fund → deposit (debited, logged) → exit (logged), as block application does."""
    await db.apply_account_balance_delta(who, Decimal(funded))
    await db.apply_account_balance_delta(who, -STAKE)
    await db.log_validator_deposit(who, "ab" * 100, STAKE, deposit_height)
    if exit_height is not None:
        await W.record_validator_exit(db, who, exit_epoch, exit_height)
    await db.connection.commit()


def test_the_gate_defaults_on():
    """Pins the shipped default; flipping it changes the unified root, so it is deliberate."""
    import importlib
    saved = os.environ.pop("QRDX_ENFORCE_VALIDATOR_WITHDRAWALS", None)
    try:
        mod = importlib.reload(W)
        assert mod.ENFORCE_VALIDATOR_WITHDRAWALS is True
    finally:
        if saved is not None:
            os.environ["QRDX_ENFORCE_VALIDATOR_WITHDRAWALS"] = saved
        importlib.reload(W)


# ── When and how much ─────────────────────────────────────────────────────

async def test_nothing_is_paid_before_the_exit_epoch():
    db = await _db()
    try:
        who = pq("early")
        await _stake(db, who, exit_epoch=30)
        assert await W.compute_payable_withdrawals(db, block_height=50, block_epoch=29) == []
    finally:
        await _close(db)


async def test_the_principal_is_paid_at_the_exit_epoch():
    db = await _db()
    try:
        who = pq("on-time")
        await _stake(db, who, exit_epoch=30)
        assert await db.get_address_balance(who) == Decimal("500000") - STAKE

        paid = await W.process_block_withdrawals(db, block_height=50, block_epoch=30)
        await db.connection.commit()

        assert paid == 1
        assert await db.get_address_balance(who) == Decimal("500000"), (
            "staked principal was not returned — supply-neutral staking requires it")
    finally:
        await _close(db)


async def test_a_withdrawal_is_paid_exactly_once():
    db = await _db()
    try:
        who = pq("once")
        await _stake(db, who, exit_epoch=30)
        await W.process_block_withdrawals(db, block_height=50, block_epoch=30)
        await db.connection.commit()
        again = await W.process_block_withdrawals(db, block_height=51, block_epoch=31)
        await db.connection.commit()
        assert again == 0
        assert await db.get_address_balance(who) == Decimal("500000")
    finally:
        await _close(db)


async def test_a_locally_recorded_offence_does_not_forfeit():
    """
    ``slashing_events`` also holds offences a node detected LOCALLY from gossip, so two
    nodes can disagree on it at any block. Forfeiture reads only evidence carried in
    canonical blocks (test_withdrawal_delay_and_forfeit.py); a local-only record must not
    change what a block pays, or the nodes' roots split.
    """
    db = await _db()
    try:
        who = pq("locally-accused")
        await _stake(db, who, exit_epoch=30)
        await db.record_slashing_event(who, "DOUBLE_SIGN", 100, 12, "evidence")
        await db.connection.commit()
        assert [w[0] for w in await W.compute_payable_withdrawals(db, 50, 30)] == [who]
    finally:
        await _close(db)


async def test_an_active_validator_is_not_paid():
    db = await _db()
    try:
        who = pq("still-active")
        await _stake(db, who, exit_height=None)
        assert await W.compute_payable_withdrawals(db, 999, 999) == []
    finally:
        await _close(db)


async def test_records_from_the_current_block_are_not_consulted():
    """
    Only records from blocks strictly BEFORE the current one count: the importer applies a
    block's own sections before its withdrawals, so reading same-block records would make
    the result depend on application order.
    """
    db = await _db()
    try:
        who = pq("same-block")
        await _stake(db, who, deposit_height=10, exit_height=50, exit_epoch=30)
        assert await W.compute_payable_withdrawals(db, block_height=50, block_epoch=40) == []
        assert len(await W.compute_payable_withdrawals(db, block_height=51, block_epoch=40)) == 1
    finally:
        await _close(db)


async def test_exit_redeposit_exit_pays_each_stake_once():
    db = await _db()
    try:
        who = pq("cycler")
        await _stake(db, who, deposit_height=10, exit_height=20, exit_epoch=30)
        assert await W.process_block_withdrawals(db, 50, 30) == 1
        await db.connection.commit()
        # Re-stake, exit again.
        await db.apply_account_balance_delta(who, -STAKE)
        await db.log_validator_deposit(who, "ab" * 100, STAKE, 60)
        await W.record_validator_exit(db, who, 80, 70)
        await db.connection.commit()
        assert await W.process_block_withdrawals(db, 90, 80) == 1
        await db.connection.commit()
        assert await db.get_address_balance(who) == Decimal("500000"), (
            "a second stake cycle was paid the wrong amount")
    finally:
        await _close(db)


async def test_top_ups_are_returned_in_full():
    db = await _db()
    try:
        who = pq("topped-up")
        await _stake(db, who, exit_height=None)
        await db.apply_account_balance_delta(who, -Decimal("50000"))
        await db.log_validator_deposit(who, "ab" * 100, Decimal("50000"), 12)
        await W.record_validator_exit(db, who, 30, 20)
        await db.connection.commit()
        assert await W.process_block_withdrawals(db, 50, 30) == 1
        await db.connection.commit()
        assert await db.get_address_balance(who) == Decimal("500000")
    finally:
        await _close(db)


async def test_the_gate_off_pays_nothing(monkeypatch):
    monkeypatch.setattr(W, "ENFORCE_VALIDATOR_WITHDRAWALS", False)
    db = await _db()
    try:
        await _stake(db, pq("gated"), exit_epoch=30)
        assert await W.process_block_withdrawals(db, 50, 30) == 0
    finally:
        await _close(db)


# ── Determinism ────────────────────────────────────────────────────────────

async def test_two_nodes_compute_the_same_list_and_root():
    """The unified root binds the credits, so both nodes must agree exactly."""
    dbs = [await _db(), await _db()]
    try:
        people = [pq(f"det-{i}") for i in range(4)]
        for db in dbs:
            for i, who in enumerate(people):
                await _stake(db, who, deposit_height=10 + i, exit_height=20 + i,
                             exit_epoch=30 + (i % 2))
        lists, roots = [], []
        for db in dbs:
            lists.append(await W.compute_payable_withdrawals(db, 60, 31))
            await W.process_block_withdrawals(db, 60, 31)
            await db.connection.commit()
            roots.append(await db.get_account_state_root())
        assert lists[0] == lists[1] and len(lists[0]) == 4
        assert roots[0] == roots[1]
    finally:
        for db in dbs:
            await _close(db)


# ── Reorg safety ───────────────────────────────────────────────────────────

async def test_rollback_rebuild_matches_forward_application():
    """
    A rollback rebuilds account_state from genesis plus EVM/exchange sections, which a
    withdrawal is not. Without the ledger re-credit the rebuild silently drops paid
    withdrawals — the same class of bug that once dropped 0x genesis funding.
    """
    db = await _db()
    try:
        kept, orphaned = pq("kept"), pq("orphaned")
        await _stake(db, kept, exit_epoch=30)
        await _stake(db, orphaned, exit_epoch=30)
        # Block 50 pays `kept`; block 70 (to be orphaned) pays `orphaned`.
        await W.apply_withdrawals(db, [(kept, 30, STAKE)], 50)
        await W.apply_withdrawals(db, [(orphaned, 30, STAKE)], 70)
        await db.connection.commit()

        # Rollback to height 60. Model the rebuild: account_state back to its pre-block
        # state (funding − stake), exactly as the chain replay would produce.
        await db.clear_account_state()
        for who in (kept, orphaned):
            await db.apply_account_balance_delta(who, Decimal("500000") - STAKE)
        await W.undo_withdrawal_logs_above(db, 60)
        await W.reapply_withdrawal_ledger(db)
        await db.connection.commit()

        assert await db.get_address_balance(kept) == Decimal("500000"), (
            "a canonical withdrawal was lost across the rollback rebuild")
        assert await db.get_address_balance(orphaned) == Decimal("500000") - STAKE, (
            "a withdrawal from an orphaned block survived the rollback")
        # And the orphaned one is payable again on the new canonical chain.
        assert [w[0] for w in await W.compute_payable_withdrawals(db, 61, 30)] == [orphaned]
    finally:
        await _close(db)


async def test_an_orphaned_exit_is_forgotten():
    db = await _db()
    try:
        who = pq("orphaned-exit")
        await _stake(db, who, exit_height=70, exit_epoch=30)
        await W.undo_withdrawal_logs_above(db, 60)
        await db.connection.commit()
        assert await W.compute_payable_withdrawals(db, 100, 99) == []
    finally:
        await _close(db)


# ── Wiring: every path must actually reach this ────────────────────────────
#
# The first refund passed its unit tests while never running in production. So these
# assert each consensus path calls the mechanism, and — because the unified root must
# bind the credits identically on both sides — that it sits AFTER the EVM section and
# BEFORE the root is computed or verified. Source-level: the paths are live-node code
# with no seam to drive them in a unit test.

import inspect

from source_text import source_of


def _between(src, before, target, after):
    b, t, a = src.index(before), src.index(target), src.index(after)
    return b < t < a


def test_the_proposer_applies_withdrawals_before_computing_the_root():
    from qrdx.validator import node_integration
    src = source_of(node_integration)
    assert _between(src, "_evm_section_producer(", "process_block_withdrawals(",
                    "_compute_unified_state_root(")


def test_the_sync_import_path_applies_withdrawals_before_e_d4():
    from qrdx.node import main
    src = source_of(main)
    sync = src[src.index('logger.warning(f"[SYNC] Rejecting PoS block {block_height}: {verr_evm}")'):]
    assert _between(sync, "Rejecting PoS block", "_apply_block_withdrawals_on_import(",
                    "_verify_unified_state_root(")


def test_the_rest_import_path_applies_withdrawals_before_e_d4():
    from qrdx.node import main
    src = source_of(main)
    rest = src[src.index("return {'ok': False, 'error': f'Invalid EVM section: {verr_evm}'}"):]
    assert _between(rest, "Invalid EVM section", "_apply_block_withdrawals_on_import(",
                    "_verify_unified_state_root(block_content)")


def test_the_p2p_import_path_applies_withdrawals_before_e_d4():
    from qrdx.rpc.modules import p2p
    src = source_of(p2p)
    assert _between(src, "self._evm_apply_section(", "process_block_withdrawals(",
                    "self._verify_unified_root(block_content)")


def test_exits_are_logged_with_their_carrying_block():
    from qrdx.exchange import block_processor
    src = source_of(block_processor.flush_validator_lifecycle_deltas)
    assert "record_validator_exit(" in src


def test_the_rollback_rebuild_restores_the_ledger():
    from qrdx.node import main
    src = source_of(main._rebuild_derived_state_after_rollback)
    # Orphaned rows must be trimmed BEFORE the rebuild, which re-credits every row left.
    assert "undo_withdrawal_logs_above(" in src and "rebuild_to_tip(" in src
    assert src.index("undo_withdrawal_logs_above(") < src.index("rebuild_to_tip(")
    # The A/B-only by-domain path re-credits after its account_state rebuild, or the
    # re-credit would be wiped by it.
    old = source_of(main._rebuild_derived_state_by_domain)
    assert old.index("rebuild_account_state_from_chain") < old.index("reapply_withdrawal_ledger(")


async def test_the_flush_actually_records_an_exit():
    """Behavioural, not just source: a STAKE_EXIT through the real flush lands in the log."""
    from types import SimpleNamespace
    from qrdx.exchange.block_processor import flush_validator_lifecycle_deltas
    from qrdx.exchange.state_manager import ExchangeStateManager
    from qrdx.exchange.transactions import ExchangeOpType

    db = await _db()
    try:
        who = pq("flush-exit")
        mgr = ExchangeStateManager()
        mgr.begin_block(40, 0.0)
        mgr._op_stake_exit(SimpleNamespace(sender=who, nonce=1,
                                           op_type=ExchangeOpType.STAKE_EXIT, params={}))
        mgr.commit_block()
        await flush_validator_lifecycle_deltas(db, mgr, block_epoch=5, block_height=40)
        await db.connection.commit()
        cur = await db.connection.execute(
            "SELECT block_height, address, exit_epoch FROM validator_exits")
        rows = await cur.fetchall()
        from qrdx.constants import UNBONDING_PERIOD_EPOCHS
        assert [tuple(r) for r in rows] == [(40, who, 5 + UNBONDING_PERIOD_EPOCHS)]
    finally:
        await _close(db)


# ── An exit must never be silently dropped ─────────────────────────────────

async def test_an_exit_in_the_activation_epoch_is_not_dropped():
    """
    An exit landing in the very epoch a validator was due to activate used to hit a
    still-pending validator, no-op, and leave it active forever. With withdrawals that is an
    exploit: refunded AND still stake-weighted. It must leave and never propose.
    """
    from qrdx.validator.epoch_state import EpochInputs, genesis_state, proposers, transition

    genesis = [{"address": pq(f"wd-genesis-{i}"), "stake": str(STAKE)} for i in range(4)]
    who = pq("exits-while-pending")
    s = genesis_state(genesis)
    s = transition(s, 1, EpochInputs([("deposit", who, "cd", STAKE)], [], []))
    activation = s[who].activation_epoch
    for e in range(2, activation):
        s = transition(s, e, EpochInputs([], [], []))
    s = transition(s, activation, EpochInputs([("exit", who, None, None)], [], []))
    for e in range(activation + 1, activation + 4):
        s = transition(s, e, EpochInputs([], [], []))
        assert s[who].status == "exited" and who not in dict(proposers(s)), e


async def test_an_ejected_validator_is_paid_without_claiming(monkeypatch):
    """Stake-floor ejection leaves no exit operation on the chain. The validator set records
    it (validator/epoch_state.py), and the principal is paid once the exit epoch plus the
    withdrawal delay has passed — it used to need a STAKE_EXIT of its own to claim it."""
    from qrdx import constants
    from qrdx.validator import epoch_state as ES
    from qrdx.validator import withdrawals as W
    from test_epoch_state import Chain

    monkeypatch.setattr(constants, "UNBONDING_PERIOD_EPOCHS", 3)   # (else 40,320 epochs)
    monkeypatch.setattr(W, "WITHDRAWAL_DELAY_EPOCHS", 2)
    db = await _db()
    try:
        chain = Chain(db)
        await chain.genesis(stakes=(100_000, 100_000, 100_000))
        joiner = pq("ejected-joiner")
        await chain.epoch(1, deposits=[(joiner, str(STAKE))])
        # Never attests, and its stake is marked down below the floor once active.
        delay = constants.ACTIVATION_DELAY_EPOCHS
        for e in range(2, 3 + delay):
            await chain.epoch(e)
        state = await ES.state_at(db, 2 + delay)
        assert state[joiner].status == "active"
        state[joiner].effective_stake = Decimal("1")       # (as if decayed; cached state)
        await ES._store(db, 2 + delay, (await ES._checkpoint(db, 2 + delay, None))[1], state)
        await chain.epoch(2 + delay)
        after = await ES.state_at(db, 3 + delay)
        assert after[joiner].status == "exiting"
        exit_epoch = after[joiner].exit_epoch
        due = exit_epoch + W.WITHDRAWAL_DELAY_EPOCHS
        not_yet, _ = await W.compute_block_withdrawals(db, chain.height + 1, due - 1)
        assert not_yet == []
        paid, forfeited = await W.compute_block_withdrawals(db, chain.height + 1, due)
        assert paid == [(joiner, exit_epoch, STAKE)] and forfeited == []
    finally:
        await _close(db)
