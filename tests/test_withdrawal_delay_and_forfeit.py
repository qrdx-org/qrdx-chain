"""
When staked principal may leave, and when it is forfeited — both as pure functions of the chain.

Two defects in the first withdrawal design:

* **Forfeiture read node-local state.** A slashed validator's stake was forfeited if
  ``slashing_events`` held an offence for it. That table also holds offences a node detected
  LOCALLY from gossip and evidence the finality pass records asynchronously, so two nodes
  could disagree at the payout block — one pays, one does not, and their account roots
  split. Forfeiture now reads only verified evidence carried in canonical blocks before the
  paying block.
* **Payout before ineligibility.** Principal was paid at the head's ``exit_epoch``, but an
  exiting validator stays eligible until the FINALIZED epoch reaches it. An offence in that
  window would be slashed from a stake already returned. Payout now waits
  ``WITHDRAWAL_DELAY_EPOCHS`` beyond the exit epoch.
"""
import os
import tempfile
from decimal import Decimal

import pytest

from qrdx.constants import MIN_VALIDATOR_STAKE, UNBONDING_PERIOD_EPOCHS
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.exchange import ExchangeStateManager
from qrdx.exchange.block_processor import flush_validator_lifecycle_deltas
from qrdx.validator import withdrawals as W
from qrdx.validator.slashing_block import BLOCK_SLASHING_KEY, make_double_sign_evidence

from test_slashing_evidence import _signed_header

STAKE = MIN_VALIDATOR_STAKE
DELAY = 4
EXIT_EPOCH = 30


@pytest.fixture(autouse=True)
def _gates(monkeypatch):
    monkeypatch.setattr(W, "ENFORCE_VALIDATOR_WITHDRAWALS", True)
    monkeypatch.setattr(W, "WITHDRAWAL_DELAY_EPOCHS", DELAY)


@pytest.fixture
async def db():
    database = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    yield database
    path = database.db_path
    await database.close()
    os.remove(path)


async def _staked_exit(db, key, exit_epoch=EXIT_EPOCH):
    """A validator that funded, deposited (debited, logged) and exited (logged)."""
    who = key.public_key.to_address()
    await db.apply_account_balance_delta(who, Decimal("500000"))
    await db.apply_account_balance_delta(who, -STAKE)
    await db.register_pending_validator(who, "ab" * 100, STAKE, block_height=10)
    await W.record_validator_exit(db, who, exit_epoch, 20)
    await db.connection.commit()
    return who


async def _block_with_evidence(db, height, evidence):
    await db.add_block(block_hash=f"{height:064x}", block_height=height,
                       block_content=str({"number": height, BLOCK_SLASHING_KEY: evidence}),
                       validator_address="0xPQ" + "00" * 32, timestamp=1_700_000_000 + height)
    await db.connection.commit()


def _double_sign_by(key):
    h1, _ = _signed_header(key, slot=9, state_root="11" * 32)
    h2, _ = _signed_header(key, slot=9, state_root="22" * 32)
    return make_double_sign_evidence(h1, h2)


# ── withdrawability delay ─────────────────────────────────────────────────

async def test_principal_waits_out_the_withdrawability_delay(db):
    who = await _staked_exit(db, PQPrivateKey.generate())
    assert await W.compute_payable_withdrawals(db, 100, EXIT_EPOCH) == []
    assert await W.compute_payable_withdrawals(db, 100, EXIT_EPOCH + DELAY - 1) == []
    assert await W.compute_payable_withdrawals(db, 100, EXIT_EPOCH + DELAY) == [
        (who, EXIT_EPOCH, STAKE)]


def test_the_production_delay_is_long():
    from qrdx.constants import WITHDRAWAL_DELAY_EPOCHS
    if "QRDX_WITHDRAWAL_DELAY_EPOCHS" not in os.environ:
        assert WITHDRAWAL_DELAY_EPOCHS >= 256


# ── forfeiture from chain evidence ────────────────────────────────────────

async def test_evidence_in_an_earlier_block_forfeits_once(db):
    key = PQPrivateKey.generate()
    who = await _staked_exit(db, key)
    await _block_with_evidence(db, 60, [_double_sign_by(key)])

    paid = await W.process_block_withdrawals(db, 100, EXIT_EPOCH + DELAY)
    await db.connection.commit()
    assert paid == 0
    assert await db.get_address_balance(who) == Decimal("500000") - STAKE

    # Settled with a zero row, so later blocks neither pay nor rescan the chain.
    cur = await db.connection.execute(
        "SELECT amount, block_height FROM validator_withdrawals WHERE address = ?", (who,))
    assert [(Decimal(a), h) for a, h in await cur.fetchall()] == [(Decimal(0), 100)]
    assert await W.compute_block_withdrawals(db, 101, EXIT_EPOCH + DELAY + 1) == ([], [])


async def test_evidence_in_the_paying_block_or_later_does_not_count(db):
    """Only blocks strictly before the paying one are consulted — the same rule every
    other withdrawal input follows, so proposer and importer agree."""
    key = PQPrivateKey.generate()
    who = await _staked_exit(db, key)
    await _block_with_evidence(db, 100, [_double_sign_by(key)])
    assert [w[0] for w in await W.compute_payable_withdrawals(db, 100, EXIT_EPOCH + DELAY)] == [who]


async def test_evidence_against_someone_else_does_not_forfeit(db):
    """Including a forged name: an attacker's own double-sign labelled with the exiting
    validator's address convicts the attacker, so the victim is still paid."""
    victim_key, attacker = PQPrivateKey.generate(), PQPrivateKey.generate()
    who = await _staked_exit(db, victim_key)
    forged = _double_sign_by(attacker)
    forged["proposer"] = who
    await _block_with_evidence(db, 60, [forged])
    assert [w[0] for w in await W.compute_payable_withdrawals(db, 100, EXIT_EPOCH + DELAY)] == [who]


async def test_a_zero_row_never_touches_account_state(db):
    """Forfeits are settled with amount 0. The ledger re-credit paths must skip them —
    crediting 0 to an address with no account would create one and move the root."""
    root = await db.get_account_state_root()
    stranger = PQPrivateKey.generate().public_key.to_address()
    await db.connection.execute(
        "INSERT INTO validator_withdrawals (address, exit_epoch, amount, block_height) "
        "VALUES (?, ?, '0', ?)", (stranger, 1, 5))
    assert await W.reapply_withdrawal_ledger(db) == 0
    await db.connection.commit()
    assert await db.get_account_state_root() == root


# ── ejected validators claim with STAKE_EXIT ──────────────────────────────

async def test_an_ejected_validator_claims_its_principal_with_stake_exit(db):
    """
    The stake-floor sweep ejects inside the asynchronous reconstruction, so it leaves no
    exit record on chain and nothing is paid automatically. The validator claims by
    submitting STAKE_EXIT: the flush logs the exit even though the validator is no longer
    active, and the withdrawal pays it like any other.
    """
    who = PQPrivateKey.generate().public_key.to_address()
    await db.apply_account_balance_delta(who, Decimal("500000") - STAKE)
    await db.register_pending_validator(who, "ab" * 100, STAKE, block_height=10)
    await db.connection.execute(          # what the sweep does: exit it, below the floor
        "UPDATE validators SET status = 'exiting', exit_epoch = 12 WHERE address = ?", (who,))
    await db.connection.commit()

    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr._validator_lifecycle_ops.append({"type": "exit", "address": who})
    await flush_validator_lifecycle_deltas(db, mgr, block_epoch=20, block_height=200)
    await db.connection.commit()

    exit_epoch = 20 + UNBONDING_PERIOD_EPOCHS
    assert await W.compute_payable_withdrawals(db, 300, exit_epoch + DELAY) == [
        (who, exit_epoch, STAKE)]


# ── cost of the forfeiture scan ───────────────────────────────────────────

async def test_blocks_with_empty_evidence_are_never_parsed(db, monkeypatch):
    """Every block carries a ``slashing_evidence`` key, almost always empty, and blocks run
    to ~100 KB. Only blocks with evidence may reach the parser — in either stored form."""
    import json
    from qrdx.validator import block_verification as BV

    key = PQPrivateKey.generate()
    who = await _staked_exit(db, key)
    for h in range(30, 60):                          # the validator's own ordinary blocks
        body = {"number": h, "proposer_address": who, BLOCK_SLASHING_KEY: []}
        content = json.dumps(body) if h % 2 else str(body)
        await db.add_block(block_hash=f"{h:064x}", block_height=h, block_content=content,
                           validator_address=who, timestamp=1_700_000_000 + h)
    await _block_with_evidence(db, 60, [_double_sign_by(key)])

    parsed = []
    real = BV._parse_block_content
    # Count stored bodies (strings) only — verifying a proof also routes its two header
    # dicts through the same function.
    monkeypatch.setattr(BV, "_parse_block_content",
                        lambda c: (parsed.append(1) if isinstance(c, str) else None) or real(c))

    assert await W.slashed_on_chain(db, who, 100)
    assert len(parsed) == 1, f"parsed {len(parsed)} blocks; only the one with evidence should be"


async def test_nothing_to_pay_means_no_scan(db, monkeypatch):
    """An exit with nothing deposited (e.g. a genesis validator's) pays nothing, so there is
    nothing to forfeit and the chain is not scanned."""
    who = PQPrivateKey.generate().public_key.to_address()
    await W.record_validator_exit(db, who, EXIT_EPOCH, 20)
    await db.connection.commit()

    async def _no_scan(*_a, **_k):
        raise AssertionError("scanned the chain for an exit that pays nothing")
    monkeypatch.setattr(W, "slashed_on_chain", _no_scan)
    assert await W.compute_block_withdrawals(db, 100, EXIT_EPOCH + DELAY) == ([], [])
