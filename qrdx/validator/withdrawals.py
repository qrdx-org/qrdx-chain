"""
Validator stake withdrawals — returning staked principal after a completed exit.

Why this exists
---------------
A ``STAKE_DEPOSIT`` debits the staker's real balance (``ExchangeStateManager.
_op_stake_deposit``). Something has to give it back once the validator has exited, or
staked principal is locked forever. That refund was originally placed in the epoch loop,
which was wrong on two counts:

1. With reconstruction on (the live configuration) the epoch loop never reaches the
   incremental path the refund lived in — it was dead code.
2. It could not simply be moved: a refund credits ``account_state``, which is bound into
   the E-D4 unified state root. The epoch loop runs asynchronously, not at block
   boundaries, so two nodes would hold different ``account_state`` depending on whether
   their loop had processed the exit yet, and the next block import would fail the root
   check.

So withdrawals are applied **inside block application**, like Ethereum's EIP-4895: every
block computes the set of withdrawals that have become payable, credits them as part of
its own state transition, and the proposer and every importer do exactly the same thing
before the unified root is computed or verified.

Determinism — the whole design rests on it
------------------------------------------
The payable set must be a pure function of the canonical chain up to the parent block, or
proposer and importer disagree on the root. It therefore reads ONLY data written during
block application and reversed on rollback:

* ``validator_deposits`` — every consensus deposit, keyed to its carrying block;
* ``validator_exits``    — every consensus exit, keyed to its carrying block, with the
  exit epoch that block's epoch deterministically implies;
* ``validator_withdrawals`` — the ledger of what has already been paid (or forfeited);
* the canonical blocks themselves, for slashing evidence (see below).

It deliberately does NOT read the ``validators`` table, which the epoch loop rebuilds
asynchronously and which can therefore lag differently on different nodes — nor the
``slashing_events`` table, for the same reason: that table also holds offences a node
detected LOCALLY from gossip and evidence the finality pass recorded asynchronously, so two
nodes can disagree on it at any given block. The forfeiture check instead reads the
self-verifying DOUBLE_SIGN / attestation proofs carried in canonical blocks strictly before
this one — identical on every node.

Withdrawability delay
---------------------
An exiting validator stays eligible until the FINALIZED epoch reaches its ``exit_epoch``,
and finality trails the head. Paying at the head's ``exit_epoch`` would return the stake
while the validator could still propose and attest — any offence in that window would be
slashed from a stake that had already left. Principal is therefore payable only from
``exit_epoch + WITHDRAWAL_DELAY_EPOCHS`` (Ethereum's
``MIN_VALIDATOR_WITHDRAWABILITY_DELAY``), which covers the finality lag and the time for
evidence to be carried in a block. It does not cover a finality STALL longer than the
delay; see docs/KNOWN_ISSUES.md.

Reorg safety
------------
``account_state`` is rebuilt from the chain after a rollback, and a withdrawal is not an
EVM or exchange transaction, so the rebuild would silently drop it. Two steps restore it:
``undo_withdrawal_logs_above`` discards exit and withdrawal records from orphaned blocks,
then ``reapply_withdrawal_ledger`` re-credits every remaining — canonical — withdrawal onto
the freshly rebuilt ledger, the way genesis allocations are reseeded.

Scope
-----
Only exits recorded as ``STAKE_EXIT`` operations are paid. A validator ejected for
inactivity by the stake-floor sweep has no exit operation in the chain (the ejection is
derived from reward accrual inside the asynchronous reconstruction), so its principal is
not returned automatically: it claims it by submitting a ``STAKE_EXIT``, which is logged
even though the validator is no longer active (see ``flush_validator_lifecycle_deltas``)
and then paid like any other exit.
"""

from __future__ import annotations

import logging
import os
from decimal import Decimal
from typing import List, Tuple

from ..constants import WITHDRAWAL_DELAY_EPOCHS

logger = logging.getLogger(__name__)

# Consensus gate. MUST be identical on every node — a mismatch means one node credits a
# withdrawal the other does not, and their unified roots diverge. Env-overridable
# (QRDX_ENFORCE_VALIDATOR_WITHDRAWALS=0) for A/B testing only.
#
# ENABLED after a soak where s16's real deposit → exit round-trip returned the 100,000
# stake on all four nodes, with the exit logged identically everywhere and account_state
# byte-identical across nodes. Getting there required fixing three pre-existing bugs the
# earlier soaks exposed (see "Staked principal never returned on exit" in
# docs/KNOWN_ISSUES.md): the hardcoded 32-slot epoch in
# validator/config.py, epoch_from_block not reading the sync path's `content` key, and a
# pending validator's exit being silently dropped.
ENFORCE_VALIDATOR_WITHDRAWALS = os.getenv(
    "QRDX_ENFORCE_VALIDATOR_WITHDRAWALS", "1").lower() not in ("0", "false", "no")

Withdrawal = Tuple[str, int, Decimal]   # (address, exit_epoch, amount_qrdx)
Forfeit = Tuple[str, int]               # (address, exit_epoch)

async def ensure_tables(db) -> None:
    """
    No-op kept for callers: the tables live in the main schema (database_sqlite.py).

    Deliberately NOT created here with ``executescript``. Python's sqlite3 issues an
    implicit COMMIT before ``executescript``, and these functions run mid-block — that
    would commit a block's uncommitted state BEFORE its E-D4 root check, breaking the
    flush-read-decide atomicity that lets a rejected block roll back cleanly.
    """
    return None


async def record_validator_exit(db, address: str, exit_epoch: int, block_height: int) -> None:
    """Log a consensus STAKE_EXIT against the block that carried it. Does not commit."""
    await ensure_tables(db)
    await db.connection.execute(
        "INSERT INTO validator_exits (block_height, address, exit_epoch) VALUES (?, ?, ?)",
        (int(block_height), address, int(exit_epoch)))


async def slashed_on_chain(db, address: str, before_height: int) -> bool:
    """
    True if a canonical block below ``before_height`` carries verified slashing evidence
    against ``address``.

    Reads block bodies, not ``slashing_events``: every node holds the same canonical blocks,
    and each proof self-verifies with no external state (a proposer cannot fabricate one —
    it would need the offender's signature over two conflicting messages).

    The SQL filters only narrow the scan; the proof itself decides. Every block carries a
    ``slashing_evidence`` key, almost always empty, so blocks whose list is empty (in the
    repr or JSON form a block may be stored in) are excluded before anything is parsed.
    """
    from .block_verification import _parse_block_content
    from .slashing_block import extract_slashing_evidence_from_dict, verified_offender

    cur = await db.connection.execute(
        "SELECT content FROM blocks WHERE block_height < ? "
        "AND content LIKE '%slashing_evidence%' "
        "AND content NOT LIKE ? AND content NOT LIKE ? "
        "AND content LIKE ? ORDER BY block_height",
        (int(before_height),
         "%'slashing_evidence': []%", '%"slashing_evidence": []%', f"%{address}%"))
    for (content,) in await cur.fetchall():
        try:
            block = _parse_block_content(content)
        except Exception:
            continue
        for ev in extract_slashing_evidence_from_dict(block):
            offender = verified_offender(ev)
            if offender and offender.lower() == address.lower():
                return True
    return False


async def compute_block_withdrawals(db, block_height: int, block_epoch: int
                                    ) -> Tuple[List[Withdrawal], List[Forfeit]]:
    """
    The withdrawals block ``block_height`` must credit, and the exits it must settle as
    forfeited.

    Pure function of the canonical chain below this block, plus this block's epoch — so the
    proposer and every importer compute the same lists. Ordered canonically by
    (address, exit_epoch).

    An exit is settled once ``exit_epoch + WITHDRAWAL_DELAY_EPOCHS`` has been
    reached and it has not been settled before. It is FORFEITED if a canonical block before
    this one carries a verified offence by the validator (a slashed validator loses its
    stake — that is what gives slashing its teeth); otherwise it is PAID everything the
    address has deposited minus everything already withdrawn, so a validator that exits,
    re-deposits and exits again is paid exactly what it put in each time, and the net supply
    effect of staking is zero.
    """
    await ensure_tables(db)
    cur = await db.connection.execute(
        "SELECT address, exit_epoch FROM validator_exits "
        "WHERE block_height < ? AND exit_epoch + ? <= ? "
        "ORDER BY LOWER(address), exit_epoch",
        (int(block_height), int(WITHDRAWAL_DELAY_EPOCHS), int(block_epoch)))
    candidates = await cur.fetchall()

    payable: List[Withdrawal] = []
    forfeited: List[Forfeit] = []
    for address, exit_epoch in candidates:
        cur = await db.connection.execute(
            "SELECT 1 FROM validator_withdrawals "
            "WHERE LOWER(address) = LOWER(?) AND exit_epoch = ?", (address, exit_epoch))
        if await cur.fetchone():
            continue                                   # already settled
        if any(f[0].lower() == address.lower() and f[1] == int(exit_epoch) for f in forfeited):
            continue

        cur = await db.connection.execute(
            "SELECT stake FROM validator_deposits "
            "WHERE LOWER(address) = LOWER(?) AND block_height < ?",
            (address, int(block_height)))
        deposited = sum((Decimal(str(r[0])) for r in await cur.fetchall()), Decimal(0))

        cur = await db.connection.execute(
            "SELECT amount FROM validator_withdrawals WHERE LOWER(address) = LOWER(?)",
            (address,))
        withdrawn = sum((Decimal(str(r[0])) for r in await cur.fetchall()), Decimal(0))
        # Withdrawals already queued earlier in THIS list (an address with two exits).
        withdrawn += sum((w[2] for w in payable if w[0].lower() == address.lower()),
                         Decimal(0))

        amount = deposited - withdrawn
        if amount <= 0:
            continue                                   # nothing to pay, so nothing to forfeit
        # The whole chain below, not just since the first deposit: a genesis validator has
        # no deposit row but could still have offended before topping up.
        if await slashed_on_chain(db, address, block_height):
            forfeited.append((address, int(exit_epoch)))
            continue
        payable.append((address, int(exit_epoch), amount))
    return payable, forfeited


async def compute_payable_withdrawals(db, block_height: int,
                                      block_epoch: int) -> List[Withdrawal]:
    """The withdrawals block ``block_height`` must credit (see ``compute_block_withdrawals``)."""
    payable, _forfeited = await compute_block_withdrawals(db, block_height, block_epoch)
    return payable


async def apply_withdrawals(db, withdrawals: List[Withdrawal], block_height: int) -> None:
    """
    Credit each withdrawal and record it in the ledger. Does not commit — it rides the
    block's commit, and a rejected block's rollback discards it with everything else.
    """
    await ensure_tables(db)
    for address, exit_epoch, amount in withdrawals:
        await db.apply_account_balance_delta(address, amount)
        await db.connection.execute(
            "INSERT INTO validator_withdrawals (address, exit_epoch, amount, block_height) "
            "VALUES (?, ?, ?, ?)",
            (address, int(exit_epoch), str(amount), int(block_height)))
        logger.info("[withdrawal] block %d returned %s QRDX of stake to %s (exit epoch %d)",
                    block_height, amount, str(address)[:24], exit_epoch)


async def record_forfeits(db, forfeited: List[Forfeit], block_height: int) -> None:
    """
    Settle forfeited exits with a zero-amount ledger row, so the chain scan behind a
    forfeiture runs once rather than on every later block. The row credits nothing; the
    ledger re-credit paths skip zero rows so they never touch an account. Does not commit.
    """
    for address, exit_epoch in forfeited:
        await db.connection.execute(
            "INSERT INTO validator_withdrawals (address, exit_epoch, amount, block_height) "
            "VALUES (?, ?, ?, ?)", (address, int(exit_epoch), "0", int(block_height)))
        logger.warning("[withdrawal] block %d: stake of %s forfeited (slashed; exit epoch %d)",
                       block_height, str(address)[:24], exit_epoch)


async def process_block_withdrawals(db, block_height: int, block_epoch: int) -> int:
    """Compute and apply this block's withdrawals and forfeits. Returns how many were paid."""
    if not ENFORCE_VALIDATOR_WITHDRAWALS:
        return 0
    payable, forfeited = await compute_block_withdrawals(db, block_height, block_epoch)
    if payable:
        await apply_withdrawals(db, payable, block_height)
    if forfeited:
        await record_forfeits(db, forfeited, block_height)
    return len(payable)


async def undo_withdrawal_logs_above(db, tip_height: int) -> None:
    """Discard exit and withdrawal records carried by orphaned blocks. Does not commit."""
    await ensure_tables(db)
    await db.connection.execute(
        "DELETE FROM validator_exits WHERE block_height > ?", (int(tip_height),))
    await db.connection.execute(
        "DELETE FROM validator_withdrawals WHERE block_height > ?", (int(tip_height),))


async def reapply_withdrawal_ledger(db) -> int:
    """
    Re-credit every canonical withdrawal onto a freshly rebuilt ``account_state``.

    The rollback rebuild reconstructs balances from genesis plus the EVM and exchange
    sections of canonical blocks; a withdrawal is neither, so the rebuild alone would drop
    it. Every ledger row still present after ``undo_withdrawal_logs_above`` is canonical,
    so re-crediting them restores exactly the forward-path balances. Does not commit.
    """
    await ensure_tables(db)
    cur = await db.connection.execute(
        "SELECT address, amount FROM validator_withdrawals ORDER BY block_height, address")
    rows = [(a, Decimal(str(v))) for a, v in await cur.fetchall()]
    rows = [(a, v) for a, v in rows if v != 0]        # forfeits credit nothing
    for address, amount in rows:
        await db.apply_account_balance_delta(address, amount)
    return len(rows)
