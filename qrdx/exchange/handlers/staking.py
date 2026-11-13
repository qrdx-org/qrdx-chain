"""
Staking (deposits, exits, delegation, commission) and on-chain governance.

These are ExchangeStateManager's methods, written as functions of the manager (``self``) and
bound to it under the same names in qrdx/exchange/state_manager.py. They are here only to keep
that file to a size one can read: read them as the class's.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from ..governance import GovernanceError, veto_escrow_address
from ..tokens import (
    TokenError,
    account as token_account,
)
from ..transactions import (
    EXCHANGE_GAS_COSTS,
    ExchangeOpType,
    ExchangeTransaction,
)
from .common import (
    ExchangeExecResult,
    logger,
)

if TYPE_CHECKING:
    from ..state_manager import ExchangeStateManager


def _op_stake_deposit(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """
    Validator-lifecycle Phase 3: a staking deposit registers the SENDER as a
    validator. Records a deterministic 'deposit' op (address=sender, the supplied
    validator public key, stake) flushed to the consensus validators table as a
    PENDING validator; the all-nodes epoch loop schedules + activates it (so every
    node agrees on membership).

    **The stake must be real.** The claimed ``stake_amount`` becomes the
    validator's ``effective_stake`` in the consensus ``validators`` table, and that
    figure weights BOTH stake-weighted proposer selection and fork-choice attesting
    weight. An unbacked claim is therefore a consensus attack: without these checks
    an account holding nothing could claim more stake than the whole honest set and
    dominate block production and fork choice. So under
    ``enforce_validator_stake`` a deposit must:

      1. clear ``MIN_VALIDATOR_STAKE`` — the same floor the local registration API
         (``validator/manager.py``) and epoch activation already apply, which the
         consensus join path was silently skipping;
      2. be backed by the sender's real ``account_state`` balance; and
      3. be DEBITED, so the stake is genuinely at risk and cannot be spent twice.

    The debit is refunded at the deterministic finalized exit epoch (see
    ``epoch_loop._refund_exited_validator_stakes``). A SLASHED validator moves to
    status 'slashed', never reaches 'exited', and so forfeits its stake — which is
    what makes slashing bite.

    Genesis validators are NOT debited: their stake is declared by the genesis file,
    which is the chain's trust root. This gate governs *joining* validators.
    """
    p = tx.params
    try:
        stake = Decimal(str(p["stake_amount"]))
    except Exception:
        return ExchangeExecResult(success=False, error="STAKE_DEPOSIT: invalid stake_amount")
    if stake <= 0:
        return ExchangeExecResult(success=False, error="STAKE_DEPOSIT: stake must be positive")

    if self.enforce_validator_stake:
        from ...constants import MIN_VALIDATOR_STAKE

        # (1) Minimum stake. Deterministic — a pure comparison against a constant.
        if stake < MIN_VALIDATOR_STAKE:
            return ExchangeExecResult(
                success=False,
                error=(
                    f"STAKE_DEPOSIT: stake {stake} below minimum " f"{MIN_VALIDATOR_STAKE} QRDX"
                ),
            )

        # (2) Ownership. ``available_balance`` is pre-loaded from account_state by
        # preload_sender_balances on every path, so this reads the same value on
        # every node. A missing pre-load (None) means the balance could not be
        # read; refuse rather than assume solvency — a deposit is too dangerous to
        # admit unverified.
        avail = self.available_balance(tx.sender)
        if avail is None:
            return ExchangeExecResult(
                success=False,
                error="STAKE_DEPOSIT: sender balance unavailable; cannot verify stake",
            )
        if avail < stake:
            return ExchangeExecResult(
                success=False,
                error=(
                    f"STAKE_DEPOSIT: insufficient balance for stake: need {stake}, "
                    f"available {avail}"
                ),
            )
    else:
        avail = self.available_balance(tx.sender)
        if avail is not None and avail < stake:
            logger.warning(
                "[observe] stake_deposit by %s: claimed stake %s exceeds available "
                "balance %s — would REJECT once validator stake is enforced",
                tx.sender[:20],
                stake,
                avail,
            )

    self._validator_lifecycle_ops.append(
        {
            "type": "deposit",
            "address": tx.sender,
            "public_key": str(p["validator_public_key"]),
            "stake": str(stake),
        }
    )
    # (It joins the committee that weighs votes when it activates: the committee is the
    # chain-derived validator set — block_processor.ensure_oracle_committee.)

    # (3) Lock it. Gate the RECORDING, not just the flush: the shared
    # account_state flush is already enforced for collateral, so recording
    # unconditionally would debit even while this gate is off.
    if self.enforce_validator_stake:
        self._record_balance_delta(tx.sender, -stake)

    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.STAKE_DEPOSIT],
        data={
            "validator": tx.sender,
            "stake": str(stake),
            "status": "pending",
            "staked_debit": str(stake) if self.enforce_validator_stake else "0",
        },
    )


def _op_stake_exit(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """The sender signals a voluntary exit: logged against the block, it moves the validator
    to exiting in the next epoch's set and out after unbonding (validator/epoch_state.py)."""
    self._validator_lifecycle_ops.append({"type": "exit", "address": tx.sender})
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.STAKE_EXIT],
        data={"validator": tx.sender, "status": "exiting"},
    )


def _op_stake_delegate(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Lock ``amount`` QRDX in ``validator``'s delegation pool (docs/STAKING.md): debited
    now, it joins the pool after a warm-up of ACTIVATION_DELAY_EPOCHS — or comes back, if
    the address is not a validator then (validator/epoch_state.py). The pool's shares earn
    the staking rate, less the validator's commission."""
    from ...constants import STAKE_MIN_DELEGATION

    p = tx.params
    try:
        amount = Decimal(str(p["amount"]))
        validator = str(p["validator"])
        token_account(validator)
    except (InvalidOperation, ValueError, TypeError, TokenError) as e:
        return ExchangeExecResult(success=False, error=f"STAKE_DELEGATE: {e}")
    if not amount.is_finite() or amount < STAKE_MIN_DELEGATION:
        return ExchangeExecResult(
            success=False, error=f"STAKE_DELEGATE: at least {STAKE_MIN_DELEGATION} QRDX"
        )
    if amount != amount.quantize(Decimal("1e-18")):
        return ExchangeExecResult(success=False, error="STAKE_DELEGATE: whole wei only")
    if self.enforce_validator_stake:
        avail = self.available_balance(tx.sender)
        if avail is None or avail < amount:
            return ExchangeExecResult(
                success=False,
                error=f"STAKE_DELEGATE: insufficient balance: need {amount}, " f"available {avail}",
            )
        self._record_balance_delta(tx.sender, -amount)
    self._validator_lifecycle_ops.append(
        {
            "type": "delegate",
            "address": tx.sender,
            "validator": validator,
            "amount": str(amount),
        }
    )
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.STAKE_DELEGATE],
        data={"validator": validator, "amount": str(amount), "status": "warming up"},
    )


def _op_stake_undelegate(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Redeem ``shares`` (default: all, warming-up delegations included) of the sender's
    stake in ``validator``'s pool: worth the pool's price at the end of the epoch, paid
    after UNBONDING_PERIOD_EPOCHS and the withdrawal delay — slashed with the pool
    meanwhile."""
    p = tx.params
    raw = p.get("shares", "all")
    shares: Optional[str] = None
    if str(raw).lower() != "all":
        try:
            value = Decimal(str(raw))
        except InvalidOperation:
            value = Decimal(0)
        if not value.is_finite() or value <= 0:
            return ExchangeExecResult(
                success=False, error="STAKE_UNDELEGATE: shares must be positive, or all"
            )
        shares = str(value)
    self._validator_lifecycle_ops.append(
        {
            "type": "undelegate",
            "address": tx.sender,
            "validator": str(p["validator"]),
            "shares": shares,
        }
    )
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.STAKE_UNDELEGATE],
        data={"validator": str(p["validator"]), "shares": shares or "all"},
    )


def _op_stake_set_commission(
    self: ExchangeStateManager, tx: ExchangeTransaction
) -> ExchangeExecResult:
    """A validator sets its commission on its pool's rewards (basis points, 0–10,000),
    from the next epoch. From an address that is not a validator it does nothing."""
    try:
        bps = int(tx.params["commission_bps"])
    except (TypeError, ValueError):
        bps = -1
    if not 0 <= bps <= 10_000:
        return ExchangeExecResult(
            success=False, error="STAKE_SET_COMMISSION: 0 to 10,000 basis points"
        )
    self._validator_lifecycle_ops.append(
        {"type": "commission", "address": tx.sender, "commission_bps": bps}
    )
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.STAKE_SET_COMMISSION],
        data={"commission_bps": bps},
    )


def validator_lifecycle_ops(self: ExchangeStateManager) -> List[Dict[str, Any]]:
    """This block's executed staking operations: deposits, exits, delegations."""
    return list(self._validator_lifecycle_ops)


#  On-chain governance (qrdx/exchange/governance.py, docs/GOVERNANCE.md)
def _gov(self: ExchangeStateManager, tx: ExchangeTransaction, fn) -> ExchangeExecResult:
    try:
        data = fn()
    except GovernanceError as e:
        return ExchangeExecResult(success=False, error=str(e))
    return ExchangeExecResult(success=True, gas_used=EXCHANGE_GAS_COSTS[tx.op_type], data=data)


def _release_vetoes(self: ExchangeStateManager, refunds: Dict[str, Decimal]) -> None:
    """Return locked veto QRDX from the escrow holder to each holder."""
    escrow = veto_escrow_address()
    for holder in sorted(refunds):
        amount = refunds[holder]
        if amount > 0:
            self._record_balance_delta(escrow, -amount)
            self._record_balance_delta(holder, amount)


def _op_gov_propose(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """A validator opens a proposal; its committee's stake is snapshotted for the vote."""

    def go():
        p = self.governance.propose(
            tx.sender, tx.params, self._current_block_height, self._oracle_members()
        )
        return {
            "proposal_id": p.id,
            "action": p.action,
            "params": p.params,
            "voting_ends": p.voting_ends,
        }

    return self._gov(tx, go)


def _op_gov_vote(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    def go():
        p = self.governance.vote(tx.sender, tx.params, self._current_block_height)
        return {
            "proposal_id": p.id,
            "status": p.status,
            "yes": str(p.yes),
            "no": str(p.no),
            "timelock_ends": p.timelock_ends,
        }

    return self._gov(tx, go)


def _op_gov_veto(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """A holder locks QRDX in the veto escrow against a passed proposal. Reaching the veto
    threshold stops the proposal and returns every holder's QRDX."""

    def go():
        p, amount, refunds = self.governance.veto(
            tx.sender, tx.params, self._current_block_height, self.available_balance(tx.sender)
        )
        self._record_balance_delta(tx.sender, -amount)
        self._record_balance_delta(veto_escrow_address(), amount)
        self._release_vetoes(refunds)
        return {
            "proposal_id": p.id,
            "status": p.status,
            "locked": str(amount),
            "veto_total": str(p.veto_total),
        }

    return self._gov(tx, go)


def _op_gov_execute(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Anyone executes a passed proposal once its timelock has ended (or closes an expired
    one). A system_spend reads the wallet's balance pre-loaded for this transaction
    (block_processor.preload_sender_balances)."""

    def go():
        p, result, moves, refunds = self.governance.execute(
            tx.params, self._current_block_height, self.available_balance
        )
        for address, delta in moves:
            self._record_balance_delta(address, delta)
        if result.get("executed") and result.get("action") == "delist_market":
            result.update(self._delist_market(result["market_id"], result.get("price")))
        if result.get("executed") and result.get("action") == "list_market":
            result.update(self._list_market(result))
        if result.get("executed") and result.get("action") == "bridge_mint_pause":
            self.bridge.set_mint_paused(result["paused"], self._current_block_height)
        if result.get("executed") and result.get("action") == "declare_quantum_emergency":
            result["doomsday"] = self._trigger_doomsday(
                f"governance proposal {p.id}: {result['reason']}"
            )
        self._release_vetoes(refunds)
        return {"proposal_id": p.id, "status": p.status, **result}

    return self._gov(tx, go)
