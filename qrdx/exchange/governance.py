"""
On-chain governance (docs/GOVERNANCE.md).

Validators propose and decide; QRDX holders can veto; nothing takes effect until a timelock has
passed. It governs three things:

* ``system_spend``   — move QRDX out of a system wallet (the treasury, grants, ...). After the
                       master controller is retired this is the ONLY way system-wallet funds move.
* ``freeze_master``  — end the genesis master controller's authority over the system wallets
                       before SYSTEM_WALLET_MASTER_SUNSET_HEIGHT, when it would end anyway.
* ``approve_fork``   — authorise a fork scheduled in the chain spec to activate
                       (docs/PROTOCOL_UPGRADES.md). An unapproved fork stays dormant.

Lifecycle, all judged by block height (never a clock):

    GOV_PROPOSE  (a validator)        → VOTING   until created_at + GOV_VOTING_PERIOD_BLOCKS
    GOV_VOTE     (validators, by stake snapshot at creation)
        yes ≥ GOV_APPROVAL_THRESHOLD_BPS of the snapshot  → PASSED  (timelock starts)
        approval no longer reachable, or the window ends  → REJECTED
    GOV_VETO     (any holder, during the timelock) locks QRDX in the veto escrow;
        locked ≥ GOV_VETO_THRESHOLD_QRDX                  → VETOED  (escrow refunded)
    GOV_EXECUTE  (anyone, from the timelock's end to its execution window's end)
                                                          → EXECUTED (escrow refunded)
        after the window                                  → EXPIRED  (escrow refunded)

Vetoes lock real QRDX (moved to a protocol escrow holder and returned when the proposal
resolves), so one balance cannot be counted twice by moving it between accounts.

This is consensus state: it is replayed on every path that applies exchange sections, committed
in the exchange state root, snapshotted for a rejected block and rebuilt after a reorg like the
rest of the exchange. Validity never depends on the node's chain spec — an ``approve_fork`` is
recorded by every node, whatever forks its own spec schedules — so nodes that have and have not
installed an upgrade keep identical state.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Dict, List, Optional, Tuple

ZERO = Decimal(0)
BPS = 10_000

ACTIONS = ("system_spend", "freeze_master", "approve_fork")

VOTING, PASSED, REJECTED, VETOED, EXECUTED, EXPIRED = (
    "voting", "passed", "rejected", "vetoed", "executed", "expired")
OPEN_STATUSES = (VOTING, PASSED)

MAX_OPEN_PER_PROPOSER = 4
MAX_OPEN_TOTAL = 64
MAX_MEMO = 280

_FORK_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def veto_escrow_address() -> str:
    """The protocol holder of QRDX locked in vetoes (a synthetic holder, like 0xPERP)."""
    return "0xVETO" + hashlib.blake2b(b"governance:veto-escrow", digest_size=18).hexdigest()


def _params():
    from .. import constants
    return constants


def _amount(raw: Any) -> Decimal:
    """A positive QRDX amount with at most 18 decimal places (whole wei)."""
    try:
        value = Decimal(str(raw))
    except (InvalidOperation, ValueError):
        raise ValueError(f"invalid amount {raw!r}") from None
    if not value.is_finite() or value <= 0:
        raise ValueError(f"amount must be positive, got {raw!r}")
    if value != value.quantize(Decimal(1).scaleb(-18)):
        raise ValueError(f"amount {raw!r} has more than 18 decimal places")
    return value


def _fmt(value: Decimal) -> str:
    """One string per amount ("1000", never "1E+3" or "1000.00") for stored state."""
    text = format(value.normalize(), "f")
    return text


def _system_wallets() -> Dict[str, str]:
    """Spendable system wallets: lowercase address → name (the burner is not spendable)."""
    c = _params()
    return {addr.lower(): name for name, addr in c.SYSTEM_WALLET_ADDRESSES.items()
            if name != "GARBAGE_COLLECTOR"}


@dataclass
class Proposal:
    id: int
    proposer: str
    action: str
    params: Dict[str, Any]
    memo: str
    created_at: int
    voting_ends: int
    weights: Dict[str, Decimal]
    total_weight: Decimal
    votes: Dict[str, bool] = field(default_factory=dict)
    yes: Decimal = ZERO
    no: Decimal = ZERO
    status: str = VOTING
    passed_at: Optional[int] = None
    timelock_ends: Optional[int] = None
    execute_by: Optional[int] = None
    vetoes: Dict[str, Decimal] = field(default_factory=dict)
    veto_total: Decimal = ZERO
    resolved_at: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "proposer": self.proposer, "action": self.action,
            "params": self.params, "memo": self.memo, "created_at": self.created_at,
            "voting_ends": self.voting_ends,
            "weights": {a: _fmt(w) for a, w in sorted(self.weights.items())},
            "total_weight": _fmt(self.total_weight),
            "votes": dict(sorted(self.votes.items())), "yes": _fmt(self.yes), "no": _fmt(self.no),
            "status": self.status, "passed_at": self.passed_at,
            "timelock_ends": self.timelock_ends, "execute_by": self.execute_by,
            "vetoes": {a: _fmt(v) for a, v in sorted(self.vetoes.items())},
            "veto_total": _fmt(self.veto_total), "resolved_at": self.resolved_at,
        }


class GovernanceError(ValueError):
    pass


class Governance:
    """Governance state and its transitions. Pure and deterministic: every method takes the
    block height it is judged at; balances it needs are passed in by the exchange state
    manager, which also applies the QRDX moves it returns."""

    def __init__(self) -> None:
        self.proposals: Dict[int, Proposal] = {}
        self.next_id: int = 1
        # Height of the block whose governance execution froze the master controller.
        self.master_frozen_at: Optional[int] = None
        # "<fork name>:<definition hash>" → approval record (chain_spec.fork_approval reads it).
        self.fork_approvals: Dict[str, Dict[str, Any]] = {}
        # From the genesis block: whether system wallets exist on this chain.
        self.system_wallets_enabled: bool = False
        self.genesis_loaded: bool = False

    # ── genesis ─────────────────────────────────────────────────────────────────────────

    def load_genesis(self, genesis_content: Any) -> None:
        if self.genesis_loaded:
            return
        try:
            content = json.loads(genesis_content) if isinstance(genesis_content, str) else genesis_content
        except ValueError:
            content = None
        if isinstance(content, dict):
            self.system_wallets_enabled = bool(content.get("system_wallet_controller"))
        self.genesis_loaded = True

    # ── status ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def effective_status(p: Proposal, height: int) -> str:
        """The status at ``height``, including deadlines no transaction has acted on yet."""
        if p.status == VOTING and height > p.voting_ends:
            return REJECTED
        if p.status == PASSED and p.execute_by is not None and height > p.execute_by:
            return EXPIRED
        return p.status

    def _open_count(self, height: int, proposer: Optional[str] = None) -> int:
        return sum(1 for p in self.proposals.values()
                   if self.effective_status(p, height) in OPEN_STATUSES
                   and (proposer is None or p.proposer == proposer))

    def get(self, proposal_id: Any) -> Proposal:
        try:
            pid = int(proposal_id)
        except (TypeError, ValueError):
            raise GovernanceError(f"invalid proposal id {proposal_id!r}") from None
        p = self.proposals.get(pid)
        if p is None:
            raise GovernanceError(f"no proposal {pid}")
        return p

    # ── propose ─────────────────────────────────────────────────────────────────────────

    def propose(self, sender: str, params: Dict[str, Any], height: int,
                committee: Optional[Dict[str, Decimal]]) -> Proposal:
        c = _params()
        proposer = sender.lower()
        if not committee or proposer not in committee:
            raise GovernanceError("only a validator (a member of the validator committee) can propose")
        if self._open_count(height, proposer) >= MAX_OPEN_PER_PROPOSER:
            raise GovernanceError(f"a validator may have at most {MAX_OPEN_PER_PROPOSER} open proposals")
        if self._open_count(height) >= MAX_OPEN_TOTAL:
            raise GovernanceError(f"at most {MAX_OPEN_TOTAL} proposals may be open at once")
        action = params.get("action")
        if action not in ACTIONS:
            raise GovernanceError(f"action must be one of {ACTIONS}, got {action!r}")
        memo = str(params.get("memo", ""))
        if len(memo) > MAX_MEMO:
            raise GovernanceError(f"memo is limited to {MAX_MEMO} characters")
        body = self._check_action(action, params, height)
        weights = {a: Decimal(w) for a, w in committee.items() if Decimal(w) > 0}
        total = sum(weights.values(), ZERO)
        if total <= 0:
            raise GovernanceError("the validator committee has no stake")
        p = Proposal(id=self.next_id, proposer=proposer, action=action, params=body, memo=memo,
                     created_at=height, voting_ends=height + c.GOV_VOTING_PERIOD_BLOCKS,
                     weights=weights, total_weight=total)
        self.proposals[p.id] = p
        self.next_id += 1
        return p

    def _check_action(self, action: str, params: Dict[str, Any], height: int) -> Dict[str, Any]:
        c = _params()
        if action == "system_spend":
            if not self.system_wallets_enabled:
                raise GovernanceError("this chain has no system wallets")
            wallet = str(params.get("wallet", "")).lower()
            if wallet not in _system_wallets():
                raise GovernanceError(f"{params.get('wallet')!r} is not a spendable system wallet")
            to = str(params.get("to", "")).strip()
            from ..crypto.account_id import is_synthetic_holder, to_account_id
            try:
                to_id = to_account_id(to)
            except ValueError as e:
                raise GovernanceError(f"invalid recipient: {e}") from None
            if is_synthetic_holder(to) or to_id == wallet:
                raise GovernanceError("the recipient must be an ordinary account")
            try:
                amount = _amount(params.get("amount"))
            except ValueError as e:
                raise GovernanceError(str(e)) from None
            return {"wallet": wallet, "to": to, "amount": _fmt(amount)}
        if action == "freeze_master":
            if self.master_frozen_at is not None:
                raise GovernanceError("the master controller is already frozen")
            if height >= c.SYSTEM_WALLET_MASTER_SUNSET_HEIGHT:
                raise GovernanceError("the master controller's authority has already ended (sunset)")
            return {}
        # approve_fork — recorded as given; deliberately NOT checked against this node's spec
        # (see the module docstring).
        fork = str(params.get("fork", ""))
        if not _FORK_NAME.match(fork):
            raise GovernanceError(f"invalid fork name {fork!r}")
        try:
            fork_height = int(params.get("height"))
        except (TypeError, ValueError):
            raise GovernanceError("approve_fork needs the fork's height") from None
        if fork_height <= height:
            raise GovernanceError("the fork's height has already passed")
        digest = str(params.get("definition_hash", "")).lower()
        if not _HEX64.match(digest):
            raise GovernanceError("approve_fork needs the fork's definition_hash "
                                  "(chain_spec.ChainSpec.fork_definition_hash)")
        return {"fork": fork, "height": fork_height, "definition_hash": digest}

    # ── vote ────────────────────────────────────────────────────────────────────────────

    def vote(self, sender: str, params: Dict[str, Any], height: int) -> Proposal:
        p = self.get(params.get("proposal_id"))
        voter = sender.lower()
        if self.effective_status(p, height) != VOTING:
            raise GovernanceError(f"proposal {p.id} is not open for voting ({self.effective_status(p, height)})")
        if voter not in p.weights:
            raise GovernanceError("only the validators in the proposal's committee snapshot can vote")
        if voter in p.votes:
            raise GovernanceError("already voted (votes are final)")
        support = params.get("support")
        if not isinstance(support, bool):
            raise GovernanceError("support must be true or false")
        p.votes[voter] = support
        if support:
            p.yes += p.weights[voter]
        else:
            p.no += p.weights[voter]
        threshold = _params().GOV_APPROVAL_THRESHOLD_BPS
        if p.yes * BPS >= p.total_weight * threshold:
            c = _params()
            p.status = PASSED
            p.passed_at = height
            p.timelock_ends = height + c.GOV_TIMELOCK_BLOCKS
            p.execute_by = p.timelock_ends + c.GOV_EXECUTION_WINDOW_BLOCKS
        elif p.no * BPS > p.total_weight * (BPS - threshold):
            p.status = REJECTED                    # approval is no longer reachable
            p.resolved_at = height
        return p

    # ── veto ────────────────────────────────────────────────────────────────────────────

    def veto(self, sender: str, params: Dict[str, Any], height: int,
             available: Optional[Decimal]) -> Tuple[Proposal, Decimal, Dict[str, Decimal]]:
        """Lock ``amount`` QRDX against a passed proposal. Returns (proposal, amount locked,
        refunds) — refunds are non-empty when this veto crossed the threshold."""
        p = self.get(params.get("proposal_id"))
        if self.effective_status(p, height) != PASSED or height >= p.timelock_ends:
            raise GovernanceError(f"proposal {p.id} cannot be vetoed now (vetoes are open during "
                                  f"its timelock only)")
        try:
            amount = _amount(params.get("amount"))
        except ValueError as e:
            raise GovernanceError(str(e)) from None
        if available is None:
            raise GovernanceError("sender balance unavailable; cannot lock the veto")
        if available < amount:
            raise GovernanceError(f"insufficient QRDX to lock: need {amount}, available {available}")
        # Keyed by the sender exactly as the transaction names it — the form its locked QRDX
        # was debited under, so the refund lands on the same balance entry.
        holder = sender
        p.vetoes[holder] = p.vetoes.get(holder, ZERO) + amount
        p.veto_total += amount
        refunds: Dict[str, Decimal] = {}
        if p.veto_total >= Decimal(_params().GOV_VETO_THRESHOLD_QRDX):
            p.status = VETOED
            p.resolved_at = height
            refunds = dict(p.vetoes)
        return p, amount, refunds

    # ── execute ─────────────────────────────────────────────────────────────────────────

    def execute(self, params: Dict[str, Any], height: int,
                wallet_balance: Callable[[str], Optional[Decimal]]
                ) -> Tuple[Proposal, Dict[str, Any], List[Tuple[str, Decimal]], Dict[str, Decimal]]:
        """Execute a passed proposal whose timelock has ended, or close an expired one.
        Returns (proposal, result, balance moves [(address, delta)], refunds)."""
        p = self.get(params.get("proposal_id"))
        status = self.effective_status(p, height)
        if status == EXPIRED:
            p.status = EXPIRED
            p.resolved_at = height
            return p, {"executed": False, "expired": True}, [], dict(p.vetoes)
        if status != PASSED:
            raise GovernanceError(f"proposal {p.id} is not executable ({status})")
        if height < p.timelock_ends:
            raise GovernanceError(f"proposal {p.id} is timelocked until block {p.timelock_ends}")

        moves: List[Tuple[str, Decimal]] = []
        result: Dict[str, Any] = {"executed": True, "action": p.action}
        if p.action == "system_spend":
            amount = Decimal(p.params["amount"])
            balance = wallet_balance(p.params["wallet"])
            if balance is None:
                raise GovernanceError("system wallet balance unavailable")
            if balance < amount:
                # Retryable until the execution window closes.
                raise GovernanceError(f"system wallet holds {balance} QRDX, the proposal spends {amount}")
            moves = [(p.params["wallet"], -amount), (p.params["to"], amount)]
            result.update(wallet=p.params["wallet"], to=p.params["to"], amount=_fmt(amount))
        elif p.action == "freeze_master":
            if self.master_frozen_at is None:
                self.master_frozen_at = height
            result["master_frozen_at"] = self.master_frozen_at
        else:  # approve_fork
            key = f"{p.params['fork']}:{p.params['definition_hash']}"
            if key not in self.fork_approvals:
                self.fork_approvals[key] = {**p.params, "approved_at": height, "proposal": p.id}
            result["approved_at"] = self.fork_approvals[key]["approved_at"]
        p.status = EXECUTED
        p.resolved_at = height
        return p, result, moves, dict(p.vetoes)

    # ── reads used by consensus ─────────────────────────────────────────────────────────

    def fork_approved_at(self, fork_name: str, definition_hash: str) -> Optional[int]:
        rec = self.fork_approvals.get(f"{fork_name}:{definition_hash.lower()}")
        return int(rec["approved_at"]) if rec else None

    # ── commitment ──────────────────────────────────────────────────────────────────────

    @property
    def touched(self) -> bool:
        return bool(self.proposals or self.fork_approvals or self.master_frozen_at is not None)

    def state_hash(self) -> bytes:
        blob = json.dumps({
            "next_id": self.next_id,
            "master_frozen_at": self.master_frozen_at,
            "fork_approvals": self.fork_approvals,
            "proposals": [self.proposals[i].to_dict() for i in sorted(self.proposals)],
        }, sort_keys=True, separators=(",", ":"))
        return hashlib.blake2b(b"governance:" + blob.encode(), digest_size=32).digest()

    def view(self, p: Proposal, height: int) -> Dict[str, Any]:
        """A proposal as an API shows it: its stored record plus its status at ``height``."""
        d = p.to_dict()
        d["status"] = self.effective_status(p, height)
        d["threshold_bps"] = _params().GOV_APPROVAL_THRESHOLD_BPS
        return d


def _approval_lookup(fork_name: str, definition_hash: str) -> Optional[int]:
    """chain_spec's view of on-chain fork approvals: the live exchange state's."""
    from .state_manager import ExchangeStateManager
    inst = ExchangeStateManager.instance
    return inst.governance.fork_approved_at(fork_name, definition_hash) if inst else None


def master_authority(height: int) -> Tuple[bool, str]:
    """May the genesis master controller still move system-wallet funds in the block at
    ``height``? Not from SYSTEM_WALLET_MASTER_SUNSET_HEIGHT on, and not once governance has
    frozen it (from the block whose exchange section executed the freeze)."""
    c = _params()
    if height >= c.SYSTEM_WALLET_MASTER_SUNSET_HEIGHT:
        return False, (f"the master controller's authority over system wallets ended at block "
                       f"{c.SYSTEM_WALLET_MASTER_SUNSET_HEIGHT}; system-wallet funds move only "
                       f"by governance proposal (system_spend)")
    from .state_manager import ExchangeStateManager
    inst = ExchangeStateManager.instance
    frozen = inst.governance.master_frozen_at if inst else None
    if frozen is not None and height >= frozen:
        return False, (f"governance froze the master controller at block {frozen}; system-wallet "
                       f"funds move only by governance proposal (system_spend)")
    return True, ""


def _install() -> None:
    from .. import chain_spec
    chain_spec.set_approval_lookup(_approval_lookup)


_install()
