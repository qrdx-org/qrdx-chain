"""
ExchangeStateManager's module-level helpers and constants (qrdx/exchange/state_manager.py
re-exports them, so imports of them from there keep working).
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

from ..transactions import (
    ExchangeTransaction,
)

logger = logging.getLogger("qrdx.exchange.state_manager")

ZERO = Decimal("0")


# ---------------------------------------------------------------------------
# Transaction execution result
# ---------------------------------------------------------------------------


class ExchangeExecResult:
    """Result of executing a single exchange transaction."""

    __slots__ = ("success", "gas_used", "data", "error", "logs", "fee")

    def __init__(
        self,
        success: bool = True,
        gas_used: int = 0,
        data: Optional[Dict[str, Any]] = None,
        error: str = "",
        logs: Optional[List[Dict[str, Any]]] = None,
    ):
        self.success = success
        self.gas_used = gas_used
        self.data = data or {}
        self.error = error
        self.logs = logs or []
        self.fee = ZERO  # QRDX paid for gas (burned)


class _OperationFailed(Exception):
    """An operation returned a failed result: its changes are undone like a raise's."""

    def __init__(self, result: ExchangeExecResult) -> None:
        super().__init__(result.error)
        self.result = result


class _BatchAction(ExchangeTransaction):
    """One action of a BATCH, run as an operation of its own: the batch's (verified) sender, no
    nonce of its own (the batch's covers it), and a hash — the ids of the orders it places —
    derived from the batch's hash and the action's place in it."""

    def __init__(self, batch_hash: str, index: int, **fields: Any) -> None:
        super().__init__(**fields)
        self._hash = hashlib.blake2b(f"{batch_hash}:{index}".encode(), digest_size=32).hexdigest()

    def tx_hash(self) -> str:
        return self._hash


class _EvmAction(ExchangeTransaction):
    """An exchange action an EVM contract sent (qrdx/contracts/exchange_evm.py), run as an
    operation of the contract's account: authorized by the EVM execution that sent it (no
    signature, no nonce, its gas paid in the EVM), and a hash — the ids of the orders it places
    — derived from its place in the queue, which no other action ever takes."""

    def __init__(self, key: str, **fields: Any) -> None:
        super().__init__(**fields)
        self._hash = hashlib.blake2b(f"evm-action:{key}".encode(), digest_size=32).hexdigest()

    def tx_hash(self) -> str:
        return self._hash


# Spot fees are whole in an 18-decimal asset.
SPOT_FEE_QUANTUM = Decimal("1e-18")
# The stakers' fee share in other assets is sold for QRDX (convert_staker_fees, the tick): at
# most once every STAKER_FEE_CONVERT_SECONDS a token, at no less than STAKER_FEE_CONVERT_SLIPPAGE
# under its QRDX pool's TWAP over STAKER_FEE_TWAP_SECONDS, visiting at most so many resting orders.
STAKER_FEE_CONVERT_SECONDS = Decimal(60)
STAKER_FEE_CONVERT_SLIPPAGE = Decimal("0.02")
STAKER_FEE_TWAP_SECONDS = 600
STAKER_FEE_CONVERT_MAKERS = 20

# The most hops one SWAP may take (``path``).
MAX_SWAP_HOPS = 4

# PLACE_ORDER order types that make a spot trigger (qrdx/exchange/trading.py).
_TRIGGER_KINDS = {"stop_loss": "sl", "stop": "sl", "take_profit": "tp", "oco": "oco"}


def _attached_legs(params: Dict[str, Any]) -> List[Tuple[str, Decimal, Decimal, int]]:
    """An order's attached ``tp`` / ``sl``: [(kind, trigger price, limit price — 0 for a market
    order — and the matching it prepays)]."""
    from ..clearinghouse import TRIGGER_DEFAULT_MAKERS

    legs = []
    for kind in ("tp", "sl"):
        leg = params.get(kind)
        if leg is None:
            continue
        if not isinstance(leg, dict) or "trigger_price" not in leg:
            raise ValueError(f"{kind} is {{trigger_price, limit_price?, max_makers?}}")
        makers = leg.get("max_makers", TRIGGER_DEFAULT_MAKERS)
        if isinstance(makers, bool) or not isinstance(makers, int):
            raise ValueError(f"{kind}.max_makers must be a whole number")
        trigger = Decimal(str(leg["trigger_price"]))
        limit = Decimal(str(leg.get("limit_price") or "0"))
        if not trigger.is_finite() or trigger <= 0 or not limit.is_finite() or limit < 0:
            raise ValueError(f"{kind}: prices must be positive")
        legs.append((kind, trigger, limit, makers))
    return legs


def _trigger_makers(value: Any) -> int:
    """A spot trigger's prepaid matching (``max_makers``; default SPOT_TRIGGER_DEFAULT_MAKERS)."""
    from ..trading import SPOT_TRIGGER_DEFAULT_MAKERS, SPOT_TRIGGER_MAX_MAKERS

    makers = SPOT_TRIGGER_DEFAULT_MAKERS if value is None else value
    if isinstance(makers, bool) or not isinstance(makers, int):
        raise ValueError("max_makers must be a whole number")
    if not 1 <= makers <= SPOT_TRIGGER_MAX_MAKERS:
        raise ValueError(f"max_makers must be 1 to {SPOT_TRIGGER_MAX_MAKERS}")
    return makers


def _encode_fee_token(_token: str, value: Any) -> Any:
    # (Module-level: committed collections are pickled with their encoder in the exchange
    # checkpoints — a lambda cannot be.)
    return [str(value[0]), str(value[1])]


def _book_nonce(tx: ExchangeTransaction) -> int:
    """The nonce an order carries into its book's own per-owner replay check. A transaction
    signed in another lane (an agent's, a master's, a leader's: ``nonce_key``) passes 0, which the
    book does not check: lanes number independently, and the manager's lane nonce already
    refuses a replay. (Passing the lane's nonce refused an agent's orders once the owner's own
    nonce had passed it, and the owner's once its agent's had.)"""
    return 0 if getattr(tx, "signer", "") else tx.nonce


def _id_or_raw(address: str) -> str:
    """An address's canonical account id, or the address itself (lowercase) if it has none."""
    try:
        return _account_key(address)
    except ValueError:
        return str(address).lower()


def _account_key(address: str) -> str:
    from ..authority import account_id

    return account_id(address)


def _default_policy():
    from ..authority import Policy

    return Policy()


def _describe_policy(policy) -> Dict[str, Any]:
    from ..authority import describe

    return describe(policy)


def _policy_value(action: str, p: Dict[str, Any]) -> Any:
    """The ACCOUNT_POLICY action's value, checked for its type."""
    if action == "recover":
        raise ValueError("a recovery is the guardians' (ACCOUNT_RECOVER), never signed")
    if action in ("add_controller", "remove_controller"):
        return str(p["controller"])
    if action == "own_key":
        if not isinstance(p["enabled"], bool):
            raise ValueError("enabled must be true or false")
        return p["enabled"]
    if action == "guardians":
        from ..authority import DEFAULT_RECOVERY_DELAY

        guardians, threshold = p["guardians"], p.get("threshold", 0)
        delay = p.get("recovery_delay", DEFAULT_RECOVERY_DELAY)
        if not isinstance(guardians, list) or not all(isinstance(g, str) for g in guardians):
            raise ValueError("guardians is a list of addresses")
        for name, n in (("threshold", threshold), ("recovery_delay", delay)):
            if isinstance(n, bool) or not isinstance(n, int):
                raise ValueError(f"{name} must be a whole number")
        # (Queued as text when the own key signs it: one canonical form.)
        return json.dumps(
            {"guardians": sorted(guardians), "threshold": threshold, "recovery_delay": delay},
            sort_keys=True,
            separators=(",", ":"),
        )
    seconds = p["seconds"]
    if isinstance(seconds, bool) or not isinstance(seconds, int):
        raise ValueError("seconds must be a whole number")
    return seconds


def _parse_value(change) -> Any:
    if change.action == "own_key":
        return change.value == "True"
    if change.action == "delay":
        return int(change.value)
    return change.value


_CONTROLLER_ADDRESS = re.compile(r"0x[Pp][Qq]([0-9a-fA-F]{64}|[Mm][Ss][0-9a-fA-F]{38})")


def _apply_policy(policy, action: str, value: Any, account: str):
    """``policy`` with the change made — or ValueError if it may not be: a controller is a
    post-quantum key or a multisig, never the account, at most MAX_CONTROLLERS; an account
    whose own key is off keeps at least one controller."""
    from dataclasses import replace

    from ..authority import MAX_CONTROLLERS, MAX_DELAY_SECONDS, account_id

    if action == "add_controller":
        if not _CONTROLLER_ADDRESS.fullmatch(value):
            raise ValueError("a controller is a post-quantum (0xPQ…) or multisig (0xPQMS…) address")
        if account_id(value) == account_id(account):
            raise ValueError("an account does not control itself")
        if account_id(value) in policy.controller_ids():
            raise ValueError("already a controller")
        if len(policy.controllers) >= MAX_CONTROLLERS:
            raise ValueError(f"at most {MAX_CONTROLLERS} controllers")
        return replace(policy, controllers=tuple(sorted(policy.controllers + (value,))))
    if action == "remove_controller":
        ids = policy.controller_ids()
        if account_id(value) not in ids:
            raise ValueError("not a controller")
        kept = tuple(c for c in policy.controllers if account_id(c) != account_id(value))
        if not kept and not policy.own_key:
            raise ValueError("an account whose own key is off keeps a controller")
        return replace(policy, controllers=kept)
    if action == "own_key":
        if not value and not policy.controllers:
            raise ValueError("bind a controller before turning the own key off")
        return replace(policy, own_key=bool(value))
    if action == "delay":
        if not 0 <= int(value) <= MAX_DELAY_SECONDS:
            raise ValueError(f"the delay is 0 to {MAX_DELAY_SECONDS} seconds")
        return replace(policy, delay=int(value))
    if action == "guardians":
        from ..authority import MAX_GUARDIANS, MIN_RECOVERY_DELAY

        spec = json.loads(value)
        guardians, threshold, delay = spec["guardians"], spec["threshold"], spec["recovery_delay"]
        if not guardians:
            return replace(policy, guardians=(), guardian_threshold=0, recovery_delay=0)
        if len(guardians) > MAX_GUARDIANS:
            raise ValueError(f"at most {MAX_GUARDIANS} guardians")
        ids = []
        for g in guardians:
            if not _CONTROLLER_ADDRESS.fullmatch(g):
                raise ValueError(
                    "a guardian is a post-quantum (0xPQ…) or multisig (0xPQMS…) address"
                )
            ids.append(account_id(g))
        if account_id(account) in ids:
            raise ValueError("an account is not its own guardian")
        if len(set(ids)) != len(ids):
            raise ValueError("a guardian is named twice")
        if not 1 <= threshold <= len(guardians):
            raise ValueError(f"the threshold is 1 to {len(guardians)}")
        if not MIN_RECOVERY_DELAY <= delay <= MAX_DELAY_SECONDS:
            raise ValueError(
                f"the recovery delay is {MIN_RECOVERY_DELAY} to {MAX_DELAY_SECONDS} seconds"
            )
        return replace(
            policy,
            guardians=tuple(sorted(guardians)),
            guardian_threshold=threshold,
            recovery_delay=delay,
        )
    if action == "recover":  # queued by the guardians (ACCOUNT_RECOVER), never signed
        if not _CONTROLLER_ADDRESS.fullmatch(value):
            raise ValueError("a controller is a post-quantum (0xPQ…) or multisig (0xPQMS…) address")
        if account_id(value) == account_id(account):
            raise ValueError("an account does not control itself")
        return replace(policy, controllers=(value,), own_key=False)
    raise ValueError(f"unknown action {action!r}")


def _flag(params: Dict[str, Any], key: str) -> bool:
    """A yes/no parameter: JSON true or false (absent: false). Anything else is refused — a
    string "false" is not false."""
    value = params.get(key, False)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be true or false, got {value!r}")
    return value


# ---------------------------------------------------------------------------
# Exchange State Manager
# ---------------------------------------------------------------------------
