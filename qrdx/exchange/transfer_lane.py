"""
Plain QRDX transfers, judged and run natively (native/qrdx-native/src/lane.rs; docs/NATIVE.md).

Most of a loaded block is transfers of native QRDX, each signed by its own account's key. Judging
a block's section (``section_errors``) and running it (``process_transaction``) cost Python
about 130 µs such a transfer: an undo scope, a dozen dict reads and writes, decimal arithmetic.
What of that depends on state is arithmetic over a few dicts — each lane's next nonce, what each
payer owes the block, each address's available balance and its delta for the block, the block's
fees — and that runs natively, over consecutive runs of such transfers.

What decides a transaction's fate in any other way is Python's own, unchanged:

* ``prepare``: its form (``validate_basic``), its fee floor (``validate_fee``), its amount
  (``tokens.amount``), its recipient and memo, its fees — once a transaction, under the
  exchange's decimal context. Any refusal there, and anything that is not a plain transfer
  (another operation, another token, an agent's or a multisig's signature, an expiry, the free
  lane), leaves the transaction to Python, which words the refusal.
* At the start of each run: whether each sender may sign for itself (``signer_error``), and who
  pays its gas (``fee_payer``) — which no transfer can change within a run.

The native code bails, and Python runs the run itself, whenever it would not reproduce Python
exactly (a value past its 128-bit decimals, a nonce out of sequence, a refusal to word). What it
writes back goes through the same dicts, with the same undo records, in the same order of first
insertion. tests/test_transfer_lane.py runs random blocks both ways and compares everything.

``QRDX_NATIVE=0`` turns it off with the rest of the native module.
"""

from __future__ import annotations

from decimal import Decimal, localcontext
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import undo
from .handlers.common import ExchangeExecResult
from .orderbook import _CTX
from .tokens import (
    TokenError,
    account as token_account,
    amount as token_amount,
    is_native_asset,
    memo as token_memo,
)
from .transactions import EXCHANGE_GAS_COSTS, ExchangeOpType, ExchangeTransaction, _wei_per_qrdx

GAS = EXCHANGE_GAS_COSTS[ExchangeOpType.TOKEN_TRANSFER]
_PARAMS = frozenset({"token_address", "to", "amount", "memo"})


def _native(name: str) -> Optional[Callable[..., Any]]:
    from .. import native

    if not native.AVAILABLE:
        return None
    return getattr(native._native, name, None)


def enabled() -> bool:
    return _native("lane_run") is not None


class Prepared:
    """What Python's own checks found of a plain transfer, for the native passes."""

    __slots__ = ("amount", "to", "memo", "max_fee", "fee", "base_gas")

    def __init__(self, amount, to, memo, max_fee, fee, base_gas) -> None:
        self.amount, self.to, self.memo = amount, to, memo
        self.max_fee, self.fee, self.base_gas = max_fee, fee, base_gas


def prepare(tx: Any) -> Optional[Prepared]:
    """A plain QRDX transfer that passes Python's checks of its own (form, fee floor, amount,
    recipient, memo), with its fees; None for anything else. Remembered while every field it
    read is as it was (a proposer judges its selection, then runs it)."""
    if type(tx) is not ExchangeTransaction or tx.op_type != ExchangeOpType.TOKEN_TRANSFER:
        return None
    fingerprint = tx._fingerprint()
    key = None if fingerprint is None else (fingerprint, tx.public_key, tx.signature)
    memo = tx.__dict__.get("_lane_memo")
    if key is not None and memo is not None and memo[0] == key:
        return memo[1]  # type: ignore[no-any-return]
    out = _prepare(tx)
    if key is not None:
        tx.__dict__["_lane_memo"] = (key, out)
    return out


def _prepare(tx: Any) -> Optional[Prepared]:
    if tx.signer or (tx.public_key or b"")[:1] == b"{":
        return None
    p = tx.params
    if (
        not isinstance(p, dict)
        or not _PARAMS.issuperset(p)
        or not is_native_asset(p.get("token_address"))
    ):
        return None
    if isinstance(tx.gas_price, bool) or not isinstance(tx.gas_price, int) or tx.gas_price <= 0:
        return None
    try:
        with localcontext(_CTX):
            tx.validate_basic()
            tx.validate_fee()
            base_gas = GAS + tx.signature_gas()
            if tx.gas_limit < base_gas:
                return None
            value = token_amount(p["amount"])
            note = token_memo(p.get("memo"))
            to = str(p["to"])
            token_account(to)
            max_fee = tx.max_fee()
            fee = Decimal(base_gas) * Decimal(tx.gas_price) / _wei_per_qrdx()
    except (TokenError, ValueError, ArithmeticError, TypeError):
        return None
    return Prepared(value, to, note, max_fee, fee, base_gas)


def prepare_all(txs: Sequence[Any]) -> List[Optional[Prepared]]:
    if not enabled():
        return [None] * len(txs)
    return [prepare(tx) for tx in txs]


def runs(prepared: Sequence[Optional[Any]]) -> List[Tuple[int, int]]:
    """The maximal [start, end) runs of prepared transactions."""
    out, i = [], 0
    while i < len(prepared):
        if prepared[i] is None:
            i += 1
            continue
        j = i
        while j < len(prepared) and prepared[j] is not None:
            j += 1
        out.append((i, j))
        i = j
    return out


def _who_pays(mgr: Any, txs: Sequence[Any]) -> Optional[Dict[str, str]]:
    """Each sender's payer, if every one may sign for itself now; else None."""
    payers: Dict[str, str] = {}
    for tx in txs:
        if tx.sender in payers:
            continue
        if mgr.signer_error(tx):
            return None
        payers[tx.sender] = mgr.fee_payer(tx)
    return payers


def judge(
    mgr: Any,
    txs: Sequence[Any],
    prepared_run: Sequence[Optional[Prepared]],
    balance: Callable[[str], Any],
    nonces: Dict[str, int],
    owed: Dict[str, Decimal],
) -> bool:
    """``_inclusion_error`` over a run: True if every one may be in the block (``nonces`` and
    ``owed`` then updated as Python's would be); False to have Python judge the run."""
    fn = _native("lane_judge")
    prepared = [p for p in prepared_run if p is not None]
    if fn is None or not mgr.enforce_fees or len(prepared) != len(txs):
        return False
    payers = _who_pays(mgr, txs)
    if payers is None:
        return False
    lanes: Dict[str, int] = {}
    for tx in txs:
        lane = tx.nonce_key()
        if lane not in lanes:
            lanes[lane] = nonces.get(lane, mgr._nonces.get(lane, 0))
    held: Dict[str, Optional[str]] = {}
    owing: Dict[str, str] = {}
    for payer in set(payers.values()):
        b = balance(payer)
        held[payer] = None if b is None else str(b)
        if payer in owed:
            owing[payer] = str(owed[payer])
    out = fn(
        [
            (tx.nonce_key(), tx.nonce, payers[tx.sender], str(pr.max_fee))
            for tx, pr in zip(txs, prepared, strict=True)
        ],
        lanes,
        owing,
        held,
    )
    if out is None:
        return False
    new_nonces, new_owed = out
    nonces.update(new_nonces)
    for payer, value in new_owed.items():
        owed[payer] = Decimal(value)
    return True


def _above_floors(mgr: Any, txs: Sequence[Any], prepared: Sequence[Prepared]) -> bool:
    """Every sender keeps its fee floor (``ExchangeStateManager.fee_floor``) even if all its
    transfers in the run ran and nothing came in: otherwise Python runs the run, and refuses
    the transfer that would cross it."""
    sent: Dict[str, Decimal] = {}
    with localcontext(_CTX):
        for tx, pr in zip(txs, prepared, strict=True):
            sent[tx.sender] = sent.get(tx.sender, Decimal(0)) + pr.amount
        for sender, total in sent.items():
            floor = mgr.fee_floor(sender)
            held = mgr._available_balances.get(sender)
            if floor is not None and (held is None or held - total < floor):
                return False
    return True


def run(
    mgr: Any,
    txs: Sequence[Any],
    prepared_run: Sequence[Optional[Prepared]],
    prepaid_run: Sequence[Optional[Tuple[str, Decimal]]],
) -> Optional[List[ExchangeExecResult]]:
    """``process_transaction`` over a run of transfers judged includable: their results, the
    manager's state as Python's would leave it; None to have Python run them."""
    fn = _native("lane_run")
    prepared = [p for p in prepared_run if p is not None]
    prepaid = [p for p in prepaid_run if p is not None]
    if fn is None or not mgr.enforce_fees or not len(prepared) == len(prepaid) == len(txs):
        return None
    payers = _who_pays(mgr, txs)
    if payers is None:
        return None
    for tx, paid in zip(txs, prepaid, strict=True):
        if paid[0] != payers[tx.sender]:
            return None
    if mgr._fee_reserve is not None and not _above_floors(mgr, txs, prepared):
        return None
    lanes: Dict[str, int] = {}
    addresses: Dict[str, None] = {}
    for tx, pr, paid in zip(txs, prepared, prepaid, strict=True):
        lanes.setdefault(tx.nonce_key(), mgr._nonces.get(tx.nonce_key(), 0))
        for a in (tx.sender, pr.to, paid[0]):
            addresses.setdefault(a)
    deltas, avail = mgr._balance_deltas, mgr._available_balances
    out = fn(
        [
            (
                tx.nonce_key(),
                tx.nonce,
                tx.sender,
                pr.to,
                str(pr.amount),
                paid[0],
                str(paid[1]),
                str(pr.fee),
            )
            for tx, pr, paid in zip(txs, prepared, prepaid, strict=True)
        ],
        lanes,
        {a: (str(deltas[a]) if a in deltas else None) for a in addresses},
        {a: (str(avail[a]) if a in avail else None) for a in addresses},
        str(mgr._block_fees),
    )
    if out is None:
        return None
    outcomes, new_nonces, new_deltas, added, new_avail, fees = out

    # The state, through the same dicts and undo records; new delta keys in insertion order.
    for lane, n in new_nonces.items():
        if n != lanes[lane]:
            mgr._nonces[lane] = n
    values = dict(new_deltas)
    for a in values:
        undo.keep_entry(deltas, a, mutable=False, transient=True)
    for a, v in values.items():
        if a in deltas:
            deltas[a] = Decimal(v)
    for a in added:
        deltas[a] = Decimal(values[a])
    for a, v in new_avail:
        undo.keep_entry(avail, a, mutable=False, transient=True)
        avail[a] = Decimal(v)
    mgr._block_fees = Decimal(fees)

    # Each result, as process_transaction records it.
    results: List[ExchangeExecResult] = []
    for tx, pr, (ran, found) in zip(txs, prepared, outcomes, strict=True):
        if ran:
            data: Dict[str, Any] = {"token_address": "QRDX", "to": pr.to, "amount": str(pr.amount)}
            if pr.memo:
                data["memo"] = pr.memo
            result = ExchangeExecResult(success=True, gas_used=GAS, data=data)
            result.gas_used = min(int(tx.gas_limit), result.gas_used + tx.signature_gas())
        else:
            held = None if found is None else Decimal(found)
            result = ExchangeExecResult(
                success=False,
                error=f"TOKEN_TRANSFER: insufficient QRDX: need {pr.amount}, available {held}",
            )
            result.gas_used = pr.base_gas
        tx.gas_used = result.gas_used
        result.fee = pr.fee
        tx.success = result.success
        tx.result = result.data
        tx.error = result.error
        mgr._block_exchange_txs.append(tx)
        mgr._block_results.append(result)
        results.append(result)
    return results
