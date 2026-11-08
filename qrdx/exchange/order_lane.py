"""
Plain spot orders and cancels, run natively (native/qrdx-native/src/order_lane.rs;
docs/EXCHANGE_ENGINE.md, E3b).

A spot order costs Python about 200 µs: the transaction's wrapper, an undo scope, the router's
plan, matching, and each fill's settlement — a dozen ledger moves, fees, referrals, the stakers'
part. Over the native books (qrdx/exchange/native_book.py) all of it runs in Rust, a run of
consecutive plain orders and cancels at a time, and this module is the Python around it:

* ``prepare``: what Python's handler parses of a transaction, with Python's own functions, once
  a transaction — a limit order (its pair, side, price, amount, time in force, hidden or
  iceberg) or a cancel (its pair and order id), signed by its own account's single key, paying
  gas, of a well-formed transaction (``validate_basic``, ``validate_fee``) that does not expire.
  Anything else (a market or trigger order, a bracket, a builder fee, an agent's or a
  multisig's signature, the free lane, a value Python would refuse) is Python's. A prepared
  transaction is judged for the block natively, as a plain transfer is
  (``transfer_lane.judge``: its nonce, and its payer's fees).
* ``run``: per stretch of a run, what no operation in it can change — each pair's book and
  where its pools start to fill, whether a fill could reach a trigger or a bracket or count
  toward fee tiers, which tokens are paused or freeze a sender, who pays each sender's gas.
  The native run stops before the first operation it would not run exactly as Python does;
  Python runs that one (``process_transaction``) and the run continues after it.

What the native run changes goes back through Python's own dicts, with the same undo records
and keys entering in the same order. ``tests/test_order_lane.py`` runs random blocks both ways
and compares everything. ``QRDX_ORDER_LANE=0`` turns it off (``QRDX_NATIVE=0`` and
``QRDX_NATIVE_BOOK=0`` too).
"""

from __future__ import annotations

import time
import weakref
from decimal import Decimal, localcontext
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import native_book, undo
from .handlers.common import ExchangeExecResult
from .orderbook import _CTX
from .transactions import (
    EXCHANGE_GAS_COSTS,
    EXCHANGE_GAS_PER_MAKER,
    ExchangeOpType,
    ExchangeTransaction,
    _wei_per_qrdx,
    match_budget,
)

PLACE = EXCHANGE_GAS_COSTS[ExchangeOpType.PLACE_ORDER]
CANCEL = EXCHANGE_GAS_COSTS[ExchangeOpType.CANCEL_ORDER]
_PLACE_PARAMS = frozenset(
    {"pair", "side", "order_type", "price", "amount", "tif", "hidden", "display_size"}
)
_CANCEL_PARAMS = frozenset({"pair", "order_id"})
_MAX_GAS_PRICE = 1 << 62


def _native(name: str) -> Optional[Callable[..., Any]]:
    from .. import native

    if not native.AVAILABLE:
        return None
    return getattr(native._native, name, None)


def enabled() -> bool:
    import os

    if os.environ.get("QRDX_ORDER_LANE", "1") == "0":
        return False
    return _native("order_lane_run") is not None and native_book.available()


class Prepared:
    """What Python's handler parses of a plain order or cancel."""

    __slots__ = (
        "place",
        "pair",
        "order_id",
        "side",
        "price",
        "amount",
        "tif",
        "hidden",
        "display",
        "makers",
        "max_fee",
    )

    def __init__(
        self,
        place,
        pair,
        order_id,
        max_fee,
        side="",
        price="",
        amount="",
        tif="",
        hidden=False,
        display="0",
        makers=0,
    ) -> None:
        self.place, self.pair, self.order_id, self.max_fee = place, pair, order_id, max_fee
        self.side, self.price, self.amount, self.tif = side, price, amount, tif
        self.hidden, self.display, self.makers = hidden, display, makers


def prepare(tx: Any) -> Optional[Prepared]:
    """A plain limit order or cancel, as Python's handler reads it; None for anything else.
    Remembered while every field it read is as it was."""
    if type(tx) is not ExchangeTransaction or tx.op_type not in (
        ExchangeOpType.PLACE_ORDER,
        ExchangeOpType.CANCEL_ORDER,
    ):
        return None
    fingerprint = tx._fingerprint()
    key = None if fingerprint is None else (fingerprint, tx.public_key, tx.signature)
    memo = tx.__dict__.get("_order_lane_memo")
    if key is not None and memo is not None and memo[0] == key:
        return memo[1]  # type: ignore[no-any-return]
    out = _prepare(tx)
    if key is not None:
        tx.__dict__["_order_lane_memo"] = (key, out)
    return out


def _text(value: Any) -> Optional[str]:
    """``str(Decimal(str(value)))`` for a finite value (as the handler reads it); else None."""
    try:
        d = Decimal(str(value))
    except ArithmeticError:
        return None
    return str(d) if d.is_finite() else None


def _ascii(*values: Any) -> bool:
    return all(isinstance(v, str) and v.isascii() for v in values)


def _prepare(tx: Any) -> Optional[Prepared]:
    if tx.signer or (tx.public_key or b"")[:1] == b"{":
        return None
    gp = tx.gas_price
    if isinstance(gp, bool) or not isinstance(gp, int) or not 0 < gp < _MAX_GAS_PRICE:
        return None
    gl = tx.gas_limit
    if isinstance(gl, bool) or not isinstance(gl, int) or not 0 < gl < _MAX_GAS_PRICE:
        return None
    p = tx.params
    if not isinstance(p, dict) or not _ascii(tx.sender) or not isinstance(tx.nonce, int):
        return None
    try:
        with localcontext(_CTX):
            tx.validate_basic()
            tx.validate_fee()
            max_fee = tx.max_fee()
    except (ValueError, ArithmeticError, TypeError):
        return None
    pair = p.get("pair")
    if not isinstance(pair, str) or not pair.isascii() or ":" not in pair:
        return None
    if tx.op_type == ExchangeOpType.CANCEL_ORDER:
        order_id = p.get("order_id")
        if not _CANCEL_PARAMS.issuperset(p) or not _ascii(order_id) or gl < CANCEL:
            return None
        return Prepared(False, pair, order_id, max_fee)
    if not _PLACE_PARAMS.issuperset(p) or gl < PLACE:
        return None
    side, kind = p.get("side"), p.get("order_type")
    if not isinstance(side, str) or not isinstance(kind, str) or not _ascii(side, kind):
        return None
    if side.lower() not in ("buy", "sell") or kind.lower() != "limit":
        return None
    hidden = p.get("hidden", False)
    tif = str(p.get("tif", "gtc")).lower()
    if not isinstance(hidden, bool) or not tif.isascii():
        return None
    price, amount = _text(p.get("price")), _text(p.get("amount"))
    display = _text(p.get("display_size", "0"))
    if price is None or amount is None or display is None:
        return None
    makers = match_budget(ExchangeOpType.PLACE_ORDER, gl)
    return Prepared(
        True,
        pair,
        tx.tx_hash()[:16],
        max_fee,
        side.lower(),
        price,
        amount,
        tif,
        hidden,
        display,
        makers or 0,
    )


def prepare_all(txs: Sequence[Any]) -> List[Optional[Prepared]]:
    if not enabled():
        return [None] * len(txs)
    return [prepare(tx) for tx in txs]


def judged_together(transfers: Sequence[Any], orders: Sequence[Any]) -> List[Any]:
    """What ``section_errors`` judges natively: each transaction's transfer or order
    preparation (both carry its maximum fee), None for what Python judges."""
    return [t if t is not None else o for t, o in zip(transfers, orders, strict=True)]


class Critical(Exception):
    """An operation of the run that Python ran raised (the block is invalid): which, and why."""

    def __init__(self, index: int, error: Exception) -> None:
        super().__init__(str(error))
        self.index, self.error = index, error


def _handlers_are_own(mgr: Any) -> bool:
    """The manager runs its own handlers (a test may patch one: then Python runs it all)."""
    from .handlers import spot

    cls = type(mgr)
    return (
        "_op_place_order" not in mgr.__dict__
        and "_op_cancel_order" not in mgr.__dict__
        and getattr(cls, "_op_place_order", None) is spot._op_place_order
        and getattr(cls, "_op_cancel_order", None) is spot._op_cancel_order
        and getattr(cls, "_settle_orderbook", None) is spot._settle_orderbook
    )


class _Pairs:
    """The pairs a stretch of a run trades, each once: what its operations read of them."""

    def __init__(self, mgr: Any) -> None:
        self.mgr = mgr
        self.canonical: Dict[str, Optional[str]] = {}
        self.index: Dict[str, int] = {}
        self.rows: List[Tuple[Any, ...]] = []
        self.books: List[Any] = []
        self.names: List[str] = []
        idx = mgr.trading.spot_index() if len(mgr.trading.spot_triggers) else None
        self.triggered = (
            set()
            if idx is None
            else {pair for side in ("above", "below") for pair, lst in idx[side].items() if lst}
        )
        self.parents = set() if idx is None else set(idx["parents"])

    def pair_of(self, raw: str) -> Optional[str]:
        if raw not in self.canonical:
            pair = self.mgr._canonical_pair(raw)
            book = self.mgr._order_books.get(pair)
            ok = type(book) is native_book.NativeSpotBook and book.maker_guard is None
            self.canonical[raw] = pair if ok else None
        return self.canonical[raw]

    def slot(self, pair: str) -> int:
        i = self.index.get(pair)
        if i is None:
            i = self.index[pair] = len(self.rows)
            self.rows.append(self._row(pair))
            self.books.append(self.mgr._order_books[pair])
            self.names.append(pair)
        return i

    def _asset(self, token: str) -> Tuple[str, bool, bool]:
        from .tokens import is_native_asset

        if is_native_asset(token):
            return (token, True, False)
        t = self.mgr.tokens.peek(token)
        return (token, False, bool(t is not None and t.paused))

    def _pools(self, base: str, quote: str) -> Tuple[Optional[str], Optional[str]]:
        """Where the pair's pools start to fill a buyer (the lowest price, fee included) and a
        seller (the highest): an order that reaches one is Python's (the router's plan)."""
        buy: Optional[Decimal] = None
        sell: Optional[Decimal] = None
        with localcontext(_CTX):
            for pool in self.mgr.pool_manager.get_pools_for_pair(base, quote):
                if pool.is_paused or (pool.state.token0, pool.state.token1) != (base, quote):
                    continue
                f = pool.state.fee_tier.rate
                up, down = pool.liquid_sqrt(False), pool.liquid_sqrt(True)
                if up is not None:
                    eff = up * up / (1 - f)
                    buy = eff if buy is None or eff < buy else buy
                if down is not None:
                    eff = down * down * (1 - f)
                    sell = eff if sell is None or eff > sell else sell
        return (None if buy is None else str(buy)), (None if sell is None else str(sell))

    def _row(self, pair: str) -> Tuple[Any, ...]:
        mgr = self.mgr
        book = mgr._order_books[pair]
        base, quote = pair.split(":", 1)
        b, q = self._asset(base), self._asset(quote)
        buy_pool, sell_pool = self._pools(base, quote)
        has_stops = len(book._stop_orders) > 0
        places_bail = b[2] or q[2] or has_stops
        trades_bail = pair in self.triggered or mgr._settles_in_tier_unit(quote)
        handed = list(book._handed.keys())
        return (
            book._native,
            book._owner_nonces,
            pair,
            b,
            q,
            mgr.orderbook_escrow_address(pair),
            buy_pool,
            sell_pool,
            (places_bail, trades_bail, has_stops),
            handed,
        )


def _fee_info(mgr: Any) -> Callable[[str], Tuple[str, str, Optional[str], bool]]:
    from .clearinghouse import REFERRAL_VOLUME_CAP

    ch = mgr.clearinghouse

    def info(owner: str) -> Tuple[str, str, Optional[str], bool]:
        with localcontext(_CTX):
            taker, maker = ch.fee_rates(owner)
            ref = ch.referrals.peek(owner)
        if ref is None:
            return str(taker), str(maker), None, False
        return str(taker), str(maker), ref.referrer, ref.volume < REFERRAL_VOLUME_CAP

    return info


def _consts(mgr: Any) -> Tuple[Any, ...]:
    from .. import constants
    from ..validator.epoch_state import STAKER_FEE_HOLDER
    from .clearinghouse import REFEREE_DISCOUNT, REFERRER_SHARE

    with localcontext(_CTX):
        share = min(Decimal(1), Decimal(int(constants.STAKER_FEE_SHARE_BPS)) / 10_000)
        keep = 1 - REFEREE_DISCOUNT
    return (
        constants.SYSTEM_WALLET_ADDRESSES["TREASURY_MULTISIG"],
        STAKER_FEE_HOLDER,
        str(share),
        str(keep),
        str(REFERRER_SHARE),
        str(_wei_per_qrdx()),
        int(mgr._current_block_height),
        float(mgr._block_clock()),
        PLACE,
        CANCEL,
        EXCHANGE_GAS_PER_MAKER,
    )


def _payers(mgr: Any, txs: Sequence[Any]) -> Dict[str, Optional[str]]:
    """Each sender's payer, or None where it may not sign for itself now (Python's)."""
    out: Dict[str, Optional[str]] = {}
    for tx in txs:
        if tx.sender not in out:
            out[tx.sender] = None if mgr.signer_error(tx) else mgr.fee_payer(tx)
    return out


def run(
    mgr: Any,
    txs: Sequence[Any],
    prepared_run: Sequence[Optional[Prepared]],
    prepaid_run: Sequence[Optional[Tuple[str, Decimal]]],
) -> Optional[List[ExchangeExecResult]]:
    """``process_transaction`` over a run of plain orders and cancels judged includable: their
    results, the manager's state as Python's would leave it; None to have Python run them."""
    fn = _native("order_lane_run")
    if (
        fn is None
        or not native_book.available()
        or not (mgr.enforce_fees and mgr.enforce_orderbook_settlement)
        or not mgr.enforce_spot_settlement
        or not _handlers_are_own(mgr)
        or any(p is None for p in prepared_run)
        or any(p is None for p in prepaid_run)
    ):
        return None
    payers = _payers(mgr, txs)
    results: List[ExchangeExecResult] = []
    i = 0
    while i < len(txs):
        done = _stretch(mgr, fn, txs, prepared_run, prepaid_run, payers, i, results)
        i += done
        if i < len(txs):  # (the operation it stopped at: Python's)
            try:
                results.append(mgr.process_transaction(txs[i], prepaid_run[i], True))
            except Exception as e:
                raise Critical(i, e) from e
            i += 1
    return results


def _stretch(mgr, fn, txs, prepared, prepaid, payers, start, results) -> int:  # noqa: C901
    """Run natively from ``start`` until the first operation Python must run: how many ran."""
    pairs = _Pairs(mgr)
    triggers = mgr.trading.spot_triggers
    has_triggers = len(triggers) > 0
    ops: List[Tuple[Any, ...]] = []
    senders: Dict[Tuple[str, str], None] = {}
    now = time.time()
    for k in range(start, len(txs)):
        tx, pr, paid = txs[k], prepared[k], prepaid[k]
        payer = payers.get(tx.sender)
        pair = pairs.pair_of(pr.pair)
        if payer is None or paid[0] != payer or pair is None:
            break
        if (
            not pr.place
            and has_triggers
            and (pr.order_id in triggers or mgr.trading.bracket_of(pr.order_id) is not None)
        ):
            break
        slot = pairs.slot(pair)
        head = (
            pr.place,
            tx.nonce_key(),
            tx.nonce,
            tx.sender,
            payer,
            str(paid[1]),
            tx.gas_limit,
            tx.gas_price,
            slot,
            pr.order_id,
        )
        if pr.place:
            body = (pr.side, pr.price, pr.amount, pr.tif, pr.hidden, pr.display, now, pr.makers)
            ops.append((head, body))
            for token in pair.split(":", 1):
                senders.setdefault((tx.sender, token))
        else:
            ops.append((head, None))
    if not ops:
        return 0
    frozen = _frozen(mgr, senders)
    books = pairs.books
    saved = [b._native.copy() for b in books]  # (pointer copies)
    try:
        out = fn(
            ops,
            pairs.rows,
            frozen,
            pairs.parents,
            (
                mgr._balance_deltas,
                mgr._available_balances,
                mgr._token_balance_deltas,
                mgr._available_token_balances,
            ),
            mgr._nonces,
            mgr.fee_tokens,
            _fee_info(mgr),
            _consts(mgr),
            (str(mgr._block_fees), str(mgr._block_staker_fees)),
        )
    except Exception:
        # Nothing of Python's was written yet: the books as they were, and Python runs it.
        for book, s in zip(books, saved, strict=True):
            book._native = s
        return 0
    (
        done,
        outcomes,
        qrdx,
        tokens,
        lanes,
        book_nonces,
        fee_tokens,
        totals,
        placed,
        handed,
        detached,
    ) = out
    for book, s in zip(books, saved, strict=True):
        book._kept(s)  # (the undo scope's record of the book: no-op outside one)
    _write_back(mgr, qrdx, tokens, lanes, book_nonces, fee_tokens, totals, placed, books)
    for slot, d in handed:
        o = books[slot]._handed.get(d["id"])
        if o is not None:
            native_book._update(o, d)
    for slot in detached:
        books[slot]._handed = weakref.WeakValueDictionary()
    for book, name in zip(books, pairs.names, strict=True):
        if book.has_expiring:
            mgr._note_expiring(name)
    for k, (success, gas_used, fee, error, data) in enumerate(outcomes, start=start):
        tx = txs[k]
        result = ExchangeExecResult(success=success, gas_used=gas_used, data=data, error=error)
        result.fee = Decimal(fee)
        tx.gas_used = gas_used
        tx.success = success
        tx.result = result.data
        tx.error = error
        mgr._block_exchange_txs.append(tx)
        mgr._block_results.append(result)
        results.append(result)
    return int(done)


def _frozen(mgr: Any, senders: Dict[Tuple[str, str], None]) -> List[Tuple[str, str]]:
    """The (sender, token) pairs a token freezes: only a token with frozen holders, or one that
    freezes by default, can."""
    from .tokens import is_native_asset

    registry = mgr.tokens
    out = []
    for sender, token in senders:
        if is_native_asset(token):
            continue
        t = registry.tokens.peek(str(token).lower())
        if not registry.frozen and not (t is not None and t.default_frozen):
            continue
        if registry.is_frozen(token, sender):
            out.append((sender, token))
    return out


def _write_back(mgr, qrdx, tokens, lanes, book_nonces, fee_tokens, totals, placed, books) -> None:
    """What the native run changed, through Python's own dicts and undo records."""
    deltas, avail = mgr._balance_deltas, mgr._available_balances
    for address, delta, held in qrdx:
        undo.keep_entry(deltas, address, mutable=False)
        deltas[address] = Decimal(delta)
        if held is not None:
            undo.keep_entry(avail, address, mutable=False)
            avail[address] = Decimal(held)
    deltas, avail = mgr._token_balance_deltas, mgr._available_token_balances
    for key, delta, held in tokens:
        key = tuple(key)
        undo.keep_entry(deltas, key, mutable=False)
        deltas[key] = Decimal(delta)
        if held is not None:
            undo.keep_entry(avail, key, mutable=False)
            avail[key] = Decimal(held)
    for lane, n in lanes:
        mgr._nonces[lane] = n
    for slot, owner, n in book_nonces:
        books[slot]._owner_nonces[owner] = n
    for token, pending in fee_tokens:
        old = mgr.fee_tokens.peek(token)
        mgr.fee_tokens[token] = (Decimal(pending), old[1] if old is not None else Decimal("0"))
    undo.keep(mgr, mgr._UNDO_FIELDS, "manager", shallow=True)
    mgr._block_fees = Decimal(totals[0])
    mgr._block_staker_fees = Decimal(totals[1])
    mgr._total_orders += placed
