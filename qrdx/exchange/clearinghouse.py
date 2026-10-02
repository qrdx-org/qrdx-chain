"""
Perpetuals clearinghouse — order-book-matched, zero-sum perps (docs/PERPS_CLEARINGHOUSE.md).

Every perp trade is a fill between a buyer and a seller on the market's order book, so both
accounts' positions change by equal and opposite amounts and every market's net size stays
zero. All perp collateral sits in ONE clearinghouse holder; realized PnL, fees and isolated
margin move between internal account records only. Real QRDX moves solely on deposit and
withdraw, which the exchange manager turns into balance deltas for the trader and the holder.

That replaces ``PerpEngine``, whose positions had no counterparty: closing paid PnL into a
real balance that nobody was debited for, so QRDX was minted on every win and burned on every
loss.

Exactness. Entry prices are stored quantized (``ENTRY_QUANTUM``); a position's cost basis is
always exactly ``size × entry``. When averaging into a position the quantized entry differs
from the exact average by a tiny residual, which is charged to that account's collateral. That
keeps the clearinghouse identity exact rather than approximately true:

    holder_balance  ==  Σ collateral records  −  Σ size × entry        (always)

Since every market's sizes sum to zero, Σ size × (X − entry) is the same for every price X,
so the identity says the holder holds exactly what all the accounts are worth.
"""
from __future__ import annotations

import functools
import hashlib
import json
from dataclasses import dataclass, field
from decimal import (ROUND_CEILING, ROUND_DOWN, ROUND_FLOOR, ROUND_HALF_EVEN, Context, Decimal,
                     localcontext)
from typing import Dict, List, Optional, Tuple

from .orderbook import Order, OrderBook, OrderSide, OrderType, SelfTradeAction

ZERO = Decimal(0)
TWO = Decimal(2)

DEFAULT_MAX_LEVERAGE = Decimal("20")
DEFAULT_LEVERAGE = Decimal("10")       # until an account sets one; capped at the market max
MAKER_FEE_RATE = Decimal("0.0002")     # 0.02 % of fill notional
TAKER_FEE_RATE = Decimal("0.0005")     # 0.05 %
ENTRY_QUANTUM = Decimal("1e-18")       # entry prices are stored at this precision
AMOUNT_QUANTUM = Decimal("1e-18")      # deposits/withdrawals: QRDX wei precision

# Mark price (Phase 2). Hyperliquid: median of (oracle + 150 s EMA of book premium),
# (median of best bid, best ask, last trade) and external perp prices — with a 30 s EMA of the
# book median standing in when only two inputs exist, as here (no external perp feed). Without
# that external anchor a thin book could drag the mark, so it is also held within a band of the
# oracle — a deliberate addition to Hyperliquid's rule.
PREMIUM_EMA_SECONDS = Decimal("150")
BOOK_EMA_SECONDS = Decimal("30")
MARK_ORACLE_BAND = Decimal("0.05")

# Liquidations and the backstop vault (Phase 3). An account below maintenance margin is first
# closed on the book, never past its bankruptcy price; one still below BACKSTOP_FRACTION of
# maintenance is taken over by the vault at mark; one the vault cannot cover is auto-deleveraged.
BACKSTOP_FRACTION = Decimal(2) / Decimal(3)
LIQUIDATION_PASSES = 4    # an auto-deleverage can push a counterparty under; re-check, bounded
SHARE_QUANTUM = Decimal("1e-18")
# Funding (Phase 4), Hyperliquid's formula. Each block samples the premium of the book's impact
# prices (the average price to trade IMPACT_NOTIONAL) over the oracle; at every interval boundary
# of block time, F = average premium + clamp(interest − premium, ±FUNDING_PREMIUM_CLAMP) is the
# 8-hour rate, of which the interval's share is paid — capped at FUNDING_CAP_PER_HOUR. Payment =
# size × oracle × rate, longs to shorts when positive: zero-sum, peer to peer.
DEFAULT_FUNDING_INTERVAL = Decimal(3600)
FUNDING_INTEREST_8H = Decimal("0.0001")      # 0.01 % per 8 hours
FUNDING_PREMIUM_CLAMP = Decimal("0.0005")
FUNDING_CAP_PER_HOUR = Decimal("0.04")
IMPACT_NOTIONAL = Decimal("1000")            # QRDX
EIGHT_HOURS = Decimal(8 * 3600)
RATE_QUANTUM = Decimal("1e-18")

# Reserved owners. Exchange senders are signature-verified PQ addresses, so no key can act as
# either of these.
VAULT = "@vault"          # the backstop vault's own margin account (collateral + positions)
PROTOCOL = "@protocol"    # owner of vault shares that belong to the protocol (treasury seed)


# Pinned arithmetic context. The process-wide Decimal context is not a safe default: importing
# qrdx.exchange.amm changes it, so results would depend on import order.
_CONTEXT = Context(prec=78, rounding=ROUND_HALF_EVEN)


def _pinned(method):
    @functools.wraps(method)
    def wrapper(*args, **kwargs):
        with localcontext(_CONTEXT):
            return method(*args, **kwargs)
    return wrapper


class ClearinghouseError(ValueError):
    """An operation the clearinghouse refuses. Nothing has been changed when it is raised."""


def _q_entry(x: Decimal) -> Decimal:
    return x.quantize(ENTRY_QUANTUM, rounding=ROUND_HALF_EVEN)


def _ema_step(num: Decimal, den: Decimal, sample: Decimal, dt: Decimal,
              timescale: Decimal, anchor: Decimal) -> Tuple[Decimal, Decimal]:
    """Hyperliquid's time-weighted EMA: num ← num·e^(−dt/τ) + sample·dt; den likewise with 1.
    A sample with no elapsed time has no weight. An EMA with no history starts at ``anchor``
    (what the oracle implies) with a full timescale of weight — as if it had always sat there —
    so the first book a market ever shows is smoothed like any other sample instead of becoming
    the EMA outright: a trader's own far-apart quotes cannot set the mark on a fresh market.
    Quantized so the state stays compact and its canonical form never depends on how many
    zero-length steps a node happened to take."""
    if den <= 0:
        num, den = _q_entry(anchor * timescale), _q_entry(timescale)
    if dt <= 0:
        return num, den
    decay = (-(dt / timescale)).exp()
    return _q_entry(num * decay + sample * dt), _q_entry(den * decay + dt)


def _q_amount(x: Decimal) -> Decimal:
    """Every value moved between records is a whole number of wei. A quotient such as
    30000 / 7 has ~74 decimal digits; adding it to a six-digit balance needs more digits than
    the context holds, so the transfer would round and leak value."""
    return x.quantize(AMOUNT_QUANTUM, rounding=ROUND_HALF_EVEN)


@dataclass
class Position:
    size: Decimal = ZERO               # signed: + long, − short
    entry_price: Decimal = ZERO        # average entry, quantized
    isolated_margin: Decimal = ZERO    # only for isolated positions

    @property
    def basis(self) -> Decimal:
        return self.size * self.entry_price


@dataclass
class Account:
    collateral: Decimal = ZERO                                    # cross collateral (realized)
    positions: Dict[str, Position] = field(default_factory=dict)  # market_id → position
    leverage: Dict[str, Decimal] = field(default_factory=dict)    # market_id → leverage
    isolated: Dict[str, bool] = field(default_factory=dict)       # market_id → isolated mode


@dataclass
class OrderMeta:
    """What the clearinghouse needs about a resting order that the book does not track."""
    owner: str
    leverage: Decimal
    reduce_only: bool


@dataclass
class Market:
    id: str
    base: str
    quote: str
    max_leverage: Decimal
    book: OrderBook
    oracle_price: Decimal = ZERO
    oracle_time: Decimal = ZERO          # block time the oracle was last set; 0 = unknown
    mark_price: Decimal = ZERO
    last_trade_price: Decimal = ZERO
    open_interest: Decimal = ZERO        # Σ long sizes (= Σ short sizes)
    orders: Dict[str, OrderMeta] = field(default_factory=dict)
    # Mark-price state: time-weighted EMAs on block time (numerator / denominator).
    premium_num: Decimal = ZERO
    premium_den: Decimal = ZERO
    book_num: Decimal = ZERO
    book_den: Decimal = ZERO
    ema_time: Decimal = ZERO             # block time of the last EMA update; 0 = never
    # Funding state: the premium accumulated (time-weighted) since the last settlement.
    funding_time: Decimal = ZERO         # block-time boundary of the last settlement; 0 = never
    premium_sum: Decimal = ZERO
    premium_time: Decimal = ZERO
    funding_rate: Decimal = ZERO         # the rate last paid, per interval

    @property
    def maintenance_rate(self) -> Decimal:
        """Half the initial margin at maximum leverage (Hyperliquid's rule)."""
        return Decimal(1) / (TWO * self.max_leverage)


class Clearinghouse:
    """Perp markets, their order books, and every trader's margin account."""

    def __init__(self) -> None:
        self.markets: Dict[str, Market] = {}
        self.accounts: Dict[str, Account] = {}
        # The backstop vault is the margin account ``VAULT``: fees accrue to it, and it takes
        # over positions the book could not close. Depositors own it through shares.
        self.vault_shares: Dict[str, Decimal] = {}
        self.vault_total_shares: Decimal = ZERO
        self.vault_unlock: Dict[str, Decimal] = {}    # owner → block time its shares unlock
        # Mirror of the clearinghouse holder's real balance: deposits minus withdrawals.
        self.holder_balance: Decimal = ZERO

    @property
    def vault_collateral(self) -> Decimal:
        vault = self.accounts.get(VAULT)
        return vault.collateral if vault is not None else ZERO

    # ------------------------------------------------------------------ markets

    @staticmethod
    def market_id(base: str, quote: str = "QRDX") -> str:
        return f"{base}-{quote}-PERP"

    @_pinned
    def create_market(self, base: str, quote: str = "QRDX",
                      max_leverage: Decimal = DEFAULT_MAX_LEVERAGE) -> Market:
        if not base:
            raise ClearinghouseError("base token required")
        max_leverage = Decimal(str(max_leverage))
        if max_leverage < 1:
            raise ClearinghouseError("max leverage must be at least 1")
        mid = self.market_id(base, quote)
        if mid in self.markets:
            raise ClearinghouseError(f"market {mid} already exists")
        book = OrderBook(pool_id=mid, maker_fee_rate=MAKER_FEE_RATE,
                         taker_fee_rate=TAKER_FEE_RATE,
                         self_trade_action=SelfTradeAction.CANCEL_TAKER)
        market = Market(id=mid, base=base, quote=quote, max_leverage=max_leverage, book=book)
        self.markets[mid] = market
        return market

    def market(self, market_id: str) -> Market:
        m = self.markets.get(market_id)
        if m is None:
            raise ClearinghouseError(f"market {market_id} not found")
        return m

    @_pinned
    def set_oracle_price(self, market_id: str, price: Decimal, now=None) -> None:
        """Set the oracle (index) price — at block time ``now``, when known, for the staleness
        guard — and re-derive the mark from it without advancing the EMAs: they move only with
        block time, in ``tick``."""
        price = Decimal(str(price))
        if price <= 0:
            raise ClearinghouseError("oracle price must be positive")
        m = self.market(market_id)
        m.oracle_price = price
        if now is not None:
            m.oracle_time = Decimal(str(now))
        self._refresh_mark(m, m.ema_time)

    def new_block(self, now=None) -> None:
        for m in self.markets.values():
            m.book.new_block(now)

    @_pinned
    def tick(self, now, funding_interval=None) -> List[dict]:
        """Per-block duties, run on EVERY block on every path (block_processor.run_exchange_tick):
        advance the mark-price EMAs to block time ``now``, sample the funding premium and pay
        funding at an interval boundary, then liquidate every account below maintenance at the
        new marks. Returns what happened, as events: ``{"type": "funding", ...}`` for each
        settlement and ``{"type": "liquidation", ...}`` for each liquidation that acted."""
        now = Decimal(str(now))
        interval = Decimal(str(funding_interval or DEFAULT_FUNDING_INTERVAL))
        events: List[dict] = []
        for mid in sorted(self.markets):
            m = self.markets[mid]
            dt = max(ZERO, now - m.ema_time) if m.ema_time > 0 else ZERO
            self._refresh_mark(m, now)
            self._sample_premium(m, dt)
            settled = self._settle_funding(m, now, interval)
            if settled is not None:
                events.append(settled)
        return events + self._liquidate_all()

    # ------------------------------------------------------------------ funding

    def _impact_price(self, m: Market, bids: bool) -> Optional[Decimal]:
        """Average price to sell (``bids``) or buy IMPACT_NOTIONAL on the book; None if the
        book is not that deep."""
        levels = m.book.get_bids(10 ** 9) if bids else m.book.get_asks(10 ** 9)
        cost = size = ZERO
        for price, amount in levels:
            price, amount = Decimal(str(price)), Decimal(str(amount))
            if cost + price * amount >= IMPACT_NOTIONAL:
                size += (IMPACT_NOTIONAL - cost) / price
                return IMPACT_NOTIONAL / size
            cost += price * amount
            size += amount
        return None

    def _sample_premium(self, m: Market, dt: Decimal) -> None:
        """Hyperliquid's premium: (max(0, impact bid − oracle) − max(0, oracle − impact ask)) /
        oracle, weighted by the block time it stood for."""
        if dt <= 0 or m.oracle_price <= 0:
            return
        o = m.oracle_price
        bid, ask = self._impact_price(m, bids=True), self._impact_price(m, bids=False)
        sample = ZERO
        if bid is not None:
            sample += max(ZERO, bid - o)
        if ask is not None:
            sample -= max(ZERO, o - ask)
        m.premium_sum = _q_entry(m.premium_sum + sample / o * dt)
        m.premium_time += dt

    def _settle_funding(self, m: Market, now: Decimal, interval: Decimal) -> Optional[dict]:
        """At each interval boundary of block time, pay one interval's funding. (After a halt
        of several intervals, one is paid: there were no premium samples for the rest.)
        Returns the settlement as an event, or None when nothing was due."""
        if m.oracle_price <= 0:
            return None
        boundary = (now // interval) * interval
        if m.funding_time == 0:
            m.funding_time = boundary
            return None
        if now < m.funding_time + interval:
            return None
        avg = m.premium_sum / m.premium_time if m.premium_time > 0 else ZERO
        f8 = avg + min(max(FUNDING_INTEREST_8H - avg, -FUNDING_PREMIUM_CLAMP),
                       FUNDING_PREMIUM_CLAMP)
        cap = FUNDING_CAP_PER_HOUR * interval / 3600
        rate = min(max(f8 * interval / EIGHT_HOURS, -cap), cap).quantize(RATE_QUANTUM)
        self._pay_funding(m, rate)
        m.funding_rate = rate
        m.funding_time = boundary
        m.premium_sum = m.premium_time = ZERO
        return {"type": "funding", "market": m.id, "rate": str(rate), "premium": str(avg),
                "oracle_price": str(m.oracle_price), "open_interest": str(m.open_interest),
                "funding_time": str(boundary)}

    def _pay_funding(self, m: Market, rate: Decimal) -> None:
        """size × oracle × rate from every position (longs pay when positive, shorts receive).
        Isolated positions pay from their own margin. Rounding each payment to wei leaves a
        few wei over or short; the vault takes that, so the payments sum to exactly zero."""
        if rate == 0:
            return
        total = ZERO
        for owner in sorted(self.accounts):
            a = self.accounts[owner]
            p = a.positions.get(m.id)
            if p is None or p.size == 0:
                continue
            pay = _q_amount(p.size * m.oracle_price * rate)
            if a.isolated.get(m.id, False):
                p.isolated_margin -= pay
            else:
                a.collateral -= pay
            total += pay
        if total != 0:
            self.account(VAULT).collateral += total

    def _refresh_mark(self, m: Market, now: Decimal) -> None:
        """mark = median(oracle + premium EMA, book median, book-median EMA), held within
        ±MARK_ORACLE_BAND of the oracle. Liquidations trigger on mark, not the last trade, so
        one large trade or a spoofed order on a thin book cannot move it far on its own."""
        if m.oracle_price <= 0:
            return
        dt = max(ZERO, now - m.ema_time) if m.ema_time > 0 else ZERO
        bid, ask = m.book.best_bid, m.book.best_ask
        last = m.last_trade_price if m.last_trade_price > 0 else None
        if bid is not None and ask is not None:
            mid = (Decimal(str(bid)) + Decimal(str(ask))) / TWO
            m.premium_num, m.premium_den = _ema_step(
                m.premium_num, m.premium_den, mid - m.oracle_price, dt, PREMIUM_EMA_SECONDS,
                anchor=ZERO)
        book = None
        if bid is not None and ask is not None and last is not None:
            book = sorted([Decimal(str(bid)), Decimal(str(ask)), last])[1]
            m.book_num, m.book_den = _ema_step(m.book_num, m.book_den, book, dt,
                                               BOOK_EMA_SECONDS, anchor=m.oracle_price)
        if now > 0:
            m.ema_time = now
        premium = m.premium_num / m.premium_den if m.premium_den > 0 else ZERO
        inputs = [m.oracle_price + premium]
        if book is not None:
            inputs += [book, m.book_num / m.book_den if m.book_den > 0 else book]
        mark = sorted(inputs)[len(inputs) // 2]
        lo = m.oracle_price * (1 - MARK_ORACLE_BAND)
        hi = m.oracle_price * (1 + MARK_ORACLE_BAND)
        m.mark_price = _q_entry(min(max(mark, lo), hi))

    # ------------------------------------------------------------------ accounts

    def account(self, owner: str) -> Account:
        acct = self.accounts.get(owner)
        if acct is None:
            acct = self.accounts[owner] = Account()
        return acct

    @staticmethod
    def _user(owner: str) -> str:
        if owner in (VAULT, PROTOCOL):
            raise ClearinghouseError(f"{owner} is a reserved account")
        return owner

    @staticmethod
    def _amount(amount) -> Decimal:
        amount = Decimal(str(amount))
        if amount <= 0:
            raise ClearinghouseError("amount must be positive")
        if amount != amount.quantize(AMOUNT_QUANTUM):
            raise ClearinghouseError("amount has more than 18 decimal places")
        return amount

    @_pinned
    def deposit(self, owner: str, amount) -> Decimal:
        self._user(owner)
        amount = self._amount(amount)
        self.account(owner).collateral += amount
        self.holder_balance += amount
        return amount

    @_pinned
    def withdrawable(self, owner: str) -> Decimal:
        """Realized collateral not needed as margin. Unrealized profit must be realized first."""
        acct = self.accounts.get(owner)
        if acct is None:
            return ZERO
        free = self.cross_equity(owner) - self.cross_requirement(owner)
        return max(ZERO, min(acct.collateral, free))

    @_pinned
    def withdraw(self, owner: str, amount) -> Decimal:
        self._user(owner)
        amount = self._amount(amount)
        if amount > self.withdrawable(owner):
            raise ClearinghouseError(
                f"withdrawal of {amount} exceeds the withdrawable {self.withdrawable(owner)}")
        if amount > self.holder_balance:          # cannot happen while the identity holds
            raise ClearinghouseError("clearinghouse holder cannot cover the withdrawal")
        self.accounts[owner].collateral -= amount
        self.holder_balance -= amount
        return amount

    @_pinned
    def set_leverage(self, owner: str, market_id: str, leverage, isolated: bool) -> None:
        self._user(owner)
        m = self.market(market_id)
        leverage = Decimal(str(leverage))
        if leverage < 1 or leverage > m.max_leverage:
            raise ClearinghouseError(f"leverage must be between 1 and {m.max_leverage}")
        acct = self.account(owner)
        pos = acct.positions.get(market_id)
        busy = (pos is not None and pos.size != 0) or any(
            o.owner == owner for o in m.orders.values())
        if busy and bool(isolated) != acct.isolated.get(market_id, False):
            raise ClearinghouseError("cannot change margin mode with an open position or orders")
        if busy and pos is not None and pos.size != 0 and acct.isolated.get(market_id, False):
            raise ClearinghouseError("cannot change an isolated position's leverage while open")
        before = (acct.leverage.get(market_id), acct.isolated.get(market_id))
        acct.leverage[market_id] = leverage
        acct.isolated[market_id] = bool(isolated)
        if self.cross_equity(owner) < self.cross_requirement(owner):
            for store, value in ((acct.leverage, before[0]), (acct.isolated, before[1])):
                if value is None:
                    store.pop(market_id, None)
                else:
                    store[market_id] = value
            raise ClearinghouseError("insufficient margin for that leverage")

    def _leverage(self, acct: Account, m: Market) -> Decimal:
        return acct.leverage.get(m.id, min(DEFAULT_LEVERAGE, m.max_leverage))

    # ------------------------------------------------------------------ backstop vault

    @_pinned
    def vault_nav(self) -> Decimal:
        """What the vault is worth: its collateral plus its positions' PnL at mark."""
        return self.cross_equity(VAULT)

    def _mint_shares(self, holder: str, shares: Decimal) -> None:
        self.vault_shares[holder] = self.vault_shares.get(holder, ZERO) + shares
        self.vault_total_shares += shares

    @_pinned
    def vault_deposit(self, owner: str, amount, now, lockup, protocol: bool = False) -> Decimal:
        """Move ``amount`` of the owner's free collateral into the vault for shares at NAV;
        they unlock ``lockup`` seconds of block time later. ``protocol``: a treasury seed —
        the shares belong to PROTOCOL and never unlock. Returns the shares minted."""
        self._user(owner)
        amount = self._amount(amount)
        now, lockup = Decimal(str(now)), Decimal(str(lockup))
        if amount > self.withdrawable(owner):
            raise ClearinghouseError(
                f"vault deposit of {amount} exceeds the withdrawable {self.withdrawable(owner)}")
        nav = self.vault_nav()
        if self.vault_total_shares > 0 and nav <= 0:
            # Wiped out: the old shares are worth nothing. Write them off, start afresh.
            self.vault_shares, self.vault_unlock = {}, {}
            self.vault_total_shares = ZERO
        if self.vault_total_shares == 0 and nav > 0:
            # Value that accrued before anyone held shares (fees) belongs to the protocol.
            self._mint_shares(PROTOCOL, nav.quantize(SHARE_QUANTUM, rounding=ROUND_DOWN))
        if self.vault_total_shares == 0:
            shares = amount
        else:
            shares = (amount * self.vault_total_shares / nav).quantize(
                SHARE_QUANTUM, rounding=ROUND_DOWN)
        if shares <= 0:
            raise ClearinghouseError("deposit too small for a share")
        self.accounts[owner].collateral -= amount
        self.account(VAULT).collateral += amount
        if protocol:
            self._mint_shares(PROTOCOL, shares)
        else:
            self._mint_shares(owner, shares)
            self.vault_unlock[owner] = max(self.vault_unlock.get(owner, ZERO), now + lockup)
        return shares

    @_pinned
    def vault_withdraw(self, owner: str, shares, now) -> Decimal:
        """Redeem shares at NAV into the owner's collateral. Refused while locked, or beyond
        what the vault can release without dropping below margin on its own positions.
        Returns the value paid out (rounded down: the remaining holders keep the dust)."""
        self._user(owner)
        shares, now = Decimal(str(shares)), Decimal(str(now))
        if shares <= 0 or shares != shares.quantize(SHARE_QUANTUM):
            raise ClearinghouseError("shares must be positive with at most 18 decimal places")
        have = self.vault_shares.get(owner, ZERO)
        if shares > have:
            raise ClearinghouseError(f"only {have} vault shares held")
        unlock = self.vault_unlock.get(owner, ZERO)
        if now < unlock:
            raise ClearinghouseError(f"vault shares are locked until block time {unlock}")
        nav = self.vault_nav()
        value = ZERO
        if nav > 0:
            value = (shares * nav / self.vault_total_shares).quantize(
                AMOUNT_QUANTUM, rounding=ROUND_DOWN)
        if value > self.withdrawable(VAULT):
            raise ClearinghouseError(
                "the vault cannot release that much while it carries positions")
        self.account(VAULT).collateral -= value
        self.account(owner).collateral += value
        self.vault_shares[owner] = have - shares
        self.vault_total_shares -= shares
        if self.vault_shares[owner] == 0:
            del self.vault_shares[owner]
            self.vault_unlock.pop(owner, None)
        return value

    # ------------------------------------------------------------------ margin math

    @staticmethod
    def _upnl(m: Market, pos: Position) -> Decimal:
        return pos.size * (m.mark_price - pos.entry_price)

    @_pinned
    def cross_equity(self, owner: str) -> Decimal:
        """Cross collateral plus the unrealized PnL of every cross position, at mark."""
        acct = self.accounts.get(owner)
        if acct is None:
            return ZERO
        eq = acct.collateral
        for mid, pos in acct.positions.items():
            if pos.size != 0 and not acct.isolated.get(mid, False):
                eq += self._upnl(self.markets[mid], pos)
        return eq

    @_pinned
    def open_order_margin(self, owner: str) -> Decimal:
        """Margin reserved by resting orders that could increase exposure (cross or isolated:
        isolated margin is drawn from cross collateral when the order fills)."""
        total = ZERO
        for m in self.markets.values():
            for oid, meta in m.orders.items():
                if meta.owner != owner or meta.reduce_only:
                    continue
                order = m.book.get_order(oid)
                if order is not None and order.is_active:
                    total += order.remaining * order.price / meta.leverage
        return total

    @_pinned
    def cross_requirement(self, owner: str) -> Decimal:
        """Initial margin for every cross position at mark, plus resting-order reservations."""
        acct = self.accounts.get(owner)
        if acct is None:
            return ZERO
        req = ZERO
        for mid, pos in acct.positions.items():
            if pos.size != 0 and not acct.isolated.get(mid, False):
                m = self.markets[mid]
                req += abs(pos.size) * m.mark_price / self._leverage(acct, m)
        return req + self.open_order_margin(owner)

    @_pinned
    def cross_maintenance(self, owner: str) -> Decimal:
        acct = self.accounts.get(owner)
        if acct is None:
            return ZERO
        total = ZERO
        for mid, pos in acct.positions.items():
            if pos.size != 0 and not acct.isolated.get(mid, False):
                m = self.markets[mid]
                total += abs(pos.size) * m.mark_price * m.maintenance_rate
        return total

    # ------------------------------------------------------------------ trading

    @_pinned
    def place_order(self, owner: str, market_id: str, order_id: str, side: str,
                    size, price, nonce: int, reduce_only: bool = False,
                    ioc: bool = False) -> List[dict]:
        """
        Place a limit order. Matches against the book; any remainder rests (or is cancelled if
        ``ioc``). Returns the fills. Refuses — changing nothing — if the account could not
        carry the result at initial margin assuming a full fill at the worst price the limit
        allows.
        """
        self._user(owner)
        m = self.market(market_id)
        if m.mark_price <= 0:
            raise ClearinghouseError(f"market {market_id} has no price yet")
        size, price = Decimal(str(size)), Decimal(str(price))
        if size <= 0 or price <= 0:
            raise ClearinghouseError("size and price must be positive")
        buy = str(side).lower() in ("buy", "long", "bid")
        if not buy and str(side).lower() not in ("sell", "short", "ask"):
            raise ClearinghouseError(f"unknown side {side!r}")
        acct = self.account(owner)
        pos = acct.positions.get(market_id, Position())
        lev = self._leverage(acct, m)
        q = size if buy else -size

        if reduce_only:
            if pos.size == 0 or (pos.size > 0) == buy or size > abs(pos.size):
                raise ClearinghouseError("reduce-only order would not reduce the position")
        else:
            self._check_initial_margin(owner, acct, m, pos, q, price, lev)

        order = Order(id=order_id, owner=owner,
                      side=OrderSide.BUY if buy else OrderSide.SELL,
                      order_type=OrderType.LIMIT, price=price, amount=size,
                      nonce=nonce, timestamp=0.0)
        trades = m.book.place_order(order)
        m.orders[order_id] = OrderMeta(owner=owner, leverage=lev, reduce_only=bool(reduce_only))

        fills = []
        for tr in trades:
            fills.append(self._apply_fill(m, tr, taker_limit=price))
        if ioc and order.is_active:
            m.book.cancel_order(order_id, caller=owner)
        self._prune_orders(m)
        return fills

    @_pinned
    def cancel_order(self, owner: str, market_id: str, order_id: str) -> None:
        m = self.market(market_id)
        meta = m.orders.get(order_id)
        if meta is None or meta.owner != owner:
            raise ClearinghouseError(f"no open order {order_id} for this account")
        m.book.cancel_order(order_id, caller=owner)
        self._prune_orders(m)

    def _prune_orders(self, m: Market) -> None:
        for oid in [oid for oid in m.orders if m.book.get_order(oid) is None
                    or not m.book.get_order(oid).is_active]:
            del m.orders[oid]

    def _check_initial_margin(self, owner: str, acct: Account, m: Market, pos: Position,
                              q: Decimal, limit: Decimal, lev: Decimal) -> None:
        """Worst case of a full fill at the limit: buys fill at or below it, sells at or above."""
        increase = max(ZERO, abs(pos.size + q) - abs(pos.size))
        worst_pnl = q * (m.mark_price - limit)              # value change vs mark at the limit
        worst_fee = abs(q) * limit * TAKER_FEE_RATE
        free = self.cross_equity(owner) - self.cross_requirement(owner)
        if acct.isolated.get(m.id, False):
            # The new exposure's margin comes out of cross collateral at fill time.
            need = increase * limit / lev + worst_fee
            iso_equity = pos.isolated_margin + self._upnl(m, pos) + worst_pnl + increase * limit / lev
            if free < need or iso_equity < abs(pos.size + q) * m.mark_price / lev:
                raise ClearinghouseError("insufficient margin for the order")
            return
        current = abs(pos.size) * m.mark_price / lev
        after = abs(pos.size + q) * m.mark_price / lev
        if free + worst_pnl - worst_fee < after - current:
            raise ClearinghouseError("insufficient margin for the order")

    # ------------------------------------------------------------------ fills

    def _apply_fill(self, m: Market, tr, taker_limit: Decimal) -> dict:
        price, amount = Decimal(str(tr.price)), Decimal(str(tr.amount))
        maker_meta = m.orders.get(tr.maker_order_id)
        maker = maker_meta.owner if maker_meta else None
        out = {"market": m.id, "price": str(price), "amount": str(amount), "buyer": tr.buyer,
               "seller": tr.seller, "maker": maker, "realized": {}}
        for owner, q in ((tr.buyer, amount), (tr.seller, -amount)):
            fee = Decimal(str(tr.maker_fee if owner == maker else tr.taker_fee))
            lev = (maker_meta.leverage if owner == maker and maker_meta
                   else self._leverage(self.account(owner), m))
            # Isolated margin is sized at the lower of the fill price and the order's limit:
            # a sell can fill above its limit, and the pre-trade check only reserved margin
            # at the limit.
            margin_price = price if owner == maker else min(price, taker_limit)
            out["realized"][owner] = str(self._trade_into(owner, m, q, price, lev, margin_price))
            acct = self.accounts[owner]
            acct.collateral -= fee
            self.account(VAULT).collateral += fee
        m.last_trade_price = price
        return out

    def _trade_into(self, owner: str, m: Market, q: Decimal, price: Decimal,
                    lev: Decimal, margin_price: Decimal) -> Decimal:
        """Apply a signed fill of ``q`` at ``price`` to ``owner``'s position. Returns the
        realized PnL. Keeps cost basis exactly size × entry (see the module docstring)."""
        acct = self.account(owner)
        isolated = acct.isolated.get(m.id, False)
        pos = acct.positions.setdefault(m.id, Position())
        s, entry = pos.size, pos.entry_price
        realized = ZERO

        if s == 0 or (s > 0) == (q > 0):                      # open / increase
            new = s + q
            exact_basis = s * entry + q * price
            pos.entry_price = _q_entry(exact_basis / new)
            pos.size = new
            acct.collateral -= exact_basis - pos.basis        # rounding residual (≈1e-18)
            if isolated:
                moved = _q_amount(abs(q) * margin_price / lev)
                acct.collateral -= moved
                pos.isolated_margin += moved
        else:                                                 # reduce, close, or flip
            closing = min(abs(q), abs(s))
            realized = closing * (price - entry) * (1 if s > 0 else -1)
            new = s + q
            if isolated:
                pos.isolated_margin += realized
                if new == 0 or (new > 0) != (s > 0):          # fully closed (maybe flipping)
                    released = pos.isolated_margin
                else:
                    released = _q_amount(pos.isolated_margin * closing / abs(s))
                pos.isolated_margin -= released
                acct.collateral += released
            else:
                acct.collateral += realized
            if new == 0:
                pos.size, pos.entry_price = ZERO, ZERO
            elif (new > 0) == (s > 0):                        # reduced, entry unchanged
                pos.size = new
            else:                                             # flipped through zero
                pos.size, pos.entry_price = new, _q_entry(price)
                acct.collateral -= new * price - pos.basis    # residual (0 unless price unquantized)
                if isolated:
                    moved = _q_amount(abs(new) * margin_price / lev)
                    acct.collateral -= moved
                    pos.isolated_margin += moved

        m.open_interest += max(pos.size, ZERO) - max(s, ZERO)
        if pos.size == 0 and pos.isolated_margin == 0:
            del acct.positions[m.id]
        return realized

    # ------------------------------------------------------------------ liquidations

    def _iso_equity(self, acct: Account, mid: str) -> Decimal:
        pos = acct.positions.get(mid)
        if pos is None:
            return ZERO
        return pos.isolated_margin + self._upnl(self.markets[mid], pos)

    @staticmethod
    def _maintenance(pos: Position, m: Market) -> Decimal:
        return abs(pos.size) * m.mark_price * m.maintenance_rate

    def _liquidate_all(self) -> List[dict]:
        """Every account below maintenance at the current marks, in owner order: isolated
        positions one by one, then the cross account as a whole. Auto-deleveraging closes
        counterparties at a worse price than mark, which can leave one that was already checked
        below maintenance, so passes repeat (bounded) until one changes nothing."""
        events: List[dict] = []
        for _ in range(LIQUIDATION_PASSES):
            acted = [e for e in self._liquidation_pass() if e["stage"] != "book" or e["filled"]]
            events.extend(acted)
            if not acted:
                break
        return events

    def _liquidation_pass(self) -> List[dict]:
        events = []
        for owner in sorted(self.accounts):
            acct = self.accounts.get(owner)
            if acct is None:
                continue
            for mid in sorted(mid for mid, p in acct.positions.items()
                              if p.size != 0 and acct.isolated.get(mid, False)):
                pos = acct.positions.get(mid)
                if pos is not None and pos.size != 0 and \
                        self._iso_equity(acct, mid) < self._maintenance(pos, self.markets[mid]):
                    events.append(self._liquidate(owner, [mid], isolated=True))
            cross = sorted(mid for mid, p in acct.positions.items()
                           if p.size != 0 and not acct.isolated.get(mid, False))
            if cross and self.cross_equity(owner) < self.cross_maintenance(owner):
                events.append(self._liquidate(owner, cross, isolated=False))
        return events

    def _margin_state(self, owner: str, mids: List[str], isolated: bool):
        """(equity, maintenance, any position still open) for what is being liquidated."""
        acct = self.accounts[owner]
        if isolated:
            pos = acct.positions.get(mids[0])
            if pos is None or pos.size == 0:
                return ZERO, ZERO, False
            return (self._iso_equity(acct, mids[0]),
                    self._maintenance(pos, self.markets[mids[0]]), True)
        still_open = any(acct.positions.get(mid) is not None and acct.positions[mid].size != 0
                         for mid in mids)
        return self.cross_equity(owner), self.cross_maintenance(owner), still_open

    def _liquidate(self, owner: str, mids: List[str], isolated: bool) -> dict:
        """Hyperliquid's sequence. 1: cancel the account's orders and close its positions on
        the book, never past the bankruptcy price. 2: if it is still below BACKSTOP_FRACTION of
        maintenance, the vault takes the positions over at mark with whatever margin is left.
        3: if the vault cannot cover a negative balance, auto-deleverage it."""
        eq0, mm0, _ = self._margin_state(owner, mids, isolated)
        event = {"type": "liquidation", "owner": owner, "markets": list(mids),
                 "mode": "isolated" if isolated else "cross", "stage": "book",
                 "equity": str(eq0), "maintenance": str(mm0), "filled": ZERO, "fills": []}
        self._cancel_orders_of(owner, mids[0] if isolated else None)
        for mid in mids:
            fills = self._close_on_book(owner, mid, isolated)
            event["fills"].extend(fills)
            event["filled"] += sum((Decimal(f["amount"]) for f in fills), ZERO)
        eq, mm, still_open = self._margin_state(owner, mids, isolated)
        if still_open and eq >= mm * BACKSTOP_FRACTION:
            return event              # healthy again, or the book may refill: next block decides
        if not still_open and eq >= 0:
            return event              # closed on the book, solvent
        if owner != VAULT and self.vault_nav() + eq >= 0:
            self._backstop(owner, mids, isolated)
            event["stage"] = "backstop"
        elif still_open and eq < 0:
            self._adl(owner, mids, -eq)
            event["stage"] = "adl"
        return event

    def _cancel_orders_of(self, owner: str, market_id: Optional[str] = None) -> None:
        for mid in sorted(self.markets):
            if market_id is not None and mid != market_id:
                continue
            m = self.markets[mid]
            for oid in sorted(oid for oid, meta in m.orders.items() if meta.owner == owner):
                m.book.cancel_order(oid, caller=owner)
            self._prune_orders(m)

    def _close_on_book(self, owner: str, mid: str, isolated: bool) -> List[dict]:
        """A reduce-only IOC for the whole position, limited to the bankruptcy price — the
        price at which closing it, taker fee included, leaves exactly zero — so no book fill
        can create bad debt. Returns the fills."""
        acct = self.accounts[owner]
        pos = acct.positions.get(mid)
        if pos is None or pos.size == 0:
            return []
        m = self.markets[mid]
        eq = self._iso_equity(acct, mid) if isolated else self.cross_equity(owner)
        q = pos.size
        if q > 0:                                     # sell, at no less than bankruptcy
            limit = ((q * m.mark_price - eq) / (q * (1 - TAKER_FEE_RATE))).quantize(
                ENTRY_QUANTUM, rounding=ROUND_CEILING)
            limit = max(limit, ENTRY_QUANTUM)
        else:                                         # buy back, at no more than bankruptcy
            a = -q
            limit = ((a * m.mark_price + eq) / (a * (1 + TAKER_FEE_RATE))).quantize(
                ENTRY_QUANTUM, rounding=ROUND_FLOOR)
            if limit <= 0:
                return []
        order = Order(id=f"liq:{mid}:{owner}", owner=owner,
                      side=OrderSide.SELL if q > 0 else OrderSide.BUY,
                      order_type=OrderType.LIMIT, price=limit, amount=abs(q),
                      nonce=0, timestamp=0.0)
        try:
            trades = m.book.place_order(order, protocol=True)
        except ValueError:
            return []                 # e.g. dust below the book's minimum size: backstop takes it
        m.orders[order.id] = OrderMeta(owner=owner, leverage=self._leverage(acct, m),
                                       reduce_only=True)
        fills = [self._apply_fill(m, tr, taker_limit=limit) for tr in trades]
        if order.is_active:
            m.book.cancel_order(order.id, caller=owner)
        self._prune_orders(m)
        return fills

    def _backstop(self, owner: str, mids: List[str], isolated: bool) -> None:
        """The vault takes the positions over at mark, with the margin that backed them
        (negative if the account is underwater: the vault absorbs that)."""
        acct = self.accounts[owner]
        vault = self.account(VAULT)
        for mid in mids:
            pos = acct.positions.get(mid)
            if pos is None or pos.size == 0:
                continue
            m = self.markets[mid]
            q = pos.size
            before = acct.collateral
            self._trade_into(owner, m, -q, m.mark_price, self._leverage(acct, m), m.mark_price)
            if isolated:
                # Closing released the position's margin and PnL into cross collateral; it
                # belongs to the vault now. The account's cross collateral is untouched.
                released = acct.collateral - before
                acct.collateral -= released
                vault.collateral += released
            self._trade_into(VAULT, m, q, m.mark_price, self._leverage(vault, m), m.mark_price)
        if not isolated:
            vault.collateral += acct.collateral
            acct.collateral = ZERO

    def _adl(self, owner: str, mids: List[str], deficit: Decimal) -> None:
        """Auto-deleveraging: close the bankrupt positions against the most profitable, most
        leveraged opposite positions at prices that return the account to zero. The deficit is
        split across the positions by notional; the counterparties give up that much of their
        unrealized profit."""
        acct = self.accounts[owner]
        live = [(mid, acct.positions[mid].size) for mid in mids
                if mid in acct.positions and acct.positions[mid].size != 0]
        weights = [abs(q) * self.markets[mid].mark_price for mid, q in live]
        total = sum(weights, ZERO)
        left_deficit = deficit
        for i, (mid, q) in enumerate(live):
            m = self.markets[mid]
            share = (left_deficit if i == len(live) - 1
                     else _q_amount(deficit * weights[i] / total))
            left_deficit -= share
            # Closing q at `price` hands the account q·(price − mark) = share. Rounded in the
            # account's favour, so it ends at zero or a hair above, never below.
            price = m.mark_price + share / q
            if q > 0:
                price = price.quantize(ENTRY_QUANTUM, rounding=ROUND_CEILING)
            else:
                price = max(price.quantize(ENTRY_QUANTUM, rounding=ROUND_FLOOR), ENTRY_QUANTUM)
            sign = 1 if q > 0 else -1
            lev = self._leverage(acct, m)
            left = abs(q)
            for other in self._adl_queue(m, -sign, exclude=owner):
                if left == 0:
                    break
                take = min(left, abs(self.accounts[other].positions[mid].size))
                self._trade_into(owner, m, -sign * take, price, lev, price)
                self._trade_into(other, m, sign * take, price,
                                 self._leverage(self.accounts[other], m), price)
                left -= take

    def _adl_queue(self, m: Market, sign: int, exclude: str) -> List[str]:
        """Positions on side ``sign``, ranked as Hyperliquid does: (mark / entry for longs,
        entry / mark for shorts) × notional / account value, highest first; accounts with no
        positive value last; ties by owner."""
        ranked = []
        for other, a in self.accounts.items():
            if other == exclude:
                continue
            p = a.positions.get(m.id)
            if p is None or p.size == 0 or (p.size > 0) != (sign > 0):
                continue
            value = (self._iso_equity(a, m.id) if a.isolated.get(m.id, False)
                     else self.cross_equity(other))
            if value <= 0 or p.entry_price <= 0:
                score = Decimal(-1)
            else:
                pnl = (m.mark_price / p.entry_price if p.size > 0
                       else p.entry_price / m.mark_price)
                score = pnl * abs(p.size) * m.mark_price / value
            ranked.append((-score, other))
        ranked.sort()
        return [o for _, o in ranked]

    # ------------------------------------------------------------------ invariants

    @_pinned
    def net_size(self, market_id: str) -> Decimal:
        return sum((a.positions[market_id].size for a in self.accounts.values()
                    if market_id in a.positions), ZERO)

    @_pinned
    def collateral_total(self) -> Decimal:
        total = ZERO
        for a in self.accounts.values():
            total += a.collateral + sum((p.isolated_margin for p in a.positions.values()), ZERO)
        return total

    @_pinned
    def identity_gap(self) -> Decimal:
        """holder − (Σ collateral − Σ size × entry). Exactly zero while the books are sound."""
        basis = sum((p.basis for a in self.accounts.values() for p in a.positions.values()), ZERO)
        return self.holder_balance - (self.collateral_total() - basis)

    # ------------------------------------------------------------------ consensus state

    def canonical(self) -> dict:
        """Every consensus-relevant field, in a canonical order (no timestamps)."""
        def d(x):
            return str(x)
        markets = {}
        for mid in sorted(self.markets):
            m = self.markets[mid]
            orders = []
            for oid in sorted(m.orders):
                o = m.book.get_order(oid)
                if o is None:
                    continue
                meta = m.orders[oid]
                orders.append([oid, o.owner, o.side.value, d(o.price), d(o.amount), d(o.filled),
                               d(meta.leverage), meta.reduce_only])
            markets[mid] = {"base": m.base, "quote": m.quote, "max_lev": d(m.max_leverage),
                            "oracle": d(m.oracle_price), "oracle_time": d(m.oracle_time),
                            "mark": d(m.mark_price),
                            "last": d(m.last_trade_price), "oi": d(m.open_interest),
                            "ema": [d(m.premium_num), d(m.premium_den), d(m.book_num),
                                    d(m.book_den), d(m.ema_time)],
                            "funding": [d(m.funding_time), d(m.premium_sum), d(m.premium_time),
                                        d(m.funding_rate)],
                            "orders": orders,
                            # time priority within each level, stop orders, nonces, last trade
                            "book": m.book.state_digest().hex()}
        accounts = {}
        for owner in sorted(self.accounts):
            a = self.accounts[owner]
            accounts[owner] = {
                "collateral": d(a.collateral),
                "positions": {mid: [d(p.size), d(p.entry_price), d(p.isolated_margin)]
                              for mid, p in sorted(a.positions.items())},
                "leverage": {mid: d(v) for mid, v in sorted(a.leverage.items())},
                "isolated": {mid: v for mid, v in sorted(a.isolated.items())},
            }
        vault = {"shares": {o: d(v) for o, v in sorted(self.vault_shares.items())},
                 "total_shares": d(self.vault_total_shares),
                 "unlock": {o: d(t) for o, t in sorted(self.vault_unlock.items())}}
        return {"markets": markets, "accounts": accounts, "vault": vault,
                "holder": d(self.holder_balance)}

    def state_hash(self) -> bytes:
        blob = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"))
        return hashlib.blake2b(blob.encode(), digest_size=32).digest()
