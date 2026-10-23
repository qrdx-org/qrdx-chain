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

import bisect
import contextlib
import copy
import dataclasses
import functools
import hashlib
import heapq
import json
from dataclasses import dataclass, field
from decimal import (
    ROUND_CEILING,
    ROUND_DOWN,
    ROUND_FLOOR,
    ROUND_HALF_EVEN,
    ROUND_HALF_UP,
    Context,
    Decimal,
    localcontext,
)
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .. import constants
from . import undo
from .commitment import (
    Section,
    as_committed_dict,
    committed,
    encode_value,
    tracked,
    verifying,
)
from .orderbook import MatchBudget, Order, OrderBook, OrderSide, OrderType, SelfTradeAction

ZERO = Decimal(0)
TWO = Decimal(2)

DEFAULT_MAX_LEVERAGE = Decimal("20")
DEFAULT_LEVERAGE = Decimal("10")  # until an account sets one; capped at the market max
MAKER_FEE_RATE = Decimal("0.0002")  # 0.02 % of fill notional
TAKER_FEE_RATE = Decimal("0.0005")  # 0.05 %
# Fee tiers (docs/TRADING_FEATURES.md): an account's rates follow its perps volume (notional, in
# QRDX, as buyer or seller) over the last FEE_VOLUME_DAYS days of block time — (volume at least,
# taker rate, maker rate). A negative maker rate is a rebate, paid out of the fee the same
# trade's taker pays: every taker rate is above every rebate, so no trade costs the vault.
FEE_VOLUME_DAYS = 14
FEE_TIERS: Tuple[Tuple[Decimal, Decimal, Decimal], ...] = (
    (Decimal(0), TAKER_FEE_RATE, MAKER_FEE_RATE),
    (Decimal(5_000_000), Decimal("0.00045"), Decimal("0.00016")),
    (Decimal(25_000_000), Decimal("0.00040"), Decimal("0.00012")),
    (Decimal(100_000_000), Decimal("0.00035"), Decimal("0.00008")),
    (Decimal(500_000_000), Decimal("0.00030"), Decimal("0.00004")),
    (Decimal(2_000_000_000), Decimal("0.00028"), Decimal(0)),
    (Decimal(7_000_000_000), Decimal("0.00026"), Decimal("-0.00002")),
)
FEE_QUANTUM = Decimal("0.00000001")
# Referrals: an account that joins a referrer's code pays REFEREE_DISCOUNT less on its first
# REFERRAL_VOLUME_CAP of volume, and the referrer earns REFERRER_SHARE of the fees it pays
# (out of the vault's). An account joins once, before REFERRAL_JOIN_MAX_VOLUME of volume.
REFEREE_DISCOUNT = Decimal("0.04")
REFERRER_SHARE = Decimal("0.10")
REFERRAL_VOLUME_CAP = Decimal(25_000_000)
REFERRAL_JOIN_MAX_VOLUME = Decimal(10_000)
ENTRY_QUANTUM = Decimal("1e-18")  # entry prices are stored at this precision
AMOUNT_QUANTUM = Decimal("1e-18")  # deposits/withdrawals: QRDX wei precision

# Mark price (Phase 2). Hyperliquid: median of (oracle + 150 s EMA of book premium),
# (median of best bid, best ask, last trade) and external perp prices — the validators vote the
# last (other venues' perps, ``set_external_perp_price``), with a 30 s EMA of the book median
# standing in while no vote is fresh. A thin book could then drag the mark, so it is also held
# within a band of the oracle — a deliberate addition to Hyperliquid's rule.
PREMIUM_EMA_SECONDS = Decimal("150")
BOOK_EMA_SECONDS = Decimal("30")
MARK_ORACLE_BAND = Decimal("0.05")
# Other venues' perp price (the validators' vote, ``set_external_perp_price``) is the mark's
# third input while it is this fresh; older, the book-median EMA stands in for it.
EXTERNAL_PRICE_MAX_AGE = Decimal("120")

# Liquidations and the backstop vault (Phase 3). An account below maintenance margin is first
# closed on the book, never past its bankruptcy price; one still below BACKSTOP_FRACTION of
# maintenance is taken over by the vault at mark; one the vault cannot cover is auto-deleveraged.
BACKSTOP_FRACTION = Decimal(2) / Decimal(3)
LIQUIDATION_PASSES = 4  # an auto-deleverage can push a counterparty under; re-check, bounded
# Large positions are closed in slices (Hyperliquid): above LIQUIDATION_SLICE_NOTIONAL at mark,
# a book liquidation sends LIQUIDATION_SLICE_FRACTION of the position, then the position cools
# down for LIQUIDATION_COOLDOWN_SECONDS of block time — meanwhile only the backstop acts (below
# BACKSTOP_FRACTION of maintenance). One whole-position market order on a thin book would sweep
# it to the bankruptcy price.
LIQUIDATION_SLICE_NOTIONAL = Decimal("100000")
LIQUIDATION_SLICE_FRACTION = Decimal("0.2")
LIQUIDATION_COOLDOWN_SECONDS = Decimal("30")
# The vault unwinds what it takes over instead of holding it: every VAULT_UNWIND_SECONDS per
# market (the first one after the takeover), it sends a slice — as for a liquidation — to the
# book as a reduce-only IOC at most VAULT_UNWIND_SLIPPAGE through mark.
VAULT_UNWIND_SECONDS = Decimal("30")
VAULT_UNWIND_SLIPPAGE = Decimal("0.005")
SHARE_QUANTUM = Decimal("1e-18")
# Funding (Phase 4), Hyperliquid's formula. Each block samples the premium of the book's impact
# prices (the average price to trade IMPACT_NOTIONAL) over the oracle; at every interval boundary
# of block time, F = average premium + clamp(interest − premium, ±FUNDING_PREMIUM_CLAMP) is the
# 8-hour rate, of which the interval's share is paid — capped at FUNDING_CAP_PER_HOUR. Payment =
# size × oracle × rate, longs to shorts when positive: zero-sum, peer to peer.
DEFAULT_FUNDING_INTERVAL = Decimal(3600)
FUNDING_INTEREST_8H = Decimal("0.0001")  # 0.01 % per 8 hours
FUNDING_PREMIUM_CLAMP = Decimal("0.0005")
FUNDING_CAP_PER_HOUR = Decimal("0.04")
IMPACT_NOTIONAL = Decimal("1000")  # QRDX
EIGHT_HOURS = Decimal(8 * 3600)
RATE_QUANTUM = Decimal("1e-18")

# Trigger orders (stop-loss / take-profit, docs/TRADING_FEATURES.md). They wait off the book and
# are judged on the mark price in every block's tick, where the crossed ones fire as ordinary
# orders of their owner — risk-reducing ones first, then those the mark passed furthest, then
# the first placed. A market trigger fills at most TRIGGER_SLIPPAGE through mark. The matching a
# trigger may do when it fires is paid for when it is placed (``max_makers``); a block fires no
# more than TRIGGER_FIRES_PER_BLOCK of them, visiting no more than TRIGGER_MAKERS_PER_BLOCK
# resting orders between them — the rest fire in the next blocks.
TRIGGER_SLIPPAGE = Decimal("0.10")
TRIGGER_DEFAULT_MAKERS = 20
TRIGGER_MAX_MAKERS = 100
TRIGGERS_PER_ACCOUNT = 50  # in each market
TRIGGER_FIRES_PER_BLOCK = 64
TRIGGER_MAKERS_PER_BLOCK = 1000

# User vaults (docs/TRADING_FEATURES.md): a margin account its leader trades and others join —
# copy trading. Joining moves the joiner's free collateral in for shares at NAV (the vault
# account's equity at mark); they unlock USER_VAULT_LOCKUP_SECONDS later. Leaving pays out the
# shares at NAV, less the leader's ``profit_share`` of what they gained over what they cost.
# The leader holds at least USER_VAULT_LEADER_MIN_SHARE of the shares while anyone else holds
# any, and puts in at least USER_VAULT_MIN_DEPOSIT to create one.
USER_VAULT_LOCKUP_SECONDS = Decimal(24 * 3600)
USER_VAULT_LEADER_MIN_SHARE = Decimal("0.05")
USER_VAULT_DEFAULT_PROFIT_SHARE = Decimal("0.10")
USER_VAULT_MAX_PROFIT_SHARE = Decimal("0.50")
USER_VAULT_MIN_DEPOSIT = Decimal(100)
USER_VAULTS_PER_LEADER = 5
# A vault's order may be no more than this much worse than the mark when it is placed (a buy
# above, a sell below): a leader cannot hand a counterparty it controls the vault's equity in
# one fill. (Within the band, depositors trust the leader — docs/TRADING_FEATURES.md.)
USER_VAULT_ORDER_BAND = Decimal("0.10")

# Portfolio margin (docs/TRADING_FEATURES.md): tokens deposited as margin beside the settlement
# token, each valued at a perp market's oracle price less its haircut (``portfolio_assets``, a
# chain-spec parameter — none by default). They count toward cross equity; an account liquidated
# hands them to the backstop vault at that same value (its equity unchanged), and the vault sells
# them back into the settlement token, a slice every VAULT_UNWIND_SECONDS, no more than
# PORTFOLIO_UNWIND_SLIPPAGE under the oracle. A deposit is worth at least PORTFOLIO_MIN_DEPOSIT.
PORTFOLIO_MIN_DEPOSIT = Decimal(100)
PORTFOLIO_UNWIND_SLIPPAGE = Decimal("0.02")


def portfolio_assets() -> Dict[str, Tuple[str, Decimal]]:
    """token → (perp market pricing it, haircut), from PERP_PORTFOLIO_ASSETS."""
    from .. import constants

    out: Dict[str, Tuple[str, Decimal]] = {}
    for entry in constants.PERP_PORTFOLIO_ASSETS:
        token, market, haircut = str(entry).rsplit(":", 2)
        cut = Decimal(haircut)
        if not ZERO < cut < 1:
            raise ValueError(f"PERP_PORTFOLIO_ASSETS {entry}: a haircut is between 0 and 1")
        out[token.lower()] = (market, cut)
    return out


# Market liquidity (docs/TRADING_FEATURES.md §14). A perp market's creator puts liquidity into a
# vault for it (CREATE_MARKET ``liquidity``, at least the chain-spec PERP_MARKET_MIN_LIQUIDITY),
# and the protocol quotes that vault on the market's book: every MARKET_MAKER_REQUOTE_SECONDS
# (or once the mark moves MARKET_MAKER_REQUOTE_MOVE), MARKET_MAKER_LEVELS post-only orders a
# side, MARKET_MAKER_SPREAD from the mark and MARKET_MAKER_STEP apart, each side's quotes worth
# MARKET_MAKER_DEPTH × the vault's equity in all — less on the side its position already leans
# to, none once that position reaches MARKET_MAKER_MAX_INVENTORY × equity. Quotes are pulled
# while the oracle is stale. It never takes: a level that would cross is skipped. Anyone may add
# to the vault (at NAV, as any user vault); the creator's shares are locked for the chain-spec
# PERP_MARKET_LIQUIDITY_LOCKUP_SECONDS.
MARKET_MAKER_LEVELS = 5
MARKET_MAKER_SPREAD = Decimal("0.001")
MARKET_MAKER_STEP = Decimal("0.001")
MARKET_MAKER_DEPTH = Decimal(1)
MARKET_MAKER_MAX_INVENTORY = Decimal(3)
MARKET_MAKER_REQUOTE_SECONDS = Decimal(5)
MARKET_MAKER_REQUOTE_MOVE = Decimal("0.0025")
MARKET_MAKER_MARKETS_PER_BLOCK = 8


# Risk limits (docs/CONSENSUS_ROADMAP.md 2, 3). The price band and the circuit breaker are
# chain-spec (constants.PERP_PRICE_BAND_BPS, PERP_BREAKER_*; 0 turns one off):
# * band — an order more than the band worse than the oracle (a buy above, a sell below) is
#   refused: a fat finger, or a book pushed far from the index;
# * breaker — the mark moving PERP_BREAKER_MOVE_BPS within PERP_BREAKER_WINDOW_SECONDS of block
#   time holds the market to reduce-only orders for PERP_BREAKER_COOLDOWN_SECONDS.
# Open-interest cap: a market with a liquidity vault holds at most OI_CAP_MULTIPLE × the vault's
# equity of open interest (notional at mark), and every market at least the chain-spec
# PERP_MIN_OI_CAP (0: no floor — a market without a vault and without a floor is uncapped).
OI_CAP_MULTIPLE = Decimal(50)
# Staking fee discounts (Hyperliquid's tiers): QRDX staked → the fraction of fees spared.
STAKE_FEE_DISCOUNTS: Tuple[Tuple[Decimal, Decimal], ...] = (
    (Decimal(10), Decimal("0.05")),
    (Decimal(100), Decimal("0.10")),
    (Decimal(1_000), Decimal("0.15")),
    (Decimal(10_000), Decimal("0.20")),
    (Decimal(100_000), Decimal("0.30")),
    (Decimal(500_000), Decimal("0.40")),
)
# The order grid's price precision (Hyperliquid's): significant figures, and decimals a market
# with sz_decimals 0 may use (one fewer for each size decimal).
PRICE_SIG_FIGS = 5
MAX_PRICE_DECIMALS = 6
# Leverage tiers, marginal: the slice of a position's notional above each floor carries at most
# max leverage / divisor (and at most the account's leverage), so its initial margin rises
# continuously with size. Maintenance is unchanged: liquidation prices stay linear.
LEVERAGE_TIERS: Tuple[Tuple[Decimal, int], ...] = (
    (Decimal(0), 1),
    (Decimal(1_000_000), 2),
    (Decimal(10_000_000), 4),
)


def initial_margin(m: "Market", lev: Decimal, notional: Decimal) -> Decimal:
    """Initial margin for a position worth ``notional`` at leverage ``lev``, tiered."""
    total = ZERO
    for i, (floor, divisor) in enumerate(LEVERAGE_TIERS):
        if notional <= floor:
            break
        top = LEVERAGE_TIERS[i + 1][0] if i + 1 < len(LEVERAGE_TIERS) else notional
        cap = max(Decimal(1), m.max_leverage / divisor)
        total += (min(notional, top) - floor) / min(lev, cap)
    return total


def _bps(value: Any) -> Decimal:
    return Decimal(int(value)) / 10_000


def _staker_part(protocol_fee: Decimal) -> Decimal:
    """The stakers' share (STAKER_FEE_SHARE_BPS) of a perps fee the protocol keeps
    (docs/CONSENSUS_ROADMAP.md 6), in the perps collateral: QRDX is staker income at once, a
    stablecoin is sold for QRDX by the exchange's tick (``convert_staker_fees``)."""
    if protocol_fee <= 0:
        return ZERO
    share = min(Decimal(1), _bps(constants.STAKER_FEE_SHARE_BPS))
    return _q_amount(protocol_fee * share) if share > 0 else ZERO


def market_maker_address(market_id: str) -> str:
    """A market's liquidity vault: a protocol form no key can sign for (``0xUVLT``)."""
    return "0xUVLT" + hashlib.blake2b(f"mm:{market_id}".encode(), digest_size=18).hexdigest()


# Reserved owners. Exchange senders are signature-verified PQ addresses, so no key can act as
# either of these.
# Both are addresses (protocol forms no key signs for: qrdx/crypto/account_id.py), so their
# balances can be looked up, indexed and proven like any account's (docs/CONSENSUS_ROADMAP.md A).
VAULT = "0xHLPV" + hashlib.blake2b(b"perps:backstop-vault", digest_size=18).hexdigest()
PROTOCOL = "0xPROT" + hashlib.blake2b(b"perps:protocol-shares", digest_size=18).hexdigest()


# Pinned arithmetic context. The process-wide Decimal context is not a safe default: importing
# qrdx.exchange.amm changes it, so results would depend on import order.
_CONTEXT = Context(prec=78, rounding=ROUND_HALF_EVEN)


def _pinned(method):
    @functools.wraps(method)
    def wrapper(*args, **kwargs):
        with localcontext(_CONTEXT):
            return method(*args, **kwargs)

    return wrapper


def _mutator(method):
    """A public entry point that may change the clearinghouse: inside an undo scope
    (qrdx/exchange/undo.py) its own fields and every market's are recorded first."""

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        self._keep_all()
        return method(self, *args, **kwargs)

    return wrapper


class ClearinghouseError(ValueError):
    """An operation the clearinghouse refuses. Nothing has been changed when it is raised."""


def _q_entry(x: Decimal) -> Decimal:
    return x.quantize(ENTRY_QUANTUM, rounding=ROUND_HALF_EVEN)


def _ema_step(
    num: Decimal, den: Decimal, sample: Decimal, dt: Decimal, timescale: Decimal, anchor: Decimal
) -> Tuple[Decimal, Decimal]:
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
    size: Decimal = ZERO  # signed: + long, − short
    entry_price: Decimal = ZERO  # average entry, quantized
    isolated_margin: Decimal = ZERO  # only for isolated positions
    # Block time of the last protocol close: a liquidation slice, or (the vault's) a takeover
    # or unwind slice. 0 = none. Committed only once set.
    close_time: Decimal = ZERO

    def encode(self) -> List[str]:
        out = [str(self.size), str(self.entry_price), str(self.isolated_margin)]
        if self.close_time > 0:
            out.append(str(self.close_time))
        return out

    @property
    def basis(self) -> Decimal:
        return self.size * self.entry_price

    def __deepcopy__(self, memo: Dict[int, Any]) -> "Position":
        # Every field is an immutable value: a field-for-field copy is a deep one (and an undo
        # scope copies positions on every operation that touches an account).
        new = Position.__new__(Position)
        new.__dict__.update(self.__dict__)
        memo[id(self)] = new
        return new


@dataclass
class Account:
    collateral: Decimal = ZERO  # cross collateral (realized)
    positions: Dict[str, Position] = field(default_factory=dict)  # market_id → position
    leverage: Dict[str, Decimal] = field(default_factory=dict)  # market_id → leverage
    isolated: Dict[str, bool] = field(default_factory=dict)  # market_id → isolated mode
    assets: Dict[str, Decimal] = field(default_factory=dict)  # token → amount (portfolio margin)

    def __deepcopy__(self, memo: Dict[int, Any]) -> "Account":
        new = Account.__new__(Account)
        new.__dict__.update(self.__dict__)
        new.positions = {mid: copy.deepcopy(p, memo) for mid, p in self.positions.items()}
        new.leverage = dict(self.leverage)
        new.isolated = dict(self.isolated)
        new.assets = dict(self.__dict__.get("assets", {}))
        for name, value in self.__dict__.items():  # any field added later: copied properly
            if name not in ("collateral", "positions", "leverage", "isolated", "assets"):
                new.__dict__[name] = copy.deepcopy(value, memo)
        memo[id(self)] = new
        return new

    def __setstate__(self, state: Dict[str, Any]) -> None:
        self.__dict__.update(state)
        self.__dict__.setdefault("assets", {})  # (pickled before portfolio margin)


@dataclass
class OrderMeta:
    """What the clearinghouse needs about a resting order that the book does not track."""

    owner: str
    leverage: Decimal
    reduce_only: bool


@dataclass(frozen=True)
class Trigger:
    """A stop or take-profit order waiting for the mark price (replaced, never changed)."""

    owner: str
    side: str  # "buy" or "sell"
    kind: str  # "sl" (stop) or "tp" (take profit)
    trigger_price: Decimal
    size: Decimal  # ZERO for a position's TP/SL: the whole position when it fires
    limit_price: Decimal  # ZERO: a market order, at most TRIGGER_SLIPPAGE through mark
    reduce_only: bool
    position: bool  # a position's TP/SL: closes it whole; cancelled once there is none to close
    tif: str  # what the order is when it fires: "gtc" or "ioc" (a market trigger: "ioc")
    max_makers: int  # the matching it paid for when placed
    seq: int  # placement order across the clearinghouse
    # One-cancels-the-other: when one trigger of a group fires, the rest are cancelled (an
    # order's attached TP and SL are a group). ``parent``: the order they were attached to —
    # cancelled with it if it is cancelled unfilled, and once it is done and there is no
    # position left for them to reduce.
    group: str = ""
    parent: str = ""

    @property
    def reduces(self) -> bool:
        return self.reduce_only or self.position

    @property
    def fires_above(self) -> bool:
        """Fires once the mark rises to the trigger price (a buy stop, a sell take-profit);
        otherwise once it falls to it."""
        return (self.side == "buy") == (self.kind == "sl")

    def crossed(self, mark: Decimal) -> bool:
        return mark >= self.trigger_price if self.fires_above else mark <= self.trigger_price


def _encode_trigger(_tid: str, t: Trigger) -> Any:
    return [
        t.owner,
        t.side,
        t.kind,
        str(t.trigger_price),
        str(t.size),
        str(t.limit_price),
        t.reduce_only,
        t.position,
        t.tif,
        t.max_makers,
        t.seq,
    ] + ([t.group, t.parent] if t.group or t.parent else [])


@dataclass(frozen=True)
class UserVault:
    leader: str
    name: str
    profit_share: Decimal
    total_shares: Decimal
    created: Decimal  # block time
    # A market's liquidity vault (``MARKET_MAKER_*``): the market it makes, quoted by the
    # protocol in every tick — no one signs for it, its leader included.
    managed: str = ""


@dataclass(frozen=True)
class VaultHolding:
    shares: Decimal
    basis: Decimal  # what the shares held cost: deposits, less the part withdrawals took back
    unlock: Decimal  # block time


def _encode_user_vault(_vault: str, v: UserVault) -> Any:
    out = [v.leader, v.name, str(v.profit_share), str(v.total_shares), str(v.created)]
    return out + [v.managed] if v.managed else out


def _encode_holding(_key: str, h: VaultHolding) -> Any:
    return [str(h.shares), str(h.basis), str(h.unlock)]


def user_vault_address(leader: str, seed: str) -> str:
    """A user vault's address: a protocol form no key can sign for (``0xUVLT``,
    qrdx/crypto/account_id.py); its leader signs for it."""
    return (
        "0xUVLT" + hashlib.blake2b(f"uvault:{leader}:{seed}".encode(), digest_size=18).hexdigest()
    )


@dataclass(frozen=True)
class Referral:
    referrer: str
    volume: Decimal  # the referee's volume since it joined (its discount ends at the cap)


def _encode_volume(_owner: str, days: tuple) -> Any:
    return [[day, str(notional)] for day, notional in days]


def _encode_referral(_owner: str, r: Referral) -> Any:
    return [r.referrer, str(r.volume)]


@dataclass
class Market:
    id: str
    base: str
    quote: str
    max_leverage: Decimal
    book: OrderBook
    oracle_price: Decimal = ZERO
    oracle_time: Decimal = ZERO  # block time the oracle was last set; 0 = unknown
    mark_price: Decimal = ZERO
    last_trade_price: Decimal = ZERO
    open_interest: Decimal = ZERO  # Σ long sizes (= Σ short sizes)
    orders: Dict[str, OrderMeta] = field(default_factory=dict)
    # Mark-price state: time-weighted EMAs on block time (numerator / denominator).
    premium_num: Decimal = ZERO
    premium_den: Decimal = ZERO
    book_num: Decimal = ZERO
    book_den: Decimal = ZERO
    ema_time: Decimal = ZERO  # block time of the last EMA update; 0 = never
    # Funding state: the premium accumulated (time-weighted) since the last settlement.
    funding_time: Decimal = ZERO  # block-time boundary of the last settlement; 0 = never
    premium_sum: Decimal = ZERO
    premium_time: Decimal = ZERO
    funding_rate: Decimal = ZERO  # the rate last paid, per interval
    # Other venues' perp price, as the validators voted it (0 = none yet), and when it was set.
    external_price: Decimal = ZERO
    external_time: Decimal = ZERO
    # Trigger orders waiting for the mark, by id (committed per trigger).
    triggers: Dict[str, Trigger] = field(default_factory=dict)
    # Its liquidity vault's last quotes: block time, and the mark they were quoted around.
    mm_time: Decimal = ZERO
    mm_mark: Decimal = ZERO
    # Circuit breaker: the mark at the window's start, when it started, and until when the
    # market accepts only reduce-only orders (block time).
    breaker_mark: Decimal = ZERO
    breaker_time: Decimal = ZERO
    halted_until: Decimal = ZERO
    # Delisted (docs/CONSENSUS_ROADMAP.md 4): settled at this price; it trades no more.
    settled_price: Decimal = ZERO
    # The order grid (Hyperliquid's szDecimals): sizes in this many decimals, prices in at most
    # 5 significant figures and 6 − sz_decimals decimals. -1: no grid.
    sz_decimals: int = -1
    # A deployer market (docs/HYPERLIQUID_PARITY.md): its deployer, which sets its oracle and
    # takes this share of the protocol's fees on it; and until when the validators hold it
    # frozen (reduce-only, its oracle theirs).
    deployer: str = ""
    deployer_fee_share: Decimal = ZERO
    frozen_until: Decimal = ZERO

    def __post_init__(self) -> None:
        # Resting orders' clearinghouse metadata, committed per order (never changed in place).
        self.orders = as_committed_dict(
            self.orders, "ch.market_orders", _encode_order_meta, mutable=False
        )
        self.triggers = as_committed_dict(
            self.triggers, "ch.market_triggers", _encode_trigger, mutable=False
        )

    def __setstate__(self, state: Dict[str, Any]) -> None:
        # A market pickled before trigger orders existed (a persisted checkpoint).
        self.__dict__.update(state)
        if "triggers" not in state:
            self.triggers = as_committed_dict(
                {}, "ch.market_triggers", _encode_trigger, mutable=False
            )

    @property
    def maintenance_rate(self) -> Decimal:
        """Half the initial margin at maximum leverage (Hyperliquid's rule)."""
        return Decimal(1) / (TWO * self.max_leverage)


# A market's own fields — what an undo scope records of it (its book, orders and triggers keep
# themselves).
_MARKET_FIELDS = tuple(
    f.name for f in dataclasses.fields(Market) if f.name not in ("book", "orders", "triggers")
)


def _encode_order_meta(_oid: str, meta: OrderMeta) -> Any:
    return [meta.owner, str(meta.leverage), meta.reduce_only]


def _encode_account(_owner: str, a: Account) -> Any:
    out = {
        "collateral": str(a.collateral),
        "positions": {mid: p.encode() for mid, p in sorted(a.positions.items())},
        "leverage": {mid: str(v) for mid, v in sorted(a.leverage.items())},
        "isolated": dict(sorted(a.isolated.items())),
    }
    if a.assets:  # (absent while none: every other account's encoding unchanged)
        out["assets"] = {t: str(v) for t, v in sorted(a.assets.items())}
    return out


def _market_header(m: Market) -> Dict[str, Any]:
    """A market's own fields — everything the commitment covers but its orders and book."""
    d = str
    header: Dict[str, Any] = {
        "base": m.base,
        "quote": m.quote,
        "max_lev": d(m.max_leverage),
        "oracle": d(m.oracle_price),
        "oracle_time": d(m.oracle_time),
        "mark": d(m.mark_price),
        "last": d(m.last_trade_price),
        "oi": d(m.open_interest),
        "ema": [d(m.premium_num), d(m.premium_den), d(m.book_num), d(m.book_den), d(m.ema_time)],
        "funding": [d(m.funding_time), d(m.premium_sum), d(m.premium_time), d(m.funding_rate)],
    }
    if m.external_price > 0:  # absent until first voted (a root unchanged till then)
        header["ext"] = [d(m.external_price), d(m.external_time)]
    if m.mm_time > 0:  # absent until its liquidity vault first quotes
        header["mm"] = [d(m.mm_time), d(m.mm_mark)]
    if m.breaker_time > 0 or m.halted_until > 0:  # absent until the breaker first runs
        header["breaker"] = [d(m.breaker_mark), d(m.breaker_time), d(m.halted_until)]
    if m.settled_price > 0:
        header["settled"] = d(m.settled_price)
    if m.sz_decimals >= 0:
        header["sz"] = m.sz_decimals
    if m.deployer:  # (absent on a validator-priced market)
        header["dep"] = [m.deployer, d(m.deployer_fee_share)]
    if m.frozen_until > 0:  # absent until the validators first freeze it
        header["frozen"] = d(m.frozen_until)
    return header


class _LiquidationIndex:
    """Where each margin account turns liquidatable, by market — derived from ``accounts``,
    never committed.

    ``_liquidation_pass`` used to compute the equity of every account with a position on every
    block: about 3 µs an account, 148 ms at 50,000, more than half a 250 ms slot. Equity and
    maintenance are linear in the mark, so a position whose margin covers that market alone
    (isolated, or the account's only cross market) has an exact liquidation price; an account
    with cross positions in several markets is checked every pass (``always``). A tick takes the
    thresholds the new marks have crossed and runs the exact check on those owners only."""

    def __init__(self) -> None:
        # market → sorted [(threshold, owner)]: a long is liquidatable below its threshold, a
        # short above it.
        self.longs: Dict[str, List[Tuple[Decimal, str]]] = {}
        self.shorts: Dict[str, List[Tuple[Decimal, str]]] = {}
        self.entries: Dict[str, List[Tuple[str, bool, Decimal]]] = {}  # owner → its thresholds
        self.always: set = set()
        self.rates: Dict[str, Decimal] = {}  # the maintenance rate each market was indexed at
        self.token: List[Any] = []  # ties the index to the accounts dict it was built from

    def put(self, owner: str, entries: List[Tuple[str, bool, Decimal]], always: bool) -> None:
        for mid, is_long, t in self.entries.pop(owner, ()):
            side = self.longs if is_long else self.shorts
            lst = side[mid]
            i = bisect.bisect_left(lst, (t, owner))
            if i < len(lst) and lst[i] == (t, owner):
                del lst[i]
        self.always.discard(owner)
        if always:
            self.always.add(owner)
        if entries:
            self.entries[owner] = entries
            for mid, is_long, t in entries:
                bisect.insort(
                    (self.longs if is_long else self.shorts).setdefault(mid, []), (t, owner)
                )

    def crossed(self, mid: str, mark: Decimal) -> List[str]:
        """Owners whose threshold in market ``mid`` the mark has reached — a superset (by a
        relative 1e-15) of those the exact check liquidates."""
        tol = abs(mark) * _INDEX_TOLERANCE + _INDEX_TOLERANCE
        out = []
        longs = self.longs.get(mid)
        if longs:
            out += [o for _t, o in longs[bisect.bisect_left(longs, (mark - tol, "")) :]]
        shorts = self.shorts.get(mid)
        if shorts:
            out += [o for _t, o in shorts[: bisect.bisect_right(shorts, (mark + tol, "\uffff"))]]
        return out


_INDEX_TOLERANCE = Decimal("1e-15")


class Clearinghouse:
    """Perp markets, their order books, and every trader's margin account."""

    last_makers_visited = 0  # (a clearinghouse restored from before it existed reads this)
    trigger_seq = 0

    # Committed entry by entry (qrdx/exchange/commitment.py). Read-only scans use peek*.
    accounts = committed("ch.accounts", _encode_account)
    vault_shares = committed("ch.vault_shares", encode_value, mutable=False)
    vault_unlock = committed("ch.vault_unlock", encode_value, mutable=False)
    user_vaults = committed("ch.user_vaults", _encode_user_vault, mutable=False)
    vault_holdings = committed("ch.vault_holdings", _encode_holding, mutable=False)
    volumes = committed("ch.volumes", _encode_volume, mutable=False)
    # Portfolio margin: tokens held as margin, in total (the perps holder's ledger balance of
    # them), and when the vault last sold each.
    asset_holdings = committed("ch.asset_holdings", encode_value, mutable=False)
    asset_unwind_time = committed("ch.asset_unwind_time", encode_value, mutable=False)
    referral_codes = committed("ch.referral_codes", encode_value, mutable=False)
    referrals = committed("ch.referrals", _encode_referral, mutable=False)

    def __init__(self) -> None:
        self.markets: Dict[str, Market] = {}
        self.accounts = {}  # owner → Account (committed: see the class attributes)
        # The backstop vault is the margin account ``VAULT``: fees accrue to it, and it takes
        # over positions the book could not close. Depositors own it through shares.
        self.vault_shares = {}
        self.vault_total_shares: Decimal = ZERO
        self.vault_unlock = {}  # owner → block time its shares unlock
        # Mirror of the clearinghouse holder's real balance: deposits minus withdrawals.
        self.holder_balance: Decimal = ZERO
        # The stakers' share of fee income withheld from the backstop vault this block, to
        # leave the clearinghouse at the block's end (``take_staker_fees``): perps in QRDX only.
        self.staker_fees: Decimal = ZERO
        # Per operation, not state: the positions it changed (their orders are re-checked), the
        # orders that cancelled, and the block time of the running tick.
        self._touched: set = set()
        self._cancelled: List[dict] = []
        self.last_cancelled: List[dict] = []
        self.last_makers_visited = 0  # resting orders the last placement visited (its gas)
        self._now: Decimal = ZERO
        self.trigger_seq = 0  # triggers placed so far (committed once there is one)
        self.user_vaults = {}  # vault address → UserVault
        self.vault_holdings = {}  # "vault|holder" → VaultHolding
        self.volumes = {}  # owner → ((day, notional), …): the last FEE_VOLUME_DAYS days traded
        self.referral_codes = {}  # code → its referrer
        self.referrals = {}  # referee → Referral
        self.asset_holdings = {}  # token → amount held as margin, every account
        self.asset_unwind_time = {}  # token → block time the vault last sold some

    _LATER_FIELDS = (
        "user_vaults",
        "vault_holdings",
        "volumes",
        "referral_codes",
        "referrals",
        "asset_holdings",
        "asset_unwind_time",
    )

    def __setstate__(self, state: Dict[str, Any]) -> None:
        # A clearinghouse pickled before these existed (a persisted checkpoint).
        self.__dict__.update(state)
        for name in self._LATER_FIELDS:
            if name not in state:
                setattr(self, name, {})

    @property
    def vault_collateral(self) -> Decimal:
        vault = self.accounts.peek(VAULT)
        return vault.collateral if vault is not None else ZERO

    def _keep_all(self) -> None:
        """Inside an undo scope, once: the clearinghouse's scalars and every market's own fields
        (few markets; their order metadata, books and the accounts keep themselves)."""
        scope = undo.active()
        if scope is None or not scope.first(self, "clearinghouse"):
            return
        markets = dict(self.markets)
        headers = {mid: {f: getattr(m, f) for f in _MARKET_FIELDS} for mid, m in markets.items()}
        scalars = {
            "vault_total_shares": self.vault_total_shares,
            "holder_balance": self.holder_balance,
            "_now": self.__dict__.get("_now", ZERO),
            "trigger_seq": self.trigger_seq,
            "staker_fees": self.__dict__.get("staker_fees", ZERO),
        }

        def restore() -> None:
            self.markets.clear()
            self.markets.update(markets)
            for mid, fields in headers.items():
                for name, value in fields.items():
                    setattr(markets[mid], name, value)
            for name, value in scalars.items():
                setattr(self, name, value)

        scope.record(self, "clearinghouse", restore)

    # ------------------------------------------------------------------ markets

    @staticmethod
    def market_id(base: str, quote: str = "QRDX") -> str:
        return f"{base}-{quote}-PERP"

    @_mutator
    @_pinned
    def create_market(
        self,
        base: str,
        quote: str = "QRDX",
        max_leverage: Decimal = DEFAULT_MAX_LEVERAGE,
        sz_decimals: int = -1,
        deployer: str = "",
        deployer_fee_share: Decimal = ZERO,
    ) -> Market:
        if not base:
            raise ClearinghouseError("base token required")
        deployer_fee_share = Decimal(str(deployer_fee_share))
        if not ZERO <= deployer_fee_share <= 1 or (deployer_fee_share and not deployer):
            raise ClearinghouseError("a deployer's fee share is 0 to 1, on its own market")
        max_leverage = Decimal(str(max_leverage))
        if max_leverage < 1:
            raise ClearinghouseError("max leverage must be at least 1")
        if isinstance(sz_decimals, bool) or not -1 <= int(sz_decimals) <= MAX_PRICE_DECIMALS:
            raise ClearinghouseError(f"sz_decimals is 0 to {MAX_PRICE_DECIMALS} (-1: no grid)")
        mid = self.market_id(base, quote)
        if mid in self.markets:
            raise ClearinghouseError(f"market {mid} already exists")
        book = OrderBook(
            pool_id=mid,
            maker_fee_rate=MAKER_FEE_RATE,
            taker_fee_rate=TAKER_FEE_RATE,
            self_trade_action=SelfTradeAction.CANCEL_TAKER,
        )
        market = Market(
            id=mid,
            base=base,
            quote=quote,
            max_leverage=max_leverage,
            book=book,
            sz_decimals=int(sz_decimals),
            deployer=deployer,
            deployer_fee_share=deployer_fee_share,
        )
        self.markets[mid] = market
        return market

    @staticmethod
    def _check_grid(m: Market, size: Any, price: Any, reduce_only: bool) -> None:
        """An order a user places must fit the market's grid — a size in whole lots, a price of
        at most 5 significant figures (an integer always fits) and 6 − sz_decimals decimals — and,
        unless it only reduces, be worth PERP_MIN_ORDER_VALUE."""
        size, price = Decimal(str(size)), Decimal(str(price))
        if m.sz_decimals >= 0:
            lot = Decimal(1).scaleb(-m.sz_decimals)
            if size % lot != 0:
                raise ClearinghouseError(f"{m.id} sizes are multiples of {lot}")
            if price != price.to_integral_value():
                t = price.normalize().as_tuple()
                decimals = -int(t.exponent)
                if len(t.digits) > PRICE_SIG_FIGS or decimals > MAX_PRICE_DECIMALS - m.sz_decimals:
                    raise ClearinghouseError(
                        f"{m.id} prices have at most {PRICE_SIG_FIGS} significant figures and "
                        f"{MAX_PRICE_DECIMALS - m.sz_decimals} decimals"
                    )
        minimum = Decimal(int(constants.PERP_MIN_ORDER_VALUE))
        if minimum > 0 and not reduce_only and size * price < minimum:
            raise ClearinghouseError(f"an order is worth at least {minimum}")

    def market(self, market_id: str) -> Market:
        m = self.markets.get(market_id)
        if m is None:
            raise ClearinghouseError(f"market {market_id} not found")
        return m

    @_mutator
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

    @_mutator
    def set_external_perp_price(self, market_id: str, price: Decimal, now=None) -> None:
        """Set other venues' perp price for the market (the validators' vote) — the mark's third
        input while fresh — and re-derive the mark, like ``set_oracle_price``."""
        price = Decimal(str(price))
        if price <= 0:
            raise ClearinghouseError("external price must be positive")
        m = self.market(market_id)
        m.external_price = price
        if now is not None:
            m.external_time = Decimal(str(now))
        self._refresh_mark(m, m.ema_time)

    @_mutator
    def new_block(self, now=None) -> None:
        for m in self.markets.values():
            m.book.new_block(now)
        if now is not None:
            self._now = Decimal(str(now))  # block time: the day a fill's volume counts in

    @_mutator
    @_pinned
    def tick(self, now, funding_interval=None) -> List[dict]:
        """Per-block duties, run on EVERY block on every path (block_processor.run_exchange_tick):
        advance the mark-price EMAs to block time ``now``, sample the funding premium and pay
        funding at an interval boundary, then liquidate every account below maintenance at the
        new marks, and let the vault unwind a slice of what it holds. Trigger orders the new
        marks crossed fire first (``_fire_triggers``). Returns what happened, as
        events: ``{"type": "funding", ...}`` for each settlement, ``{"type": "trigger_fired" /
        "trigger_cancelled", ...}`` for each trigger that fired, ``{"type": "liquidation",
        ...}`` for each liquidation that acted, ``{"type": "vault_unwind", ...}`` for each
        unwind that filled and ``{"type": "order_cancelled", ...}`` for each resting order a
        position change left the account unqualified for (``_trim_orders``)."""
        now = Decimal(str(now))
        interval = Decimal(str(funding_interval or DEFAULT_FUNDING_INTERVAL))
        events: List[dict] = []
        for mid in sorted(self.markets):
            m = self.markets[mid]
            if m.settled_price > 0:  # delisted: no mark, no funding
                continue
            dt = max(ZERO, now - m.ema_time) if m.ema_time > 0 else ZERO
            self._refresh_mark(m, now)
            tripped = self._trip_breaker(m, now)
            if tripped is not None:
                events.append(tripped)
            self._sample_premium(m, dt)
            settled = self._settle_funding(m, now, interval)
            if settled is not None:
                events.append(settled)
        self._now = now  # block time, for the liquidation slices' cooldowns
        self._touched, self._cancelled = set(), []
        events += self._fire_triggers(now)
        events += self._liquidate_all()
        events += self._vault_unwind(now)
        self._trim_touched()
        events += self._quote_markets(now)
        return events + self._cancelled

    # ------------------------------------------------------------------ funding

    def _impact_price(self, m: Market, bids: bool) -> Optional[Decimal]:
        """Average price to sell (``bids``) or buy IMPACT_NOTIONAL on the book; None if the
        book is not that deep."""
        levels = m.book.iter_levels(bids=bids)  # best first, read only as deep as needed
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
        """At each interval boundary of block time, pay the interval's funding. After a halt
        the chain resumes past several boundaries: the interval the premium samples cover is
        paid at its rate, and each interval with no block in it at the interest-only rate (no
        premium was observed — dYdX's rule): a position held through a halt kept its exposure,
        and pays its carry, for that time. Returns the settlement as an event, or None when
        nothing was due."""
        if m.oracle_price <= 0:
            return None
        boundary = (now // interval) * interval
        if m.funding_time == 0:
            m.funding_time = boundary
            return None
        if now < m.funding_time + interval:
            return None
        avg = m.premium_sum / m.premium_time if m.premium_time > 0 else ZERO
        rate = self._funding_rate(avg, interval)
        intervals = int((boundary - m.funding_time) // interval)
        paid = rate + self._funding_rate(ZERO, interval) * (intervals - 1)
        self._pay_funding(m, paid)
        m.funding_rate = rate
        m.funding_time = boundary
        m.premium_sum = m.premium_time = ZERO
        event: Dict[str, Any] = {
            "type": "funding",
            "market": m.id,
            "rate": str(rate),
            "premium": str(avg),
            "oracle_price": str(m.oracle_price),
            "open_interest": str(m.open_interest),
            "funding_time": str(boundary),
        }
        if intervals > 1:
            event.update(intervals=intervals, paid_rate=str(paid))
        return event

    @staticmethod
    def _funding_rate(avg_premium: Decimal, interval: Decimal) -> Decimal:
        """One interval's rate: F = premium + clamp(interest − premium, ±0.05 %) is the 8-hour
        rate; the interval's share of it, capped per hour."""
        f8 = avg_premium + min(
            max(FUNDING_INTEREST_8H - avg_premium, -FUNDING_PREMIUM_CLAMP), FUNDING_PREMIUM_CLAMP
        )
        cap = FUNDING_CAP_PER_HOUR * interval / 3600
        return min(max(f8 * interval / EIGHT_HOURS, -cap), cap).quantize(RATE_QUANTUM)

    def _pay_funding(self, m: Market, rate: Decimal) -> None:
        """size × oracle × rate from every position (longs pay when positive, shorts receive).
        Isolated positions pay from their own margin. Rounding each payment to wei leaves a
        few wei over or short; the vault takes that, so the payments sum to exactly zero."""
        if rate == 0:
            return
        total = ZERO
        for owner in sorted(self.accounts):
            p = self.accounts.peek(owner).positions.get(m.id)
            if p is None or p.size == 0:
                continue
            a = self.accounts[owner]  # this account changes
            pay = _q_amount(p.size * m.oracle_price * rate)
            if a.isolated.get(m.id, False):
                p.isolated_margin -= pay
            else:
                a.collateral -= pay
            total += pay
        if total != 0:
            self.account(VAULT).collateral += total

    def _refresh_mark(self, m: Market, now: Decimal) -> None:
        """mark = median(oracle + premium EMA, book median, other venues' perp price), held
        within ±MARK_ORACLE_BAND of the oracle; the book-median EMA stands in for the external
        price while none is fresh. Liquidations trigger on mark, not the last trade, so one
        large trade or a spoofed order on a thin book cannot move it far on its own. With the
        external price, a squeeze of the local book moves the mark only at the pace of the
        150 s premium EMA, about 5× slower than through the 30 s book EMA it replaces — time
        for arbitrage with the other venues to close the gap."""
        if m.oracle_price <= 0:
            return
        dt = max(ZERO, now - m.ema_time) if m.ema_time > 0 else ZERO
        bid, ask = m.book.best_bid, m.book.best_ask
        last = m.last_trade_price if m.last_trade_price > 0 else None
        if bid is not None and ask is not None:
            mid = (Decimal(str(bid)) + Decimal(str(ask))) / TWO
            m.premium_num, m.premium_den = _ema_step(
                m.premium_num,
                m.premium_den,
                mid - m.oracle_price,
                dt,
                PREMIUM_EMA_SECONDS,
                anchor=ZERO,
            )
        book = None
        if bid is not None and ask is not None and last is not None:
            book = sorted([Decimal(str(bid)), Decimal(str(ask)), last])[1]
            m.book_num, m.book_den = _ema_step(
                m.book_num, m.book_den, book, dt, BOOK_EMA_SECONDS, anchor=m.oracle_price
            )
        if now > 0:
            m.ema_time = now
        premium = m.premium_num / m.premium_den if m.premium_den > 0 else ZERO
        inputs = [m.oracle_price + premium]
        external = None
        if m.external_price > 0 and (now <= 0 or now - m.external_time <= EXTERNAL_PRICE_MAX_AGE):
            external = m.external_price
        if book is not None:
            ema = m.book_num / m.book_den if m.book_den > 0 else book
            inputs += [book, external if external is not None else ema]
        elif external is not None:
            inputs.append(external)
        inputs.sort()
        half = len(inputs) // 2
        mark = inputs[half] if len(inputs) % 2 else (inputs[half - 1] + inputs[half]) / TWO
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

    @_mutator
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

    @_mutator
    @_pinned
    def withdraw(self, owner: str, amount) -> Decimal:
        self._user(owner)
        amount = self._amount(amount)
        if amount > self.withdrawable(owner):
            raise ClearinghouseError(
                f"withdrawal of {amount} exceeds the withdrawable {self.withdrawable(owner)}"
            )
        if amount > self.holder_balance:  # cannot happen while the identity holds
            raise ClearinghouseError("clearinghouse holder cannot cover the withdrawal")
        self.accounts[owner].collateral -= amount
        self.holder_balance -= amount
        return amount

    @_mutator
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
            o.owner == owner for o in m.orders.values()
        )
        if busy and bool(isolated) != acct.isolated.get(market_id, False):
            raise ClearinghouseError("cannot change margin mode with an open position or orders")
        if busy and pos is not None and pos.size != 0 and acct.isolated.get(market_id, False):
            raise ClearinghouseError("cannot change an isolated position's leverage while open")
        before = (acct.leverage.get(market_id), acct.isolated.get(market_id))
        acct.leverage[market_id] = leverage
        acct.isolated[market_id] = bool(isolated)
        if self.cross_equity(owner) < self.cross_requirement(owner):
            stores: Tuple[Tuple[Dict[str, Any], Any], ...] = (
                (acct.leverage, before[0]),
                (acct.isolated, before[1]),
            )
            for store, value in stores:
                if value is None:
                    store.pop(market_id, None)
                else:
                    store[market_id] = value
            raise ClearinghouseError("insufficient margin for that leverage")

    @_mutator
    @_pinned
    def pay_builder(self, owner: str, builder: str, amount: Decimal) -> None:
        """A builder's fee on an order it routed: ``amount`` of ``owner``'s collateral to the
        builder's margin account (an internal transfer), out of free margin only."""
        amount = _q_amount(Decimal(str(amount)))
        if amount <= 0:
            return
        if self.cross_equity(owner) - self.cross_requirement(owner) < amount:
            raise ClearinghouseError(f"not enough free margin for the builder fee ({amount})")
        self.account(owner).collateral -= amount
        self.account(builder).collateral += amount

    @_mutator
    @_pinned
    def adjust_isolated_margin(self, owner: str, market_id: str, delta) -> Decimal:
        """Move ``delta`` of collateral into an isolated position's margin (``delta`` < 0: out of
        it, back to the account's cross collateral) — Hyperliquid's ``updateIsolatedMargin``.
        Adding takes free cross margin; removing leaves the position at least its initial margin
        at mark, so it never raises the position's leverage past its setting. Returns the
        position's isolated margin after."""
        self._user(owner)
        m = self.market(market_id)
        delta = Decimal(str(delta))
        if not delta.is_finite() or delta == 0 or delta != _q_amount(delta):
            raise ClearinghouseError("the amount is a non-zero number of whole wei")
        acct = self.account(owner)
        pos = acct.positions.get(market_id)
        if pos is None or pos.size == 0 or not acct.isolated.get(market_id, False):
            raise ClearinghouseError(f"no isolated position in {market_id}")
        if delta > 0:
            if self.cross_equity(owner) - self.cross_requirement(owner) < delta:
                raise ClearinghouseError("not enough free cross margin to add")
        else:
            need = initial_margin(m, self._leverage(acct, m), abs(pos.size) * m.mark_price)
            if self._iso_equity(acct, market_id) + delta < need:
                raise ClearinghouseError(
                    f"the position must keep its initial margin ({need}) after the removal"
                )
        acct.collateral -= delta
        pos.isolated_margin += delta
        return pos.isolated_margin

    @_mutator
    @_pinned
    def delist(self, market_id: str, price: Optional[Decimal] = None) -> Dict[str, Any]:
        """Settle ``market_id`` for good, by governance (docs/CONSENSUS_ROADMAP.md 4). Every
        order and trigger in it is cancelled and every position closed at one price — ``price``,
        or the oracle's — which is zero-sum: the sizes net to zero. Its liquidity vault stops
        quoting and its lockup ends. The market refuses every order after. An account the
        settlement leaves in debt is resolved by the tick, as any debt is."""
        m = self.market(market_id)
        if m.settled_price > 0:
            raise ClearinghouseError(f"{market_id} is already delisted")
        settle = _q_entry(Decimal(str(price)) if price is not None else m.oracle_price)
        if not settle.is_finite() or settle <= 0:
            raise ClearinghouseError(f"{market_id} has no price to settle at")
        owners = set(self._orders_by_owner(m)) | set(self._trigger_index(m)["owners"])
        for owner in sorted(owners):
            self._cancel_orders_of(owner, market_id)
        holders = sorted(
            owner
            for owner, a in self.accounts.peek_items()
            if a.positions.get(market_id) is not None and a.positions[market_id].size != 0
        )
        closed = []
        for owner in holders:
            acct = self.account(owner)
            size = acct.positions[market_id].size
            realized = self._trade_into(owner, m, -size, settle, self._leverage(acct, m), settle)
            closed.append({"owner": owner, "size": str(size), "realized": str(realized)})
        if m.open_interest != 0:
            raise ClearinghouseError(f"{market_id}'s positions do not net to zero")
        m.settled_price = settle
        now = Decimal(str(self.__dict__.get("_now", ZERO)))
        vault = market_maker_address(market_id)
        v = self.user_vaults.peek(vault) if len(self.user_vaults) else None
        if v is not None:
            h = self._holding(vault, v.leader)
            if h.unlock > now:
                self._set_holding(vault, v.leader, dataclasses.replace(h, unlock=now))
        return {"market_id": market_id, "settled_price": str(settle), "closed": closed}

    def take_staker_fees(self) -> Decimal:
        """The stakers' fee share withheld since the last call (already out of the holder's
        balance here; the caller moves it on the ledger)."""
        out = self.__dict__.get("staker_fees", ZERO)
        if out:
            self._keep_all()
            self.staker_fees = ZERO
        return out

    def halted(self, m: Market) -> bool:
        """The market's circuit breaker — or, a deployer market, the validators' freeze — holds
        it to reduce-only orders now."""
        now = Decimal(str(self.__dict__.get("_now", ZERO)))
        return (m.halted_until > 0 and now < m.halted_until) or self.frozen(m, now)

    @staticmethod
    def frozen(m: Market, now: Any) -> bool:
        """A deployer market the validators hold frozen at block time ``now``."""
        return m.frozen_until > 0 and Decimal(str(now)) < m.frozen_until

    @_mutator
    def freeze(self, market_id: str, until: Decimal) -> None:
        """The validators froze a deployer market until block time ``until``."""
        m = self.market(market_id)
        m.frozen_until = max(m.frozen_until, Decimal(str(until)))

    def oi_cap(self, m: Market) -> Optional[Decimal]:
        """The market's open-interest cap (notional at mark), None if uncapped."""
        floor = Decimal(constants.PERP_MIN_OI_CAP)
        vault = market_maker_address(m.id)
        if vault in self.user_vaults:
            return max(floor, self.cross_equity(vault) * OI_CAP_MULTIPLE)
        return floor if floor > 0 else None

    def _trip_breaker(self, m: Market, now: Decimal) -> Optional[dict]:
        """Each tick, after the mark is refreshed: a move of PERP_BREAKER_MOVE within the
        window halts the market's new exposure for the cooldown."""
        move = _bps(constants.PERP_BREAKER_MOVE_BPS)
        if m.mark_price <= 0 or move <= 0:
            return None
        if m.breaker_time <= 0 or now - m.breaker_time >= constants.PERP_BREAKER_WINDOW_SECONDS:
            m.breaker_mark, m.breaker_time = m.mark_price, now
            return None
        if m.breaker_mark > 0 and abs(m.mark_price - m.breaker_mark) / m.breaker_mark >= move:
            m.halted_until = now + constants.PERP_BREAKER_COOLDOWN_SECONDS
            moved_from = m.breaker_mark
            m.breaker_mark, m.breaker_time = m.mark_price, now
            return {
                "type": "circuit_breaker",
                "market": m.id,
                "from": str(moved_from),
                "to": str(m.mark_price),
                "halted_until": str(m.halted_until),
            }
        return None

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

    @_mutator
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
                f"vault deposit of {amount} exceeds the withdrawable {self.withdrawable(owner)}"
            )
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
                SHARE_QUANTUM, rounding=ROUND_DOWN
            )
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

    @_mutator
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
                AMOUNT_QUANTUM, rounding=ROUND_DOWN
            )
        if value > self.withdrawable(VAULT):
            raise ClearinghouseError(
                "the vault cannot release that much while it carries positions"
            )
        self.account(VAULT).collateral -= value
        self.account(owner).collateral += value
        self.vault_shares[owner] = have - shares
        self.vault_total_shares -= shares
        if self.vault_shares[owner] == 0:
            del self.vault_shares[owner]
            self.vault_unlock.pop(owner, None)
        return value

    # ------------------------------------------------------------------ user vaults

    def user_vault(self, vault: str) -> UserVault:
        v = self.user_vaults.peek(vault)
        if v is None:
            raise ClearinghouseError(f"no vault {vault}")
        return v

    def _holding(self, vault: str, holder: str) -> VaultHolding:
        return self.vault_holdings.peek(f"{vault}|{holder}") or VaultHolding(ZERO, ZERO, ZERO)

    def _set_holding(self, vault: str, holder: str, h: VaultHolding) -> None:
        key = f"{vault}|{holder}"
        if h.shares > 0:
            self.vault_holdings[key] = h
        elif key in self.vault_holdings:
            del self.vault_holdings[key]

    @_mutator
    @_pinned
    def create_user_vault(
        self,
        leader: str,
        vault: str,
        name: str,
        amount,
        profit_share,
        now,
        managed: str = "",
        lockup=ZERO,
    ) -> Decimal:
        """A vault ``leader`` trades (as the vault's signer) with ``amount`` of its own free
        collateral to start, one share per QRDX. ``managed``: a market's liquidity vault,
        quoted by the protocol, the leader's shares locked for ``lockup`` seconds. Returns the
        shares."""
        self._user(leader)
        amount, now = self._amount(amount), Decimal(str(now))
        profit_share = Decimal(str(profit_share))
        if vault in self.user_vaults or vault in self.accounts:
            raise ClearinghouseError(f"{vault} exists")
        if not ZERO <= profit_share <= USER_VAULT_MAX_PROFIT_SHARE:
            raise ClearinghouseError(f"profit share must be 0 to {USER_VAULT_MAX_PROFIT_SHARE}")
        if amount < USER_VAULT_MIN_DEPOSIT:
            raise ClearinghouseError(f"a vault starts with at least {USER_VAULT_MIN_DEPOSIT}")
        if not managed and sum(
            1 for v in self.user_vaults.peek_values() if v.leader == leader and not v.managed
        ) >= (USER_VAULTS_PER_LEADER):
            raise ClearinghouseError(f"at most {USER_VAULTS_PER_LEADER} vaults per leader")
        if amount > self.withdrawable(leader):
            raise ClearinghouseError(
                f"{amount} exceeds the withdrawable {self.withdrawable(leader)}"
            )
        self.accounts[leader].collateral -= amount
        self.account(vault).collateral += amount
        self.user_vaults[vault] = UserVault(
            leader=leader,
            name=str(name),
            profit_share=profit_share,
            total_shares=amount,
            created=now,
            managed=managed,
        )
        self._set_holding(vault, leader, VaultHolding(amount, amount, now + Decimal(str(lockup))))
        return amount

    @_mutator
    @_pinned
    def user_vault_deposit(self, owner: str, vault: str, amount, now) -> Decimal:
        """Join a vault: ``amount`` of the owner's free collateral for shares at NAV, locked for
        USER_VAULT_LOCKUP_SECONDS (the leader's are not). Returns the shares."""
        self._user(owner)
        amount, now = self._amount(amount), Decimal(str(now))
        v = self.user_vault(vault)
        if owner == vault:
            raise ClearinghouseError("a vault does not join itself")
        if amount > self.withdrawable(owner):
            raise ClearinghouseError(
                f"{amount} exceeds the withdrawable {self.withdrawable(owner)}"
            )
        nav = self.cross_equity(vault)
        if v.total_shares <= 0 or nav <= 0:
            raise ClearinghouseError("the vault has nothing left to join")
        shares = (amount * v.total_shares / nav).quantize(SHARE_QUANTUM, rounding=ROUND_DOWN)
        if shares <= 0:
            raise ClearinghouseError("deposit too small for a share")
        total = v.total_shares + shares
        leader_shares = self._holding(vault, v.leader).shares + (shares if owner == v.leader else 0)
        if leader_shares < total * USER_VAULT_LEADER_MIN_SHARE:
            raise ClearinghouseError(
                f"the leader must hold at least {USER_VAULT_LEADER_MIN_SHARE:%} of the vault"
            )
        h = self._holding(vault, owner)
        unlock = (
            max(h.unlock, now)
            if owner == v.leader
            else max(h.unlock, now + USER_VAULT_LOCKUP_SECONDS)
        )
        self.accounts[owner].collateral -= amount
        self.account(vault).collateral += amount
        self._set_holding(vault, owner, VaultHolding(h.shares + shares, h.basis + amount, unlock))
        self.user_vaults[vault] = dataclasses.replace(v, total_shares=total)
        return shares

    @_mutator
    @_pinned
    def user_vault_withdraw(self, owner: str, vault: str, shares, now) -> Tuple[Decimal, Decimal]:
        """Leave (part of) a vault: ``shares`` at NAV into the owner's collateral, less the
        leader's profit share of what they gained over their cost. Refused while locked, beyond
        what the vault can release without dropping below margin on its positions, or if the
        leader would hold less than its minimum while others hold shares. Returns (paid,
        profit share)."""
        self._user(owner)
        shares, now = Decimal(str(shares)), Decimal(str(now))
        if shares <= 0 or shares != shares.quantize(SHARE_QUANTUM):
            raise ClearinghouseError("shares must be positive with at most 18 decimal places")
        v = self.user_vault(vault)
        h = self._holding(vault, owner)
        if shares > h.shares:
            raise ClearinghouseError(f"only {h.shares} shares held")
        if now < h.unlock:
            raise ClearinghouseError(f"the shares are locked until block time {h.unlock}")
        total = v.total_shares - shares
        if owner == v.leader and total > 0:
            if h.shares - shares < total * USER_VAULT_LEADER_MIN_SHARE:
                raise ClearinghouseError(
                    f"the leader must hold at least {USER_VAULT_LEADER_MIN_SHARE:%} of the vault"
                )
        nav = self.cross_equity(vault)
        value = ZERO
        if nav > 0:
            value = (shares * nav / v.total_shares).quantize(AMOUNT_QUANTUM, rounding=ROUND_DOWN)
        if value > self.withdrawable(vault):
            raise ClearinghouseError("the vault cannot release that much while it holds positions")
        cost = (h.basis * shares / h.shares).quantize(AMOUNT_QUANTUM, rounding=ROUND_DOWN)
        fee = ZERO
        if owner != v.leader and value > cost:
            fee = ((value - cost) * v.profit_share).quantize(AMOUNT_QUANTUM, rounding=ROUND_DOWN)
        self.accounts[vault].collateral -= value
        self.account(owner).collateral += value - fee
        if fee > 0:
            self.account(v.leader).collateral += fee
        self._set_holding(vault, owner, VaultHolding(h.shares - shares, h.basis - cost, h.unlock))
        self.user_vaults[vault] = dataclasses.replace(v, total_shares=total)
        return value - fee, fee

    # ------------------------------------------------------------------ portfolio margin

    def asset_price(self, token: str) -> Decimal:
        """A margin token's value per unit, haircut applied (0 if it has no price)."""
        spec = portfolio_assets().get(token.lower())
        if spec is None:
            return ZERO
        m = self.markets.get(spec[0])
        if m is None or m.oracle_price <= 0:
            return ZERO
        return m.oracle_price * (1 - spec[1])

    def assets_value(self, acct: Account) -> Decimal:
        return sum(
            (amount * self.asset_price(token) for token, amount in sorted(acct.assets.items())),
            ZERO,
        )

    @_mutator
    @_pinned
    def deposit_asset(self, owner: str, token: str, amount) -> Decimal:
        """Hold ``amount`` of a portfolio-margin token as margin (the manager moves it into the
        perps holder). Returns the account's holding."""
        self._user(owner)
        amount, token = self._amount(amount), str(token).lower()
        price = self.asset_price(token)
        if price <= 0:
            raise ClearinghouseError(f"{token} is not accepted as margin")
        if amount * price < PORTFOLIO_MIN_DEPOSIT:
            raise ClearinghouseError(f"a margin deposit is worth at least {PORTFOLIO_MIN_DEPOSIT}")
        acct = self.account(owner)
        acct.assets[token] = acct.assets.get(token, ZERO) + amount
        self.asset_holdings[token] = self.asset_holdings.get(token, ZERO) + amount
        return acct.assets[token]

    @_mutator
    @_pinned
    def withdraw_asset(self, owner: str, token: str, amount) -> Decimal:
        """Release ``amount`` of a margin token (the manager moves it out of the perps holder):
        refused if what is left would not carry the account — its positions and orders, and
        what it owes in settlement token (its collateral below zero counts against it)."""
        self._user(owner)
        amount, token = self._amount(amount), str(token).lower()
        acct = self.accounts.peek(owner)
        held = acct.assets.get(token, ZERO) if acct is not None else ZERO
        if amount > held:
            raise ClearinghouseError(f"only {held} of {token} held as margin")
        left = self.cross_equity(owner) - amount * self.asset_price(token)
        if left < self.cross_requirement(owner):
            raise ClearinghouseError("what is left would not carry the account's positions")
        acct = self.accounts[owner]
        acct.assets[token] = held - amount
        if not acct.assets[token]:
            del acct.assets[token]
        self.asset_holdings[token] = self.asset_holdings[token] - amount
        if not self.asset_holdings[token]:
            del self.asset_holdings[token]
        return amount

    def _seize_assets(self, owner: str) -> None:
        """A liquidated account's margin tokens go to the backstop vault at the value they
        counted for (equity unchanged on both sides); the vault sells them (``unwind_assets``)."""
        acct = self.accounts.peek(owner)
        if acct is None or not acct.assets or owner == VAULT:
            return
        acct = self.accounts[owner]
        vault = self.account(VAULT)
        for token, amount in sorted(acct.assets.items()):
            value = (amount * self.asset_price(token)).quantize(AMOUNT_QUANTUM, rounding=ROUND_DOWN)
            acct.collateral += value
            vault.collateral -= value
            vault.assets[token] = vault.assets.get(token, ZERO) + amount
        acct.assets.clear()

    def unwind_assets_due(self, now: Decimal) -> List[Tuple[str, Decimal, Decimal]]:
        """The vault's margin tokens due a sale now: (token, amount, the least it accepts —
        the oracle less PORTFOLIO_UNWIND_SLIPPAGE)."""
        vault = self.accounts.peek(VAULT)
        if vault is None or not vault.assets:
            return []
        due = []
        assets = portfolio_assets()
        for token, amount in sorted(vault.assets.items()):
            spec = assets.get(token)
            m = self.markets.get(spec[0]) if spec is not None else None
            last = Decimal(str(self.asset_unwind_time.get(token, ZERO)))
            if m is None or m.oracle_price <= 0 or now - last < VAULT_UNWIND_SECONDS:
                continue
            value = amount * m.oracle_price
            part = (
                amount
                if value <= LIQUIDATION_SLICE_NOTIONAL
                else (amount * LIQUIDATION_SLICE_FRACTION).quantize(
                    AMOUNT_QUANTUM, rounding=ROUND_FLOOR
                )
            )
            floor = part * m.oracle_price * (1 - PORTFOLIO_UNWIND_SLIPPAGE)
            due.append((token, part, floor))
        return due

    @_mutator
    def record_asset_sale(self, token: str, sold: Decimal, proceeds: Decimal, now) -> None:
        """The vault sold ``sold`` of a margin token for ``proceeds`` of settlement token (the
        manager moved both on the ledger)."""
        vault = self.accounts[VAULT]
        vault.assets[token] = vault.assets[token] - sold
        if not vault.assets[token]:
            del vault.assets[token]
        self.asset_holdings[token] = self.asset_holdings[token] - sold
        if not self.asset_holdings[token]:
            del self.asset_holdings[token]
        vault.collateral += proceeds
        self.holder_balance += proceeds
        self.asset_unwind_time[token] = Decimal(str(now))

    @_mutator
    def mark_asset_unwind(self, token: str, now) -> None:
        """A sale was due but found no buyer within its bound: try again next interval."""
        self.asset_unwind_time[token] = Decimal(str(now))

    @_pinned
    def asset_gap(self) -> Dict[str, Decimal]:
        """token → holdings − Σ accounts' (zero everywhere while the books are sound)."""
        totals: Dict[str, Decimal] = {}
        for a in self.accounts.peek_values():
            for token, amount in a.assets.items():
                totals[token] = totals.get(token, ZERO) + amount
        tokens = set(totals) | set(dict.keys(self.asset_holdings))
        return {
            t: self.asset_holdings.get(t, ZERO) - totals.get(t, ZERO)
            for t in sorted(tokens)
            if self.asset_holdings.get(t, ZERO) != totals.get(t, ZERO)
        }

    # ------------------------------------------------------------------ margin math

    @staticmethod
    def _upnl(m: Market, pos: Position) -> Decimal:
        return pos.size * (m.mark_price - pos.entry_price)

    @_pinned
    def cross_equity(self, owner: str) -> Decimal:
        """Cross collateral plus the unrealized PnL of every cross position, at mark, plus the
        portfolio-margin tokens held, at their haircut value."""
        acct = self.accounts.peek(owner)
        if acct is None:
            return ZERO
        eq = acct.collateral + (self.assets_value(acct) if acct.assets else ZERO)
        for mid, pos in acct.positions.items():
            if pos.size != 0 and not acct.isolated.get(mid, False):
                eq += self._upnl(self.markets[mid], pos)
        return eq

    @_pinned
    def open_order_margin(self, owner: str) -> Decimal:
        """Margin reserved by resting orders that could increase exposure (cross or isolated:
        isolated margin is drawn from cross collateral when the order fills). What would only
        close the position reserves nothing (``_opening_amounts``); it used to reserve as if it
        opened, unless flagged reduce-only."""
        return sum((self._reserved_in(owner, m) for m in self.markets.values()), ZERO)

    def _resting(self, owner: str, m: Market) -> List[Tuple[Order, OrderMeta]]:
        """``owner``'s active resting orders in ``m``, by id."""
        out = []
        for oid in sorted(self._orders_by_owner(m).get(owner, ())):
            meta = tracked(m.orders).peek(oid)
            order = m.book.get_order(oid)
            if meta is not None and order is not None and order.is_active:
                out.append((order, meta))
        return out

    @staticmethod
    def _orders_by_owner(m: Market) -> Dict[str, set]:
        """owner → the ids of its orders in ``m``: derived from the order metadata, never
        committed. Built in full when missing (a new or unpickled market) and otherwise brought
        up to date with the ids marked since — as the liquidation index is — so finding one
        account's orders does not scan every order in the market."""
        orders = tracked(m.orders)
        index = m.__dict__.get("_by_owner")
        if index is None or orders.__dict__.get("_index_token") is not index["token"]:
            index = {"token": [], "owners": {}, "owner_of": {}}
            orders.track_changes()
            orders.take_changes()
            orders.__dict__["_index_token"] = index["token"]
            for oid, meta in orders.peek_items():
                index["owner_of"][oid] = meta.owner
                index["owners"].setdefault(meta.owner, set()).add(oid)
            m.__dict__["_by_owner"] = index
        else:
            for oid in orders.take_changes():
                old = index["owner_of"].pop(oid, None)
                if old is not None:
                    index["owners"][old].discard(oid)
                meta = orders.peek(oid)
                if meta is not None:
                    index["owner_of"][oid] = meta.owner
                    index["owners"].setdefault(meta.owner, set()).add(oid)
        return index["owners"]

    def _opening_amounts(
        self, owner: str, m: Market, extra: Optional[Tuple[Order, OrderMeta]] = None
    ) -> List[Tuple[Order, OrderMeta, Decimal]]:
        """Each resting order (and ``extra``, as if resting) with the part of it that would
        open exposure. The position's size is closing capacity, used by the orders on the side
        that closes it (sells against a long, buys against a short) in the order they would
        fill — by price, then id; every order on the other side opens whole."""
        acct = self.accounts.peek(owner)
        pos = acct.positions.get(m.id) if acct is not None else None
        size = pos.size if pos is not None else ZERO
        sell = size > 0
        orders = self._resting(owner, m) + ([extra] if extra is not None else [])
        closing = [x for x in orders if size != 0 and (x[0].side == OrderSide.SELL) == sell]
        closing.sort(key=lambda x: (x[0].price if sell else -x[0].price, x[0].id))
        capacity = abs(size)
        out = []
        for order, meta in closing:
            used = min(capacity, order.remaining)
            capacity -= used
            out.append((order, meta, order.remaining - used))
        closing_ids = {o.id for o, _ in closing}
        out += [(o, meta, o.remaining) for o, meta in orders if o.id not in closing_ids]
        return out

    @_pinned
    def cross_requirement(self, owner: str) -> Decimal:
        """Initial margin for every cross position at mark, plus resting-order reservations."""
        acct = self.accounts.peek(owner)
        if acct is None:
            return ZERO
        req = ZERO
        for mid, pos in acct.positions.items():
            if pos.size != 0 and not acct.isolated.get(mid, False):
                m = self.markets[mid]
                req += initial_margin(m, self._leverage(acct, m), abs(pos.size) * m.mark_price)
        return req + self.open_order_margin(owner)

    @_pinned
    def cross_maintenance(self, owner: str) -> Decimal:
        acct = self.accounts.peek(owner)
        if acct is None:
            return ZERO
        total = ZERO
        for mid, pos in acct.positions.items():
            if pos.size != 0 and not acct.isolated.get(mid, False):
                m = self.markets[mid]
                total += abs(pos.size) * m.mark_price * m.maintenance_rate
        return total

    # ------------------------------------------------------------------ trading

    @_mutator
    @_pinned
    def place_order(
        self,
        owner: str,
        market_id: str,
        order_id: str,
        side: str,
        size,
        price,
        nonce: int,
        reduce_only: bool = False,
        ioc: bool = False,
        max_makers: Optional[int] = None,
        tif: str = "gtc",
        hidden: bool = False,
        display_size=ZERO,
    ) -> List[dict]:
        """
        Place a limit order. Matches against the book; any remainder rests. ``tif``: "gtc"
        rests the remainder; "ioc" (or ``ioc``) cancels it; "fok" fills whole or refuses;
        "alo" (post-only) refuses if it would match at all. ``hidden`` / ``display_size``: a
        resting order that shows nothing, or a slice at a time (an iceberg), in the book.
        Returns the fills. Refuses — changing nothing — if the account could not carry the
        result at initial margin assuming a full fill at the worst price the limit allows.
        ``max_makers``: how many resting orders it may visit (what its gas pays for,
        ``orderbook.MatchBudget``); the remainder is cancelled when they run out.
        """
        self._user(owner)
        self._check_grid(self.market(market_id), size, price, bool(reduce_only))
        self._touched, self._cancelled, self.last_cancelled = set(), [], []
        self.last_makers_visited = 0
        fills = self._place(
            owner,
            market_id,
            order_id,
            side,
            size,
            price,
            nonce,
            reduce_only=reduce_only,
            tif="ioc" if ioc else tif,
            hidden=hidden,
            display_size=display_size,
            max_makers=max_makers,
        )
        self._trim_touched()
        self.last_cancelled = self._cancelled
        return fills

    def _place(
        self,
        owner: str,
        market_id: str,
        order_id: str,
        side: str,
        size,
        price,
        nonce: int,
        *,
        reduce_only: bool = False,
        tif: str = "gtc",
        hidden: bool = False,
        display_size=ZERO,
        max_makers: Optional[int] = None,
        protocol: bool = False,
    ) -> List[dict]:
        """``place_order`` without its per-operation bookkeeping (a fired trigger, a batch's
        orders and a modify place through it). ``protocol``: placed by the clearinghouse for
        the owner (a trigger), so not counted against the owner's per-block order limit."""
        tif = str(tif).lower()
        if tif not in ("gtc", "ioc", "fok", "alo"):
            raise ClearinghouseError(f"unknown time in force {tif!r} (gtc, ioc, fok, alo)")
        m = self.market(market_id)
        if m.mark_price <= 0:
            raise ClearinghouseError(f"market {market_id} has no price yet")
        size, price = Decimal(str(size)), Decimal(str(price))
        if size <= 0 or price <= 0:
            raise ClearinghouseError("size and price must be positive")
        buy = str(side).lower() in ("buy", "long", "bid")
        if not buy and str(side).lower() not in ("sell", "short", "ask"):
            raise ClearinghouseError(f"unknown side {side!r}")
        if owner in self.user_vaults and (
            price > m.mark_price * (1 + USER_VAULT_ORDER_BAND)
            if buy
            else price < m.mark_price * (1 - USER_VAULT_ORDER_BAND)
        ):
            raise ClearinghouseError(
                f"a vault's order may be at most {USER_VAULT_ORDER_BAND:%} worse than the mark"
            )
        if m.settled_price > 0:
            raise ClearinghouseError(f"{market_id} is delisted")
        band = _bps(constants.PERP_PRICE_BAND_BPS)
        if (
            band > 0
            and m.oracle_price > 0
            and (
                price > m.oracle_price * (1 + band) if buy else price < m.oracle_price * (1 - band)
            )
        ):
            raise ClearinghouseError(
                f"an order may be at most {band:%} worse than the oracle ({m.oracle_price})"
            )
        if not reduce_only and self.halted(m):
            if self.frozen(m, self.__dict__.get("_now", ZERO)):
                raise ClearinghouseError(
                    f"the validators have frozen {market_id}: reduce-only orders until "
                    f"block time {m.frozen_until}"
                )
            raise ClearinghouseError(
                f"{market_id}'s circuit breaker has tripped: reduce-only orders until "
                f"block time {m.halted_until}"
            )
        acct = self.account(owner)
        pos = acct.positions.get(market_id, Position())
        lev = self._leverage(acct, m)
        q = size if buy else -size
        oi_before = m.open_interest

        if reduce_only:
            if pos.size == 0 or (pos.size > 0) == buy or size > abs(pos.size):
                raise ClearinghouseError("reduce-only order would not reduce the position")
        else:
            self._check_initial_margin(owner, acct, m, pos, q, price, lev)
        if tif in ("gtc", "alo"):  # it may rest
            self._check_resting_margin(owner, m, order_id, buy, size, price, lev, reduce_only)

        order = Order(
            id=order_id,
            owner=owner,
            side=OrderSide.BUY if buy else OrderSide.SELL,
            order_type=OrderType.LIMIT,
            price=price,
            amount=size,
            nonce=nonce,
            timestamp=0.0,
            tif=tif,
            hidden=bool(hidden),
            display_size=Decimal(str(display_size)),
        )
        budget = MatchBudget(max_makers) if max_makers is not None else None
        capped = self.oi_cap(m) is not None
        # A capped market checks open interest after the fills: they run in a scope of their own
        # so a refusal undoes them whoever called (ClearinghouseError changes nothing).
        with undo.atomic() if capped else contextlib.nullcontext():
            if capped:
                self._keep_all()
            try:
                trades = self._match(m, order, protocol=protocol, budget=budget)
            finally:
                # Read by the operation even when it fails (a fill-or-kill pays for its visits).
                self.last_makers_visited = budget.visited if budget is not None else 0
            m.orders[order_id] = OrderMeta(owner=owner, leverage=lev, reduce_only=bool(reduce_only))
            fills = []
            for tr in trades:
                fills.append(self._apply_fill(m, tr, taker_limit=price))
            cap = self.oi_cap(m) if capped else None
            if (
                cap is not None
                and m.open_interest > oi_before
                and m.open_interest * m.mark_price > cap
            ):
                raise ClearinghouseError(
                    f"{market_id}'s open interest is capped at {cap} (its liquidity sets the cap)"
                )
        if tif in ("ioc", "fok") and order.is_active:
            m.book.cancel_order(order_id, caller=owner)
        self._prune_orders(m, self._match_ids(m, order_id, trades))
        return fills

    def _match(
        self,
        m: Market,
        order: Order,
        protocol: bool = False,
        budget: Optional[MatchBudget] = None,
    ) -> List[Any]:
        """Match ``order`` on the book, guarding each maker's fill (Hyperliquid checks makers
        at match time). A maker whose fill would open exposure is cancelled instead if it is
        reduce-only, or if the margin its order reserved does not cover that exposure and the
        account's free margin does not either — the reservation assumed the position as it
        stood, and an earlier fill (maybe in this very match) can turn a closing order into an
        opening one."""
        pending: Dict[str, Decimal] = {}  # owner → position change from this match's fills
        free: Dict[str, Decimal] = {}  # owner → free margin left for unreserved openings
        reserved: Dict[str, Decimal] = {}  # order id → its opening part, as reserved

        def guard(maker: Order, amount: Decimal) -> bool:
            meta = tracked(m.orders).peek(maker.id)
            if meta is None:
                return True
            owner = meta.owner
            if owner not in free:  # first fill of this owner in this match: book as reserved
                free[owner] = self.cross_equity(owner) - self.cross_requirement(owner)
                for o, _meta, opening in self._opening_amounts(owner, m):
                    reserved[o.id] = opening
            acct = self.accounts.peek(owner)
            pos = acct.positions.get(m.id) if acct is not None else None
            size = (pos.size if pos is not None else ZERO) + pending.get(owner, ZERO)
            q = amount if maker.side == OrderSide.BUY else -amount
            opening = max(ZERO, abs(size + q) - abs(size))
            if opening > 0:
                if meta.reduce_only:
                    self._cancel_event(owner, m.id, maker.id, "reduce_only")
                    return False
                covered = min(opening, reserved.get(maker.id, ZERO))
                reserved[maker.id] = reserved.get(maker.id, ZERO) - covered
                need = (opening - covered) * maker.price / meta.leverage
                if need > free[owner]:
                    self._cancel_event(owner, m.id, maker.id, "margin")
                    return False
                free[owner] -= need
            pending[owner] = pending.get(owner, ZERO) + q
            return True

        m.book.maker_guard = guard
        try:
            return m.book.place_order(order, protocol=protocol, budget=budget)
        finally:
            m.book.maker_guard = None

    def _cancel_event(self, owner: str, mid: str, order_id: str, reason: str) -> None:
        self._cancelled.append(
            {
                "type": "order_cancelled",
                "market": mid,
                "order_id": order_id,
                "owner": owner,
                "reason": reason,
            }
        )

    def _trim_touched(self) -> None:
        """Every account whose position just changed: the resting orders it no longer
        qualifies for are cancelled (``_trim_orders``)."""
        touched = sorted(self._touched)
        self._touched = set()
        for owner, mid in touched:
            if owner != VAULT:
                self._trim_orders(owner, mid)

    def _trim_orders(self, owner: str, mid: str) -> None:
        """After ``owner``'s position in ``mid`` changed: a reduce-only order that would now
        open exposure is cancelled (Hyperliquid's reduceOnlyCanceled); then, while the account
        cannot carry its resting orders at initial margin, its opening orders there are
        cancelled, the least likely to fill first (marginCanceled). An order that only closed
        the position reserved nothing, so one left opening by a smaller position would
        otherwise fill unmargined."""
        m = self.markets[mid]

        def cancel(order: Order, reason: str) -> None:
            m.book.cancel_order(order.id, caller=owner)
            self._prune_orders(m, [order.id])
            self._cancel_event(owner, mid, order.id, reason)

        for order, meta, opening in self._opening_amounts(owner, m):
            if meta.reduce_only and opening > 0:
                cancel(order, "reduce_only")
        position_triggers = [  # a position's TP/SL, and an order's once the order is done
            tid
            for tid in sorted(self._trigger_index(m)["owners"].get(owner, ()))
            if tracked(m.triggers).peek(tid).position
            or (
                tracked(m.triggers).peek(tid).parent
                and tracked(m.triggers).peek(tid).parent not in m.orders
            )
        ]
        if position_triggers:
            acct = self.accounts.peek(owner)
            pos = acct.positions.get(mid) if acct is not None else None
            held = pos.size if pos is not None else ZERO
            for tid in position_triggers:
                if held == 0 or (held > 0) == (tracked(m.triggers).peek(tid).side == "buy"):
                    del m.triggers[tid]  # the position it was for is gone
                    self._cancelled.append(
                        {
                            "type": "trigger_cancelled",
                            "market": mid,
                            "trigger_id": tid,
                            "owner": owner,
                            "reason": "position_closed",
                        }
                    )
        if self.cross_equity(owner) >= self.cross_requirement(owner):
            return
        opening_orders = [
            order
            for order, meta, opening in self._opening_amounts(owner, m)
            if opening > 0 and not meta.reduce_only
        ]
        opening_orders.sort(key=lambda o: (o.price if o.side == OrderSide.BUY else -o.price, o.id))
        for order in opening_orders:
            if self.cross_equity(owner) >= self.cross_requirement(owner):
                break
            cancel(order, "margin")

    @_mutator
    @_pinned
    def cancel_order(self, owner: str, market_id: str, order_id: str) -> None:
        """Cancel a resting order or a trigger order."""
        m = self.market(market_id)
        trigger = tracked(m.triggers).peek(order_id)
        if trigger is not None and trigger.owner == owner:
            del m.triggers[order_id]
            return
        meta = m.orders.get(order_id)
        if meta is None or meta.owner != owner:
            raise ClearinghouseError(f"no open order {order_id} for this account")
        cancelled = m.book.cancel_order(order_id, caller=owner)
        self._prune_orders(m, [order_id])
        if cancelled is not None and cancelled.filled == 0:
            for tid in self._children_of(m, owner, order_id):  # its TP/SL protect nothing
                del m.triggers[tid]

    @_mutator
    @_pinned
    def cancel_all(self, owner: str, market_id: Optional[str] = None) -> int:
        """Cancel every resting order and trigger of ``owner`` (in one market, or all).
        Returns how many."""
        if market_id is not None:
            self.market(market_id)
        count = 0
        for mid in sorted(self.markets):
            if market_id is not None and mid != market_id:
                continue
            m = self.markets[mid]
            mine = sorted(self._orders_by_owner(m).get(owner, ()))
            for oid in mine:
                if tracked(m.orders).peek(oid) is not None:
                    m.book.cancel_order(oid, caller=owner)
                    count += 1
            self._prune_orders(m, mine)
            for tid in sorted(self._trigger_index(m)["owners"].get(owner, ())):
                del m.triggers[tid]
                count += 1
        return count

    @_mutator
    @_pinned
    def modify_order(
        self,
        owner: str,
        market_id: str,
        order_id: str,
        new_id: str,
        size=None,
        price=None,
        trigger_price=None,
        limit_price=None,
        max_makers: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Change an open order in one step: what is left of it (``size``) and its ``price``.
        A smaller size at the same price keeps the order's place in the queue; any other change
        replaces it with a new order ``new_id`` — the old one cancelled, the new one matched
        and margined as any order, all or nothing. A trigger order changes its ``size``,
        ``trigger_price`` and ``limit_price`` in place (and queues again). Returns
        ``{"order_id", "fills", "resting"}``."""
        self._touched, self._cancelled, self.last_cancelled = set(), [], []
        self.last_makers_visited = 0
        m = self.market(market_id)
        trigger = tracked(m.triggers).peek(order_id)
        if trigger is not None and trigger.owner == owner:
            if price is not None:
                raise ClearinghouseError("a trigger order changes trigger_price and limit_price")
            for px in (trigger_price, limit_price):
                if px is not None and Decimal(str(px)) > 0:
                    self._check_grid(
                        m, trigger.size if size is None else size, px, trigger.reduce_only
                    )
            changed = self._new_trigger(
                m,
                trigger,
                size=trigger.size if size is None else size,
                trigger_price=(trigger.trigger_price if trigger_price is None else trigger_price),
                limit_price=trigger.limit_price if limit_price is None else limit_price,
            )
            m.triggers[order_id] = changed
            return {"order_id": order_id, "fills": [], "resting": False}
        if trigger_price is not None or limit_price is not None:
            raise ClearinghouseError("only a trigger order has a trigger or limit price")
        meta = m.orders.get(order_id)
        order = m.book.get_order(order_id)
        if meta is None or meta.owner != owner or order is None or not order.is_active:
            raise ClearinghouseError(f"no open order {order_id} for this account")
        size = order.remaining if size is None else Decimal(str(size))
        price = order.price if price is None else Decimal(str(price))
        if size <= 0 or price <= 0:
            raise ClearinghouseError("size and price must be positive")
        self._check_grid(m, size, price, meta.reduce_only)
        if price == order.price and size < order.remaining:
            m.book.reduce_order(order_id, order.filled + size, caller=owner)
            return {"order_id": order_id, "fills": [], "resting": True}
        m.book.cancel_order(order_id, caller=owner)
        self._prune_orders(m, [order_id])
        fills = self._place(
            owner,
            market_id,
            new_id,
            order.side.value,
            size,
            price,
            0,
            reduce_only=meta.reduce_only,
            tif="alo" if order.tif == "alo" else "gtc",
            hidden=order.hidden,
            display_size=order.display_size if order.display_size < size else ZERO,
            max_makers=max_makers,
        )
        self._trim_touched()
        self.last_cancelled = self._cancelled
        return {"order_id": new_id, "fills": fills, "resting": new_id in m.orders}

    @_mutator
    @_pinned
    def protocol_ioc(
        self,
        owner: str,
        market_id: str,
        order_id: str,
        side: str,
        size,
        price,
        *,
        reduce_only: bool,
        max_makers: int,
    ) -> Tuple[List[dict], List[dict]]:
        """An immediate-or-cancel order the protocol places for ``owner`` outside any
        transaction (a TWAP slice): margined and matched as the owner's own, within
        ``max_makers``; all or nothing. Returns (fills, orders it cancelled); raises
        ClearinghouseError / ValueError, changing nothing, if it is refused."""
        self._touched, self._cancelled = set(), []
        with undo.atomic():
            self._keep_all()
            fills = self._place(
                owner,
                market_id,
                order_id,
                side,
                size,
                price,
                0,
                reduce_only=reduce_only,
                tif="ioc",
                max_makers=max_makers,
                protocol=True,
            )
            self._trim_touched()
        return fills, list(self._cancelled)

    # ------------------------------------------------------------------ market liquidity

    def _quote_markets(self, now: Decimal) -> List[dict]:
        """The block's re-quotes of markets' liquidity vaults (see MARKET_MAKER_*): those due —
        the longest unquoted first — at most MARKET_MAKER_MARKETS_PER_BLOCK."""
        if not len(self.user_vaults):
            return []
        due = []
        for vault, v in sorted(self.user_vaults.peek_items()):
            m = self.markets.get(v.managed) if v.managed else None
            if m is None or m.settled_price > 0:
                continue
            moved = (
                m.mm_mark > 0
                and m.mark_price > 0
                and abs(m.mark_price - m.mm_mark) / m.mm_mark >= MARKET_MAKER_REQUOTE_MOVE
            )
            if moved or now - m.mm_time >= MARKET_MAKER_REQUOTE_SECONDS:
                due.append((m.mm_time, m.id, vault))
        events = []
        for _t, mid, vault in sorted(due)[:MARKET_MAKER_MARKETS_PER_BLOCK]:
            events.append(self._quote(self.markets[mid], vault, now))
        return events

    def _quote(self, m: Market, vault: str, now: Decimal) -> dict:
        """Cancel the vault's quotes on ``m`` and post the ladder for the mark now."""
        from .. import constants

        mine = sorted(self._orders_by_owner(m).get(vault, ()))
        for oid in mine:
            if tracked(m.orders).peek(oid) is not None:
                m.book.cancel_order(oid, caller=vault)
        self._prune_orders(m, mine)
        m.mm_time, m.mm_mark = now, m.mark_price
        stale = (
            m.oracle_time > 0 and now - m.oracle_time > constants.PERP_ORACLE_STALE_SECONDS
        ) or self.halted(m)
        equity = self.cross_equity(vault)
        event: Dict[str, Any] = {"type": "market_quotes", "market": m.id, "vault": vault}
        if stale or m.mark_price <= 0 or equity <= 0:
            return {**event, "levels": 0, "reason": "stale oracle" if stale else "no price"}
        acct = self.accounts.peek(vault)
        pos = acct.positions.get(m.id) if acct is not None else None
        held = (pos.size if pos is not None else ZERO) * m.mark_price
        limit = equity * MARKET_MAKER_MAX_INVENTORY
        scale = {
            "buy": max(ZERO, 1 - max(ZERO, held) / limit),
            "sell": max(ZERO, 1 - max(ZERO, -held) / limit),
        }
        per_level = equity * MARKET_MAKER_DEPTH / MARKET_MAKER_LEVELS
        placed = 0
        for side in ("buy", "sell"):
            for i in range(MARKET_MAKER_LEVELS):
                offset = MARKET_MAKER_SPREAD + i * MARKET_MAKER_STEP
                if side == "buy":
                    price = (m.mark_price * (1 - offset)).quantize(
                        ENTRY_QUANTUM, rounding=ROUND_FLOOR
                    )
                else:
                    price = (m.mark_price * (1 + offset)).quantize(
                        ENTRY_QUANTUM, rounding=ROUND_CEILING
                    )
                size = (per_level * scale[side] / price).quantize(
                    AMOUNT_QUANTUM, rounding=ROUND_DOWN
                )
                if size <= m.book.min_order_size:
                    continue
                try:
                    with undo.atomic():
                        self._keep_all()
                        self._place(
                            vault,
                            m.id,
                            f"mm.{side[0]}{i}",
                            side,
                            size,
                            price,
                            0,
                            tif="alo",
                            max_makers=0,
                            protocol=True,
                        )
                    placed += 1
                except (ClearinghouseError, ValueError):
                    continue  # it would cross, or the vault cannot carry more: skip the level
        return {**event, "levels": placed, "equity": str(equity)}

    # ------------------------------------------------------------------ trigger orders

    @_mutator
    @_pinned
    def place_trigger(
        self,
        owner: str,
        market_id: str,
        trigger_id: str,
        side: str,
        kind: str,
        trigger_price,
        size=ZERO,
        limit_price=ZERO,
        reduce_only: bool = False,
        position: bool = False,
        tif: str = "gtc",
        max_makers: int = TRIGGER_DEFAULT_MAKERS,
        group: str = "",
        parent: str = "",
    ) -> Trigger:
        """A stop (``kind`` "sl") or take-profit ("tp") order: when the mark reaches
        ``trigger_price`` it is placed as a limit order at ``limit_price`` (``tif``), or as a
        market order (no limit price: IOC at most TRIGGER_SLIPPAGE through mark). A buy stop
        and a sell take-profit fire as the mark rises to the trigger, the others as it falls.
        ``position``: the position's TP/SL — no size; it closes the whole position, whatever
        it is then, and is cancelled once there is no position on that side to close.
        Refused if the mark has already reached the trigger (place an order instead)."""
        self._user(owner)
        m = self.market(market_id)
        if m.settled_price > 0:
            raise ClearinghouseError(f"{market_id} is delisted")
        if m.mark_price <= 0:
            raise ClearinghouseError(f"market {market_id} has no price yet")
        side = str(side).lower()
        if side in ("long", "bid"):
            side = "buy"
        elif side in ("short", "ask"):
            side = "sell"
        if side not in ("buy", "sell"):
            raise ClearinghouseError(f"unknown side {side!r}")
        kind = {"stop": "sl", "stop_loss": "sl", "take_profit": "tp"}.get(str(kind), str(kind))
        if kind not in ("sl", "tp"):
            raise ClearinghouseError("a trigger is a stop (sl) or a take-profit (tp)")
        if trigger_id in m.triggers or trigger_id in m.orders:
            raise ClearinghouseError(f"duplicate order id {trigger_id}")
        if not 1 <= int(max_makers) <= TRIGGER_MAX_MAKERS:
            raise ClearinghouseError(f"max_makers must be 1 to {TRIGGER_MAX_MAKERS}")
        if len(self._trigger_index(m)["owners"].get(owner, ())) >= TRIGGERS_PER_ACCOUNT:
            raise ClearinghouseError(f"at most {TRIGGERS_PER_ACCOUNT} trigger orders per market")
        if position:
            if Decimal(str(size or 0)) != 0:
                raise ClearinghouseError("a position's TP/SL has no size: it closes the position")
            acct = self.accounts.peek(owner)
            pos = acct.positions.get(market_id) if acct is not None else None
            if pos is None or pos.size == 0 or (pos.size > 0) == (side == "buy"):
                raise ClearinghouseError(f"no position for a {side} to close")
        tif = str(tif).lower()
        if tif not in ("gtc", "ioc"):
            raise ClearinghouseError("a trigger order fires as gtc or ioc")
        if m.sz_decimals >= 0 or constants.PERP_MIN_ORDER_VALUE:
            for px in (trigger_price, limit_price):
                if px is not None and Decimal(str(px)) > 0:
                    self._check_grid(
                        m,
                        ZERO if position else (size or ZERO),
                        px,
                        True if position else bool(reduce_only),
                    )
        trigger = self._new_trigger(
            m,
            Trigger(
                owner=owner,
                side=side,
                kind=kind,
                trigger_price=ZERO,
                size=ZERO,
                limit_price=ZERO,
                reduce_only=bool(reduce_only) or bool(position),
                position=bool(position),
                tif=tif,
                max_makers=int(max_makers),
                seq=0,
                group=str(group),
                parent=str(parent),
            ),
            size=size,
            trigger_price=trigger_price,
            limit_price=limit_price,
        )
        m.triggers[trigger_id] = trigger
        return trigger

    def _new_trigger(self, m: Market, t: Trigger, *, size, trigger_price, limit_price) -> Trigger:
        """``t`` with these prices and size, checked; queued last (a new ``seq``)."""
        size = Decimal(str(size or 0))
        trigger_price = Decimal(str(trigger_price))
        limit_price = Decimal(str(limit_price or 0))
        if not trigger_price.is_finite() or trigger_price <= 0:
            raise ClearinghouseError("trigger price must be positive")
        if not limit_price.is_finite() or limit_price < 0:
            raise ClearinghouseError("limit price must be positive (or none: a market order)")
        if not size.is_finite() or (size <= 0 if not t.position else size != 0):
            raise ClearinghouseError("size must be positive")
        if trigger_price != t.trigger_price and dataclasses.replace(
            t, trigger_price=trigger_price
        ).crossed(m.mark_price):
            raise ClearinghouseError(
                f"the mark ({m.mark_price}) has already reached the trigger price"
            )
        self.trigger_seq += 1  # placed or changed: queued last
        return dataclasses.replace(
            t,
            trigger_price=trigger_price,
            size=size,
            limit_price=limit_price,
            seq=self.trigger_seq,
        )

    @staticmethod
    def _trigger_index(m: Market) -> Dict[str, Any]:
        """The market's triggers by owner and by trigger price — derived, never committed;
        kept up to date from the ids marked since (as ``_orders_by_owner``). ``above``: those
        that fire as the mark rises, ``below``: as it falls; each sorted by (price, seq, id)."""
        triggers = tracked(m.triggers)
        index = m.__dict__.get("_trigger_index")
        if index is None or triggers.__dict__.get("_index_token") is not index["token"]:
            index = {"token": [], "owners": {}, "keys": {}, "above": [], "below": []}
            triggers.track_changes()
            triggers.take_changes()
            triggers.__dict__["_index_token"] = index["token"]
            changed: Iterable[str] = list(dict.keys(triggers))
            m.__dict__["_trigger_index"] = index
        else:
            changed = triggers.take_changes()
        for tid in changed:
            old = index["keys"].pop(tid, None)
            if old is not None:
                owner, above, key = old
                lst = index["above" if above else "below"]
                i = bisect.bisect_left(lst, key)
                if i < len(lst) and lst[i] == key:
                    del lst[i]
                index["owners"][owner].discard(tid)
            t = triggers.peek(tid)
            if t is not None:
                key = (t.trigger_price, t.seq, tid)
                bisect.insort(index["above" if t.fires_above else "below"], key)
                index["keys"][tid] = (t.owner, t.fires_above, key)
                index["owners"].setdefault(t.owner, set()).add(tid)
        return index

    def _crossed_triggers(self, m: Market) -> List[str]:
        index = self._trigger_index(m)
        mark = m.mark_price
        above, below = index["above"], index["below"]
        hit = [tid for _p, _s, tid in above[: bisect.bisect_right(above, (mark, 1 << 62, "~"))]]
        hit += [tid for _p, _s, tid in below[bisect.bisect_left(below, (mark, -1, "")) :]]
        return hit

    def _fire_triggers(self, now: Decimal) -> List[dict]:
        """Fire the triggers the marks have reached, in priority order (see TRIGGER_SLIPPAGE)
        and within the block's limits. While a market's oracle is stale only risk-reducing
        triggers fire, as only reduce-only orders are accepted."""
        from .. import constants

        stale_after = Decimal(constants.PERP_ORACLE_STALE_SECONDS)
        queue = []
        for mid in sorted(self.markets):
            m = self.markets[mid]
            if m.mark_price <= 0:
                continue
            stale = (m.oracle_time > 0 and now - m.oracle_time > stale_after) or self.halted(m)
            for tid in self._crossed_triggers(m):
                t = tracked(m.triggers).peek(tid)
                if t is None or (stale and not t.reduces):
                    continue
                passed = abs(m.mark_price - t.trigger_price) / m.mark_price
                queue.append(((0 if t.reduces else 1, -passed, t.seq, mid, tid), mid, tid))
        queue.sort()
        events: List[dict] = []
        fired = makers = 0
        for _key, mid, tid in queue:
            m = self.markets[mid]
            t = tracked(m.triggers).peek(tid)
            if t is None:
                continue  # cancelled by an earlier one (its position closed)
            if fired >= TRIGGER_FIRES_PER_BLOCK or makers + t.max_makers > TRIGGER_MAKERS_PER_BLOCK:
                break
            fired += 1
            makers += t.max_makers
            events.append(self._fire(m, tid, t))
        return events

    def _fire(self, m: Market, tid: str, t: Trigger) -> dict:
        """Place a crossed trigger's order for its owner (all or nothing); it is gone either
        way."""
        del m.triggers[tid]
        event: Dict[str, Any] = {"market": m.id, "trigger_id": tid, "owner": t.owner}
        buy = t.side == "buy"
        size = t.size
        if t.reduces:
            acct = self.accounts.peek(t.owner)
            pos = acct.positions.get(m.id) if acct is not None else None
            held = pos.size if pos is not None else ZERO
            if held == 0 or (held > 0) == buy:
                return {"type": "trigger_cancelled", **event, "reason": "no position to reduce"}
            size = abs(held) if t.position else min(size, abs(held))
        if t.limit_price > 0:
            price, tif = t.limit_price, t.tif
        else:
            through = m.mark_price * (1 + TRIGGER_SLIPPAGE if buy else 1 - TRIGGER_SLIPPAGE)
            price = through.quantize(ENTRY_QUANTUM, rounding=ROUND_FLOOR if buy else ROUND_CEILING)
            tif = "ioc"
        touched, cancelled = set(self._touched), len(self._cancelled)
        try:
            with undo.atomic():
                self._keep_all()
                fills = self._place(
                    t.owner,
                    m.id,
                    tid,
                    t.side,
                    size,
                    price,
                    0,
                    reduce_only=t.reduces,
                    tif=tif,
                    max_makers=t.max_makers,
                    protocol=True,
                )
        except Exception as e:  # noqa: BLE001 — deterministic on every node; never fails the block
            self._touched = touched
            del self._cancelled[cancelled:]
            return {"type": "trigger_cancelled", **event, "reason": str(e)}
        for other in self._group_of(m, t, tid):  # one cancels the other
            del m.triggers[other]
            self._cancelled.append(
                {
                    "type": "trigger_cancelled",
                    "market": m.id,
                    "trigger_id": other,
                    "owner": t.owner,
                    "reason": "oco",
                }
            )
        return {
            "type": "trigger_fired",
            **event,
            "side": t.side,
            "kind": t.kind,
            "size": str(size),
            "price": str(price),
            "fills": fills,
            "resting": tid in m.orders,
        }

    def _group_of(self, m: Market, t: Trigger, tid: str) -> List[str]:
        """The other triggers of ``t``'s one-cancels-the-other group."""
        if not t.group:
            return []
        return [
            other
            for other in sorted(self._trigger_index(m)["owners"].get(t.owner, ()))
            if other != tid and tracked(m.triggers).peek(other).group == t.group
        ]

    def _children_of(self, m: Market, owner: str, parent: str) -> List[str]:
        return [
            tid
            for tid in sorted(self._trigger_index(m)["owners"].get(owner, ()))
            if tracked(m.triggers).peek(tid).parent == parent
        ]

    def _prune_orders(self, m: Market, ids: Optional[Iterable[str]] = None) -> None:
        """Drop the metadata of orders no longer resting. ``ids``: the orders the operation
        placed, filled or cancelled — the only ones that can have stopped resting (no perp
        order expires) — so a placement does not walk every order in the market (it did:
        most of its cost at 10,000 resting orders). Without ``ids``, every order; verifying,
        both, and they must agree."""

        def stopped(oid: str) -> bool:
            o = m.book.get_order(oid)
            return o is None or not o.is_active

        if ids is None or verifying():
            stale = [oid for oid in dict.keys(m.orders) if stopped(oid)]
            if ids is not None and not set(stale) <= set(ids):
                raise AssertionError(
                    f"order pruning: {sorted(set(stale) - set(ids))[:3]} stopped resting "
                    "outside the operation's orders"
                )
        else:
            stale = [oid for oid in dict.fromkeys(ids) if oid in m.orders and stopped(oid)]
        for oid in stale:
            del m.orders[oid]

    def _match_ids(self, m: Market, order_id: str, trades: List[Any]) -> List[str]:
        """The orders a match can have stopped: the taker, its makers, and makers the guard
        cancelled."""
        ids = [order_id] + [tr.maker_order_id for tr in trades]
        ids += [c["order_id"] for c in self._cancelled if c["market"] == m.id]
        return ids

    def _check_initial_margin(
        self,
        owner: str,
        acct: Account,
        m: Market,
        pos: Position,
        q: Decimal,
        limit: Decimal,
        lev: Decimal,
    ) -> None:
        """Worst case of a full fill at the limit: buys fill at or below it, sells at or above.
        Resting orders that close the position and would fill no later than this one (at its
        price or better) use its capacity first: this one closes only what they leave."""
        size = pos.size
        closes_with_sells = size > 0
        if size != 0 and (q < 0) == closes_with_sells:
            ahead = sum(
                (
                    o.remaining
                    for o, _meta in self._resting(owner, m)
                    if (o.side == OrderSide.SELL) == closes_with_sells
                    and (o.price <= limit if closes_with_sells else o.price >= limit)
                ),
                ZERO,
            )
            size -= min(abs(size), ahead) * (1 if size > 0 else -1)
        increase = max(ZERO, abs(size + q) - abs(size))
        worst_pnl = q * (m.mark_price - limit)  # value change vs mark at the limit
        worst_fee = abs(q) * limit * TAKER_FEE_RATE
        free = self.cross_equity(owner) - self.cross_requirement(owner)
        if acct.isolated.get(m.id, False):
            # The new exposure's margin comes out of cross collateral at fill time.
            moved = initial_margin(m, lev, abs(size + q) * limit) - initial_margin(
                m, lev, abs(size) * limit
            )
            moved = max(ZERO, moved) if increase > 0 else ZERO
            need = moved + worst_fee
            iso_equity = pos.isolated_margin + self._upnl(m, pos) + worst_pnl + moved
            if free < need or iso_equity < initial_margin(m, lev, abs(size + q) * m.mark_price):
                raise ClearinghouseError("insufficient margin for the order")
            return
        current = initial_margin(m, lev, abs(size) * m.mark_price)
        after = initial_margin(m, lev, abs(size + q) * m.mark_price)
        if free + worst_pnl - worst_fee < after - current:
            raise ClearinghouseError("insufficient margin for the order")

    def _check_resting_margin(
        self,
        owner: str,
        m: Market,
        order_id: str,
        buy: bool,
        size: Decimal,
        limit: Decimal,
        lev: Decimal,
        reduce_only: bool,
    ) -> None:
        """The other worst case: the order rests whole. The margin its opening part reserves,
        and any it shifts onto the account's other orders by closing the position before them,
        must fit in the free margin. (The fill check alone let a sell far above mark rest
        against almost no collateral: filled there, it would be worth the gap.)"""
        probe = Order(
            id=order_id,
            owner=owner,
            side=OrderSide.BUY if buy else OrderSide.SELL,
            order_type=OrderType.LIMIT,
            price=limit,
            amount=size,
            nonce=0,
            timestamp=0.0,
        )
        meta = OrderMeta(owner=owner, leverage=lev, reduce_only=reduce_only)
        delta = self._reserved_in(owner, m, extra=(probe, meta)) - self._reserved_in(owner, m)
        if delta > 0 and self.cross_equity(owner) - self.cross_requirement(owner) < delta:
            raise ClearinghouseError("insufficient margin for the order")

    def _reserved_in(
        self, owner: str, m: Market, extra: Optional[Tuple[Order, OrderMeta]] = None
    ) -> Decimal:
        """The margin ``owner``'s resting orders in ``m`` reserve (with ``extra`` resting)."""
        total = ZERO
        for order, meta, opening in self._opening_amounts(owner, m, extra):
            if opening > 0 and not meta.reduce_only:
                total += opening * order.price / meta.leverage
        return total

    # ------------------------------------------------------------------ fills

    def _apply_fill(self, m: Market, tr, taker_limit: Decimal) -> dict:
        price, amount = Decimal(str(tr.price)), Decimal(str(tr.amount))
        maker_meta = m.orders.get(tr.maker_order_id)
        maker = maker_meta.owner if maker_meta else None
        out = {
            "market": m.id,
            "price": str(price),
            "amount": str(amount),
            "buyer": tr.buyer,
            "seller": tr.seller,
            "maker": maker,
            "maker_order_id": tr.maker_order_id,
            "taker_order_id": tr.taker_order_id,
            "realized": {},
        }
        notional = amount * price
        for owner, q in ((tr.buyer, amount), (tr.seller, -amount)):
            fee, reward, referrer = self._fee(owner, owner == maker, notional)
            lev = (
                maker_meta.leverage
                if owner == maker and maker_meta
                else self._leverage(self.account(owner), m)
            )
            # Isolated margin is sized at the lower of the fill price and the order's limit:
            # a sell can fill above its limit, and the pre-trade check only reserved margin
            # at the limit.
            margin_price = price if owner == maker else min(price, taker_limit)
            out["realized"][owner] = str(self._trade_into(owner, m, q, price, lev, margin_price))
            acct = self.accounts[owner]
            acct.collateral -= fee
            staker = _staker_part(fee - reward)
            kept = fee - reward - staker
            if m.deployer and kept > 0 and m.deployer_fee_share > 0:
                # A deployer market: its deployer's share of what the protocol keeps.
                share = _q_amount(kept * m.deployer_fee_share)
                self.account(m.deployer).collateral += share
                kept -= share
            self.account(VAULT).collateral += kept
            if staker > 0:  # leaves the clearinghouse: its records and its holder alike
                self.holder_balance -= staker
                self.staker_fees = self.__dict__.get("staker_fees", ZERO) + staker
            if reward > 0:
                self.account(referrer).collateral += reward
            out.setdefault("fees", {})[owner] = str(fee)
        for owner in (tr.buyer, tr.seller):
            self._record_volume(owner, notional)
        m.last_trade_price = price
        return out

    # ------------------------------------------------------------------ fees

    def _day(self) -> int:
        return int(Decimal(str(self.__dict__.get("_now", ZERO))) // 86400)

    @_pinned
    def volume(self, owner: str) -> Decimal:
        """``owner``'s perps volume over the last FEE_VOLUME_DAYS days of block time."""
        first = self._day() - FEE_VOLUME_DAYS + 1
        return sum((n for day, n in self.volumes.peek(owner, ()) if day >= first), ZERO)

    def fee_rates(self, owner: str) -> Tuple[Decimal, Decimal]:
        """(taker, maker) for ``owner``'s volume, less its staking discount (a rebate is kept
        whole)."""
        volume = self.volume(owner)
        taker, maker = FEE_TIERS[0][1], FEE_TIERS[0][2]
        for floor, t, mk in FEE_TIERS:
            if volume >= floor:
                taker, maker = t, mk
        discount = self.stake_discount(owner)
        if discount > 0:
            taker = taker * (1 - discount)
            maker = maker * (1 - discount) if maker > 0 else maker
        return taker, maker

    def set_stakes(self, staked: Dict[str, Decimal]) -> None:
        """Each account's QRDX at stake for the block being processed (``stake_discount``)."""
        self.__dict__["_staked"] = staked

    def stake_discount(self, owner: str) -> Decimal:
        """Hyperliquid's staking fee discount: the fraction of its fees an account staking QRDX
        is spared (STAKE_FEE_DISCOUNTS), by its stake — its own validator principal and its
        delegations' value — as the validator set of the block's parent has it (set each block
        by the exchange, a function of the chain; never committed, like the oracle committee)."""
        staked = self.__dict__.get("_staked") or {}
        amount = staked.get(str(owner).lower(), ZERO)
        discount = ZERO
        for floor, d in STAKE_FEE_DISCOUNTS:
            if amount >= floor:
                discount = d
        return discount

    def _fee(self, owner: str, is_maker: bool, notional: Decimal) -> Tuple[Decimal, Decimal, str]:
        """(fee, referral reward, referrer) for ``owner``'s side of a fill: its tier's rate (a
        rebate is negative), less a referee's discount; the referrer's share of what is left."""
        if owner in (VAULT, PROTOCOL):
            return ZERO, ZERO, ""
        taker, maker = self.fee_rates(owner)
        fee = (notional * (maker if is_maker else taker)).quantize(
            FEE_QUANTUM, rounding=ROUND_HALF_UP
        )
        ref = self.referrals.peek(owner)
        if fee <= 0 or ref is None:
            return fee, ZERO, ""
        if ref.volume < REFERRAL_VOLUME_CAP:
            fee = (fee * (1 - REFEREE_DISCOUNT)).quantize(FEE_QUANTUM, rounding=ROUND_HALF_UP)
        reward = (fee * REFERRER_SHARE).quantize(FEE_QUANTUM, rounding=ROUND_DOWN)
        return fee, reward, ref.referrer

    def _record_volume(self, owner: str, notional: Decimal) -> None:
        if owner in (VAULT, PROTOCOL):
            return
        day = self._day()
        days = [(d, n) for d, n in self.volumes.peek(owner, ()) if d > day - FEE_VOLUME_DAYS]
        if days and days[-1][0] == day:
            days[-1] = (day, days[-1][1] + notional)
        else:
            days.append((day, notional))
        self.volumes[owner] = tuple(days)
        ref = self.referrals.peek(owner)
        if ref is not None and ref.volume < REFERRAL_VOLUME_CAP:
            self.referrals[owner] = dataclasses.replace(ref, volume=ref.volume + notional)

    @_mutator
    def register_referral_code(self, owner: str, code: str) -> None:
        """``owner`` takes ``code`` (3-16 of a-z, 0-9, _), once, if no one has it."""
        import re

        self._user(owner)
        if not re.fullmatch(r"[a-z0-9_]{3,16}", code or ""):
            raise ClearinghouseError("a referral code is 3 to 16 of a-z, 0-9 and _")
        if code in self.referral_codes:
            raise ClearinghouseError(f"the code {code} is taken")
        if any(o == owner for o in self.referral_codes.peek_values()):
            raise ClearinghouseError("an account has one referral code")
        self.referral_codes[code] = owner

    @_mutator
    @_pinned
    def join_referral(self, owner: str, code: str) -> str:
        """``owner`` joins ``code``'s referrer, once, before REFERRAL_JOIN_MAX_VOLUME of
        volume. Returns the referrer."""
        self._user(owner)
        referrer = self.referral_codes.peek(code)
        if referrer is None:
            raise ClearinghouseError(f"no referral code {code}")
        if referrer == owner:
            raise ClearinghouseError("an account does not refer itself")
        if owner in self.referrals:
            raise ClearinghouseError("the account has already joined a referrer")
        if self.volume(owner) >= REFERRAL_JOIN_MAX_VOLUME:
            raise ClearinghouseError(
                f"an account joins a referrer before {REFERRAL_JOIN_MAX_VOLUME} of volume"
            )
        self.referrals[owner] = Referral(referrer=referrer, volume=ZERO)
        return referrer

    def _trade_into(
        self, owner: str, m: Market, q: Decimal, price: Decimal, lev: Decimal, margin_price: Decimal
    ) -> Decimal:
        """Apply a signed fill of ``q`` at ``price`` to ``owner``'s position. Returns the
        realized PnL. Keeps cost basis exactly size × entry (see the module docstring)."""
        acct = self.account(owner)
        isolated = acct.isolated.get(m.id, False)
        pos = acct.positions.setdefault(m.id, Position())
        s, entry = pos.size, pos.entry_price
        realized = ZERO
        self._touched.add((owner, m.id))  # its resting orders are re-checked (_trim_touched)

        if s == 0 or (s > 0) == (q > 0):  # open / increase
            new = s + q
            exact_basis = s * entry + q * price
            pos.entry_price = _q_entry(exact_basis / new)
            pos.size = new
            acct.collateral -= exact_basis - pos.basis  # rounding residual (≈1e-18)
            if isolated:
                moved = _q_amount(
                    initial_margin(m, lev, abs(new) * margin_price)
                    - initial_margin(m, lev, abs(s) * margin_price)
                )
                acct.collateral -= moved
                pos.isolated_margin += moved
        else:  # reduce, close, or flip
            closing = min(abs(q), abs(s))
            realized = closing * (price - entry) * (1 if s > 0 else -1)
            new = s + q
            if isolated:
                pos.isolated_margin += realized
                if new == 0 or (new > 0) != (s > 0):  # fully closed (maybe flipping)
                    released = pos.isolated_margin
                else:
                    released = _q_amount(pos.isolated_margin * closing / abs(s))
                pos.isolated_margin -= released
                acct.collateral += released
            else:
                acct.collateral += realized
            if new == 0:
                pos.size, pos.entry_price = ZERO, ZERO
            elif (new > 0) == (s > 0):  # reduced, entry unchanged
                pos.size = new
            else:  # flipped through zero
                pos.size, pos.entry_price = new, _q_entry(price)
                acct.collateral -= new * price - pos.basis  # residual (0 unless price unquantized)
                if isolated:
                    moved = _q_amount(initial_margin(m, lev, abs(new) * margin_price))
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
        """One pass over the owners the liquidation index says may be under maintenance, in
        owner order — exactly what checking every owner would liquidate, in the same order. A
        liquidation can push an owner later in the order under (auto-deleveraging closes
        counterparties worse than mark), so after each one the index is brought up to date and
        newly crossed owners above it join the pass. With QRDX_VERIFY_STATE_COMMITMENTS the full
        scan runs alongside on a copy, and the two must agree."""
        reference = None
        if verifying():
            import copy

            reference = copy.deepcopy(self)
        index = self._liquidation_index()
        queue = sorted(self._liquidation_candidates(index))
        heapq.heapify(queue)
        seen: set = set()
        events: List[dict] = []
        while queue:
            owner = heapq.heappop(queue)
            if owner in seen:
                continue
            seen.add(owner)
            before = len(events)
            self._check_owner(owner, events)
            if len(events) > before:
                self._sync_liquidation_index(index)
                for later in self._liquidation_candidates(index):
                    if later > owner and later not in seen:
                        heapq.heappush(queue, later)
        if reference is not None:
            want = reference._liquidation_pass_full()
            if want != events or reference.canonical() != self.canonical():
                raise AssertionError(
                    "liquidation index: the indexed pass differs from the full scan "
                    f"({len(events)} vs {len(want)} events)"
                )
        return events

    def _liquidation_pass_full(self) -> List[dict]:
        """Every owner, in order: the definition ``_liquidation_pass`` reproduces."""
        events: List[dict] = []
        for owner in sorted(self.accounts):
            self._check_owner(owner, events)
        return events

    def _check_owner(self, owner: str, events: List[dict]) -> None:
        """The exact check: isolated positions one by one, then the cross account as a whole."""
        acct = self.accounts.peek(owner)  # a scan; _liquidate marks what it changes
        if acct is None:
            return
        for mid in sorted(
            mid
            for mid, p in acct.positions.items()
            if p.size != 0 and acct.isolated.get(mid, False)
        ):
            pos = acct.positions.get(mid)
            if (
                pos is not None
                and pos.size != 0
                and self._iso_equity(acct, mid) < self._maintenance(pos, self.markets[mid])
            ):
                events.append(self._liquidate(owner, [mid], isolated=True))
        cross = sorted(
            mid
            for mid, p in acct.positions.items()
            if p.size != 0 and not acct.isolated.get(mid, False)
        )
        if cross and self.cross_equity(owner) < self.cross_maintenance(owner):
            events.append(self._liquidate(owner, cross, isolated=False))
        elif (
            not cross
            and owner != VAULT  # (the backstop itself: nothing behind it to take over)
            and acct.assets
            and acct.collateral < 0
            and self.cross_equity(owner) < 0
        ):
            events.append(self._liquidate_debt(owner))

    def _liquidate_debt(self, owner: str) -> dict:
        """An account with no positions that owes more settlement token than its margin tokens
        are worth after their haircut: the vault takes the tokens at that value and absorbs
        what they do not cover (as it would in a backstop takeover)."""
        eq0 = self.cross_equity(owner)
        self._seize_assets(owner)
        acct = self.accounts[owner]
        if acct.collateral < 0:
            self.account(VAULT).collateral += acct.collateral
            acct.collateral = ZERO
        return {
            "type": "liquidation",
            "owner": owner,
            "markets": [],
            "mode": "cross",
            "stage": "assets",
            "equity": str(eq0),
            "maintenance": "0",
            "filled": ZERO,
            "fills": [],
        }

    # ------------------------------------------------------------------ liquidation index

    def _liquidation_index(self) -> _LiquidationIndex:
        """The index, built in full when missing (a new or unpickled clearinghouse, a changed
        maintenance rate) and otherwise brought up to date with the accounts marked since."""
        index: Optional[_LiquidationIndex] = getattr(self, "_liq", None)
        accounts = self.accounts
        if (
            index is None
            or getattr(accounts, "_index_token", None) is not index.token
            or any(index.rates.get(mid) != m.maintenance_rate for mid, m in self.markets.items())
        ):
            index = _LiquidationIndex()
            accounts.track_changes()
            accounts.take_changes()
            accounts._index_token = index.token
            index.rates = {mid: m.maintenance_rate for mid, m in self.markets.items()}
            for owner, acct in accounts.peek_items():
                index.put(owner, *self._thresholds(acct))
            self._liq = index
        else:
            self._sync_liquidation_index(index)
        return index

    def _sync_liquidation_index(self, index: _LiquidationIndex) -> None:
        for owner in self.accounts.take_changes():
            index.put(owner, *self._thresholds(self.accounts.peek(owner)))

    def _liquidation_candidates(self, index: _LiquidationIndex) -> set:
        found = set(index.always)
        for mid, m in self.markets.items():
            found.update(index.crossed(mid, m.mark_price))
        return found

    def _thresholds(self, acct: Optional[Account]) -> Tuple[List[Tuple[str, bool, Decimal]], bool]:
        """(the account's liquidation prices, whether it must be checked every pass)."""
        if acct is None:
            return [], False
        if acct.assets and (
            acct.collateral < 0 or any(p.size != 0 for p in acct.positions.values())
        ):
            return [], True  # its margin (or its debt's cover) moves with the tokens' prices
        out: List[Tuple[str, bool, Decimal]] = []
        cross: List[Tuple[str, Position]] = []
        for mid, pos in acct.positions.items():
            if pos.size == 0:
                continue
            if acct.isolated.get(mid, False):
                t = self._threshold(pos, mid, pos.isolated_margin)
                if t is None:
                    return [], True
                out.append((mid, pos.size > 0, t))
            else:
                cross.append((mid, pos))
        if len(cross) > 1:
            return [], True  # equity spans several marks: no single price
        if cross:
            mid, pos = cross[0]
            t = self._threshold(pos, mid, acct.collateral)
            if t is None:
                return [], True
            out.append((mid, pos.size > 0, t))
        return out, False

    def _threshold(self, pos: Position, mid: str, margin: Decimal) -> Optional[Decimal]:
        """The mark at which margin + size·(mark − entry) = |size|·mark·rate: a long is under
        maintenance below it, a short above it. None when there is no such price."""
        m = self.markets.get(mid)
        if m is None:
            return None
        rate = m.maintenance_rate
        if pos.size > 0:
            if rate >= 1:
                return None
            return (pos.size * pos.entry_price - margin) / (pos.size * (1 - rate))
        size = -pos.size
        return (margin + size * pos.entry_price) / (size * (1 + rate))

    def _margin_state(self, owner: str, mids: List[str], isolated: bool):
        """(equity, maintenance, any position still open) for what is being liquidated."""
        acct = self.accounts[owner]
        if isolated:
            pos = acct.positions.get(mids[0])
            if pos is None or pos.size == 0:
                return ZERO, ZERO, False
            return (
                self._iso_equity(acct, mids[0]),
                self._maintenance(pos, self.markets[mids[0]]),
                True,
            )
        still_open = any(
            acct.positions.get(mid) is not None and acct.positions[mid].size != 0 for mid in mids
        )
        return self.cross_equity(owner), self.cross_maintenance(owner), still_open

    def _liquidate(self, owner: str, mids: List[str], isolated: bool) -> dict:
        """Hyperliquid's sequence. 1: cancel the account's orders and close its positions on
        the book, never past the bankruptcy price. 2: if it is still below BACKSTOP_FRACTION of
        maintenance, the vault takes the positions over at mark with whatever margin is left.
        3: if the vault cannot cover a negative balance, auto-deleverage it."""
        eq0, mm0, _ = self._margin_state(owner, mids, isolated)
        event: Dict[str, Any] = {
            "type": "liquidation",
            "owner": owner,
            "markets": list(mids),
            "mode": "isolated" if isolated else "cross",
            "stage": "book",
            "equity": str(eq0),
            "maintenance": str(mm0),
            "filled": ZERO,
            "fills": [],
        }
        self._cancel_orders_of(owner, mids[0] if isolated else None)
        if not isolated:
            self._seize_assets(owner)
        for mid in mids:
            fills = self._close_on_book(owner, mid, isolated)
            event["fills"].extend(fills)
            event["filled"] += sum((Decimal(f["amount"]) for f in fills), ZERO)
        eq, mm, still_open = self._margin_state(owner, mids, isolated)
        if still_open and eq >= mm * BACKSTOP_FRACTION:
            return event  # healthy again, or the book may refill: next block decides
        if not still_open and eq >= 0:
            return event  # closed on the book, solvent
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
            mine = sorted(self._orders_by_owner(m).get(owner, ()))
            for oid in mine:
                if tracked(m.orders).peek(oid) is not None:
                    m.book.cancel_order(oid, caller=owner)
            self._prune_orders(m, mine)
            for tid in sorted(self._trigger_index(m)["owners"].get(owner, ())):
                del m.triggers[tid]

    def _close_on_book(self, owner: str, mid: str, isolated: bool) -> List[dict]:
        """A reduce-only IOC for the position, limited to the bankruptcy price — the price at
        which closing it, taker fee included, leaves exactly zero — so no book fill can create
        bad debt (a slice closed at that price loses at most its share of the equity). Above
        LIQUIDATION_SLICE_NOTIONAL only a slice is sent, and then the position cools down.
        Returns the fills."""
        acct = self.accounts[owner]
        pos = acct.positions.get(mid)
        if pos is None or pos.size == 0:
            return []
        m = self.markets[mid]
        amount = self._slice(pos, m)
        if amount < abs(pos.size):
            now = getattr(self, "_now", ZERO)
            if pos.close_time > 0 and now - pos.close_time < LIQUIDATION_COOLDOWN_SECONDS:
                return []  # cooling down from the last slice: only the backstop acts
            pos.close_time = now
        eq = self._iso_equity(acct, mid) if isolated else self.cross_equity(owner)
        q = pos.size
        if q > 0:  # sell, at no less than bankruptcy
            limit = ((q * m.mark_price - eq) / (q * (1 - TAKER_FEE_RATE))).quantize(
                ENTRY_QUANTUM, rounding=ROUND_CEILING
            )
            limit = max(limit, ENTRY_QUANTUM)
        else:  # buy back, at no more than bankruptcy
            a = -q
            limit = ((a * m.mark_price + eq) / (a * (1 + TAKER_FEE_RATE))).quantize(
                ENTRY_QUANTUM, rounding=ROUND_FLOOR
            )
            if limit <= 0:
                return []
        return self._protocol_ioc(owner, m, "liq", q > 0, amount, limit)

    @staticmethod
    def _slice(pos: Position, m: Market) -> Decimal:
        """How much of a position one protocol close sends to the book: all of it, or a slice
        of a large one."""
        size = abs(pos.size)
        if size * m.mark_price <= LIQUIDATION_SLICE_NOTIONAL:
            return size
        return (size * LIQUIDATION_SLICE_FRACTION).quantize(AMOUNT_QUANTUM, rounding=ROUND_FLOOR)

    def _protocol_ioc(
        self, owner: str, m: Market, tag: str, sell: bool, amount: Decimal, limit: Decimal
    ) -> List[dict]:
        """A reduce-only IOC the protocol sends for ``owner``: what fills, at ``limit`` or
        better, is applied; the rest is cancelled. Returns the fills."""
        acct = self.accounts[owner]
        order = Order(
            id=f"{tag}:{m.id}:{owner}",
            owner=owner,
            side=OrderSide.SELL if sell else OrderSide.BUY,
            order_type=OrderType.LIMIT,
            price=limit,
            amount=amount,
            nonce=0,
            timestamp=0.0,
        )
        try:
            trades = self._match(m, order, protocol=True)
        except ValueError:
            return []  # e.g. dust below the book's minimum size: backstop takes it
        m.orders[order.id] = OrderMeta(
            owner=owner, leverage=self._leverage(acct, m), reduce_only=True
        )
        fills = [self._apply_fill(m, tr, taker_limit=limit) for tr in trades]
        if order.is_active:
            m.book.cancel_order(order.id, caller=owner)
        self._prune_orders(m, self._match_ids(m, order.id, trades))
        return fills

    def _vault_unwind(self, now: Decimal) -> List[dict]:
        """The vault closes what it took over, a slice at a time: per market, once every
        VAULT_UNWIND_SECONDS of block time, a reduce-only IOC at most VAULT_UNWIND_SLIPPAGE
        through mark. It used to hold the positions until it fell under maintenance itself."""
        vault = self.accounts.peek(VAULT)
        if vault is None:
            return []
        events: List[dict] = []
        for mid in sorted(mid for mid, p in vault.positions.items() if p.size != 0):
            m = self.markets[mid]
            pos = vault.positions[mid]
            if m.mark_price <= 0 or now - pos.close_time < VAULT_UNWIND_SECONDS:
                continue
            self.accounts[VAULT].positions[mid].close_time = now  # this account changes
            sell = pos.size > 0
            if sell:
                limit = (m.mark_price * (1 - VAULT_UNWIND_SLIPPAGE)).quantize(
                    ENTRY_QUANTUM, rounding=ROUND_CEILING
                )
            else:
                limit = (m.mark_price * (1 + VAULT_UNWIND_SLIPPAGE)).quantize(
                    ENTRY_QUANTUM, rounding=ROUND_FLOOR
                )
            fills = self._protocol_ioc(VAULT, m, "unwind", sell, self._slice(pos, m), limit)
            if fills:
                events.append(
                    {
                        "type": "vault_unwind",
                        "market": mid,
                        "filled": sum((Decimal(f["amount"]) for f in fills), ZERO),
                        "fills": fills,
                    }
                )
        return events

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
            # The unwind starts a full interval later: the book just failed to absorb this.
            taken = vault.positions.get(mid)
            if taken is not None:  # (none if it netted the vault's own position to zero)
                taken.close_time = getattr(self, "_now", ZERO)
        if not isolated:
            vault.collateral += acct.collateral
            acct.collateral = ZERO

    def _adl(self, owner: str, mids: List[str], deficit: Decimal) -> None:
        """Auto-deleveraging: close the bankrupt positions against the most profitable, most
        leveraged opposite positions at prices that return the account to zero. The deficit is
        split across the positions by notional; the counterparties give up that much of their
        unrealized profit."""
        acct = self.accounts[owner]
        live = [
            (mid, acct.positions[mid].size)
            for mid in mids
            if mid in acct.positions and acct.positions[mid].size != 0
        ]
        weights = [abs(q) * self.markets[mid].mark_price for mid, q in live]
        total = sum(weights, ZERO)
        left_deficit = deficit
        for i, (mid, q) in enumerate(live):
            m = self.markets[mid]
            share = left_deficit if i == len(live) - 1 else _q_amount(deficit * weights[i] / total)
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
                self._trade_into(
                    other, m, sign * take, price, self._leverage(self.accounts[other], m), price
                )
                left -= take

    def _adl_queue(self, m: Market, sign: int, exclude: str) -> List[str]:
        """Positions on side ``sign``, ranked as Hyperliquid does: (mark / entry for longs,
        entry / mark for shorts) × notional / account value, highest first; accounts with no
        positive value last; ties by owner."""
        ranked = []
        for other, a in self.accounts.peek_items():
            if other == exclude:
                continue
            p = a.positions.get(m.id)
            if p is None or p.size == 0 or (p.size > 0) != (sign > 0):
                continue
            value = (
                self._iso_equity(a, m.id)
                if a.isolated.get(m.id, False)
                else self.cross_equity(other)
            )
            if value <= 0 or p.entry_price <= 0:
                score = Decimal(-1)
            else:
                pnl = m.mark_price / p.entry_price if p.size > 0 else p.entry_price / m.mark_price
                score = pnl * abs(p.size) * m.mark_price / value
            ranked.append((-score, other))
        ranked.sort()
        return [o for _, o in ranked]

    # ------------------------------------------------------------------ invariants

    @_pinned
    def net_size(self, market_id: str) -> Decimal:
        return sum(
            (
                a.positions[market_id].size
                for a in self.accounts.peek_values()
                if market_id in a.positions
            ),
            ZERO,
        )

    @_pinned
    def collateral_total(self) -> Decimal:
        total = ZERO
        for a in self.accounts.peek_values():
            total += a.collateral + sum((p.isolated_margin for p in a.positions.values()), ZERO)
        return total

    @_pinned
    def identity_gap(self) -> Decimal:
        """holder − (Σ collateral − Σ size × entry). Exactly zero while the books are sound."""
        basis = sum(
            (p.basis for a in self.accounts.peek_values() for p in a.positions.values()), ZERO
        )
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
                orders.append(
                    [
                        oid,
                        o.owner,
                        o.side.value,
                        d(o.price),
                        d(o.amount),
                        d(o.filled),
                        d(meta.leverage),
                        meta.reduce_only,
                    ]
                )
            markets[mid] = {
                **_market_header(m),
                "orders": orders,
                # time priority within each level, stop orders, nonces, last trade
                "book": m.book.state_digest().hex(),
            }
            if len(m.triggers):  # absent while there are none (a root unchanged till then)
                markets[mid]["triggers"] = {
                    tid: _encode_trigger(tid, t)
                    for tid, t in sorted(tracked(m.triggers).peek_items())
                }
        accounts = {}
        for owner in sorted(self.accounts):
            a = self.accounts[owner]
            accounts[owner] = {
                "collateral": d(a.collateral),
                "positions": {mid: p.encode() for mid, p in sorted(a.positions.items())},
                "leverage": {mid: d(v) for mid, v in sorted(a.leverage.items())},
                "isolated": dict(sorted(a.isolated.items())),
                **({"assets": {t: d(v) for t, v in sorted(a.assets.items())}} if a.assets else {}),
            }
        vault = {
            "shares": {o: d(v) for o, v in sorted(self.vault_shares.items())},
            "total_shares": d(self.vault_total_shares),
            "unlock": {o: d(t) for o, t in sorted(self.vault_unlock.items())},
        }
        out = {
            "markets": markets,
            "accounts": accounts,
            "vault": vault,
            "holder": d(self.holder_balance),
        }
        if self.trigger_seq:
            out["trigger_seq"] = self.trigger_seq
        if len(self.user_vaults):
            out["user_vaults"] = {
                a: _encode_user_vault(a, v) for a, v in sorted(self.user_vaults.peek_items())
            }
            out["vault_holdings"] = {
                k: _encode_holding(k, h) for k, h in sorted(self.vault_holdings.peek_items())
            }
        if len(self.volumes):
            out["volumes"] = {o: _encode_volume(o, v) for o, v in sorted(self.volumes.peek_items())}
        if len(self.asset_holdings) or len(self.asset_unwind_time):
            out["asset_holdings"] = {t: str(v) for t, v in sorted(self.asset_holdings.peek_items())}
            out["asset_unwind_time"] = {
                t: str(v) for t, v in sorted(self.asset_unwind_time.peek_items())
            }
        if len(self.referral_codes):
            out["referral_codes"] = dict(sorted(self.referral_codes.peek_items()))
            out["referrals"] = {
                o: _encode_referral(o, r) for o, r in sorted(self.referrals.peek_items())
            }
        return out

    def state_hash(self) -> bytes:
        blob = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"))
        return hashlib.blake2b(blob.encode(), digest_size=32).digest()

    def commitment(self) -> bytes:
        """The incremental commitment (``incremental_state_root``): every market's own fields,
        its order metadata and its book; every account; the vault's shares and unlocks; the
        holder mirror. Costs the markets plus what changed, not every account."""
        sec = Section("clearinghouse")
        for mid in sorted(self.markets):
            m = self.markets[mid]
            sec.value([mid, _market_header(m)])
            sec.raw(tracked(m.orders).commitment())
            sec.raw(m.book.cached_digest())
            if len(m.triggers):  # absent while there are none (a root unchanged till then)
                sec.raw(tracked(m.triggers).commitment())
        sec.raw(self.accounts.commitment())
        sec.raw(self.vault_shares.commitment())
        sec.raw(self.vault_unlock.commitment())
        sec.value([str(self.vault_total_shares), str(self.holder_balance)])
        if self.trigger_seq:
            sec.value(["trigger_seq", self.trigger_seq])
        if len(self.user_vaults):  # (nothing until the first user vault)
            sec.raw(self.user_vaults.commitment())
            sec.raw(self.vault_holdings.commitment())
        if len(self.volumes):  # (nothing until the first fill)
            sec.raw(self.volumes.commitment())
        if len(self.asset_holdings) or len(self.asset_unwind_time):  # (none until first used)
            sec.raw(self.asset_holdings.commitment())
            sec.raw(self.asset_unwind_time.commitment())
        if len(self.referral_codes):  # (nothing until the first referral code)
            sec.raw(self.referral_codes.commitment())
            sec.raw(self.referrals.commitment())
        return sec.digest()

    def verify_commitment(self) -> None:
        """Check every incremental part against a from-scratch recomputation."""
        for m in self.markets.values():
            tracked(m.orders).verify()
            tracked(m.triggers).verify()
            m.book.verify_digest()
        self.accounts.verify()
        self.vault_shares.verify()
        self.vault_unlock.verify()
        self.user_vaults.verify()
        self.vault_holdings.verify()
        self.volumes.verify()
        self.asset_holdings.verify()
        self.asset_unwind_time.verify()
        self.referral_codes.verify()
        self.referrals.verify()
