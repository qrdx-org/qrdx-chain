"""
Perpetuals: markets and their listing, tickers, token perps, collateral, vaults, leverage and
margin, perp orders and triggers, and the spot readings token perps are priced by.

These are ExchangeStateManager's methods, written as functions of the manager (``self``) and
bound to it under the same names in qrdx/exchange/state_manager.py. They are here only to keep
that file to a size one can read: read them as the class's.
"""

from __future__ import annotations

import hashlib
import re
from decimal import ROUND_DOWN, Decimal
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

from .. import undo
from ..clearinghouse import Clearinghouse, ClearinghouseError
from ..commitment import tracked
from ..governance import GovernanceError
from ..orderbook import (
    _pinned,
)
from ..transactions import (
    EXCHANGE_GAS_COSTS,
    EXCHANGE_GAS_PER_MAKER,
    ExchangeOpType,
    ExchangeTransaction,
    match_budget,
)
from .common import (
    SPOT_FEE_QUANTUM,
    ZERO,
    ExchangeExecResult,
    _attached_legs,
    _book_nonce,
    _flag,
    logger,
)

if TYPE_CHECKING:
    from ..state_manager import ExchangeStateManager


def _op_create_market(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """List a token perp (docs/HYPERLIQUID_PARITY.md 13): a perp on an on-chain token, named
    by its address (``token``; "QRDX" for QRDX itself), priced off the token's own spot
    market and nothing else — no vote, no key sets its price. Anyone may list one, once per
    token, while the token has a spot market to read: a path of pools to the settlement
    asset with SPOT_ORACLE_TWAP_SECONDS of price history and SPOT_ORACLE_MIN_DEPTH of depth
    (``spot_reading``). A market priced by the validators is listed at genesis
    (PERP_GENESIS_MARKETS) or by governance (``list_market``), never here.

    ``max_leverage`` is at most (and defaults to) PERP_SPOT_MAX_LEVERAGE; ``sz_decimals``
    sets the order grid. With the fee gate on, the lister burns PERP_MARKET_LISTING_FEE QRDX:
    a market costs every node work in every block. ``liquidity`` (at least
    PERP_MARKET_MIN_LIQUIDITY of the lister's perps collateral) seeds the market's liquidity
    vault, which the protocol quotes on its book; ``liquidity_profit_share`` (default 10 %)
    is the lister's cut of others' gains in it. The lister's shares are locked for
    PERP_MARKET_LIQUIDITY_LOCKUP_SECONDS. A refusal is a non-critical failure.
    """
    from ... import constants
    from ..clearinghouse import USER_VAULT_DEFAULT_PROFIT_SHARE, market_maker_address

    p = tx.params
    try:
        liquidity = Decimal(str(p.get("liquidity", "0")))
        if not liquidity.is_finite() or liquidity < 0:
            raise ValueError("liquidity must be a positive amount")
        token = self._token_perp_asset(str(p["token"]))
        cap = Decimal(int(constants.PERP_SPOT_MAX_LEVERAGE))
        max_leverage = Decimal(str(p.get("max_leverage", cap)))
        if not max_leverage.is_finite() or max_leverage > cap:
            raise ValueError(f"a token perp's maximum leverage is at most {cap}")
        sz = p.get("sz_decimals", constants.PERP_DEFAULT_SZ_DECIMALS)
        if isinstance(sz, bool) or not isinstance(sz, int):
            raise ValueError("sz_decimals is a whole number")
        mid = Clearinghouse.market_id(token, constants.PERP_QUOTE)
        if mid in self.clearinghouse.markets:
            raise ValueError(f"{token} already has its perp, {mid}")
        now = Decimal(str(self._block_clock()))
        price, depth, _path = self.spot_reading(token, now)
        floor = Decimal(int(constants.SPOT_ORACLE_MIN_DEPTH))
        if price is None or depth < floor:
            raise ValueError(
                f"{token} has no spot market to price a perp: it needs pools to the "
                f"settlement asset with {constants.SPOT_ORACLE_TWAP_SECONDS} seconds of "
                f"price history and {floor} of depth (within "
                f"{Decimal(int(constants.SPOT_ORACLE_DEPTH_BAND_BPS)) / 100}% of the price); "
                f"it has {depth}"
            )
    except (KeyError, ValueError, ArithmeticError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    if liquidity < constants.PERP_MARKET_MIN_LIQUIDITY:
        return ExchangeExecResult(
            success=False,
            error=f"a market is listed with at least {constants.PERP_MARKET_MIN_LIQUIDITY} "
            "of liquidity (perps collateral) for its book",
        )
    fee = Decimal(constants.PERP_MARKET_LISTING_FEE) if self.enforce_fees else ZERO
    if fee > 0:
        avail = self.available_balance(tx.sender)  # less this transaction's gas reservation
        if avail is None or avail < fee:
            return ExchangeExecResult(
                success=False,
                error=f"insufficient QRDX for the market listing fee: need {fee}, "
                f"available {avail}",
            )
    try:
        market = self.clearinghouse.create_market(
            token,
            constants.PERP_QUOTE,
            max_leverage=max_leverage,
            sz_decimals=sz,
            spot_token=token,
        )
    except (ClearinghouseError, ValueError, ArithmeticError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    data: Dict[str, Any] = {"market_id": market.id, "token": token}
    if liquidity > 0:
        vault = market_maker_address(market.id)
        try:
            self.clearinghouse.create_user_vault(
                tx.sender,
                vault,
                f"{market.id} liquidity",
                liquidity,
                Decimal(str(p.get("liquidity_profit_share", USER_VAULT_DEFAULT_PROFIT_SHARE))),
                self._block_clock(),
                managed=market.id,
                lockup=constants.PERP_MARKET_LIQUIDITY_LOCKUP_SECONDS,
            )
        except (ClearinghouseError, ValueError, ArithmeticError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        data["liquidity_vault"] = vault
    if fee > 0:
        self._record_balance_delta(tx.sender, -fee)  # burned
        data["listing_fee"] = str(fee)
    return ExchangeExecResult(
        success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.CREATE_MARKET], data=data
    )


def _delist_market(
    self: ExchangeStateManager, market_id: str, price: Optional[str]
) -> Dict[str, Any]:
    """A passed ``delist_market``: the clearinghouse settles the market, and its TWAPs end.
    A refusal (no such market, already delisted, no price) fails the execution, which may
    be retried within the proposal's execution window."""
    try:
        settled = self.clearinghouse.delist(
            market_id, Decimal(price) if price is not None else None
        )
    except ClearinghouseError as e:
        raise GovernanceError(str(e)) from None
    for tid, t in sorted(self.trading.twaps.peek_items()):
        if t.perp and t.market == market_id:
            self._cancel_twap(t.owner, tid)
    return settled


#  Perps clearinghouse (docs/PERPS_CLEARINGHOUSE.md)
def perps_holder_address() -> str:
    """The single holder of all perp collateral. Real QRDX moves only between a trader and
    this holder (deposit / withdraw); trading moves value between internal records."""
    return "0xPERP" + hashlib.blake2b(b"perps:clearinghouse", digest_size=18).hexdigest()


def _op_retired_perp(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    return ExchangeExecResult(
        success=False,
        error=(
            f"{tx.op_type.name} is retired: it traded against nobody, so it minted and "
            f"burned QRDX. Perps trade on the order book — PERP_DEPOSIT, then PERP_ORDER."
        ),
    )


def perp_collateral_token() -> str:
    """What perps settle in: a QRC-20 token address (production: the bridged USD
    stablecoin), "QRDX" for native QRDX, or "" when none is configured."""
    from ... import constants

    return constants.PERP_COLLATERAL_TOKEN


def _op_portfolio_asset(
    self: ExchangeStateManager, tx: ExchangeTransaction, deposit: bool
) -> ExchangeExecResult:
    """PERP_DEPOSIT / PERP_WITHDRAW of a portfolio-margin token (``asset``): it moves between
    the sender and the perps holder on the ledger, and is held as margin in between."""
    asset = self.canonical_asset(tx.params["asset"])
    holder = self.perps_holder_address()
    op = ExchangeOpType.PERP_DEPOSIT if deposit else ExchangeOpType.PERP_WITHDRAW
    try:
        amount = Decimal(str(tx.params["amount"]))
        if deposit:
            if self.clearinghouse.asset_price(asset) <= 0:
                raise ValueError(f"{asset} is not accepted as margin")
            avail = self.available_token_balance(tx.sender, asset)
            if avail is None or avail < amount:
                raise ValueError(f"insufficient {asset}: need {amount}, available {avail}")
            held = self.clearinghouse.deposit_asset(tx.sender, asset, amount)
            self._settle_token_move(tx.sender, holder, asset, amount)
        else:
            self.clearinghouse.withdraw_asset(tx.sender, asset, amount)
            self._settle_token_move(holder, tx.sender, asset, amount)
            acct = self.clearinghouse.accounts.peek(tx.sender)
            held = acct.assets.get(asset.lower(), ZERO) if acct is not None else ZERO
    except (ClearinghouseError, ValueError, ArithmeticError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    return ExchangeExecResult(
        success=True, gas_used=EXCHANGE_GAS_COSTS[op], data={"asset": asset, "held": str(held)}
    )


@_pinned
def unwind_vault_assets(self: ExchangeStateManager, now: Decimal) -> List[Dict[str, Any]]:
    """The block's tick for portfolio margin: the backstop vault sells a slice of each margin
    token it took over (``Clearinghouse.unwind_assets_due``) for the settlement token
    through the best venue, out of the perps holder (covered: the clearinghouse records
    it), within its bound under the oracle — or waits for the next interval."""
    token_out = self.perp_collateral_token()
    due = self.clearinghouse.unwind_assets_due(now) if token_out else []
    events: List[Dict[str, Any]] = []
    holder = self.perps_holder_address()
    for token, part, floor in due:
        route = self.router.best_route(
            token, self.canonical_asset(token_out), part, holder, max_makers=20
        )
        if route is None or route.amount_out < floor * route.amount_in / part:
            self.clearinghouse.mark_asset_unwind(token, now)
            continue
        try:
            with undo.atomic():
                _visited, fills = self._swap_hop(holder, route, payer=holder)
                self.clearinghouse.record_asset_sale(token, route.amount_in, route.amount_out, now)
        except Exception as e:  # noqa: BLE001 — deterministic on every node; never fails the block
            logger.warning("vault asset sale of %s failed: %s", token, e)
            self.clearinghouse.mark_asset_unwind(token, now)
            continue
        events.append(
            {
                "type": "vault_asset_sale",
                "asset": token,
                "sold": str(route.amount_in),
                "proceeds": str(route.amount_out),
                "fills": fills,
            }
        )
    return events


def _op_perp_deposit(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    if tx.params.get("asset"):
        return self._op_portfolio_asset(tx, deposit=True)
    token = self.perp_collateral_token()
    if not token:
        return ExchangeExecResult(success=False, error="perps have no collateral token configured")
    amount = Decimal(str(tx.params["amount"]))
    native = token.upper() == "QRDX"
    if native:
        avail = self.available_balance(tx.sender)
        if avail is not None and avail < amount and self.enforce_collateral:
            return ExchangeExecResult(
                success=False, error=f"insufficient balance: need {amount}, available {avail}"
            )
    else:
        # Always enforced: the token flush is not gated, so admitting an unaffordable
        # deposit would apply the holder's credit while the sender's debit could not land.
        avail = self.available_token_balance(tx.sender, token)
        if avail is None or avail < amount:
            return ExchangeExecResult(
                success=False,
                error=f"insufficient collateral token balance: need {amount}, available {avail}",
            )
    try:
        amount = self.clearinghouse.deposit(tx.sender, amount)
    except ClearinghouseError as e:
        return ExchangeExecResult(success=False, error=str(e))
    if native:
        self._record_balance_delta(tx.sender, -amount)
        self._record_balance_delta(self.perps_holder_address(), amount)
    else:
        self._settle_token_move(tx.sender, self.perps_holder_address(), token, amount)
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_DEPOSIT],
        data={"collateral": str(self.clearinghouse.accounts[tx.sender].collateral)},
    )


def _op_perp_withdraw(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    if tx.params.get("asset"):
        return self._op_portfolio_asset(tx, deposit=False)
    token = self.perp_collateral_token()
    if not token:
        return ExchangeExecResult(success=False, error="perps have no collateral token configured")
    try:
        amount = self.clearinghouse.withdraw(tx.sender, Decimal(str(tx.params["amount"])))
    except ClearinghouseError as e:
        return ExchangeExecResult(success=False, error=str(e))
    if token.upper() == "QRDX":
        self._record_balance_delta(self.perps_holder_address(), -amount)
        self._record_balance_delta(tx.sender, amount)
    else:
        self._settle_token_move(self.perps_holder_address(), tx.sender, token, amount)
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_WITHDRAW],
        data={"collateral": str(self.clearinghouse.accounts[tx.sender].collateral)},
    )


def _op_vault_create(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """A user vault (``Clearinghouse.create_user_vault``): ``amount`` of the leader's perp
    collateral to start, ``profit_share`` of depositors' gains, ``name``. The leader signs
    its trades as ``signer`` with the vault as ``sender``."""
    from ..clearinghouse import USER_VAULT_DEFAULT_PROFIT_SHARE, user_vault_address
    from ..trading import NAME_MAX

    p = tx.params
    vault = user_vault_address(tx.sender, tx.tx_hash())
    try:
        if not self._signed_by_account(tx):
            raise ValueError("only the leader itself creates a vault")
        name = str(p.get("name", ""))
        if len(name) > NAME_MAX:
            raise ValueError(f"a name is at most {NAME_MAX} characters")
        shares = self.clearinghouse.create_user_vault(
            tx.sender,
            vault,
            name,
            Decimal(str(p["amount"])),
            Decimal(str(p.get("profit_share", USER_VAULT_DEFAULT_PROFIT_SHARE))),
            self._block_clock(),
        )
    except (ClearinghouseError, ValueError, ArithmeticError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.VAULT_CREATE],
        data={"vault": vault, "shares": str(shares)},
    )


def _op_vault_deposit(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Perp collateral → backstop vault shares at NAV — or, with ``vault``, a user vault's.
    Internal to the clearinghouse: no real balance moves (every vault's collateral is
    inside the perps holder too)."""
    from ... import constants

    if tx.params.get("vault"):
        try:
            shares = self.clearinghouse.user_vault_deposit(
                tx.sender,
                str(tx.params["vault"]),
                Decimal(str(tx.params["amount"])),
                self._block_clock(),
            )
        except (ClearinghouseError, ValueError, ArithmeticError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.VAULT_DEPOSIT],
            data={"vault": tx.params["vault"], "shares": str(shares)},
        )
    seeder = tx.sender.lower() in {a.lower() for a in constants.PERP_VAULT_SEEDERS}
    try:
        shares = self.clearinghouse.vault_deposit(
            tx.sender,
            Decimal(str(tx.params["amount"])),
            self._block_clock(),
            constants.PERP_VAULT_LOCKUP_SECONDS,
            protocol=seeder,
        )
    except (ClearinghouseError, ValueError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.VAULT_DEPOSIT],
        data={"shares": str(shares), "protocol_owned": seeder},
    )


def _op_vault_withdraw(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    if tx.params.get("vault"):
        try:
            paid, fee = self.clearinghouse.user_vault_withdraw(
                tx.sender,
                str(tx.params["vault"]),
                Decimal(str(tx.params["shares"])),
                self._block_clock(),
            )
        except (ClearinghouseError, ValueError, ArithmeticError) as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.VAULT_WITHDRAW],
            data={"vault": tx.params["vault"], "value": str(paid), "profit_share": str(fee)},
        )
    try:
        value = self.clearinghouse.vault_withdraw(
            tx.sender, Decimal(str(tx.params["shares"])), self._block_clock()
        )
    except (ClearinghouseError, ValueError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.VAULT_WITHDRAW],
        data={"value": str(value)},
    )


def _op_perp_set_leverage(
    self: ExchangeStateManager, tx: ExchangeTransaction
) -> ExchangeExecResult:
    p = tx.params
    mode = str(p.get("mode", "cross")).lower()
    if mode not in ("cross", "isolated"):
        return ExchangeExecResult(success=False, error=f"unknown margin mode {mode!r}")
    try:
        moved = self.clearinghouse.set_leverage(
            tx.sender, str(p["market_id"]), Decimal(str(p["leverage"])), mode == "isolated"
        )
    except (ClearinghouseError, ArithmeticError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_SET_LEVERAGE],
        data={"margin_moved": str(moved)} if moved else {},
    )


def _trade_leverage(
    self: ExchangeStateManager, owner: str, market_id: str, p: Dict[str, Any]
) -> None:
    """An order's, trigger's or TWAP's own ``leverage`` (and ``margin_mode``): the market's
    setting for the account becomes it, as PERP_SET_LEVERAGE would make it, inside the
    operation — so it is all or nothing with the order. Absent: the setting stays."""
    if p.get("leverage") is None and p.get("margin_mode") is None:
        return
    from ..clearinghouse import DEFAULT_LEVERAGE

    ch = self.clearinghouse
    m = ch.market(market_id)
    acct = ch.accounts.peek(owner)
    mode = p.get("margin_mode")
    if mode is None:
        isolated = Clearinghouse.contained(m) or (
            acct is not None and acct.isolated.get(market_id, False)
        )
    else:
        mode = str(mode).lower()
        if mode not in ("cross", "isolated"):
            raise ValueError(f"unknown margin mode {mode!r}")
        isolated = mode == "isolated"
    raw = p.get("leverage")
    if raw is None:
        leverage = (
            ch._leverage(acct, m) if acct is not None else min(DEFAULT_LEVERAGE, m.max_leverage)
        )
    else:
        if isinstance(raw, bool):
            raise ValueError("leverage is a number")
        leverage = Decimal(str(raw))
    ch.set_leverage(owner, market_id, leverage, isolated)


# ── tickers (docs/HYPERLIQUID_PARITY.md 11, Hyperliquid's HIP-1 deploy auction) ──
def reserved_tickers() -> Set[str]:
    """Tickers no one buys: the native asset's, the perps quote's, the genesis perp markets'
    (a token named BTC would pass for the BTC the validators price), and every bridged
    asset's — bound to the bridge's own token when it is created (``_mint_deposit``)."""
    from ... import constants

    out = {"QRDX", str(constants.PERP_QUOTE).upper()}
    for entry in constants.PERP_GENESIS_MARKETS:
        out.add(str(entry).split(":", 1)[0].upper())
    for entry in constants.BRIDGE_ASSETS:
        out.add(str(entry).split(":", 1)[0].upper())
    return out


def ticker_price(self: ExchangeStateManager, now: Optional[Decimal] = None) -> Decimal:
    """The ticker auction's price at block time ``now``: the opening price until the first
    sale; then twice the last sale's price, falling linearly to the floor over
    TICKER_AUCTION_SECONDS after it."""
    from ... import constants

    now = Decimal(str(self._block_clock() if now is None else now))
    floor = Decimal(constants.TICKER_MIN_PRICE)
    last = self.trading.ticker_auction.peek("last")
    if last is None:
        return max(Decimal(constants.TICKER_OPENING_PRICE), floor)
    price, at = last
    start = max(price * 2, floor)
    span = Decimal(int(constants.TICKER_AUCTION_SECONDS))
    left = max(ZERO, span - max(ZERO, now - at)) / span
    return (floor + (start - floor) * left).quantize(Decimal("1e-18"), rounding=ROUND_DOWN)


def ticker_of(self: ExchangeStateManager, token: str) -> Optional[str]:
    """The ticker a token holds, if any."""
    token = str(token).lower()
    for ticker, address in self.trading.tickers.peek_items():
        if address == token:
            return ticker
    return None


def _op_ticker_claim(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """A token's creator buys its symbol, upper-cased, as the token's ticker — one token per
    ticker, for good — at the ticker auction's price, burned. ``max_price``: the most the
    sender pays (the price moves with block time)."""
    from ...crypto.account_id import same_account

    p = tx.params
    now = Decimal(str(self._block_clock()))
    try:
        t = self.tokens.get(str(p["token_address"]))
        if t is None:
            raise ValueError(f"no token {p['token_address']}")
        if not same_account(t.creator, tx.sender):
            raise ValueError("only the token's creator claims its ticker")
        ticker = t.symbol.upper()
        if not re.fullmatch(r"[A-Z0-9]{1,12}", ticker):
            raise ValueError("a ticker is 1 to 12 letters and digits: this symbol is not one")
        if ticker in self.reserved_tickers():
            raise ValueError(f"{ticker} is reserved")
        if self.trading.tickers.peek(ticker) is not None:
            raise ValueError(f"the ticker {ticker} is taken")
        if self.ticker_of(t.address) is not None:
            raise ValueError(f"{t.address} already holds {self.ticker_of(t.address)}")
        price = self.ticker_price(now)
        if p.get("max_price") is not None:
            cap = Decimal(str(p["max_price"]))
            if not cap.is_finite() or price > cap:
                raise ValueError(f"the ticker auction is at {price}, above max_price {cap}")
        avail = self.available_balance(tx.sender)
        if price > 0 and (avail is None or avail < price):
            raise ValueError(f"a ticker costs {price} QRDX now; available {avail}")
    except (ValueError, ArithmeticError, KeyError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    if price > 0:
        self._record_balance_delta(tx.sender, -price)  # burned
    self.trading.tickers[ticker] = t.address
    self.trading.ticker_auction["last"] = (price, now)
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TICKER_CLAIM],
        data={"ticker": ticker, "token_address": t.address, "price": str(price)},
    )


def _list_market(self: ExchangeStateManager, listing: Dict[str, Any]) -> Dict[str, Any]:
    """A passed ``list_market``: a market the validators price (an off-chain asset, by its
    symbol), with the settings the proposal named. A refusal (the market exists, a setting
    out of bounds) fails the execution."""
    from ... import constants

    try:
        m = self.clearinghouse.create_market(
            str(listing["base_token"]),
            constants.PERP_QUOTE,
            max_leverage=Decimal(str(listing.get("max_leverage", "20"))),
            sz_decimals=int(listing.get("sz_decimals", constants.PERP_DEFAULT_SZ_DECIMALS)),
        )
    except (ClearinghouseError, ValueError, ArithmeticError) as e:
        raise GovernanceError(str(e)) from None
    return {"market_id": m.id}


@_pinned
def create_genesis_markets(self: ExchangeStateManager) -> List[str]:
    """The markets every network starts with (PERP_GENESIS_MARKETS), priced by the
    validators: created by the first block every path processes, so a rebuild from genesis
    creates them where the network did. A market already there is left as it is (a market is
    never removed — a delisted one stays settled). Returns those created."""
    from ... import chain_spec, constants

    created = []
    for entry in constants.PERP_GENESIS_MARKETS:
        base, leverage, sz = chain_spec.parse_genesis_market(entry)
        if Clearinghouse.market_id(base, constants.PERP_QUOTE) in self.clearinghouse.markets:
            continue
        m = self.clearinghouse.create_market(
            base, constants.PERP_QUOTE, max_leverage=Decimal(leverage), sz_decimals=sz
        )
        created.append(m.id)
    return created


# ── token perps (docs/HYPERLIQUID_PARITY.md 13) ──
def _token_perp_asset(self: ExchangeStateManager, raw: str) -> str:
    """The on-chain asset ``raw`` names, as spot pools name it: a native token's address
    (canonical), or "QRDX" — by address only, never by symbol, and never the settlement
    asset itself (it has no price in itself)."""
    if raw.strip().upper() == "QRDX":
        asset = "QRDX"
    else:
        t = self.tokens.get(raw.strip())
        if t is None:
            raise ValueError(f"no on-chain token at {raw}: a token perp names its token by address")
        asset = t.address
    if asset == self._settlement_asset():
        raise ValueError("perps settle in this asset: it has no price in itself")
    return asset


def _settlement_asset(self: ExchangeStateManager) -> str:
    """The perps settlement asset as spot pools name it ("QRDX", or a token address)."""
    token = self.perp_collateral_token()
    return "QRDX" if token.upper() == "QRDX" else self.canonical_asset(token)


def _spot_paths(self: ExchangeStateManager, start: str) -> List[Tuple[str, ...]]:
    """Every path of pools from ``start`` to the settlement asset: a pool between the two,
    or two through QRDX (QRDX's pools are where liquidity gathers). Sorted."""
    settlement = self._settlement_asset()
    pm = self.pool_manager
    paths: List[Tuple[str, ...]] = [
        (pool.state.id,) for pool in pm.get_pools_for_pair(start, settlement)
    ]
    if "QRDX" not in (start, settlement):
        for a in pm.get_pools_for_pair(start, "QRDX"):
            for b in pm.get_pools_for_pair("QRDX", settlement):
                paths.append((a.state.id, b.state.id))
    return sorted(paths)


def _path_reading(
    self: ExchangeStateManager, start: str, path: Tuple[str, ...], now: Decimal
) -> Tuple[Optional[Decimal], Decimal]:
    """(price, depth) along ``path`` from ``start``, in the settlement asset: the price the
    product of each pool's TWAP over SPOT_ORACLE_TWAP_SECONDS (None if a pool has not that
    much history, or is paused), the depth the least of the pools' — each pool's the smaller
    of what moving its price SPOT_ORACLE_DEPTH_BAND_BPS up or down takes (``band_depth``),
    valued onward at the TWAPs."""
    from ... import constants

    window, at = int(constants.SPOT_ORACLE_TWAP_SECONDS), int(now)
    band = Decimal(int(constants.SPOT_ORACLE_DEPTH_BAND_BPS)) / 10_000
    current, prices, depths = start, [], []
    for pid in path:
        pool = self.pool_manager.get_pool(pid)
        if (
            pool is None
            or pool.is_paused
            or current
            not in (
                pool.state.token0,
                pool.state.token1,
            )
        ):
            return None, ZERO
        st = pool.state
        forward = st.token0 == current
        twap = pool.twap_price(window, at)
        if not twap or twap <= 0:
            return None, ZERO
        up1, down0 = pool.band_depth(band)
        depth1 = min(up1, down0 * twap)  # in token1
        prices.append(twap if forward else 1 / twap)
        depths.append(depth1 if forward else depth1 / twap)  # in the token it leaves by
        current = st.token1 if forward else st.token0
    if current != self._settlement_asset() or not path:
        return None, ZERO
    depth: Optional[Decimal] = None
    for i, d in enumerate(depths):
        for onward in prices[i + 1 :]:
            d *= onward
        depth = d if depth is None else min(depth, d)
    price = Decimal(1)
    for x in prices:
        price *= x
    return price, (depth or ZERO).quantize(Decimal("1e-18"), rounding=ROUND_DOWN)


def spot_reading(
    self: ExchangeStateManager, token: str, now: Decimal
) -> Tuple[Optional[Decimal], Decimal, Tuple[str, ...]]:
    """A token's spot market now, as its perp reads it: (price, depth, path) along the
    deepest path of pools to the settlement asset that has a price (``_path_reading``; ties:
    the first path in order). Whatever pool is deepest when read: no one's choice of pools
    to list on, so a perp listed while the token traded thinly follows it to deeper pools.
    A new pool counts only once it has a TWAP's history, and outweighing the others takes
    real capital held near the price: it is what pricing the perp costs."""
    best: Tuple[Optional[Decimal], Decimal, Tuple[str, ...]] = (None, ZERO, ())
    for path in self._spot_paths(token):
        price, depth = self._path_reading(token, path, now)
        if price is not None and (best[0] is None or depth > best[1]):
            best = (price, depth, path)
    return best


@_pinned
def update_spot_oracles(self: ExchangeStateManager, now: Decimal) -> List[Dict[str, Any]]:
    """Each block, before the clearinghouse's tick: every live token perp reads its spot
    market (``spot_reading``). Its depth at most doubles over SPOT_ORACLE_TWAP_SECONDS (falls
    at once), so liquidity added for a block raises no cap. Its oracle is the TWAP, moved at
    most ORACLE_MAX_STEP_BPS a second — only while the depth is at least
    SPOT_ORACLE_MIN_DEPTH; otherwise it goes stale, and the market takes only reduce-only
    orders."""
    from ... import constants

    now = Decimal(str(now))
    ch = self.clearinghouse
    window = Decimal(int(constants.SPOT_ORACLE_TWAP_SECONDS))
    step = Decimal(int(constants.ORACLE_MAX_STEP_BPS)) / 10_000
    events: List[Dict[str, Any]] = []
    for mid in sorted(ch.markets):
        m = ch.markets[mid]
        if not m.spot_token or m.settled_price > 0:
            continue
        price, depth, path = self.spot_reading(m.spot_token, now)
        if depth > m.spot_depth:
            # Up at most doubling over SPOT_ORACLE_TWAP_SECONDS (from SPOT_ORACLE_MIN_DEPTH
            # at the first reading), down at once: liquidity added for a moment, however
            # much, raises the cap by a sliver — only liquidity that stays raises it.
            dt = max(ZERO, now - m.spot_time) if m.spot_time > 0 else ZERO
            base = max(m.spot_depth, Decimal(int(constants.SPOT_ORACLE_MIN_DEPTH)))
            allowed = base * (1 + min(Decimal(1), dt / window))
            depth = min(depth, allowed).quantize(Decimal("1e-18"), rounding=ROUND_DOWN)
        if price is not None and depth < Decimal(int(constants.SPOT_ORACLE_MIN_DEPTH)):
            price = None
        if price is not None and step > 0 and m.oracle_price > 0 and m.oracle_time > 0:
            bound = step * max(ZERO, now - m.oracle_time)
            lo = m.oracle_price * (1 - min(bound, Decimal("0.99")))
            hi = m.oracle_price * (1 + bound)
            price = min(max(price, lo), hi)
        if price is not None:
            price = price.quantize(Decimal(1).scaleb(-18))
        ch.set_spot_reading(mid, price, depth, now, path)
        if price is None:
            events.append({"type": "spot_oracle_waiting", "market": mid, "depth": str(depth)})
    return events


def _op_perp_isolated_margin(
    self: ExchangeStateManager, tx: ExchangeTransaction
) -> ExchangeExecResult:
    """Add ``amount`` of free cross margin to an isolated position (negative: take it back,
    keeping the position's initial margin) — Hyperliquid's ``updateIsolatedMargin``."""
    p = tx.params
    try:
        margin = self.clearinghouse.adjust_isolated_margin(
            tx.sender, str(p["market_id"]), Decimal(str(p["amount"]))
        )
    except (ClearinghouseError, ArithmeticError, ValueError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_ISOLATED_MARGIN],
        data={"market_id": str(p["market_id"]), "isolated_margin": str(margin)},
    )


def _op_perp_order(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """A perp order — and its attached take-profit / stop-loss (``tp`` / ``sl``: each
    ``{trigger_price, limit_price?, max_makers?}``): reduce-only triggers on the other side,
    sized to the order, one cancelling the other, placed with it. Each costs what a
    PERP_TRIGGER costs; the order's matching gets what is left of the gas limit."""
    p = tx.params
    order_id = tx.tx_hash()[:16]
    m = self.clearinghouse.markets.get(str(p["market_id"]))
    if m is not None and not bool(p.get("reduce_only", False)) and self._perp_oracle_stale(m):
        return ExchangeExecResult(
            success=False,
            error=self._reduce_only_reason(m),
        )
    try:
        legs = _attached_legs(p)
        builder = self._builder_of(tx, spot=False)
    except ValueError as e:
        return ExchangeExecResult(success=False, error=str(e))
    legs_gas = sum(
        EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_TRIGGER] + makers * EXCHANGE_GAS_PER_MAKER
        for _kind, _trigger, _limit, makers in legs
    )
    gas_limit = getattr(tx, "gas_limit", None)
    try:
        if (
            gas_limit is not None
            and legs_gas > int(gas_limit) - EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_ORDER]
        ):
            raise ValueError(f"the attached TP/SL need {legs_gas} gas beyond the order's")
        self._trade_leverage(tx.sender, str(p["market_id"]), p)
        fills = self.clearinghouse.place_order(
            tx.sender,
            str(p["market_id"]),
            order_id,
            str(p["side"]),
            Decimal(str(p["size"])),
            Decimal(str(p["price"])),
            _book_nonce(tx),
            reduce_only=bool(p.get("reduce_only", False)),
            tif=str(p.get("tif", "gtc")),
            hidden=_flag(p, "hidden"),
            display_size=Decimal(str(p.get("display_size", "0"))),
            max_makers=match_budget(
                ExchangeOpType.PERP_ORDER, None if gas_limit is None else gas_limit - legs_gas
            ),
        )
        builder_fee = ZERO
        if builder is not None:  # on the notional of the fills this order took
            taken = sum(
                (
                    Decimal(f["amount"]) * Decimal(f["price"])
                    for f in fills
                    if f.get("taker_order_id") == order_id
                ),
                ZERO,
            )
            builder_fee = (taken * builder[1]).quantize(SPOT_FEE_QUANTUM, ROUND_DOWN)
            self.clearinghouse.pay_builder(tx.sender, builder[0], builder_fee)
        # Not resting after its fills: filled, IOC, or stopped by self-trade prevention
        # (an order that would hit the sender's own resting order is cancelled there).
        resting = order_id in self.clearinghouse.markets[str(p["market_id"])].orders
        attached = []
        if legs and (resting or fills):  # (an order that did nothing protects nothing)
            buy = str(p["side"]).lower() in ("buy", "long", "bid")
            for kind, trigger, limit, makers in legs:
                self.clearinghouse.place_trigger(
                    tx.sender,
                    str(p["market_id"]),
                    f"{order_id}.{kind}",
                    "sell" if buy else "buy",
                    kind,
                    trigger,
                    size=Decimal(str(p["size"])),
                    limit_price=limit,
                    reduce_only=True,
                    max_makers=makers,
                    group=order_id,
                    parent=order_id,
                )
                attached.append(f"{order_id}.{kind}")
    except (ClearinghouseError, ValueError, ArithmeticError) as e:
        # It pays for the resting orders it visited before failing (a fill-or-kill that
        # could not fill whole), as it would have had it succeeded.
        return ExchangeExecResult(
            success=False,
            error=str(e),
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_ORDER]
            + self.clearinghouse.last_makers_visited * EXCHANGE_GAS_PER_MAKER,
        )
    data: Dict[str, Any] = {"order_id": order_id, "fills": fills, "resting": resting}
    if builder is not None:
        data["builder_fee"] = {"builder": builder[0], "amount": str(builder_fee)}
    if attached:
        data["attached"] = attached
    if self.clearinghouse.last_cancelled:
        # Resting orders the fills left an account unqualified for (theirs or a maker's).
        data["cancelled"] = self.clearinghouse.last_cancelled
    visited = self.clearinghouse.last_makers_visited
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_ORDER]
        + visited * EXCHANGE_GAS_PER_MAKER
        + (legs_gas if attached else 0),
        data=data,
    )


def _reduce_only_reason(self: ExchangeStateManager, m) -> str:
    """Why ``m`` takes only reduce-only orders now (``_perp_oracle_stale``)."""
    if self.clearinghouse.halted(m):
        return f"{m.id}'s circuit breaker has tripped: only reduce-only orders are accepted"
    return f"the oracle for {m.id} is stale; only reduce-only orders are accepted"


def _perp_oracle_stale(self: ExchangeStateManager, m) -> bool:
    """A market whose oracle has not been set for PERP_ORACLE_STALE_SECONDS of block time
    accepts only orders that reduce exposure."""
    from ... import constants

    return m is not None and (
        (
            m.oracle_time > 0
            and Decimal(str(self._block_clock())) - m.oracle_time
            > constants.PERP_ORACLE_STALE_SECONDS
        )
        or self.clearinghouse.halted(m)
    )


def _op_perp_trigger(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """A stop or take-profit order (``Clearinghouse.place_trigger``). It prepays the
    matching it may do when it fires: ``max_makers`` resting orders (default
    TRIGGER_DEFAULT_MAKERS) at EXCHANGE_GAS_PER_MAKER each."""
    from ..clearinghouse import TRIGGER_DEFAULT_MAKERS

    p = tx.params
    base = EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_TRIGGER]
    try:
        makers = p.get("max_makers", TRIGGER_DEFAULT_MAKERS)
        if isinstance(makers, bool) or not isinstance(makers, int):
            raise ValueError("max_makers must be a whole number")
        gas = base + makers * EXCHANGE_GAS_PER_MAKER
        if gas > tx.gas_limit:
            raise ValueError(
                f"gas limit {tx.gas_limit} does not cover the trigger's prepaid matching "
                f"({gas})"
            )
        trigger_id = tx.tx_hash()[:16]
        self._trade_leverage(tx.sender, str(p["market_id"]), p)
        self.clearinghouse.place_trigger(
            tx.sender,
            str(p["market_id"]),
            trigger_id,
            str(p["side"]),
            str(p["kind"]),
            Decimal(str(p["trigger_price"])),
            size=Decimal(str(p.get("size", "0"))),
            limit_price=Decimal(str(p.get("limit_price", "0"))),
            reduce_only=_flag(p, "reduce_only"),
            position=_flag(p, "position"),
            tif=str(p.get("tif", "gtc")),
            max_makers=makers,
        )
    except (ClearinghouseError, ValueError, ArithmeticError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    return ExchangeExecResult(success=True, gas_used=gas, data={"order_id": trigger_id})


def _op_perp_modify(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    p = tx.params

    def opt(key):
        return None if p.get(key) is None else Decimal(str(p[key]))

    m = self.clearinghouse.markets.get(str(p["market_id"]))
    meta = tracked(m.orders).peek(str(p["order_id"])) if m is not None else None
    if m is not None and meta is not None and not meta.reduce_only and self._perp_oracle_stale(m):
        return ExchangeExecResult(
            success=False,
            error=self._reduce_only_reason(m),
        )
    try:
        out = self.clearinghouse.modify_order(
            tx.sender,
            str(p["market_id"]),
            str(p["order_id"]),
            tx.tx_hash()[:16],
            size=opt("size"),
            price=opt("price"),
            trigger_price=opt("trigger_price"),
            limit_price=opt("limit_price"),
            max_makers=match_budget(ExchangeOpType.PERP_MODIFY, getattr(tx, "gas_limit", None)),
        )
    except (ClearinghouseError, ValueError, ArithmeticError) as e:
        return ExchangeExecResult(
            success=False,
            error=str(e),
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_MODIFY]
            + self.clearinghouse.last_makers_visited * EXCHANGE_GAS_PER_MAKER,
        )
    if self.clearinghouse.last_cancelled:
        out["cancelled"] = self.clearinghouse.last_cancelled
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_MODIFY]
        + self.clearinghouse.last_makers_visited * EXCHANGE_GAS_PER_MAKER,
        data=out,
    )


def _op_perp_cancel(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    p = tx.params
    try:
        self.clearinghouse.cancel_order(tx.sender, str(p["market_id"]), str(p["order_id"]))
    except (ClearinghouseError, ValueError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    return ExchangeExecResult(success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_CANCEL])
