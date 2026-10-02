"""
Read-only views of the exchange — spot (AMM pools, liquidity positions, swap quotes, the spot
order books) and perps — shared by every surface that reports them: the REST API, the JSON-RPC
``exchange_*`` / ``perp_*`` methods and the realtime streams, so they all say the same thing in
the same shape. Pure functions over an ExchangeStateManager; every value is JSON-safe (Decimals
as strings). Nothing here changes state — quotes run the router's exact, read-only quoting.
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any, Dict, Iterable, List, Optional

from .clearinghouse import PROTOCOL, VAULT, Market, Position
from .journal import jsonable

ZERO = Decimal(0)


def _s(value) -> Optional[str]:
    return None if value is None else str(value)


def account_key(ch, address: str) -> Optional[str]:
    """The clearinghouse keys accounts by the sender string as signed; accept any casing."""
    if not address:
        return None
    if address in ch.accounts:
        return address
    low = address.lower()
    for key in ch.accounts:
        if key.lower() == low:
            return key
    return None


# ── native tokens ──────────────────────────────────────────────────────────

def tokens(mgr) -> List[Dict[str, Any]]:
    """Every native token: supply, decimals, authorities (qrdx/exchange/tokens.py)."""
    reg = mgr.tokens
    return [reg.tokens[a].summary() for a in sorted(reg.tokens)]


def token(mgr, token_address: str) -> Optional[Dict[str, Any]]:
    t = mgr.tokens.get(token_address)
    if t is None:
        return None
    out = t.summary()
    out["frozen_accounts"] = sum(1 for tok, _ in mgr.tokens.frozen if tok == t.address)
    return out


def token_allowance(mgr, token_address: str, owner: str, spender: str) -> Dict[str, Any]:
    t = mgr.tokens.require(token_address)
    return {"token_address": t.address, "owner": owner, "spender": spender,
            "allowance": str(mgr.tokens.allowance(t.address, owner, spender))}


def token_frozen(mgr, token_address: str, address: str) -> bool:
    return mgr.tokens.is_frozen(token_address, address)


# ── spot: AMM pools ─────────────────────────────────────────────────────────

def _same(a: str, b: str) -> bool:
    return bool(a) and bool(b) and a.lower() == b.lower()


def pool_summary(mgr, pool) -> Dict[str, Any]:
    st = pool.state
    return {
        "pool_id": st.id, "token0": st.token0, "token1": st.token1,
        "fee_tier": int(st.fee_tier), "fee_rate": str(st.fee_tier.rate),
        "tick_spacing": st.fee_tier.tick_spacing, "pool_type": st.pool_type.name,
        "creator": st.creator, "stake": str(st.stake_amount),
        "price": str(st.price),                       # token1 per token0
        "sqrt_price_x96": str(st.sqrt_price), "tick": st.tick,
        "liquidity": str(st.liquidity),               # active (in range) at the current tick
        "positions": len(st.positions),
        "protocol_fees": [str(st.protocol_fees_0), str(st.protocol_fees_1)],
        "volume": [str(st.total_volume_0), str(st.total_volume_1)],
        "holder_address": mgr.pool_holder_address(st.id),
        "paused": pool.is_paused,
    }


def pools(mgr, token_a: Optional[str] = None, token_b: Optional[str] = None
          ) -> List[Dict[str, Any]]:
    """Every pool, or a pair's pools, by id."""
    pm = mgr.pool_manager
    found = (pm.get_pools_for_pair(token_a, token_b) if token_a and token_b
             else pm.get_all_pools())
    return [pool_summary(mgr, p) for p in sorted(found, key=lambda p: p.state.id)]


def position_summary(pool, position) -> Dict[str, Any]:
    from .amm import TICK_BASE
    principal0, principal1, fees0, fees1 = pool.position_value(position.id)
    st = pool.state
    return {
        "position_id": position.id, "pool_id": st.id, "owner": position.owner,
        "token0": st.token0, "token1": st.token1,
        "tick_lower": position.tick_lower, "tick_upper": position.tick_upper,
        "price_lower": str((TICK_BASE ** position.tick_lower).quantize(Decimal("1e-18"))),
        "price_upper": str((TICK_BASE ** position.tick_upper).quantize(Decimal("1e-18"))),
        "liquidity": str(position.liquidity),
        "in_range": position.tick_lower <= st.tick < position.tick_upper,
        # What REMOVE_LIQUIDITY of the whole position would pay right now.
        "amount0": str(principal0), "amount1": str(principal1),
        "fees0": str(fees0), "fees1": str(fees1),
    }


def pool(mgr, pool_id: str, twap_window: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """One pool with its initialized ticks and positions; ``twap_window`` (seconds of block
    time) adds the time-weighted price over that window, when the pool has the history."""
    p = mgr.pool_manager.get_pool(pool_id)
    if p is None:
        return None
    st = p.state
    out = pool_summary(mgr, p)
    out["ticks"] = [{"tick": t, "liquidity_net": str(st.ticks[t].liquidity_net),
                     "liquidity_gross": str(st.ticks[t].liquidity_gross)}
                    for t in sorted(st.ticks)]
    out["position_list"] = [position_summary(p, st.positions[pid])
                            for pid in sorted(st.positions)]
    if twap_window:
        now = int(mgr._block_clock())
        twap = p.twap_price(int(twap_window), now)
        out["twap"] = {"window": int(twap_window), "as_of": now, "price": _s(twap)}
    return out


def liquidity_quote(mgr, pool_id: str, tick_lower: int, tick_upper: int,
                    liquidity=None, amount0=None, amount1=None) -> Optional[Dict[str, Any]]:
    """What adding liquidity costs: give ``liquidity`` (L) for its exact deposit, or token
    amounts for the most L they buy (a missing amount is unlimited). The deposit is what
    ADD_LIQUIDITY will charge, if the price has not moved."""
    p = mgr.pool_manager.get_pool(pool_id)
    if p is None:
        return None
    lower, upper = int(tick_lower), int(tick_upper)
    if liquidity is not None:
        L = Decimal(str(liquidity))
        if L <= 0:
            raise ValueError("liquidity must be positive")
        p._check_range(lower, upper)
    else:
        if amount0 is None and amount1 is None:
            raise ValueError("give liquidity, or amount0 and/or amount1")
        L = p.liquidity_for_amounts(lower, upper,
                                    None if amount0 is None else Decimal(str(amount0)),
                                    None if amount1 is None else Decimal(str(amount1)))
    cost0, cost1 = p.amounts_for_liquidity(lower, upper, L, round_up=True)
    st = p.state
    return {"pool_id": st.id, "token0": st.token0, "token1": st.token1,
            "tick_lower": lower, "tick_upper": upper, "liquidity": str(L),
            "amount0": str(cost0), "amount1": str(cost1),
            "in_range": lower <= st.tick < upper, "price": str(st.price)}


def positions(mgr, address: str) -> List[Dict[str, Any]]:
    """An address's liquidity positions, every pool."""
    out = []
    for p in sorted(mgr.pool_manager.get_all_pools(), key=lambda p: p.state.id):
        for pid in sorted(p.state.positions):
            pos = p.state.positions[pid]
            if _same(pos.owner, address):
                out.append(position_summary(p, pos))
    return out


def quote(mgr, token_in: str, token_out: str, amount_in, sender: str = "",
          pool_id: Optional[str] = None, venue: str = "auto") -> Optional[Dict[str, Any]]:
    """The exact fill a SWAP would get against the current state (the router's own quote, so a
    swap in the next block gets exactly this unless something trades first). None when nothing
    can fill it."""
    from .router import FillSource
    amount = Decimal(str(amount_in))
    if amount <= 0:
        raise ValueError("amount_in must be positive")
    route = mgr.router.best_route(token_in, token_out, amount, sender, pool_id=pool_id,
                                  venue=str(venue or "auto").lower())
    if route is None:
        return None
    out = {
        "source": route.source.value, "pool_id": route.pool_id, "pair": route.pair,
        "token_in": token_in, "token_out": token_out,
        "amount_in": str(route.amount_in), "amount_out": str(route.amount_out),
        "unfilled_in": str(amount - route.amount_in),
        "fee": str(route.fee_total),
        "execution_price": str(route.price),          # token_in paid per token_out received
    }
    if route.source == FillSource.AMM and route.plan is not None:
        from .amm import sqrt_price_to_price
        p = mgr.pool_manager.get_pool(route.pool_id)
        before = p.state.price
        after = sqrt_price_to_price(route.plan.sqrt_price)
        out["price_before"] = str(before)
        out["price_after"] = str(after)
        out["price_impact"] = (str((abs(after - before) / before).quantize(Decimal("1e-8")))
                               if before > 0 else None)
    return out


# ── spot: order books ───────────────────────────────────────────────────────

def _spot_book(mgr, pair: str):
    key = mgr._canonical_pair(pair)
    return key, mgr._order_books.get(key)


def spot_order_book(mgr, pair: str, depth: int = 20) -> Optional[Dict[str, Any]]:
    """A spot pair's order book (``base:quote`` by token address, either order): aggregated
    price levels, best first, priced in quote per base."""
    key, book = _spot_book(mgr, pair)
    if book is None:
        return None
    depth = max(1, min(int(depth), 500))
    base, quote_token = key.split(":", 1)
    return {
        "pair": key, "base": base, "quote": quote_token,
        "bids": [[str(p), str(a)] for p, a in book.get_bids(depth)],
        "asks": [[str(p), str(a)] for p, a in book.get_asks(depth)],
        "best_bid": _s(book.best_bid), "best_ask": _s(book.best_ask),
        "escrow_address": mgr.orderbook_escrow_address(key),
    }


def spot_open_orders(mgr, address: str) -> List[Dict[str, Any]]:
    """An address's resting spot orders, every pair."""
    out = []
    for key in sorted(mgr._order_books):
        book = mgr._order_books[key]
        for oid in sorted(book._orders):
            o = book._orders[oid]
            if not o.is_active or not _same(o.owner, address):
                continue
            out.append({
                "pair": key, "order_id": oid, "side": o.side.value,
                "order_type": o.order_type.value, "price": str(o.price),
                "amount": str(o.amount), "filled": str(o.filled), "remaining": str(o.remaining),
            })
    return out


# ── markets ────────────────────────────────────────────────────────────────

def market_summary(m: Market) -> Dict[str, Any]:
    from .. import constants
    interval = Decimal(constants.PERP_FUNDING_INTERVAL_SECONDS)
    book = m.book
    return {
        "market_id": m.id, "base": m.base, "quote": m.quote,
        "max_leverage": _s(m.max_leverage), "maintenance_rate": _s(m.maintenance_rate),
        "oracle_price": _s(m.oracle_price), "oracle_time": _s(m.oracle_time),
        "mark_price": _s(m.mark_price), "last_trade_price": _s(m.last_trade_price),
        "open_interest": _s(m.open_interest),
        "best_bid": _s(book.best_bid), "best_ask": _s(book.best_ask),
        "funding_rate": _s(m.funding_rate), "funding_time": _s(m.funding_time),
        "next_funding_time": _s(m.funding_time + interval) if m.funding_time > 0 else None,
        "premium_sum": _s(m.premium_sum), "premium_time": _s(m.premium_time),
    }


def markets(mgr) -> List[Dict[str, Any]]:
    ch = mgr.clearinghouse
    return [market_summary(ch.markets[mid]) for mid in sorted(ch.markets)]


def market(mgr, market_id: str) -> Optional[Dict[str, Any]]:
    m = mgr.clearinghouse.markets.get(market_id)
    return None if m is None else market_summary(m)


def order_book(mgr, market_id: str, depth: int = 20) -> Optional[Dict[str, Any]]:
    m = mgr.clearinghouse.markets.get(market_id)
    if m is None:
        return None
    depth = max(1, min(int(depth), 500))
    return {
        "market_id": m.id,
        "bids": [[str(p), str(a)] for p, a in m.book.get_bids(depth)],
        "asks": [[str(p), str(a)] for p, a in m.book.get_asks(depth)],
        "mark_price": _s(m.mark_price), "oracle_price": _s(m.oracle_price),
        "last_trade_price": _s(m.last_trade_price),
    }


# ── accounts ───────────────────────────────────────────────────────────────

def open_orders(mgr, address: str) -> List[Dict[str, Any]]:
    ch = mgr.clearinghouse
    key = account_key(ch, address) or address
    out = []
    for mid in sorted(ch.markets):
        m = ch.markets[mid]
        for oid in sorted(m.orders):
            meta = m.orders[oid]
            if meta.owner != key:
                continue
            o = m.book.get_order(oid)
            if o is None or not o.is_active:
                continue
            out.append({
                "market_id": mid, "order_id": oid, "side": o.side.value, "price": str(o.price),
                "size": str(o.amount), "filled": str(o.filled), "remaining": str(o.remaining),
                "reduce_only": meta.reduce_only, "leverage": str(meta.leverage),
            })
    return out


def _liquidation_price(ch, owner: str, m: Market, pos: Position, isolated: bool) -> Optional[str]:
    """The mark at which this position would hit maintenance, other positions held at their
    current marks. Isolated: margin + q(p − entry) = |q|·p·r. Cross: the account's equity and
    maintenance with this position's terms moved to p."""
    q, e, r = pos.size, pos.entry_price, m.maintenance_rate
    if q == 0:
        return None
    denominator = q - abs(q) * r
    if denominator == 0:
        return None
    if isolated:
        numerator = q * e - pos.isolated_margin
    else:
        equity = ch.cross_equity(owner)
        maintenance = ch.cross_maintenance(owner)
        upnl = q * (m.mark_price - e)
        mm = abs(q) * m.mark_price * r
        numerator = maintenance - mm - equity + upnl + q * e
    price = numerator / denominator
    return str(price.quantize(Decimal("1e-8"))) if price > 0 else None


def account(mgr, address: str) -> Dict[str, Any]:
    """Everything a wallet shows: collateral, margin, positions with PnL and liquidation prices,
    open orders, vault shares — plus the clearinghouse holder and the vault, for reference."""
    ch = mgr.clearinghouse
    key = account_key(ch, address)
    acct = ch.accounts.get(key) if key else None
    positions, leverage = {}, {}
    if acct is not None:
        for mid, pos in sorted(acct.positions.items()):
            m = ch.markets[mid]
            iso = acct.isolated.get(mid, False)
            positions[mid] = {
                "size": str(pos.size), "entry_price": str(pos.entry_price),
                "mark_price": str(m.mark_price), "isolated": iso,
                "isolated_margin": str(pos.isolated_margin),
                "notional": str(abs(pos.size) * m.mark_price),
                "unrealized_pnl": str(pos.size * (m.mark_price - pos.entry_price)),
                "leverage": str(ch._leverage(acct, m)),
                "liquidation_price": _liquidation_price(ch, key, m, pos, iso),
            }
        for mid in sorted(set(acct.leverage) | set(acct.isolated)):
            if mid in ch.markets:
                leverage[mid] = {"leverage": str(ch._leverage(acct, ch.markets[mid])),
                                 "mode": "isolated" if acct.isolated.get(mid, False) else "cross"}
    owner = key or address
    return {
        "address": address,
        "exchange_nonce": mgr.get_nonce(key or address),
        "collateral": str(acct.collateral) if acct is not None else "0",
        "withdrawable": str(ch.withdrawable(owner)),
        "equity": str(ch.cross_equity(owner)),
        "maintenance_margin": str(ch.cross_maintenance(owner)),
        "initial_margin": str(ch.cross_requirement(owner)),
        "open_order_margin": str(ch.open_order_margin(owner)),
        "positions": positions,
        "leverage": leverage,
        "orders": open_orders(mgr, owner),
        "vault_shares": str(ch.vault_shares.get(owner, 0)),
        "vault_unlock_time": str(ch.vault_unlock.get(owner, 0)),
        "holder_address": mgr.perps_holder_address(),
        "holder_balance": str(ch.holder_balance),
        "collateral_token": mgr.perp_collateral_token(),
        "vault": vault(mgr),
    }


# ── the backstop vault ─────────────────────────────────────────────────────

def vault(mgr) -> Dict[str, Any]:
    from .. import constants
    ch = mgr.clearinghouse
    nav = ch.vault_nav()
    acct = ch.accounts.get(VAULT)
    total = ch.vault_total_shares
    return {
        "nav": str(nav), "collateral": str(ch.vault_collateral), "total_shares": str(total),
        "share_value": str(nav / total) if total > 0 else None,
        "protocol_shares": str(ch.vault_shares.get(PROTOCOL, 0)),
        "depositors": sum(1 for o in ch.vault_shares if o != PROTOCOL),
        "positions": ({mid: {"size": str(p.size), "entry_price": str(p.entry_price)}
                       for mid, p in sorted(acct.positions.items())} if acct is not None else {}),
        "lockup_seconds": constants.PERP_VAULT_LOCKUP_SECONDS,
    }


# ── receipts and events (the journal) ──────────────────────────────────────

def receipt(mgr, tx_hash: str) -> Optional[Dict[str, Any]]:
    return mgr.journal.receipt(tx_hash)


def events(mgr, *, market: Optional[str] = None, address: Optional[str] = None,
           types: Optional[Iterable[str]] = None, since: Optional[int] = None,
           limit: int = 100) -> Dict[str, Any]:
    limit = max(1, min(int(limit), 1000))
    found = mgr.journal.query(market=market, address=address, types=types, since=since,
                              limit=limit)
    return {"events": jsonable(found), "last_seq": mgr.journal.seq}


def trades(mgr, market_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    return events(mgr, market=market_id, types=["fill"], limit=limit)["events"]
