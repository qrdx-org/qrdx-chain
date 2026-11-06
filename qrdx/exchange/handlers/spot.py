"""
Spot trading: pools and liquidity, swaps and their routes, the order book, spot fees and the
stakers' share of them, brackets and spot trigger orders, uncrossing.

These are ExchangeStateManager's methods, written as functions of the manager (``self``) and
bound to it under the same names in qrdx/exchange/state_manager.py. They are here only to keep
that file to a size one can read: read them as the class's.
"""

from __future__ import annotations

from decimal import ROUND_DOWN, ROUND_FLOOR, ROUND_HALF_UP, Decimal
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Tuple

from ...validator.epoch_state import STAKER_FEE_HOLDER
from .. import undo
from ..amm import (
    FEE_CREATOR_SHARE,
    FEE_TREASURY_SHARE,
    FEE_VALIDATOR_SHARE,
    Q96,
    FeeTier,
    PoolType,
)
from ..commitment import tracked
from ..orderbook import (
    MatchBudget,
    Order,
    OrderBook,
    OrderSide,
    OrderType,
    SelfTradeAction,
    _pinned,
)
from ..router import FillSource
from ..tokens import (
    canonical_asset,
)
from ..transactions import (
    EXCHANGE_GAS_COSTS,
    EXCHANGE_GAS_PER_MAKER,
    ExchangeOpType,
    ExchangeTransaction,
    match_budget,
)
from .common import (
    _TRIGGER_KINDS,
    MAX_SWAP_HOPS,
    SPOT_FEE_QUANTUM,
    STAKER_FEE_CONVERT_MAKERS,
    STAKER_FEE_CONVERT_SECONDS,
    STAKER_FEE_CONVERT_SLIPPAGE,
    STAKER_FEE_TWAP_SECONDS,
    ZERO,
    ExchangeExecResult,
    _BatchAction,
    _book_nonce,
    _flag,
    _trigger_makers,
    logger,
)

if TYPE_CHECKING:
    from ..state_manager import ExchangeStateManager


def _op_create_pool(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    p = tx.params
    fee_tier = FeeTier(int(p["fee_tier"]))
    pool_type = (
        PoolType[p["pool_type"]]
        if isinstance(p["pool_type"], str)
        else PoolType(int(p["pool_type"]))
    )
    if p.get("initial_price") is not None:
        # Plain price, token1 per token0 of the CANONICAL (sorted) pair.
        sqrt_price = Decimal(str(p["initial_price"])).sqrt() * Q96
    else:
        sqrt_price = Decimal(str(p["initial_sqrt_price"]))
    stake = Decimal(str(p["stake_amount"]))

    # Phase E: pool creation must be backed by real QRDX. Check affordability of
    # the declared stake BEFORE creating (a failed op is not reverted), mirroring
    # the perp-margin path. create_pool() separately validates stake >= the
    # per-type minimum (raises) — this is the additional can-the-creator-afford-it
    # check.
    avail = self.available_balance(tx.sender)
    if avail is not None and avail < stake:
        if self.enforce_pool_stake:
            return ExchangeExecResult(
                success=False,
                error=(f"insufficient balance for pool stake: need {stake}, " f"available {avail}"),
            )
        logger.warning(
            "[Phase E observe] create_pool by %s: stake %s exceeds available "
            "balance %s — would REJECT once pool stake is enforced",
            tx.sender[:20],
            stake,
            avail,
        )

    for asset in (self.canonical_asset(p["token0"]), self.canonical_asset(p["token1"])):
        t = self.tokens.peek(asset)
        if t is not None and (t.fee_enabled or t.non_transferable):
            # Spot moves are exact (a pool's reserves, a book's escrow): a fee withheld
            # on the way in would break their accounting; a soulbound token cannot move.
            kind = "charges a transfer fee" if t.fee_enabled else "is non-transferable"
            return ExchangeExecResult(
                success=False, error=f"{t.symbol} {kind}: it cannot be pooled or traded"
            )
    try:
        pool = self.pool_manager.create_pool(
            self.canonical_asset(p["token0"]),
            self.canonical_asset(p["token1"]),
            fee_tier,
            pool_type,
            sqrt_price,
            tx.sender,
            stake,
        )
    except ValueError as e:
        return ExchangeExecResult(success=False, error=str(e))

    # Debit the stake as a real-balance move (flushed to account_state by the
    # async wrapper). Only RECORD the delta when enforcing — the shared flush is
    # already on for collateral, so recording unconditionally would debit even
    # while this gate is off. The stake is held in pool.state.stake_amount for a
    # future remove-pool return (staking pools) / forfeit (subsidized = burn).
    if self.enforce_pool_stake and stake > ZERO:
        self._record_balance_delta(tx.sender, -stake)

    # Create the pair's order book (its registry entries undone with a failure)
    pair_key = f"{pool.state.token0}:{pool.state.token1}"
    self._keep_pair_registries(pair_key)
    if pair_key not in self._order_books:
        book = OrderBook(
            pool_id=pair_key,
            self_trade_action=SelfTradeAction.CANCEL_TAKER,
        )
        self._order_books[pair_key] = book
        self.router.register_order_book(pair_key, book)

    self._total_pools += 1
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.CREATE_POOL],
        data={"pool_id": pool.state.id, "pair": pair_key},
    )


def _keep_pair_registries(self: ExchangeStateManager, pair_key: str) -> None:
    """A pair's order-book entries — the manager's and the router's — as they are, for an
    undo scope to put back (they are plain registries, not committed ones)."""
    for registry in (self._order_books, self.router._order_books):
        undo.keep_entry(registry, pair_key, mutable=False)


def _op_remove_pool(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Remove a pool the sender created and REFUND its staked QRDX (the mirror of the
    CREATE_POOL stake debit). Only the creator may, and only once no position remains —
    any position, in range or not, still owns tokens in the pool. The protocol's share of
    the fees it collected is paid out as §7.6 splits it: the creator's part (15 of 30) to
    the creator, the treasury's and validators' to the treasury. SUBSIDIZED pools burned
    their stake, so it is never refunded."""
    p = tx.params
    pool = self.pool_manager.get_pool(p["pool_id"]) if p.get("pool_id") else None
    if pool is None:
        return ExchangeExecResult(success=False, error=f"no such pool: {p.get('pool_id')}")
    if tx.sender != pool.state.creator:
        return ExchangeExecResult(success=False, error="only the pool creator may remove it")
    if pool.state.positions:
        return ExchangeExecResult(
            success=False,
            error=f"pool still has {len(pool.state.positions)} position(s); remove them first",
        )

    from ... import constants
    from ..amm import PoolType

    stake = Decimal(str(pool.state.stake_amount or 0))
    pool_type = pool.state.pool_type
    pair_key = f"{pool.state.token0}:{pool.state.token1}"
    holder = self.pool_holder_address(pool.state.id)
    treasury = constants.SYSTEM_WALLET_ADDRESSES["TREASURY_MULTISIG"]
    share = FEE_CREATOR_SHARE / (FEE_CREATOR_SHARE + FEE_TREASURY_SHARE + FEE_VALIDATOR_SHARE)
    try:
        with self._atomic(pool):
            for token, fees in (
                (pool.state.token0, pool.state.protocol_fees_0),
                (pool.state.token1, pool.state.protocol_fees_1),
            ):
                to_creator = (fees * share).quantize(Decimal("1e-18"), rounding=ROUND_FLOOR)
                self._settle_token_move(holder, pool.state.creator, token, to_creator)
                self._settle_token_move(holder, treasury, token, fees - to_creator)
    except ValueError as e:
        return ExchangeExecResult(success=False, error=str(e))

    self.pool_manager.remove_pool(pool.state.id)
    self._keep_pair_registries(pair_key)
    # The order book is per PAIR; keep it while another pool of the pair remains (removing
    # it would strand that book's resting orders).
    if not self.pool_manager.get_pools_for_pair(pool.state.token0, pool.state.token1):
        book = self._order_books.get(pair_key)
        if book is not None and not book._orders:
            self._order_books.pop(pair_key, None)
            self.router.unregister_order_book(pair_key)

    refunded = ZERO
    if self.enforce_pool_stake and pool_type != PoolType.SUBSIDIZED and stake > ZERO:
        self._record_balance_delta(tx.sender, stake)
        refunded = stake

    self._total_pools = max(0, self._total_pools - 1)
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.REMOVE_POOL],
        data={
            "pool_id": pool.state.id,
            "refunded_stake": str(refunded),
            "burned_stake": str(stake) if pool_type == PoolType.SUBSIDIZED else "0",
            "protocol_fees": [str(pool.state.protocol_fees_0), str(pool.state.protocol_fees_1)],
        },
    )


def _op_add_liquidity(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Deposit liquidity ``amount`` (L) in [tick_lower, tick_upper). The tokens it costs —
    rounded up, in the pool's favour — move from the provider to the pool's holder. The pool
    is named by ``pool_id``, or by ``token0`` / ``token1`` (+ ``fee_tier`` when the pair has
    several pools)."""
    p = tx.params
    pool = self.pool_manager.get_pool(p["pool_id"]) if p.get("pool_id") else None
    if pool is None and p.get("token0") and p.get("token1"):
        pool = self._find_pool_for_pair(
            self.canonical_asset(p["token0"]),
            self.canonical_asset(p["token1"]),
            p.get("fee_tier"),
        )
    if pool is None:
        return ExchangeExecResult(success=False, error="Pool not found")
    tick_lower, tick_upper = int(p["tick_lower"]), int(p["tick_upper"])
    liquidity = Decimal(str(p["amount"]))
    try:
        pool._check_range(tick_lower, tick_upper)
    except ValueError as e:
        return ExchangeExecResult(success=False, error=str(e))
    if liquidity <= 0:
        return ExchangeExecResult(success=False, error="Liquidity amount must be positive")
    amt0, amt1 = pool.amounts_for_liquidity(tick_lower, tick_upper, liquidity, round_up=True)
    if self.enforce_spot_settlement:
        for tok, amt in ((pool.state.token0, amt0), (pool.state.token1, amt1)):
            av = self.available_token_balance(tx.sender, tok)
            if av is not None and av < amt:
                return ExchangeExecResult(
                    success=False,
                    error=f"insufficient {tok[:10]} for liquidity: need {amt}, available {av}",
                )
    holder = self.pool_holder_address(pool.state.id)
    with self._atomic(pool):
        position = pool.add_liquidity(
            tx.sender, tick_lower, tick_upper, liquidity, now=int(self._block_clock())
        )
        self._settle_token_move(tx.sender, holder, pool.state.token0, amt0)
        self._settle_token_move(tx.sender, holder, pool.state.token1, amt1)
    # Liquidity at a price past resting orders: they fill from it at the tick.
    self.trading.uncross[f"{pool.state.token0}:{pool.state.token1}"] = 1
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.ADD_LIQUIDITY],
        data={
            "pool_id": pool.state.id,
            "position_id": position.id,
            "liquidity": str(liquidity),
            "amount0": str(amt0),
            "amount1": str(amt1),
        },
    )


def _op_remove_liquidity(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Withdraw ``amount`` of L (default: all) from one of the SENDER's positions: its
    principal at the current price (rounded down) plus every fee it has earned move from
    the pool's holder to the owner. ``amount`` 0 collects fees only."""
    p = tx.params
    pool = self.pool_manager.get_pool(p["pool_id"])
    if pool is None:
        return ExchangeExecResult(success=False, error="Pool not found")
    position = pool.state.positions.get(str(p["position_id"]))
    if position is None:
        return ExchangeExecResult(success=False, error=f"Position {p['position_id']} not found")
    if position.owner != tx.sender:
        return ExchangeExecResult(
            success=False, error="only the position's owner may remove its liquidity"
        )
    raw = p.get("amount")
    amount = Decimal(str(raw)) if raw not in (None, "", "all") else None
    if amount is not None and amount < 0:
        return ExchangeExecResult(success=False, error="amount must not be negative")
    holder = self.pool_holder_address(pool.state.id)
    try:
        with self._atomic(pool):
            out0, out1 = pool.remove_liquidity(
                position.id, amount, owner=tx.sender, now=int(self._block_clock())
            )
            self._settle_token_move(holder, tx.sender, pool.state.token0, out0, release=True)
            self._settle_token_move(holder, tx.sender, pool.state.token1, out1, release=True)
    except ValueError as e:
        return ExchangeExecResult(success=False, error=str(e))
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.REMOVE_LIQUIDITY],
        data={
            "pool_id": pool.state.id,
            "position_id": position.id,
            "amount0": str(out0),
            "amount1": str(out1),
            "removed": str((out0, out1)),
        },
    )


def _find_pool_for_pair(self: ExchangeStateManager, token_a: str, token_b: str, fee_tier=None):
    """A pool for the pair: the one with ``fee_tier`` if given, else — only when the pair
    has exactly one pool — that one. Several pools and no fee tier is ambiguous: None."""
    pools = sorted(self.pool_manager.get_pools_for_pair(token_a, token_b), key=lambda p: p.state.id)
    if fee_tier is not None:
        pools = [p for p in pools if int(p.state.fee_tier) == int(fee_tier)]
    return pools[0] if len(pools) == 1 else None


# ── spot swaps: the best path, each hop through its pair's combined market ──────────
#    (docs/UNIFIED_SPOT_LIQUIDITY.md 2)
def routing_hubs(self: ExchangeStateManager) -> List[str]:
    """The tokens a swap may route through when that pays more: QRDX, and the perps
    settlement asset (where liquidity gathers)."""
    hubs = ["QRDX"]
    if self.perp_collateral_token():
        settlement = self._settlement_asset()
        if settlement not in hubs:
            hubs.append(settlement)
    return hubs


def swap_paths(self: ExchangeStateManager, token_in: str, token_out: str) -> List[List[str]]:
    """The paths a swap from ``token_in`` to ``token_out`` chooses among: the pair itself,
    then two hops through each routing hub."""
    paths = [[token_in, token_out]]
    for hub in self.routing_hubs():
        if hub not in (token_in, token_out):
            paths.append([token_in, hub, token_out])
    return paths


def _route_gas(route) -> int:
    """What a hop's walk costs beyond SWAP's base gas: each resting order it visits, and
    each pool it uses beyond the first."""
    pools = sum(1 for leg in route.legs if leg.source == FillSource.AMM)
    return (route.makers + max(0, pools - 1)) * EXCHANGE_GAS_PER_MAKER


def plan_swap(
    self: ExchangeStateManager,
    sender: str,
    path: List[str],
    amount_in: Decimal,
    *,
    pool_id: Optional[str] = None,
    venue: str = "auto",
    gas_limit: Optional[int] = None,
) -> Tuple[Optional[List[Any]], str]:
    """Plan a swap along ``path`` on the current state, hop by hop, each on its pair's
    combined market within what the gas limit pays for (read only). (routes, "") or
    (None, why not)."""
    hops = len(path) - 1
    gas = EXCHANGE_GAS_COSTS[ExchangeOpType.SWAP] * hops
    if gas_limit is not None and gas > gas_limit:
        return None, f"a {hops}-hop swap needs at least {gas} gas"
    routes: List[Any] = []
    amount = amount_in
    for i in range(hops):
        makers = None if gas_limit is None else max(0, (gas_limit - gas) // EXCHANGE_GAS_PER_MAKER)
        route = self.router.best_route(
            path[i],
            path[i + 1],
            amount,
            sender,
            pool_id=pool_id if hops == 1 else None,
            venue=venue,
            max_makers=makers,
        )
        if route is None or route.amount_out <= 0:
            error = "No liquidity available for this pair"
            return None, error if hops == 1 else f"hop {i}: {error}"
        gas += self._route_gas(route)
        routes.append(route)
        amount = route.amount_out
    return routes, ""


def choose_swap_path(
    self: ExchangeStateManager,
    sender: str,
    token_in: str,
    token_out: str,
    amount_in: Decimal,
    *,
    path: Optional[List[str]] = None,
    pool_id: Optional[str] = None,
    venue: str = "auto",
    gas_limit: Optional[int] = None,
) -> Tuple[Optional[List[str]], Optional[List[Any]], str]:
    """The path a swap takes: ``path`` if given; else the pair itself, or two hops through a
    routing hub when that pays more (a ``pool_id`` or a ``venue`` keeps it on the pair).
    Ties: the pair, then the hubs in order. (path, its planned routes, "") or
    (None, None, why not)."""
    if path is not None:
        candidates = [path]
    elif pool_id or venue != "auto":
        candidates = [[token_in, token_out]]
    else:
        candidates = self.swap_paths(token_in, token_out)
    best: Tuple[Optional[List[str]], Optional[List[Any]], str] = (None, None, "")
    for candidate in candidates:
        routes, error = self.plan_swap(
            sender, candidate, amount_in, pool_id=pool_id, venue=venue, gas_limit=gas_limit
        )
        if routes is None:
            if best[0] is None and not best[2]:
                best = (None, None, error)  # (the first candidate's reason: the pair's)
            continue
        if best[1] is None or routes[-1].amount_out > best[1][-1].amount_out:
            best = (candidate, routes, "")
    return best


def _op_swap(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Exact-input swap on the best path, each hop through its pair's combined market — the
    order book and every pool, best prices first, split between pools at the same price
    (docs/UNIFIED_SPOT_LIQUIDITY.md). Without ``path`` it goes through a routing hub
    (``routing_hubs``) when that pays more. ``pool_id`` keeps it to that pool, ``venue``
    "clob" to the book, "amm" to the pools — but no swap trades through a resting order:
    resting orders at better prices fill first.

    ``path`` [A, B, C, …] (instead of ``token_in``/``token_out``): exactly that path, up to
    MAX_SWAP_HOPS hops, each spending exactly what the one before it bought;
    ``min_amount_out`` bounds the last. All or nothing.

    Gas: SWAP's base gas for each hop, and EXCHANGE_GAS_PER_MAKER for each resting order
    visited and for each pool used beyond a hop's first — no more than the gas limit pays
    for (each hop is planned within that budget)."""
    p = tx.params
    if (p.get("pool_id") or str(p.get("venue", "auto")).lower() != "auto") and (
        self._signed_by_delegate(tx)
    ):
        # An agent or a vault's leader trades for the account: its swap takes the best route
        # — it may not steer the account's funds into a pool or venue of its choosing
        # (docs/EXCHANGE_AUDIT.md 9).
        return ExchangeExecResult(
            success=False,
            error="a swap signed for an account by its agent takes the best route: "
            "no pool_id or venue",
        )
    explicit = None
    if p.get("path") is not None:
        raw = p["path"]
        if (
            not isinstance(raw, list)
            or not 2 <= len(raw) <= MAX_SWAP_HOPS + 1
            or not all(isinstance(t, str) and t for t in raw)
        ):
            return ExchangeExecResult(
                success=False,
                error=f"path is a list of 2 to {MAX_SWAP_HOPS + 1} tokens",
            )
        explicit = [self.canonical_asset(t) for t in raw]
        ends = explicit[0], explicit[-1]
    else:
        ends = self.canonical_asset(p["token_in"]), self.canonical_asset(p["token_out"])
    if explicit is not None and len(set(explicit)) != len(explicit):
        return ExchangeExecResult(success=False, error="a swap path visits each token once")
    if ends[0] == ends[1]:
        return ExchangeExecResult(success=False, error="a swap path visits each token once")
    amount_in = Decimal(str(p["amount_in"]))
    min_out = Decimal(str(p.get("min_amount_out", "0") or "0"))
    deadline = float(p.get("deadline", 0) or 0)
    token_in = ends[0]
    if amount_in <= 0:
        return ExchangeExecResult(success=False, error="amount_in must be positive")
    if deadline > 0 and self._block_clock() > deadline:
        return ExchangeExecResult(success=False, error="Transaction deadline expired")
    avail = self.available_token_balance(tx.sender, token_in)
    if avail is not None and avail < amount_in:
        if self.enforce_spot_settlement:
            return ExchangeExecResult(
                success=False,
                error=f"insufficient token_in: need {amount_in}, available {avail}",
            )
        logger.warning(
            "[Phase E observe] swap by %s: amount_in %s exceeds available %s",
            tx.sender[:20],
            amount_in,
            avail,
        )

    gas_limit = getattr(tx, "gas_limit", None)  # (None: built in process, never in a block)
    venue = str(p.get("venue", "auto")).lower()
    path, planned, error = self.choose_swap_path(
        tx.sender,
        ends[0],
        ends[1],
        amount_in,
        path=explicit,
        pool_id=p.get("pool_id"),
        venue=venue,
        gas_limit=None if gas_limit is None else int(gas_limit),
    )
    if path is None or planned is None:
        hops = len(explicit) - 1 if explicit is not None else 1
        return ExchangeExecResult(
            success=False,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.SWAP] * hops,
            error=error,
        )
    if min_out > 0 and planned[-1].amount_out < min_out:
        return ExchangeExecResult(
            success=False,
            error=f"Slippage exceeded: got {planned[-1].amount_out}, minimum {min_out}",
        )
    # Execute hop by hop, each planned again on what the one before actually bought (a fee
    # tier the first hop's volume crossed can change the next one's fees).
    hops = len(path) - 1
    gas = EXCHANGE_GAS_COSTS[ExchangeOpType.SWAP] * hops
    amount, spent_in = amount_in, ZERO
    routes, fills = [], []
    for i in range(hops):
        makers = (
            None if gas_limit is None else max(0, (int(gas_limit) - gas) // EXCHANGE_GAS_PER_MAKER)
        )
        route = self.router.best_route(
            path[i],
            path[i + 1],
            amount,
            tx.sender,
            pool_id=p.get("pool_id") if hops == 1 else None,
            venue=venue,
            max_makers=makers,
        )
        if route is None:
            error = "No liquidity available for this pair"
            return ExchangeExecResult(
                success=False, gas_used=gas, error=error if hops == 1 else f"hop {i}: {error}"
            )
        try:
            visited, hop_fills = self._swap_hop(tx.sender, route)
        except ValueError as e:
            return ExchangeExecResult(success=False, gas_used=gas, error=str(e))
        gas += self._route_gas(route)
        spent_in = route.amount_in if i == 0 else spent_in
        amount = route.amount_out
        routes.append(route)
        fills += hop_fills
    if min_out > 0 and amount < min_out:  # (undone whole: pools, books and balances)
        return ExchangeExecResult(
            success=False,
            gas_used=gas,
            error=f"Slippage exceeded: got {amount}, minimum {min_out}",
        )

    self._total_swaps += 1
    first = routes[0]
    data: Dict[str, Any] = {
        "amount_in": str(spent_in),
        "amount_out": str(amount),
        "fee_total": str(sum((r.fee_total for r in routes), ZERO)),
        "price": str(spent_in / amount) if amount > 0 else "0",
        "source": first.source.value,
        "pool_id": first.pool_id,
        "fills": fills,
    }
    if hops > 1:
        data["path"] = path
        data["hops"] = [
            {
                "token_in": r.token_in,
                "token_out": r.token_out,
                "amount_in": str(r.amount_in),
                "amount_out": str(r.amount_out),
                "source": r.source.value,
                "pool_id": r.pool_id,
            }
            for r in routes
        ]
    return ExchangeExecResult(success=True, gas_used=gas, data=data)


def _swap_hop(
    self: ExchangeStateManager, sender: str, route, payer: Optional[str] = None
) -> Tuple[int, List[Dict[str, Any]]]:
    """Execute one planned hop — every leg: the order book's, each pool's — and settle each
    with its real counterparty; returns the resting orders it visited and its fills. Raises
    ValueError (its changes undone) if it cannot settle. ``payer``: the protocol holder its
    input comes out of instead of ``sender`` (a TWAP slice's escrow, in the block's tick:
    every debit covered by protocol records)."""
    covered = payer is not None
    pair = route.pair or self._canonical_pair(f"{route.token_in}:{route.token_out}")
    base, quote = pair.split(":", 1)
    legs = route.legs
    engines: List[Any] = [
        self.pool_manager.get_pool(leg.pool_id) for leg in legs if leg.source == FillSource.AMM
    ]
    visited = 0
    fills: List[Dict[str, Any]] = []
    with self._atomic(*[e for e in engines if e is not None]):
        for leg in legs:
            trades, order, leg_visited = self.router.apply_leg(
                route, leg, sender, now=int(self._block_clock())
            )
            if leg.source == FillSource.AMM:
                holder = self.pool_holder_address(leg.pool_id)
                self._settle_token_move(
                    payer or sender, holder, route.token_in, leg.amount_in, covered=covered
                )
                self._settle_token_move(
                    holder, sender, route.token_out, leg.amount_out, covered=covered
                )
                fills.append(self._amm_fill(route, sender, leg))
            else:
                self._settle_orderbook(order, trades, base, quote, pair, payer)
                fills += self._clob_fills(pair, trades, sender, route.side)
                visited += leg_visited
        self._record_spot_prices(pair, route)
        self._flag_self_pass(pair, route)
    return visited, fills


def _flag_self_pass(self: ExchangeStateManager, pair: str, route) -> None:
    """A taker the book closed to at its own resting order (self-trade prevention) may have
    moved a pool past that order: the tick fills it from the pool (``uncross_spot_books``),
    so no arbitrageur can trade against it there."""
    if (
        route is not None
        and route.stopped == "self"
        and any(leg.source == FillSource.AMM for leg in route.legs)
    ):
        self.trading.uncross[pair] = 1


def pair_price(self: ExchangeStateManager, pair: str) -> Optional[Decimal]:
    """A spot pair's price: its last trade, a pool's included; a pair that never traded,
    its deepest pool's (most active liquidity, then the lowest id)."""
    book = self._order_books.get(pair)
    if book is not None and book.last_price:
        return Decimal(str(book.last_price))
    base, quote = pair.split(":", 1) if ":" in pair else (pair, "")
    pools = [p for p in self.pool_manager.get_pools_for_pair(base, quote) if p.state.sqrt_price > 0]
    if not pools:
        return None
    pool = max(pools, key=lambda p: (p.state.liquidity, [-ord(c) for c in p.state.id]))
    return pool.state.price


def pair_quotes(
    self: ExchangeStateManager, pair: str
) -> Tuple[Optional[Decimal], Optional[Decimal]]:
    """A spot pair's best bid and ask now, fees included: the book's displayed top, and
    what each pool pays a seller or charges a buyer at the margin (where its liquidity
    starts). (None, None) sides when nothing quotes."""
    book = self._order_books.get(pair)
    bids = [book.best_bid] if book is not None and book.best_bid is not None else []
    asks = [book.best_ask] if book is not None and book.best_ask is not None else []
    base, quote = pair.split(":", 1)
    for pool in self.pool_manager.get_pools_for_pair(base, quote):
        if pool.is_paused:
            continue
        f = pool.state.fee_tier.rate
        down, up = pool.liquid_sqrt(True), pool.liquid_sqrt(False)
        if down is not None:
            bids.append(down * down * (1 - f))
        if up is not None:
            asks.append(up * up / (1 - f))
    return (max(bids) if bids else None), (min(asks) if asks else None)


def _record_spot_prices(
    self: ExchangeStateManager,
    pair: str,
    route=None,
    prices: Iterable[Decimal] = (),
    buy: Optional[bool] = None,
) -> None:
    """A taker's fills on ``pair`` (a route's legs, and ``prices``: order-book trades): the
    pair's last price is the worst it reached (the highest for a buy), and every spot
    trigger a fill reached is marked so — it fires at the tick even if the price goes back
    (docs/UNIFIED_SPOT_LIQUIDITY.md 5)."""
    seen = [Decimal(str(x)) for x in prices if x]
    if route is not None:
        seen += [leg.price for leg in route.legs if leg.price > 0]
        if buy is None:
            buy = route.side == OrderSide.BUY
    if not seen:
        return
    lo, hi = min(seen), max(seen)
    book = self._order_books.get(pair)
    if book is not None and route is not None:  # (the book's own trades set it already)
        book.record_price(hi if buy else lo)
    if not len(self.trading.spot_triggers):
        return
    from dataclasses import replace

    for tid in dict.fromkeys(self.trading.crossed(pair, lo) + self.trading.crossed(pair, hi)):
        t = self.trading.spot_triggers.peek(tid)
        if t is None or t.reached or t.amount <= 0:  # (an empty bracket protects nothing yet)
            continue
        leg = t.crossed_leg(lo) or t.crossed_leg(hi)
        if leg is not None:
            self.trading.spot_triggers[tid] = replace(t, reached=leg[0])


# A spot trade as the market-data feed sees it (journal.py → market_data.py): the pair in
# canonical "base:quote" order, the price in quote per base, the base amount, and the
# TAKER's side. Result data only — never hashed.
def _clob_fills(pair: str, trades, taker: str, side) -> List[Dict[str, Any]]:
    side = getattr(side, "value", side)
    return [
        {
            "market": pair,
            "venue": "clob",
            "trade_id": t.id,
            "price": str(t.price),
            "amount": str(t.amount),
            "buyer": t.buyer,
            "seller": t.seller,
            "maker": t.seller if t.buyer == taker else t.buyer,
            "taker": taker,
            "side": side,
            "maker_order_id": t.maker_order_id,
            "taker_order_id": t.taker_order_id,
            # Each side's fee, in the asset it received (the buyer's in base).
            "fees": {
                t.buyer: str(t.taker_fee if t.buyer == taker else t.maker_fee),
                t.seller: str(t.taker_fee if t.seller == taker else t.maker_fee),
            },
        }
        for t in trades
    ]


def _amm_fill(self: ExchangeStateManager, route, taker: str, leg=None) -> Dict[str, Any]:
    """One pool's fill (``leg``; none: the route's only one)."""
    leg = leg if leg is not None else route.legs[0]
    pair = self._canonical_pair(f"{route.token_in}:{route.token_out}")
    base = pair.split(":", 1)[0]
    holder = self.pool_holder_address(leg.pool_id)
    if route.token_in == base:  # selling base into the pool
        amount, quote_amount, side = leg.amount_in, leg.amount_out, "sell"
        buyer, seller = holder, taker
    else:
        amount, quote_amount, side = leg.amount_out, leg.amount_in, "buy"
        buyer, seller = taker, holder
    return {
        "market": pair,
        "venue": "amm",
        "pool_id": leg.pool_id,
        "price": str(quote_amount / amount) if amount > 0 else "0",
        "amount": str(amount),
        "quote_amount": str(quote_amount),
        "buyer": buyer,
        "seller": seller,
        "maker": holder,
        "taker": taker,
        "side": side,
    }


def canonical_asset_method(self: ExchangeStateManager, value) -> str:
    """Spot's name for an asset: "QRDX" for native QRDX, a registered token's canonical
    address, anything else as given (qrdx/exchange/tokens.py)."""
    return canonical_asset(value, self.tokens)


def _canonical_pair(self: ExchangeStateManager, pair: str) -> str:
    """Order books (like AMM pools) are keyed by the SORTED pair of canonical asset names —
    create_pool canonicalizes ``token0:token1`` (swaps if token0 > token1). Normalize a
    caller's pair the same way so PLACE_ORDER/CANCEL_ORDER find the book in either input
    order and with any spelling of QRDX or a token address."""
    if ":" in pair:
        a, b = (self.canonical_asset(x) for x in pair.split(":", 1))
        return f"{b}:{a}" if a > b else f"{a}:{b}"
    return pair


def _op_place_order(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    p = tx.params
    pair = self._canonical_pair(p["pair"])
    book = self._order_books.get(pair)
    if book is None:
        return ExchangeExecResult(success=False, error=f"No order book for {pair}")

    # Robust enum parsing: accept string values ("buy") or names ("BUY")
    raw_side = p["side"]
    try:
        side = OrderSide(raw_side)
    except ValueError:
        side = OrderSide[str(raw_side).upper()]

    raw_otype = p["order_type"]
    kind = _TRIGGER_KINDS.get(str(raw_otype).lower())
    if kind is not None:
        return self._place_spot_trigger(tx, pair, book, side, kind)
    try:
        order_type = OrderType(raw_otype)
    except ValueError:
        order_type = OrderType[str(raw_otype).upper()]

    order = Order(
        id=tx.tx_hash()[:16],  # deterministic from tx hash
        owner=tx.sender,
        side=side,
        order_type=order_type,
        price=Decimal(str(p.get("price", "0"))),
        amount=Decimal(str(p["amount"])),
        stop_price=Decimal(str(p["stop_price"])) if p.get("stop_price") else None,
        nonce=_book_nonce(tx),
        tif=str(p.get("tif", "gtc")).lower(),
        hidden=_flag(p, "hidden"),
        display_size=Decimal(str(p.get("display_size", "0"))),
    )

    # Phase E CLOB settlement: reject what we cannot settle BEFORE matching mutates
    # the book (a failed op is NOT reverted — the block continues). Only plain LIMIT
    # orders are settled in this increment; MARKET/STOP need affordability handling
    # not yet built. The worst-case cost (full amount at the limit price) bounds the
    # taker's total outflow (fills at maker prices ≤ limit, + resting escrow), so a
    # taker that affords it can never overdraw.
    base, quote = (pair.split(":", 1) + [""])[:2] if ":" in pair else (pair, "")
    if self.enforce_orderbook_settlement:
        # A market order takes what the book has and never rests: each fill is paid live
        # (a payment its balance cannot cover fails it whole), so there is no worst case to
        # check first — nor any escrow.
        need_token = quote if side == OrderSide.BUY else base
        need_amount = (order.amount * order.price) if side == OrderSide.BUY else order.amount
        avail = self.available_token_balance(tx.sender, need_token)
        if order_type is OrderType.LIMIT and avail is not None and avail < need_amount:
            return ExchangeExecResult(
                success=False,
                error=f"insufficient balance for order: need {need_amount} {need_token[:10]}, "
                f"available {avail}",
            )

    # An attached take-profit / stop-loss (``tp`` / ``sl``: each {trigger_price, price?}) on
    # a buy: a sell trigger — a one-cancels-the-other with both — that starts empty; each
    # fill of this order puts the base it bought (after its fee) into the trigger's escrow.
    # It costs what a trigger costs; the order's matching gets what is left of the gas.
    bracket_gas = 0
    bracket_id = f"{order.id}.b"
    gas_limit = getattr(tx, "gas_limit", None)
    try:
        legs = {
            leg: (p[leg].get("trigger_price"), p[leg].get("price"))
            for leg in ("tp", "sl")
            if isinstance(p.get(leg), dict)
        }
        if any(p.get(leg) is not None and not isinstance(p[leg], dict) for leg in ("tp", "sl")):
            raise ValueError("tp and sl are {trigger_price, price?}")
        builder = self._builder_of(tx, spot=True)
        if builder is not None and legs:
            # (the bracket takes what the order buys: no builder fee can come out of it)
            raise ValueError("a builder fee and an attached TP/SL do not combine on spot")
        if legs:
            if side != OrderSide.BUY:
                raise ValueError("an attached TP/SL protects what a buy order buys")
            makers_tp = _trigger_makers(p.get("tp_sl_max_makers"))
            bracket_gas = (
                EXCHANGE_GAS_COSTS[ExchangeOpType.PLACE_ORDER] + makers_tp * EXCHANGE_GAS_PER_MAKER
            )
            if (
                gas_limit is not None
                and bracket_gas > int(gas_limit) - EXCHANGE_GAS_COSTS[ExchangeOpType.PLACE_ORDER]
            ):
                raise ValueError(f"the attached TP/SL needs {bracket_gas} gas beyond the order's")
            self.trading.spot_triggers[bracket_id] = self._new_spot_trigger(
                tx.sender,
                pair,
                book,
                "sell",
                legs,
                ZERO,
                str(p.get("tp_sl_tif", "gtc")),
                makers_tp,
                parent=order.id,
            )
    except (ValueError, KeyError, ArithmeticError) as e:
        return ExchangeExecResult(success=False, error=str(e))

    makers = match_budget(
        ExchangeOpType.PLACE_ORDER, None if gas_limit is None else gas_limit - bracket_gas
    )
    budget = MatchBudget(makers) if makers is not None else None
    # The pair's combined market (docs/UNIFIED_SPOT_LIQUIDITY.md 3): the pools fill what
    # they price better than the book, within the limit; the book takes the rest, and what
    # is left rests.
    route = self.router.plan_fill(
        pair,
        side == OrderSide.BUY,
        order.amount,
        exact_in=False,
        limit=order.price if order_type is OrderType.LIMIT else None,
        sender=tx.sender,
        max_makers=makers,
    )
    pooled = self._pool_part(route)
    self._flag_self_pass(pair, route)
    if pooled is not None and order.tif == "alo":
        return ExchangeExecResult(success=False, error="post-only order would take from a pool")
    pool_fills: List[Dict[str, Any]] = []
    try:
        with self._atomic(book, *self._pools_of(pooled)):
            if pooled is not None:
                filled, _paid, pool_fills, received = self._fill_from_pools(
                    pair,
                    pooled,
                    tx.sender,
                    tx.sender,
                    covered=False,
                    bracket=bracket_id if bracket_gas else None,
                )
                order.filled += filled
            book.enter_block(self._current_block_height, self._block_clock())
            trades = book.place_order(order, budget=budget)
            if book.__dict__.get("_has_expiring"):  # (it now starts every block)
                self._note_expiring(pair)
            if self.enforce_orderbook_settlement:
                self._settle_orderbook(order, trades, base, quote, pair)
            builder_fee = self._pay_spot_builder(
                tx.sender, builder, trades, base, quote, received if pooled else ()
            )
            self._record_spot_prices(
                pair,
                pooled,
                prices=[tr.price for tr in trades],
                buy=side == OrderSide.BUY,
            )
    except ValueError as e:
        # It pays for the resting orders it visited before failing (a fill-or-kill that
        # could not fill whole), as it would have had it succeeded.
        return ExchangeExecResult(
            success=False,
            error=str(e),
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PLACE_ORDER]
            + (budget.visited if budget is not None else 0) * EXCHANGE_GAS_PER_MAKER,
        )
    data: Dict[str, Any] = {
        "order_id": order.id,
        "trades": len(trades) + len(pool_fills),
        "filled": str(order.filled),
        "fills": pool_fills + self._clob_fills(pair, trades, tx.sender, side),
    }
    if builder is not None:
        data["builder_fee"] = {"builder": builder[0], **builder_fee}
    if bracket_gas:
        bracket = self.trading.spot_triggers.peek(bracket_id)
        if not order.is_active and (bracket is None or bracket.amount <= 0):
            if bracket is not None:  # (an order that bought nothing protects nothing)
                del self.trading.spot_triggers[bracket_id]
        else:
            data["attached"] = bracket_id

    self._total_orders += 1
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PLACE_ORDER]
        + ((budget.visited if budget is not None else 0) + len(pool_fills)) * EXCHANGE_GAS_PER_MAKER
        + (bracket_gas if "attached" in data else 0),
        data=data,
    )


# ── the pools' part of a spot order (docs/UNIFIED_SPOT_LIQUIDITY.md 3–4) ──────────────
def _pool_part(route):
    """A combined route's pool legs alone (None: it has none) — what an order takes from
    the pools before the book matches the rest."""
    if route is None:
        return None
    legs = [leg for leg in route.legs if leg.source == FillSource.AMM]
    if not legs:
        return None
    from dataclasses import replace as _replace

    last = (
        max(leg.price for leg in legs)
        if route.side == OrderSide.BUY
        else min(leg.price for leg in legs)
    )
    return _replace(
        route,
        parts=legs,
        amount_in=sum((leg.amount_in for leg in legs), ZERO),
        amount_out=sum((leg.amount_out for leg in legs), ZERO),
        size=sum((leg.base for leg in legs), ZERO),
        makers=0,
        last_price=last,
    )


def _pools_of(self: ExchangeStateManager, route) -> List[Any]:
    if route is None:
        return []
    return [
        pool
        for pool in (self.pool_manager.get_pool(leg.pool_id) for leg in route.legs)
        if pool is not None
    ]


def _fill_from_pools(
    self: ExchangeStateManager,
    pair: str,
    route,
    owner: str,
    payer: str,
    *,
    covered: bool,
    bracket: Optional[str] = None,
) -> Tuple[Decimal, Decimal, List[Dict[str, Any]], List[Tuple[str, Decimal]]]:
    """Execute a route's pool legs for ``owner`` and settle each with its pool: what it pays
    out of ``payer``, what it buys to ``owner`` — or, for a buy with an attached TP/SL
    (``bracket``), into the bracket's escrow. Returns (base traded, paid in, fills,
    (token, amount) received)."""
    escrow = self.orderbook_escrow_address(pair)
    now = int(self._block_clock())
    base = paid = ZERO
    fills: List[Dict[str, Any]] = []
    received: List[Tuple[str, Decimal]] = []
    for leg in route.legs:
        self.router.apply_leg(route, leg, owner, now=now)
        holder = self.pool_holder_address(leg.pool_id)
        self._settle_token_move(payer, holder, route.token_in, leg.amount_in, covered=covered)
        to = escrow if bracket else owner
        self._settle_token_move(holder, to, route.token_out, leg.amount_out, covered=covered)
        if bracket:
            self._fill_bracket(bracket, leg.amount_out)
        base += leg.base
        paid += leg.amount_in
        fills.append(self._amm_fill(route, owner, leg))
        received.append((route.token_out, leg.amount_out))
    return base, paid, fills, received


def _pay_spot_builder(
    self: ExchangeStateManager,
    taker: str,
    builder: Optional[Tuple[str, Decimal]],
    trades,
    base: str,
    quote: str,
    pooled: Iterable[Tuple[str, Decimal]] = (),
) -> Dict[str, str]:
    """A builder's fee on the fills a spot order took: its rate of what the taker received in
    each (base for a buy, quote for a sell) — a pool's fills (``pooled``: (token, amount)
    received) included — out of it, to the builder. Returns the amounts by asset."""
    paid: Dict[str, Decimal] = {}
    if builder is None:
        return {}
    received = [(token, Decimal(str(value))) for token, value in pooled]
    for tr in trades:
        if taker not in (tr.buyer, tr.seller) or tr.maker_order_id is None:
            continue
        received.append(
            (base, Decimal(str(tr.amount)))
            if tr.buyer == taker
            else (quote, Decimal(str(tr.amount)) * Decimal(str(tr.price)))
        )
    for token, value in received:
        fee = (value * builder[1]).quantize(SPOT_FEE_QUANTUM, rounding=ROUND_DOWN)
        if fee > 0:
            self._settle_token_move(taker, builder[0], token, fee)
            paid[token] = paid.get(token, ZERO) + fee
    return {t: str(v) for t, v in sorted(paid.items())}


# ── spot fees ───────────────────────────────────────────────────────────
def _spot_fee(
    self: ExchangeStateManager, owner: str, is_maker: bool, value: Decimal
) -> Tuple[Decimal, Decimal, str]:
    """(fee, referral reward, referrer) on ``value`` of the asset ``owner`` receives in a
    spot order-book fill: its fee tier's rate (the perps tiers — one tier an account; a
    spot maker pays no less than nothing: its fee and a taker's are in different assets),
    less a referee's discount; the referrer's share of what is left."""
    from ..clearinghouse import (
        REFEREE_DISCOUNT,
        REFERRAL_VOLUME_CAP,
        REFERRER_SHARE,
    )

    ch = self.clearinghouse
    taker, maker = ch.fee_rates(owner)
    rate = max(ZERO, maker) if is_maker else taker
    fee = (value * rate).quantize(SPOT_FEE_QUANTUM, rounding=ROUND_HALF_UP)
    ref = ch.referrals.peek(owner)
    if fee <= 0 or ref is None:
        return fee, ZERO, ""
    if ref.volume < REFERRAL_VOLUME_CAP:
        fee = (fee * (1 - REFEREE_DISCOUNT)).quantize(SPOT_FEE_QUANTUM, rounding=ROUND_HALF_UP)
    reward = (fee * REFERRER_SHARE).quantize(SPOT_FEE_QUANTUM, rounding=ROUND_DOWN)
    return fee, reward, ref.referrer


def _staker_fee_part(token: str, protocol_fee: Decimal) -> Decimal:
    """The stakers' share (STAKER_FEE_SHARE_BPS) of a spot fee the protocol keeps
    (docs/CONSENSUS_ROADMAP.md 6) — in whatever asset it was paid: QRDX is staker income at
    once, another token waits at the fee holder to be sold for QRDX
    (``convert_staker_fees``)."""
    from ... import constants

    if protocol_fee <= 0:
        return ZERO
    share = min(Decimal(1), Decimal(int(constants.STAKER_FEE_SHARE_BPS)) / 10_000)
    return (protocol_fee * share).quantize(SPOT_FEE_QUANTUM, rounding=ROUND_DOWN)


def _accrue_staker_fee(self: ExchangeStateManager, token: str, amount: Decimal) -> None:
    """The stakers' fee share has reached the fee holder: QRDX is this block's staker income;
    another token is recorded for conversion (the record covers the holder's tick-time sale
    of it)."""
    if token == "QRDX":
        self._block_staker_fees += amount
        return
    pending, next_time = self.fee_tokens.get(token, (ZERO, ZERO))
    self.fee_tokens[token] = (pending + amount, next_time)


def move_perps_staker_fees(self: ExchangeStateManager) -> Decimal:
    """At the block's end: the stakers' share of perps fees the clearinghouse withheld moves
    from the perps holder to the fee holder on the ledger (in the perps collateral)."""
    amount = self.clearinghouse.take_staker_fees()
    if amount > 0:
        token = self.canonical_asset(self.perp_collateral_token() or "QRDX")
        if token == "QRDX":
            self._record_balance_delta(self.perps_holder_address(), -amount)
            self._record_balance_delta(STAKER_FEE_HOLDER, amount)
        else:
            self._settle_token_move(
                self.perps_holder_address(), STAKER_FEE_HOLDER, token, amount, covered=True
            )
        self._accrue_staker_fee(token, amount)
    return amount


@_pinned
def convert_staker_fees(self: ExchangeStateManager, now: Decimal) -> List[Dict[str, Any]]:
    """The block's tick for the stakers' fee share in other assets: each token whose attempt
    is due is sold for QRDX through the best route, out of the fee holder — only at no less
    than STAKER_FEE_CONVERT_SLIPPAGE under the TWAP of its deepest QRDX pool over
    STAKER_FEE_TWAP_SECONDS (an attacker must hold a price that long to move the floor): all
    of it, else a quarter, else it waits STAKER_FEE_CONVERT_SECONDS. The QRDX it brings is
    this block's staker income. A token with no QRDX pool, or no TWAP yet, waits."""
    if not len(self.fee_tokens):
        return []
    events: List[Dict[str, Any]] = []
    for token in self._due_fee_tokens(now):
        pending, next_time = self.fee_tokens.peek(token)
        if pending <= 0 or now < next_time:
            continue
        retry = (pending, now + STAKER_FEE_CONVERT_SECONDS)
        ref = self._qrdx_twap(token, int(now))
        sold = None
        if ref is not None and ref > 0:
            for amount in (pending, (pending / 4).quantize(SPOT_FEE_QUANTUM, ROUND_DOWN)):
                if amount <= 0:
                    continue
                sold = self._sell_staker_fee(token, amount, ref, now)
                if sold is not None:
                    break
        if sold is None:
            self.fee_tokens[token] = retry
            continue
        amount_in, amount_out, fills = sold
        left = pending - amount_in
        if left > 0:
            self.fee_tokens[token] = (left, now + STAKER_FEE_CONVERT_SECONDS)
        else:
            del self.fee_tokens[token]
        self._block_staker_fees += amount_out
        events.append(
            {
                "type": "staker_fee_conversion",
                "token": token,
                "sold": str(amount_in),
                "proceeds": str(amount_out),
                "fills": fills,
            }
        )
    return events


def _due_fee_tokens(self: ExchangeStateManager, now: Decimal) -> List[str]:
    """The fee tokens whose conversion attempt is due by ``now``, in token order — from a
    derived index by due time, never committed, kept up to date from the entries changed
    since (as ``TradingState.due_cancels``). A token with no QRDX pool waits there for good:
    visiting every one each block cost 1.9 ms at 10,000 (docs/EXCHANGE_AUDIT.md 9)."""
    import bisect

    entries = tracked(self.fee_tokens)
    index = self.__dict__.get("_fee_index")
    if index is None or entries.__dict__.get("_index_token") is not index["token"]:
        index = {"token": [], "keys": {}, "due": []}
        entries.track_changes()
        entries.take_changes()
        entries.__dict__["_index_token"] = index["token"]
        changed: Iterable[str] = list(dict.keys(entries))
        self.__dict__["_fee_index"] = index
    else:
        changed = entries.take_changes()
    for token in changed:
        old = index["keys"].pop(token, None)
        if old is not None:
            i = bisect.bisect_left(index["due"], old)
            if i < len(index["due"]) and index["due"][i] == old:
                del index["due"][i]
        v = entries.peek(token)
        if v is not None:
            key = (Decimal(v[1]), token)
            bisect.insort(index["due"], key)
            index["keys"][token] = key
    due = index["due"]
    return sorted(t for _at, t in due[: bisect.bisect_right(due, (now, "\U0010ffff"))])


def _qrdx_twap(self: ExchangeStateManager, token: str, now: int) -> Optional[Decimal]:
    """QRDX per ``token`` over STAKER_FEE_TWAP_SECONDS, from its deepest QRDX pool (most
    liquidity, then the lowest id); None without one or without the history."""
    pools = self.pool_manager.get_pools_for_pair(token, "QRDX")
    if not pools:
        return None
    pool = max(pools, key=lambda p: (p.state.liquidity, [-ord(c) for c in p.state.id]))
    price = pool.twap_price(STAKER_FEE_TWAP_SECONDS, now)  # token1 per token0
    if price is None or price <= 0:
        return None
    return price if pool.state.token0 == token else Decimal(1) / price


def _sell_staker_fee(
    self: ExchangeStateManager, token: str, amount: Decimal, ref: Decimal, now: Decimal
):
    """Sell ``amount`` of the fee holder's ``token`` for QRDX if the route pays at least the
    floor; (sold, proceeds, fills), or None (nothing changed)."""
    route = self.router.best_route(
        token, "QRDX", amount, STAKER_FEE_HOLDER, max_makers=STAKER_FEE_CONVERT_MAKERS
    )
    floor = amount * ref * (1 - STAKER_FEE_CONVERT_SLIPPAGE)
    if route is None or route.amount_in != amount or route.amount_out < floor:
        return None
    try:
        with undo.atomic():
            _visited, fills = self._swap_hop(STAKER_FEE_HOLDER, route, payer=STAKER_FEE_HOLDER)
    except Exception as e:  # noqa: BLE001 — deterministic on every node; never fails a block
        logger.warning("staker fee conversion of %s failed: %s", token, e)
        return None
    return route.amount_in, route.amount_out, fills


def staker_fee_holder() -> str:
    """Where the stakers' fee share waits for its epoch's share-out (validator/epoch_state)."""
    return STAKER_FEE_HOLDER


def block_staker_fees(self: ExchangeStateManager) -> Decimal:
    """The stakers' fee income this block took in (logged per block: staker_fee_income)."""
    return self._block_staker_fees


def _settles_in_tier_unit(self: ExchangeStateManager, quote: str) -> bool:
    """A pair quoted in the perps settlement asset: its volume counts toward fee tiers."""
    token = self.perp_collateral_token()
    return bool(token) and self.canonical_asset(token) == quote


def _settle_spot_trade(
    self: ExchangeStateManager,
    tr,
    base: str,
    quote: str,
    taker: str,
    base_src: str,
    quote_src: str,
    covered: bool = False,
    base_to: Optional[str] = None,
) -> Decimal:
    """One spot order-book fill: base seller → buyer, quote buyer → seller, each side
    paying its fee out of what it receives (the buyer in base, the seller in quote) to the
    treasury, less a referrer's share. The debits come from ``base_src`` / ``quote_src``;
    ``base_to``: where the buyer's base goes instead of the buyer (an attached TP/SL's
    escrow). Records the fees on the trade (its ``maker_fee`` / ``taker_fee``, each in the
    asset that side received). Returns the base the buyer received, after its fee."""
    from ... import constants

    treasury = constants.SYSTEM_WALLET_ADDRESSES["TREASURY_MULTISIG"]
    f = Decimal(str(tr.amount))
    notional = f * Decimal(str(tr.price))
    moves = (
        (tr.buyer, base, f, base_src, base_to or tr.buyer),
        (tr.seller, quote, notional, quote_src, tr.seller),
    )
    for owner, token, value, src, dst in moves:
        fee, reward, referrer = self._spot_fee(owner, owner != taker, value)
        self._settle_token_move(src, dst, token, value - fee, covered=covered)
        staker = self._staker_fee_part(token, fee - reward)
        if staker > 0:
            self._settle_token_move(src, STAKER_FEE_HOLDER, token, staker, covered=covered)
            self._accrue_staker_fee(token, staker)
        self._settle_token_move(src, treasury, token, fee - reward - staker, covered=covered)
        if reward > 0:
            self._settle_token_move(src, referrer, token, reward, covered=covered)
        if owner == taker:
            tr.taker_fee = fee
        else:
            tr.maker_fee = fee
        if owner == tr.buyer:
            received = value - fee
    return received


def _bracket_for(self: ExchangeStateManager, tr, taker: str) -> Optional[str]:
    """The TP/SL attached to a fill's BUY order, if it has one: the base it buys goes into
    that bracket's escrow (``_fill_bracket``), not to the buyer."""
    buy_order = tr.taker_order_id if tr.buyer == taker else tr.maker_order_id
    return self.trading.bracket_of(buy_order) if len(self.trading.spot_triggers) else None


def _drop_empty_bracket(self: ExchangeStateManager, order_id: str) -> None:
    """An order cancelled before it bought anything: its attached TP/SL (empty) goes too.
    (One that holds what the order bought stays: it protects that.)"""
    tid = self.trading.bracket_of(order_id) if len(self.trading.spot_triggers) else None
    t = self.trading.spot_triggers.peek(tid) if tid else None
    if t is not None and t.amount <= 0:
        del self.trading.spot_triggers[tid]


def _fill_bracket(self: ExchangeStateManager, tid: str, received: Decimal) -> None:
    from dataclasses import replace

    t = self.trading.spot_triggers.peek(tid)
    self.trading.spot_triggers[tid] = replace(
        t, amount=t.amount + received, escrowed=t.escrowed + received
    )


def _record_spot_volume(self: ExchangeStateManager, trades, quote: str) -> None:
    """After an operation's fills settle (so its quote held throughout): their notional
    counts toward each side's fee tier, if the pair is quoted in the settlement asset."""
    if not self._settles_in_tier_unit(quote):
        return
    for tr in trades:
        notional = Decimal(str(tr.amount)) * Decimal(str(tr.price))
        for owner in (tr.buyer, tr.seller):
            self.clearinghouse._record_volume(owner, notional)


def _settle_orderbook(
    self: ExchangeStateManager,
    order,
    trades,
    base: str,
    quote: str,
    pair: str,
    payer: Optional[str] = None,
) -> None:
    """Settle a CLOB order's matched trades + escrow its resting remainder as real
    token moves (Phase E). Conserves both tokens: each trade moves base seller→buyer
    and quote buyer→seller; the MAKER's side (the resting party) comes from the book
    escrow it funded at placement, the TAKER's (this order's owner) comes live; the
    taker keeps any price improvement automatically (it pays the maker's price, not
    its limit). The resting remainder is escrowed; CANCEL_ORDER refunds it.

    ``payer``: the protocol holder the taker's side comes out of instead (a TWAP slice's
    escrow, in the block's tick); every debit is then covered by escrow records."""
    taker = order.owner
    escrow = self.orderbook_escrow_address(pair)
    covered = payer is not None
    for tr in trades:
        # Taker's side live (or from ``payer``); the resting maker's from the book escrow.
        bracket = self._bracket_for(tr, taker)
        received = self._settle_spot_trade(
            tr,
            base,
            quote,
            taker,
            (payer or taker) if tr.seller == taker else escrow,
            (payer or taker) if tr.buyer == taker else escrow,
            covered,
            base_to=escrow if bracket else None,
        )
        if bracket:
            self._fill_bracket(bracket, received)
    self._record_spot_volume(trades, quote)
    # Escrow this order's UNFILLED remainder (it now rests on the book).
    r = Decimal(str(order.remaining))
    if r > ZERO and order.is_active:
        if order.side == OrderSide.BUY:
            self._settle_token_move(taker, escrow, quote, r * Decimal(str(order.price)))
        else:
            self._settle_token_move(taker, escrow, base, r)


def _op_cancel_order(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    p = tx.params
    order_id = p["order_id"]
    pair = self._canonical_pair(p.get("pair", ""))
    if self._cancel_spot_trigger(tx.sender, str(order_id)):
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.CANCEL_ORDER],
            data={"order_id": order_id, "status": "cancelled"},
        )

    # Search across all books if pair not specified
    if pair and pair in self._order_books:
        books_to_check = [self._order_books[pair]]
    else:
        books_to_check = list(self._order_books.values())

    for book in books_to_check:
        try:
            with self._atomic(book):
                result = book.cancel_order(order_id, caller=tx.sender)
                if result is not None:
                    self._refund_escrow(book, result, Decimal(str(result.remaining)))
                    self._drop_empty_bracket(str(order_id))
        except ValueError as e:
            return ExchangeExecResult(success=False, error=str(e))
        if result is not None:
            return ExchangeExecResult(
                success=True,
                gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.CANCEL_ORDER],
                data={"order_id": order_id, "status": "cancelled"},
            )

    return ExchangeExecResult(success=False, error=f"Order {order_id} not found")


# ── spot trigger orders (qrdx/exchange/trading.py) ──────────────────────
def _place_spot_trigger(
    self: ExchangeStateManager,
    tx: ExchangeTransaction,
    pair: str,
    book: OrderBook,
    side: OrderSide,
    kind: str,
) -> ExchangeExecResult:
    """PLACE_ORDER of a stop_loss / take_profit / oco: a spot trigger, its funds escrowed
    now. ``trigger_price`` (or ``stop_price``) and ``price`` (its limit; none: a market
    order) — an oco's stop leg; an oco's take-profit leg: ``tp_price``, ``tp_limit``.
    ``tif`` gtc or ioc; ``max_makers``: the matching it prepays."""
    p = tx.params
    try:
        makers = _trigger_makers(p.get("max_makers"))
        gas = EXCHANGE_GAS_COSTS[ExchangeOpType.PLACE_ORDER] + makers * EXCHANGE_GAS_PER_MAKER
        if gas > tx.gas_limit:
            raise ValueError(
                f"gas limit {tx.gas_limit} does not cover the trigger's prepaid matching "
                f"({gas})"
            )
        amount = Decimal(str(p["amount"]))
        if not amount.is_finite() or amount <= 0:
            raise ValueError("amount must be positive")
        if amount < book.min_order_size:
            raise ValueError(f"Order amount below minimum ({book.min_order_size})")
        legs = {
            ("sl" if kind == "oco" else kind): (
                p.get("trigger_price", p.get("stop_price", "0")),
                p.get("price"),
            )
        }
        if kind == "oco":
            legs["tp"] = (p.get("tp_price", "0"), p.get("tp_limit"))
        trigger = self._new_spot_trigger(
            tx.sender, pair, book, side.value, legs, amount, str(p.get("tif", "gtc")), makers
        )
        if self.enforce_orderbook_settlement:
            base, quote = pair.split(":", 1)
            self._settle_token_move(
                tx.sender,
                self.orderbook_escrow_address(pair),
                quote if side == OrderSide.BUY else base,
                trigger.escrowed,
            )
    except (ValueError, KeyError, ArithmeticError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    trigger_id = tx.tx_hash()[:16]
    self.trading.spot_triggers[trigger_id] = trigger
    return ExchangeExecResult(
        success=True, gas_used=gas, data={"order_id": trigger_id, "trigger": True}
    )


def _new_spot_trigger(
    self: ExchangeStateManager,
    owner: str,
    pair: str,
    book: OrderBook,
    side: str,
    legs: Dict[str, Tuple[Any, Any]],
    amount: Decimal,
    tif: str,
    makers: int,
    parent: str = "",
):
    """A checked spot trigger: ``legs`` {"sl" | "tp": (trigger price, limit price or
    None)} — both: a one-cancels-the-other. Its escrow is what it may spend: ``amount`` of
    base for a sell, ``amount`` × its highest price of quote for a buy (an attached TP/SL
    starts empty: ``amount`` 0, filled by its order's fills). Refused if the pair's last
    price has already reached a leg."""
    from dataclasses import replace

    from ..trading import SPOT_TRIGGERS_PER_ACCOUNT

    parsed = {}
    for leg, (trigger, limit) in legs.items():
        trigger, limit = Decimal(str(trigger or "0")), Decimal(str(limit or "0"))
        if not trigger.is_finite() or trigger <= 0:
            raise ValueError(f"the {leg} trigger price must be positive")
        if not limit.is_finite() or limit < 0:
            raise ValueError(f"the {leg} limit price must be positive (or none: market)")
        parsed[leg] = (trigger, limit)
    kind = "oco" if len(parsed) == 2 else next(iter(parsed))
    stop = parsed["sl"] if "sl" in parsed else parsed["tp"]
    tp = parsed.get("tp", (ZERO, ZERO)) if kind == "oco" else (ZERO, ZERO)
    tif = str(tif).lower()
    if tif not in ("gtc", "ioc"):
        raise ValueError("a trigger order fires as gtc or ioc")
    if len(self.trading.owned(owner, pair)) >= SPOT_TRIGGERS_PER_ACCOUNT:
        raise ValueError(f"at most {SPOT_TRIGGERS_PER_ACCOUNT} trigger orders per pair")
    trigger = self.trading.new_spot_trigger(
        owner=owner,
        pair=pair,
        side=side,
        kind=kind,
        trigger_price=stop[0],
        amount=amount,
        limit_price=stop[1],
        tif=tif,
        max_makers=makers,
        escrowed=ZERO,
        tp_price=tp[0],
        tp_limit=tp[1],
        parent=parent,
    )
    last = self.pair_price(pair)
    if last and trigger.crossed(last):
        raise ValueError(f"the last price ({last}) has already reached a trigger price")
    return replace(trigger, escrowed=amount * trigger.price if side == "buy" else amount)


def _cancel_spot_trigger(self: ExchangeStateManager, owner: str, trigger_id: str) -> bool:
    """Cancel ``owner``'s spot trigger and hand back its escrow; False if there is none."""
    t = self.trading.spot_triggers.peek(trigger_id)
    if t is None or t.owner != owner:
        return False
    del self.trading.spot_triggers[trigger_id]
    self._refund_trigger(t, t.escrowed)
    return True


def _fired_leg(t, last: Optional[Decimal]):
    """The leg of a spot trigger that fires: the one a trade reached (``reached``), else the
    one the pair's last price is past; None if neither."""
    if t is None:
        return None
    if t.reached:
        for leg in t.legs():
            if leg[0] == t.reached:
                return leg
    return t.crossed_leg(last) if last else None


def _refund_trigger(self: ExchangeStateManager, t, amount: Decimal) -> None:
    if self.enforce_orderbook_settlement and amount > ZERO:
        base, quote = t.pair.split(":", 1)
        self._settle_token_move(
            self.orderbook_escrow_address(t.pair),
            t.owner,
            quote if t.side == "buy" else base,
            amount,
            covered=True,
            release=True,
        )


@_pinned
def fire_spot_triggers(self: ExchangeStateManager, now: Decimal) -> List[Dict[str, Any]]:
    """The block's tick for spot triggers: those a trade reached since they were placed
    (``reached``: even within a block, even if the price went back — a pool's trades
    included), and those the pair's last price is past, fire — the price passed furthest
    first, then the first placed, within the block's limits. A pair whose token is paused
    fires nothing (its triggers wait)."""
    from ..trading import SPOT_TRIGGER_FIRES_PER_BLOCK, SPOT_TRIGGER_MAKERS_PER_BLOCK

    if not len(self.trading.spot_triggers):
        return []
    queue = []
    # Only the pairs that hold triggers (walking every book cost 47 ms a block at 10,000
    # pairs, with one trigger anywhere).
    for pair in self.trading.trigger_pairs():
        if pair not in self._order_books:
            continue
        raw = self._order_books[pair].last_price
        reached = self.trading.reached(pair)
        if (not raw and not reached) or any(
            (t := self.tokens.peek(tok)) is not None and t.paused for tok in pair.split(":", 1)
        ):
            continue
        last = Decimal(str(raw)) if raw else None
        hits = reached + (self.trading.crossed(pair, last) if last else [])
        quotes = None  # (the pair's best bid and ask: once a pair, if a trigger waits)
        for tid in dict.fromkeys(hits):
            t = self.trading.spot_triggers.peek(tid)
            leg = self._fired_leg(t, last)
            if leg is None or t.amount <= 0:  # (an attached TP/SL before its order fills)
                continue
            if t.waiting:  # fired, not filled whole: again once the market is in its band
                band = t.leg_price(leg[1], leg[2])
                if quotes is None:
                    quotes = self.pair_quotes(pair)
                best = quotes[1] if t.side == "buy" else quotes[0]
                if best is None or (best > band if t.side == "buy" else best < band):
                    continue
            passed = abs(last - leg[1]) / last if last else ZERO
            queue.append(((int(t.waiting), -passed, t.seq, tid), pair, tid))
    queue.sort()
    events: List[Dict[str, Any]] = []
    fired = makers = 0
    for _key, pair, tid in queue:
        t = self.trading.spot_triggers.peek(tid)
        if t is None:
            continue
        if (
            fired >= SPOT_TRIGGER_FIRES_PER_BLOCK
            or makers + t.max_makers > SPOT_TRIGGER_MAKERS_PER_BLOCK
        ):
            break
        fired += 1
        makers += t.max_makers
        events.append(self._fire_spot_trigger(pair, tid, t))
    return events


@_pinned
def uncross_spot_books(self: ExchangeStateManager, now: Decimal) -> List[Dict[str, Any]]:
    """The block's tick for resting spot orders a pool's price is past (liquidity added this
    block at a price beyond them: docs/UNIFIED_SPOT_LIQUIDITY.md 4): each, best first, takes
    from the pools up to its limit as a taker would — paying the pools' price out of its
    own escrow, the difference back to its owner. At most SPOT_UNCROSS_ORDERS_PER_BLOCK a
    block; the rest wait for the next."""
    from ..trading import SPOT_UNCROSS_ORDERS_PER_BLOCK

    if not len(self.trading.uncross):
        return []
    events: List[Dict[str, Any]] = []
    done = 0
    for pair in sorted(k for k, _v in self.trading.uncross.peek_items()):
        book = self._order_books.get(pair)
        if book is None:
            del self.trading.uncross[pair]
            continue
        if book.is_paused or any(
            (t := self.tokens.peek(tok)) is not None and t.paused for tok in pair.split(":", 1)
        ):
            continue  # (it waits)
        finished = True
        for buy in (True, False):
            while True:
                if done >= SPOT_UNCROSS_ORDERS_PER_BLOCK:
                    finished = False  # the rest wait for the next block
                    break
                order = self._best_resting(book, buy)
                if order is None:
                    break
                event = self._uncross_order(pair, book, order, buy)
                if event is None:
                    break  # not crossed: neither is anything behind it
                done += 1
                events.append(event)
                if order.is_active:
                    break  # the pools are at its limit now
        if finished:
            del self.trading.uncross[pair]
    return events


def _best_resting(book: OrderBook, bids: bool) -> Optional[Order]:
    """The first resting order on one side in matching priority (best price, displayed
    before hidden, then time)."""
    levels = book._bids if bids else book._asks
    for price in book.level_prices(bids):
        queue = book.fill_queue(levels[price])
        if queue:
            return queue[0][0]
    return None


def _uncross_order(self: ExchangeStateManager, pair: str, book: OrderBook, order: Order, buy: bool):
    """Fill one resting order from the pools up to its limit; its event, or None if no pool
    prices it (or the fill could not settle: it stays as it is)."""
    pooled = self._pool_part(
        self.router.plan_fill(
            pair,
            buy,
            order.remaining,
            exact_in=False,
            limit=order.price,
            sender=order.owner,
            book=False,
        )
    )
    if pooled is None:
        return None
    escrow = self.orderbook_escrow_address(pair)
    quote = pair.split(":", 1)[1]
    bracket = self.trading.bracket_of(order.id) if buy and len(self.trading.spot_triggers) else None
    try:
        with self._atomic(book, *self._pools_of(pooled)):
            filled, paid, fills, _received = self._fill_from_pools(
                pair, pooled, order.owner, escrow, covered=True, bracket=bracket
            )
            book.fill_resting(order.id, filled)
            if buy and self.enforce_orderbook_settlement:
                # Its escrow held its limit price for what filled; it paid the pools' price.
                refund = filled * order.price - paid
                if refund > 0:
                    self._settle_token_move(escrow, order.owner, quote, refund, covered=True)
            self._record_spot_prices(pair, pooled)
    except Exception as e:  # noqa: BLE001 — deterministic on every node; never fails the block
        if not isinstance(e, (ValueError, ArithmeticError)):
            logger.error("uncrossing spot order %s failed unexpectedly: %r", order.id, e)
        return None
    return {
        "type": "spot_uncross",
        "pair": pair,
        "order_id": order.id,
        "owner": order.owner,
        "side": "buy" if buy else "sell",
        "amount": str(filled),
        "paid": str(paid),
        "fills": fills,
        "resting": order.is_active,
    }


def _fire_spot_trigger(self: ExchangeStateManager, pair: str, tid: str, t) -> Dict[str, Any]:
    """Place a reached trigger's order for its owner, settled out of its escrow. A limit
    trigger is gone after it (what it did not use goes back to its owner). A market trigger
    that could not fill whole within its band keeps the rest waiting (``waiting``), its
    escrow with it: it fires again at each tick the pair's price is back within the band —
    a stop never disappears unfilled."""
    book = self._order_books[pair]
    base, quote = pair.split(":", 1)
    escrow = self.orderbook_escrow_address(pair)
    buy = t.side == "buy"
    event: Dict[str, Any] = {"pair": pair, "trigger_id": tid, "owner": t.owner}
    last = Decimal(str(book.last_price)) if book.last_price else None
    leg = self._fired_leg(t, last) or t.legs()[0]
    price = t.leg_price(leg[1], leg[2])
    order = Order(
        id=tid,
        owner=t.owner,
        side=OrderSide.BUY if buy else OrderSide.SELL,
        order_type=OrderType.LIMIT,
        price=price,
        amount=t.amount,
        nonce=0,
        timestamp=0.0,
        tif=t.tif if leg[2] > 0 else "ioc",
    )
    # The pair's combined market: the pools fill what they price better than the book.
    route = self.router.plan_fill(
        pair,
        buy,
        t.amount,
        exact_in=False,
        limit=price,
        sender=t.owner,
        max_makers=t.max_makers,
    )
    pooled = self._pool_part(route)
    pool_fills: List[Dict[str, Any]] = []
    try:
        with self._atomic(*self._pools_of(pooled)):
            del self.trading.spot_triggers[tid]
            used = ZERO
            if pooled is not None:
                filled, used, pool_fills, _received = self._fill_from_pools(
                    pair, pooled, t.owner, escrow, covered=True
                )
                order.filled += filled
            trades = book.place_order(order, protocol=True, budget=MatchBudget(t.max_makers))
            settle = self.enforce_orderbook_settlement
            for tr in trades:
                f = Decimal(str(tr.amount))
                notional = f * Decimal(str(tr.price))
                if settle:  # both sides out of escrow: the maker's order, this trigger's
                    bracket = self._bracket_for(tr, t.owner)
                    received = self._settle_spot_trade(
                        tr,
                        base,
                        quote,
                        t.owner,
                        escrow,
                        escrow,
                        covered=True,
                        base_to=escrow if bracket else None,
                    )
                    if bracket:
                        self._fill_bracket(bracket, received)
                used += notional if buy else f
            if settle:
                self._record_spot_volume(trades, quote)
            if order.is_active:  # resting: it keeps what its remainder escrows
                used += order.remaining * order.price if buy else order.remaining
            waiting = leg[2] <= 0 and order.remaining >= book.min_order_size
            if waiting:  # the rest waits, its escrow with it
                from dataclasses import replace

                self.trading.spot_triggers[tid] = replace(
                    t,
                    amount=order.remaining,
                    escrowed=t.escrowed - used,
                    reached=leg[0],
                    waiting=True,
                )
            else:
                self._refund_trigger(t, t.escrowed - used)
            self._record_spot_prices(pair, pooled, prices=[tr.price for tr in trades], buy=buy)
            self._flag_self_pass(pair, route)
    except Exception as e:  # noqa: BLE001 — deterministic on every node; never fails the block
        if not isinstance(e, (ValueError, ArithmeticError)):
            logger.error("spot trigger %s failed unexpectedly: %r", tid, e)
        try:
            with undo.atomic():
                del self.trading.spot_triggers[tid]
                self._refund_trigger(t, t.escrowed)
        except Exception:  # noqa: BLE001 — it waits (a paused or frozen token)
            return {"type": "spot_trigger_waiting", **event, "reason": str(e)}
        return {"type": "spot_trigger_cancelled", **event, "reason": str(e)}
    return {
        "type": "spot_trigger_fired",
        **event,
        "side": t.side,
        "kind": leg[0],
        "amount": str(t.amount),
        "price": str(price),
        "filled": str(order.filled),
        "waiting": waiting,
        "fills": pool_fills + self._clob_fills(pair, trades, t.owner, t.side),
        "resting": order.is_active,
    }


def _refund_escrow(
    self: ExchangeStateManager,
    book: OrderBook,
    order: Order,
    amount: Decimal,
    covered: bool = False,
) -> None:
    """Phase E CLOB: hand back what ``amount`` of a spot order locked in its book's escrow
    (``amount`` × price of the quote token for a buy, ``amount`` of the base for a sell —
    what it escrowed at placement)."""
    if not self.enforce_orderbook_settlement or amount <= ZERO:
        return
    pair = getattr(book, "pool_id", "") or ""
    base, quote = (pair.split(":", 1) + [""])[:2] if ":" in pair else (pair, "")
    escrow = self.orderbook_escrow_address(pair)
    if order.side == OrderSide.BUY:
        self._settle_token_move(
            escrow,
            order.owner,
            quote,
            amount * Decimal(str(order.price)),
            covered=covered,
            release=True,
        )
    else:
        self._settle_token_move(escrow, order.owner, base, amount, covered=covered, release=True)


def _op_modify_order(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Change a resting spot order in one step: what is left of it (``amount``) and its
    ``price``. A smaller amount at the same price keeps its place in the queue and hands
    back the escrow it no longer needs; any other change cancels it (refunding its escrow)
    and places the new order (escrowing again) — all or nothing."""
    p = tx.params
    pair = self._canonical_pair(p["pair"])
    book = self._order_books.get(pair)
    order = book._orders.get(str(p["order_id"])) if book is not None else None
    if (
        book is None
        or order is None
        or not order.is_active
        or order.owner != tx.sender
        or order.order_type != OrderType.LIMIT
    ):
        return ExchangeExecResult(success=False, error=f"no resting limit order {p['order_id']}")
    amount = Decimal(str(p.get("amount", order.remaining)))
    price = Decimal(str(p.get("price", order.price)))
    if amount <= 0 or price <= 0:
        return ExchangeExecResult(success=False, error="amount and price must be positive")
    if price == order.price and amount < order.remaining:
        freed = order.remaining - amount
        try:
            book.reduce_order(order.id, order.filled + amount, caller=tx.sender)
            self._refund_escrow(book, order, freed)
        except ValueError as e:
            return ExchangeExecResult(success=False, error=str(e))
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.MODIFY_ORDER],
            data={"order_id": order.id, "trades": 0, "filled": "0", "fills": []},
        )
    try:
        cancelled = book.cancel_order(order.id, caller=tx.sender)
        self._refund_escrow(book, cancelled, Decimal(str(cancelled.remaining)))
    except ValueError as e:
        return ExchangeExecResult(success=False, error=str(e))
    replacement_tx = _BatchAction(
        tx.tx_hash(),
        0,
        op_type=ExchangeOpType.PLACE_ORDER,
        sender=tx.sender,
        nonce=0,
        params={},
        gas_limit=tx.gas_limit
        - EXCHANGE_GAS_COSTS[ExchangeOpType.MODIFY_ORDER]
        + EXCHANGE_GAS_COSTS[ExchangeOpType.PLACE_ORDER],
        gas_price=tx.gas_price,
        chain_id=tx.chain_id,
        timestamp=tx.timestamp,
    )
    bracket = self.trading.bracket_of(order.id) if len(self.trading.spot_triggers) else None
    if bracket:  # its attached TP/SL follows it to the replacement
        from dataclasses import replace as _replace

        t = self.trading.spot_triggers.peek(bracket)
        self.trading.spot_triggers[bracket] = _replace(t, parent=replacement_tx.tx_hash()[:16])
    replacement = {
        "pair": pair,
        "side": order.side.value,
        "order_type": "limit",
        "price": str(price),
        "amount": str(amount),
        "tif": "alo" if order.tif == "alo" else "gtc",
        "hidden": order.hidden,
    }
    if order.is_iceberg and order.display_size < amount:
        replacement["display_size"] = str(order.display_size)
    replacement_tx.params = replacement
    placed = self._op_place_order(replacement_tx)
    placed.gas_used += (
        EXCHANGE_GAS_COSTS[ExchangeOpType.MODIFY_ORDER]
        - EXCHANGE_GAS_COSTS[ExchangeOpType.PLACE_ORDER]
    )
    return placed
