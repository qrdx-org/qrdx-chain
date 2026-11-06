"""
Acting for an account (agents, sub-accounts), TWAP orders, batches, cancel-all and the dead
man's switch, builder fees, and the exchange actions of EVM contracts.

These are ExchangeStateManager's methods, written as functions of the manager (``self``) and
bound to it under the same names in qrdx/exchange/state_manager.py. They are here only to keep
that file to a size one can read: read them as the class's.
"""

from __future__ import annotations

import json
import re
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Tuple

from .. import undo
from ..orderbook import (
    _pinned,
)
from ..transactions import (
    EXCHANGE_GAS_COSTS,
    EXCHANGE_GAS_PER_CANCEL,
    EXCHANGE_GAS_PER_MAKER,
    ExchangeOpType,
    ExchangeTransaction,
    batch_actions,
)
from .common import (
    ZERO,
    ExchangeExecResult,
    _BatchAction,
    _EvmAction,
    _flag,
    _id_or_raw,
    _OperationFailed,
    logger,
)

if TYPE_CHECKING:
    from ..state_manager import ExchangeStateManager


# ── acting for an account (qrdx/exchange/trading.py) ───────────────────
def _op_agent_approve(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Approve ``agent`` (a PQ address) to sign trading operations for the account until
    ``valid_until`` (block time; 0 or absent: until revoked); ``name`` labels it.
    Approving it again replaces its approval. Only the account itself may approve."""
    import re

    from ..trading import AGENTS_PER_ACCOUNT, NAME_MAX, AgentGrant

    p = tx.params
    agent = str(p["agent"])
    try:
        if not self._signed_by_account(tx):
            raise ValueError("only the account itself approves agents")
        if self.trading.master_of(tx.sender) is not None:
            raise ValueError("a sub-account's agents are its master's")
        if not re.fullmatch(r"0x[Pp][Qq][0-9a-fA-F]{64}", agent):
            raise ValueError("an agent is a post-quantum (0xPQ…) address")
        if agent.lower() == tx.sender.lower():
            raise ValueError("an account does not approve itself")
        valid_until = Decimal(str(p.get("valid_until", 0) or 0))
        if not valid_until.is_finite() or valid_until < 0:
            raise ValueError("valid_until is a block time (0: until revoked)")
        if 0 < valid_until <= Decimal(str(self._block_clock())):
            raise ValueError("valid_until has already passed")
        name = str(p.get("name", ""))
        if len(name) > NAME_MAX:
            raise ValueError(f"a name is at most {NAME_MAX} characters")
        limit = Decimal(str(p.get("max_notional_per_day", 0) or 0))
        if not limit.is_finite() or limit < 0:
            raise ValueError("max_notional_per_day is an amount (0: no limit)")
    except (ValueError, ArithmeticError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    grants = [g for g in self.trading.agents.peek(tx.sender, ()) if g.agent != agent]
    if len(grants) >= AGENTS_PER_ACCOUNT:
        return ExchangeExecResult(
            success=False, error=f"at most {AGENTS_PER_ACCOUNT} agents per account"
        )
    grant = AgentGrant(agent=agent, valid_until=valid_until, name=name, max_notional_per_day=limit)
    self.trading.agents[tx.sender] = tuple(sorted(grants + [grant], key=lambda g: g.agent))
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.AGENT_APPROVE],
        data={
            "agent": agent,
            "valid_until": str(grant.valid_until),
            "max_notional_per_day": str(limit),
        },
    )


def _op_agent_revoke(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Revoke an agent: it signs nothing more for the account. (An agent may revoke itself.)"""
    agent = str(tx.params["agent"])
    grants = self.trading.agents.peek(tx.sender, ())
    if not any(g.agent == agent for g in grants) or tx.signer not in ("", agent):
        return ExchangeExecResult(success=False, error=f"{agent[:16]}… is not an agent here")
    kept = tuple(g for g in grants if g.agent != agent)
    if kept:
        self.trading.agents[tx.sender] = kept
    else:
        del self.trading.agents[tx.sender]
    self.trading.forget_spend(tx.sender, agent)
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.AGENT_REVOKE],
        data={"agent": agent, "status": "revoked"},
    )


def _op_subaccount_create(
    self: ExchangeStateManager, tx: ExchangeTransaction
) -> ExchangeExecResult:
    """A new sub-account: its own balances, margin account and orders, at an address no key
    controls — the master signs for it (``signer``). Returns its address."""
    from ..trading import NAME_MAX, SUBACCOUNTS_PER_ACCOUNT, SubAccount, subaccount_address

    name = str(tx.params.get("name", ""))
    if not self._signed_by_account(tx):
        return ExchangeExecResult(success=False, error="only the account itself creates one")
    if self.trading.master_of(tx.sender) is not None:
        return ExchangeExecResult(success=False, error="a sub-account has no sub-accounts")
    if len(name) > NAME_MAX:
        return ExchangeExecResult(success=False, error=f"a name is at most {NAME_MAX} characters")
    index = int(self.trading.subaccount_counts.peek(tx.sender, 0))
    if index >= SUBACCOUNTS_PER_ACCOUNT:
        return ExchangeExecResult(
            success=False, error=f"at most {SUBACCOUNTS_PER_ACCOUNT} sub-accounts"
        )
    address = subaccount_address(tx.sender, index)
    self.trading.subaccounts[address] = SubAccount(master=tx.sender, index=index, name=name)
    self.trading.subaccount_counts[tx.sender] = index + 1
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.SUBACCOUNT_CREATE],
        data={"subaccount": address, "index": index},
    )


def _op_subaccount_transfer(
    self: ExchangeStateManager, tx: ExchangeTransaction
) -> ExchangeExecResult:
    """Move ``amount`` of ``asset`` (QRDX or a token) between the master (the sender) and
    one of its sub-accounts: ``direction`` "to_sub" or "from_sub"."""
    p = tx.params
    sub = str(p["subaccount"])
    if not self._signed_by_account(tx) or self.trading.master_of(sub) != tx.sender:
        return ExchangeExecResult(success=False, error=f"{sub[:16]}… is not a sub-account here")
    direction = str(p["direction"])
    if direction not in ("to_sub", "from_sub"):
        return ExchangeExecResult(success=False, error="direction is to_sub or from_sub")
    try:
        amount = Decimal(str(p["amount"]))
        if not amount.is_finite() or amount <= 0:
            raise ValueError("amount must be positive")
        asset = self.canonical_asset(p["asset"])
        frm, to = (tx.sender, sub) if direction == "to_sub" else (sub, tx.sender)
        avail = self.available_token_balance(frm, asset)
        if avail is None or avail < amount:
            raise ValueError(f"insufficient {p['asset']}: need {amount}, available {avail}")
        self._settle_token_move(frm, to, asset, amount)
    except (ValueError, ArithmeticError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.SUBACCOUNT_TRANSFER],
        data={"subaccount": sub, "asset": asset, "amount": str(amount)},
    )


# ── TWAP orders (qrdx/exchange/trading.py) ──────────────────────────────
def _op_twap_order(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """A TWAP: ``duration`` seconds, in ``slices`` (default: one every TWAP_MIN_INTERVAL
    seconds, at most TWAP_MAX_SLICES), each within ``max_slippage``. Perps: ``market_id``,
    ``side``, ``size``, ``reduce_only``. Spot: ``token_in``, ``token_out``, ``amount_in`` —
    escrowed now, swapped slice by slice. Gas: the base, and each slice's work and its
    ``max_makers`` of matching, up front. The first slice runs in this block's tick."""
    from dataclasses import replace

    from ..trading import (
        TWAP_DEFAULT_MAKERS,
        TWAP_DEFAULT_SLIPPAGE,
        TWAP_MAX_DURATION,
        TWAP_MAX_MAKERS,
        TWAP_MAX_SLICES,
        TWAP_MAX_SLIPPAGE,
        TWAP_MIN_DURATION,
        TWAP_MIN_INTERVAL,
        TWAP_SLICE_GAS,
        TWAPS_PER_ACCOUNT,
        Twap,
    )

    p = tx.params
    try:
        duration, slices, makers = (
            p["duration"],
            p.get("slices", min(TWAP_MAX_SLICES, int(p["duration"]) // TWAP_MIN_INTERVAL)),
            p.get("max_makers", TWAP_DEFAULT_MAKERS),
        )
        for name, value in (("duration", duration), ("slices", slices), ("makers", makers)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be a whole number")
        if not TWAP_MIN_DURATION <= duration <= TWAP_MAX_DURATION:
            raise ValueError(f"duration must be {TWAP_MIN_DURATION} to {TWAP_MAX_DURATION} seconds")
        if not 1 <= slices <= TWAP_MAX_SLICES or duration < slices * TWAP_MIN_INTERVAL:
            raise ValueError(
                f"slices must be 1 to {TWAP_MAX_SLICES}, at least {TWAP_MIN_INTERVAL} s apart"
            )
        if not 1 <= makers <= TWAP_MAX_MAKERS:
            raise ValueError(f"max_makers must be 1 to {TWAP_MAX_MAKERS}")
        slippage = Decimal(str(p.get("max_slippage", TWAP_DEFAULT_SLIPPAGE)))
        if not slippage.is_finite() or not ZERO < slippage <= TWAP_MAX_SLIPPAGE:
            raise ValueError(f"max_slippage must be above 0 and at most {TWAP_MAX_SLIPPAGE}")
        gas = EXCHANGE_GAS_COSTS[ExchangeOpType.TWAP_ORDER] + slices * (
            TWAP_SLICE_GAS + makers * EXCHANGE_GAS_PER_MAKER
        )
        if gas > tx.gas_limit:
            raise ValueError(f"a TWAP of {slices} slices needs {gas} gas")
        if len(self.trading.twaps_of(tx.sender)) >= TWAPS_PER_ACCOUNT:
            raise ValueError(f"at most {TWAPS_PER_ACCOUNT} TWAPs per account")
        perp = "market_id" in p
        if perp:
            market = str(p["market_id"])
            if market not in self.clearinghouse.markets:
                raise ValueError(f"market {market} not found")
            if self.clearinghouse.markets[market].settled_price > 0:
                raise ValueError(f"{market} is delisted")
            side = str(p["side"]).lower()
            side = {"long": "buy", "bid": "buy", "short": "sell", "ask": "sell"}.get(side, side)
            if side not in ("buy", "sell"):
                raise ValueError(f"unknown side {p['side']!r}")
            total = Decimal(str(p["size"]))
            token_in = token_out = ""
            self._trade_leverage(tx.sender, market, p)  # its slices trade at it
        else:
            token_in = self.canonical_asset(p["token_in"])
            token_out = self.canonical_asset(p["token_out"])
            if token_in == token_out:
                raise ValueError("token_in and token_out are the same")
            market = self._canonical_pair(f"{token_in}:{token_out}")
            if market not in self._order_books and not self.pool_manager.get_pools_for_pair(
                token_in, token_out
            ):
                raise ValueError(f"no market for {market}")
            side = "sell" if token_in == market.split(":", 1)[0] else "buy"
            total = Decimal(str(p["amount_in"]))
        if not total.is_finite() or total <= 0:
            raise ValueError("the size must be positive")
        twap = Twap(
            owner=tx.sender,
            market=market,
            perp=perp,
            side=side,
            token_in=token_in,
            token_out=token_out,
            total=total,
            done=ZERO,
            received=ZERO,
            slices=slices,
            slices_done=0,
            interval=Decimal(duration) / slices,
            next_time=Decimal(str(self._block_clock())),
            reduce_only=_flag(p, "reduce_only") if perp else False,
            max_slippage=slippage,
            max_makers=makers,
            seq=0,
        )
        if not perp:  # what it will spend, escrowed for the tick to swap
            self._settle_token_move(
                tx.sender, self.orderbook_escrow_address(market), token_in, total
            )
    except (ValueError, KeyError, TypeError, ArithmeticError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    twap_id = tx.tx_hash()[:16]
    self.trading.twaps[twap_id] = replace(twap, seq=self.trading.next_seq())
    return ExchangeExecResult(success=True, gas_used=gas, data={"twap_id": twap_id})


def _op_twap_cancel(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    if not self._cancel_twap(tx.sender, str(tx.params["twap_id"])):
        return ExchangeExecResult(success=False, error=f"no TWAP {tx.params['twap_id']}")
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.TWAP_CANCEL],
        data={"twap_id": tx.params["twap_id"], "status": "cancelled"},
    )


def _cancel_twap(self: ExchangeStateManager, owner: str, twap_id: str) -> bool:
    """Stop ``owner``'s TWAP; a spot TWAP's unspent escrow goes back (covered by the TWAP's
    own record of it). False if there is none."""
    t = self.trading.twaps.peek(twap_id)
    if t is None or t.owner != owner:
        return False
    del self.trading.twaps[twap_id]
    if not t.perp and t.remaining > 0:
        self._settle_token_move(
            self.orderbook_escrow_address(t.market),
            t.owner,
            t.token_in,
            t.remaining,
            covered=True,
            release=True,
        )
    return True


@_pinned
def run_twaps(
    self: ExchangeStateManager, now: Decimal, liquidations: Iterable[Dict[str, Any]] = ()
) -> List[dict]:
    """The block's tick for TWAPs: an account just liquidated loses its perp TWAPs in those
    markets; then each TWAP whose slice is due runs one, the longest due first, within the
    block's limits."""
    from ..trading import TWAP_MAKERS_PER_BLOCK, TWAP_SLICES_PER_BLOCK

    if not len(self.trading.twaps):
        return []
    events: List[dict] = []
    for ev in liquidations:
        if ev.get("type") != "liquidation":
            continue
        for tid in self.trading.twaps_of(ev["owner"]):
            t = self.trading.twaps.peek(tid)
            if t.perp and t.market in ev.get("markets", ()):
                self._cancel_twap(t.owner, tid)
                events.append(
                    {"type": "twap_finished", **self._twap_view(tid, t), "reason": "liquidated"}
                )
    ran = makers = 0
    for tid in self.trading.due_twaps(now):
        t = self.trading.twaps.peek(tid)
        if ran >= TWAP_SLICES_PER_BLOCK or makers + t.max_makers > TWAP_MAKERS_PER_BLOCK:
            break
        ran += 1
        makers += t.max_makers
        events += self._twap_slice(tid, t)
    return events


def _twap_view(tid: str, t) -> Dict[str, Any]:
    return {
        "twap_id": tid,
        "owner": t.owner,
        "market": t.market,
        "side": t.side,
        "total": str(t.total),
        "done": str(t.done),
        "received": str(t.received),
        "slices": t.slices,
        "slices_done": t.slices_done,
    }


def _twap_slice(self: ExchangeStateManager, tid: str, t) -> List[dict]:
    """Run one slice — an IOC of the slice's size within the TWAP's slippage of the price
    now — and move the TWAP on; the last slice (or one that finds nothing left to do)
    finishes it. Never fails the block: a slice that cannot run fills nothing."""
    from dataclasses import replace

    size = t.slice_size()
    filled = got = ZERO
    fills: List[dict] = []
    reason = ""
    try:
        if t.perp:
            filled, got, fills, reason = self._perp_twap_slice(tid, t, size)
        else:
            filled, got, fills, reason = self._spot_twap_slice(t, size)
    except Exception as e:  # noqa: BLE001 — deterministic on every node; never fails the block
        if not isinstance(e, (ValueError, ArithmeticError)):
            logger.error("TWAP %s slice failed unexpectedly: %r", tid, e)
        filled, got, fills, reason = ZERO, ZERO, [], str(e)
    moved = replace(
        t,
        done=t.done + filled,
        received=t.received + got,
        slices_done=t.slices_done + 1,
        next_time=t.next_time + t.interval,
    )
    events = [
        {
            "type": "twap_slice",
            **self._twap_view(tid, moved),
            "filled": str(filled),
            "fills": fills,
            **({"reason": reason} if reason else {}),
        }
    ]
    finished = moved.slices_done >= moved.slices or moved.remaining <= 0
    if reason == "no position to reduce":
        finished = True
    self.trading.twaps[tid] = moved
    if finished:
        try:
            with undo.atomic():
                self._cancel_twap(moved.owner, tid)
        except Exception as e:  # noqa: BLE001 — a paused token: it finishes once it can
            events.append({"type": "twap_waiting", **self._twap_view(tid, moved), "reason": str(e)})
        else:
            events.append({"type": "twap_finished", **self._twap_view(tid, moved)})
    return events


def _perp_twap_slice(self: ExchangeStateManager, tid: str, t, size: Decimal):
    from ..clearinghouse import ENTRY_QUANTUM

    m = self.clearinghouse.markets.get(t.market)
    if m is None or m.mark_price <= 0:
        return ZERO, ZERO, [], "the market has no price"
    if not t.reduce_only and self._perp_oracle_stale(m):
        return ZERO, ZERO, [], "the oracle is stale"
    buy = t.side == "buy"
    if t.reduce_only:
        acct = self.clearinghouse.accounts.peek(t.owner)
        pos = acct.positions.get(t.market) if acct is not None else None
        held = pos.size if pos is not None else ZERO
        if held == 0 or (held > 0) == buy:
            return ZERO, ZERO, [], "no position to reduce"
        size = min(size, abs(held))
    price = (m.mark_price * (1 + t.max_slippage if buy else 1 - t.max_slippage)).quantize(
        ENTRY_QUANTUM, rounding=ROUND_FLOOR if buy else ROUND_CEILING
    )
    fills, _cancelled = self.clearinghouse.protocol_ioc(
        t.owner,
        t.market,
        f"{tid}.{t.slices_done}",
        t.side,
        size,
        price,
        reduce_only=t.reduce_only,
        max_makers=t.max_makers,
    )
    filled = sum((Decimal(f["amount"]) for f in fills), ZERO)
    notional = sum((Decimal(f["amount"]) * Decimal(f["price"]) for f in fills), ZERO)
    return filled, notional, fills, ""


def _spot_twap_slice(self: ExchangeStateManager, t, size: Decimal):
    """A swap of ``size`` out of the TWAP's escrow, through the best venue, refused if its
    price is more than ``max_slippage`` worse than the marginal price (a thousandth of the
    slice's quote)."""
    route = self.router.best_route(t.token_in, t.token_out, size, t.owner, max_makers=t.max_makers)
    probe = self.router.best_route(t.token_in, t.token_out, size / 1000, t.owner)
    if route is None or probe is None or probe.amount_in <= 0:
        return ZERO, ZERO, [], "no liquidity"
    marginal = probe.amount_out / probe.amount_in
    if route.amount_out < route.amount_in * marginal * (1 - t.max_slippage):
        return ZERO, ZERO, [], "beyond its slippage"
    _visited, fills = self._swap_hop(t.owner, route, payer=self.orderbook_escrow_address(t.market))
    return route.amount_in, route.amount_out, fills, ""


def _op_approve_builder_fee(
    self: ExchangeStateManager, tx: ExchangeTransaction
) -> ExchangeExecResult:
    """Let ``builder`` (a front-end) charge up to ``max_fee_rate`` of the notional of the fills
    orders it routes take (0: revoke). Signed by the account itself, never an agent."""
    from ..trading import BUILDER_FEE_MAX_SPOT

    p = tx.params
    builder = str(p["builder"])
    try:
        if not self._signed_by_account(tx):
            raise ValueError("only the account itself approves a builder")
        if not re.fullmatch(r"0x([Pp][Qq])?[0-9a-fA-F]{40}([0-9a-fA-F]{24})?", builder):
            raise ValueError("a builder is an address")
        if _id_or_raw(builder) == _id_or_raw(tx.sender):
            raise ValueError("an account does not approve itself")
        rate = Decimal(str(p["max_fee_rate"]))
        if not rate.is_finite() or not ZERO <= rate <= BUILDER_FEE_MAX_SPOT:
            raise ValueError(f"max_fee_rate is 0 to {BUILDER_FEE_MAX_SPOT}")
    except (ValueError, ArithmeticError) as e:
        return ExchangeExecResult(success=False, error=str(e))
    key = f"{_id_or_raw(tx.sender)}|{_id_or_raw(builder)}"
    if rate == 0:
        if key in self.trading.builder_approvals:
            del self.trading.builder_approvals[key]
    else:
        self.trading.builder_approvals[key] = str(rate)
    return ExchangeExecResult(
        success=True,
        gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.APPROVE_BUILDER_FEE],
        data={"builder": builder, "max_fee_rate": str(rate)},
    )


def _builder_of(
    self: ExchangeStateManager, tx: ExchangeTransaction, spot: bool
) -> Optional[Tuple[str, Decimal]]:
    """An order's builder code (``builder: {b, f}``) — checked against the account's
    approval and the cap; None without one. ValueError if it is not allowed."""
    from ..trading import BUILDER_FEE_MAX_PERP, BUILDER_FEE_MAX_SPOT

    raw = tx.params.get("builder")
    if raw is None:
        return None
    if not isinstance(raw, dict) or "b" not in raw or "f" not in raw:
        raise ValueError("builder is {b: address, f: fee rate}")
    builder, rate = str(raw["b"]), Decimal(str(raw["f"]))
    cap = BUILDER_FEE_MAX_SPOT if spot else BUILDER_FEE_MAX_PERP
    if not rate.is_finite() or not ZERO < rate <= cap:
        raise ValueError(f"a builder fee is above 0 and at most {cap}")
    approved = (
        self.trading.builder_approvals.peek(f"{_id_or_raw(tx.sender)}|{_id_or_raw(builder)}")
        if len(self.trading.builder_approvals)
        else None
    )
    if approved is None or rate > Decimal(approved):
        raise ValueError(f"the account has not approved {builder[:16]}… for that fee")
    return builder, rate


def _op_cancel_all(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Every resting order and trigger of the sender — spot (escrow refunded), perps, or
    both (``scope``), or those of one ``market`` (a pair or a perp market id). Each one
    cancelled costs EXCHANGE_GAS_PER_CANCEL; a gas limit that does not cover them all
    cancels none."""
    p = tx.params
    count = self._cancel_all_of(tx.sender, p.get("scope", "all"), p.get("market"))
    gas = EXCHANGE_GAS_COSTS[ExchangeOpType.CANCEL_ALL] + count * EXCHANGE_GAS_PER_CANCEL
    if gas > tx.gas_limit:
        return ExchangeExecResult(
            success=False,
            gas_used=tx.gas_limit,
            error=f"cancelling {count} orders needs {gas} gas; the limit is {tx.gas_limit}",
        )
    return ExchangeExecResult(success=True, gas_used=gas, data={"cancelled": count})


def _cancel_all_of(
    self: ExchangeStateManager,
    owner: str,
    scope: str = "all",
    market: Any = None,
    covered: bool = False,
) -> int:
    """Every resting order, trigger and TWAP of ``owner`` in ``scope`` (or one ``market``);
    spot escrow refunded (``covered``: out of the books' own records — in the tick, where no
    balance is loaded). Returns how many."""
    count = 0
    if scope in ("all", "spot") and (market is None or ":" in str(market)):
        pairs = sorted(self._order_books)
        if market is not None:
            pairs = [k for k in pairs if k == self._canonical_pair(str(market))]
        for pair in pairs:
            for tid in self.trading.owned(owner, pair):
                count += self._cancel_spot_trigger(owner, tid)
            book = self._order_books[pair]
            if not book._owner_order_count.get(owner) and not any(
                o.owner == owner for o in book._stop_orders.values()
            ):
                continue
            mine = sorted(
                oid
                for index in (book._orders, book._stop_orders)
                for oid, o in index.items()
                if o.owner == owner
            )
            for oid in mine:
                stop = oid in book._stop_orders  # (a stop order escrowed nothing)
                cancelled = book.cancel_order(oid, caller=owner)
                if cancelled is not None:
                    count += 1
                    if not stop:
                        self._refund_escrow(book, cancelled, cancelled.remaining, covered=covered)
    if scope in ("all", "perps") and (market is None or ":" not in str(market)):
        if market is None or str(market) in self.clearinghouse.markets:
            count += self.clearinghouse.cancel_all(owner, None if market is None else str(market))
    wanted = None if market is None else str(market)
    if wanted is not None and ":" in wanted:
        wanted = self._canonical_pair(wanted)
    for tid in self.trading.twaps_of(owner):  # and its TWAPs, by the same filter
        t = self.trading.twaps.peek(tid)
        if (scope == "all" or (scope == "perps") == t.perp) and wanted in (None, t.market):
            count += self._cancel_twap(owner, tid)
    return count


def _op_schedule_cancel(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Hyperliquid's dead man's switch: at block time ``time`` every order, trigger and TWAP
    of the sender is cancelled — unless it schedules again or clears it first (no ``time``).
    At least CANCEL_MIN_DELAY ahead; at most CANCEL_TRIGGERS_PER_DAY may fire a block day."""
    from ..trading import CANCEL_MIN_DELAY, CANCEL_TRIGGERS_PER_DAY

    now = Decimal(str(self._block_clock()))
    day = int(now // 86400)
    _t, d, fired = self.trading.cancel_at.get(tx.sender, (ZERO, day, 0))
    fired = fired if d == day else 0
    raw = tx.params.get("time")
    if raw is None:
        if tx.sender in self.trading.cancel_at:
            del self.trading.cancel_at[tx.sender]
        data: Dict[str, Any] = {"cleared": True}
    else:
        try:
            when = Decimal(str(raw))
        except (ArithmeticError, ValueError):
            return ExchangeExecResult(success=False, error="time is a block time")
        if not when.is_finite() or when < now + CANCEL_MIN_DELAY:
            return ExchangeExecResult(
                success=False, error=f"time must be at least {CANCEL_MIN_DELAY} s ahead"
            )
        if fired >= CANCEL_TRIGGERS_PER_DAY:
            return ExchangeExecResult(
                success=False,
                error=f"at most {CANCEL_TRIGGERS_PER_DAY} scheduled cancels fire a day",
            )
        self.trading.cancel_at[tx.sender] = (when, day, fired)
        data = {"time": str(when)}
    return ExchangeExecResult(
        success=True, gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.SCHEDULE_CANCEL], data=data
    )


@_pinned
def run_scheduled_cancels(self: ExchangeStateManager, now: Decimal) -> List[Dict[str, Any]]:
    """The block's tick for scheduled cancels: each due account's orders, triggers and TWAPs
    are cancelled (at most CANCELS_PER_BLOCK accounts a block; the rest wait one)."""
    from ..trading import CANCELS_PER_BLOCK

    events: List[Dict[str, Any]] = []
    for owner in self.trading.due_cancels(now)[:CANCELS_PER_BLOCK]:
        when, day, fired = self.trading.cancel_at[owner]
        today = int(now // 86400)
        try:
            with undo.atomic():
                count = self._cancel_all_of(owner, covered=True)
        except Exception as e:  # noqa: BLE001 — deterministic; never fails the block
            logger.warning("scheduled cancel of %s failed: %s", owner, e)
            count = 0
        self.trading.cancel_at[owner] = (ZERO, today, (fired if day == today else 0) + 1)
        events.append(
            {"type": "scheduled_cancel", "owner": owner, "time": str(when), "cancelled": count}
        )
    return events


# ── exchange actions of EVM contracts (qrdx/contracts/exchange_evm.py) ──
def queue_evm_actions(self: ExchangeStateManager, actions: List[Tuple[str, str, str, int]]) -> None:
    """An accepted EVM section's exchange actions — (contract, operation, params JSON,
    exchange gas limit), in the order its transactions sent them — queued for the start of
    the next block. Called as the section commits, inside the block being processed (its
    height keys them)."""
    if not actions:
        return
    prefix = f"{int(self._current_block_height):012d}:"
    q = self.trading.evm_actions
    start = sum(1 for k, _v in q.peek_items() if k.startswith(prefix))
    for i, (sender, op, params, gas) in enumerate(actions, start):
        q[f"{prefix}{i:05d}"] = (str(sender), str(op), str(params), int(gas))


def _queued_evm_actions(self: ExchangeStateManager) -> List[Tuple[str, ExchangeTransaction]]:
    from ..trading import EVM_ACTIONS_PER_BLOCK

    q = self.trading.evm_actions
    if not len(q):
        return []
    out: List[Tuple[str, ExchangeTransaction]] = []
    for key, (sender, op, params, gas) in sorted(q.peek_items())[:EVM_ACTIONS_PER_BLOCK]:
        try:
            decoded = json.loads(params)
        except ValueError:
            decoded = {}
        op_type = ExchangeOpType[op]
        action = _EvmAction(
            key,
            op_type=op_type,
            sender=sender,
            nonce=0,
            params=decoded if isinstance(decoded, dict) else {},
            gas_limit=int(gas),
            gas_price=0,
            timestamp=1.0,
        )
        out.append((key, action))
    return out


def evm_action_txs(self: ExchangeStateManager) -> List[ExchangeTransaction]:
    """The queued actions the next block runs, as the operations they are, oldest first
    (what the block's balance preloads must cover)."""
    return [action for _key, action in self._queued_evm_actions()]


@_pinned
def run_evm_actions(self: ExchangeStateManager) -> List[Dict[str, Any]]:
    """The start of a block, before its transactions: the actions EVM contracts sent in the
    blocks before, each as an operation of its contract's account, all or nothing (one that
    fails changes nothing; it was checked to be well formed when it was sent). At most
    EVM_ACTIONS_PER_BLOCK; the rest wait a block."""
    events: List[Dict[str, Any]] = []
    for key, action in self._queued_evm_actions():
        del self.trading.evm_actions[key]
        try:
            with self.atomic():
                result = self._execute_op(action)
                if not result.success:
                    raise _OperationFailed(result)
        except _OperationFailed as refused:
            result = refused.result
        except Exception as e:  # noqa: BLE001 — deterministic; never fails the block
            logger.warning("EVM action %s of %s failed: %s", key, action.sender, e)
            result = ExchangeExecResult(success=False, error=str(e) or type(e).__name__)
        # Its receipt, fills and order history in the node's journal, under its own hash.
        action.gas_used = result.gas_used = min(
            int(action.gas_limit), int(result.gas_used or action.gas_limit)
        )
        action.success, action.result, action.error = result.success, result.data, result.error
        self._block_exchange_txs.append(action)
        self._block_results.append(result)
        events.append(
            {
                "type": "evm_action",
                "key": key,
                "owner": action.sender,
                "op": action.op_type.name,
                "success": result.success,
                "error": result.error,
                "id": action.tx_hash()[:16],
                **({"data": result.data} if result.success and result.data else {}),
            }
        )
    return events


def _op_batch(self: ExchangeStateManager, tx: ExchangeTransaction) -> ExchangeExecResult:
    """Run the actions in order as the sender, all or nothing: the first that fails fails
    the batch, and the operation's undo scope puts back everything before it. Gas: the
    batch's own plus each action's, within the batch's gas limit — an action may use what
    the earlier ones left."""
    batch_hash = tx.tx_hash()
    used = EXCHANGE_GAS_COSTS[ExchangeOpType.BATCH]
    results = []
    for i, (op, params) in enumerate(batch_actions(tx.params)):
        action = _BatchAction(
            batch_hash,
            i,
            op_type=op,
            sender=tx.sender,
            nonce=0,
            params=params,
            gas_limit=max(0, tx.gas_limit - used),
            gas_price=tx.gas_price,
            chain_id=tx.chain_id,
            timestamp=tx.timestamp,
        )
        base = EXCHANGE_GAS_COSTS[op]
        if action.gas_limit < base:
            return ExchangeExecResult(
                success=False,
                gas_used=tx.gas_limit,
                error=f"action {i} ({op.name}): out of gas",
            )
        try:
            result = self._execute_op(action)
        except (ValueError, KeyError, TypeError, ArithmeticError) as e:
            result = ExchangeExecResult(success=False, error=str(e) or type(e).__name__)
        used += result.gas_used or base
        if used > tx.gas_limit:
            return ExchangeExecResult(
                success=False, gas_used=tx.gas_limit, error=f"action {i}: out of gas"
            )
        if not result.success:
            return ExchangeExecResult(
                success=False,
                gas_used=used,
                error=f"action {i} ({op.name}): {result.error}",
            )
        results.append({"op": op.name, "order_id": action.tx_hash()[:16], **result.data})
    return ExchangeExecResult(success=True, gas_used=used, data={"results": results})
