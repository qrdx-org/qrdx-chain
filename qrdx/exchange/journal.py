"""
The exchange journal — what each committed block did, for wallets, the API and the streams.

* **Receipts:** one per executed exchange transaction (success or failure, its error, the
  operation's result data — an order's id and fills, a deposit's new collateral, …), keyed by
  transaction hash. Exchange transactions are admitted to a mempool and execute only when a
  block includes them; the receipt is how a wallet learns what happened.
* **Events:** a sequenced feed of perps fills (including liquidation and trigger fills),
  liquidations, trigger orders that fired or were cancelled, and funding settlements.
* **Market data** (``self.market``, qrdx/exchange/market_data.py): every trade on every market —
  spot order-book fills, AMM swaps and perps fills — with candles and 24-hour statistics.

This is NOT consensus state: it is never hashed, and it is recorded only when a block commits (a
reverted block leaves nothing behind). It follows the canonical chain: a reorg undoes the
orphaned blocks (``rollback_to``) before the new branch is applied, and a restart loads it with
the persisted exchange checkpoint (qrdx/derived_state_rebuild.py). Bounded: the oldest receipts
and events fall off.
"""

from __future__ import annotations

import os
from collections import OrderedDict, deque
from decimal import Decimal
from typing import Any, Deque, Dict, Iterable, List, Optional

from .clearinghouse import VAULT as VAULT_OWNER
from .market_data import MarketData

MAX_RECEIPTS = 50_000
MAX_EVENTS = 10_000
# Blocks of trading history waiting for the history indexer (qrdx/trading_history.py) to write
# them to the database; the oldest are dropped beyond this (the indexer has stopped).
MAX_HISTORY_OUTBOX = 50_000
# Operations whose receipts are orders' history (placed, changed, cancelled), and the param
# naming their market.
_ORDER_OPS = {
    "PLACE_ORDER": "placed",
    "PERP_ORDER": "placed",
    "PERP_TRIGGER": "placed",
    "TWAP_ORDER": "placed",
    "CANCEL_ORDER": "cancelled",
    "PERP_CANCEL": "cancelled",
    "TWAP_CANCEL": "cancelled",
    "MODIFY_ORDER": "modified",
    "PERP_MODIFY": "modified",
    "CANCEL_ALL": "cancel_all",
}


def _history_enabled() -> bool:
    """The trading history indexer runs (QRDX_TRADING_HISTORY, on by default): otherwise the
    journal keeps no rows for it."""
    return os.getenv("QRDX_TRADING_HISTORY", "1").strip().lower() not in ("0", "false", "no", "off")


def jsonable(value: Any) -> Any:
    """Decimals as strings, recursively — everything the journal hands out is JSON-safe."""
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    if isinstance(value, bytes):
        return value.hex()
    return value


class ExchangeJournal:
    def __init__(self, max_receipts: int = MAX_RECEIPTS, max_events: int = MAX_EVENTS):
        self.max_receipts = max_receipts
        self.receipts: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self.events: Deque[Dict[str, Any]] = deque(maxlen=max_events)
        self.seq = 0  # last event sequence number (monotonic per journal)
        self.market = MarketData()
        self.height = -1  # the last block recorded
        # The trading history's rows by block, until the history indexer writes them; and the
        # height a reorg cut the history back to (the indexer deletes what is above it first).
        self.history_outbox: "OrderedDict[int, Dict[str, Any]]" = OrderedDict()
        self.history_cut: Optional[int] = None
        self._history: Dict[str, List[Dict[str, Any]]] = {}

    # ── recording (at block commit) ────────────────────────────────────

    def record_block(
        self,
        height: int,
        timestamp: float,
        txs: Iterable,
        results: Iterable,
        tick_events: Iterable[Dict[str, Any]],
        samples: Iterable[Dict[str, Any]] = (),
    ) -> None:
        self.height = max(self.height, int(height))
        when: Dict[str, Any] = {"block_height": int(height), "block_time": float(timestamp)}
        self._history = {"trades": [], "orders": [], "funding": [], "samples": list(samples)}
        history_time = float(timestamp)
        for tx, result in zip(txs, results, strict=False):
            tx_hash = tx.tx_hash()
            data = jsonable(getattr(result, "data", {}) or {})
            self.receipts[tx_hash] = {
                "tx_hash": tx_hash,
                **when,
                "op": tx.op_type.name,
                "sender": tx.sender,
                "nonce": tx.nonce,
                "success": bool(result.success),
                "error": result.error or "",
                "gas_used": int(result.gas_used or 0),
                "gas_price": int(getattr(tx, "gas_price", 0) or 0),  # wei per gas
                "fee": str(getattr(result, "fee", 0) or 0),  # QRDX, burned
                "data": data,
            }
            self.receipts.move_to_end(tx_hash)
            while len(self.receipts) > self.max_receipts:
                self.receipts.popitem(last=False)
            if result.success:
                self._record_fills(tx.op_type.name, data, when, tx_hash, tx.sender)
            self._history_orders(tx, result, data, tx_hash)
        for ev in tick_events or ():
            ev = jsonable(ev)
            self._history_tick(ev)
            if ev.get("type") == "trigger_fired":
                fills = ev.pop("fills", [])
                self._event("trigger_fired", when, **{k: v for k, v in ev.items() if k != "type"})
                for fill in fills:
                    self._event(
                        "fill",
                        when,
                        tx_hash=None,
                        order_id=ev.get("trigger_id"),
                        taker=ev.get("owner"),
                        liquidation=False,
                        **fill,
                    )
                    self._perp_trade(fill, when, None, ev.get("owner"), kind="trigger")
            elif ev.get("type") == "spot_trigger_fired":
                fills = ev.pop("fills", [])
                self._event(
                    "spot_trigger_fired", when, **{k: v for k, v in ev.items() if k != "type"}
                )
                self._record_fills(
                    "PLACE_ORDER", {"fills": fills}, when, None, ev.get("owner"), kind="trigger"
                )
            elif ev.get("type") in ("spot_trigger_cancelled", "spot_trigger_waiting"):
                self._event(ev["type"], when, **{k: v for k, v in ev.items() if k != "type"})
            elif ev.get("type") == "twap_slice":
                fills = ev.pop("fills", [])
                self._event("twap_slice", when, **{k: v for k, v in ev.items() if k != "type"})
                op = "PERP_ORDER" if "-PERP" in str(ev.get("market", "")) else "SWAP"
                data = {"fills": fills, "order_id": ev.get("twap_id")}
                self._record_fills(op, data, when, None, ev.get("owner"), kind="twap")
            elif ev.get("type") == "vault_asset_sale":
                fills = ev.pop("fills", [])
                self._event(
                    "vault_asset_sale", when, **{k: v for k, v in ev.items() if k != "type"}
                )
                self._record_fills(
                    "SWAP", {"fills": fills}, when, None, VAULT_OWNER, kind="vault_asset_sale"
                )
            elif ev.get("type") in ("twap_finished", "twap_waiting"):
                self._event(ev["type"], when, **{k: v for k, v in ev.items() if k != "type"})
            elif ev.get("type") == "trigger_cancelled":
                self._event(ev["type"], when, **{k: v for k, v in ev.items() if k != "type"})
            elif ev.get("type") == "liquidation":
                fills = ev.pop("fills", [])
                self._event(
                    "liquidation",
                    when,
                    market=",".join(ev.get("markets", [])),
                    **{k: v for k, v in ev.items() if k != "type"},
                )
                for fill in fills:
                    self._event(
                        "fill",
                        when,
                        tx_hash=None,
                        order_id=None,
                        taker=ev.get("owner"),
                        liquidation=True,
                        **fill,
                    )
                    self._perp_trade(fill, when, None, ev.get("owner"), kind="liquidation")
            elif ev.get("type") == "vault_unwind":
                fills = ev.pop("fills", [])
                self._event("vault_unwind", when, **{k: v for k, v in ev.items() if k != "type"})
                for fill in fills:
                    self._event(
                        "fill", when, tx_hash=None, order_id=None, taker=VAULT_OWNER, **fill
                    )
                    self._perp_trade(fill, when, None, VAULT_OWNER, kind="vault_unwind")
            elif ev.get("type") in ("funding", "order_cancelled"):
                self._event(ev["type"], when, **{k: v for k, v in ev.items() if k != "type"})
        self.market.advance(timestamp, height)
        if any(self._history.values()) and _history_enabled():
            self.history_outbox[int(height)] = {"time": history_time, **self._history}
            while len(self.history_outbox) > MAX_HISTORY_OUTBOX:
                self.history_outbox.popitem(last=False)
        self._history = {}

    def rollback_to(self, height: int) -> None:
        """Undo every block above ``height`` — a reorg orphaned them. Their receipts, events and
        trades go; event and trade sequence numbers are not reused, so a stream subscriber sees
        the new branch's as new. (A receipt or event that one of them pushed out of the window
        stays out.)"""
        while self.receipts:
            tx_hash = next(reversed(self.receipts))
            if int(self.receipts[tx_hash].get("block_height", -1)) <= height:
                break
            del self.receipts[tx_hash]
        while self.events and int(self.events[-1].get("block_height", -1)) > height:
            self.events.pop()
        self.market.rollback_to(height)
        self.height = min(self.height, int(height))
        for h in [h for h in self.history_outbox if h > height]:
            del self.history_outbox[h]
        self.history_cut = height if self.history_cut is None else min(self.history_cut, height)

    def prune(self, height: int) -> None:
        """No reorg reaches ``height`` or below: forget the undo kept for those blocks."""
        self.market.prune(height)

    def _record_fills(
        self,
        op: str,
        data: Dict[str, Any],
        when: Dict[str, Any],
        tx_hash: Optional[str],
        sender: str,
        kind: str = "trade",
    ) -> None:
        """The trades a successful operation made: perps fills (events and market data), spot
        and AMM fills (market data); a batch's, action by action."""
        if op in ("PERP_ORDER", "PERP_MODIFY"):
            for fill in data.get("fills", []):
                self._event(
                    "fill",
                    when,
                    tx_hash=tx_hash,
                    order_id=data.get("order_id"),
                    taker=sender,
                    liquidation=False,
                    **fill,
                )
                self._perp_trade(fill, when, tx_hash, sender, kind=kind)
        elif op in ("PLACE_ORDER", "MODIFY_ORDER", "SWAP"):
            for fill in data.get("fills", []):
                self._history_trade(fill, fill["venue"], kind, tx_hash, fill.get("taker"))
                self.market.record_trade(
                    fill["market"],
                    price=fill["price"],
                    amount=fill["amount"],
                    side=fill["side"],
                    venue=fill["venue"],
                    tx_hash=tx_hash,
                    maker=fill.get("maker"),
                    taker=fill.get("taker"),
                    pool_id=fill.get("pool_id"),
                    **when,
                )
        elif op == "BATCH":
            for action in data.get("results", []):
                self._record_fills(action.get("op", ""), action, when, tx_hash, sender, kind)

    # ── the trading history's rows (written by qrdx/trading_history.py) ─────

    def _history_trade(
        self, fill: Dict[str, Any], venue: str, kind: str, tx_hash: Optional[str], taker
    ) -> None:
        rows = self._history.get("trades")
        if rows is None:
            return
        maker = fill.get("maker")
        side = fill.get("side") or (
            "sell" if maker is not None and fill.get("buyer") == maker else "buy"
        )
        rows.append(
            {
                "market": fill.get("market"),
                "venue": venue,
                "kind": kind,
                "price": fill.get("price"),
                "amount": fill.get("amount"),
                "side": side,
                "buyer": fill.get("buyer"),
                "seller": fill.get("seller"),
                "maker": maker,
                "taker": taker,
                "maker_order_id": fill.get("maker_order_id"),
                "taker_order_id": fill.get("taker_order_id"),
                "tx_hash": tx_hash,
                "fees": fill.get("fees") or {},
                "realized": fill.get("realized") or {},
                "pool_id": fill.get("pool_id"),
            }
        )

    def _history_order(self, **row: Any) -> None:
        rows = self._history.get("orders")
        if rows is not None:
            rows.append(row)

    def _history_orders(self, tx, result, data: Dict[str, Any], tx_hash: str) -> None:
        """Orders' history from a transaction: placed (or refused), changed, cancelled — a
        batch's, action by action."""
        op = tx.op_type.name
        if op == "BATCH":
            if not result.success:
                return
            for action in data.get("results", []):
                inner = action.get("op", "")
                if inner in _ORDER_OPS:
                    self._order_row(inner, {}, action, True, "", tx.sender, tx_hash)
            return
        if op in _ORDER_OPS:
            self._order_row(
                op, dict(tx.params or {}), data, result.success, result.error, tx.sender, tx_hash
            )

    def _order_row(self, op, params, data, success, error, sender, tx_hash) -> None:
        event = _ORDER_OPS[op] if success else "rejected"
        order_id = data.get("order_id") or data.get("twap_id") or params.get("order_id")
        order_id = order_id or params.get("twap_id")
        market = (
            params.get("market_id")
            or params.get("pair")
            or params.get("market")
            or data.get("market")
        )
        detail = {
            k: params[k]
            for k in (
                "side",
                "order_type",
                "kind",
                "price",
                "amount",
                "size",
                "trigger_price",
                "limit_price",
                "tif",
                "hidden",
                "display_size",
                "reduce_only",
                "duration",
                "scope",
            )
            if k in params
        }
        for k in ("filled", "resting", "cancelled"):
            if k in data:
                detail[k] = data[k]
        if not success:
            detail["error"] = error
        self._history_order(
            account=sender,
            market=market,
            order_id=order_id,
            event=f"{op.lower()}:{event}" if op.startswith(("TWAP", "PERP_TRIGGER")) else event,
            tx_hash=tx_hash,
            detail=detail,
        )

    def _history_tick(self, ev: Dict[str, Any]) -> None:
        kind = ev.get("type")
        if kind == "funding":
            rows = self._history.get("funding")
            if rows is not None:
                rows.append({k: v for k, v in ev.items() if k != "type"})
            return
        orders = {
            "trigger_fired": "triggered",
            "trigger_cancelled": "cancelled",
            "spot_trigger_fired": "triggered",
            "spot_trigger_cancelled": "cancelled",
            "order_cancelled": "cancelled",
            "twap_finished": "finished",
            "liquidation": "liquidated",
        }
        if kind in orders:
            self._history_order(
                account=ev.get("owner"),
                market=ev.get("market") or ev.get("pair") or ",".join(ev.get("markets") or []),
                order_id=ev.get("order_id") or ev.get("trigger_id") or ev.get("twap_id"),
                event=orders[kind],
                tx_hash=None,
                detail={
                    k: v
                    for k, v in ev.items()
                    if k in ("reason", "stage", "size", "price", "resting", "done", "filled")
                },
            )

    def _perp_trade(
        self, fill: Dict[str, Any], when: Dict[str, Any], tx_hash, taker, kind: str = "trade"
    ) -> None:
        self._history_trade(fill, "perp", kind, tx_hash, taker)
        maker = fill.get("maker")
        side = "sell" if maker is not None and fill.get("buyer") == maker else "buy"
        self.market.record_trade(
            fill["market"],
            price=fill["price"],
            amount=fill["amount"],
            side=side,
            venue="perp",
            tx_hash=tx_hash,
            maker=maker,
            taker=taker,
            **when,
        )

    def _event(self, event_type: str, when: Dict[str, Any], /, **fields) -> None:
        # (Positional-only: an event's own fields may be named anything — a trigger's "kind".)
        self.seq += 1
        self.events.append({"seq": self.seq, **when, **fields, "type": event_type})

    # ── queries ────────────────────────────────────────────────────────

    def receipt(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        return self.receipts.get(str(tx_hash).lower().removeprefix("0x"))

    def query(
        self,
        *,
        market: Optional[str] = None,
        address: Optional[str] = None,
        types: Optional[Iterable[str]] = None,
        since: Optional[int] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Newest-last events matching every given filter. ``address`` matches a fill's buyer or
        seller and a liquidation's owner; ``market`` matches the event's market (a cross
        liquidation lists every market it covered)."""
        wanted = set(types) if types else None
        addr = address.lower() if address else None
        out: List[Dict[str, Any]] = []
        for ev in reversed(self.events):
            if since is not None and ev["seq"] <= since:
                break
            if wanted is not None and ev["type"] not in wanted:
                continue
            if market is not None and market not in str(ev.get("market", "")).split(","):
                continue
            if addr is not None and addr not in {
                str(ev.get(k, "")).lower() for k in ("buyer", "seller", "owner")
            }:
                continue
            out.append(ev)
            if len(out) >= limit:
                break
        out.reverse()
        return out
