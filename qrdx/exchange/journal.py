"""
The exchange journal — what each committed block did, for wallets, the API and the streams.

* **Receipts:** one per executed exchange transaction (success or failure, its error, the
  operation's result data — an order's id and fills, a deposit's new collateral, …), keyed by
  transaction hash. Exchange transactions are admitted to a mempool and execute only when a
  block includes them; the receipt is how a wallet learns what happened.
* **Events:** a sequenced feed of perps fills (including liquidation fills), liquidations and
  funding settlements.

This is NOT consensus state: it is never hashed or snapshotted, and it is recorded only when a
block commits (a reverted block leaves nothing behind). It lives on the ExchangeStateManager, so
every rebuild — a reorg, a rejected block, a restart — rebuilds it from the canonical chain like
the rest of the exchange state. Bounded: the oldest receipts and events fall off.
"""
from __future__ import annotations

from collections import OrderedDict, deque
from decimal import Decimal
from typing import Any, Deque, Dict, Iterable, List, Optional

MAX_RECEIPTS = 50_000
MAX_EVENTS = 10_000


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
        self.seq = 0                     # last event sequence number (monotonic per journal)

    # ── recording (at block commit) ────────────────────────────────────

    def record_block(self, height: int, timestamp: float, txs: Iterable, results: Iterable,
                     tick_events: Iterable[Dict[str, Any]]) -> None:
        when = {"block_height": int(height), "block_time": float(timestamp)}
        for tx, result in zip(txs, results):
            tx_hash = tx.tx_hash()
            data = jsonable(getattr(result, "data", {}) or {})
            self.receipts[tx_hash] = {
                "tx_hash": tx_hash, **when, "op": tx.op_type.name, "sender": tx.sender,
                "nonce": tx.nonce, "success": bool(result.success), "error": result.error or "",
                "gas_used": int(result.gas_used or 0),
                "gas_price": int(getattr(tx, "gas_price", 0) or 0),          # wei per gas
                "fee": str(getattr(result, "fee", 0) or 0),                    # QRDX, burned
                "data": data,
            }
            self.receipts.move_to_end(tx_hash)
            while len(self.receipts) > self.max_receipts:
                self.receipts.popitem(last=False)
            if tx.op_type.name == "PERP_ORDER" and result.success:
                for fill in data.get("fills", []):
                    self._event("fill", when, tx_hash=tx_hash, order_id=data.get("order_id"),
                                taker=tx.sender, liquidation=False, **fill)
        for ev in tick_events or ():
            ev = jsonable(ev)
            if ev.get("type") == "liquidation":
                fills = ev.pop("fills", [])
                self._event("liquidation", when, market=",".join(ev.get("markets", [])),
                            **{k: v for k, v in ev.items() if k != "type"})
                for fill in fills:
                    self._event("fill", when, tx_hash=None, order_id=None,
                                taker=ev.get("owner"), liquidation=True, **fill)
            elif ev.get("type") == "funding":
                self._event("funding", when, **{k: v for k, v in ev.items() if k != "type"})

    def _event(self, kind: str, when: Dict[str, Any], **fields) -> None:
        self.seq += 1
        self.events.append({"seq": self.seq, "type": kind, **when, **fields})

    # ── queries ────────────────────────────────────────────────────────

    def receipt(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        return self.receipts.get(str(tx_hash).lower().removeprefix("0x"))

    def query(self, *, market: Optional[str] = None, address: Optional[str] = None,
              types: Optional[Iterable[str]] = None, since: Optional[int] = None,
              limit: int = 100) -> List[Dict[str, Any]]:
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
                    str(ev.get(k, "")).lower() for k in ("buyer", "seller", "owner")}:
                continue
            out.append(ev)
            if len(out) >= limit:
                break
        out.reverse()
        return out
