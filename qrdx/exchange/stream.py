"""
Realtime exchange streams (the WebSocket ``/ws`` and SSE ``/stream`` channels) — perps, spot and
native tokens.

A background poller — read-only, like the chain-tip poller in qrdx/node/observability.py, so it
can never stall or diverge block processing — publishes to the event hub:

    perp_markets            every market's summary when it changes (prices, OI, top of book,
                            funding); "perp_markets:<id>" for one market
    perp_book:<id>          a market's order book (top levels) when it changes
    perp_events             fills, liquidations, funding settlements as they commit;
                            "perp_events:<id>" for one market
    perp_account:<address>  an account's snapshot (collateral, margin, positions with live PnL
                            and liquidation price, open orders) when it changes
    spot_pools              every AMM pool's summary when it changes; "spot_pools:<id>" for one
    spot_book:<a>:<b>       a spot pair's order book (either token order) when it changes
    spot_account:<address>  an address's liquidity positions (with uncollected fees) and resting
                            spot orders when they change
    tokens                  every native token's registry entry (supply, authorities) when it
                            changes; "tokens:<address>" for one

Books and accounts are only built for channels someone has subscribed to. The shapes are the
REST / JSON-RPC views' (qrdx/exchange/views.py). This is a display feed: a reading may catch a
block mid-application, so wallets confirm with ``/get_exchange_receipt`` and re-read state over
REST or RPC after reconnecting.
"""
from __future__ import annotations

import asyncio
from typing import Any, Callable, Dict, Optional

from . import views

ACCOUNT_STREAM_OMIT = ("vault", "holder_address", "holder_balance")


class PerpStreamPublisher:
    """Remembers what each channel last published and, each ``step``, publishes what changed."""

    def __init__(self, hub, book_depth: int = 20):
        self.hub = hub
        self.book_depth = book_depth
        self.markets: Dict[str, Dict[str, Any]] = {}
        self.books: Dict[str, Dict[str, Any]] = {}
        self.accounts: Dict[str, Dict[str, Any]] = {}
        self.pools: Dict[str, Dict[str, Any]] = {}
        self.tokens: Dict[str, Dict[str, Any]] = {}
        self.spot_books: Dict[str, Dict[str, Any]] = {}
        self.spot_accounts: Dict[str, Dict[str, Any]] = {}
        self.journal_id: Optional[int] = None
        self.last_seq = 0

    def step(self, mgr) -> None:
        hub = self.hub
        if not hub.subscriber_count:
            return
        journal = mgr.journal
        # A different journal is a rebuilt manager (reorg, rejected block, restart): its history
        # was replayed, not new — resume from its head instead of re-sending it.
        if id(journal) != self.journal_id:
            self.journal_id, self.last_seq = id(journal), journal.seq
        elif journal.seq > self.last_seq:
            for ev in journal.query(since=self.last_seq, limit=1000):
                hub.publish_nowait({"type": "perp_event", "channel": "perp_events",
                                    "key": ev.get("market"), "event": ev})
            self.last_seq = journal.seq

        for summary in views.markets(mgr):
            mid = summary["market_id"]
            if self.markets.get(mid) != summary:
                self.markets[mid] = summary
                hub.publish_nowait({"type": "perp_market", "channel": "perp_markets",
                                    "key": mid, "market": summary})
            if hub.wants("perp_book", mid):
                book = views.order_book(mgr, mid, self.book_depth)
                if self.books.get(mid) != book:
                    self.books[mid] = book
                    hub.publish_nowait({"type": "perp_book", "channel": "perp_book",
                                        "key": mid, "book": book})
            else:
                self.books.pop(mid, None)

        watched = hub.keys("perp_account")
        for address in watched:
            snap = {k: v for k, v in views.account(mgr, address).items()
                    if k not in ACCOUNT_STREAM_OMIT}
            if self.accounts.get(address) != snap:
                self.accounts[address] = snap
                hub.publish_nowait({"type": "perp_account", "channel": "perp_account",
                                    "key": address, "account": snap})
        for address in list(self.accounts):
            if address not in watched:
                del self.accounts[address]

        self._step_spot(mgr)

    def _changed(self, cache: Dict[str, Any], key: str, value: Any) -> bool:
        if cache.get(key) == value:
            return False
        cache[key] = value
        return True

    def _step_spot(self, mgr) -> None:
        hub = self.hub
        if hub.wants("spot_pools") or hub.keys("spot_pools"):
            for summary in views.pools(mgr):
                if self._changed(self.pools, summary["pool_id"], summary):
                    hub.publish_nowait({"type": "spot_pool", "channel": "spot_pools",
                                        "key": summary["pool_id"], "pool": summary})
        else:
            self.pools.clear()
        if hub.wants("tokens") or hub.keys("tokens"):
            for token in views.tokens(mgr):
                if self._changed(self.tokens, token["token_address"], token):
                    hub.publish_nowait({"type": "token", "channel": "tokens",
                                        "key": token["token_address"], "token": token})
        else:
            self.tokens.clear()
        pairs = hub.keys("spot_book")
        for pair in pairs:
            book = views.spot_order_book(mgr, pair, self.book_depth)
            if book is not None and self._changed(self.spot_books, pair, book):
                hub.publish_nowait({"type": "spot_book", "channel": "spot_book",
                                    "key": pair, "book": book})
        for pair in list(self.spot_books):
            if pair not in pairs:
                del self.spot_books[pair]
        watched = hub.keys("spot_account")
        for address in watched:
            snap = spot_account(mgr, address)
            if self._changed(self.spot_accounts, address, snap):
                hub.publish_nowait({"type": "spot_account", "channel": "spot_account",
                                    "key": address, "account": snap})
        for address in list(self.spot_accounts):
            if address not in watched:
                del self.spot_accounts[address]


def spot_account(mgr, address: str) -> Dict[str, Any]:
    return {"positions": views.positions(mgr, address),
            "orders": views.spot_open_orders(mgr, address)}


# Perps came first; the publisher now covers spot and tokens too.
ExchangeStreamPublisher = PerpStreamPublisher


async def perp_stream_poller(hub, *, get_manager: Callable[[], Any], interval: float = 1.0,
                             book_depth: int = 20, _max_iterations: Optional[int] = None) -> None:
    publisher = PerpStreamPublisher(hub, book_depth)
    iterations = 0
    while True:
        try:
            publisher.step(get_manager())
        except asyncio.CancelledError:
            break
        except Exception:
            pass
        iterations += 1
        if _max_iterations is not None and iterations >= _max_iterations:
            break
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            break


def initial_snapshots(mgr, channels, book_depth: int = 20):
    """The current state for newly subscribed perps channels, so a subscriber starts from a full
    picture instead of waiting for the next change."""
    out = []
    for channel in sorted(channels):
        base, _, key = channel.partition(":")
        if base == "perp_markets":
            for summary in views.markets(mgr):
                if not key or summary["market_id"] == key:
                    out.append({"type": "perp_market", "channel": "perp_markets",
                                "key": summary["market_id"], "market": summary, "snapshot": True})
        elif base == "perp_book" and key:
            book = views.order_book(mgr, key, book_depth)
            if book is not None:
                out.append({"type": "perp_book", "channel": "perp_book", "key": key,
                            "book": book, "snapshot": True})
        elif base == "perp_account" and key:
            snap = {k: v for k, v in views.account(mgr, key).items()
                    if k not in ACCOUNT_STREAM_OMIT}
            out.append({"type": "perp_account", "channel": "perp_account", "key": key,
                        "account": snap, "snapshot": True})
        elif base == "spot_pools":
            for summary in views.pools(mgr):
                if not key or summary["pool_id"] == key:
                    out.append({"type": "spot_pool", "channel": "spot_pools",
                                "key": summary["pool_id"], "pool": summary, "snapshot": True})
        elif base == "tokens":
            for token in views.tokens(mgr):
                if not key or token["token_address"] == key.lower():
                    out.append({"type": "token", "channel": "tokens",
                                "key": token["token_address"], "token": token, "snapshot": True})
        elif base == "spot_book" and key:
            book = views.spot_order_book(mgr, key, book_depth)
            if book is not None:
                out.append({"type": "spot_book", "channel": "spot_book", "key": book["pair"],
                            "book": book, "snapshot": True})
        elif base == "spot_account" and key:
            out.append({"type": "spot_account", "channel": "spot_account", "key": key,
                        "account": spot_account(mgr, key), "snapshot": True})
    return out
