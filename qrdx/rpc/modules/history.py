"""
JSON-RPC for history.

``tx_*`` — over the transaction index (qrdx/tx_index.py):
every kind of transaction (legacy transfers, exchange operations, EVM transactions) filed under
every account it touched. Always on, like ``exchange_*``; the REST twins are
``/get_address_history``, ``/get_latest_transactions`` and ``/get_indexed_transaction``.

    tx_getHistory(address, limit, cursor, kinds)  → a page of the address's transactions,
                                                    newest first, and ``next_cursor``
    tx_getRecent(limit, cursor, kinds)            → the chain's latest transactions
    tx_getTransaction(tx_hash)                    → one indexed transaction and its accounts

``history_*`` — over the trading history (qrdx/trading_history.py): every trade, order event,
funding settlement and minute sample, kept (the ``market_*`` methods serve the recent ones from
memory). Pages are newest first; pass ``next_cursor`` back as ``cursor``.

    history_getTrades(address, market, limit, cursor)        → trades: an address's, a market's
    history_getOrders(address, market, order_id, limit, cursor) → order events
    history_getFunding(market, limit, cursor)                → a perp market's funding settlements
    history_getMarketSamples(market, since, until, limit)    → mark, oracle, open interest and
                                                               funding rate, a minute apart
    history_getLeaderboard(window, metric, limit)            → perps accounts by pnl or volume
                                                               over a day, week, month or all
    history_getRecentTrades(address, limit)                  → an address's trades still in the
                                                               node's memory (no database needed)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..server import RPCError, RPCErrorCode, RPCModule, rpc_method


def _kinds(kinds) -> Optional[List[str]]:
    if not kinds:
        return None
    if isinstance(kinds, str):
        kinds = kinds.split(",")
    return [str(k).strip() for k in kinds if str(k).strip()]


class HistoryModule(RPCModule):
    """Context: ``db``."""

    namespace = "tx"

    def _db(self):
        db = getattr(self.context, "db", None)
        if db is None or not hasattr(db, "tx_index_head"):
            raise RPCError(RPCErrorCode.RESOURCE_UNAVAILABLE, "transaction index unavailable")
        return db

    @rpc_method
    async def getHistory(
        self, address: str, limit: int = 50, cursor: Optional[str] = None, kinds: Any = None
    ) -> Dict[str, Any]:
        from ... import tx_index

        try:
            return await tx_index.history(
                self._db(), address, limit=limit, cursor=cursor, kinds=_kinds(kinds)
            )
        except ValueError as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, str(e)) from e

    @rpc_method
    async def getRecent(
        self, limit: int = 50, cursor: Optional[str] = None, kinds: Any = None
    ) -> Dict[str, Any]:
        from ... import tx_index

        try:
            return await tx_index.recent(
                self._db(), limit=limit, cursor=cursor, kinds=_kinds(kinds)
            )
        except ValueError as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, str(e)) from e

    @rpc_method
    async def getTransaction(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        from ... import tx_index

        return await tx_index.lookup(self._db(), tx_hash)


class TradingHistoryModule(RPCModule):
    """Context: ``db``."""

    namespace = "history"

    def _db(self):
        db = getattr(self.context, "db", None)
        if db is None or not hasattr(db, "hist_trades"):
            raise RPCError(RPCErrorCode.RESOURCE_UNAVAILABLE, "trading history unavailable")
        return db

    async def _call(self, fn, *args, **kwargs):
        try:
            return await fn(self._db(), *args, **kwargs)
        except ValueError as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, str(e)) from e

    @rpc_method
    async def getTrades(
        self,
        address: Optional[str] = None,
        market: Optional[str] = None,
        limit: int = 100,
        cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        from ... import trading_history

        if not (address or market):
            raise RPCError(RPCErrorCode.INVALID_PARAMS, "give an address or a market")
        return await self._call(
            trading_history.trades, address=address, market=market, limit=limit, cursor=cursor
        )

    @rpc_method
    async def getOrders(
        self,
        address: Optional[str] = None,
        market: Optional[str] = None,
        order_id: Optional[str] = None,
        limit: int = 100,
        cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        from ... import trading_history

        return await self._call(
            trading_history.orders,
            address=address,
            market=market,
            order_id=order_id,
            limit=limit,
            cursor=cursor,
        )

    @rpc_method
    async def getFunding(
        self, market: str, limit: int = 100, cursor: Optional[str] = None
    ) -> Dict[str, Any]:
        from ... import trading_history

        return await self._call(trading_history.funding, market, limit=limit, cursor=cursor)

    @rpc_method
    async def getMarketSamples(
        self,
        market: str,
        since: Optional[float] = None,
        until: Optional[float] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        from ... import trading_history

        return await self._call(
            trading_history.samples, market, since=since, until=until, limit=limit
        )

    @rpc_method
    async def getLeaderboard(
        self, window: str = "day", metric: str = "pnl", limit: int = 50
    ) -> List[Dict[str, Any]]:
        from ... import trading_history

        return await self._call(
            trading_history.leaderboard, window=window, metric=metric, limit=limit
        )

    @rpc_method
    async def getRecentTrades(self, address: str, limit: int = 100) -> List[Dict[str, Any]]:
        from ...exchange import ExchangeStateManager, views

        return views.address_trades(ExchangeStateManager.get_instance(), address, limit)
