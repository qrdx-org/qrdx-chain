"""
JSON-RPC for transaction history — ``tx_*`` — over the transaction index (qrdx/tx_index.py):
every kind of transaction (legacy transfers, exchange operations, EVM transactions) filed under
every account it touched. Always on, like ``exchange_*``; the REST twins are
``/get_address_history``, ``/get_latest_transactions`` and ``/get_indexed_transaction``.

    tx_getHistory(address, limit, cursor, kinds)  → a page of the address's transactions,
                                                    newest first, and ``next_cursor``
    tx_getRecent(limit, cursor, kinds)            → the chain's latest transactions
    tx_getTransaction(tx_hash)                    → one indexed transaction and its accounts
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
    async def getHistory(self, address: str, limit: int = 50, cursor: Optional[str] = None,
                         kinds: Any = None) -> Dict[str, Any]:
        from ... import tx_index
        try:
            return await tx_index.history(self._db(), address, limit=limit, cursor=cursor,
                                          kinds=_kinds(kinds))
        except ValueError as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, str(e))

    @rpc_method
    async def getRecent(self, limit: int = 50, cursor: Optional[str] = None,
                        kinds: Any = None) -> Dict[str, Any]:
        from ... import tx_index
        try:
            return await tx_index.recent(self._db(), limit=limit, cursor=cursor,
                                         kinds=_kinds(kinds))
        except ValueError as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, str(e))

    @rpc_method
    async def getTransaction(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        from ... import tx_index
        return await tx_index.lookup(self._db(), tx_hash)
