"""
JSON-RPC for the exchange and its perpetuals — ``exchange_*`` and ``perp_*``.

Always on (like ``dht_*`` / ``p2p_*``), because wallets need it on any node: every write goes
through the same admission + gossip path as ``POST /submit_exchange_tx``, and every read comes
from the same views as the REST endpoints (qrdx/exchange/views.py), so all surfaces agree.

    exchange_sendTransaction(tx)            → tx hash; admitted, then included by a validator
    exchange_getSigningPayload(tx)          → the exact bytes to sign + the resulting hash
    exchange_getTransactionReceipt(hash)    → the executed result, or null while pending
    exchange_getNonce(address)              → the next exchange nonce
    exchange_getTokenBalance(token, addr)   → a token balance (any address form)
    exchange_getTokenAccount(token, addr)   → {balance, frozen}
    exchange_getTokens()   exchange_getToken(token)   exchange_getAllowance(token, owner, spender)
    exchange_getStateRoot()

    exchange_getPools(token_a, token_b)   exchange_getPool(pool_id, twap_window)
    exchange_getPositions(address)        exchange_quoteSwap(token_in, token_out, amount_in, …)
    exchange_quoteLiquidity(pool_id, tick_lower, tick_upper, liquidity | amount0, amount1)
    exchange_getOrderBook(pair, depth)    exchange_getOpenOrders(address)

    perp_getMarkets()   perp_getMarket(id)   perp_getOrderBook(id, depth)
    perp_getAccount(address)   perp_getOpenOrders(address)   perp_getVault()
    perp_getTrades(id, limit)   perp_getEvents(market_id, address, types, since, limit)
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..server import RPCError, RPCErrorCode, RPCModule, rpc_method


def _manager():
    from ...exchange import ExchangeStateManager
    return ExchangeStateManager.get_instance()


class ExchangeModule(RPCModule):
    """Exchange transactions: submit, sign, track. Context: ``submitter`` (an
    ExchangeSubmitter) and ``db``."""

    namespace = "exchange"

    @rpc_method
    async def sendTransaction(self, tx: Any, propagated: bool = False) -> str:
        """Admit a signed exchange transaction (a JSON object, or the string ``to_hex()``
        makes) and gossip it. Returns its hash; the receipt appears once a block includes it."""
        submitter = getattr(self.context, "submitter", None)
        if submitter is None:
            raise RPCError(RPCErrorCode.RESOURCE_UNAVAILABLE, "exchange submission unavailable")
        ok, err, tx_hash = await submitter.submit(tx, propagated=bool(propagated))
        if not ok:
            raise RPCError(RPCErrorCode.TRANSACTION_REJECTED, err)
        return tx_hash

    @rpc_method
    async def getSigningPayload(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        from ...exchange.submission import signing_payload
        try:
            return signing_payload(tx)
        except Exception as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, f"invalid transaction fields: {e}")

    @rpc_method
    async def getTransactionReceipt(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        from ...exchange import views
        return views.receipt(_manager(), tx_hash)

    @rpc_method
    async def getNonce(self, address: str) -> int:
        from ...exchange import views
        mgr = _manager()
        return mgr.get_nonce(views.account_key(mgr.clearinghouse, address) or address)

    @rpc_method
    async def getTokenBalance(self, token_address: str, address: str) -> str:
        db = getattr(self.context, "db", None)
        if db is None:
            raise RPCError(RPCErrorCode.RESOURCE_UNAVAILABLE, "database unavailable")
        return str(await db.get_token_balance(token_address, address))

    @rpc_method
    async def getTokenAccount(self, token_address: str, address: str) -> Dict[str, Any]:
        """A holder's balance of a token and whether the token's freeze authority froze it."""
        from ...exchange import views
        db = getattr(self.context, "db", None)
        if db is None:
            raise RPCError(RPCErrorCode.RESOURCE_UNAVAILABLE, "database unavailable")
        return {"token_address": token_address, "address": address,
                "balance": str(await db.get_token_balance(token_address, address)),
                "frozen": views.token_frozen(_manager(), token_address, address)}

    @rpc_method
    async def getTokens(self) -> List[Dict[str, Any]]:
        from ...exchange import views
        return views.tokens(_manager())

    @rpc_method
    async def getToken(self, token_address: str) -> Dict[str, Any]:
        from ...exchange import views
        found = views.token(_manager(), token_address)
        if found is None:
            raise RPCError(RPCErrorCode.RESOURCE_NOT_FOUND, f"token {token_address} not found")
        return found

    @rpc_method
    async def getAllowance(self, token_address: str, owner: str, spender: str) -> Dict[str, Any]:
        from ...exchange import views
        try:
            return views.token_allowance(_manager(), token_address, owner, spender)
        except ValueError as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, str(e))

    @rpc_method
    async def getStateRoot(self) -> Dict[str, Any]:
        mgr = _manager()
        return {"exchange_state_root": mgr.compute_state_root(),
                "block_height": mgr._current_block_height}

    # ── spot reads (qrdx/exchange/views.py) ──

    @rpc_method
    async def getPools(self, token_a: Optional[str] = None,
                       token_b: Optional[str] = None) -> List[Dict[str, Any]]:
        from ...exchange import views
        return views.pools(_manager(), token_a, token_b)

    @rpc_method
    async def getPool(self, pool_id: str, twap_window: Optional[int] = None) -> Dict[str, Any]:
        from ...exchange import views
        found = views.pool(_manager(), pool_id, twap_window)
        if found is None:
            raise RPCError(RPCErrorCode.RESOURCE_NOT_FOUND, f"pool {pool_id} not found")
        return found

    @rpc_method
    async def quoteLiquidity(self, pool_id: str, tick_lower: int, tick_upper: int,
                             liquidity: Any = None, amount0: Any = None,
                             amount1: Any = None) -> Dict[str, Any]:
        from ...exchange import views
        try:
            found = views.liquidity_quote(_manager(), pool_id, tick_lower, tick_upper,
                                          liquidity, amount0, amount1)
        except (ValueError, ArithmeticError) as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, str(e))
        if found is None:
            raise RPCError(RPCErrorCode.RESOURCE_NOT_FOUND, f"pool {pool_id} not found")
        return found

    @rpc_method
    async def getPositions(self, address: str) -> List[Dict[str, Any]]:
        from ...exchange import views
        return views.positions(_manager(), address)

    @rpc_method
    async def quoteSwap(self, token_in: str, token_out: str, amount_in: Any, sender: str = "",
                        pool_id: Optional[str] = None, venue: str = "auto") -> Dict[str, Any]:
        from ...exchange import views
        try:
            found = views.quote(_manager(), token_in, token_out, amount_in, sender, pool_id, venue)
        except (ValueError, ArithmeticError) as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, str(e))
        if found is None:
            raise RPCError(RPCErrorCode.RESOURCE_NOT_FOUND, "no liquidity for this swap")
        return found

    @rpc_method
    async def getOrderBook(self, pair: str, depth: int = 20) -> Dict[str, Any]:
        from ...exchange import views
        found = views.spot_order_book(_manager(), pair, depth)
        if found is None:
            raise RPCError(RPCErrorCode.RESOURCE_NOT_FOUND, f"no order book for {pair}")
        return found

    @rpc_method
    async def getOpenOrders(self, address: str) -> List[Dict[str, Any]]:
        from ...exchange import views
        return views.spot_open_orders(_manager(), address)


class PerpModule(RPCModule):
    """Read-only perps state (docs/PERPS_CLEARINGHOUSE.md)."""

    namespace = "perp"

    @rpc_method
    async def getMarkets(self) -> List[Dict[str, Any]]:
        from ...exchange import views
        return views.markets(_manager())

    @rpc_method
    async def getMarket(self, market_id: str) -> Dict[str, Any]:
        from ...exchange import views
        found = views.market(_manager(), market_id)
        if found is None:
            raise RPCError(RPCErrorCode.RESOURCE_NOT_FOUND, f"market {market_id} not found")
        return found

    @rpc_method
    async def getOrderBook(self, market_id: str, depth: int = 20) -> Dict[str, Any]:
        from ...exchange import views
        found = views.order_book(_manager(), market_id, depth)
        if found is None:
            raise RPCError(RPCErrorCode.RESOURCE_NOT_FOUND, f"market {market_id} not found")
        return found

    @rpc_method
    async def getAccount(self, address: str) -> Dict[str, Any]:
        from ...exchange import views
        return views.account(_manager(), address)

    @rpc_method
    async def getOpenOrders(self, address: str) -> List[Dict[str, Any]]:
        from ...exchange import views
        return views.open_orders(_manager(), address)

    @rpc_method
    async def getVault(self) -> Dict[str, Any]:
        from ...exchange import views
        return views.vault(_manager())

    @rpc_method
    async def getTrades(self, market_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        from ...exchange import views
        return views.trades(_manager(), market_id, limit)

    @rpc_method
    async def getEvents(self, market_id: Optional[str] = None, address: Optional[str] = None,
                        types: Optional[List[str]] = None, since: Optional[int] = None,
                        limit: int = 100) -> Dict[str, Any]:
        from ...exchange import views
        return views.events(_manager(), market=market_id, address=address, types=types,
                            since=since, limit=limit)
