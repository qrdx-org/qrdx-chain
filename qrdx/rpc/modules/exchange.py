"""
JSON-RPC for the exchange and its perpetuals — ``exchange_*`` and ``perp_*``.

Always on (like ``dht_*`` / ``p2p_*``), because wallets need it on any node: every write goes
through the same admission + gossip path as ``POST /submit_exchange_tx``, and every read comes
from the same views as the REST endpoints (qrdx/exchange/views.py), so all surfaces agree.

    exchange_sendTransaction(tx)            → tx hash; admitted, then included by a validator
    exchange_getSigningPayload(tx)          → the exact bytes to sign + the resulting hash
    exchange_getTransactionReceipt(hash)    → the executed result, or null while pending
    exchange_getNonce(address)              → the next exchange nonce
    exchange_gasPrice()                     → wei per gas to offer (the floor)
    exchange_getTokenBalance(token, addr)   → a token balance (any address form)
    exchange_getTokenAccount(token, addr)   → {balance, frozen}
    exchange_getTokens()   exchange_getToken(token)   exchange_getAllowance(token, owner, spender)
    exchange_isTokenOperator(token, holder, operator)
    exchange_getNftCollections()   exchange_getNftCollection(collection)
    exchange_getNft(collection, token_id)   exchange_getNftsOf(owner, collection, limit)
    exchange_isNftOperator(collection, owner, operator)
    exchange_getStateRoot()

    exchange_getPools(token_a, token_b)   exchange_getPool(pool_id, twap_window)
    exchange_getPositions(address)        exchange_quoteSwap(token_in, token_out, amount_in, …)
    exchange_quoteLiquidity(pool_id, tick_lower, tick_upper, liquidity | amount0, amount1)
    exchange_getOrderBook(pair, depth)    exchange_getOpenOrders(address)

    perp_getMarkets()   perp_getMarket(id)   perp_getOrderBook(id, depth)
    perp_getAccount(address)   perp_getOpenOrders(address)   perp_getVault()
    perp_getTrades(id, limit)   perp_getEvents(market_id, address, types, since, limit)
    perp_getTriggers(address)   perp_getTwaps(address)   perp_getFeeSchedule(address)
    perp_getUserVaults(leader)   perp_getUserVault(vault, holder)
    perp_getDeployer(address | dex)   (docs/HYPERLIQUID_PARITY.md: a deployer's bond and markets)
    exchange_getAgents(address)   exchange_getSubaccounts(address)
    exchange_getTicker(ticker)   exchange_getTickerAuction()   (unique tickers: HIP-1's auction)
    exchange_getFreeActions(address)   (the free trading lane: docs/TOKENOMICS.md)

    market_getMarkets(kind)   market_getTicker(market)   market_getOrderBook(market, depth, level)
    market_getTrades(market, limit, since)   market_getCandles(market, interval, limit, end)
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

        if isinstance(tx, dict) and "gas_price" not in tx:
            tx = dict(tx, gas_price=str(await self.gasPrice()))  # what the next block takes
        try:
            return signing_payload(tx)
        except Exception as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, f"invalid transaction fields: {e}") from e

    @rpc_method
    async def getTransactionReceipt(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        from ...exchange import views

        return views.receipt(_manager(), tx_hash)

    @rpc_method
    async def gasPrice(self) -> int:
        """The exchange gas price to offer, in wei per gas: the next block's base fee with
        headroom for one more full block (qrdx/fee_market.py) — the floor when the chain is
        quiet."""
        from ... import constants
        from ...fee_market import suggested_prices

        db = getattr(self.context, "db", None)
        if db is None:
            return constants.EXCHANGE_MIN_GAS_PRICE_WEI
        return (await suggested_prices(db))[1]

    @rpc_method
    async def getFreeActions(self, address: str) -> Dict[str, Any]:
        """``address``'s free trading actions (docs/TOKENOMICS.md): its budget, how many it has
        used, how many are left, and whether a trading operation of its would go free now (and
        why not, if not)."""
        from ...exchange import ExchangeOpType, ExchangeTransaction

        mgr = _manager()
        used, last = mgr.trading.action_budgets.peek(address, (0, 0))
        budget = mgr.free_action_budget(address)
        probe = ExchangeTransaction(
            op_type=ExchangeOpType.PERP_ORDER,
            sender=address,
            nonce=0,
            params={"market_id": "", "side": "buy", "size": "0", "price": "0"},
            gas_limit=1,
            gas_price=0,
            timestamp=1.0,
        )
        why = mgr.free_action_error(probe) if probe.free_eligible() else "no free lane here"
        return {
            "address": address,
            "budget": budget,
            "used": int(used),
            "remaining": max(0, budget - int(used)),
            "last_free_action": str(last),
            "lane_open": mgr.free_lane_open(),
            "free_now": why == "",
            "why_not": why or None,
        }

    @rpc_method
    async def getNonce(self, address: str, signer: Optional[str] = None) -> int:
        """The next nonce of ``address`` — or, with ``signer`` (an agent, a sub-account's
        master, a vault's leader), of that signer's lane for it."""
        from ...exchange import views

        mgr = _manager()
        key = views.account_key(mgr.clearinghouse, address) or address
        if signer and signer != key:
            key = f"{key}|{signer}"
        return mgr.get_nonce(key)

    @rpc_method
    async def getProtocolAddresses(self) -> Dict[str, Any]:
        """Every address the protocol holds balances at: pools, book escrows, the perps holder,
        the backstop vault, vaults, the veto escrow, the bridge, the system wallets."""
        from ...exchange import views

        return views.protocol_addresses(_manager())

    @rpc_method
    async def getAgents(self, address: str) -> List[Dict[str, Any]]:
        """The agent keys ``address`` approved to trade for it."""
        from ...exchange import views

        return views.agents(_manager(), address)

    @rpc_method
    async def getSubaccounts(self, address: str) -> List[Dict[str, Any]]:
        from ...exchange import views

        return views.subaccounts(_manager(), address)

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
        return {
            "token_address": token_address,
            "address": address,
            "balance": str(await db.get_token_balance(token_address, address)),
            "frozen": views.token_frozen(_manager(), token_address, address),
        }

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
    async def getTicker(self, ticker: str) -> Dict[str, Any]:
        """The token a unique ticker names (docs/HYPERLIQUID_PARITY.md 11)."""
        from ...exchange import views

        found = views.ticker(_manager(), ticker)
        if found is None:
            raise RPCError(RPCErrorCode.RESOURCE_NOT_FOUND, f"no ticker {ticker}")
        return found

    @rpc_method
    async def getTickerAuction(self) -> Dict[str, Any]:
        """The ticker auction's price now, its floor and its last sale."""
        from ...exchange import views

        return views.ticker_auction(_manager())

    @rpc_method
    async def getAllowance(self, token_address: str, owner: str, spender: str) -> Dict[str, Any]:
        from ...exchange import views

        try:
            return views.token_allowance(_manager(), token_address, owner, spender)
        except ValueError as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, str(e)) from e

    @rpc_method
    async def getNftCollections(self) -> List[Dict[str, Any]]:
        from ...exchange import views

        return views.nft_collections(_manager())

    @rpc_method
    async def getNftCollection(self, collection: str) -> Dict[str, Any]:
        from ...exchange import views

        found = views.nft_collection(_manager(), collection)
        if found is None:
            raise RPCError(RPCErrorCode.RESOURCE_NOT_FOUND, f"collection {collection} not found")
        return found

    @rpc_method
    async def getNft(self, collection: str, token_id: Any) -> Dict[str, Any]:
        from ...exchange import views

        found = views.nft(_manager(), collection, token_id)
        if found is None:
            raise RPCError(
                RPCErrorCode.RESOURCE_NOT_FOUND, f"NFT {collection} #{token_id} not found"
            )
        return found

    @rpc_method
    async def getNftsOf(
        self, owner: str, collection: Optional[str] = None, limit: int = 500
    ) -> List[Dict[str, Any]]:
        from ...exchange import views

        return views.nfts_of(_manager(), owner, collection, limit)

    @rpc_method
    async def isNftOperator(self, collection: str, owner: str, operator: str) -> bool:
        from ...exchange import views

        return views.nft_operator(_manager(), collection, owner, operator)

    @rpc_method
    async def isTokenOperator(self, token_address: str, holder: str, operator: str) -> bool:
        try:
            return _manager().tokens.is_operator(token_address, holder, operator)
        except Exception:
            return False

    @rpc_method
    async def getStateRoot(self) -> Dict[str, Any]:
        mgr = _manager()
        return {
            "exchange_state_root": mgr.compute_state_root(),
            "block_height": mgr._current_block_height,
        }

    # ── spot reads (qrdx/exchange/views.py) ──

    @rpc_method
    async def getPools(
        self, token_a: Optional[str] = None, token_b: Optional[str] = None
    ) -> List[Dict[str, Any]]:
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
    async def quoteLiquidity(
        self,
        pool_id: str,
        tick_lower: int,
        tick_upper: int,
        liquidity: Any = None,
        amount0: Any = None,
        amount1: Any = None,
    ) -> Dict[str, Any]:
        from ...exchange import views

        try:
            found = views.liquidity_quote(
                _manager(), pool_id, tick_lower, tick_upper, liquidity, amount0, amount1
            )
        except (ValueError, ArithmeticError) as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, str(e)) from e
        if found is None:
            raise RPCError(RPCErrorCode.RESOURCE_NOT_FOUND, f"pool {pool_id} not found")
        return found

    @rpc_method
    async def getPositions(self, address: str) -> List[Dict[str, Any]]:
        from ...exchange import views

        return views.positions(_manager(), address)

    @rpc_method
    async def quoteSwap(
        self,
        token_in: str,
        token_out: str,
        amount_in: Any,
        sender: str = "",
        pool_id: Optional[str] = None,
        venue: str = "auto",
    ) -> Dict[str, Any]:
        from ...exchange import views

        try:
            found = views.quote(_manager(), token_in, token_out, amount_in, sender, pool_id, venue)
        except (ValueError, ArithmeticError) as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, str(e)) from e
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
    async def getTriggers(self, address: str) -> List[Dict[str, Any]]:
        """An address's trigger orders waiting for their price, perps and spot."""
        from ...exchange import views

        return views.triggers(_manager(), address)

    @rpc_method
    async def getTwaps(self, address: str) -> List[Dict[str, Any]]:
        from ...exchange import views

        return views.twaps(_manager(), address)

    @rpc_method
    async def getFeeSchedule(self, address: Optional[str] = None) -> Dict[str, Any]:
        from ...exchange import views

        return views.fee_schedule(_manager(), address)

    @rpc_method
    async def getUserVaults(self, leader: Optional[str] = None) -> List[Dict[str, Any]]:
        from ...exchange import views

        return views.user_vaults(_manager(), leader)

    @rpc_method
    async def getUserVault(self, vault: str, holder: Optional[str] = None) -> Dict[str, Any]:
        from ...exchange import views

        found = views.user_vault(_manager(), vault, holder)
        if found is None:
            raise RPCError(RPCErrorCode.RESOURCE_NOT_FOUND, f"no vault {vault}")
        return found

    @rpc_method
    async def getDeployer(self, who: str) -> Dict[str, Any]:
        """A market deployer, by address or namespace: its bond, what it is unbonding and
        when that unlocks, and the markets it runs."""
        mgr = _manager()
        address = who
        found = mgr.trading.deployers.peek(who)
        if found is None:
            for addr, d in mgr.trading.deployers.peek_items():
                if d.dex == who:
                    address, found = addr, d
                    break
        if found is None:
            raise RPCError(RPCErrorCode.RESOURCE_NOT_FOUND, f"no deployer {who}")
        return {
            "address": address,
            "dex": found.dex,
            "bond": str(found.bond),
            "unbonding": str(found.unbonding),
            "unlock": str(found.unlock) if found.unbonding > 0 else None,
            "markets": mgr.deployer_markets(address),
        }

    @rpc_method
    async def getVault(self) -> Dict[str, Any]:
        from ...exchange import views

        return views.vault(_manager())

    @rpc_method
    async def getTrades(self, market_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        from ...exchange import views

        return views.trades(_manager(), market_id, limit)

    @rpc_method
    async def getEvents(
        self,
        market_id: Optional[str] = None,
        address: Optional[str] = None,
        types: Optional[List[str]] = None,
        since: Optional[int] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        from ...exchange import views

        return views.events(
            _manager(), market=market_id, address=address, types=types, since=since, limit=limit
        )


class MarketModule(RPCModule):
    """Market data for interfaces, one shape for spot pairs and perps markets (the REST
    ``/get_markets`` family; docs/PERPS_API.md §8). A market is a spot pair ``base:quote``
    (token addresses, unique symbols or QRDX, either order) or a perps market id."""

    namespace = "market"

    @staticmethod
    def _found(value, market: str):
        if value is None:
            raise RPCError(RPCErrorCode.RESOURCE_NOT_FOUND, f"no market {market}")
        return value

    @rpc_method
    async def getMarkets(self, kind: Optional[str] = None) -> List[Dict[str, Any]]:
        from ...exchange import views

        return views.market_tickers(_manager(), kind)

    @rpc_method
    async def getTicker(self, market: str) -> Dict[str, Any]:
        from ...exchange import views

        return self._found(views.market_ticker(_manager(), market), market)

    @rpc_method
    async def getOrderBook(self, market: str, depth: int = 50, level: int = 2) -> Dict[str, Any]:
        from ...exchange import views

        return self._found(views.market_book(_manager(), market, depth, level), market)

    @rpc_method
    async def getTrades(
        self, market: str, limit: int = 100, since: Optional[int] = None
    ) -> Dict[str, Any]:
        from ...exchange import views

        return self._found(views.market_trades(_manager(), market, limit, since), market)

    @rpc_method
    async def getCandles(
        self, market: str, interval: str = "1m", limit: int = 200, end: Optional[float] = None
    ) -> Dict[str, Any]:
        from ...exchange import views

        try:
            found = views.market_candles(_manager(), market, interval, limit, end)
        except ValueError as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, str(e)) from e
        return self._found(found, market)


class AccountModule(RPCModule):
    """Who may sign for an address, and what an address may sign for (docs/ACCOUNT_CONTROL.md):
    ``account_getAuthority(address)`` / ``account_getControlled(address)``."""

    namespace = "account"

    @rpc_method
    async def getAuthority(self, address: str) -> Dict[str, Any]:
        from ...exchange import views

        try:
            return views.authority(_manager(), address)
        except ValueError as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, str(e)) from e

    @rpc_method
    async def getControlled(self, address: str) -> Dict[str, Any]:
        from ...exchange import views

        try:
            return views.controlled(_manager(), address)
        except ValueError as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, str(e)) from e


class QnsModule(RPCModule):
    """QNS, the QRDX Name Service (docs/QNS.md): ``qns_resolve(name)``, ``qns_reverse(address)``,
    ``qns_getName(name)``, ``qns_namesOf(address)``, ``qns_price(years)``."""

    namespace = "qns"

    @staticmethod
    def _now():
        from decimal import Decimal

        return Decimal(str(_manager()._block_clock()))

    @rpc_method
    async def resolve(self, name: str) -> Optional[str]:
        from ...exchange.qns import QnsError, normalize

        mgr = _manager()
        try:
            return mgr.qns.resolve(mgr.nfts, normalize(name), self._now())
        except QnsError as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, str(e)) from e

    @rpc_method
    async def reverse(self, address: str) -> Optional[str]:
        mgr = _manager()
        try:
            return mgr.qns.reverse(mgr.nfts, address, self._now())
        except ValueError as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, str(e)) from e

    @rpc_method
    async def getName(self, name: str) -> Optional[Dict[str, Any]]:
        from ...exchange.qns import QnsError, normalize, summary

        mgr = _manager()
        try:
            return summary(mgr.qns, mgr.nfts, normalize(name), self._now())
        except QnsError as e:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, str(e)) from e

    @rpc_method
    async def namesOf(self, address: str) -> List[str]:
        mgr = _manager()
        return mgr.qns.names_of(mgr.nfts, address)

    @rpc_method
    async def price(self, years: int = 1) -> str:
        from ... import constants

        return str(constants.QNS_PRICE_PER_YEAR * int(years))
