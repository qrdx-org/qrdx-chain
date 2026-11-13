"""
Read-only REST views of the exchange: perps, spot, tokens, pools, NFTs and market data.

The node's state (the database, the HTTP client, the EVM and exchange runtimes, this node's
identity) lives in qrdx.node.main and is read from it at call time, as ``_node.<name>``:
startup rebinds it, and tests replace it.
"""

from typing import Optional

from fastapi import Query

from qrdx.logger import get_logger
from qrdx.node import main as _node
from qrdx.node.main import app

logger = get_logger(__name__)


@app.get("/get_exchange_state_root")
async def get_exchange_state_root():
    """
    Return this node's current exchange state root (Whitepaper §3.6 BLAKE3-512).

    Read-only view of the protocol-level exchange state. All honest nodes that
    have imported the same blocks must report an identical root — the cross-node
    consistency guarantee enforced by D3 import replay.
    """
    try:
        from qrdx.exchange import ExchangeStateManager

        mgr = ExchangeStateManager.get_instance()
        return {
            "ok": True,
            "result": {
                "exchange_state_root": mgr.compute_state_root(),
                # The root commits to the height, and the exchange ticks every block: compare
                # roots between nodes only at the same height.
                "block_height": mgr._current_block_height,
                "pools": mgr.pool_count,
                "pairs": mgr.pair_count,
            },
        }
    except Exception as e:
        logger.error(f"get_exchange_state_root error: {e}")
        return {"ok": False, "error": str(e)}


@app.get("/get_perp_account")
async def get_perp_account(address: str):
    """
    One perps account (docs/PERPS_CLEARINGHOUSE.md): exchange nonce, collateral, withdrawable,
    equity and margin, positions (with unrealized PnL and an estimated liquidation price), open
    orders, vault shares — plus the clearinghouse holder and the backstop vault. Identical on
    every node that has imported the same blocks.
    """
    try:
        from qrdx.exchange import ExchangeStateManager, views

        return {"ok": True, "result": views.account(ExchangeStateManager.get_instance(), address)}
    except Exception as e:
        logger.error(f"get_perp_account error: {e}")
        return {"ok": False, "error": str(e)}


@app.get("/get_perp_orders")
async def get_perp_orders(address: str):
    """An address's resting perp orders, every market."""
    from qrdx.exchange import ExchangeStateManager, views

    return {"ok": True, "result": views.open_orders(ExchangeStateManager.get_instance(), address)}


@app.get("/get_perp_markets")
async def get_perp_markets():
    """Every perps market: prices (oracle, mark, last), open interest, top of book, funding."""
    from qrdx.exchange import ExchangeStateManager, views

    return {"ok": True, "result": views.markets(ExchangeStateManager.get_instance())}


@app.get("/get_perp_orderbook")
async def get_perp_orderbook(market_id: str, depth: int = Query(default=20, ge=1, le=500)):
    """A market's order book: aggregated price levels, best first."""
    from qrdx.exchange import ExchangeStateManager, views

    book = views.order_book(ExchangeStateManager.get_instance(), market_id, depth)
    if book is None:
        return {"ok": False, "error": f"market {market_id} not found"}
    return {"ok": True, "result": book}


@app.get("/get_perp_vault")
async def get_perp_vault():
    """The backstop vault: NAV, shares, share value, the positions it carries, the lockup."""
    from qrdx.exchange import ExchangeStateManager, views

    return {"ok": True, "result": views.vault(ExchangeStateManager.get_instance())}


@app.get("/get_perp_trades")
async def get_perp_trades(market_id: str, limit: int = Query(default=50, ge=1, le=1000)):
    """A market's recent fills, oldest first (liquidation fills included, and flagged)."""
    from qrdx.exchange import ExchangeStateManager, views

    return {
        "ok": True,
        "result": views.trades(ExchangeStateManager.get_instance(), market_id, limit),
    }


@app.get("/get_perp_events")
async def get_perp_events(
    market_id: Optional[str] = None,
    address: Optional[str] = None,
    types: Optional[str] = None,
    since: Optional[int] = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    """The perps event feed — fills, liquidations, funding settlements — filtered by market,
    address (a fill's buyer or seller, a liquidation's owner), comma-separated ``types``, and
    ``since`` (a sequence number: return only newer events). ``last_seq`` is the newest
    sequence number, to resume from."""
    from qrdx.exchange import ExchangeStateManager, views

    return {
        "ok": True,
        "result": views.events(
            ExchangeStateManager.get_instance(),
            market=market_id,
            address=address,
            types=[t.strip() for t in types.split(",") if t.strip()] if types else None,
            since=since,
            limit=limit,
        ),
    }


@app.get("/get_token_balance")
async def get_token_balance(token_address: str, address: str):
    """Read-only: one holder's balance in the consensus QRC-20 token ledger. Any address form,
    including protocol holders (the perps clearinghouse, pool reserves, order-book escrow)."""
    try:
        from qrdx.exchange import ExchangeStateManager, views

        return {
            "ok": True,
            "result": {
                "token_address": token_address,
                "address": address,
                "balance": str(await _node.db.get_token_balance(token_address, address)),
                "frozen": views.token_frozen(
                    ExchangeStateManager.get_instance(), token_address, address
                ),
            },
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.get("/get_tokens")
async def get_tokens():
    """Every native token: name, symbol, decimals, supply, max supply, mint and freeze
    authorities (docs/NATIVE_TOKENS.md)."""
    from qrdx.exchange import ExchangeStateManager, views

    return {"ok": True, "result": views.tokens(ExchangeStateManager.get_instance())}


@app.get("/get_token")
async def get_token(token_address: str):
    """One native token's registry entry."""
    from qrdx.exchange import ExchangeStateManager, views

    found = views.token(ExchangeStateManager.get_instance(), token_address)
    if found is None:
        return {"ok": False, "error": f"token {token_address} not found"}
    return {"ok": True, "result": found}


@app.get("/get_token_allowance")
async def get_token_allowance(token_address: str, owner: str, spender: str):
    """How much of ``owner``'s tokens ``spender`` may move with TOKEN_TRANSFER_FROM."""
    from qrdx.exchange import ExchangeStateManager, views

    try:
        return {
            "ok": True,
            "result": views.token_allowance(
                ExchangeStateManager.get_instance(), token_address, owner, spender
            ),
        }
    except ValueError as e:
        return {"ok": False, "error": str(e)}


@app.get("/get_pools")
async def get_pools(token_a: Optional[str] = None, token_b: Optional[str] = None):
    """Spot AMM pools — all of them, or one pair's: price, tick, active liquidity, fee tier,
    protocol fees, volume, and the holder address that owns the pool's reserves."""
    from qrdx.exchange import ExchangeStateManager, views

    return {
        "ok": True,
        "result": views.pools(ExchangeStateManager.get_instance(), token_a, token_b),
    }


@app.get("/get_pool")
async def get_pool(pool_id: str, twap_window: Optional[int] = Query(default=None, ge=1)):
    """One AMM pool with its initialized ticks and positions. ``twap_window`` (seconds of block
    time) adds the pool's time-weighted price over that window."""
    from qrdx.exchange import ExchangeStateManager, views

    found = views.pool(ExchangeStateManager.get_instance(), pool_id, twap_window)
    if found is None:
        return {"ok": False, "error": f"pool {pool_id} not found"}
    return {"ok": True, "result": found}


@app.get("/get_liquidity_quote")
async def get_liquidity_quote(
    pool_id: str,
    tick_lower: int,
    tick_upper: int,
    liquidity: Optional[str] = None,
    amount0: Optional[str] = None,
    amount1: Optional[str] = None,
):
    """What adding liquidity to a range costs: pass ``liquidity`` for its exact deposit, or
    ``amount0`` / ``amount1`` for the most liquidity they buy at the current price. Ticks are
    multiples of the pool's tick spacing; the result's ``liquidity`` is ADD_LIQUIDITY's
    ``amount``."""
    from qrdx.exchange import ExchangeStateManager, views

    try:
        found = views.liquidity_quote(
            ExchangeStateManager.get_instance(),
            pool_id,
            tick_lower,
            tick_upper,
            liquidity,
            amount0,
            amount1,
        )
    except (ValueError, ArithmeticError) as e:
        return {"ok": False, "error": str(e)}
    if found is None:
        return {"ok": False, "error": f"pool {pool_id} not found"}
    return {"ok": True, "result": found}


@app.get("/get_lp_positions")
async def get_lp_positions(address: str):
    """An address's liquidity positions, every pool: range, liquidity, whether it is in range,
    and what removing it would pay right now (principal + uncollected fees)."""
    from qrdx.exchange import ExchangeStateManager, views

    return {"ok": True, "result": views.positions(ExchangeStateManager.get_instance(), address)}


@app.get("/get_swap_quote")
async def get_swap_quote(
    token_in: str,
    token_out: str,
    amount_in: str,
    sender: str = "",
    pool_id: Optional[str] = None,
    venue: str = "auto",
):
    """The exact fill a SWAP would get right now — the router's own quote across the pair's
    pools and its order book (``venue`` auto | amm | clob, ``pool_id`` pins a pool). Pass
    ``sender`` so the quote stops where self-trade prevention would. Set the swap's
    ``min_amount_out`` from ``amount_out`` less your slippage tolerance."""
    from qrdx.exchange import ExchangeStateManager, views

    try:
        found = views.quote(
            ExchangeStateManager.get_instance(),
            token_in,
            token_out,
            amount_in,
            sender,
            pool_id,
            venue,
        )
    except (ValueError, ArithmeticError) as e:
        return {"ok": False, "error": str(e)}
    if found is None:
        return {"ok": False, "error": "no liquidity for this swap"}
    return {"ok": True, "result": found}


@app.get("/get_spot_orderbook")
async def get_spot_orderbook(pair: str, depth: int = Query(default=20, ge=1, le=500)):
    """A spot pair's order book (``tokenA:tokenB`` by address, either order): aggregated price
    levels in quote per base, best first."""
    from qrdx.exchange import ExchangeStateManager, views

    book = views.spot_order_book(ExchangeStateManager.get_instance(), pair, depth)
    if book is None:
        return {"ok": False, "error": f"no order book for {pair}"}
    return {"ok": True, "result": book}


@app.get("/get_nft_collections")
async def get_nft_collections():
    """Every native NFT collection: metadata, size, royalties, authorities."""
    from qrdx.exchange import ExchangeStateManager, views

    return {"ok": True, "result": views.nft_collections(ExchangeStateManager.get_instance())}


@app.get("/get_nft_collection")
async def get_nft_collection(collection: str):
    from qrdx.exchange import ExchangeStateManager, views

    found = views.nft_collection(ExchangeStateManager.get_instance(), collection)
    if found is None:
        return {"ok": False, "error": f"collection {collection} not found"}
    return {"ok": True, "result": found}


@app.get("/get_nft")
async def get_nft(collection: str, token_id: str):
    """One NFT: its owner, metadata uri, name, approval, and its collection's royalties."""
    from qrdx.exchange import ExchangeStateManager, views

    found = views.nft(ExchangeStateManager.get_instance(), collection, token_id)
    if found is None:
        return {"ok": False, "error": f"NFT {collection} #{token_id} not found"}
    return {"ok": True, "result": found}


@app.get("/get_nfts")
async def get_nfts(
    owner: str, collection: Optional[str] = None, limit: int = Query(default=500, ge=1, le=5000)
):
    """An owner's NFTs (its 0x or 0xPQ address), every collection or one."""
    from qrdx.exchange import ExchangeStateManager, views

    return {
        "ok": True,
        "result": views.nfts_of(ExchangeStateManager.get_instance(), owner, collection, limit),
    }


@app.get("/get_spot_orders")
async def get_spot_orders(address: str):
    """An address's resting spot orders, every pair."""
    from qrdx.exchange import ExchangeStateManager, views

    return {
        "ok": True,
        "result": views.spot_open_orders(ExchangeStateManager.get_instance(), address),
    }


# ── market data: one shape for spot pairs and perps markets (docs/PERPS_API.md §8) ──


@app.get("/get_markets")
async def get_markets(kind: Optional[str] = None):
    """Every market's ticker — spot pairs (order book and/or AMM pools) and perps markets:
    top of book, last price, 24h open/high/low/change/volume. ``kind`` = spot | perp."""
    from qrdx.exchange import ExchangeStateManager, views

    return {"ok": True, "result": views.market_tickers(ExchangeStateManager.get_instance(), kind)}


@app.get("/get_ticker")
async def get_ticker(market: str):
    """One market's ticker. ``market`` is a spot pair ``base:quote`` (addresses, unique
    symbols or QRDX, either order) or a perps market id."""
    from qrdx.exchange import ExchangeStateManager, views

    found = views.market_ticker(ExchangeStateManager.get_instance(), market)
    if found is None:
        return {"ok": False, "error": f"no market {market}"}
    return {"ok": True, "result": found}


@app.get("/get_orderbook")
async def get_orderbook(
    market: str,
    depth: int = Query(default=50, ge=1, le=1000),
    level: int = Query(default=2, ge=2, le=3),
):
    """A market's order book: level 2 = price levels with running base/quote totals, level 3 =
    every resting order per level in time priority; plus best bid/ask, spread (and in bps),
    mid, last price, the block height it reflects and, for a spot pair, its AMM pools."""
    from qrdx.exchange import ExchangeStateManager, views

    found = views.market_book(ExchangeStateManager.get_instance(), market, depth, level)
    if found is None:
        return {"ok": False, "error": f"no market {market}"}
    return {"ok": True, "result": found}


@app.get("/get_trades")
async def get_trades(
    market: str, limit: int = Query(default=100, ge=1, le=1000), since: Optional[int] = None
):
    """A market's recent trades, oldest first — order-book fills, AMM swaps, perps fills — with
    the taker's side and the transaction. ``since`` (a trade ``seq``) returns only newer ones."""
    from qrdx.exchange import ExchangeStateManager, views

    found = views.market_trades(ExchangeStateManager.get_instance(), market, limit, since)
    if found is None:
        return {"ok": False, "error": f"no market {market}"}
    return {"ok": True, "result": found}


@app.get("/get_candles")
async def get_candles(
    market: str,
    interval: str = "1m",
    limit: int = Query(default=200, ge=1, le=1500),
    end: Optional[float] = None,
):
    """OHLCV candles by block time (1m 5m 15m 1h 4h 1d)."""
    from qrdx.exchange import ExchangeStateManager, views

    try:
        found = views.market_candles(
            ExchangeStateManager.get_instance(), market, interval, limit, end
        )
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    if found is None:
        return {"ok": False, "error": f"no market {market}"}
    return {"ok": True, "result": found}


@app.get("/get_perp_market")
async def get_perp_market(market_id: str):
    """
    One perps market (docs/PERPS_CLEARINGHOUSE.md): oracle, mark and last trade prices, open
    interest, the top of the book, and funding — the rate last paid, when, when the next is due,
    and the premium accumulated since. Identical on every node that has imported the same blocks.
    """
    try:
        from qrdx.exchange import ExchangeStateManager, views

        found = views.market(ExchangeStateManager.get_instance(), market_id)
        if found is None:
            return {"ok": False, "error": f"market {market_id} not found"}
        return {"ok": True, "result": found}
    except Exception as e:
        logger.error(f"get_perp_market error: {e}")
        return {"ok": False, "error": str(e)}
