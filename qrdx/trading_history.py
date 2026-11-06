"""
The trading history — every trade, every order's life, funding and market samples, kept.

The exchange journal (qrdx/exchange/journal.py) keeps recent trades and events in memory, and
only so many (1,000 trades a market). This writes what each committed block traded to the
database for good:

* **trades** — every fill on every venue: perps (including liquidations, fired triggers, TWAP
  slices and the backstop vault's unwinds), the spot order books and the AMM pools; with both
  sides' order ids, and each account's fee and realized PnL;
* **orders** — each order's life: placed (or refused), changed, cancelled, triggered,
  finished, liquidated — so a cancelled or filled order is still there;
* **funding** — every funding settlement of every perp market;
* **samples** — each perp market's mark, oracle, open interest and funding rate, once a minute.

The journal hands over each committed block's rows (``history_outbox``); the indexer writes
them under the block-processing lock, a batch per pass. A reorg rolls the journal back, which
marks the height (``history_cut``); the indexer deletes everything above it before writing
again, and a re-applied height replaces what was written for it. Accounts are filed by their
canonical account id (qrdx/crypto/account_id.py), as in the transaction index.

Derived, node-local, never hashed — like the transaction index (qrdx/tx_index.py).
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

from .tx_index import account_key, parse_cursor

logger = logging.getLogger(__name__)

FLUSH_BATCH = 500  # blocks written per pass under the lock
MAX_PAGE = 500
LEADERBOARD_WINDOWS = {"day": 86400, "week": 7 * 86400, "month": 30 * 86400, "all": None}


async def flush(db, journal, *, max_blocks: int = FLUSH_BATCH) -> int:
    """Write the journal's waiting rows (after any reorg cut); returns the blocks written."""
    if journal is None or not hasattr(db, "hist_write_block"):
        return 0
    if journal.history_cut is not None:
        await db.hist_cut(int(journal.history_cut) + 1)
        journal.history_cut = None
    done = 0
    for height in list(journal.history_outbox)[:max_blocks]:
        await db.hist_write_block(int(height), journal.history_outbox[height])
        del journal.history_outbox[height]
        done += 1
    return done


async def history_poller(
    db_getter,
    lock: Optional[asyncio.Lock] = None,
    *,
    get_journal,
    interval: float = 1.0,
    _max_iterations: Optional[int] = None,
) -> None:
    """Follow the journal: each pass writes what is waiting, under ``lock`` (the journal is
    written at block commit, under the same lock). Never raises."""
    iterations = 0
    while True:
        try:
            db = db_getter()
            if db is not None:
                if lock is not None:
                    async with lock:
                        done = await flush(db, get_journal())
                else:
                    done = await flush(db, get_journal())
                if done >= FLUSH_BATCH:
                    await asyncio.sleep(0)
                    continue
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.debug("trading history pass failed: %s", e)
        iterations += 1
        if _max_iterations is not None and iterations >= _max_iterations:
            break
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            break


# ── rows for the database ──────────────────────────────────────────────────


def trade_accounts(trade: Dict[str, Any]) -> List[Dict[str, Any]]:
    """A trade's rows per account: its two sides (role maker or taker), each with the
    notional, its fee and its realized PnL (perps)."""
    out = []
    try:
        notional = str(float(trade["price"]) * float(trade["amount"]))
    except (TypeError, ValueError, KeyError):
        notional = None
    for side in ("buyer", "seller"):
        who = trade.get(side)
        key = account_key(who)
        if key is None:
            continue
        out.append(
            {
                "account": key,
                "role": "maker" if who == trade.get("maker") else "taker",
                "side": "buy" if side == "buyer" else "sell",
                "notional": notional,
                "fee": (trade.get("fees") or {}).get(who),
                "realized": (trade.get("realized") or {}).get(who),
            }
        )
    return out


# ── reading it ─────────────────────────────────────────────────────────────


def _page(rows: List[Dict[str, Any]], limit: int) -> Dict[str, Any]:
    for row in rows:
        for key in ("detail", "fees", "realized"):
            if isinstance(row.get(key), str):
                try:
                    row[key] = json.loads(row[key])
                except ValueError:
                    pass
        row["cursor"] = f"{row['block_height']}:{row['position']}"
    return {
        "items": rows,
        "next_cursor": rows[-1]["cursor"] if len(rows) == limit else None,
    }


def _limit(limit: Any) -> int:
    return max(1, min(int(limit), MAX_PAGE))


async def trades(
    db,
    *,
    address: Optional[str] = None,
    market: Optional[str] = None,
    limit: int = 100,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """Trades, newest first, a page at a time: an address's (``address``), a market's, or
    both."""
    limit = _limit(limit)
    rows = await db.hist_trades(
        account=account_key(address) if address else None,
        market=market,
        before=parse_cursor(cursor),
        limit=limit,
    )
    return _page(rows, limit)


async def orders(
    db,
    *,
    address: Optional[str] = None,
    market: Optional[str] = None,
    order_id: Optional[str] = None,
    limit: int = 100,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """Order events, newest first: an address's, a market's or one order's."""
    if not (address or order_id):
        raise ValueError("give an address or an order id")
    limit = _limit(limit)
    rows = await db.hist_orders(
        account=account_key(address) if address else None,
        market=market,
        order_id=order_id,
        before=parse_cursor(cursor),
        limit=limit,
    )
    return _page(rows, limit)


async def funding(
    db, market: str, *, limit: int = 100, cursor: Optional[str] = None
) -> Dict[str, Any]:
    limit = _limit(limit)
    return _page(await db.hist_funding(market, before=parse_cursor(cursor), limit=limit), limit)


async def samples(
    db,
    market: str,
    *,
    since: Optional[float] = None,
    until: Optional[float] = None,
    limit: int = 500,
) -> List[Dict[str, Any]]:
    """A perp market's minute samples (mark, oracle, open interest, funding rate), oldest
    first."""
    return await db.hist_samples(market, since=since, until=until, limit=_limit(limit))


async def leaderboard(
    db, *, window: str = "day", metric: str = "pnl", now: Optional[float] = None, limit: int = 50
) -> List[Dict[str, Any]]:
    """Perps accounts ranked by realized PnL net of fees (``pnl``) or by volume, over the last
    day, week, month or all time of block time."""
    if window not in LEADERBOARD_WINDOWS:
        raise ValueError(f"window is one of {', '.join(LEADERBOARD_WINDOWS)}")
    if metric not in ("pnl", "volume"):
        raise ValueError("metric is pnl or volume")
    span = LEADERBOARD_WINDOWS[window]
    since = None
    if span is not None:
        latest = now if now is not None else await db.hist_latest_time()
        since = None if latest is None else float(latest) - span
    return await db.hist_leaderboard(since=since, metric=metric, limit=_limit(limit))
