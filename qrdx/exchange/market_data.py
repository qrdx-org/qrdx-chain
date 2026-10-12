"""
Market data for trading interfaces — recent trades, OHLCV candles and 24-hour statistics for
every market: spot pairs (order-book fills and AMM swaps alike) and perps.

Like the journal it lives on (qrdx/exchange/journal.py), this is NOT consensus state: it is fed
only when a block commits, never hashed, and follows the canonical chain: a reorg undoes the
orphaned blocks' trades (``rollback_to``) before the new branch is applied. Times are block times. Bounded: the newest MAX_TRADES trades per market and
MAX_CANDLES candles per interval.

A market is named the way the exchange names it: a spot pair "base:quote" in canonical order
(the lower token address first; native QRDX sorts after addresses, so QRDX pairs are quoted in
QRDX), or a perps market id ("BTC-USD-PERP"). Every trade carries the taker's side ("buy"
lifts asks, "sell" hits bids), the price in quote per base, and the base amount.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from decimal import Decimal
from typing import Any, Deque, Dict, List, Optional

ZERO = Decimal(0)
MAX_TRADES = 1000
MAX_CANDLES = 1500
INTERVALS = {"1m": 60, "5m": 300, "15m": 900, "1h": 3600, "4h": 14400, "1d": 86400}
DAY = 86400


class _Market:
    def __init__(self):
        self.trades: Deque[Dict[str, Any]] = deque(maxlen=MAX_TRADES)
        # [open, high, low, close, base volume, quote volume (Decimal), trades (int)]
        self.candles: Dict[int, "OrderedDict[int, List[Any]]"] = {
            seconds: OrderedDict() for seconds in INTERVALS.values()
        }
        self.last_price: Optional[Decimal] = None
        self.trade_count = 0


class MarketData:
    def __init__(self):
        self.markets: Dict[str, _Market] = {}
        self.seq = 0  # last trade sequence number (monotonic)
        self.now = 0.0  # latest block time recorded
        # What each block changed, newest last, to undo it on a reorg (``rollback_to``): per
        # trade (height, market, the candles it touched as they were, the market's last price
        # and trade count before it, the trade it pushed out of the recent-trades window).
        self._undo: Deque[tuple] = deque()
        self._undo_now: Deque[tuple] = deque()  # (height, ``now`` before that block)

    def _market(self, market: str) -> _Market:
        m = self.markets.get(market)
        if m is None:
            m = self.markets[market] = _Market()
        return m

    # ── recording (at block commit) ───────────────────────────────────

    def record_trade(
        self,
        market: str,
        *,
        price,
        amount,
        side: str,
        block_height: int,
        block_time: float,
        venue: str,
        tx_hash: Optional[str] = None,
        maker: Optional[str] = None,
        taker: Optional[str] = None,
        pool_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        price, amount = Decimal(str(price)), Decimal(str(amount))
        if price <= 0 or amount <= 0:
            return {}
        self.seq += 1
        self.now = max(self.now, float(block_time))
        m = self._market(market)
        trade = {
            "seq": self.seq,
            "market": market,
            "price": str(price),
            "amount": str(amount),
            "quote_amount": str(price * amount),
            "side": side,
            "venue": venue,
            "block_height": int(block_height),
            "block_time": float(block_time),
            "tx_hash": tx_hash,
            "maker": maker,
            "taker": taker,
            "pool_id": pool_id,
        }
        evicted = m.trades[0] if len(m.trades) == m.trades.maxlen else None
        before: List[tuple] = []
        self._undo.append((int(block_height), market, before, m.last_price, m.trade_count, evicted))
        m.trades.append(trade)
        m.last_price = price
        m.trade_count += 1
        t = int(block_time)
        for seconds, candles in m.candles.items():
            start = t - t % seconds
            c = candles.get(start)
            before.append((seconds, start, None if c is None else list(c)))
            if c is None:
                # open, high, low, close, base volume, quote volume, trades
                candles[start] = [price, price, price, price, amount, price * amount, 1]
                while len(candles) > MAX_CANDLES:
                    candles.popitem(last=False)
            else:
                c[1] = max(c[1], price)
                c[2] = min(c[2], price)
                c[3] = price
                c[4] += amount
                c[5] += price * amount
                c[6] += 1
        return trade

    def advance(self, block_time: float, block_height: Optional[int] = None) -> None:
        if block_height is not None:
            self._undo_now.append((int(block_height), self.now))
        self.now = max(self.now, float(block_time))

    # ── reorgs ─────────────────────────────────────────────────────────

    def rollback_to(self, height: int) -> None:
        """Undo every block above ``height``: its trades, their candle updates, last prices and
        counts, and the block time. (A candle a trade pushed out of a market's MAX_CANDLES
        window stays out.) Sequence numbers are not reused."""
        while self._undo and self._undo[-1][0] > height:
            _h, market, before, last_price, count, evicted = self._undo.pop()
            m = self.markets[market]
            if m.trades:
                m.trades.pop()
            if evicted is not None:
                m.trades.appendleft(evicted)
            m.last_price, m.trade_count = last_price, count
            for seconds, start, candle in before:
                candles = m.candles[seconds]
                if candle is None:
                    candles.pop(start, None)
                else:
                    candles[start] = candle
        while self._undo_now and self._undo_now[-1][0] > height:
            self.now = self._undo_now.pop()[1]

    def prune(self, height: int) -> None:
        """Forget the undo of blocks at or below ``height`` (no reorg reaches them)."""
        while self._undo and self._undo[0][0] <= height:
            self._undo.popleft()
        while self._undo_now and self._undo_now[0][0] <= height:
            self._undo_now.popleft()

    # ── queries ────────────────────────────────────────────────────────

    def trades(
        self, market: str, limit: int = 100, since: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Newest-last trades, after sequence ``since`` when given."""
        m = self.markets.get(market)
        if m is None:
            return []
        limit = max(1, min(int(limit), MAX_TRADES))
        out = [t for t in m.trades if since is None or t["seq"] > since]
        return out[-limit:]

    def since(self, seq: int, limit: int = 1000) -> List[Dict[str, Any]]:
        """Every market's trades after sequence ``seq``, oldest first (the stream's feed)."""
        if seq >= self.seq:
            return []
        out = [t for m in self.markets.values() for t in m.trades if t["seq"] > seq]
        out.sort(key=lambda t: t["seq"])
        return out[-max(1, int(limit)) :]

    def trades_of(self, address: str, limit: int = 100) -> List[Dict[str, Any]]:
        """An address's trades (maker or taker), every market, newest last."""
        a = address.lower()
        out = [
            t
            for m in self.markets.values()
            for t in m.trades
            if a in (str(t.get("maker") or "").lower(), str(t.get("taker") or "").lower())
        ]
        out.sort(key=lambda t: t["seq"])
        return out[-max(1, min(int(limit), MAX_TRADES)) :]

    def candles(
        self, market: str, interval: str = "1m", limit: int = 200, end: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        if interval not in INTERVALS:
            raise ValueError(f"interval must be one of {', '.join(INTERVALS)}")
        m = self.markets.get(market)
        if m is None:
            return []
        limit = max(1, min(int(limit), MAX_CANDLES))
        rows = [
            (start, c)
            for start, c in m.candles[INTERVALS[interval]].items()
            if end is None or start <= end
        ]
        return [
            {
                "time": start,
                "open": str(c[0]),
                "high": str(c[1]),
                "low": str(c[2]),
                "close": str(c[3]),
                "volume": str(c[4]),
                "quote_volume": str(c[5]),
                "trades": c[6],
            }
            for start, c in rows[-limit:]
        ]

    def stats_24h(self, market: str) -> Dict[str, Any]:
        """Last price, and over the 24 hours of block time to the latest block: open, high,
        low, change, base and quote volume, trade count."""
        m = self.markets.get(market)
        empty = {
            "last_price": None,
            "open_24h": None,
            "high_24h": None,
            "low_24h": None,
            "change_24h": None,
            "change_pct_24h": None,
            "volume_24h": "0",
            "quote_volume_24h": "0",
            "trades_24h": 0,
        }
        if m is None:
            return empty
        out = dict(empty, last_price=None if m.last_price is None else str(m.last_price))
        since = self.now - DAY
        window = [c for start, c in m.candles[60].items() if start + 60 > since]
        if not window:
            return out
        opened = window[0][0]
        high = max(c[1] for c in window)
        low = min(c[2] for c in window)
        last = m.last_price
        if last is None:  # set by the same trade that opened any candle
            return out
        out.update(
            open_24h=str(opened),
            high_24h=str(high),
            low_24h=str(low),
            change_24h=str(last - opened),
            change_pct_24h=(
                str(((last - opened) / opened * 100).quantize(Decimal("0.01"))) if opened else None
            ),
            volume_24h=str(sum((c[4] for c in window), ZERO)),
            quote_volume_24h=str(sum((c[5] for c in window), ZERO)),
            trades_24h=int(sum(c[6] for c in window)),
        )
        return out
