"""
Where a validator's oracle votes come from (docs/PERPS_CLEARINGHOUSE.md §8).

``QRDX_ORACLE_FEED`` selects the source:

    file:<path>                 a JSON object {"BTC": "65000.5", ...}, re-read on every vote — the
                                testnet's scripted feed (the integration scenarios write it)
    static:BTC=65000,ETH=3200   fixed prices (development)
    exchanges                   the median of USD spot prices from several public exchange APIs,
                                refreshed in the background (production)
    (unset)                     this validator does not vote

A vote is an INPUT to consensus, like a transaction: it need not be deterministic, and a node
whose feed fails simply does not vote. The chain aggregates the committee's votes
deterministically — a stake-weighted median, so a minority of wrong feeds cannot move it.
Markets are quoted in USD; a market base with a "q" prefix (qBTC, the bridged asset) is priced
as its underlying.
"""
from __future__ import annotations

import json
import os
import statistics
import threading
import time
from decimal import Decimal, InvalidOperation
from typing import Callable, Dict, Iterable, List, Optional

from ..logger import get_logger

logger = get_logger(__name__)


def _positive(value) -> Optional[Decimal]:
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None
    return d if d.is_finite() and d > 0 else None


def underlying(base: str) -> str:
    """qBTC → BTC: a bridged asset is priced as what it bridges."""
    return base[1:] if len(base) > 1 and base[0] == "q" and base[1:].isupper() else base


class PriceFeed:
    def prices(self, bases: Iterable[str]) -> Dict[str, Decimal]:
        """USD prices for whichever of ``bases`` the feed knows; others are left out."""
        raise NotImplementedError


class StaticPriceFeed(PriceFeed):
    def __init__(self, spec: str):
        self._prices: Dict[str, Decimal] = {}
        for item in spec.split(","):
            if "=" in item:
                k, v = item.split("=", 1)
                p = _positive(v.strip())
                if p is not None:
                    self._prices[k.strip()] = p

    def prices(self, bases):
        return {b: self._prices[b] for b in bases if b in self._prices}


class FilePriceFeed(PriceFeed):
    def __init__(self, path: str):
        self.path = path

    def prices(self, bases):
        try:
            with open(self.path) as f:
                data = json.load(f)
        except (OSError, ValueError):
            return {}
        out = {}
        for b in bases:
            p = _positive(data.get(b)) if isinstance(data, dict) else None
            if p is not None:
                out[b] = p
        return out


# Public USD spot endpoints: symbol → (url, how to read the price from the JSON body).
_EXCHANGES: List[Callable[[str], tuple]] = [
    lambda s: (f"https://api.coinbase.com/v2/prices/{s}-USD/spot",
               lambda j: j["data"]["amount"]),
    lambda s: (f"https://api.kraken.com/0/public/Ticker?pair={s}USD",
               lambda j: next(iter(j["result"].values()))["c"][0]),
    lambda s: (f"https://api.binance.com/api/v3/ticker/price?symbol={s}USDT",
               lambda j: j["price"]),
]


class ExchangePriceFeed(PriceFeed):
    """Median of the exchanges that answered, per asset, refreshed every ``interval`` seconds in
    a background thread so block production never waits on the network. Prices older than
    ``max_age`` are not voted."""

    def __init__(self, interval: float = 5.0, max_age: float = 30.0, timeout: float = 3.0):
        self.interval, self.max_age, self.timeout = interval, max_age, timeout
        self._cache: Dict[str, tuple] = {}            # symbol → (price, fetched_at)
        self._wanted: set = set()
        self._lock = threading.Lock()
        threading.Thread(target=self._run, daemon=True, name="oracle-feed").start()

    def prices(self, bases):
        now, out = time.time(), {}
        with self._lock:
            for b in bases:
                self._wanted.add(underlying(b))
                hit = self._cache.get(underlying(b))
                if hit and now - hit[1] <= self.max_age:
                    out[b] = hit[0]
        return out

    def _run(self):
        import httpx
        while True:
            with self._lock:
                wanted = sorted(self._wanted)
            for symbol in wanted:
                quotes = []
                for endpoint in _EXCHANGES:
                    url, read = endpoint(symbol)
                    try:
                        r = httpx.get(url, timeout=self.timeout)
                        p = _positive(read(r.json()))
                        if p is not None:
                            quotes.append(p)
                    except Exception as e:
                        logger.debug("oracle feed: %s: %s", url, e)
                if quotes:
                    with self._lock:
                        self._cache[symbol] = (statistics.median(quotes), time.time())
            time.sleep(self.interval)


def feed_from_env(spec: Optional[str] = None) -> Optional[PriceFeed]:
    spec = (os.getenv("QRDX_ORACLE_FEED", "") if spec is None else spec).strip()
    if not spec:
        return None
    if spec.startswith("file:"):
        return FilePriceFeed(spec[len("file:"):])
    if spec.startswith("static:"):
        return StaticPriceFeed(spec[len("static:"):])
    if spec == "exchanges":
        return ExchangePriceFeed()
    logger.warning("QRDX_ORACLE_FEED=%r is not a known feed; this validator will not vote", spec)
    return None


def build_vote(wallet, nonce: int, prices: Dict[str, Decimal]):
    """An ORACLE_VOTE exchange transaction signed by the validator's PQ wallet."""
    from ..exchange import ExchangeOpType, ExchangeTransaction
    tx = ExchangeTransaction(
        op_type=ExchangeOpType.ORACLE_VOTE, sender=wallet.address, nonce=nonce,
        params={"prices": {b: str(p) for b, p in sorted(prices.items())}},
        gas_limit=100_000, gas_price=Decimal("1"))
    tx.public_key = wallet.public_key
    tx.signature = wallet.sign(tx.signing_bytes())
    return tx
