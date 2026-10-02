"""Test helper: give a perp market an oracle price.

Perps execute, settle and liquidate at the market's oracle mark price, never a price the
trader names (tests/test_perp_price_integrity.py). In consensus that price arrives through an
UPDATE_ORACLE from an authorized reporter, and the mark then follows the index through an
EMA. Unit tests of settlement math need an exact price, so this sets index = mark = price
directly, stamped at the manager's current block time so it is never stale.
"""
from decimal import Decimal


def price_market(mgr, market_id, price):
    market = mgr.perp_engine.get_market(market_id)
    market.index_price = Decimal(str(price))
    market.mark_price = Decimal(str(price))
    market.last_price_update = float(getattr(mgr, "_current_block_timestamp", 0.0) or 0.0)
    return market
