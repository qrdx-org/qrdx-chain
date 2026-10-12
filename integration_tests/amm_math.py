"""AMM price helpers for the scenarios that create pools (s15, s17, s18)."""

import math
from decimal import Decimal

from qrdx.exchange.amm import Q96


def price_to_sqrt_price_q96(price: Decimal) -> Decimal:
    """Convert a human-readable price to a Q96 sqrt price."""
    if price <= 0:
        raise ValueError("Price must be positive")
    sqrt_p = Decimal(str(math.sqrt(float(price)))) * Q96
    return sqrt_p.quantize(Decimal("1"))
