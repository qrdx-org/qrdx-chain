"""Test helper: what an executed exchange operation pays for gas (docs/PERPS_API.md §1).

Every executed operation — success or failure — pays its gas at the gas price, in QRDX, burned.
Exact-balance assertions on the production enforcement set account for it with this.
"""
from decimal import Decimal

from qrdx import constants
from qrdx.exchange.transactions import EXCHANGE_GAS_COSTS


def fee_of(op, gas_price: int = None) -> Decimal:
    price = constants.EXCHANGE_MIN_GAS_PRICE_WEI if gas_price is None else gas_price
    return Decimal(EXCHANGE_GAS_COSTS[op]) * Decimal(price) / Decimal(constants.WEI_PER_QRDX)
