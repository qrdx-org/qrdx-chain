"""
The price of a block's gas (docs/BLOCK_LIMITS.md): an EIP-1559 base fee for each kind of gas.

Each block's signed header carries two base fees: the EVM's and the exchange's, in wei per unit
of gas. Each is set by the block's parent, as Ethereum's is:

    next = parent_fee × (1 + (parent_gas − target) / target / 8),   target = limit / 2,

never below the domain's floor (``EVM_MIN_GAS_PRICE_WEI`` / ``EXCHANGE_MIN_GAS_PRICE_WEI``),
and at least one wei up when the parent was over target. ``parent_gas`` is the gas its sections
declared (oracle votes excluded). Every transaction in a block must offer at least its domain's
base fee; validators' oracle votes are exempt, so that a burst of traffic can never stall the
prices the exchange runs on. Fees are burned, as before.

Without it a block's gas cost the same however full blocks were: a sender filled every block,
slowing the chain to what a node could execute, for the floor price — and EVM transactions had no
floor at all (a gas price of 0 executed for free). Now a run of full blocks raises the price
12.5% a block: 30 seconds of them at 250 ms slots multiply it ~1.4 million times.
"""

from __future__ import annotations

import contextvars
from typing import Any, Iterable, Optional, Tuple

# The EVM base fee of the block whose EVM section is executing (evm_block_apply sets it from the
# chain; the BASEFEE opcode reads it). None outside a block: the floor.
CURRENT_EVM_BASE_FEE: "contextvars.ContextVar[Optional[int]]" = contextvars.ContextVar(
    "qrdx_current_evm_base_fee", default=None
)

ELASTICITY = 2  # the target is half the limit
CHANGE_DENOMINATOR = 8  # at most 1/8 up or down per block


def next_base_fee(parent_fee: int, parent_gas: int, limit: int, floor: int) -> int:
    """The base fee after a block that declared ``parent_gas`` of a domain's ``limit``."""
    target = max(1, int(limit) // ELASTICITY)
    fee, gas = int(parent_fee), int(parent_gas)
    if gas > target:
        fee += max(1, fee * (gas - target) // target // CHANGE_DENOMINATOR)
    elif gas < target:
        fee -= fee * (target - gas) // target // CHANGE_DENOMINATOR
    return max(int(floor), fee)


def floors() -> Tuple[int, int]:
    from .constants import EVM_MIN_GAS_PRICE_WEI, EXCHANGE_MIN_GAS_PRICE_WEI

    return int(EVM_MIN_GAS_PRICE_WEI), int(EXCHANGE_MIN_GAS_PRICE_WEI)


def _is_vote(item: Any) -> bool:
    from .exchange.transactions import ExchangeOpType

    op = item.get("op_type") if isinstance(item, dict) else getattr(item, "op_type", None)
    if op is None:
        return False
    try:
        return int(op) == int(ExchangeOpType.ORACLE_VOTE)
    except (TypeError, ValueError):
        return False


def _price(item: Any) -> int:
    raw = item.get("gas_price", 0) if isinstance(item, dict) else getattr(item, "gas_price", 0)
    return int(raw)


def fee_gas(
    exchange_section: Optional[Iterable[Any]], evm_section: Optional[Iterable[str]]
) -> Tuple[int, int]:
    """(EVM gas, exchange gas) a block's sections declared, for its children's base fees —
    oracle votes excluded."""
    from .block_limits import exchange_section_gas
    from .contracts.evm_mempool import parse_eth_raw_tx

    evm_gas = sum(int(parse_eth_raw_tx(raw)["gas"]) for raw in evm_section or ())
    exchange_gas = exchange_section_gas([i for i in exchange_section or () if not _is_vote(i)])
    return evm_gas, exchange_gas


def header_fees(block: Optional[dict]) -> Tuple[int, int]:
    """The base fees a block's header declares (the floors for genesis, which has none)."""
    evm_floor, exchange_floor = floors()
    if not block:
        return evm_floor, exchange_floor
    return int(block.get("base_fee", evm_floor)), int(
        block.get("exchange_base_fee", exchange_floor)
    )


def child_fees(
    parent: Optional[dict],
    parent_exchange_section: Optional[Iterable[Any]],
    parent_evm_section: Optional[Iterable[str]],
) -> Tuple[int, int]:
    """The base fees of the block whose parent is ``parent`` (its content), given the sections
    the parent carried."""
    from .constants import BLOCK_EXCHANGE_GAS_LIMIT, BLOCK_GAS_LIMIT

    evm_floor, exchange_floor = floors()
    evm_fee, exchange_fee = header_fees(parent)
    evm_gas, exchange_gas = fee_gas(parent_exchange_section, parent_evm_section)
    return (
        next_base_fee(evm_fee, evm_gas, BLOCK_GAS_LIMIT, evm_floor),
        next_base_fee(exchange_fee, exchange_gas, BLOCK_EXCHANGE_GAS_LIMIT, exchange_floor),
    )


async def base_fees_at(db: Any, height: int) -> Tuple[int, int]:
    """The base fees of a block at ``height`` on the stored chain: set by its parent, the block
    at ``height − 1`` (stored, with its sections, before anything is built on it)."""
    from .validator.block_verification import _parse_block_content

    if height <= 1:  # the parent is genesis: no fees, no sections
        return floors()
    parent = await db.get_block_by_id(int(height) - 1)
    if not parent:
        return floors()
    try:
        content = _parse_block_content(parent.get("content") or parent.get("block_content"))
    except (ValueError, SyntaxError):
        content = None  # no header to read: the floors (every node reads the same bytes)
    parent_hash = parent.get("hash") or parent.get("block_hash")
    exchange = await db.get_block_exchange_txs(parent_hash)
    evm = await db.get_block_evm_txs(parent_hash)
    return child_fees(content, exchange, evm)


def block_fee_error(
    block: dict,
    exchange_section: Optional[Iterable[Any]],
    evm_section: Optional[Iterable[str]],
    expected: Tuple[int, int],
) -> str:
    """Why a block's fees are wrong, or "" if they are right: its header must declare the base
    fees its parent sets, and every transaction it carries must offer at least them (oracle
    votes exempt)."""
    from .contracts.evm_mempool import parse_eth_raw_tx

    try:
        declared = (int(block["base_fee"]), int(block["exchange_base_fee"]))
    except (KeyError, TypeError, ValueError):
        return "block declares no base fees"
    if declared != tuple(expected):
        return f"base fees {declared} are not the parent's {tuple(expected)}"
    evm_fee, exchange_fee = declared
    for i, raw in enumerate(evm_section or ()):
        price = int(parse_eth_raw_tx(raw)["gas_price"])
        if price < evm_fee:
            return f"evm tx {i} offers {price} wei of gas, under the base fee {evm_fee}"
    for i, item in enumerate(exchange_section or ()):
        if _is_vote(item):
            continue
        price = _price(item)
        if price < exchange_fee:
            return f"exchange op {i} offers {price} wei of gas, under the base fee {exchange_fee}"
    return ""


def with_headroom(fee: int) -> int:
    """A price that still pays the base fee after one more full block (at most 1/8 higher):
    what to offer a transaction meant for the next block or two."""
    return int(fee) + max(1, int(fee) // CHANGE_DENOMINATOR)


async def suggested_prices(db: Any) -> Tuple[int, int]:
    """(EVM, exchange) gas prices to offer now: the next block's base fees, with headroom."""
    tip = int(await db.get_next_block_id()) - 1
    evm_fee, exchange_fee = await base_fees_at(db, tip + 1)
    return with_headroom(evm_fee), with_headroom(exchange_fee)


def current_evm_base_fee() -> int:
    """What the BASEFEE opcode returns: the executing block's EVM base fee, or the floor."""
    fee = CURRENT_EVM_BASE_FEE.get()
    return int(fee) if fee is not None else floors()[0]
