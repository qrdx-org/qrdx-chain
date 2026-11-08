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

Big blocks (``BIG_BLOCK_INTERVAL``, docs/BLOCK_LIMITS.md) are priced on an EVM track of their own:
a big block's EVM base fee is set by the big block before it, an ordinary block's by the ordinary
block before it — so the two kinds never move each other's price — and a big block's moves up to
1/2 per big block (``BIG_BLOCK_CHANGE_DENOMINATOR``): a big block comes once an interval, and a
run of full ones must get expensive in minutes. Twenty full big blocks multiply it ~3,300 times.
"""

from __future__ import annotations

import contextvars
import weakref
from collections import OrderedDict
from typing import Any, Iterable, Optional, Tuple

# The EVM base fee of the block whose EVM section is executing (evm_block_apply sets it from the
# chain; the BASEFEE opcode reads it). None outside a block: the floor.
CURRENT_EVM_BASE_FEE: "contextvars.ContextVar[Optional[int]]" = contextvars.ContextVar(
    "qrdx_current_evm_base_fee", default=None
)

ELASTICITY = 2  # the target is half the limit
CHANGE_DENOMINATOR = 8  # at most 1/8 up or down per block


BIG_BLOCK_CHANGE_DENOMINATOR = 2  # a big block's price: at most 1/2 up or down per big block


def next_base_fee(
    parent_fee: int, parent_gas: int, limit: int, floor: int, denominator: int = CHANGE_DENOMINATOR
) -> int:
    """The base fee after a block that declared ``parent_gas`` of a domain's ``limit``."""
    target = max(1, int(limit) // ELASTICITY)
    fee, gas = int(parent_fee), int(parent_gas)
    if gas > target:
        fee += max(1, fee * (gas - target) // target // denominator)
    elif gas < target:
        fee -= fee * (target - gas) // target // denominator
    return max(int(floor), fee)


def floors() -> Tuple[int, int]:
    from .constants import EVM_MIN_GAS_PRICE_WEI, EXCHANGE_MIN_GAS_PRICE_WEI

    return int(EVM_MIN_GAS_PRICE_WEI), int(EXCHANGE_MIN_GAS_PRICE_WEI)


def _is_vote(item: Any) -> bool:
    from .exchange.transactions import ExchangeOpType

    if isinstance(item, str):  # (the binary form's text)
        from .exchange.wire import peek

        op: Any = peek(item)[0]
    else:
        op = item.get("op_type") if isinstance(item, dict) else getattr(item, "op_type", None)
    if op is None:
        return False
    try:
        return int(op) == int(ExchangeOpType.ORACLE_VOTE)
    except (TypeError, ValueError):
        return False


def _in_free_lane(item: Any) -> bool:
    """A trading operation sent at gas price 0 in the free lane (docs/TOKENOMICS.md)."""
    from .exchange.transactions import ExchangeOpType, free_trading_op

    if _price(item) != 0:
        return False
    if isinstance(item, str):  # (a free one in the binary form: decoded for its params)
        from .exchange.transactions import ExchangeTransaction

        item = ExchangeTransaction.from_any(item)
    op = item.get("op_type") if isinstance(item, dict) else getattr(item, "op_type", None)
    params = item.get("params") if isinstance(item, dict) else getattr(item, "params", None)
    if op is None:
        return False
    try:
        op_type = ExchangeOpType[op] if isinstance(op, str) else ExchangeOpType(int(op))
    except (KeyError, TypeError, ValueError):
        return False
    return free_trading_op(op_type, params or {})


def _price(item: Any) -> int:
    if isinstance(item, str):  # (the binary form's text: its head read alone)
        from .exchange.wire import peek

        return int(peek(item)[2])
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


# What a stored block contributes to its children's base fees, by block hash, for each database:
# its header's fees, and the gas its sections declared. A block's hash commits to its header and
# its body, so on one chain a hash names one block's worth, across reorganizations. Read once a
# block: the parent's whole exchange section, read back and parsed for every block built or
# imported on it, was megabytes a block at full load.
_FEE_INPUTS: "weakref.WeakKeyDictionary[Any, OrderedDict]" = weakref.WeakKeyDictionary()
_FEE_INPUTS_KEPT = 1024


# The exchange gas each block's section declared, noted as the section is stored (by block hash,
# for each database): a block's children read it rather than parse its section back.
_EXCHANGE_GAS: "weakref.WeakKeyDictionary[Any, OrderedDict]" = weakref.WeakKeyDictionary()


def note_exchange_section(db: Any, block_hash: str, section: Iterable[Any]) -> None:
    """A block's exchange section is being stored: keep the gas it declared (``fee_gas``)."""
    try:
        cache = _EXCHANGE_GAS.get(db)
        if cache is None:
            cache = _EXCHANGE_GAS[db] = OrderedDict()
        cache[block_hash] = fee_gas(section, ())[1]
        cache.move_to_end(block_hash)
        while len(cache) > _FEE_INPUTS_KEPT:
            cache.popitem(last=False)
    except (TypeError, ValueError, AttributeError):
        pass  # (read back from the database instead)


def _noted_exchange_gas(db: Any, block_hash: str) -> Optional[int]:
    try:
        cache = _EXCHANGE_GAS.get(db)
    except TypeError:
        return None
    return None if cache is None else cache.get(block_hash)


def _fee_cache(db: Any) -> Optional["OrderedDict"]:
    try:
        cache = _FEE_INPUTS.get(db)
        if cache is None:
            cache = _FEE_INPUTS[db] = OrderedDict()
        return cache
    except TypeError:  # (a database object that cannot be referenced weakly: not cached)
        return None


async def _stored_block(db: Any, height: int) -> Optional[Tuple[Tuple[int, int], int, int]]:
    """(header fees, EVM gas, exchange gas) of the stored block at ``height``, or None if there
    is none."""
    from . import chain_index
    from .validator.block_verification import _parse_block_content

    # (a block's inputs are read once: its hash, from the chain index's memory, finds them)
    try:
        indexed = await chain_index.block_hash_at(db, int(height))
    except Exception:
        indexed = None
    held = _fee_cache(db) if indexed is not None else None
    if held is not None:
        known = held.get(indexed)
        if known is not None:
            return known
    block = await db.get_block_by_id(int(height))
    if not block:
        return None
    block_hash = block.get("hash") or block.get("block_hash")
    cache = _fee_cache(db) if block_hash else None
    known = cache.get(block_hash) if cache is not None else None
    if known is not None:
        return known
    try:
        content = _parse_block_content(block.get("content") or block.get("block_content"))
    except (ValueError, SyntaxError):
        content = None  # no header to read: the floors (every node reads the same bytes)
    evm_gas, _ = fee_gas((), await db.get_block_evm_txs(block_hash))
    exchange_gas = _noted_exchange_gas(db, block_hash)
    if exchange_gas is None:
        _, exchange_gas = fee_gas(await db.get_block_exchange_txs(block_hash), ())
    inputs = (header_fees(content), evm_gas, exchange_gas)
    if cache is not None:
        cache[block_hash] = inputs
        while len(cache) > _FEE_INPUTS_KEPT:
            cache.popitem(last=False)
    return inputs


def _evm_track_parent(height: int) -> int:
    """The block whose EVM gas sets this one's EVM base fee — the previous block of its kind
    (docs/BLOCK_LIMITS.md, big blocks): a big block's is the big block an interval before it;
    an ordinary block's, the ordinary block before it. Big blocks are priced apart, so one does
    not move ordinary blocks' price, nor ordinary ones its. (No big blocks: the parent.)"""
    from .block_limits import is_big_block
    from .constants import BIG_BLOCK_INTERVAL

    if is_big_block(height):
        return int(height) - int(BIG_BLOCK_INTERVAL)
    parent = int(height) - 1
    return parent - 1 if is_big_block(parent) else parent


async def base_fees_at(db: Any, height: int) -> Tuple[int, int]:
    """The base fees of a block at ``height`` on the stored chain. The exchange's is set by its
    parent, the block at ``height − 1``; the EVM's by the previous block of its kind
    (``_evm_track_parent``) — the parent, unless big blocks are in play (each stored, with its
    sections, before anything is built on it)."""
    from .block_limits import evm_gas_limit_at, exchange_gas_limit_at, is_big_block

    evm_floor, exchange_floor = floors()
    if height <= 1:  # the parent is genesis: no fees, no sections
        return floors()
    parent = await _stored_block(db, int(height) - 1)
    if parent is None:
        return floors()
    fees, evm_gas, exchange_gas = parent
    exchange_fee = next_base_fee(
        fees[1],
        exchange_gas,
        exchange_gas_limit_at(int(height) - 1),  # (the parent's limit, its gas over its target)
        exchange_floor,
    )
    source_height = _evm_track_parent(int(height))
    if source_height < 1:
        return evm_floor, exchange_fee
    if source_height != int(height) - 1:
        source = await _stored_block(db, source_height)
        if source is None:
            return evm_floor, exchange_fee
        fees, evm_gas, _exchange_gas = source
    evm_fee = next_base_fee(
        fees[0],
        evm_gas,
        evm_gas_limit_at(source_height),
        evm_floor,
        # A big block comes once an interval: its price moves faster, so that filling every big
        # block with slow work gets expensive within minutes, not hours.
        denominator=BIG_BLOCK_CHANGE_DENOMINATOR if is_big_block(height) else CHANGE_DENOMINATOR,
    )
    return evm_fee, exchange_fee


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
        if _is_vote(item) or _in_free_lane(item):
            continue  # (a free operation's budget is judged when it executes)
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
