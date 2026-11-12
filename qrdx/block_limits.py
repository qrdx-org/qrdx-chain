"""
What one block may carry (docs/BLOCK_LIMITS.md).

Every node executes every block within the slot clock, so a block's contents are bounded by
what a node can execute, not only by its size in bytes:

* its EVM transactions' declared gas limits sum to at most ``BLOCK_GAS_LIMIT`` — or, every
  ``BIG_BLOCK_INTERVAL``-th block (a big block), ``BIG_BLOCK_GAS_LIMIT``;
* its exchange operations' declared gas limits sum to at most ``BLOCK_EXCHANGE_GAS_LIMIT``;
* it carries at most ``MAX_ATTESTATIONS_PER_BLOCK`` votes (each a Dilithium signature to
  verify) and ``MAX_SLASHING_EVIDENCE_PER_BLOCK`` slashing proofs (two each).

``block_resource_error`` is a validity rule: every import path calls it (through
``_verify_chain_rules``) before anything in the block is verified or applied, so the work a
block can make a node do is bounded before the node starts doing it. The proposer fills
blocks to the same limits.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from . import chain_spec

# Each proof carries two signed messages to verify; a block of them is still a few hundred
# milliseconds of verification at most. Offences are rare: a backlog waits a block.
MAX_SLASHING_EVIDENCE_PER_BLOCK = 16


def is_big_block(height: Optional[int]) -> bool:
    """Whether the block at ``height`` is a big block (HyperEVM's): every
    ``BIG_BLOCK_INTERVAL``-th, by height — what every node knows of a block before running it."""
    from .constants import BIG_BLOCK_GAS_LIMIT, BIG_BLOCK_INTERVAL, BLOCK_GAS_LIMIT

    interval = int(BIG_BLOCK_INTERVAL)
    return (
        interval > 0
        and int(BIG_BLOCK_GAS_LIMIT) > int(BLOCK_GAS_LIMIT)
        and height is not None
        and int(height) > 0
        and int(height) % interval == 0
    )


def evm_gas_limit_at(height: Optional[int]) -> int:
    """The EVM gas a block at ``height`` may carry: a big block's, or an ordinary one's."""
    from .constants import BIG_BLOCK_GAS_LIMIT, BLOCK_GAS_LIMIT

    return int(BIG_BLOCK_GAS_LIMIT) if is_big_block(height) else int(BLOCK_GAS_LIMIT)


def max_evm_tx_gas() -> int:
    """The most gas one EVM transaction may declare: what the biggest block carries (a
    transaction above the ordinary limit waits for a big block)."""
    from .constants import BIG_BLOCK_GAS_LIMIT, BIG_BLOCK_INTERVAL, BLOCK_GAS_LIMIT

    big = int(BIG_BLOCK_GAS_LIMIT) if int(BIG_BLOCK_INTERVAL) > 0 else 0
    return max(int(BLOCK_GAS_LIMIT), big)


def exchange_section_gas(section: Optional[Iterable[Any]]) -> int:
    """The declared gas limits of an exchange section's operations, summed."""
    total = 0
    for item in section or ():
        if isinstance(item, dict):
            gas = item.get("gas_limit", 100_000)
        elif isinstance(item, str):  # (the binary form's text: its head read alone)
            from .exchange.wire import peek

            gas = peek(item)[1]
        else:
            gas = item.gas_limit
        total += int(gas)
    return total


def exchange_gas_limit_at(height: Optional[int]) -> int:
    """The exchange gas a block at ``height`` may carry (``BLOCK_EXCHANGE_GAS_LIMIT``, which a
    fork may change). With no height, the largest the schedule ever allows: a mempool turning
    away an operation that no block could carry."""
    spec = chain_spec.active()
    name = "BLOCK_EXCHANGE_GAS_LIMIT"
    if height is not None:
        return int(spec.param_at(name, max(0, int(height))))
    if _largest_exchange_gas[0] is not spec:  # (asked once a transaction: worked out once a spec)
        values = [spec.params[name]] + [
            f["params"][name] for f in spec.forks if name in f.get("params", {})
        ]
        _largest_exchange_gas[:] = [spec, max(int(v) for v in values)]
    return int(_largest_exchange_gas[1])


_largest_exchange_gas: List[Any] = [None, 0]


def exchange_section_gas_error(
    section: Optional[Iterable[Any]], height: Optional[int] = None
) -> str:
    try:
        total = exchange_section_gas(section)
    except (TypeError, ValueError, AttributeError) as e:
        return f"malformed exchange section: {e}"
    limit = exchange_gas_limit_at(height)
    if total > limit:
        return f"exchange section exceeds the block gas limit ({total} > {limit})"
    return ""


def block_resource_error(
    block: Dict[str, Any],
    exchange_section: Optional[Iterable[Any]] = None,
    evm_section: Optional[Iterable[str]] = None,
    height: Optional[int] = None,
) -> str:
    """Why ``block`` carries more than a block may, or "" if it does not. The sections travel
    beside the block's content on some paths; pass them when they do (otherwise they are read
    from the content). ``height``: the block's (a big block carries more EVM gas)."""
    from .constants import MAX_ATTESTATIONS_PER_BLOCK
    from .contracts.evm_block_apply import section_gas_error

    attestations = block.get("attestations") or ()
    if len(attestations) > MAX_ATTESTATIONS_PER_BLOCK:
        return f"{len(attestations)} attestations (at most {MAX_ATTESTATIONS_PER_BLOCK})"
    evidence = block.get("slashing_evidence") or ()
    if len(evidence) > MAX_SLASHING_EVIDENCE_PER_BLOCK:
        return f"{len(evidence)} slashing proofs (at most {MAX_SLASHING_EVIDENCE_PER_BLOCK})"
    if exchange_section is None:
        exchange_section = block.get("exchange_transactions")
    error = exchange_section_gas_error(exchange_section, height)
    if error:
        return error
    if evm_section is None:
        evm_section = block.get("evm_transactions")
    return section_gas_error(list(evm_section or ()), height)
