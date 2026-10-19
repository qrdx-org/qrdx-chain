"""
What one block may carry (docs/BLOCK_LIMITS.md).

Every node executes every block within the slot clock, so a block's contents are bounded by
what a node can execute, not only by its size in bytes:

* its EVM transactions' declared gas limits sum to at most ``BLOCK_GAS_LIMIT``;
* its exchange operations' declared gas limits sum to at most ``BLOCK_EXCHANGE_GAS_LIMIT``;
* it carries at most ``MAX_ATTESTATIONS_PER_BLOCK`` votes (each a Dilithium signature to
  verify) and ``MAX_SLASHING_EVIDENCE_PER_BLOCK`` slashing proofs (two each).

``block_resource_error`` is a validity rule: every import path calls it (through
``_verify_chain_rules``) before anything in the block is verified or applied, so the work a
block can make a node do is bounded before the node starts doing it. The proposer fills
blocks to the same limits.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

# Each proof carries two signed messages to verify; a block of them is still a few hundred
# milliseconds of verification at most. Offences are rare: a backlog waits a block.
MAX_SLASHING_EVIDENCE_PER_BLOCK = 16


def exchange_section_gas(section: Optional[Iterable[Any]]) -> int:
    """The declared gas limits of an exchange section's operations, summed."""
    total = 0
    for item in section or ():
        gas = item.get("gas_limit", 100_000) if isinstance(item, dict) else item.gas_limit
        total += int(gas)
    return total


def exchange_section_gas_error(section: Optional[Iterable[Any]]) -> str:
    from .constants import BLOCK_EXCHANGE_GAS_LIMIT

    try:
        total = exchange_section_gas(section)
    except (TypeError, ValueError, AttributeError) as e:
        return f"malformed exchange section: {e}"
    if total > BLOCK_EXCHANGE_GAS_LIMIT:
        return (
            f"exchange section exceeds the block gas limit ({total} > {BLOCK_EXCHANGE_GAS_LIMIT})"
        )
    return ""


def block_resource_error(
    block: Dict[str, Any],
    exchange_section: Optional[Iterable[Any]] = None,
    evm_section: Optional[Iterable[str]] = None,
) -> str:
    """Why ``block`` carries more than a block may, or "" if it does not. The sections travel
    beside the block's content on some paths; pass them when they do (otherwise they are read
    from the content)."""
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
    error = exchange_section_gas_error(exchange_section)
    if error:
        return error
    if evm_section is None:
        evm_section = block.get("evm_transactions")
    return section_gas_error(list(evm_section or ()))
