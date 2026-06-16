"""
Deterministic epoch reward/penalty deltas (validator-lifecycle unification).

A pure, deterministic function of the epoch's converged inputs — the active
validator set (from the `validators` table) and the set of addresses that attested
this epoch (from `attestation_votes`, which ride in blocks and converge). Every
node computes identical deltas, so applying them keeps the consensus `validators`
table byte-identical network-wide (the safety property — eligibility is enforced
off that table).

Kept intentionally simple + sqrt-free (pure Decimal): a stake-proportional base
amount, awarded to attesters and charged to non-attesters. The exact economic
formula can be refined later; what matters for unification is determinism and that
participation moves stake. Pairs with ``db.apply_epoch_validator_updates``.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Dict, Iterable, List, Tuple

# 0.01% of effective stake per epoch — a small, deterministic base amount.
DEFAULT_REWARD_QUOTIENT = Decimal("10000")
_Q = Decimal("0.00000001")  # 8 dp, matches the token/stake precision


def compute_epoch_reward_deltas(
    active_validators: List[dict],
    attester_addresses: Iterable[str],
    reward_quotient: Decimal = DEFAULT_REWARD_QUOTIENT,
) -> Tuple[Dict[str, Decimal], Dict[str, Decimal]]:
    """
    Returns ``(rewards, penalties)`` — per-address Decimal deltas for one epoch.

    Each active validator gets ``base = effective_stake / reward_quotient`` (8 dp);
    it is a REWARD if the validator attested this epoch, else a PENALTY. Pure +
    deterministic: identical inputs → identical output on every node.
    """
    attesters = {str(a) for a in (attester_addresses or [])}
    rewards: Dict[str, Decimal] = {}
    penalties: Dict[str, Decimal] = {}
    for v in active_validators or []:
        addr = v.get("address")
        if not addr:
            continue
        stake = Decimal(str(v.get("effective_stake") or 0))
        if stake <= 0 or reward_quotient <= 0:
            continue
        base = (stake / reward_quotient).quantize(_Q)
        if base <= 0:
            continue
        if addr in attesters:
            rewards[addr] = base
        else:
            penalties[addr] = base
    return rewards, penalties
