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

from ..constants import SLOT_DURATION_MS, SLOTS_PER_EPOCH

# The base amount is 0.01% of effective stake per 64 s of chain time: the per-epoch rate first
# set for 32 two-second slots, now held per unit of time. A flat per-epoch rate made rewards
# and penalties accrue 8x faster per day once epochs became 8 s (250 ms slots); an offline
# validator was ejected for lost stake after ~15 hours instead of ~5 days. Integer arithmetic,
# so every node derives the same quotient from the same chain spec.
_REFERENCE_EPOCH_MS = 64_000


def reward_quotient(
    slot_ms: int = SLOT_DURATION_MS, slots_per_epoch: int = SLOTS_PER_EPOCH
) -> Decimal:
    """Divisor of effective stake giving one epoch's base amount (10,000 for 64 s epochs,
    80,000 for the standard 8 s)."""
    return Decimal(max(1, 10_000 * _REFERENCE_EPOCH_MS // (int(slot_ms) * int(slots_per_epoch))))


DEFAULT_REWARD_QUOTIENT = reward_quotient()
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
