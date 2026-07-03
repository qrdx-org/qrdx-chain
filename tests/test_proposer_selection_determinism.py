"""
Proposer selection must be identical on every node (no competing tip blocks).

`ValidatorSelector.select_proposer` is stake-weighted over a cumulative
distribution, which walks the validator list IN ORDER — so its result must not
depend on list order. Callers build the validator set in node-local order (each
node lists itself first), so if selection were order-dependent, different nodes
would pick different proposers for the same slot, produce competing blocks, and
churn the chain with reorgs (which blocked E-D4 enforcement).

These tests pin order-independence: every permutation of the same validator set
selects the same proposer for a given slot, across many slots.
"""

import itertools
from decimal import Decimal

from qrdx.validator.selection import ValidatorSelector
from qrdx.validator.types import Validator, ValidatorStatus


def _val(addr: str, stake: str) -> Validator:
    return Validator(
        address=addr,
        public_key=b"",
        stake=Decimal(stake),
        effective_stake=Decimal(stake),
        status=ValidatorStatus.ACTIVE,
        activation_epoch=0,
    )


def _set():
    # Distinct stakes so weighting actually matters (not just uniform).
    return [
        _val("0xPQ" + "aa" * 32, "100000"),
        _val("0xPQ" + "bb" * 32, "300000"),
        _val("0xPQ" + "cc" * 32, "200000"),
    ]


def test_proposer_identical_across_all_orderings():
    sel = ValidatorSelector()
    randao = b"\x00" * 32
    base = _set()
    for slot in range(0, 64):
        chosen = {
            sel.select_proposer(slot, list(perm), randao).address
            for perm in itertools.permutations(base)
        }
        assert len(chosen) == 1, f"slot {slot}: orderings disagree on proposer: {chosen}"


def test_node_local_first_ordering_agrees():
    """Mirror the real bug: each 'node' puts its own validator first."""
    sel = ValidatorSelector()
    randao = b"\x00" * 32
    base = _set()
    for slot in range(0, 64):
        per_node = []
        for i in range(len(base)):
            ordered = [base[i]] + base[:i] + base[i + 1:]  # node i lists itself first
            per_node.append(sel.select_proposer(slot, ordered, randao).address)
        assert len(set(per_node)) == 1, f"slot {slot}: nodes disagree: {per_node}"


def test_expected_proposer_matches_selector_and_is_order_independent():
    """The importer-side reconstruction agrees with the selector for every slot
    and is independent of the (address, stake) tuple ordering."""
    from qrdx.validator.block_verification import expected_proposer_for_slot
    sel = ValidatorSelector()
    randao = b"\x00" * 32
    base = _set()
    tuples = [(v.address, v.effective_stake) for v in base]
    import itertools as _it
    for slot in range(0, 48):
        via_selector = sel.select_proposer(slot, base, randao).address
        # Every ordering of the reconstructed tuples yields the selector's choice.
        for perm in _it.permutations(tuples):
            assert expected_proposer_for_slot(slot, list(perm), randao) == via_selector


def test_expected_proposer_empty_set_is_none():
    from qrdx.validator.block_verification import expected_proposer_for_slot
    assert expected_proposer_for_slot(5, []) is None


def test_weighting_still_reflects_stake():
    """Determinism must not flatten the stake weighting — the heaviest validator
    should win a clear plurality of slots."""
    sel = ValidatorSelector()
    randao = b"\x00" * 32
    base = _set()  # bb has 300k of 600k total
    counts = {}
    for slot in range(0, 600):
        p = sel.select_proposer(slot, base, randao).address
        counts[p] = counts.get(p, 0) + 1
    heaviest = "0xPQ" + "bb" * 32
    # ~50% expected; assert it's the clear winner and selection isn't degenerate.
    assert counts.get(heaviest, 0) == max(counts.values())
    assert len(counts) >= 2, "selection collapsed to a single validator"


# --- RANDAO liveness layer: top-K proposer ranking (primary + backups) ---

def test_proposer_ranking_primary_matches_select_proposer():
    sel = ValidatorSelector()
    vals = _set()
    mix = b"\x11" * 32
    for slot in range(20):
        ranking = sel.proposer_ranking(slot, vals, mix, k=2)
        primary = sel.select_proposer(slot, vals, mix)
        assert ranking[0].address == primary.address  # rank 0 == the existing primary


def test_proposer_ranking_distinct_deterministic_and_order_independent():
    sel = ValidatorSelector()
    vals = _set()
    mix = b"\x22" * 32
    import itertools as _it
    for slot in (0, 5, 13, 99):
        base = [v.address for v in sel.proposer_ranking(slot, vals, mix, k=3)]
        assert len(base) == len(set(base)) == 3          # distinct, full ranking
        # deterministic + order-independent across permutations of the input
        for perm in _it.permutations(vals):
            assert [v.address for v in sel.proposer_ranking(slot, list(perm), mix, k=3)] == base


def test_proposer_rank_lookup():
    sel = ValidatorSelector()
    vals = _set()
    mix = b"\x33" * 32
    ranking = sel.proposer_ranking(0, vals, mix, k=2)
    assert sel.proposer_rank(0, ranking[0].address, vals, mix, k=2) == 0
    assert sel.proposer_rank(0, ranking[1].address, vals, mix, k=2) == 1
    # the third validator is outside the top-2 → not eligible
    outside = [v for v in vals if v.address not in {ranking[0].address, ranking[1].address}][0]
    assert sel.proposer_rank(0, outside.address, vals, mix, k=2) is None
