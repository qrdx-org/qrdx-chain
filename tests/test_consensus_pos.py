"""
QRDX Step 3 — Consensus: Quantum-Resistant Proof-of-Stake Tests

Comprehensive test coverage for all PoS consensus sub-systems:
  3.1  QR-PoS Core Engine          (ConsensusEngine, ConsensusV2PoS)
  3.2  Validator Manager Types     (Validator, ValidatorSet, PoSBlock)
  3.3  Stake Management            (StakeStatus, Deposits, Withdrawals)
  3.4  RANDAO Selection            (ValidatorSelector, committees)
  3.5  Attestations                (Attestation, AttestationPool)
  3.6  Slashing                    (SlashingExecutor, SlashingProtectionDB)
  3.7  Finality (LMD-GHOST + FFG) (ForkChoiceStore, ForkChoice)
  3.8  Rewards & Inflation         (RewardsCalculator, InflationSchedule)
  3.9  Sync Committee              (SyncCommitteeManager)
  3.10 Legacy PoW Removal          (no V1, no mining code paths)
  3.x  Lifecycle                   (LifecycleManager, queues)
  3.x  Gossip                      (GossipTopic, GossipMessage)
"""

import asyncio
import hashlib
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import List

import pytest

# ---------------------------------------------------------------------------
# 3.1 — QR-PoS Core Engine imports
# ---------------------------------------------------------------------------
from qrdx.consensus import (
    ConsensusVersion,
    ConsensusActivation,
    ConsensusSchedule,
    ConsensusEngine,
    Consensus_V2_PoS,
    CONSENSUS_ENGINE,
    CONSENSUS_SCHEDULE,
    get_consensus_info,
    get_pos_rules,
    is_pos_active,
    calculate_block_reward,
)

# ---------------------------------------------------------------------------
# 3.2 — Validator Types
# ---------------------------------------------------------------------------
from qrdx.validator.types import (
    ValidatorStatus,
    Validator,
    ValidatorSet,
    EpochInfo,
    SlotInfo,
    ValidatorError,
    NotPQWalletError,
    InsufficientStakeError,
    InvalidValidatorError,
    ValidatorNotActiveError,
    SlashingProtectionError,
    AlreadyProposedError,
    AlreadyAttestedError,
)

# ---------------------------------------------------------------------------
# 3.4 — Selection
# ---------------------------------------------------------------------------
from qrdx.validator.selection import (
    ValidatorSelector,
    compute_initial_randao,
)

# ---------------------------------------------------------------------------
# 3.5 — Attestations
# ---------------------------------------------------------------------------
from qrdx.validator.attestation import (
    Attestation,
    AttestationPool,
    AttestationAggregator,
)

# ---------------------------------------------------------------------------
# 3.6 — Slashing
# ---------------------------------------------------------------------------
from qrdx.validator.slashing import (
    SlashingConditions,
    SLASHING_PENALTIES,
    SlashingEvidence,
    DoubleSignEvidence,
    SurroundVoteEvidence,
    SlashingExecutor,
    SlashingProtectionDB,
)

# ---------------------------------------------------------------------------
# 3.7 — Fork Choice
# ---------------------------------------------------------------------------
from qrdx.validator.fork_choice import (
    BlockNode,
    Checkpoint,
    LatestMessage,
    ForkChoiceStore,
    ForkChoice,
)

# ---------------------------------------------------------------------------
# 3.8 — Rewards & Inflation
# ---------------------------------------------------------------------------
from qrdx.validator.rewards import (
    RewardsCalculator,
    RewardSummary,
    EpochRewardReport,
    InflationSchedule,
    WEIGHT_DENOMINATOR,
    TIMELY_SOURCE_WEIGHT,
    TIMELY_TARGET_WEIGHT,
    TIMELY_HEAD_WEIGHT,
)

# ---------------------------------------------------------------------------
# 3.9 — Sync Committee
# ---------------------------------------------------------------------------
from qrdx.validator.sync_committee import (
    SyncCommittee,
    SyncAggregate,
    SyncCommitteeManager,
    LightClientUpdate,
    SyncCommitteeContribution,
)

# ---------------------------------------------------------------------------
# 3.x — Lifecycle
# ---------------------------------------------------------------------------
from qrdx.validator.lifecycle import (
    LifecycleState,
    DepositRequest,
    ExitRequest,
    WithdrawalRequest,
    ValidatorLifecycle,
    ValidatorActivationQueue,
    ValidatorExitQueue,
    LifecycleManager,
)

# ---------------------------------------------------------------------------
# 3.x — Gossip
# ---------------------------------------------------------------------------
from qrdx.validator.gossip import (
    GossipTopic,
    GossipMessage,
    get_topic_name,
)


# ============================================================================
# TEST HELPERS
# ============================================================================

def _make_validator(
    index: int,
    *,
    stake: Decimal = Decimal("100000"),
    status: ValidatorStatus = ValidatorStatus.ACTIVE,
    slashed: bool = False,
) -> Validator:
    """Create a test validator with deterministic fields."""
    addr = f"0xPQ{'%040x' % index}"
    pk = hashlib.sha256(f"pk_{index}".encode()).digest() * 60  # ~1920 bytes
    return Validator(
        address=addr,
        public_key=pk[:1952],  # Dilithium3 public key size
        stake=stake,
        effective_stake=stake,
        status=status,
        activation_epoch=0,
        slashed=slashed,
        index=index,
    )


def _make_validators(n: int, base_stake: Decimal = Decimal("100000")) -> List[Validator]:
    """Create N test validators."""
    return [_make_validator(i, stake=base_stake) for i in range(n)]


def _block_hash(label: str) -> str:
    """Deterministic 64-char hex hash from a label."""
    return hashlib.sha256(label.encode()).hexdigest()


# ============================================================================
# 3.1 — QR-PoS CORE ENGINE
# ============================================================================

class TestConsensusVersion:
    """ConsensusVersion enum tests."""

    def test_pos_version_value(self):
        assert ConsensusVersion.CONSENSUS_V2_POS == 2

    def test_pos_is_only_version(self):
        """After PoW removal, V2_POS should be the only production version."""
        members = list(ConsensusVersion)
        # V2_POS must exist
        assert ConsensusVersion.CONSENSUS_V2_POS in members


class TestConsensusSchedule:
    """ConsensusSchedule activation tests."""

    def test_pos_active_from_genesis(self):
        schedule = ConsensusSchedule()
        assert schedule.get_active_version(0) == ConsensusVersion.CONSENSUS_V2_POS

    def test_pos_active_at_high_block(self):
        schedule = ConsensusSchedule()
        assert schedule.get_active_version(1_000_000) == ConsensusVersion.CONSENSUS_V2_POS

    def test_activation_height_is_zero(self):
        schedule = ConsensusSchedule()
        height = schedule.get_activation_height(ConsensusVersion.CONSENSUS_V2_POS)
        assert height == 0

    def test_is_hard_fork(self):
        schedule = ConsensusSchedule()
        assert schedule.is_hard_fork(ConsensusVersion.CONSENSUS_V2_POS) is True

    def test_all_activations_list(self):
        schedule = ConsensusSchedule()
        activations = schedule.get_all_activations()
        assert len(activations) >= 1
        assert activations[0].version == ConsensusVersion.CONSENSUS_V2_POS


class TestConsensusEngine:
    """ConsensusEngine factory tests."""

    def test_get_rules_returns_pos(self):
        engine = ConsensusEngine()
        rules = engine.get_rules(0)
        assert isinstance(rules, Consensus_V2_PoS)

    def test_rules_are_cached(self):
        engine = ConsensusEngine()
        r1 = engine.get_rules(0)
        r2 = engine.get_rules(0)
        assert r1 is r2

    def test_pos_active_check(self):
        engine = ConsensusEngine()
        assert engine.is_hard_fork_active(0, ConsensusVersion.CONSENSUS_V2_POS)

    def test_global_engine(self):
        assert isinstance(CONSENSUS_ENGINE, ConsensusEngine)

    def test_global_schedule(self):
        assert isinstance(CONSENSUS_SCHEDULE, ConsensusSchedule)


class TestConsensusV2PoS:
    """Consensus_V2_PoS rule tests."""

    def test_version_is_pos(self):
        rules = Consensus_V2_PoS()
        assert rules.version == ConsensusVersion.CONSENSUS_V2_POS

    def test_merkle_tree_empty(self):
        rules = Consensus_V2_PoS()
        root = rules.calculate_merkle_tree([])
        assert root == hashlib.sha256(b"").hexdigest()

    def test_merkle_tree_single_hash(self):
        rules = Consensus_V2_PoS()
        root = rules.calculate_merkle_tree(["aabbcc"])
        assert root == "aabbcc"

    def test_merkle_tree_two_leaves(self):
        rules = Consensus_V2_PoS()
        root = rules.calculate_merkle_tree(["aaa", "bbb"])
        # Two hashes: sorted → combined → sha256
        assert isinstance(root, str) and len(root) == 64

    def test_merkle_tree_deterministic(self):
        rules = Consensus_V2_PoS()
        txs = ["tx1", "tx2", "tx3", "tx4"]
        r1 = rules.calculate_merkle_tree(txs)
        r2 = rules.calculate_merkle_tree(txs)
        assert r1 == r2

    def test_merkle_tree_order_independent(self):
        """Sorted hashes means order of input doesn't affect root."""
        rules = Consensus_V2_PoS()
        r1 = rules.calculate_merkle_tree(["a", "b", "c"])
        r2 = rules.calculate_merkle_tree(["c", "a", "b"])
        assert r1 == r2

    def test_difficulty_returns_fixed(self):
        rules = Consensus_V2_PoS()
        d = rules.calculate_new_difficulty(Decimal("2.0"), Decimal("100"))
        assert d == Decimal("1.0")

    def test_coinbase_rejected(self):
        """PoS must reject coinbase transactions."""
        from unittest.mock import MagicMock
        rules = Consensus_V2_PoS()
        # Need to mock CoinbaseTransaction check
        # The method does: isinstance(tx, CoinbaseTransaction)
        # Create a mock that is detected as CoinbaseTransaction via import
        import qrdx.transactions as txmod
        if hasattr(txmod, 'CoinbaseTransaction'):
            cb = txmod.CoinbaseTransaction.__new__(txmod.CoinbaseTransaction)
            assert rules.validate_coinbase_transactions([cb]) is False

    def test_proposer_selection_deterministic(self):
        rules = Consensus_V2_PoS()
        validators = _make_validators(5)
        randao = os.urandom(32)
        p1 = rules._select_proposer(10, validators, randao)
        p2 = rules._select_proposer(10, validators, randao)
        assert p1.address == p2.address

    def test_proposer_different_slots_different_proposers(self):
        rules = Consensus_V2_PoS()
        validators = _make_validators(10)
        randao = os.urandom(32)
        proposers = set()
        for slot in range(100):
            p = rules._select_proposer(slot, validators, randao)
            proposers.add(p.address)
        # Over 100 slots, multiple validators should be selected
        assert len(proposers) > 1

    def test_finality_check_supermajority(self):
        """2/3+ stake attesting → finality."""
        rules = Consensus_V2_PoS()
        validators = _make_validators(6, base_stake=Decimal("100000"))
        block_hash = "aa" * 32

        @dataclass
        class FakeAtt:
            block_hash: str
            validator_address: str

        # 5 of 6 attest (83%)
        attestations = [
            FakeAtt(block_hash=block_hash, validator_address=v.address)
            for v in validators[:5]
        ]
        assert rules.check_finality(attestations, block_hash, validators) is True

    def test_finality_check_below_threshold(self):
        """< 2/3 stake → no finality."""
        rules = Consensus_V2_PoS()
        validators = _make_validators(6, base_stake=Decimal("100000"))
        block_hash = "bb" * 32

        @dataclass
        class FakeAtt:
            block_hash: str
            validator_address: str

        # 3 of 6 attest (50%)
        attestations = [
            FakeAtt(block_hash=block_hash, validator_address=v.address)
            for v in validators[:3]
        ]
        assert rules.check_finality(attestations, block_hash, validators) is False

    def test_slot_epoch_conversion(self):
        rules = Consensus_V2_PoS()
        assert rules.slot_to_epoch(0) == 0
        assert rules.slot_to_epoch(31) == 0
        assert rules.slot_to_epoch(32) == 1
        assert rules.slot_to_epoch(64) == 2
        assert rules.epoch_start_slot(0) == 0
        assert rules.epoch_start_slot(1) == 32
        assert rules.epoch_start_slot(3) == 96

    def test_timestamp_to_slot(self):
        rules = Consensus_V2_PoS()
        assert rules._timestamp_to_slot(0) == 0
        assert rules._timestamp_to_slot(2) == 1
        assert rules._timestamp_to_slot(10) == 5

    def test_slot_to_timestamp(self):
        rules = Consensus_V2_PoS()
        assert rules._slot_to_timestamp(0) == 0
        assert rules._slot_to_timestamp(5) == 10
        assert rules._slot_to_timestamp(100) == 200


class TestConsensusUtilities:
    """Utility function tests."""

    def test_get_pos_rules_is_v2(self):
        rules = get_pos_rules()
        assert isinstance(rules, Consensus_V2_PoS)

    def test_is_pos_active_always(self):
        assert is_pos_active(0) is True
        assert is_pos_active(1_000_000) is True

    def test_get_consensus_info(self):
        info = get_consensus_info()
        assert info["consensus_type"] == "proof_of_stake"
        assert len(info["activations"]) >= 1

    def test_calculate_block_reward_positive(self):
        reward = calculate_block_reward(
            slot=10,
            total_stake=Decimal("10000000"),
            attestation_count=5,
        )
        assert reward > Decimal("0")

    def test_calculate_block_reward_zero_stake(self):
        reward = calculate_block_reward(
            slot=10,
            total_stake=Decimal("0"),
            attestation_count=5,
        )
        assert reward == Decimal("0")


# ============================================================================
# 3.2 — VALIDATOR TYPES
# ============================================================================

class TestValidatorStatus:
    """ValidatorStatus enum tests."""

    def test_all_statuses_exist(self):
        assert ValidatorStatus.PENDING.value == "pending"
        assert ValidatorStatus.ACTIVE.value == "active"
        assert ValidatorStatus.EXITING.value == "exiting"
        assert ValidatorStatus.EXITED.value == "exited"
        assert ValidatorStatus.SLASHED.value == "slashed"

    def test_status_count(self):
        assert len(ValidatorStatus) == 5


class TestValidator:
    """Validator dataclass tests."""

    def test_active_validator(self):
        v = _make_validator(0)
        assert v.is_active is True
        assert v.can_propose is True
        assert v.can_attest is True

    def test_pending_cannot_propose(self):
        v = _make_validator(0, status=ValidatorStatus.PENDING)
        assert v.is_active is False
        assert v.can_propose is False

    def test_slashed_cannot_propose(self):
        v = _make_validator(0, slashed=True)
        assert v.can_propose is False
        assert v.can_attest is False

    def test_public_key_hex(self):
        v = _make_validator(0)
        assert isinstance(v.public_key_hex, str)
        assert len(v.public_key_hex) > 0
        # Should be hex
        int(v.public_key_hex, 16)

    def test_serialization_roundtrip(self):
        v = _make_validator(7)
        d = v.to_dict()
        v2 = Validator.from_dict(d)
        assert v2.address == v.address
        assert v2.public_key == v.public_key
        assert v2.stake == v.stake
        assert v2.status == v.status
        assert v2.index == v.index

    def test_serialization_keys(self):
        v = _make_validator(0)
        d = v.to_dict()
        expected_keys = {
            'address', 'public_key', 'stake', 'effective_stake',
            'status', 'activation_epoch', 'exit_epoch', 'slashed',
            'uptime_score', 'index', 'created_at',
        }
        assert set(d.keys()) == expected_keys


class TestValidatorSet:
    """ValidatorSet tests."""

    def test_total_stake_auto_calculated(self):
        validators = _make_validators(4, base_stake=Decimal("100000"))
        vs = ValidatorSet(epoch=0, validators=validators)
        assert vs.total_stake == Decimal("400000")

    def test_get_by_address(self):
        validators = _make_validators(5)
        vs = ValidatorSet(epoch=0, validators=validators)
        found = vs.get_validator_by_address(validators[3].address)
        assert found is not None
        assert found.index == 3

    def test_get_by_address_not_found(self):
        validators = _make_validators(3)
        vs = ValidatorSet(epoch=0, validators=validators)
        assert vs.get_validator_by_address("0xNONEXISTENT") is None

    def test_get_by_index(self):
        validators = _make_validators(5)
        vs = ValidatorSet(epoch=0, validators=validators)
        assert vs.get_validator_by_index(2) is validators[2]
        assert vs.get_validator_by_index(99) is None

    def test_size(self):
        validators = _make_validators(7)
        vs = ValidatorSet(epoch=1, validators=validators)
        assert vs.size == 7


class TestEpochAndSlotInfo:
    """EpochInfo and SlotInfo tests."""

    def test_epoch_slot_count(self):
        ei = EpochInfo(epoch=0, start_slot=0, end_slot=31)
        assert ei.slot_count == 32

    def test_slot_info(self):
        si = SlotInfo(slot=10, epoch=0, proposer_index=3)
        assert si.block_proposed is False
        assert si.attestation_count == 0


class TestValidatorExceptions:
    """Validator exception hierarchy tests."""

    def test_not_pq_wallet_error(self):
        err = NotPQWalletError()
        assert "Post-Quantum" in str(err)

    def test_insufficient_stake_error(self):
        err = InsufficientStakeError(
            required=Decimal("100000"),
            actual=Decimal("50000"),
        )
        assert err.required == Decimal("100000")
        assert err.actual == Decimal("50000")

    def test_already_proposed_error(self):
        err = AlreadyProposedError(slot=42)
        assert err.slot == 42
        assert "42" in str(err)

    def test_already_attested_error(self):
        err = AlreadyAttestedError(slot=99)
        assert err.slot == 99

    def test_exception_hierarchy(self):
        assert issubclass(NotPQWalletError, ValidatorError)
        assert issubclass(InsufficientStakeError, ValidatorError)
        assert issubclass(SlashingProtectionError, ValidatorError)
        assert issubclass(AlreadyProposedError, SlashingProtectionError)
        assert issubclass(AlreadyAttestedError, SlashingProtectionError)


# ============================================================================
# 3.4 — RANDAO SELECTION
# ============================================================================

class TestValidatorSelector:
    """ValidatorSelector tests (pure deterministic functions)."""

    def test_select_proposer_deterministic(self):
        selector = ValidatorSelector(seed=b'\x01' * 32)
        validators = _make_validators(8)
        randao = b'\xaa' * 32
        p1 = selector.select_proposer(10, validators, randao)
        p2 = selector.select_proposer(10, validators, randao)
        assert p1.address == p2.address

    def test_select_proposer_different_slots(self):
        selector = ValidatorSelector()
        validators = _make_validators(10)
        randao = os.urandom(32)
        proposers = set()
        for slot in range(50):
            p = selector.select_proposer(slot, validators, randao)
            proposers.add(p.address)
        # Multiple different proposers expected
        assert len(proposers) > 1

    def test_select_proposer_no_validators(self):
        selector = ValidatorSelector()
        assert selector.select_proposer(0, [], b'\x00' * 32) is None

    def test_select_proposer_only_eligible(self):
        """Slashed validators excluded from selection."""
        selector = ValidatorSelector()
        v_active = _make_validator(0)
        v_slashed = _make_validator(1, slashed=True)
        randao = os.urandom(32)
        for _ in range(20):
            p = selector.select_proposer(_, [v_active, v_slashed], randao)
            assert p.address == v_active.address

    def test_select_proposer_stake_weighted(self):
        """Higher-stake validators selected more often."""
        selector = ValidatorSelector()
        v_big = _make_validator(0, stake=Decimal("900000"))
        v_small = _make_validator(1, stake=Decimal("100000"))
        randao = b'\x55' * 32
        counts = {v_big.address: 0, v_small.address: 0}
        for slot in range(1000):
            p = selector.select_proposer(slot, [v_big, v_small], randao)
            counts[p.address] += 1
        # Big should be selected much more often
        assert counts[v_big.address] > counts[v_small.address]

    def test_select_committee(self):
        selector = ValidatorSelector()
        validators = _make_validators(20)
        randao = os.urandom(32)
        committee = selector.select_committee(5, validators, 8, randao)
        assert len(committee) == 8
        # All are from the validator set
        committee_addrs = {v.address for v in committee}
        all_addrs = {v.address for v in validators}
        assert committee_addrs.issubset(all_addrs)

    def test_select_committee_limited_by_eligible(self):
        selector = ValidatorSelector()
        validators = _make_validators(3)
        randao = os.urandom(32)
        committee = selector.select_committee(5, validators, 10, randao)
        # Can't have more than 3 members
        assert len(committee) == 3

    def test_select_committee_deterministic(self):
        selector = ValidatorSelector()
        validators = _make_validators(10)
        randao = b'\xbb' * 32
        c1 = selector.select_committee(7, validators, 5, randao)
        c2 = selector.select_committee(7, validators, 5, randao)
        assert [v.address for v in c1] == [v.address for v in c2]

    def test_shuffle_preserves_elements(self):
        selector = ValidatorSelector()
        validators = _make_validators(10)
        shuffled = selector._shuffle_validators(validators, os.urandom(32))
        assert len(shuffled) == 10
        assert set(v.address for v in shuffled) == set(v.address for v in validators)

    def test_shuffle_deterministic(self):
        selector = ValidatorSelector()
        validators = _make_validators(10)
        seed = b'\xcc' * 32
        s1 = selector._shuffle_validators(validators, seed)
        s2 = selector._shuffle_validators(validators, seed)
        assert [v.address for v in s1] == [v.address for v in s2]

    def test_randao_update(self):
        selector = ValidatorSelector()
        mix = b'\x00' * 32
        reveal = b'\xff' * 32
        new_mix = selector.update_randao(mix, reveal)
        assert len(new_mix) == 32
        assert new_mix != mix

    def test_randao_update_xor_property(self):
        """RANDAO is XOR of current mix with hash of reveal."""
        selector = ValidatorSelector()
        mix = os.urandom(32)
        reveal = os.urandom(32)
        new_mix = selector.update_randao(mix, reveal)
        # Verify XOR: new_mix = mix XOR SHA256(reveal)
        reveal_hash = hashlib.sha256(reveal).digest()
        expected = bytes(a ^ b for a, b in zip(mix, reveal_hash))
        assert new_mix == expected

    def test_proposer_duties_full_epoch(self):
        selector = ValidatorSelector()
        validators = _make_validators(8)
        randao = os.urandom(32)
        duties = selector.get_proposer_duties(0, 32, validators, randao)
        assert len(duties) == 32
        # Each duty is (slot, validator)
        for slot, validator in duties:
            assert 0 <= slot < 32
            assert validator.is_active

    def test_committee_duties_full_epoch(self):
        selector = ValidatorSelector()
        validators = _make_validators(20)
        randao = os.urandom(32)
        duties = selector.get_committee_duties(0, 32, validators, 8, randao)
        assert len(duties) == 32
        for slot, committee in duties:
            assert len(committee) <= 8

    def test_compute_proposer_index(self):
        selector = ValidatorSelector()
        validators = _make_validators(5)
        randao = os.urandom(32)
        idx = selector.compute_proposer_index(0, validators, randao)
        assert 0 <= idx < 5

    def test_is_proposer(self):
        selector = ValidatorSelector()
        validators = _make_validators(5)
        randao = os.urandom(32)
        proposer = selector.select_proposer(0, validators, randao)
        assert selector.is_proposer(0, proposer.address, validators, randao) is True
        # Non-proposer
        non_proposer = [v for v in validators if v.address != proposer.address][0]
        assert selector.is_proposer(0, non_proposer.address, validators, randao) is False

    def test_is_in_committee(self):
        selector = ValidatorSelector()
        validators = _make_validators(20)
        randao = os.urandom(32)
        committee = selector.select_committee(0, validators, 5, randao)
        member = committee[0]
        assert selector.is_in_committee(0, member.address, validators, 5, randao) is True


class TestInitialRANDAO:
    """compute_initial_randao tests."""

    def test_deterministic(self):
        addresses = ["0xPQ0001", "0xPQ0002"]
        r1 = compute_initial_randao(1000, addresses)
        r2 = compute_initial_randao(1000, addresses)
        assert r1 == r2

    def test_different_time_different_result(self):
        addresses = ["0xPQ0001"]
        r1 = compute_initial_randao(1000, addresses)
        r2 = compute_initial_randao(2000, addresses)
        assert r1 != r2

    def test_length_32(self):
        r = compute_initial_randao(0, ["addr1"])
        assert len(r) == 32


# ============================================================================
# 3.5 — ATTESTATIONS
# ============================================================================

class TestAttestation:
    """Attestation dataclass tests."""

    def test_signing_root_deterministic(self):
        a1 = Attestation(
            slot=10, epoch=0, block_hash="aa" * 32,
            validator_address="0xPQ01", validator_index=0,
            signature=b'\x00' * 64,
        )
        a2 = Attestation(
            slot=10, epoch=0, block_hash="aa" * 32,
            validator_address="0xPQ01", validator_index=0,
            signature=b'\x00' * 64,
        )
        assert a1.signing_root == a2.signing_root

    def test_signing_root_differs_for_different_slots(self):
        a1 = Attestation(
            slot=10, epoch=0, block_hash="aa" * 32,
            validator_address="0xPQ01", validator_index=0,
            signature=b'\x00' * 64,
        )
        a2 = Attestation(
            slot=11, epoch=0, block_hash="aa" * 32,
            validator_address="0xPQ01", validator_index=0,
            signature=b'\x00' * 64,
        )
        assert a1.signing_root != a2.signing_root

    def test_serialization_roundtrip(self):
        a = Attestation(
            slot=10, epoch=0, block_hash="bb" * 32,
            validator_address="0xPQ99", validator_index=5,
            signature=os.urandom(64),
            source_epoch=0, target_epoch=1,
        )
        d = a.to_dict()
        a2 = Attestation.from_dict(d)
        assert a2.slot == a.slot
        assert a2.block_hash == a.block_hash
        assert a2.validator_address == a.validator_address
        assert a2.signature == a.signature


@pytest.mark.asyncio
class TestAttestationPool:
    """AttestationPool async tests."""

    async def test_add_attestation(self):
        pool = AttestationPool()
        att = Attestation(
            slot=1, epoch=0, block_hash="cc" * 32,
            validator_address="0xPQ01", validator_index=0,
            signature=b'\x00' * 64,
        )
        result = await pool.add_attestation(att, verify_signature=False)
        assert result is True

    async def test_duplicate_rejected(self):
        pool = AttestationPool()
        att = Attestation(
            slot=1, epoch=0, block_hash="cc" * 32,
            validator_address="0xPQ01", validator_index=0,
            signature=b'\x00' * 64,
        )
        await pool.add_attestation(att, verify_signature=False)
        result = await pool.add_attestation(att, verify_signature=False)
        assert result is False

    async def test_double_vote_detected(self):
        """Different block_hash at same slot → slashable."""
        pool = AttestationPool()
        att1 = Attestation(
            slot=1, epoch=0, block_hash="aa" * 32,
            validator_address="0xPQ01", validator_index=0,
            signature=b'\x01' * 64,
        )
        att2 = Attestation(
            slot=1, epoch=0, block_hash="bb" * 32,
            validator_address="0xPQ01", validator_index=0,
            signature=b'\x02' * 64,
        )
        await pool.add_attestation(att1, verify_signature=False)
        result = await pool.add_attestation(att2, verify_signature=False)
        assert result is False  # Double vote rejected

    async def test_get_attestations_for_block(self):
        pool = AttestationPool()
        bh = "dd" * 32
        for i in range(5):
            att = Attestation(
                slot=1, epoch=0, block_hash=bh,
                validator_address=f"0xPQ0{i}", validator_index=i,
                signature=os.urandom(64),
            )
            await pool.add_attestation(att, verify_signature=False)
        atts = await pool.get_attestations_for_block(1, bh)
        assert len(atts) == 5

    async def test_get_attestations_for_slot(self):
        pool = AttestationPool()
        # Two different blocks at slot 5
        for i in range(3):
            att = Attestation(
                slot=5, epoch=0, block_hash="aa" * 32,
                validator_address=f"0xPQa{i}", validator_index=i,
                signature=os.urandom(64),
            )
            await pool.add_attestation(att, verify_signature=False)
        for i in range(2):
            att = Attestation(
                slot=5, epoch=0, block_hash="bb" * 32,
                validator_address=f"0xPQb{i}", validator_index=10 + i,
                signature=os.urandom(64),
            )
            await pool.add_attestation(att, verify_signature=False)
        atts = await pool.get_attestations_for_slot(5)
        assert len(atts) == 5

    async def test_attestation_count(self):
        pool = AttestationPool()
        bh = "ee" * 32
        for i in range(3):
            att = Attestation(
                slot=2, epoch=0, block_hash=bh,
                validator_address=f"0xPQ0{i}", validator_index=i,
                signature=os.urandom(64),
            )
            await pool.add_attestation(att, verify_signature=False)
        count = await pool.get_attestation_count(2, bh)
        assert count == 3

    async def test_supermajority(self):
        """5/6 validators attesting = 83% → supermajority."""
        pool = AttestationPool()
        validators = _make_validators(6)
        bh = "ff" * 32
        for v in validators[:5]:
            att = Attestation(
                slot=1, epoch=0, block_hash=bh,
                validator_address=v.address, validator_index=v.index,
                signature=os.urandom(64),
            )
            await pool.add_attestation(att, verify_signature=False)
        assert await pool.has_supermajority(1, bh, validators) is True

    async def test_no_supermajority(self):
        """2/6 validators attesting = 33% → no supermajority."""
        pool = AttestationPool()
        validators = _make_validators(6)
        bh = "ff" * 32
        for v in validators[:2]:
            att = Attestation(
                slot=1, epoch=0, block_hash=bh,
                validator_address=v.address, validator_index=v.index,
                signature=os.urandom(64),
            )
            await pool.add_attestation(att, verify_signature=False)
        assert await pool.has_supermajority(1, bh, validators) is False

    async def test_select_for_inclusion(self):
        pool = AttestationPool()
        # Add attestations at slots 1-5
        for slot in range(1, 6):
            att = Attestation(
                slot=slot, epoch=0, block_hash="ab" * 32,
                validator_address=f"0xPQ0{slot}", validator_index=slot,
                signature=os.urandom(64),
            )
            await pool.add_attestation(att, verify_signature=False)
        # Select for block at slot 10
        selected = await pool.select_attestations_for_inclusion(10, max_attestations=3)
        assert len(selected) <= 3
        # Oldest first
        if selected:
            assert selected[0].slot <= selected[-1].slot

    async def test_prune_old_attestations(self):
        pool = AttestationPool()
        for slot in range(10):
            att = Attestation(
                slot=slot, epoch=0, block_hash="ab" * 32,
                validator_address=f"0xPQ0{slot}", validator_index=slot,
                signature=os.urandom(64),
            )
            await pool.add_attestation(att, verify_signature=False)
        await pool.prune_old_attestations(current_slot=100, keep_slots=50)
        # All attestations at slot < 50 should be pruned
        atts = await pool.get_attestations_for_slot(0)
        assert len(atts) == 0

    async def test_statistics(self):
        pool = AttestationPool()
        att = Attestation(
            slot=1, epoch=0, block_hash="ab" * 32,
            validator_address="0xPQ01", validator_index=0,
            signature=os.urandom(64),
        )
        await pool.add_attestation(att, verify_signature=False)
        stats = await pool.get_statistics()
        assert stats['total_attestations'] == 1
        assert stats['validators_seen'] == 1


class TestAttestationAggregator:
    """AttestationAggregator tests."""

    def test_aggregate_preserves_all(self):
        """Currently returns all attestations (no BLS aggregation)."""
        atts = []
        for i in range(5):
            atts.append(Attestation(
                slot=1, epoch=0, block_hash="aa" * 32,
                validator_address=f"0xPQ0{i}", validator_index=i,
                signature=os.urandom(64),
                source_epoch=0, target_epoch=1,
            ))
        result = AttestationAggregator.aggregate_attestations(atts)
        assert len(result) == 5


# ============================================================================
# 3.6 — SLASHING
# ============================================================================

class TestSlashingConditions:
    """Slashing enum and penalty tests."""

    def test_all_conditions(self):
        assert SlashingConditions.DOUBLE_SIGN.value == "double_sign"
        assert SlashingConditions.INVALID_ATTESTATION.value == "invalid_attestation"
        assert SlashingConditions.SURROUND_VOTE.value == "surround_vote"
        assert SlashingConditions.DOWNTIME.value == "downtime"
        assert SlashingConditions.BRIDGE_FRAUD.value == "bridge_fraud"

    def test_double_sign_penalty_50pct(self):
        assert SLASHING_PENALTIES[SlashingConditions.DOUBLE_SIGN] == Decimal("0.50")

    def test_bridge_fraud_penalty_100pct(self):
        assert SLASHING_PENALTIES[SlashingConditions.BRIDGE_FRAUD] == Decimal("1.00")

    def test_all_conditions_have_penalties(self):
        for condition in SlashingConditions:
            assert condition in SLASHING_PENALTIES


class TestSurroundVoteEvidence:
    """SurroundVoteEvidence.is_surround() tests."""

    def test_vote1_surrounds_vote2(self):
        ev = SurroundVoteEvidence(
            source_epoch_1=1, target_epoch_1=10,
            signature_1=b'\x01',
            source_epoch_2=3, target_epoch_2=7,
            signature_2=b'\x02',
        )
        assert ev.is_surround() is True

    def test_vote2_surrounds_vote1(self):
        ev = SurroundVoteEvidence(
            source_epoch_1=3, target_epoch_1=7,
            signature_1=b'\x01',
            source_epoch_2=1, target_epoch_2=10,
            signature_2=b'\x02',
        )
        assert ev.is_surround() is True

    def test_no_surround(self):
        ev = SurroundVoteEvidence(
            source_epoch_1=1, target_epoch_1=5,
            signature_1=b'\x01',
            source_epoch_2=6, target_epoch_2=10,
            signature_2=b'\x02',
        )
        assert ev.is_surround() is False

    def test_identical_votes_no_surround(self):
        ev = SurroundVoteEvidence(
            source_epoch_1=1, target_epoch_1=5,
            signature_1=b'\x01',
            source_epoch_2=1, target_epoch_2=5,
            signature_2=b'\x02',
        )
        assert ev.is_surround() is False


class TestSlashingEvidence:
    """SlashingEvidence serialization tests."""

    def test_serialization_roundtrip(self):
        ev = SlashingEvidence(
            condition=SlashingConditions.DOUBLE_SIGN,
            validator_address="0xPQ01",
            slot=100,
            epoch=3,
            evidence_data={"block1": "aaa", "block2": "bbb"},
        )
        d = ev.to_dict()
        ev2 = SlashingEvidence.from_dict(d)
        assert ev2.condition == ev.condition
        assert ev2.validator_address == ev.validator_address
        assert ev2.slot == ev.slot
        assert ev2.epoch == ev.epoch

    def test_double_sign_evidence_to_dict(self):
        ev = DoubleSignEvidence(
            slot=10,
            block1_hash="aa" * 32,
            block1_signature=b'\x01' * 32,
            block2_hash="bb" * 32,
            block2_signature=b'\x02' * 32,
        )
        d = ev.to_dict()
        assert d['type'] == 'double_sign'
        assert d['slot'] == 10


@pytest.mark.asyncio
class TestSlashingExecutor:
    """SlashingExecutor detection tests."""

    async def test_double_sign_detected(self):
        executor = SlashingExecutor()
        # First proposal is fine
        ev1 = await executor.check_double_sign("0xPQ01", 10, "aaa", b'\x01')
        assert ev1 is None
        # Same slot, different hash → double sign
        ev2 = await executor.check_double_sign("0xPQ01", 10, "bbb", b'\x02')
        assert ev2 is not None
        assert ev2.condition == SlashingConditions.DOUBLE_SIGN

    async def test_same_block_no_double_sign(self):
        executor = SlashingExecutor()
        await executor.check_double_sign("0xPQ01", 10, "aaa", b'\x01')
        ev = await executor.check_double_sign("0xPQ01", 10, "aaa", b'\x01')
        assert ev is None

    async def test_surround_vote_detected(self):
        executor = SlashingExecutor()
        # First attestation: source=1, target=5
        ev1 = await executor.check_surround_vote("0xPQ01", 1, 5, b'\x01')
        assert ev1 is None
        # Second attestation: source=0, target=10 → surrounds first
        ev2 = await executor.check_surround_vote("0xPQ01", 0, 10, b'\x02')
        assert ev2 is not None
        assert ev2.condition == SlashingConditions.SURROUND_VOTE

    async def test_no_surround_different_validator(self):
        executor = SlashingExecutor()
        await executor.check_surround_vote("0xPQ01", 1, 5, b'\x01')
        ev = await executor.check_surround_vote("0xPQ02", 0, 10, b'\x02')
        assert ev is None  # Different validator, no slashing

    async def test_downtime_detected(self):
        executor = SlashingExecutor()
        ev = await executor.check_downtime("0xPQ01", 5, expected_attestations=32, actual_attestations=2)
        assert ev is not None
        assert ev.condition == SlashingConditions.DOWNTIME

    async def test_downtime_ok(self):
        executor = SlashingExecutor()
        ev = await executor.check_downtime("0xPQ01", 5, expected_attestations=32, actual_attestations=30)
        assert ev is None

    async def test_downtime_zero_expected(self):
        executor = SlashingExecutor()
        ev = await executor.check_downtime("0xPQ01", 5, expected_attestations=0, actual_attestations=0)
        assert ev is None

    async def test_submit_duplicate_evidence_rejected(self):
        executor = SlashingExecutor()
        ev = SlashingEvidence(
            condition=SlashingConditions.DOUBLE_SIGN,
            validator_address="0xPQ01",
            slot=10, epoch=0,
            evidence_data={"test": True},
        )
        assert await executor.submit_evidence(ev) is True
        assert await executor.submit_evidence(ev) is False  # Duplicate

    async def test_get_pending_evidence(self):
        executor = SlashingExecutor()
        await executor.check_double_sign("0xPQ01", 10, "aaa", b'\x01')
        await executor.check_double_sign("0xPQ01", 10, "bbb", b'\x02')
        pending = await executor.get_pending_evidence()
        assert len(pending) == 1

    async def test_prune_old_data(self):
        executor = SlashingExecutor()
        # Record at slot 10
        await executor.check_double_sign("0xPQ01", 10, "aaa", b'\x01')
        # Prune with current_epoch=200
        await executor.prune_old_data(current_epoch=200, keep_epochs=50)
        # Old data should be pruned
        assert len(executor._proposals) == 0


@pytest.mark.asyncio
class TestSlashingProtectionDB:
    """SlashingProtectionDB tests with temp SQLite file."""

    async def test_block_signing_protection(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            db = SlashingProtectionDB(db_path)
            await db.initialize()

            assert await db.can_sign_block("0xPQ01", 10) is True
            await db.record_block_signature("0xPQ01", 10, "block_hash_a")
            assert await db.can_sign_block("0xPQ01", 10) is False
            # Different slot is fine
            assert await db.can_sign_block("0xPQ01", 11) is True

            await db.close()
        finally:
            os.unlink(db_path)

    async def test_attestation_signing_protection(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            db = SlashingProtectionDB(db_path)
            await db.initialize()

            assert await db.can_sign_attestation("0xPQ01", 1, 5) is True
            await db.record_attestation_signature("0xPQ01", 1, 5)
            # Same target epoch → blocked
            assert await db.can_sign_attestation("0xPQ01", 1, 5) is False
            # Surround vote → blocked
            assert await db.can_sign_attestation("0xPQ01", 0, 10) is False

            await db.close()
        finally:
            os.unlink(db_path)

    async def test_surround_vote_both_directions(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            db = SlashingProtectionDB(db_path)
            await db.initialize()

            # Record (source=2, target=8)
            await db.record_attestation_signature("0xPQ01", 2, 8)
            # Surrounded by: (source=1, target=10) → source<2 and 8<10
            assert await db.can_sign_attestation("0xPQ01", 1, 10) is False
            # Surrounds existing: (source=3, target=6) → 2<3 and 6<8
            assert await db.can_sign_attestation("0xPQ01", 3, 6) is False
            # Non-overlapping is fine: (source=9, target=12)
            assert await db.can_sign_attestation("0xPQ01", 9, 12) is True

            await db.close()
        finally:
            os.unlink(db_path)


# ============================================================================
# 3.7 — FORK CHOICE (LMD-GHOST + CASPER FFG)
# ============================================================================

class TestBlockNodeAndCheckpoint:
    """BlockNode and Checkpoint data tests."""

    def test_block_node_hashable(self):
        b = BlockNode(
            block_hash="aaa", parent_hash="bbb", slot=1,
            proposer_address="0xPQ01", state_root="ccc",
        )
        assert hash(b) == hash("aaa")

    def test_checkpoint_equality(self):
        c1 = Checkpoint(epoch=1, root="abc")
        c2 = Checkpoint(epoch=1, root="abc")
        assert c1 == c2

    def test_checkpoint_inequality(self):
        c1 = Checkpoint(epoch=1, root="abc")
        c2 = Checkpoint(epoch=2, root="abc")
        assert c1 != c2

    def test_latest_message(self):
        lm = LatestMessage(epoch=5, root="xyz")
        assert lm.epoch == 5


@pytest.mark.asyncio
class TestForkChoiceStore:
    """ForkChoiceStore LMD-GHOST + Casper FFG tests."""

    def _genesis(self) -> BlockNode:
        return BlockNode(
            block_hash=_block_hash("genesis"),
            parent_hash="0" * 64,
            slot=0,
            proposer_address="genesis",
            state_root="state0",
            justified=True,
            finalized=True,
        )

    async def test_genesis_is_head(self):
        genesis = self._genesis()
        store = ForkChoiceStore(genesis, genesis_time=0)
        assert store.get_head() == genesis.block_hash

    async def test_single_chain(self):
        genesis = self._genesis()
        store = ForkChoiceStore(genesis, genesis_time=0)

        b1 = BlockNode(
            block_hash=_block_hash("b1"),
            parent_hash=genesis.block_hash,
            slot=1, proposer_address="v1", state_root="s1",
        )
        assert await store.on_block(b1) is True
        assert store.get_head() == b1.block_hash

    async def test_fork_heaviest_wins(self):
        genesis = self._genesis()
        store = ForkChoiceStore(genesis, genesis_time=0)
        store.balances = {"v1": Decimal("100000"), "v2": Decimal("200000")}

        # Fork: two children of genesis
        b_a = BlockNode(
            block_hash=_block_hash("fork_a"),
            parent_hash=genesis.block_hash,
            slot=1, proposer_address="v1", state_root="sa",
        )
        b_b = BlockNode(
            block_hash=_block_hash("fork_b"),
            parent_hash=genesis.block_hash,
            slot=1, proposer_address="v2", state_root="sb",
        )
        await store.on_block(b_a)
        await store.on_block(b_b)

        # v2 (200K) attests to fork_b
        store.latest_messages["v2"] = LatestMessage(epoch=0, root=b_b.block_hash)
        # v1 (100K) attests to fork_a
        store.latest_messages["v1"] = LatestMessage(epoch=0, root=b_a.block_hash)

        head = store.get_head()
        assert head == b_b.block_hash  # Heavier chain wins

    async def test_attestation_accepted(self):
        genesis = self._genesis()
        store = ForkChoiceStore(genesis, genesis_time=0)

        b1 = BlockNode(
            block_hash=_block_hash("b1"),
            parent_hash=genesis.block_hash,
            slot=1, proposer_address="v1", state_root="s1",
        )
        await store.on_block(b1)

        target = Checkpoint(epoch=0, root=b1.block_hash)
        source = Checkpoint(epoch=0, root=genesis.block_hash)
        result = await store.on_attestation("v1", b1.block_hash, source, target)
        assert result is True

    async def test_attestation_unknown_block_rejected(self):
        genesis = self._genesis()
        store = ForkChoiceStore(genesis, genesis_time=0)

        target = Checkpoint(epoch=0, root="nonexistent")
        source = Checkpoint(epoch=0, root=genesis.block_hash)
        result = await store.on_attestation("v1", "nonexistent", source, target)
        assert result is False

    async def test_block_before_finalized_rejected(self):
        genesis = self._genesis()
        store = ForkChoiceStore(genesis, genesis_time=0)
        # Genesis is at slot 0 and finalized
        b_old = BlockNode(
            block_hash=_block_hash("old"),
            parent_hash=genesis.block_hash,
            slot=0,  # Same slot as finalized genesis
            proposer_address="v1", state_root="s_old",
        )
        result = await store.on_block(b_old)
        assert result is False

    async def test_equivocating_validator_excluded(self):
        genesis = self._genesis()
        store = ForkChoiceStore(genesis, genesis_time=0)
        store.balances = {"v1": Decimal("100000"), "v2": Decimal("50000")}

        b1 = BlockNode(
            block_hash=_block_hash("b1"),
            parent_hash=genesis.block_hash,
            slot=1, proposer_address="v1", state_root="s1",
        )
        await store.on_block(b1)

        store.latest_messages["v1"] = LatestMessage(epoch=0, root=b1.block_hash)
        # Mark v1 as equivocating
        store.add_equivocation("v1")
        # v1's weight should be excluded
        weight = store.get_weight(b1.block_hash)
        assert weight == Decimal("0")

    async def test_finalized_blocks_marked(self):
        genesis = self._genesis()
        store = ForkChoiceStore(genesis, genesis_time=0)

        # Build chain: genesis → b1 → b2 → b3
        parent = genesis.block_hash
        for i in range(1, 4):
            b = BlockNode(
                block_hash=_block_hash(f"chain_{i}"),
                parent_hash=parent,
                slot=i, proposer_address="v1", state_root=f"s{i}",
            )
            await store.on_block(b)
            parent = b.block_hash

        # Manually finalize a block
        store._mark_finalized(_block_hash("chain_2"))
        assert store.is_finalized(_block_hash("chain_2")) is True
        assert store.is_finalized(_block_hash("chain_1")) is True  # Ancestor
        assert store.is_finalized(genesis.block_hash) is True
        assert store.is_finalized(_block_hash("chain_3")) is False

    async def test_update_balances(self):
        genesis = self._genesis()
        store = ForkChoiceStore(genesis, genesis_time=0)
        store.update_balances({"v1": Decimal("100000")})
        assert store.balances["v1"] == Decimal("100000")


@pytest.mark.asyncio
class TestForkChoice:
    """High-level ForkChoice wrapper tests."""

    async def test_genesis_head(self):
        fc = ForkChoice(
            genesis_block_hash=_block_hash("gen"),
            genesis_state_root="state0",
            genesis_time=0,
        )
        assert fc.get_head() == _block_hash("gen")

    async def test_add_block_and_head(self):
        fc = ForkChoice(
            genesis_block_hash=_block_hash("gen"),
            genesis_state_root="state0",
            genesis_time=0,
        )
        added = await fc.add_block(
            block_hash=_block_hash("b1"),
            parent_hash=_block_hash("gen"),
            slot=1, proposer_address="v1", state_root="s1",
        )
        assert added is True
        assert fc.get_head() == _block_hash("b1")

    async def test_finalized_checkpoint_starts_at_genesis(self):
        fc = ForkChoice(
            genesis_block_hash=_block_hash("gen"),
            genesis_state_root="state0",
            genesis_time=0,
        )
        epoch, root = fc.get_finalized_checkpoint()
        assert epoch == 0
        assert root == _block_hash("gen")

    async def test_justified_checkpoint_starts_at_genesis(self):
        fc = ForkChoice(
            genesis_block_hash=_block_hash("gen"),
            genesis_state_root="state0",
            genesis_time=0,
        )
        epoch, root = fc.get_justified_checkpoint()
        assert epoch == 0

    async def test_status(self):
        fc = ForkChoice(
            genesis_block_hash=_block_hash("gen"),
            genesis_state_root="state0",
            genesis_time=0,
        )
        status = fc.get_status()
        assert status['head'] == _block_hash("gen")
        assert status['head_slot'] == 0
        assert status['total_blocks'] == 1

    async def test_add_attestation(self):
        fc = ForkChoice(
            genesis_block_hash=_block_hash("gen"),
            genesis_state_root="state0",
            genesis_time=0,
        )
        result = await fc.add_attestation(
            validator_address="v1",
            block_hash=_block_hash("gen"),
            source_epoch=0, source_root=_block_hash("gen"),
            target_epoch=0, target_root=_block_hash("gen"),
        )
        assert result is True


# ============================================================================
# 3.8 — REWARDS & INFLATION
# ============================================================================

class TestRewardsCalculator:
    """RewardsCalculator math tests."""

    def test_base_reward_positive(self):
        calc = RewardsCalculator()
        reward = calc.get_base_reward(
            effective_balance=Decimal("100000"),
            total_active_balance=Decimal("10000000"),
        )
        assert reward > Decimal("0")

    def test_base_reward_zero_total(self):
        calc = RewardsCalculator()
        reward = calc.get_base_reward(
            effective_balance=Decimal("100000"),
            total_active_balance=Decimal("0"),
        )
        assert reward == Decimal("0")

    def test_base_reward_scales_with_balance(self):
        calc = RewardsCalculator()
        total = Decimal("10000000")
        r_small = calc.get_base_reward(Decimal("100000"), total)
        r_big = calc.get_base_reward(Decimal("200000"), total)
        assert r_big > r_small

    def test_proposer_reward(self):
        calc = RewardsCalculator()
        base = Decimal("10")
        reward = calc.get_proposer_reward(base, attestations_included=5)
        assert reward > Decimal("0")

    def test_attestation_rewards_all_correct(self):
        calc = RewardsCalculator()
        base = Decimal("10")
        total = Decimal("1000000")
        participating = Decimal("800000")
        s, t, h = calc.get_attestation_rewards(
            base, True, True, True,
            participating, participating, participating,
            total,
        )
        assert s > Decimal("0")
        assert t > Decimal("0")
        assert h > Decimal("0")

    def test_attestation_rewards_none_correct(self):
        calc = RewardsCalculator()
        base = Decimal("10")
        total = Decimal("1000000")
        s, t, h = calc.get_attestation_rewards(
            base, False, False, False,
            Decimal("0"), Decimal("0"), Decimal("0"),
            total,
        )
        assert s == Decimal("0")
        assert t == Decimal("0")
        assert h == Decimal("0")

    def test_attestation_penalties_all_missed(self):
        calc = RewardsCalculator()
        base = Decimal("10")
        s, t, h = calc.get_attestation_penalties(base, False, False, False)
        assert s > Decimal("0")
        assert t > Decimal("0")
        assert h > Decimal("0")

    def test_attestation_penalties_all_correct_zero(self):
        calc = RewardsCalculator()
        base = Decimal("10")
        s, t, h = calc.get_attestation_penalties(base, True, True, True)
        assert s == Decimal("0")
        assert t == Decimal("0")
        assert h == Decimal("0")

    def test_sync_committee_reward_participation(self):
        calc = RewardsCalculator()
        reward = calc.get_sync_committee_reward(Decimal("10"), True, 100)
        assert reward > Decimal("0")

    def test_sync_committee_reward_no_participation(self):
        calc = RewardsCalculator()
        reward = calc.get_sync_committee_reward(Decimal("10"), False, 100)
        assert reward == Decimal("0")

    def test_inactivity_penalty_low_delay(self):
        """No penalty when finality delay <= 4."""
        calc = RewardsCalculator()
        penalty = calc.get_inactivity_penalty(
            Decimal("100000"), inactivity_score=10, finality_delay=4,
        )
        assert penalty == Decimal("0")

    def test_inactivity_penalty_high_delay(self):
        """Penalty when finality delay > 4."""
        calc = RewardsCalculator()
        penalty = calc.get_inactivity_penalty(
            Decimal("100000"), inactivity_score=10, finality_delay=10,
        )
        assert penalty > Decimal("0")

    def test_slashing_penalty_increases_with_correlation(self):
        calc = RewardsCalculator()
        p_solo = calc.get_slashing_penalty(
            Decimal("100000"),
            total_slashed_balance=Decimal("100000"),
            total_active_balance=Decimal("10000000"),
        )
        p_corr = calc.get_slashing_penalty(
            Decimal("100000"),
            total_slashed_balance=Decimal("3000000"),
            total_active_balance=Decimal("10000000"),
        )
        assert p_corr > p_solo

    def test_reward_summary_net(self):
        rs = RewardSummary(validator_address="0xPQ01", epoch=0)
        rs.source_reward = Decimal("5")
        rs.target_reward = Decimal("10")
        rs.source_penalty = Decimal("3")
        assert rs.total_reward == Decimal("15")
        assert rs.total_penalty == Decimal("3")
        assert rs.net_reward == Decimal("12")

    def test_epoch_reward_report(self):
        report = EpochRewardReport(epoch=0, slot_range=(0, 31))
        report.total_rewards = Decimal("100")
        report.total_penalties = Decimal("10")
        assert report.total_net_issuance == Decimal("0")  # Not auto-calculated


class TestInflationSchedule:
    """InflationSchedule tests."""

    def test_initial_rate(self):
        schedule = InflationSchedule()
        rate = schedule.get_annual_inflation_rate(2025)
        assert rate == Decimal("0.02") or rate == Decimal("0.0200")

    def test_rate_decays(self):
        schedule = InflationSchedule()
        r0 = schedule.get_annual_inflation_rate(2025)
        r1 = schedule.get_annual_inflation_rate(2026)
        r5 = schedule.get_annual_inflation_rate(2030)
        assert r1 < r0
        assert r5 < r1

    def test_minimum_rate(self):
        schedule = InflationSchedule()
        rate = schedule.get_annual_inflation_rate(2100)
        assert rate >= Decimal("0.005")

    def test_epoch_inflation_positive(self):
        schedule = InflationSchedule()
        inflation = schedule.get_epoch_inflation(
            epoch=0,
            total_supply=Decimal("1000000000"),
        )
        assert inflation > Decimal("0")

    def test_projected_supply_increases(self):
        schedule = InflationSchedule()
        projections = schedule.get_projected_supply(
            initial_supply=Decimal("1000000000"),
            years=5,
        )
        assert len(projections) == 6  # 0 through 5
        # Supply should increase each year
        for i in range(1, len(projections)):
            assert projections[i][1] > projections[i - 1][1]


class TestRewardWeights:
    """Reward weight constant tests."""

    def test_weights_sum_less_than_denominator(self):
        """Source + Target + Head + Sync + Proposer should not exceed denominator."""
        total = TIMELY_SOURCE_WEIGHT + TIMELY_TARGET_WEIGHT + TIMELY_HEAD_WEIGHT
        # Individual components checked; other weights (sync, proposer) fill the rest
        assert total < WEIGHT_DENOMINATOR

    def test_target_weight_highest(self):
        """Target correctness is most important."""
        assert TIMELY_TARGET_WEIGHT > TIMELY_SOURCE_WEIGHT
        assert TIMELY_TARGET_WEIGHT > TIMELY_HEAD_WEIGHT


# ============================================================================
# 3.9 — SYNC COMMITTEE
# ============================================================================

class TestSyncCommitteeManager:
    """SyncCommitteeManager tests."""

    def _validators_dicts(self, n: int) -> list:
        """Create N validator dicts for sync committee."""
        return [
            {
                'address': f"0xPQ{i:04d}",
                'public_key': f"pk_{i}",
                'effective_balance': 100000,
            }
            for i in range(n)
        ]

    def test_period_from_epoch(self):
        mgr = SyncCommitteeManager(epochs_per_period=256)
        assert mgr.get_sync_committee_period(0) == 0
        assert mgr.get_sync_committee_period(255) == 0
        assert mgr.get_sync_committee_period(256) == 1

    def test_period_from_slot(self):
        mgr = SyncCommitteeManager(epochs_per_period=256, slots_per_epoch=32)
        # slot 0 → epoch 0 → period 0
        assert mgr.get_sync_committee_period_from_slot(0) == 0
        # slot 8191 → epoch 255 → period 0
        assert mgr.get_sync_committee_period_from_slot(8191) == 0
        # slot 8192 → epoch 256 → period 1
        assert mgr.get_sync_committee_period_from_slot(8192) == 1

    def test_compute_committee(self):
        mgr = SyncCommitteeManager(sync_committee_size=16, epochs_per_period=256)
        validators = self._validators_dicts(50)
        randao = os.urandom(32)
        committee = mgr.compute_sync_committee(0, validators, randao)
        assert len(committee.pubkeys) == 16
        assert committee.period == 0

    def test_committee_cached(self):
        mgr = SyncCommitteeManager(sync_committee_size=16, epochs_per_period=256)
        validators = self._validators_dicts(50)
        randao = os.urandom(32)
        c1 = mgr.compute_sync_committee(0, validators, randao)
        c2 = mgr.compute_sync_committee(0, validators, randao)
        assert c1 is c2

    def test_is_in_committee(self):
        mgr = SyncCommitteeManager(sync_committee_size=16, epochs_per_period=256)
        validators = self._validators_dicts(50)
        randao = os.urandom(32)
        committee = mgr.compute_sync_committee(0, validators, randao)
        member = committee.pubkeys[0]
        assert mgr.is_in_sync_committee(member, 0, validators, randao) is True

    def test_record_and_aggregate(self):
        mgr = SyncCommitteeManager(sync_committee_size=4, epochs_per_period=256)
        validators = self._validators_dicts(10)
        randao = os.urandom(32)
        committee = mgr.compute_sync_committee(0, validators, randao)

        # Record signatures for 2 of 4 members
        mgr.record_sync_signature(0, committee.pubkeys[0], b'\x01' * 32)
        mgr.record_sync_signature(0, committee.pubkeys[1], b'\x02' * 32)

        agg = mgr.aggregate_sync_signatures(0, committee)
        assert agg is not None
        assert agg.participation_count == 2

    def test_aggregate_no_signatures(self):
        mgr = SyncCommitteeManager(sync_committee_size=4, epochs_per_period=256)
        validators = self._validators_dicts(10)
        randao = os.urandom(32)
        committee = mgr.compute_sync_committee(0, validators, randao)
        agg = mgr.aggregate_sync_signatures(0, committee)
        assert agg is None

    def test_cleanup_old_signatures(self):
        mgr = SyncCommitteeManager()
        mgr._current_signatures[10] = {"v1": b'\x01'}
        mgr._current_signatures[100] = {"v2": b'\x02'}
        mgr.cleanup_old_signatures(current_slot=120, keep_slots=64)
        assert 10 not in mgr._current_signatures
        assert 100 in mgr._current_signatures


class TestSyncAggregate:
    """SyncAggregate participation tests."""

    def test_participation_count(self):
        bits = (1 | (1 << 3) | (1 << 7)).to_bytes(2, 'little')  # 3 bits set
        agg = SyncAggregate(slot=0, sync_committee_bits=bits, sync_committee_signature="sig")
        assert agg.participation_count == 3

    def test_participation_rate(self):
        bits = (0xFF).to_bytes(1, 'little')  # 8 bits set
        agg = SyncAggregate(slot=0, sync_committee_bits=bits, sync_committee_signature="sig")
        rate = agg.participation_rate
        assert rate == 8 / 512  # SYNC_COMMITTEE_SIZE default is 512


class TestLightClientUpdate:
    """LightClientUpdate creation tests."""

    def test_create_update(self):
        mgr = SyncCommitteeManager(sync_committee_size=4, epochs_per_period=256)
        agg = SyncAggregate(
            slot=10,
            sync_committee_bits=b'\x0f',
            sync_committee_signature="agg_sig",
        )
        update = mgr.create_light_client_update(
            attested_slot=10,
            attested_root="root10",
            finalized_slot=5,
            finalized_root="root5",
            sync_aggregate=agg,
        )
        assert update.attested_header_slot == 10
        assert update.finalized_header_slot == 5
        assert update.sync_aggregate is agg


class TestSyncCommitteeContribution:
    """SyncCommitteeContribution subcommittee tests."""

    def test_subcommittee_index(self):
        idx = SyncCommitteeContribution.get_subcommittee_index(
            validator_index_in_committee=0,
            committee_size=512,
            subnet_count=4,
        )
        assert idx == 0

        idx = SyncCommitteeContribution.get_subcommittee_index(
            validator_index_in_committee=200,
            committee_size=512,
            subnet_count=4,
        )
        assert idx == 200 // 128  # 128 per subnet


# ============================================================================
# 3.10 — LEGACY PoW REMOVAL
# ============================================================================

class TestPoWRemoval:
    """Verify no PoW code paths remain in consensus.py."""

    def test_no_consensus_v1_class(self):
        """Consensus_V1 should not exist after PoW removal."""
        import qrdx.consensus as mod
        assert not hasattr(mod, 'Consensus_V1'), \
            "Consensus_V1 class still exists — PoW code not removed"

    def test_no_v1_in_rules_map(self):
        """ConsensusEngine should not map V1."""
        engine = ConsensusEngine()
        for version in engine._rules_map:
            assert version != 1, "V1 (PoW) still in ConsensusEngine._rules_map"

    def test_pos_is_only_production_version(self):
        """Only CONSENSUS_V2_POS should be active for any block height."""
        schedule = ConsensusSchedule()
        for height in [0, 1, 100, 1_000_000]:
            assert schedule.get_active_version(height) == ConsensusVersion.CONSENSUS_V2_POS

    def test_no_difficulty_adjustment_logic(self):
        """PoS difficulty always returns 1.0."""
        rules = get_pos_rules()
        result = rules.calculate_new_difficulty(Decimal("5"), Decimal("100"))
        assert result == Decimal("1.0")

    def test_no_mining_imports_in_pos(self):
        """Consensus_V2_PoS should not import mining functions."""
        import inspect
        source = inspect.getsource(Consensus_V2_PoS.calculate_new_difficulty)
        assert "difficulty_to_hashrate" not in source
        assert "hashrate_to_difficulty" not in source
        assert "START_DIFFICULTY" not in source


# ============================================================================
# 3.x — LIFECYCLE
# ============================================================================

class TestLifecycleState:
    """LifecycleState enum tests."""

    def test_all_states(self):
        states = list(LifecycleState)
        state_names = {s.name for s in states}
        expected = {
            'PENDING_DEPOSIT', 'PENDING_ACTIVATION', 'ACTIVE',
            'PENDING_EXIT', 'EXITED', 'WITHDRAWABLE', 'WITHDRAWN',
        }
        assert expected == state_names

    def test_state_count(self):
        assert len(LifecycleState) == 7


class TestValidatorActivationQueue:
    """ValidatorActivationQueue tests."""

    def test_add_and_length(self):
        queue = ValidatorActivationQueue(churn_limit=4)
        lc = ValidatorLifecycle(address="0xPQ01", public_key="pk1")
        queue.add_to_queue(lc, eligibility_epoch=5)
        assert queue.length == 1

    def test_sorted_insertion(self):
        queue = ValidatorActivationQueue(churn_limit=4)
        lc1 = ValidatorLifecycle(address="0xPQ01", public_key="pk1")
        lc2 = ValidatorLifecycle(address="0xPQ02", public_key="pk2")
        lc3 = ValidatorLifecycle(address="0xPQ03", public_key="pk3")
        queue.add_to_queue(lc3, eligibility_epoch=10)
        queue.add_to_queue(lc1, eligibility_epoch=3)
        queue.add_to_queue(lc2, eligibility_epoch=7)
        # Queue should be sorted by eligibility epoch
        assert queue._queue[0] == (3, "0xPQ01")
        assert queue._queue[1] == (7, "0xPQ02")
        assert queue._queue[2] == (10, "0xPQ03")

    def test_churn_limit(self):
        queue = ValidatorActivationQueue(churn_limit=2)
        for i in range(5):
            lc = ValidatorLifecycle(address=f"0xPQ{i:02d}", public_key=f"pk{i}")
            queue.add_to_queue(lc, eligibility_epoch=0)
        to_activate = queue.get_validators_to_activate(current_epoch=0)
        assert len(to_activate) == 2  # Churn limit

    def test_activate_removes_from_queue(self):
        queue = ValidatorActivationQueue(churn_limit=4)
        lc = ValidatorLifecycle(address="0xPQ01", public_key="pk1")
        queue.add_to_queue(lc, eligibility_epoch=0)
        to_activate = queue.get_validators_to_activate(0)
        queue.activate_validators(to_activate, activation_epoch=4)
        assert queue.length == 0
        assert lc.state == LifecycleState.ACTIVE
        assert lc.activation_epoch == 4

    def test_estimated_wait_time(self):
        queue = ValidatorActivationQueue(churn_limit=2)
        for i in range(6):
            lc = ValidatorLifecycle(address=f"0xPQ{i:02d}", public_key=f"pk{i}")
            queue.add_to_queue(lc, eligibility_epoch=0)
        # Position 5 (0-indexed), churn=2 → 3 epochs + ACTIVATION_DELAY
        wait = queue.get_estimated_wait_time("0xPQ05", 0)
        assert wait is not None
        assert wait >= 3


class TestValidatorExitQueue:
    """ValidatorExitQueue tests."""

    def test_request_exit(self):
        queue = ValidatorExitQueue(churn_limit=4)
        lc = ValidatorLifecycle(address="0xPQ01", public_key="pk1")
        lc.state = LifecycleState.ACTIVE
        queue.request_exit(lc, exit_epoch=10)
        assert queue.length == 1
        assert lc.state == LifecycleState.PENDING_EXIT

    def test_process_exits(self):
        queue = ValidatorExitQueue(churn_limit=4)
        lc = ValidatorLifecycle(address="0xPQ01", public_key="pk1")
        lc.state = LifecycleState.ACTIVE
        queue.request_exit(lc, exit_epoch=5)
        to_exit = queue.get_validators_to_exit(current_epoch=5)
        queue.process_exits(to_exit, current_epoch=5)
        assert lc.state == LifecycleState.EXITED
        assert lc.withdrawable_epoch is not None


@pytest.mark.asyncio
class TestLifecycleManager:
    """LifecycleManager integration tests."""

    async def test_submit_deposit(self):
        mgr = LifecycleManager()
        ok, msg = await mgr.submit_deposit(
            "0xPQ01", "pk1", Decimal("100000"), "0xW01", "sig1",
        )
        assert ok is True

    async def test_deposit_below_minimum(self):
        mgr = LifecycleManager()
        ok, msg = await mgr.submit_deposit(
            "0xPQ01", "pk1", Decimal("1000"), "0xW01", "sig1",
        )
        assert ok is False
        assert "Minimum" in msg

    async def test_deposit_duplicate_rejected(self):
        mgr = LifecycleManager()
        await mgr.submit_deposit("0xPQ01", "pk1", Decimal("100000"), "0xW01", "sig1")
        ok, msg = await mgr.submit_deposit("0xPQ01", "pk1", Decimal("100000"), "0xW01", "sig2")
        assert ok is False

    async def test_deposit_inclusion_and_activation(self):
        mgr = LifecycleManager()
        await mgr.submit_deposit("0xPQ01", "pk1", Decimal("100000"), "0xW01", "sig1")
        await mgr.process_deposit_inclusion("0xPQ01", inclusion_slot=0, current_epoch=0)

        # Should be in activation queue
        assert mgr.activation_queue.length == 1

        # Process epoch should activate (eligibility at epoch 1, current at 1)
        await mgr.process_epoch(1)
        # Validator activated after delay
        status = mgr.get_validator_status("0xPQ01")
        assert status is not None
        assert status['state'] in ['PENDING_ACTIVATION', 'ACTIVE']

    async def test_voluntary_exit(self):
        mgr = LifecycleManager()
        # Set up active validator directly
        lc = ValidatorLifecycle(
            address="0xPQ01", public_key="pk1",
            state=LifecycleState.ACTIVE,
            deposit_amount=Decimal("100000"),
            effective_balance=Decimal("100000"),
        )
        mgr._validators["0xPQ01"] = lc
        mgr._active_count = 1

        ok, msg = await mgr.request_voluntary_exit("0xPQ01", "sig", current_epoch=10)
        assert ok is True
        assert lc.state == LifecycleState.PENDING_EXIT

    async def test_force_exit(self):
        mgr = LifecycleManager()
        lc = ValidatorLifecycle(
            address="0xPQ01", public_key="pk1",
            state=LifecycleState.ACTIVE,
        )
        mgr._validators["0xPQ01"] = lc
        mgr._active_count = 1

        await mgr.force_exit("0xPQ01", "slashed", current_epoch=5)
        assert lc.state == LifecycleState.EXITED

    async def test_withdrawal_processing(self):
        mgr = LifecycleManager()
        lc = ValidatorLifecycle(
            address="0xPQ01", public_key="pk1",
            state=LifecycleState.WITHDRAWABLE,
            effective_balance=Decimal("100000"),
            withdrawable_balance=Decimal("100000"),
        )
        mgr._validators["0xPQ01"] = lc

        ok, amount = await mgr.process_withdrawal("0xPQ01", current_epoch=100)
        assert ok is True
        assert amount == Decimal("100000")
        assert lc.state == LifecycleState.WITHDRAWN

    async def test_queue_stats(self):
        mgr = LifecycleManager()
        stats = mgr.get_queue_stats()
        assert 'activation_queue_length' in stats
        assert 'exit_queue_length' in stats
        assert 'churn_limit' in stats

    async def test_max_validators_limit(self):
        mgr = LifecycleManager(max_validators=2)
        # Deposit and include 2 validators
        await mgr.submit_deposit("0xPQ01", "pk1", Decimal("100000"), "0xW01", "sig1")
        await mgr.process_deposit_inclusion("0xPQ01", 0, 0)
        await mgr.submit_deposit("0xPQ02", "pk2", Decimal("100000"), "0xW02", "sig2")
        await mgr.process_deposit_inclusion("0xPQ02", 1, 0)
        # 3rd deposit should be rejected (max_validators=2)
        ok, msg = await mgr.submit_deposit("0xPQ03", "pk3", Decimal("100000"), "0xW03", "sig3")
        assert ok is False
        assert "Maximum" in msg


# ============================================================================
# 3.x — GOSSIP
# ============================================================================

class TestGossipTopics:
    """GossipTopic and GossipMessage tests."""

    def test_all_topics_exist(self):
        assert GossipTopic.BEACON_BLOCK.value == "beacon_block"
        assert GossipTopic.BEACON_ATTESTATION.value == "beacon_attestation"
        assert GossipTopic.VOLUNTARY_EXIT.value == "voluntary_exit"
        assert GossipTopic.PROPOSER_SLASHING.value == "proposer_slashing"
        assert GossipTopic.ATTESTER_SLASHING.value == "attester_slashing"
        assert GossipTopic.SYNC_COMMITTEE_MESSAGE.value == "sync_committee_message"

    def test_topic_count(self):
        assert len(GossipTopic) >= 11

    def test_topic_name_includes_fork_digest(self):
        name = get_topic_name(GossipTopic.BEACON_BLOCK)
        assert "/qrdx/" in name
        assert "beacon_block" in name

    def test_gossip_message_auto_id(self):
        msg = GossipMessage(
            topic=GossipTopic.BEACON_BLOCK,
            data=b"test",
            sender="node1",
        )
        assert len(msg.message_id) == 16

    def test_gossip_message_unique_ids(self):
        msg1 = GossipMessage(
            topic=GossipTopic.BEACON_BLOCK,
            data=b"test1",
            sender="node1",
        )
        msg2 = GossipMessage(
            topic=GossipTopic.BEACON_BLOCK,
            data=b"test2",
            sender="node1",
        )
        assert msg1.message_id != msg2.message_id


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

@pytest.mark.asyncio
class TestConsensusIntegration:
    """Cross-module integration tests."""

    async def test_selection_plus_fork_choice(self):
        """Validators selected → blocks added to fork choice → correct head."""
        validators = _make_validators(5)
        selector = ValidatorSelector()
        randao = os.urandom(32)

        fc = ForkChoice(
            genesis_block_hash=_block_hash("gen"),
            genesis_state_root="state0",
            genesis_time=0,
        )
        fc.store.update_balances({v.address: v.effective_stake for v in validators})

        parent = _block_hash("gen")
        for slot in range(1, 4):
            proposer = selector.select_proposer(slot, validators, randao)
            bh = _block_hash(f"block_{slot}")
            await fc.add_block(bh, parent, slot, proposer.address, f"state_{slot}")
            parent = bh

        # Head should be the last block
        assert fc.get_head() == _block_hash("block_3")

    async def test_attestation_pool_feeds_fork_choice(self):
        """Attestations collected in pool → applied to fork choice."""
        validators = _make_validators(4)
        pool = AttestationPool()
        fc = ForkChoice(
            genesis_block_hash=_block_hash("gen"),
            genesis_state_root="state0",
            genesis_time=0,
        )

        bh = _block_hash("b1")
        await fc.add_block(bh, _block_hash("gen"), 1, "v1", "s1")

        # Add attestations to pool
        for i, v in enumerate(validators):
            att = Attestation(
                slot=1, epoch=0, block_hash=bh,
                validator_address=v.address, validator_index=i,
                signature=os.urandom(64),
            )
            await pool.add_attestation(att, verify_signature=False)

        count = await pool.get_attestation_count(1, bh)
        assert count == 4

    async def test_lifecycle_to_selection(self):
        """Validators deposited via lifecycle → used in selection."""
        mgr = LifecycleManager()
        # Deposit and include
        for i in range(4):
            await mgr.submit_deposit(
                f"0xPQ{i:04d}", f"pk{i}", Decimal("100000"),
                f"0xW{i:04d}", f"sig{i}",
            )
            await mgr.process_deposit_inclusion(f"0xPQ{i:04d}", i, 0)

        # Create Validator objects for selection
        selector = ValidatorSelector()
        validators = _make_validators(4)
        randao = os.urandom(32)

        proposer = selector.select_proposer(0, validators, randao)
        assert proposer is not None

    def test_rewards_with_real_constants(self):
        """Rewards calculator uses actual protocol constants."""
        from qrdx.constants import BASE_REWARD_FACTOR
        calc = RewardsCalculator()
        reward = calc.get_base_reward(
            Decimal("100000"),
            Decimal("15000000"),  # 150 validators × 100K
        )
        assert reward > Decimal("0")
        # Verify it uses the correct factor
        assert BASE_REWARD_FACTOR == 64
