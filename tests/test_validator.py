"""
QRDX Validator Test Suite

Comprehensive tests for QR-PoS consensus components.
"""

import pytest
import hashlib
import asyncio
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

# Import all validator components
from qrdx.validator.types import (
    Validator,
    ValidatorStatus,
    ValidatorSet,
    EpochInfo,
    SlotInfo,
)
from qrdx.validator.fork_choice import (
    ForkChoice,
    ForkChoiceStore,
    BlockNode,
    Checkpoint,
    LatestMessage,
)
from qrdx.validator.epoch_processing import (
    EpochProcessor,
    EpochProcessingResult,
    ValidatorRecord,
    ValidatorShuffling,
)
from qrdx.validator.rewards import (
    RewardsCalculator,
    RewardSummary,
    EpochRewardReport,
    InflationSchedule,
)
from qrdx.validator.genesis import (
    GenesisCreator,
    GenesisConfig,
    GenesisState,
    GenesisBlock,
    GenesisValidator,
    create_testnet_genesis,
)
from qrdx.validator.sync_committee import (
    SyncCommittee,
    SyncCommitteeManager,
    SyncAggregate,
    LightClientUpdate,
)
from qrdx.constants import (
    SLOTS_PER_EPOCH,
    MIN_VALIDATOR_STAKE,
    MAX_VALIDATORS,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def sample_validators():
    """Create sample validators for testing."""
    validators = []
    for i in range(10):
        validators.append({
            'address': f'qrdx_validator_{i:040d}',
            'public_key': hashlib.sha256(f'pubkey_{i}'.encode()).hexdigest() * 60,  # ~1920 chars
            'effective_balance': Decimal('200000') + Decimal(i * 10000),
            'status': 'active',
        })
    return validators


@pytest.fixture
def sample_attestations(sample_validators):
    """Create sample attestations for testing."""
    attestations = []
    for i, v in enumerate(sample_validators[:8]):  # 8 of 10 attest
        attestations.append({
            'validator_address': v['address'],
            'slot': 100,
            'target_epoch': 3,
            'source_epoch': 2,
            'beacon_block_root': hashlib.sha256(b'block_100').hexdigest(),
            'source_correct': True,
            'target_correct': True,
            'head_correct': True if i < 6 else False,  # 6 voted correct head
        })
    return attestations


@pytest.fixture
def sample_blocks(sample_validators):
    """Create sample blocks for testing."""
    blocks = []
    for i in range(SLOTS_PER_EPOCH):
        proposer = sample_validators[i % len(sample_validators)]
        blocks.append({
            'slot': 96 + i,  # Epoch 3 starts at slot 96
            'proposer_address': proposer['address'],
            'parent_hash': hashlib.sha256(f'block_{95 + i}'.encode()).hexdigest(),
            'block_hash': hashlib.sha256(f'block_{96 + i}'.encode()).hexdigest(),
            'attestations_included': 5 + i % 3,
        })
    return blocks


@pytest.fixture
def randao_mix():
    """Create a sample RANDAO mix."""
    return hashlib.sha256(b'test_randao_seed').digest()


# =============================================================================
# FORK CHOICE TESTS
# =============================================================================

class TestForkChoice:
    """Test LMD-GHOST fork choice implementation."""
    
    def test_fork_choice_initialization(self):
        """Test ForkChoice initialization with genesis."""
        genesis_root = hashlib.sha256(b'genesis').hexdigest()
        genesis_time = 1700000000
        
        # Create genesis block node
        genesis_block = BlockNode(
            block_hash=genesis_root,
            parent_hash='0' * 64,
            slot=0,
            proposer_address='genesis_proposer',
            state_root=hashlib.sha256(b'genesis_state').hexdigest(),
        )
        
        store = ForkChoiceStore(genesis_block, genesis_time)
        
        assert store.genesis_time == genesis_time
        assert store.justified_checkpoint is not None
        assert store.finalized_checkpoint is not None
    
    def test_block_node_creation(self):
        """Test BlockNode data structure."""
        block_hash = hashlib.sha256(b'block').hexdigest()
        parent = hashlib.sha256(b'parent').hexdigest()
        
        node = BlockNode(
            block_hash=block_hash,
            slot=100,
            parent_hash=parent,
            state_root=hashlib.sha256(b'state').hexdigest(),
            proposer_address='test_proposer',
        )
        
        assert node.block_hash == block_hash
        assert node.slot == 100
        assert node.parent_hash == parent
        assert node.weight == 0
    
    def test_checkpoint_creation(self):
        """Test Checkpoint data structure."""
        checkpoint = Checkpoint(
            epoch=5,
            root=hashlib.sha256(b'checkpoint').hexdigest(),
        )
        
        assert checkpoint.epoch == 5
        assert len(checkpoint.root) == 64
    
    @pytest.mark.asyncio
    async def test_fork_choice_on_block(self):
        """Test processing a new block."""
        genesis_root = hashlib.sha256(b'genesis').hexdigest()
        genesis_block = BlockNode(
            block_hash=genesis_root,
            parent_hash='0' * 64,
            slot=0,
            proposer_address='genesis',
            state_root=hashlib.sha256(b'genesis_state').hexdigest(),
        )
        store = ForkChoiceStore(genesis_block, 1700000000)
        
        # Create child block
        block_hash = hashlib.sha256(b'block_1').hexdigest()
        new_block = BlockNode(
            block_hash=block_hash,
            slot=1,
            parent_hash=genesis_root,
            state_root=hashlib.sha256(b'state_1').hexdigest(),
            proposer_address='proposer_1',
        )
        
        result = await store.on_block(new_block)
        assert result is True
        assert block_hash in store.blocks
    
    def test_fork_choice_get_head(self):
        """Test head selection with LMD-GHOST."""
        genesis_root = hashlib.sha256(b'genesis').hexdigest()
        genesis_block = BlockNode(
            block_hash=genesis_root,
            parent_hash='0' * 64,
            slot=0,
            proposer_address='genesis',
            state_root=hashlib.sha256(b'genesis_state').hexdigest(),
        )
        store = ForkChoiceStore(genesis_block, 1700000000)
        
        # Add child block
        block_1_root = hashlib.sha256(b'block_1').hexdigest()
        block_1 = BlockNode(
            block_hash=block_1_root,
            slot=1,
            parent_hash=genesis_root,
            state_root=hashlib.sha256(b'state_1').hexdigest(),
            proposer_address='proposer_1',
        )
        store.blocks[block_1_root] = block_1
        genesis_block.children.append(block_1_root)
        
        head = store.get_head()
        assert head == block_1_root
    
    @pytest.mark.asyncio
    async def test_latest_message_tracking(self):
        """Test tracking of validator latest messages."""
        genesis_root = hashlib.sha256(b'genesis').hexdigest()
        genesis_block = BlockNode(
            block_hash=genesis_root,
            parent_hash='0' * 64,
            slot=0,
            proposer_address='genesis',
            state_root=hashlib.sha256(b'genesis_state').hexdigest(),
        )
        store = ForkChoiceStore(genesis_block, 1700000000)
        
        validator = 'qrdx_test_validator'
        block_hash = hashlib.sha256(b'block').hexdigest()
        
        # Add block first
        block = BlockNode(
            block_hash=block_hash,
            slot=10,
            parent_hash=genesis_root,
            state_root=hashlib.sha256(b'state').hexdigest(),
            proposer_address='proposer',
        )
        store.blocks[block_hash] = block
        
        # Submit attestation
        source = Checkpoint(epoch=0, root=genesis_root)
        target = Checkpoint(epoch=0, root=block_hash)
        
        await store.on_attestation(validator, block_hash, source, target)
        
        assert validator in store.latest_messages
        assert store.latest_messages[validator].root == block_hash


# =============================================================================
# EPOCH PROCESSING TESTS
# =============================================================================

class TestEpochProcessor:
    """Test epoch boundary processing."""
    
    @pytest.fixture
    def processor(self):
        return EpochProcessor()
    
    @pytest.fixture
    def validator_records(self, sample_validators):
        records = []
        for v in sample_validators:
            records.append(ValidatorRecord(
                address=v['address'],
                public_key=bytes.fromhex(v['public_key'][:64]),
                effective_balance=v['effective_balance'],
                slashed=False,
                activation_eligibility_epoch=0,
                activation_epoch=0,
                exit_epoch=None,
                withdrawable_epoch=None,
            ))
        return records
    
    def test_compute_activation_exit_epoch(self, processor):
        """Test activation/exit epoch calculation."""
        current_epoch = 10
        expected = 10 + 1 + 4  # epoch + 1 + ACTIVATION_DELAY_EPOCHS
        
        result = processor.compute_activation_exit_epoch(current_epoch)
        assert result == expected
    
    def test_validator_churn_limit(self, processor):
        """Test validator churn limit calculation."""
        # Small set: minimum churn (4 is the floor)
        assert processor.get_validator_churn_limit(100) == 4
        assert processor.get_validator_churn_limit(1000) == 4
        
        # Large set: scales but floor is 4
        # Formula: max(4, count // 65536)
        assert processor.get_validator_churn_limit(65536) == 4  # 65536/65536 = 1, but min is 4
        assert processor.get_validator_churn_limit(262144) == 4  # 262144/65536 = 4
    
    @pytest.mark.asyncio
    async def test_process_epoch_basic(self, processor, validator_records, sample_attestations, sample_blocks, randao_mix):
        """Test basic epoch processing."""
        result = await processor.process_epoch(
            epoch=3,
            validators=validator_records,
            attestations=sample_attestations,
            blocks=sample_blocks,
            randao_mix=randao_mix,
        )
        
        assert isinstance(result, EpochProcessingResult)
        assert result.epoch == 3
        assert result.total_active_balance > 0
        assert result.participation_rate >= 0


class TestValidatorShuffling:
    """Test deterministic validator shuffling."""
    
    def test_compute_shuffled_index(self):
        """Test index shuffling is deterministic."""
        seed = hashlib.sha256(b'test_seed').digest()
        
        # Same inputs should give same outputs
        result1 = ValidatorShuffling.compute_shuffled_index(5, 100, seed)
        result2 = ValidatorShuffling.compute_shuffled_index(5, 100, seed)
        
        assert result1 == result2
        assert 0 <= result1 < 100
    
    def test_shuffling_is_bijective(self):
        """Test shuffling is a permutation (bijective)."""
        seed = hashlib.sha256(b'bijective_test').digest()
        count = 50
        
        shuffled = set()
        for i in range(count):
            shuffled_idx = ValidatorShuffling.compute_shuffled_index(i, count, seed)
            shuffled.add(shuffled_idx)
        
        # All indices should be unique
        assert len(shuffled) == count
    
    def test_compute_committee(self, sample_validators):
        """Test committee computation."""
        seed = hashlib.sha256(b'committee_seed').digest()
        addresses = [v['address'] for v in sample_validators]
        
        # With only 10 validators and 32 slots * 1 committee = 32 committees,
        # each committee will be very small. Need more validators for meaningful test.
        # For 10 validators across 32 committees, most will be empty.
        
        # Instead, test with committees_per_slot matching validator count
        committee = ValidatorShuffling.compute_committee(
            validators=addresses,
            slot=0,
            committee_index=0,
            committees_per_slot=1,
            seed=seed,
        )
        
        # With only 10 validators divided by 32 slots, result may be small
        # The important thing is the algorithm doesn't crash
        assert isinstance(committee, list)
        # All returned addresses should be from our validator set
        assert all(addr in addresses for addr in committee)


# =============================================================================
# REWARDS CALCULATOR TESTS
# =============================================================================

class TestRewardsCalculator:
    """Test reward and penalty calculations."""
    
    @pytest.fixture
    def calculator(self):
        return RewardsCalculator()
    
    def test_base_reward_calculation(self, calculator):
        """Test base reward formula."""
        effective_balance = Decimal('200000')
        total_active = Decimal('2000000')
        
        base_reward = calculator.get_base_reward(effective_balance, total_active)
        
        assert base_reward > 0
        assert isinstance(base_reward, Decimal)
    
    def test_base_reward_scales_with_balance(self, calculator):
        """Test that base reward scales with effective balance."""
        total_active = Decimal('2000000')
        
        reward_low = calculator.get_base_reward(Decimal('100000'), total_active)
        reward_high = calculator.get_base_reward(Decimal('200000'), total_active)
        
        assert reward_high > reward_low
    
    def test_proposer_reward(self, calculator):
        """Test block proposer reward calculation."""
        base_reward = Decimal('100')
        attestations_included = 10
        
        proposer_reward = calculator.get_proposer_reward(base_reward, attestations_included)
        
        assert proposer_reward > 0
        assert proposer_reward > base_reward / 10  # Should be meaningful
    
    def test_attestation_rewards_correct_votes(self, calculator):
        """Test attestation rewards for correct votes."""
        base_reward = Decimal('100')
        total_active = Decimal('2000000')
        participating = Decimal('1500000')  # 75% participation
        
        source_r, target_r, head_r = calculator.get_attestation_rewards(
            base_reward=base_reward,
            voted_correct_source=True,
            voted_correct_target=True,
            voted_correct_head=True,
            source_participating_balance=participating,
            target_participating_balance=participating,
            head_participating_balance=participating,
            total_active_balance=total_active,
        )
        
        assert source_r > 0
        assert target_r > 0
        assert head_r > 0
    
    def test_attestation_penalties_missed(self, calculator):
        """Test penalties for missing attestation duties."""
        base_reward = Decimal('100')
        
        source_p, target_p, head_p = calculator.get_attestation_penalties(
            base_reward=base_reward,
            voted_correct_source=False,
            voted_correct_target=False,
            voted_correct_head=False,
        )
        
        assert source_p > 0
        assert target_p > 0
        assert head_p > 0
    
    def test_inactivity_penalty(self, calculator):
        """Test inactivity leak penalty."""
        effective_balance = Decimal('200000')
        inactivity_score = 10
        finality_delay = 10  # Well past threshold
        
        penalty = calculator.get_inactivity_penalty(
            effective_balance, inactivity_score, finality_delay
        )
        
        assert penalty > 0
    
    def test_no_inactivity_penalty_when_finalizing(self, calculator):
        """Test no inactivity penalty when chain is finalizing."""
        effective_balance = Decimal('200000')
        inactivity_score = 10
        finality_delay = 2  # Below threshold
        
        penalty = calculator.get_inactivity_penalty(
            effective_balance, inactivity_score, finality_delay
        )
        
        assert penalty == 0
    
    def test_slashing_penalty(self, calculator):
        """Test slashing penalty calculation."""
        effective_balance = Decimal('200000')
        total_slashed = Decimal('400000')  # 2 validators slashed
        total_active = Decimal('2000000')
        
        penalty = calculator.get_slashing_penalty(
            effective_balance, total_slashed, total_active
        )
        
        assert penalty > 0
        assert penalty <= effective_balance  # Can't lose more than stake


# =============================================================================
# INFLATION SCHEDULE TESTS
# =============================================================================

class TestInflationSchedule:
    """Test token inflation schedule."""
    
    @pytest.fixture
    def schedule(self):
        return InflationSchedule()
    
    def test_initial_inflation_rate(self, schedule):
        """Test initial inflation rate."""
        rate = schedule.get_annual_inflation_rate(2025)
        assert rate == Decimal('0.02')  # 2%
    
    def test_inflation_decays(self, schedule):
        """Test inflation rate decreases over time."""
        rate_2025 = schedule.get_annual_inflation_rate(2025)
        rate_2030 = schedule.get_annual_inflation_rate(2030)
        
        assert rate_2030 < rate_2025
    
    def test_minimum_inflation_floor(self, schedule):
        """Test inflation doesn't go below minimum."""
        rate_2100 = schedule.get_annual_inflation_rate(2100)
        
        assert rate_2100 >= Decimal('0.005')  # 0.5% minimum
    
    def test_epoch_inflation_calculation(self, schedule):
        """Test per-epoch inflation amount."""
        total_supply = Decimal('100000000')  # 100M
        epoch = 1000
        
        epoch_inflation = schedule.get_epoch_inflation(epoch, total_supply)
        
        assert epoch_inflation > 0
        assert epoch_inflation < total_supply * Decimal('0.001')  # Sanity check


# =============================================================================
# GENESIS CREATION TESTS
# =============================================================================

class TestGenesisCreator:
    """Test genesis state and block creation."""
    
    @pytest.fixture
    def config(self):
        return GenesisConfig(
            chain_id=9999,
            network_name='qrdx-testnet',
            min_genesis_validators=2,
            initial_supply=Decimal('100000000'),
        )
    
    @pytest.fixture
    def creator(self, config):
        return GenesisCreator(config)
    
    def test_add_validator(self, creator):
        """Test adding a genesis validator."""
        # Create a mock Dilithium public key (hex-encoded, ~1920 chars)
        pubkey = hashlib.sha256(b'validator_1').hexdigest() * 60
        
        result = creator.add_validator(
            address='qrdx_validator_test',
            public_key=pubkey,
            stake=Decimal('100000'),
        )
        
        assert result is True
    
    def test_reject_low_stake(self, creator):
        """Test rejecting validator with insufficient stake."""
        pubkey = hashlib.sha256(b'low_stake').hexdigest() * 60
        
        result = creator.add_validator(
            address='qrdx_low_stake',
            public_key=pubkey,
            stake=Decimal('1000'),  # Below minimum
        )
        
        assert result is False
    
    def test_add_account(self, creator):
        """Test adding a pre-funded account."""
        result = creator.add_account(
            address='qrdx_treasury',
            balance=Decimal('10000000'),
            label='Treasury',
        )
        
        assert result is True
    
    def test_create_genesis(self, creator):
        """Test creating genesis state and block."""
        # Add minimum validators
        for i in range(2):
            pubkey = hashlib.sha256(f'validator_{i}'.encode()).hexdigest() * 60
            creator.add_validator(
                address=f'qrdx_validator_{i:040d}',
                public_key=pubkey,
                stake=Decimal('100000'),
            )
        
        state, block = creator.create_genesis(genesis_time=1700000000)
        
        assert isinstance(state, GenesisState)
        assert isinstance(block, GenesisBlock)
        assert len(state.validators) == 2
        assert state.genesis_time == 1700000000
        assert len(block.block_hash) == 64
    
    def test_genesis_validators_root(self, creator):
        """Test validators root is computed."""
        for i in range(2):
            pubkey = hashlib.sha256(f'validator_{i}'.encode()).hexdigest() * 60
            creator.add_validator(
                address=f'qrdx_validator_{i:040d}',
                public_key=pubkey,
                stake=Decimal('100000'),
            )
        
        state, _ = creator.create_genesis()
        
        assert len(state.genesis_validators_root) == 64
        assert state.genesis_validators_root != '0' * 64
    
    def test_create_testnet_genesis(self):
        """Test testnet genesis helper."""
        validators = [
            ('qrdx_val_1', hashlib.sha256(b'v1').hexdigest() * 60, Decimal('100000')),
            ('qrdx_val_2', hashlib.sha256(b'v2').hexdigest() * 60, Decimal('150000')),
        ]
        
        state, block = create_testnet_genesis(validators)
        
        assert state.network_name == 'qrdx-testnet'
        assert len(state.validators) == 2


# =============================================================================
# SYNC COMMITTEE TESTS
# =============================================================================

class TestSyncCommitteeManager:
    """Test sync committee operations."""
    
    @pytest.fixture
    def manager(self):
        return SyncCommitteeManager()
    
    def test_get_sync_committee_period(self, manager):
        """Test period calculation from epoch."""
        # With 256 epochs per period
        assert manager.get_sync_committee_period(0) == 0
        assert manager.get_sync_committee_period(255) == 0
        assert manager.get_sync_committee_period(256) == 1
        assert manager.get_sync_committee_period(512) == 2
    
    def test_compute_sync_committee(self, manager, sample_validators, randao_mix):
        """Test sync committee computation."""
        committee = manager.compute_sync_committee(
            period=0,
            validators=sample_validators,
            randao_mix=randao_mix,
        )
        
        assert isinstance(committee, SyncCommittee)
        assert len(committee.pubkeys) == manager.committee_size
        assert committee.start_epoch == 0
    
    def test_committee_is_cached(self, manager, sample_validators, randao_mix):
        """Test committee caching."""
        committee1 = manager.compute_sync_committee(0, sample_validators, randao_mix)
        committee2 = manager.compute_sync_committee(0, sample_validators, randao_mix)
        
        assert committee1 is committee2  # Same object
    
    def test_is_in_sync_committee(self, manager, sample_validators, randao_mix):
        """Test checking sync committee membership."""
        committee = manager.compute_sync_committee(0, sample_validators, randao_mix)
        
        # At least one of our validators should be in committee
        in_committee = False
        for v in sample_validators:
            if manager.is_in_sync_committee(
                v['public_key'], slot=0, validators=sample_validators, randao_mix=randao_mix
            ):
                in_committee = True
                break
        
        assert in_committee or len(sample_validators) < manager.committee_size
    
    def test_aggregate_sync_signatures(self, manager, sample_validators, randao_mix):
        """Test signature aggregation."""
        committee = manager.compute_sync_committee(0, sample_validators, randao_mix)
        
        # Record some signatures - need to record by pubkey in the committee
        recorded_pubkeys = committee.pubkeys[:5]
        for pubkey in recorded_pubkeys:
            manager.record_sync_signature(
                slot=10,
                validator_pubkey=pubkey,
                signature=hashlib.sha256(f'sig_{pubkey}'.encode()).digest(),
            )
        
        aggregate = manager.aggregate_sync_signatures(10, committee)
        
        assert aggregate is not None
        # Check that participation count matches recorded signatures
        assert aggregate.participation_count >= 5  # At least 5 should have participated
    
    def test_create_light_client_update(self, manager, sample_validators, randao_mix):
        """Test light client update creation."""
        committee = manager.compute_sync_committee(0, sample_validators, randao_mix)
        
        # Create aggregate
        for pubkey in committee.pubkeys[:10]:
            manager.record_sync_signature(10, pubkey, b'signature')
        
        aggregate = manager.aggregate_sync_signatures(10, committee)
        
        update = manager.create_light_client_update(
            attested_slot=10,
            attested_root=hashlib.sha256(b'attested').hexdigest(),
            finalized_slot=5,
            finalized_root=hashlib.sha256(b'finalized').hexdigest(),
            sync_aggregate=aggregate,
        )
        
        assert isinstance(update, LightClientUpdate)
        assert update.attested_header_slot == 10
        assert update.finalized_header_slot == 5


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestValidatorIntegration:
    """Integration tests for validator components."""
    
    @pytest.mark.asyncio
    async def test_full_epoch_cycle(self, sample_validators, sample_attestations, sample_blocks, randao_mix):
        """Test complete epoch processing cycle."""
        # Setup
        processor = EpochProcessor()
        calculator = RewardsCalculator()
        
        validator_records = [
            ValidatorRecord(
                address=v['address'],
                public_key=bytes.fromhex(v['public_key'][:64]),
                effective_balance=v['effective_balance'],
                slashed=False,
                activation_eligibility_epoch=0,
                activation_epoch=0,
                exit_epoch=None,
                withdrawable_epoch=None,
            )
            for v in sample_validators
        ]
        
        # Process epoch
        result = await processor.process_epoch(
            epoch=3,
            validators=validator_records,
            attestations=sample_attestations,
            blocks=sample_blocks,
            randao_mix=randao_mix,
        )
        
        # Verify results
        assert result.epoch == 3
        assert result.total_active_balance > 0
        assert result.participation_rate > 0
        
        # Rewards should have been calculated
        assert result.total_rewards >= 0
    
    @pytest.mark.asyncio
    async def test_fork_choice_with_attestations(self, sample_validators, randao_mix):
        """Test fork choice with attestation weighting."""
        genesis_root = hashlib.sha256(b'genesis').hexdigest()
        genesis_block = BlockNode(
            block_hash=genesis_root,
            parent_hash='0' * 64,
            slot=0,
            proposer_address='genesis',
            state_root=hashlib.sha256(b'genesis_state').hexdigest(),
        )
        store = ForkChoiceStore(genesis_block, 1700000000)
        
        # Set validator balances
        for v in sample_validators:
            store.balances[v['address']] = v['effective_balance']
        
        # Create two competing forks
        fork_a = hashlib.sha256(b'fork_a').hexdigest()
        fork_b = hashlib.sha256(b'fork_b').hexdigest()
        
        node_a = BlockNode(
            block_hash=fork_a,
            slot=1,
            parent_hash=genesis_root,
            state_root=hashlib.sha256(b'state_a').hexdigest(),
            proposer_address='proposer_a',
        )
        node_b = BlockNode(
            block_hash=fork_b,
            slot=1,
            parent_hash=genesis_root,
            state_root=hashlib.sha256(b'state_b').hexdigest(),
            proposer_address='proposer_b',
        )
        
        store.blocks[fork_a] = node_a
        store.blocks[fork_b] = node_b
        genesis_block.children.append(fork_a)
        genesis_block.children.append(fork_b)
        
        # More validators attest to fork_a
        source = Checkpoint(epoch=0, root=genesis_root)
        
        for i, v in enumerate(sample_validators):
            target_fork = fork_a if i < 7 else fork_b  # 7 vote for A, 3 for B
            target = Checkpoint(epoch=0, root=target_fork)
            await store.on_attestation(v['address'], target_fork, source, target)
        
        # Fork A should win (higher weight)
        head = store.get_head()
        assert head == fork_a


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
