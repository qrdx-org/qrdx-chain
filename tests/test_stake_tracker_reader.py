"""
Tests for StakeTrackerReader - On-Chain Validator Loading

This test suite validates the StakeTrackerReader module that provides
on-chain validator verification as an alternative to genesis-based loading.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from eth_utils import to_checksum_address

# Import the module under test
from eth.consensus.stake_tracker_reader import (
    StakeTrackerReader,
    ValidatorInfo,
    ValidatorStatus,
    create_stake_tracker_reader,
)


class TestValidatorInfo:
    """Test ValidatorInfo data class"""
    
    def test_validator_info_creation(self):
        """Test creating a ValidatorInfo instance"""
        validator = ValidatorInfo(
            validator_index=0,
            staker_address=to_checksum_address("0x" + "00" * 20),
            dilithium_public_key=b"0" * 1952,
            stake=100_000 * 10**18,
            delegated_stake=50_000 * 10**18,
            status=ValidatorStatus.ACTIVE,
            activation_epoch=0,
            exit_epoch=0,
            slashed=False,
            rewards_earned=1000 * 10**18,
            commission_rate=500,  # 5%
        )
        
        assert validator.validator_index == 0
        assert validator.stake == 100_000 * 10**18
        assert validator.delegated_stake == 50_000 * 10**18
        assert validator.total_stake == 150_000 * 10**18
        assert validator.is_active is True
        assert validator.slashed is False
    
    def test_validator_status_check(self):
        """Test is_active property for different statuses"""
        active_validator = ValidatorInfo(
            validator_index=0,
            staker_address=to_checksum_address("0x" + "00" * 20),
            dilithium_public_key=b"0" * 1952,
            stake=100_000 * 10**18,
            delegated_stake=0,
            status=ValidatorStatus.ACTIVE,
            activation_epoch=0,
            exit_epoch=0,
            slashed=False,
            rewards_earned=0,
            commission_rate=0,
        )
        
        pending_validator = ValidatorInfo(
            validator_index=1,
            staker_address=to_checksum_address("0x" + "01" * 20),
            dilithium_public_key=b"1" * 1952,
            stake=100_000 * 10**18,
            delegated_stake=0,
            status=ValidatorStatus.PENDING,
            activation_epoch=1,
            exit_epoch=0,
            slashed=False,
            rewards_earned=0,
            commission_rate=0,
        )
        
        assert active_validator.is_active is True
        assert pending_validator.is_active is False


class TestStakeTrackerReader:
    """Test StakeTrackerReader contract interface"""
    
    @pytest.fixture
    def mock_web3(self):
        """Mock Web3 instance"""
        web3 = MagicMock()
        web3.is_connected.return_value = True
        web3.eth = MagicMock()
        return web3
    
    @pytest.fixture
    def mock_contract(self):
        """Mock contract instance"""
        contract = MagicMock()
        contract.functions = MagicMock()
        return contract
    
    @pytest.fixture
    def reader(self, mock_web3, mock_contract):
        """Create StakeTrackerReader with mocked dependencies"""
        with patch('eth.consensus.stake_tracker_reader.Web3', return_value=mock_web3):
            with patch('builtins.open', create=True) as mock_open:
                # Mock ABI file reading
                mock_open.return_value.__enter__.return_value.read.return_value = '[]'
                
                reader = StakeTrackerReader(
                    rpc_url="http://localhost:8545",
                    contract_address="0x" + "42" * 20,
                )
                reader.contract = mock_contract
                return reader
    
    def test_initialization(self, reader):
        """Test StakeTrackerReader initialization"""
        assert reader.rpc_url == "http://localhost:8545"
        assert reader.contract_address == to_checksum_address("0x" + "42" * 20)
        assert reader.timeout == 30
        assert reader.retry_attempts == 3
    
    def test_is_connected(self, reader, mock_web3):
        """Test connection check"""
        mock_web3.is_connected.return_value = True
        assert reader.is_connected() is True
        
        mock_web3.is_connected.return_value = False
        assert reader.is_connected() is False
    
    def test_get_min_stake(self, reader, mock_contract):
        """Test getting minimum stake from contract"""
        mock_contract.functions.MIN_STAKE().call.return_value = 100_000 * 10**18
        
        min_stake = reader.get_min_stake()
        assert min_stake == 100_000 * 10**18
        
        # Should cache the value
        min_stake_again = reader.get_min_stake()
        assert min_stake_again == 100_000 * 10**18
        # Should only call contract once (cached)
        assert mock_contract.functions.MIN_STAKE().call.call_count == 1
    
    def test_get_validator_count(self, reader, mock_contract):
        """Test getting validator count"""
        mock_contract.functions.getValidatorCount().call.return_value = 4
        
        count = reader.get_validator_count()
        assert count == 4
    
    def test_get_total_staked(self, reader, mock_contract):
        """Test getting total staked amount"""
        mock_contract.functions.getTotalStaked().call.return_value = 400_000 * 10**18
        
        total = reader.get_total_staked()
        assert total == 400_000 * 10**18
    
    def test_get_current_epoch(self, reader, mock_contract):
        """Test getting current epoch"""
        mock_contract.functions.getCurrentEpoch().call.return_value = 100
        
        epoch = reader.get_current_epoch()
        assert epoch == 100
    
    def test_get_validator(self, reader, mock_contract):
        """Test getting validator by address"""
        validator_address = to_checksum_address("0x" + "01" * 20)
        
        # Mock isValidator check
        mock_contract.functions.isValidator().call.return_value = True
        
        # Mock getValidator response (tuple matching Solidity struct)
        mock_contract.functions.getValidator().call.return_value = (
            0,  # validatorIndex
            validator_address,  # stakerAddress
            b"0" * 1952,  # dilithiumPublicKey
            100_000 * 10**18,  # stake
            0,  # delegatedStake
            1,  # status (ACTIVE)
            0,  # activationEpoch
            0,  # exitEpoch
            False,  # slashed
            0,  # rewardsEarned
            500,  # commissionRate (5%)
        )
        
        validator = reader.get_validator(validator_address)
        
        assert validator is not None
        assert validator.validator_index == 0
        assert validator.staker_address == validator_address
        assert validator.stake == 100_000 * 10**18
        assert validator.status == ValidatorStatus.ACTIVE
        assert validator.slashed is False
    
    def test_get_validator_not_found(self, reader, mock_contract):
        """Test getting non-existent validator"""
        mock_contract.functions.isValidator().call.return_value = False
        
        validator = reader.get_validator("0x" + "99" * 20)
        assert validator is None
    
    def test_verify_validator_stake_success(self, reader, mock_contract):
        """Test verifying validator with sufficient stake"""
        validator_address = to_checksum_address("0x" + "01" * 20)
        
        mock_contract.functions.isValidator().call.return_value = True
        mock_contract.functions.getValidator().call.return_value = (
            0, validator_address, b"0" * 1952,
            100_000 * 10**18,  # stake >= MIN_STAKE
            0, 1, 0, 0, False, 0, 500
        )
        
        is_valid = reader.verify_validator_stake(
            validator_address,
            minimum_stake=100_000 * 10**18
        )
        
        assert is_valid is True
    
    def test_verify_validator_stake_insufficient(self, reader, mock_contract):
        """Test verifying validator with insufficient stake"""
        validator_address = to_checksum_address("0x" + "01" * 20)
        
        mock_contract.functions.isValidator().call.return_value = True
        mock_contract.functions.getValidator().call.return_value = (
            0, validator_address, b"0" * 1952,
            50_000 * 10**18,  # stake < MIN_STAKE
            0, 1, 0, 0, False, 0, 500
        )
        
        is_valid = reader.verify_validator_stake(
            validator_address,
            minimum_stake=100_000 * 10**18
        )
        
        assert is_valid is False
    
    def test_verify_validator_not_active(self, reader, mock_contract):
        """Test verifying validator with non-active status"""
        validator_address = to_checksum_address("0x" + "01" * 20)
        
        mock_contract.functions.isValidator().call.return_value = True
        mock_contract.functions.getValidator().call.return_value = (
            0, validator_address, b"0" * 1952,
            100_000 * 10**18,
            0, 0,  # status = PENDING (not ACTIVE)
            0, 0, False, 0, 500
        )
        
        is_valid = reader.verify_validator_stake(validator_address)
        assert is_valid is False
    
    def test_get_active_validators(self, reader, mock_contract):
        """Test getting all active validators"""
        # Mock getActiveValidatorIndices
        mock_contract.functions.getActiveValidatorIndices().call.return_value = [0, 1, 2]
        
        # Mock getValidatorByIndex for each
        def mock_get_validator_by_index(index):
            mock_call = MagicMock()
            # Generate valid Ethereum address (20 bytes = 40 hex chars)
            address = to_checksum_address('0x' + f'{index:02d}' * 20)
            mock_call.call.return_value = (
                index,
                address,
                bytes([index]) * 1952,
                100_000 * 10**18,
                0, 1, 0, 0, False, 0, 500
            )
            return mock_call
        
        mock_contract.functions.getValidatorByIndex.side_effect = mock_get_validator_by_index
        
        validators = reader.get_active_validators()
        
        assert len(validators) == 3
        assert all(v.is_active for v in validators)
        assert validators[0].validator_index == 0
        assert validators[1].validator_index == 1
        assert validators[2].validator_index == 2


class TestCreateStakeTrackerReader:
    """Test factory function for creating StakeTrackerReader"""
    
    def test_create_with_params(self):
        """Test creating reader with explicit parameters"""
        with patch('eth.consensus.stake_tracker_reader.Web3'):
            with patch('builtins.open', create=True) as mock_open:
                mock_open.return_value.__enter__.return_value.read.return_value = '[]'
                
                reader = create_stake_tracker_reader(
                    rpc_url="http://localhost:8545",
                    contract_address="0x" + "42" * 20
                )
                
                assert reader is not None
                assert reader.contract_address == to_checksum_address("0x" + "42" * 20)
    
    def test_create_missing_config(self):
        """Test creating reader without configuration returns None"""
        with patch.dict('os.environ', {}, clear=True):
            reader = create_stake_tracker_reader()
            assert reader is None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
