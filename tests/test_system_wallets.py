#!/usr/bin/env python3
"""
System Wallet Test and Demonstration Script

This script demonstrates the complete system wallet implementation:
1. Creating a PQ controller wallet
2. Initializing system wallets
3. Creating a genesis block with system wallets
4. Validating system wallet transactions
5. Testing security constraints

Run this script to verify the system wallet implementation.
"""

import sys
import asyncio
import pytest
from decimal import Decimal
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.crypto.system_wallets import (
    initialize_system_wallets,
    create_default_system_wallets,
    is_system_wallet_address,
    is_address_off_curve,
    generate_system_wallet_address,
)
from qrdx.crypto.address import is_pq_address, is_system_address
from qrdx.validator.genesis import GenesisConfig, GenesisCreator
from qrdx.transactions.validation import TransactionValidator
from qrdx.logger import get_logger

logger = get_logger(__name__)


def test_system_wallet_addresses():
    """Test system wallet address generation and validation."""
    print("\n" + "="*80)
    print("TEST 1: System Wallet Address Validation")
    print("="*80)
    
    # Test address generation
    for i in range(1, 11):
        addr = generate_system_wallet_address(i)
        print(f"Generated system wallet {i:2d}: {addr}")
        
        # Validate address
        assert is_system_wallet_address(addr), f"Failed: {addr} should be system wallet"
        assert is_address_off_curve(addr), f"Failed: {addr} should be off-curve"
        assert is_system_address(addr), f"Failed: {addr} should be system address"
    
    # Test invalid addresses
    regular_addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1"
    assert not is_system_wallet_address(regular_addr), "Regular address should not be system wallet"
    
    print("\n✓ All address validation tests passed!")


def test_system_wallet_creation():
    """Test creating default system wallets."""
    print("\n" + "="*80)
    print("TEST 2: System Wallet Creation")
    print("="*80)
    
    wallets = create_default_system_wallets()
    
    print(f"\nCreated {len(wallets)} system wallets:")
    total_balance = Decimal("0")
    
    for wallet in wallets:
        print(f"\n  {wallet.name}")
        print(f"    Address:     {wallet.address}")
        print(f"    Balance:     {wallet.genesis_balance:,} QRDX")
        print(f"    Category:    {wallet.category}")
        print(f"    Type:        {wallet.wallet_type.value}")
        print(f"    Is Burner:   {wallet.is_burner}")
        total_balance += wallet.genesis_balance
    
    print(f"\n  Total allocation: {total_balance:,} QRDX")
    assert total_balance == Decimal("75000000"), "Total should be 75M QRDX"
    
    print("\n✓ System wallet creation tests passed!")


def test_pq_controller_wallet():
    """Test creating a PQ controller wallet."""
    print("\n" + "="*80)
    print("TEST 3: PQ Controller Wallet")
    print("="*80)
    
    # Generate a PQ private key for the controller
    controller_key = PQPrivateKey.generate()
    controller_pubkey = controller_key.public_key  # Property, not method
    controller_address = controller_pubkey.to_address()
    
    print(f"\nController Wallet:")
    print(f"  Address:      {controller_address}")
    print(f"  Type:         Post-Quantum (Dilithium)")
    print(f"  Is PQ:        {is_pq_address(controller_address)}")
    print(f"  Fingerprint:  {controller_pubkey.fingerprint()}")
    
    assert is_pq_address(controller_address), "Controller must be PQ address"
    
    print("\n✓ PQ controller wallet tests passed!")
    
    return controller_key, controller_address


@pytest.fixture
def controller_key():
    """Generate a PQ controller key for tests."""
    return PQPrivateKey.generate()


@pytest.fixture
def controller_address(controller_key):
    """Derive controller address from PQ key."""
    return controller_key.public_key.to_address()


@pytest.fixture
def manager(controller_address):
    """Initialize system wallet manager with controller."""
    return initialize_system_wallets(controller_address)


def test_system_wallet_manager(controller_address):
    """Test system wallet manager."""
    print("\n" + "="*80)
    print("TEST 4: System Wallet Manager")
    print("="*80)
    
    # Initialize manager
    manager = initialize_system_wallets(controller_address)
    
    print(f"\nSystem Wallet Manager initialized:")
    print(f"  Controller:   {manager.controller_address}")
    print(f"  Total Wallets: {len(manager.get_all_wallets())}")
    print(f"  Total Balance: {manager.get_total_genesis_balance():,} QRDX")
    
    # Test wallet lookup
    test_addr = "0x0000000000000000000000000000000000000003"  # Developer Fund
    wallet = manager.get_system_wallet(test_addr)
    assert wallet is not None, "Developer Fund wallet should exist"
    print(f"\n  Found wallet: {wallet.name}")
    
    # Test authorization
    assert manager.can_spend_from(test_addr, controller_address), \
        "Controller should be able to spend from system wallet"
    
    other_addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1"
    assert not manager.can_spend_from(test_addr, other_addr), \
        "Other addresses should NOT be able to spend from system wallet"
    
    # Test burner wallet
    burner_addr = "0x0000000000000000000000000000000000000001"
    assert manager.is_burner_wallet(burner_addr), "Garbage collector should be burner"
    
    print("\n✓ System wallet manager tests passed!")
    
    return manager


def test_genesis_creation(controller_address):
    """Test genesis creation with system wallets."""
    print("\n" + "="*80)
    print("TEST 5: Genesis Creation with System Wallets")
    print("="*80)
    
    # Create genesis config
    config = GenesisConfig(
        chain_id=9999,
        network_name="qrdx-system-wallet-test",
        min_genesis_validators=0,
        initial_supply=Decimal("100000000"),
        system_wallet_controller=controller_address,
        enable_system_wallets=True,
    )
    
    # Create genesis
    creator = GenesisCreator(config)
    
    # Add a test account
    creator.add_account(
        "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
        Decimal("1000000"),
        "test-account"
    )
    
    # Generate genesis
    state, block = creator.create_genesis()
    
    print(f"\nGenesis Created:")
    print(f"  Block Hash:           {block.block_hash}")
    print(f"  State Root:           {state.state_root}")
    print(f"  System Wallets:       {len(state.system_wallets)}")
    print(f"  System Controller:    {state.system_wallet_controller}")
    print(f"  Total System Balance: {state.total_system_wallets} QRDX")
    
    # Verify system wallets in state
    assert len(state.system_wallets) == 10, "Should have 10 system wallets"
    assert state.system_wallet_controller == controller_address, "Controller mismatch"
    
    # Check a specific wallet
    dev_fund = state.system_wallets.get("0x0000000000000000000000000000000000000003")
    assert dev_fund is not None, "Developer Fund should exist in genesis"
    print(f"\n  Developer Fund:")
    print(f"    Name:     {dev_fund['name']}")
    print(f"    Balance:  {dev_fund['balance']} QRDX")
    print(f"    Category: {dev_fund['category']}")
    
    print("\n✓ Genesis creation tests passed!")
    
    return state, block


def test_transaction_validation(controller_key, controller_address, manager):
    """Test transaction validation with system wallets."""
    print("\n" + "="*80)
    print("TEST 6: Transaction Validation")
    print("="*80)
    
    # Create a validator with the system wallet manager
    validator = TransactionValidator(manager)
    
    # Mock transaction class
    class MockTransaction:
        def __init__(self, sender, signer=None):
            self.sender = sender
            self.public_key = None
            self.signature_type = 'dilithium'
            
            if signer:
                # Set public key to match signer
                if signer == controller_address:
                    self.public_key = controller_key.public_key.to_bytes()  # Property, not method
    
    # Test 1: Controller spending from system wallet - SHOULD PASS
    print("\n  Test 1: Controller spending from Developer Fund")
    dev_fund_addr = "0x0000000000000000000000000000000000000003"
    tx1 = MockTransaction(dev_fund_addr, controller_address)
    tx1.public_key = controller_key.public_key.to_bytes()  # Property, not method
    
    is_valid, error = validator.validate_transaction(tx1)
    print(f"    Result: {'✓ PASS' if is_valid else '✗ FAIL'}")
    print(f"    Message: {error}")
    assert is_valid, "Controller should be able to spend from system wallet"
    
    # Test 2: Other address spending from system wallet - SHOULD FAIL
    print("\n  Test 2: Unauthorized address spending from Developer Fund")
    tx2 = MockTransaction(dev_fund_addr, "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1")
    
    is_valid, error = validator.validate_transaction(tx2)
    print(f"    Result: {'✗ FAIL (expected)' if not is_valid else '✓ UNEXPECTED PASS'}")
    print(f"    Message: {error}")
    assert not is_valid, "Other addresses should NOT be able to spend from system wallet"
    
    # Test 3: Spending from burner wallet - SHOULD FAIL
    print("\n  Test 3: Spending from Garbage Collector (burner wallet)")
    burner_addr = "0x0000000000000000000000000000000000000001"
    tx3 = MockTransaction(burner_addr, controller_address)
    tx3.public_key = controller_key.public_key.to_bytes()  # Property, not method
    
    is_valid, error = validator.validate_transaction(tx3)
    print(f"    Result: {'✗ FAIL (expected)' if not is_valid else '✓ UNEXPECTED PASS'}")
    print(f"    Message: {error}")
    assert not is_valid, "Cannot spend from burner wallet"
    
    # Test 4: Regular transaction - SHOULD PASS
    print("\n  Test 4: Regular non-system wallet transaction")
    tx4 = MockTransaction("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1")
    
    is_valid, error = validator.validate_transaction(tx4)
    print(f"    Result: {'✓ PASS' if is_valid else '✗ FAIL'}")
    print(f"    Message: {error}")
    assert is_valid, "Regular transactions should pass"
    
    print("\n✓ All transaction validation tests passed!")


def main():
    """Run all tests."""
    print("\n" + "="*80)
    print("QRDX SYSTEM WALLET TEST SUITE")
    print("="*80)
    
    try:
        # Run tests
        test_system_wallet_addresses()
        test_system_wallet_creation()
        controller_key, controller_address = test_pq_controller_wallet()
        manager = test_system_wallet_manager(controller_address)
        state, block = test_genesis_creation(controller_address)
        test_transaction_validation(controller_key, controller_address, manager)
        
        # Summary
        print("\n" + "="*80)
        print("ALL TESTS PASSED!")
        print("="*80)
        print("\nSystem Wallet Implementation Summary:")
        print(f"  ✓ 10 system wallets created (75M QRDX total)")
        print(f"  ✓ Off-curve addresses (no private keys)")
        print(f"  ✓ Controlled by single PQ wallet: {controller_address[:20]}...")
        print(f"  ✓ Integrated into genesis creation")
        print(f"  ✓ Transaction validation enforced")
        print(f"  ✓ Burner wallet protection active")
        print("\nThe system is secure and ready for deployment!")
        
        return 0
        
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
