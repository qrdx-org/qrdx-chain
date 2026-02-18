# QRDX System Wallets Implementation

## Overview

This document describes the complete implementation of system wallets for the QRDX blockchain. System wallets are special off-curve addresses that provide decentralized treasury and system functionality with quantum-resistant security.

## Key Features

### 1. **Off-Curve Addresses**
- System wallet addresses cannot be generated from any private key
- Addresses are deterministic: `0x0000000000000000000000000000000000000001` through `0x000000000000000000000000000000000000000a`
- Not derivable from secp256k1 or Dilithium curves

### 2. **Quantum-Resistant Control**
- All system wallets are controlled by a single Post-Quantum (Dilithium) wallet
- Controller wallet is defined in genesis and cannot be changed
- Provides quantum-resistant security for treasury operations

### 3. **Pre-Funded in Genesis**
- System wallets are automatically created and funded during genesis
- Total allocation: 75M QRDX across 10 wallets
- Balances are immutably recorded in the genesis block

### 4. **Decentralized Governance**
- System wallets support various ecosystem functions
- Controller wallet can be a multisig or governance contract
- Transparent on-chain treasury management

## System Wallet List

| Address | Name | Balance | Category | Purpose |
|---------|------|---------|----------|---------|
| `0x...0001` | Garbage Collector | 0 QRDX | System | Burns unclaimed tokens (burner wallet) |
| `0x...0002` | Community Grants | 5M QRDX | Treasury | Community project funding |
| `0x...0003` | Developer Fund | 10M QRDX | Treasury | Core development funding |
| `0x...0004` | Ecosystem Fund | 8M QRDX | Treasury | Strategic investments |
| `0x...0005` | Staking Rewards | 15M QRDX | System | Validator/delegator rewards |
| `0x...0006` | Marketing | 3M QRDX | Treasury | Marketing and partnerships |
| `0x...0007` | Liquidity Reserve | 7M QRDX | DeFi | DEX liquidity provision |
| `0x...0008` | Treasury Multisig | 20M QRDX | Treasury | Main protocol treasury |
| `0x...0009` | Bug Bounty | 1M QRDX | Security | Security researcher rewards |
| `0x...000a` | Airdrop | 6M QRDX | Distribution | Community airdrops |

**Total: 75,000,000 QRDX**

## Architecture

### Core Components

#### 1. `qrdx/crypto/system_wallets.py`
Main implementation module containing:
- `SystemWallet` - Data class for wallet configuration
- `SystemWalletManager` - Manages wallet lifecycle and validation
- `initialize_system_wallets()` - Creates wallet manager with controller
- `create_default_system_wallets()` - Factory for default 10 wallets

#### 2. `qrdx/crypto/address.py`
Address validation extensions:
- `is_system_address()` - Check if address is system-owned
- `validate_system_address()` - Validate system address format
- `is_reserved_address()` - Check reserved address ranges

#### 3. `qrdx/validator/genesis.py`
Genesis integration:
- `GenesisConfig.system_wallet_controller` - Controller PQ address
- `GenesisConfig.enable_system_wallets` - Enable/disable system wallets
- `GenesisState.system_wallets` - System wallet state in genesis
- `GenesisCreator._init_system_wallets()` - Initialize system wallets

#### 4. `qrdx/validator/genesis_init.py`
Database initialization:
- `_init_system_wallets()` - Create system wallet outputs in genesis
- Support for burner wallets (no spendable output)
- System wallet metadata storage

#### 5. `qrdx/transactions/validation.py`
Transaction validation:
- `TransactionValidator` - Validates all transactions
- `validate_transaction()` - Global validation function
- Controller signature verification
- Burner wallet protection

#### 6. `qrdx/constants.py`
Configuration constants:
- `SYSTEM_WALLET_ADDRESSES` - Wallet address mapping
- `SYSTEM_WALLET_GENESIS_BALANCES` - Initial balances
- `SYSTEM_WALLET_METADATA` - Wallet descriptions

## Usage

### Creating Genesis with System Wallets

```python
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.validator.genesis import GenesisConfig, GenesisCreator
from decimal import Decimal

# 1. Generate PQ controller wallet
controller_key = PQPrivateKey.generate()
controller_address = controller_key.public_key().to_address()

# 2. Create genesis configuration
config = GenesisConfig(
    chain_id=1,
    network_name="qrdx-mainnet",
    initial_supply=Decimal("100000000"),
    system_wallet_controller=controller_address,
    enable_system_wallets=True,
)

# 3. Create genesis
creator = GenesisCreator(config)
state, block = creator.create_genesis()

# 4. System wallets are now in genesis!
print(f"System wallets created: {len(state.system_wallets)}")
print(f"Controller: {state.system_wallet_controller}")
```

### Spending from System Wallets

```python
from qrdx.transactions.contract_transaction import ContractTransaction
from decimal import Decimal

# Only the controller wallet can spend from system wallets
dev_fund_addr = "0x0000000000000000000000000000000000000003"
recipient_addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1"

# Create transaction
tx = ContractTransaction(
    nonce=1,
    sender=dev_fund_addr,  # System wallet
    to=recipient_addr,
    value=Decimal("1000"),  # 1000 QRDX
    gas_limit=21000,
    gas_price=Decimal("0.00001"),
    data=b"",
)

# Sign with controller wallet (MUST be controller)
tx.sign(controller_key.to_bytes(), signature_type='dilithium')

# This will pass validation
is_valid = tx.verify_signature()  # True
```

### Validation

```python
from qrdx.transactions.validation import validate_transaction

# Transaction from system wallet by controller - PASS
is_valid, error = validate_transaction(tx)
assert is_valid

# Transaction from system wallet by other wallet - FAIL
unauthorized_tx = create_tx_from(dev_fund_addr, other_key)
is_valid, error = validate_transaction(unauthorized_tx)
assert not is_valid  # "System wallet can only be spent by controller"
```

## Security Features

### 1. Off-Curve Addresses
- **No Private Key**: System wallet addresses have no corresponding private key
- **Cannot Be Brute Forced**: Not derivable from any key generation algorithm
- **Deterministic**: Addresses are fixed and known in advance

### 2. Controller Authorization
- **Single Controller**: Only designated PQ wallet can spend from system wallets
- **Signature Verification**: Every transaction checked against controller public key
- **Quantum-Resistant**: Controller uses Dilithium (ML-DSA-65) signatures

### 3. Burner Wallet Protection
- **One-Way Only**: Burner wallets can receive but never spend
- **Permanent Burn**: Tokens sent to burner are permanently removed from circulation
- **Validation Enforced**: Blockchain rejects any spend from burner wallet

### 4. Genesis Immutability
- **Fixed at Genesis**: System wallets created in genesis block
- **Cannot Add/Remove**: Wallet set is immutable after genesis
- **Transparent**: All balances visible in genesis state

## Database Schema

```sql
CREATE TABLE system_wallets (
    address VARCHAR(66) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    wallet_type VARCHAR(50) NOT NULL,
    controller_address VARCHAR(128) NOT NULL,
    is_burner BOOLEAN NOT NULL DEFAULT FALSE,
    category VARCHAR(50) NOT NULL,
    genesis_balance NUMERIC(24, 6) NOT NULL DEFAULT 0,
    created_at TIMESTAMP(0) NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP(0) NOT NULL DEFAULT NOW()
);

CREATE TABLE chain_metadata (
    key VARCHAR(255) PRIMARY KEY,
    value JSONB NOT NULL,
    created_at TIMESTAMP(0) NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP(0) NOT NULL DEFAULT NOW()
);
```

## Testing

Run the comprehensive test suite:

```bash
python tests/test_system_wallets.py
```

Tests cover:
1. ✓ Address generation and validation
2. ✓ System wallet creation
3. ✓ PQ controller wallet generation
4. ✓ System wallet manager functionality
5. ✓ Genesis creation with system wallets
6. ✓ Transaction validation (authorized/unauthorized)
7. ✓ Burner wallet protection

## Integration Example

### Complete Genesis Setup

```python
#!/usr/bin/env python3
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.validator.genesis import GenesisConfig, GenesisCreator
from qrdx.transactions.validation import initialize_transaction_validator
from decimal import Decimal

# Step 1: Generate controller wallet
controller_key = PQPrivateKey.generate()
controller_address = controller_key.public_key().to_address()

print(f"Controller Address: {controller_address}")
# Save controller_key securely!

# Step 2: Create genesis
config = GenesisConfig(
    chain_id=1,
    network_name="qrdx-mainnet",
    initial_supply=Decimal("100000000"),
    system_wallet_controller=controller_address,
    enable_system_wallets=True,
)

creator = GenesisCreator(config)

# Add initial validators (optional)
creator.add_validator(
    address="0xValidator1Address...",
    public_key="dilithium_pubkey_hex",
    stake=Decimal("100000"),
)

# Create genesis
state, block = creator.create_genesis()

# Step 3: Export genesis
creator.export_genesis(state, block, "genesis.json")

# Step 4: Initialize transaction validator
manager = creator.get_system_wallet_manager()
initialize_transaction_validator(manager)

print("Genesis created with system wallets!")
print(f"Total system allocation: {state.total_system_wallets} QRDX")
```

## Future Enhancements

### Potential Extensions

1. **Governance Integration**
   - Controller could be a governance contract
   - On-chain voting for system wallet spending
   - Multi-signature controller support

2. **Automated Distributions**
   - Smart contract automation for staking rewards
   - Scheduled airdrop distributions
   - Vesting schedules for developer fund

3. **Transparency Tools**
   - Block explorer integration
   - Real-time balance tracking
   - Spending history and analytics

4. **Additional Wallets**
   - Reserved addresses 0x...000b through 0x...00ff
   - Network expansion funds
   - Emergency reserves

## Constants Reference

### Address Range
- **System Wallets**: `0x0000...0001` - `0x0000...00FF` (1-255)
- **Precompiles**: `0x0000...0100` - `0x0000...01FF` (256-511)
- **QPL Programs**: `0x0000...0200` - `0x0000...02FF` (512-767)
- **Reserved**: `0x0000...0300` - `0x0000...0FFF` (768-4095)

### Configuration
```python
SYSTEM_WALLET_MIN = 0x0000000000000000000000000000000000000001
SYSTEM_WALLET_MAX = 0x00000000000000000000000000000000000000FF
TOTAL_SYSTEM_WALLET_ALLOCATION = Decimal("75000000")  # 75M QRDX
```

## Conclusion

The QRDX system wallet implementation provides:
- **Secure**: Quantum-resistant control via Dilithium signatures
- **Decentralized**: Transparent on-chain treasury management
- **Immutable**: Fixed at genesis, cannot be tampered with
- **Flexible**: Supports multiple use cases (grants, staking, airdrops, etc.)

This implementation ensures that QRDX has a robust, secure foundation for ecosystem development and community governance.
