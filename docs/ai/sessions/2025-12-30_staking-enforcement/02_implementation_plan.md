# Implementation Plan: Staking Enforcement Fix

## Overview
Fix the critical security flaw where validators can produce blocks without the required 100,000 QRDX stake.

## Design Decision: Genesis-Based Validator Funding

For testnet/development, we'll use **genesis allocation** to fund validators:

### Genesis Schema Extension

```json
{
  "version": "1",
  "params": { /* ... existing ... */ },
  "genesis": { /* ... existing ... */ },
  "accounts": {
    "0x0000000000000000000000000000000000000000": {
      "balance": "0x152d02c7e14af6800000",  // 100,000 QRDX (hex)
      "code": "0x",
      "nonce": "0x0",
      "storage": {}
    },
    /* ... one account per validator ... */
  },
  "validators": [
    {
      "index": 0,
      "address": "0x0000000000000000000000000000000000000000",
      "public_key": "0x<1952-byte-dilithium-pubkey>",
      "stake": "100000000000000000000000",  // 100k QRDX in wei
      "status": "ACTIVE",
      "activation_epoch": 0
    },
    /* ... more validators ... */
  ]
}
```

### Rationale

**Why Genesis Allocation?**
- ✅ Simple for testnet deployment
- ✅ No dependency on deployed contracts
- ✅ Validators funded from chain start
- ✅ Matches Ethereum genesis patterns

**Why Not StakeTracker.sol?**
- For **production**, validators WILL use StakeTracker
- Genesis provides bootstrap for testnet only
- Future: Add dynamic registration via contract

## Implementation Tasks

### Task 1: Update Genesis Generation Scripts
**Files**: 
- `scripts/start_multi_node_testnet.sh`
- `scripts/start_local_testnet.sh`

**Changes**:
1. Calculate validator addresses (0x0000...0000 to 0x0000...{N-1})
2. Add each validator account to genesis.accounts with MIN_STAKE balance
3. Add validators array with public keys from keystores
4. Helper to convert stake to hex (100k QRDX = 0x152d02c7e14af6800000)

**Pseudocode**:
```bash
# After generating keystores
for i in range(NUM_VALIDATORS):
    address = 0x$(printf "%040x" $i)
    pubkey = $(extract from keystore-$i.json)
    
    # Add to accounts
    accounts["$address"] = {
        "balance": "0x152d02c7e14af6800000"  # 100k QRDX
    }
    
    # Add to validators array
    validators.append({
        "index": $i,
        "address": "$address",
        "public_key": "$pubkey",
        "stake": "100000000000000000000000"
    })
```

### Task 2: Load Validators from Genesis
**Files**:
- `trinity/components/builtin/qrpos_validator/component.py`
- `trinity/components/builtin/new_block/component.py`

**Current Code (line 756)**:
```python
validator = Validator(
    index=i,
    public_key=validator_pubkey.to_bytes(),
    address=validator_address,
    stake=MIN_STAKE,  # ❌ HARDCODED
    status=ValidatorStatus.ACTIVE,
    activation_epoch=0,
    exit_epoch=None,
    slashed=False,
)
```

**New Code**:
```python
# Load genesis configuration
genesis_file = os.environ.get('GENESIS_FILE', '/tmp/qrdx-multi-node-genesis.json')
with open(genesis_file) as f:
    genesis_config = json.load(f)

# Extract validators array
genesis_validators_config = genesis_config.get('validators', [])
if not genesis_validators_config:
    raise ValueError("No validators in genesis configuration!")

# Create validators from genesis
for validator_config in genesis_validators_config:
    validator_index = validator_config['index']
    validator_address = to_canonical_address(validator_config['address'])
    stake_wei = int(validator_config['stake'])
    
    # Verify stake >= MIN_STAKE
    if stake_wei < MIN_STAKE:
        raise ValueError(
            f"Validator {validator_index} has insufficient stake: "
            f"{stake_wei}, minimum required: {MIN_STAKE}"
        )
    
    # Load public key from keystore (match by index)
    pubkey = load_pubkey_from_keystore(keystore_dir, validator_index)
    
    validator = Validator(
        index=validator_index,
        public_key=pubkey,
        address=validator_address,
        stake=stake_wei,  # ✅ FROM GENESIS
        status=ValidatorStatus.ACTIVE,
        activation_epoch=0,
        exit_epoch=None,
        slashed=False,
    )
    genesis_validators.append(validator)
```

### Task 3: Enhance ValidatorSet Validation
**File**: `py-evm/eth/consensus/qrpos.py`

**Add to `ValidatorSet.__init__`**:
```python
def __init__(self, genesis_validators: Optional[List[Validator]] = None):
    self.validators: List[Validator] = []
    self.validator_by_address: Dict[Address, Validator] = {}
    self.validator_by_pubkey: Dict[bytes, Validator] = {}
    
    if genesis_validators:
        if len(genesis_validators) < 1 or len(genesis_validators) > VALIDATOR_COUNT:
            raise ValueError(
                f"Genesis validators must be 1-{VALIDATOR_COUNT}, "
                f"got {len(genesis_validators)}"
            )
        
        # Verify all validators have minimum stake
        for validator in genesis_validators:
            if validator.stake < MIN_STAKE:
                raise ValueError(
                    f"Validator {validator.index} has insufficient stake: "
                    f"{validator.stake / 10**18:,.0f} QRDX, "
                    f"minimum: {MIN_STAKE / 10**18:,.0f} QRDX"
                )
            self.add_validator(validator)
```

### Task 4: Add Genesis Validation Helper
**File**: `py-evm/eth/consensus/qrpos.py`

```python
def load_validators_from_genesis(
    genesis_config: Dict[str, Any],
    keystore_dir: Path
) -> List[Validator]:
    """
    Load validators from genesis configuration.
    
    Args:
        genesis_config: Parsed genesis JSON
        keystore_dir: Directory containing validator keystores
        
    Returns:
        List of Validator objects
        
    Raises:
        ValueError: If genesis is invalid or stakes insufficient
    """
    from eth_utils import to_canonical_address
    import json
    
    validators_config = genesis_config.get('validators', [])
    if not validators_config:
        raise ValueError("No validators in genesis configuration")
    
    validators = []
    for val_config in validators_config:
        index = val_config['index']
        address = to_canonical_address(val_config['address'])
        stake = int(val_config['stake'])
        
        # Verify minimum stake
        if stake < MIN_STAKE:
            raise ValueError(
                f"Validator {index} stake {stake} < minimum {MIN_STAKE}"
            )
        
        # Load public key from keystore
        keystore_file = keystore_dir / f"keystore-{index}.json"
        if not keystore_file.exists():
            raise FileNotFoundError(f"Keystore not found: {keystore_file}")
        
        with open(keystore_file) as f:
            ks = json.load(f)
            pubkey_hex = ks.get('pubkey')
            if not pubkey_hex:
                raise ValueError(f"No pubkey in {keystore_file}")
            pubkey = bytes.fromhex(pubkey_hex)
        
        validator = Validator(
            index=index,
            public_key=pubkey,
            address=address,
            stake=stake,
            status=ValidatorStatus.ACTIVE,
            activation_epoch=0,
            exit_epoch=None,
            slashed=False,
        )
        validators.append(validator)
    
    return validators
```

## Testing Plan

### Unit Tests

**File**: `tests/consensus/test_qrpos_staking.py` (new)

```python
def test_validator_minimum_stake():
    """Test validators must have minimum stake."""
    from eth.consensus.qrpos import Validator, ValidatorStatus, MIN_STAKE
    
    # Should succeed with MIN_STAKE
    validator = Validator(
        index=0,
        public_key=b'\x00' * 1952,
        address=b'\x00' * 20,
        stake=MIN_STAKE,
        status=ValidatorStatus.ACTIVE,
        activation_epoch=0,
        exit_epoch=None,
        slashed=False,
    )
    assert validator.stake == MIN_STAKE
    
    # Should fail with insufficient stake
    with pytest.raises(ValueError, match="Stake must be >= "):
        Validator(
            index=0,
            public_key=b'\x00' * 1952,
            address=b'\x00' * 20,
            stake=MIN_STAKE - 1,
            status=ValidatorStatus.ACTIVE,
            activation_epoch=0,
            exit_epoch=None,
            slashed=False,
        )

def test_validator_set_rejects_insufficient_stake():
    """Test ValidatorSet rejects validators with insufficient stake."""
    from eth.consensus.qrpos import Validator, ValidatorSet, ValidatorStatus, MIN_STAKE
    
    # Create validator with insufficient stake
    # (bypassing Validator.__post_init__ for testing)
    invalid_validator = object.__new__(Validator)
    invalid_validator.index = 0
    invalid_validator.stake = MIN_STAKE // 2
    invalid_validator.public_key = b'\x00' * 1952
    invalid_validator.address = b'\x00' * 20
    
    with pytest.raises(ValueError, match="insufficient stake"):
        ValidatorSet(genesis_validators=[invalid_validator])
```

### Integration Tests

**Test Scenario 1**: Valid Genesis
```bash
# Setup
NUM_VALIDATORS=3
./scripts/start_multi_node_testnet.sh 3

# Verify
- 3 validators start successfully
- Blocks are produced
- Each validator has 100k QRDX balance
- Validators array in genesis matches running validators
```

**Test Scenario 2**: Insufficient Stake (Manual)
```bash
# Modify genesis to give validator 0 only 50k QRDX
sed -i 's/0x152d02c7e14af6800000/0xa968163f0a57b400000/g' /tmp/qrdx-multi-node-genesis.json

# Try to start validator
trinity --enable-qrpos-validator ...

# Expected output:
ERROR: Validator 0 has insufficient stake: 50000 QRDX, minimum: 100000 QRDX
```

**Test Scenario 3**: Missing Validators Array
```bash
# Create genesis without validators array
cat > /tmp/test-genesis.json << EOF
{
  "params": {...},
  "genesis": {...},
  "accounts": {...}
  // NO validators array
}
EOF

# Try to start
# Expected error:
ValueError: No validators in genesis configuration
```

## Stake Calculation Constants

```python
# Stake amounts in wei (18 decimals)
MIN_STAKE = 100_000 * 10**18  # 100,000 QRDX
MIN_STAKE_HEX = "0x152d02c7e14af6800000"  # Hex representation

# For 3 validators: 300,000 QRDX total
# For 150 validators: 15,000,000 QRDX total
```

## Backward Compatibility

**Breaking Change**: Old genesis files without `validators` array will NOT work

**Migration Path**:
1. Regenerate genesis with validators array
2. Update all testnet scripts
3. Document in CHANGELOG
4. Add validation error with helpful message

## Production Deployment Notes

For production, validators will:
1. Start with funded genesis accounts (bootstrapping)
2. Call `StakeTracker.registerValidator()` to register on-chain
3. Consensus layer reads from StakeTracker for dynamic updates
4. Genesis provides initial set only

**Future Enhancement**: Read validator set from StakeTracker contract state
