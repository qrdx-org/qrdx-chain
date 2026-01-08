# QRDX Proof-of-Stake Implementation Summary

## Overview

QRDX has been converted from Proof-of-Work (PoW) to Quantum-Resistant Proof-of-Stake (QR-PoS). This implementation prioritizes:

1. **Decentralization** - Max 150 validators, stake-weighted selection
2. **Security** - Post-quantum signatures (Dilithium3), slashing for misbehavior
3. **Functionality** - 2-second blocks, single-slot finality, web3 compatibility

## Critical Requirement

**⚠️ VALIDATORS MUST USE POST-QUANTUM (PQ) WALLETS ONLY**

Classical ECDSA wallets are NOT permitted as validators. Only Dilithium3 (ML-DSA-65) signatures are accepted for block proposals and attestations.

## Files Created/Modified

### New Files

| File | Description |
|------|-------------|
| [qrdx/validator/__init__.py](qrdx/validator/__init__.py) | Module exports |
| [qrdx/validator/types.py](qrdx/validator/types.py) | Core types (Validator, ValidatorStatus, exceptions) |
| [qrdx/validator/config.py](qrdx/validator/config.py) | ValidatorConfig, StakingConfig, constants |
| [qrdx/validator/stake.py](qrdx/validator/stake.py) | StakeManager for deposits/withdrawals |
| [qrdx/validator/selection.py](qrdx/validator/selection.py) | ValidatorSelector with RANDAO |
| [qrdx/validator/attestation.py](qrdx/validator/attestation.py) | Attestation, AttestationPool |
| [qrdx/validator/slashing.py](qrdx/validator/slashing.py) | SlashingExecutor, SlashingProtectionDB |
| [qrdx/validator/manager.py](qrdx/validator/manager.py) | Main ValidatorManager class |
| [qrdx/node/validator_integration.py](qrdx/node/validator_integration.py) | Toggleable validator node component |
| [qrdx/rpc/modules/validator.py](qrdx/rpc/modules/validator.py) | Validator RPC endpoints |
| [qrdx/migrations/migrate_to_pos.py](qrdx/migrations/migrate_to_pos.py) | Database migration script |

### Modified Files

| File | Changes |
|------|---------|
| [qrdx/consensus.py](qrdx/consensus.py) | Added Consensus_V2_PoS class with PoS validation |
| [qrdx/manager.py](qrdx/manager.py) | Added create_pos_block, validate_pos_block, commit_pos_block |
| [qrdx/constants.py](qrdx/constants.py) | Added PoS constants (SLOT_DURATION, SLOTS_PER_EPOCH, etc.) |
| [qrdx/schema.sql](qrdx/schema.sql) | Added validators, stakes, attestations, epochs, slashing tables |
| [config.example.toml](config.example.toml) | Added [validator] configuration section |

## Consensus Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| SLOT_DURATION | 2 sec | Time per slot |
| SLOTS_PER_EPOCH | 32 | Slots in an epoch |
| MIN_VALIDATOR_STAKE | 100,000 QRDX | Minimum stake to validate |
| MAX_VALIDATORS | 150 | Maximum active validators |
| ATTESTATION_THRESHOLD | 66.7% | Stake required for finality |
| UNBONDING_PERIOD | 7 days | Time to withdraw stake |

## Slashing Conditions

| Condition | Penalty | Description |
|-----------|---------|-------------|
| Double Sign | 50% | Signing two blocks for same slot |
| Invalid Attestation | 30% | Attestation with invalid data |
| Surround Vote | 50% | Attestation that surrounds another |
| Downtime | 5% | Extended offline period |
| Bridge Fraud | 100% | Fraudulent bridge operations |

## Configuration

Add to `config.toml`:

```toml
[validator]
enabled = true
pq_wallet_path = "./data/validator_wallet.json"
pq_wallet_password = ""  # Or use QRDX_VALIDATOR_PASSWORD env var
graffiti = "My Validator"

[validator.staking]
min_stake = 100000
unbonding_epochs = 5040

[validator.slashing_protection]
enabled = true
db_path = "./data/slashing_protection.db"
```

## RPC Endpoints

| Method | Description |
|--------|-------------|
| `validator_getStatus` | Get local validator status |
| `validator_getValidatorInfo` | Get info for any validator |
| `validator_getValidatorSet` | Get active validator set |
| `validator_getStake` | Get stake information |
| `validator_register` | Register as validator |
| `validator_requestExit` | Request to exit |
| `validator_getDuties` | Get proposal/attestation duties |
| `validator_getAttestations` | Get attestations |
| `validator_getSlashings` | Get slashing events |
| `validator_getChainHead` | Get PoS chain head |
| `validator_getEpochInfo` | Get epoch information |
| `validator_getConsensusParams` | Get consensus parameters |

## Migration

Run the database migration:

```bash
python -m qrdx.migrations.migrate_to_pos \
  --database-url postgresql://qrdx:qrdx@localhost/qrdx
```

Dry run first:
```bash
python -m qrdx.migrations.migrate_to_pos \
  --database-url postgresql://qrdx:qrdx@localhost/qrdx \
  --dry-run
```

## Usage

### Starting a Validator Node

1. Create a PQ wallet:
   ```bash
   qrdx wallet create --type pq --output ./data/validator_wallet.json
   ```

2. Fund the wallet with at least 100,000 QRDX

3. Configure `config.toml` with validator settings

4. Start the node:
   ```bash
   python run_node.py --config config.toml
   ```

5. Register as validator (via RPC or CLI):
   ```bash
   qrdx validator register --stake 100000
   ```

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ValidatorManager                          │
│  - Coordinates all validator operations                      │
│  - Block proposal and attestation lifecycle                  │
│  - Slashing detection and execution                          │
└─────────────────────┬───────────────────────────────────────┘
                      │
    ┌─────────────────┼─────────────────┐
    │                 │                 │
    ▼                 ▼                 ▼
┌────────┐    ┌────────────────┐   ┌────────────────┐
│ Stake  │    │   Validator    │   │  Attestation   │
│Manager │    │   Selector     │   │     Pool       │
└────────┘    └────────────────┘   └────────────────┘
    │                 │                    │
    │     RANDAO-based                     │
    │     proposer &                       │
    │     committee                        │
    │     selection                        │
    ▼                                      ▼
┌─────────────────────────────────────────────────────────────┐
│                  Consensus_V2_PoS                            │
│  - Block validation (proposer, signature, attestations)      │
│  - Finality checking (2/3+ stake attestations)               │
│  - RANDAO accumulation                                       │
└─────────────────────────────────────────────────────────────┘
```

## Next Steps

1. **Integration Testing** - Test full validator flows
2. **P2P Integration** - Connect validator to gossip protocol
3. **Monitoring** - Add Prometheus metrics for validator status
4. **Documentation** - Update user guides for validator setup
