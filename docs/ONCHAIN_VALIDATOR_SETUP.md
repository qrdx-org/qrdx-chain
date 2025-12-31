# On-Chain Validator Verification - Quick Start Guide

## Overview

QRDX consensus now supports **two validator loading modes**:

1. **Genesis-Only Mode** (testnet): Loads validators from genesis.json
2. **Hybrid Mode** (production): Tries on-chain StakeTracker first, falls back to genesis

## Default Mode: On-Chain Verification (Production-Ready)

The testnet now **defaults to on-chain mode** to match production mainnet behavior. If StakeTracker contract is not deployed yet, it automatically falls back to genesis for bootstrapping.

## How to Enable On-Chain Verification

### Step 1: Deploy StakeTracker Contract

```bash
# Navigate to contracts directory
cd /workspaces/qrdx-chain/contracts/staking

# Deploy using Hardhat/Foundry/Remix
# Example (you'll need to adapt this):
npx hardhat run scripts/deploy_stake_tracker.js --network testnet

# Save the deployed contract address
# Example output: StakeTracker deployed at 0x1234567890123456789012345678901234567890
```

### Step 2: Configure Environment Variables

```bash
# Enable on-chain validator loading
export USE_ONCHAIN_VALIDATORS=true

# Set deployed contract address (from Step 1)
export STAKE_TRACKER_ADDRESS=0x1234567890123456789012345678901234567890

# Set RPC endpoint (your QRDX node)
export QRDX_RPC_URL=http://localhost:8545

# Optional: Connection tuning
export RPC_TIMEOUT=30
export RPC_RETRY_ATTEMPTS=3
```

### Step 3: Register Validators On-Chain

For each validator that should be in the active set, someone must call:

```solidity
// Send transaction to StakeTracker contract
registerValidator(
    dilithiumPublicKey,  // 1952 bytes
    commissionRate       // 0-2000 (0% to 20%)
) payable  // Send >= 100,000 QRDX
```

**Option A: Use a script** (recommended):
```bash
# Create a script to register your genesis validators
node scripts/register_genesis_validators.js \
    --contract 0x... \
    --genesis /tmp/qrdx-multi-node-genesis.json
```

**Option B: Manual registration** (for testing):
```bash
# Use cast (Foundry) or web3.js to send transaction
cast send $STAKE_TRACKER_ADDRESS \
    "registerValidator(bytes,uint256)" \
    $DILITHIUM_PUBKEY \
    500 \
    --value "100000ether" \
    --from $VALIDATOR_ADDRESS
```

### Step 4: Restart Validators

```bash
# Export the environment variables (if not in .env)
export USE_ONCHAIN_VALIDATORS=true
export STAKE_TRACKER_ADDRESS=0x...
export QRDX_RPC_URL=http://localhost:8545

# Start validator (same command as before)
trinity --enable-qrpos-validator \
    --validator-index 0 \
    --validator-private-key /path/to/keystore.json
```

### Step 5: Verify On-Chain Loading

Check the logs for these messages:

**✅ Success (On-Chain Mode)**:
```
🔒 On-chain validator loading enabled: StakeTracker @ 0x...
Attempting to load validators from StakeTracker contract...
✅ Loaded 4 validators from on-chain contract (total stake: 400,000 QRDX)
🔒 Using decentralized on-chain validator set (production-ready)
```

**⚠️ Fallback (Genesis Mode)**:
```
⚠️  Failed to load validators from contract: <error>. Falling back to genesis...
Loading validators from genesis configuration...
✅ Loaded 4 validators from genesis (total stake: 400,000 QRDX)
⚠️  Genesis-based loading is NOT production-ready.
```

## Environment Variable Reference

| Variable | Required? | Default | Description |
|----------|-----------|---------|-------------|
| `USE_ONCHAIN_VALIDATORS` | No | `true` | Enable on-chain loading (set `false` for genesis-only) |
| `STAKE_TRACKER_ADDRESS` | Yes (on-chain) | None | Deployed StakeTracker contract address |
| `QRDX_RPC_URL` | Yes (on-chain) | `http://localhost:8545` | JSON-RPC endpoint |
| `RPC_TIMEOUT` | No | `30` | Request timeout (seconds) |
| `RPC_RETRY_ATTEMPTS` | No | `3` | Number of retry attempts |
| `GENESIS_FILE` | Yes | `/tmp/qrdx-multi-node-genesis.json` | Genesis file path |
| `QRDX_KEYSTORE_DIR` | Yes | `/tmp/qrdx-validator-keys` | Validator keystore directory |

## Migration Roadmap

### Phase 1: Bootstrap Mode (If no contract deployed)
```bash
# DEFAULT - tries on-chain, falls back to genesis if contract not found
# No environment variables needed
```
- Attempts on-chain loading first
- Falls back to genesis.json if contract not deployed
- ⚠️ Genesis fallback can be cheated by modifying local files

### Phase 2: Production Mode (Contract deployed)
```bash
# DEFAULT - just set contract address
STAKE_TRACKER_ADDRESS=0x...   # Contract deployed
```
- On-chain verification active
- Genesis used only if contract call fails
- ✅ Production-ready, cannot be cheated

### Phase 3: Full On-Chain (Week 4+)
```bash
USE_ONCHAIN_VALIDATORS=true
GENESIS_VALIDATORS_DEPRECATED=true  # Future flag
```
- All validators MUST be registered on-chain
- Genesis file only for initial bootstrap
- ✅ Production-ready, cannot be cheated

## Testing Modes Locally

### Default Behavior (Tries On-Chain, Falls Back to Genesis)
```bash
# No environment variables needed - this is the default
trinity --enable-qrpos-validator --validator-index 0

# Without contract deployed, you'll see:
# "⚠️ Failed to load validators from contract: ... Falling back to genesis..."
```

### Genesis-Only Mode (Opt-In for Development)
```bash
# Explicitly disable on-chain loading
export USE_ONCHAIN_VALIDATORS=false

trinity --enable-qrpos-validator --validator-index 0

# Will skip contract attempt and go straight to genesis
```

### Full Test (Real Contract)
```bash
# 1. Start QRDX node with RPC
trinity --enable-eth1-rpc --rpc-port 8545

# 2. Deploy StakeTracker
cd contracts/staking && npx hardhat deploy

# 3. Register validators
node scripts/register_validators.js

# 4. Start validator with on-chain mode
export USE_ONCHAIN_VALIDATORS=true
export STAKE_TRACKER_ADDRESS=<deployed-address>
trinity --enable-qrpos-validator --validator-index 0

# Should see: "✅ Loaded X validators from on-chain contract"
```

## Troubleshooting

### "Could not initialize on-chain loading"
**Cause**: Missing STAKE_TRACKER_ADDRESS or RPC connection failed  
**Fix**: Check environment variables and RPC endpoint

### "Failed to load validators from contract"
**Cause**: Contract not deployed or network mismatch  
**Fix**: Verify contract address and network

### "No validators loaded, cannot initialize consensus"
**Cause**: Neither on-chain nor genesis loading worked  
**Fix**: Check genesis.json exists and has validators array

### "Validator X has insufficient stake"
**Cause**: On-chain stake < 100,000 QRDX  
**Fix**: Register with correct stake amount

## Security Considerations

### Genesis-Only Mode ❌
- ⚠️ **Can be cheated**: Modify genesis.json locally
- ⚠️ **No verification**: Trusts local file
- ✅ **Use for**: Controlled testnets only

### Hybrid/On-Chain Mode ✅
- ✅ **Cannot be cheated**: Blockchain verification
- ✅ **Cryptographic proofs**: Contract enforces stakes
- ✅ **Use for**: Production mainnet

## Example: 4-Validator Testnet Setup

```bash
# Terminal 1: Deploy contract
cd contracts/staking
npx hardhat run scripts/deploy_stake_tracker.js
# Output: 0xABCD...

# Terminal 2: Register 4 validators
for i in 0 1 2 3; do
    node scripts/register_validator.js \
        --index $i \
        --stake 100000 \
        --contract 0xABCD...
done

# Terminal 3-6: Start validators
for i in 0 1 2 3; do
    (
        export USE_ONCHAIN_VALIDATORS=true
        export STAKE_TRACKER_ADDRESS=0xABCD...
        export QRDX_RPC_URL=http://localhost:$((8545 + i))
        
        trinity --enable-qrpos-validator \
            --validator-index $i \
            --data-dir /tmp/qrdx-node-$i \
            --port $((30303 + i))
    ) &
done
```

## Next Steps

1. **Test Genesis Mode**: Already working! ✅
2. **Deploy Contract**: Use Hardhat/Foundry
3. **Register Validators**: On-chain transactions
4. **Enable Hybrid Mode**: Set environment variables
5. **Verify Logs**: Check for on-chain success messages
6. **Monitor**: Watch for dynamic validator changes

## Questions?

Refer to:
- `docs/ai/sessions/2025-12-30_staking-enforcement/04_decentralization_analysis.md` - Security details
- `docs/ai/sessions/2025-12-30_staking-enforcement/05_onchain_integration_plan.md` - Architecture
- `docs/ai/sessions/2025-12-30_staking-enforcement/06_progress.md` - Implementation status
