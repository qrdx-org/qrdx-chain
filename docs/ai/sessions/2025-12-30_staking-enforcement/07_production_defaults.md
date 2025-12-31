# Production Defaults: On-Chain First

**Date**: 2025-12-30  
**Change**: Flip default behavior from genesis-only to on-chain verification  
**Rationale**: Testnet should represent production-ready mainnet, not development environment

## User Requirement

> "Onchain validators needs to be default. The testnet needs to represent a 'local' version of a production ready mainnet"

This is correct - the current default of genesis-only mode creates false confidence. If developers test only with genesis, they won't catch production issues.

## Changes Made

### 1. Default Value Change

**Before**:
```python
use_onchain = os.environ.get('USE_ONCHAIN_VALIDATORS', 'false').lower() == 'true'
```

**After**:
```python
# Default to on-chain (production-ready), set to 'false' to use genesis-only
use_onchain = os.environ.get('USE_ONCHAIN_VALIDATORS', 'true').lower() == 'true'
```

**Files Modified**:
- `trinity/components/builtin/qrpos_validator/component.py`
- `trinity/components/builtin/new_block/component.py`

### 2. Behavior Inversion

| Scenario | Old Behavior | New Behavior |
|----------|--------------|--------------|
| **No env vars** | Genesis-only (can be cheated) | On-chain first, genesis fallback (production-ready) |
| **USE_ONCHAIN_VALIDATORS=true** | On-chain | On-chain |
| **USE_ONCHAIN_VALIDATORS=false** | Genesis-only | Genesis-only |
| **Contract not deployed** | Genesis-only | Tries on-chain, falls back to genesis gracefully |

### 3. Documentation Updates

**ONCHAIN_VALIDATOR_SETUP.md** changes:
- Environment variable table: `USE_ONCHAIN_VALIDATORS` default changed from `false` to `true`
- Configuration examples: Default mode now shows on-chain behavior
- Migration roadmap: Genesis-only is now opt-in, not default
- Testing section: Shows how to explicitly disable on-chain for development

## Philosophy Shift

### Old Approach (Development-First)
- Default: Genesis-only (centralized, can be cheated)
- To enable production: Set USE_ONCHAIN_VALIDATORS=true
- Risk: Developers forget to enable on-chain, ship vulnerable code

### New Approach (Production-First)
- Default: On-chain verification (decentralized, production-ready)
- To use genesis: Set USE_ONCHAIN_VALIDATORS=false
- Benefit: Production behavior by default, genesis opt-in for debugging

## Bootstrap Path

The system gracefully handles cold start:

1. **First run (no contract deployed)**:
   ```
   ⚠️ Failed to load validators from contract: HTTPError...
   Falling back to genesis...
   ✅ Loaded 4 validators from genesis (total stake: 400,000 QRDX)
   ⚠️ Genesis-based loading is NOT production-ready.
   ```

2. **After deploying StakeTracker contract**:
   ```
   🔒 On-chain validator loading enabled: StakeTracker @ 0x...
   ✅ Loaded 4 validators from on-chain contract (total stake: 400,000 QRDX)
   🔒 Using decentralized on-chain validator set (production-ready)
   ```

3. **Development/debugging (explicit genesis mode)**:
   ```bash
   export USE_ONCHAIN_VALIDATORS=false
   # Skips on-chain attempt entirely
   ```

## Security Posture

### Before This Change
- ❌ Default mode can be cheated (modify genesis.json)
- ❌ Testnet doesn't match production security
- ❌ Easy to forget enabling on-chain in production

### After This Change
- ✅ Default mode is production-ready
- ✅ Testnet validates like mainnet will
- ✅ Genesis-only requires explicit opt-in (developers know it's insecure)

## Migration Impact

### For Existing Testnets
**No breaking changes** - graceful fallback ensures existing testnets continue working:
- On first run, attempts on-chain (fails), falls back to genesis
- Logs clearly warn that genesis mode is not production-ready
- Once contract deployed, automatically switches to on-chain

### For New Testnets
- Start validating with production-ready defaults immediately
- Contract deployment encouraged from day 1
- Clear path to mainnet (already using production behavior)

## Testing Verification

### Scenario 1: No Contract Deployed (Cold Start)
```bash
# No environment variables set
trinity --enable-qrpos-validator --validator-index 0

# Expected output:
# ⚠️ Failed to load validators from contract...
# Falling back to genesis...
# ✅ Loaded 4 validators from genesis
```

### Scenario 2: Contract Deployed
```bash
# Set contract address only
export STAKE_TRACKER_ADDRESS=0x...
trinity --enable-qrpos-validator --validator-index 0

# Expected output:
# 🔒 On-chain validator loading enabled...
# ✅ Loaded 4 validators from on-chain contract
```

### Scenario 3: Development Mode (Genesis-Only)
```bash
# Explicitly disable on-chain
export USE_ONCHAIN_VALIDATORS=false
trinity --enable-qrpos-validator --validator-index 0

# Expected output:
# ⚠️ StakeTrackerReader not configured.
#    Using genesis-based validator loading...
# ✅ Loaded 4 validators from genesis
```

## Documentation Alignment

All documentation now reflects production-first philosophy:

- **Quick Start**: Shows default behavior (on-chain with fallback)
- **Environment Variables**: USE_ONCHAIN_VALIDATORS defaults to `true`
- **Migration Roadmap**: Genesis-only is "opt-in for development"
- **Configuration Examples**: Default mode shown first, genesis mode labeled "development"

## Conclusion

This change aligns testnet behavior with production requirements:
- **Testnet = Local Mainnet**: Same security model, same verification path
- **Safe by Default**: Production-ready behavior without configuration
- **Clear Warnings**: Genesis fallback logs security warnings
- **Smooth Bootstrap**: Graceful degradation when contract not deployed yet

The testnet now accurately represents what production will look like, ensuring developers test against the real security model from day 1.

## Files Modified

1. `trinity/components/builtin/qrpos_validator/component.py` - Default to 'true'
2. `trinity/components/builtin/new_block/component.py` - Default to 'true'
3. `docs/ONCHAIN_VALIDATOR_SETUP.md` - Updated all sections for new defaults

## Next Steps

With production defaults in place:
1. Start 2-node testnet (no env vars) → See on-chain attempt + genesis fallback
2. Deploy StakeTracker contract
3. Restart testnet → See automatic on-chain loading
4. Verify production-ready behavior by default ✅
