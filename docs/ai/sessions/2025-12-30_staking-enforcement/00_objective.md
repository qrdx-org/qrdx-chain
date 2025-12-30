# Objective: Fix Staking Enforcement Bypass

## Problem Statement
Validators can currently start the local testnet and produce blocks **without** having the required 100,000 QRDX stake. This completely bypasses the whitepaper's core requirement that validators must stake to participate.

## Root Cause
In `trinity/components/builtin/qrpos_validator/component.py` line 756:
```python
validator = Validator(
    index=i,
    public_key=validator_pubkey.to_bytes(),
    address=validator_address,
    stake=MIN_STAKE,  # ⚠️ HARDCODED - not checked against actual on-chain stake!
    status=ValidatorStatus.ACTIVE,
    activation_epoch=0,
    exit_epoch=None,
    slashed=False,
)
```

The code **assumes** all validators have MIN_STAKE without:
1. Checking if they've registered via StakeTracker.sol
2. Verifying they have on-chain balance
3. Reading actual stake amounts from genesis or contract state

## Acceptance Criteria
- [ ] Genesis configuration includes validator stakes (not hardcoded)
- [ ] Validators without proper stake cannot start producing blocks
- [ ] Validator component reads stake from genesis or StakeTracker contract
- [ ] Local testnet initializes validator stakes properly
- [ ] Tests verify that unstaked validators are rejected
- [ ] Production deployment enforces 100k QRDX minimum

## Success Metrics
1. ✅ Local testnet validators have actual QRDX balances in genesis
2. ✅ Starting a validator without stake fails with clear error
3. ✅ ValidatorSet initialization validates stake amounts
4. ✅ No hardcoded stake assumptions in validator component
5. ✅ Integration test: unstaked validator rejected

## Scope
### In Scope
- Genesis configuration for validator stakes
- Validator component stake verification
- ValidatorSet initialization from genesis
- StakeTracker integration (read stakes)
- Test script updates to fund validators

### Out of Scope (Future Work)
- Dynamic validator registration during runtime
- Stake withdrawal/slashing logic (already implemented in contracts)
- Bridge integration for cross-chain staking
- Delegation mechanisms (already in StakeTracker.sol)

## Whitepaper Compliance
Per QRDX Whitepaper v2.0, Section 9 (Consensus):
- **Minimum Stake**: 100,000 QRDX (enforced at registration)
- **Maximum Validators**: 150 (already enforced)
- **Validator Selection**: Based on stake-weighted random selection
- **Slashing**: 5% for downtime (contract implemented, not enforced in runtime yet)

**Current Status**: ❌ Minimum stake requirement NOT enforced at runtime
**Target Status**: ✅ Full enforcement from genesis through runtime
