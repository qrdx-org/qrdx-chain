# Objective: Get Validator to Production Standards

## Date
December 6, 2025

## Goal
Bring the QRDX validator implementation to production-ready standards with NO STUBS, NO SHORTCUTS, NO TESTNET CHEATS. Previous agent failed because the implementation had testnet shortcuts that would not work in production.

## Acceptance Criteria
1. **Block Production**: Validators create and sign real blocks with Dilithium signatures
2. **Block Broadcasting**: Blocks propagated to all peers via P2P
3. **Block Import**: Peers validate and import blocks correctly
4. **Attestations**: Validators create, broadcast, and aggregate attestations
5. **Finality**: Justified and finalized checkpoints tracked correctly
6. **Fork Choice**: Weight-based fork choice working (LMD-GHOST)
7. **RPC Interface**: All Ethereum JSON-RPC methods working (no stubs)
8. **Production Ready**: No TODO, STUB, FIXME, or testnet shortcuts anywhere

## Whitepaper Requirements (v2.0)
Based on QRDX-Whitepaper-v2.0.md:

### Consensus (Section 9)
- **QR-PoS**: Quantum-Resistant Proof-of-Stake
- **Validator Set**: 150 active validators
- **Staking**: 100,000 QRDX minimum per validator
- **Block Time**: 2 seconds per slot
- **Finality**: Single-slot finality via BFT consensus
- **Selection**: Pseudo-random weighted by stake

### Block Structure
- **Signatures**: CRYSTALS-Dilithium3 (3,309 bytes)
- **Attestations**: 2/3+ validators must attest for finality
- **Extra Data**: QR-PoS metadata (slot, validator_index, proposer_pubkey)
- **Difficulty**: 0 (no PoW)

### Finality Gadget (Section 9.4)
1. Validator proposes block
2. Other validators attest to block validity
3. Block becomes final when 2/3+ of stake has attested
4. Finalized blocks cannot be reverted

### Safety Guarantee
As long as >2/3 of validators are honest, no conflicting blocks can be finalized.

### Slashing Conditions (Section 9.5)
- Double-signing: 50% stake
- Invalid attestation: 30% stake
- Downtime: 5% stake (>10% missed attestations)
- Bridge fraud: 100% stake

## Success Metrics
- [ ] Chain height increasing every 2 seconds
- [ ] All 150 validators taking turns proposing
- [ ] Blocks propagating to all peers within 500ms
- [ ] Attestations reaching quorum (100+/150)
- [ ] Justified checkpoints updating every epoch
- [ ] Finalized checkpoints advancing steadily
- [ ] Fork choice converging correctly
- [ ] Zero stubs or TODOs in production code
- [ ] All tests passing
- [ ] No production-blocking issues

## Scope
- **In Scope**: Everything needed for production validator
- **Out of Scope**: Bridge functionality, smart contracts, governance (these come later)

## Known Issues from Previous Agent
- Block production pipeline incomplete
- Attestations created but not broadcast/aggregated
- Fork choice not implemented
- RPC methods may have stubs
- IPC event delivery uncertain
- Genesis timestamp = 0 (cosmetic but wrong)
