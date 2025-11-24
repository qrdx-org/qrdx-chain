# Key Architectural Decisions

This document records significant design decisions made during the QRDX implementation, including rationale, alternatives considered, and impacts.

---

## Decision 1: Post-Quantum Algorithm Selection

**Date**: Session Day 1 (Planning Phase)
**Category**: Cryptography
**Status**: ✅ Implemented

### Decision
Use **ML-DSA-65** (Dilithium3) for signatures and **ML-KEM-768** (Kyber768) for key encapsulation.

### Rationale
- **NIST Standardization**: Both algorithms are NIST-approved post-quantum standards (FIPS 204 and FIPS 203)
- **Security Level**: Both provide NIST Level 3 security (~192-bit classical equivalent)
- **Maturity**: Part of NIST's final PQC standards, widely reviewed
- **Library Support**: Well-supported by liboqs-python v0.9.0+
- **Performance**: Reasonable performance characteristics for blockchain use

### Alternatives Considered
1. **Falcon**: More compact signatures but slower verification and complex floating-point operations
2. **SPHINCS+**: Stateless hash-based, but much larger signatures (7.8 KB vs 3.3 KB)
3. **Classic McEliece**: Extremely large public keys (hundreds of KB)

### Impact
- **Transaction Size**: ~5.2 KB per transaction (47x Ethereum)
- **Block Header Size**: ~3.7 KB (includes validator signature)
- **Network Bandwidth**: Higher requirements than ECDSA-based chains
- **Storage**: Increased on-chain storage requirements
- **Security**: Quantum-resistant against Shor's and Grover's algorithms

### Trade-offs
- ✅ **Pros**: Future-proof security, NIST-approved, mature implementation
- ❌ **Cons**: Larger transaction sizes, higher bandwidth requirements

---

## Decision 2: BLAKE3 for Hashing

**Date**: Session Day 1 (Phase 1)
**Category**: Cryptography
**Status**: ✅ Implemented

### Decision
Replace Keccak256 with **BLAKE3** for all hashing operations (block headers, Merkle trees, address derivation).

### Rationale
- **Quantum Resistance**: Not vulnerable to Grover's algorithm speedup (unlike SHA-2/SHA-3)
- **Performance**: Faster than Keccak256 (multiple GB/s throughput)
- **Parallelizable**: Supports SIMD and multi-threading
- **Security**: Based on proven BLAKE2 design, peer-reviewed
- **Output Size**: 32 bytes (same as Keccak256)

### Alternatives Considered
1. **SHA-3/Keccak256**: Not quantum-resistant, vulnerable to Grover's algorithm
2. **BLAKE2**: Good but BLAKE3 is significantly faster and more parallelizable
3. **SHA-256**: Widely used but not quantum-resistant

### Impact
- **Block Header Hashing**: Uses BLAKE3 instead of Keccak256
- **Address Derivation**: `address = BLAKE3(public_key)[:20]`
- **Merkle Trees**: BLAKE3 for transaction/state root hashes
- **Performance**: Faster than Keccak256 on modern hardware

### Trade-offs
- ✅ **Pros**: Quantum-resistant, faster, parallelizable
- ❌ **Cons**: Different from Ethereum (not compatible), less widely used in blockchain

---

## Decision 3: Transaction Structure with Embedded Public Key

**Date**: Session Day 1 (Phase 2)
**Category**: Transaction Format
**Status**: ✅ Implemented

### Decision
Include **full Dilithium public key** (1,952 bytes) in every signed transaction.

### Rationale
- **Signature Verification**: Dilithium signatures require the public key for verification
- **Sender Recovery**: No mathematical relationship between public key and signature (unlike ECDSA)
- **Address Derivation**: Address = BLAKE3(public_key)[:20]
- **State Management**: Allows verification without looking up public key from state

### Alternatives Considered
1. **Store Public Keys On-Chain**: Look up by address
   - ❌ Requires state access during validation
   - ❌ Chicken-and-egg problem for first transaction
2. **Separate Public Key Registry**: Dedicated registry contract
   - ❌ Adds complexity and extra transactions
   - ❌ Still requires initial public key publication

### Impact
- **Transaction Size**: Adds 1,952 bytes per transaction
- **Total Transaction Size**: ~5.2 KB (nonce + to + value + gas + data + chain_id + public_key + signature)
- **Validation**: Self-contained transactions (no state lookup needed)
- **Network**: Higher bandwidth requirements

### Trade-offs
- ✅ **Pros**: Self-contained verification, simpler validation logic
- ❌ **Cons**: Larger transactions, higher bandwidth costs

---

## Decision 4: Dual-Mode Transaction Support

**Date**: Session Day 1 (Phase 2)
**Category**: Backward Compatibility
**Status**: ✅ Implemented

### Decision
Support **both Dilithium (primary) and ECDSA (legacy)** signatures in transaction utilities.

### Rationale
- **Testing**: Allow testing with smaller legacy transactions during development
- **Migration**: Potential future support for legacy transaction replay/verification
- **Flexibility**: Framework can handle multiple signature schemes
- **Clean Detection**: Key size-based detection (Dilithium: 4,032 bytes, ECDSA: 32 bytes)

### Alternatives Considered
1. **Dilithium Only**: Pure quantum-resistant
   - ❌ Harder to test with existing tooling
   - ❌ No migration path from Ethereum
2. **Runtime Configuration**: Switch via config flag
   - ❌ More complex, error-prone

### Impact
- **Code Complexity**: Added conditional logic in 4 functions
- **Testing**: Can use legacy ECDSA for faster test iterations
- **Production**: Will primarily use Dilithium, ECDSA only for special cases

### Trade-offs
- ✅ **Pros**: Testing flexibility, migration path, framework reuse
- ❌ **Cons**: Slightly more complex code, potential confusion

---

## Decision 5: QR-PoS with 150 Validators

**Date**: Session Day 1 (Phase 5)
**Category**: Consensus
**Status**: ✅ Implemented

### Decision
Implement **QR-PoS with exactly 150 validators** and **single-slot finality**.

### Rationale
- **Whitepaper Specification**: Explicitly requires 150 validators
- **Performance**: Target 5,000+ TPS with 2-second block times
- **Finality**: Single-slot finality (2 seconds) vs Ethereum's 12-15 minutes
- **Decentralization**: Balance between performance and decentralization
- **BFT Safety**: 2/3 supermajority (100 validators) for finality

### Alternatives Considered
1. **Ethereum's ~900K Validators**: Too many for 2-second blocks
2. **Proof-of-Work**: Not in whitepaper, incompatible with quantum resistance goals
3. **Variable Validator Count**: More flexible but adds complexity

### Impact
- **Finality Time**: 2 seconds (single slot)
- **Throughput**: Supports 5,000+ TPS target
- **Stake Requirement**: Minimum 100,000 QRDX per validator
- **Attestation Size**: 150 attestations × ~3.5 KB = ~525 KB per block
- **Network**: Higher bandwidth for attestation propagation

### Trade-offs
- ✅ **Pros**: Fast finality, high throughput, quantum-resistant
- ❌ **Cons**: Higher centralization risk than Ethereum, higher bandwidth

---

## Decision 6: Stake-Weighted Proposer Selection

**Date**: Session Day 1 (Phase 5)
**Category**: Consensus
**Status**: ✅ Implemented

### Decision
Use **stake-weighted random selection** for block proposers (not round-robin).

### Rationale
- **Fairness**: Validators with more stake have proportionally more proposal opportunities
- **Incentive Alignment**: Encourages higher stakes for more rewards
- **Security**: Harder to predict proposer sequence (vs round-robin)
- **Sybil Resistance**: Splitting stake doesn't gain advantage

### Alternatives Considered
1. **Round-Robin**: Simpler but unfair to validators with different stakes
2. **Pure Random**: Fair but doesn't weight by stake (economic security)
3. **VRF-Based**: More complex, requires additional crypto primitives

### Impact
- **Selection Logic**: `compute_proposer_index()` with cumulative stake calculation
- **Testing**: Verified with 100-slot simulation (higher stake = more proposals)
- **Economic Model**: Validators incentivized to increase stake

### Trade-offs
- ✅ **Pros**: Fair, secure, incentive-aligned
- ❌ **Cons**: Slightly more complex than round-robin

---

## Decision 7: VM Fork Extending Shanghai

**Date**: Session Day 1 (Phase 6)
**Category**: EVM Compatibility
**Status**: ✅ Implemented

### Decision
Extend **Shanghai fork** (latest py-evm fork) with quantum-resistant precompiles.

### Rationale
- **Modern Features**: Includes all latest EVM improvements (push0, warm coinbase, etc.)
- **Code Reuse**: Inherit all Shanghai opcodes and precompiles
- **Compatibility**: Maximum compatibility with modern Ethereum tooling
- **Framework Pattern**: py-evm designed for fork-based extensions

### Alternatives Considered
1. **Extend Berlin/London**: Older forks, missing modern features
2. **Fork from Genesis**: Start from scratch
   - ❌ Lose all EVM improvements since genesis
   - ❌ Massive reimplementation effort

### Impact
- **Opcodes**: All Shanghai opcodes available (0x00-0x5f)
- **Precompiles**: Shanghai precompiles (0x01-0x08) + QRDX precompiles (0x09-0x0c)
- **Smart Contracts**: Solidity contracts can use all modern EVM features
- **Tooling**: Compatible with Solidity, Hardhat, Foundry, etc.

### Trade-offs
- ✅ **Pros**: Full EVM compatibility, modern features, less reimplementation
- ❌ **Cons**: Inherits some Ethereum quirks, larger codebase

---

## Decision 8: Precompile Gas Pricing

**Date**: Session Day 1 (Phase 6)
**Category**: Gas Economics
**Status**: ✅ Implemented

### Decision
Set precompile gas costs:
- **Dilithium Verify (0x09)**: 50,000 gas
- **Kyber Encapsulate (0x0a)**: 30,000 gas
- **Kyber Decapsulate (0x0b)**: 30,000 gas
- **BLAKE3 Hash (0x0c)**: 60 + 12/word gas

### Rationale
- **Dilithium Verify**: Most expensive operation (5,293-byte input, complex math)
- **Kyber Operations**: Moderate cost, similar complexity
- **BLAKE3**: Cheap and fast, priced similar to SHA-256 precompile
- **Calibration**: Based on estimated computational cost vs EVM base operations

### Alternatives Considered
1. **Higher Prices**: More conservative, but discourages use
2. **Lower Prices**: Risk underpricing, potential DoS vector
3. **Dynamic Pricing**: Adjust based on actual benchmarks
   - ⏳ **Future Work**: Re-calibrate after benchmarking

### Impact
- **Smart Contract Costs**: Quantum operations accessible but not cheap
- **DoS Resistance**: Priced high enough to prevent abuse
- **Usability**: Low enough for practical use cases

### Trade-offs
- ✅ **Pros**: Reasonable initial pricing, DoS-resistant
- ❌ **Cons**: Not benchmarked yet, may need adjustment

### Future Work
- Run performance benchmarks on target hardware
- Adjust gas prices based on actual operation costs
- Consider dynamic pricing for optimization

---

## Decision 9: Address Format Compatibility

**Date**: Session Day 1 (Phase 1)
**Category**: Address System
**Status**: ✅ Implemented

### Decision
Use **20-byte addresses** (same as Ethereum): `address = BLAKE3(public_key)[:20]`

### Rationale
- **Tooling Compatibility**: Works with existing Ethereum tooling (MetaMask, Etherscan, etc.)
- **Size**: 20 bytes is sufficient for collision resistance
- **Familiar UX**: Users understand 0x... address format
- **Standard**: EIP-55 checksum encoding still applies

### Alternatives Considered
1. **32-byte Addresses**: Full BLAKE3 output
   - ❌ Breaks tooling compatibility
   - ❌ Longer addresses, worse UX
2. **16-byte Addresses**: Smaller
   - ❌ Weaker collision resistance
3. **Different Encoding**: Base58, Bech32, etc.
   - ❌ Breaks compatibility with Ethereum tooling

### Impact
- **Compatibility**: Ethereum tools can display QRDX addresses
- **Collision Resistance**: 2^160 address space (sufficient)
- **User Experience**: Familiar address format

### Trade-offs
- ✅ **Pros**: Maximum compatibility, familiar UX
- ❌ **Cons**: Slightly weaker than 32-byte addresses

---

## Decision 10: Comprehensive Documentation Strategy

**Date**: Session Day 1 (Documentation Phase)
**Category**: Development Process
**Status**: 🔄 In Progress

### Decision
Follow **"iterate_long" documentation format** with session-based tracking.

### Rationale
- **Long-Running Sessions**: 10-phase project spanning many hours
- **Context Preservation**: Maintain state across context limits
- **Handoff Capability**: Enable work continuation by other agents
- **Progress Tracking**: Clear visibility into what's done vs remaining
- **Decision History**: Record architectural choices and rationale

### Alternatives Considered
1. **No Documentation**: Just code
   - ❌ Lose context, hard to resume, no decision history
2. **README Only**: Single file
   - ❌ Not structured for long sessions, hard to navigate
3. **Git Commits**: Use commit messages
   - ❌ Not detailed enough, hard to search

### Impact
- **Session Directory**: `/docs/ai/sessions/2025-11-23_qrdx-implementation/`
- **Files**:
  - `00_objective.md` - Goals and acceptance criteria
  - `01_analysis.md` - Architecture and patterns
  - `02_implementation_plan.md` - Task breakdown
  - `03_progress.md` - Current state (this file)
  - `04_decisions.md` - Design decisions (this file)
- **Workflow**: Update docs at phase boundaries and major decisions

### Trade-offs
- ✅ **Pros**: Excellent context preservation, easy resumption, clear history
- ❌ **Cons**: Time investment in documentation

---

## Summary Statistics

**Total Decisions Documented**: 10
**Categories**:
- Cryptography: 2 decisions
- Transaction Format: 2 decisions
- Consensus: 2 decisions
- EVM Compatibility: 2 decisions
- Address System: 1 decision
- Development Process: 1 decision

**Decision Impact**:
- ✅ **High Impact**: 7 decisions (crypto, consensus, transaction format)
- ✅ **Medium Impact**: 2 decisions (gas pricing, address format)
- ✅ **Low Impact**: 1 decision (documentation process)

**Status**:
- ✅ **Implemented**: 9 decisions
- 🔄 **In Progress**: 1 decision (documentation)

---

## Future Decisions Required

### Phase 6: Chain Configuration
- Genesis validator set composition
- Initial token distribution
- Chain ID selection
- Network parameters (peer discovery, etc.)

### Phase 7-8: Smart Contracts
- qRC20 token standard specifics
- AMM fee tier structure
- Hook system design

### Phase 9: Bridge
- Bridge security model (multi-sig vs validator set)
- Fraud proof window duration
- Cross-chain message format

### Phase 10: Governance
- Voting mechanism (linear vs quadratic)
- Proposal threshold requirements
- Timelock duration
