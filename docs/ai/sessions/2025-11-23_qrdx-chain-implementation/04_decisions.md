# Key Decisions Made During Implementation

## Date: 2025-11-23

## Decision 1: NIST Final Algorithm Names
**Context**: The whitepaper refers to CRYSTALS-Dilithium and CRYSTALS-Kyber, but NIST has finalized the names as ML-DSA and ML-KEM.

**Decision**: Use ML-DSA-65 and ML-KEM-768 (the official NIST FIPS names)
- ML-DSA-65 = Dilithium3 / NIST Level 3
- ML-KEM-768 = Kyber768 / NIST Level 3

**Rationale**:
- FIPS 204 and FIPS 203 use these names
- liboqs library supports both old and new names
- Using official names ensures long-term compatibility
- Documentation will explain the mapping for clarity

**Impact**: Code uses ML-DSA/ML-KEM internally but documentation references both names for clarity

---

## Decision 2: Signature and Key Sizes
**Context**: Whitepaper specified approximate sizes, but actual NIST standards define exact sizes.

**Decision**: Use exact NIST-specified sizes:
- Dilithium/ML-DSA-65:
  - Private key: 4,032 bytes (not 4,016)
  - Public key: 1,952 bytes ✓
  - Signature: 3,309 bytes (not 3,293)

**Rationale**:
- Must match liboqs implementation exactly
- NIST FIPS documents specify these sizes
- Whitepaper values were approximations

**Impact**: Transaction size is 16 bytes larger than initial whitepaper estimate (negligible)

---

## Decision 3: BLAKE3 Output Length
**Context**: BLAKE3 supports variable-length output. Whitepaper mentions 512-bit for quantum resistance.

**Decision**: Use 256-bit (32 bytes) by default, with 512-bit option available
- Default: 32 bytes (Hash32 compatible with Ethereum)
- Quantum-resistant: 64 bytes available when needed

**Rationale**:
- 256-bit provides 256-bit quantum security (Grover's algorithm reduces by square root)
- Maintains Ethereum compatibility (Hash32 type)
- 512-bit available for maximum security when needed
- Storage efficiency

**Impact**: State roots, block hashes use 32 bytes for compatibility

---

## Decision 4: Address Format
**Context**: Need to decide on QRDX address format - new format or Ethereum-compatible.

**Decision**: Use Ethereum-compatible 20-byte addresses
- Derived from BLAKE3(public_key)[-20:]
- EIP-55 checksumming supported
- Standard hex format with 0x prefix

**Rationale**:
- Tooling compatibility (wallets, explorers, libraries)
- Familiar UX for users
- 20 bytes sufficient for security (2^160 addresses)
- Can implement quantum-resistant checksumming later if needed

**Impact**: Existing Ethereum tools can display QRDX addresses with minimal modification

---

## Decision 5: Contract Address Generation
**Context**: Should contract addresses use Keccak256 (Ethereum) or BLAKE3?

**Decision**: Use BLAKE3 for contract address generation
- CREATE: BLAKE3(RLP(sender, nonce))[-20:]
- CREATE2: BLAKE3(0xff || sender || salt || init_code_hash)[-20:]

**Rationale**:
- Quantum resistance throughout the system
- Same formula as Ethereum, just different hash function
- Deterministic and reproducible
- No compatibility issues (contracts are chain-specific)

**Impact**: Contract addresses will differ from Ethereum even with same bytecode

---

## Decision 6: Signature Storage in Transactions
**Context**: Dilithium signatures are 3,309 bytes vs 65 bytes for ECDSA. Consider compression?

**Decision**: Store full uncompressed signatures
- No compression applied
- Full 3,309-byte signatures in transactions
- Public key (1,952 bytes) also included

**Rationale**:
- Compression adds CPU overhead
- Signature verification is already fast (~60μs)
- Network bandwidth not the bottleneck (block time is 2s)
- Simpler implementation
- Can optimize later if needed

**Impact**: Transactions are ~5.2KB vs ~110 bytes, but acceptable given 2s block time

---

## Decision 7: Public Key in Transaction
**Context**: Should transactions include the full public key or derive from signature?

**Decision**: Include full public key (1,952 bytes) in each transaction
- Explicit public_key field in transaction
- No public key recovery from signature

**Rationale**:
- Dilithium doesn't support public key recovery
- Explicit is clearer and more secure
- Verification is straightforward
- Storage cost acceptable

**Impact**: Additional 1,952 bytes per transaction

---

## Decision 8: Backward Compatibility with ECDSA
**Context**: Should we support ECDSA transactions during transition?

**Decision**: Keep eth-keys library as optional dependency for now
- New QRDX transactions use Dilithium only
- Legacy support can be added via transaction type if needed
- Focus on pure quantum-resistant chain first

**Rationale**:
- Clean break is simpler
- Bridge handles classical assets
- No mixed security model
- Can add hybrid mode later if community desires

**Impact**: QRDX Chain is quantum-resistant from genesis

---

## Decision 9: Library Choice: liboqs-python
**Context**: Multiple Python libraries available for post-quantum crypto.

**Decision**: Use liboqs-python (Open Quantum Safe project)
- Maintained by Open Quantum Safe consortium
- NIST-compliant implementations
- Battle-tested in multiple projects
- C implementation (fast)

**Alternatives Considered**:
- pycryptodome: No full PQ support
- PQClean: Lower-level, harder to use
- Pure Python implementations: Too slow

**Impact**: Fast, reliable, but adds C library dependency

---

## Decision 10: Key Management API Design
**Context**: How should developers interact with quantum-resistant keys?

**Decision**: High-level API in eth.crypto.keys module
```python
from eth.crypto import generate_keypair, derive_address, sign_message
```

**Rationale**:
- Simple, Pythonic API
- Hides complexity of Dilithium
- Similar to eth-keys API (familiar)
- Easy to test and mock

**Impact**: Developer-friendly API, low learning curve

---

## Summary of Key Constraints

### Performance Implications
- Transaction size: 5.2KB (47x larger)
- Signature verification: ~60μs (2.5x slower than ECDSA)
- Key generation: ~50μs (3x slower)
- Block size: Will grow proportionally with transaction count

### Storage Implications
- Each transaction requires ~5KB storage
- State database needs efficient indexing
- Archive nodes will grow faster

### Network Implications
- Block propagation may be slower
- P2P protocol may need optimization
- 2-second block time provides buffer

### Mitigation Strategies Planned
1. Database optimization and compression
2. Efficient P2P protocols
3. State pruning for non-archive nodes
4. Possible signature aggregation research (future)

---

## Future Decisions Needed

1. **Signature Aggregation**: Research BLS-like aggregation for Dilithium
2. **Zero-Knowledge Proofs**: Quantum-resistant zkSNARKs when available
3. **Layer 2**: Rollup design with PQ signatures
4. **Cross-Chain**: Bridge security model details
5. **Privacy**: Encrypted transaction pool design with Kyber
