# QRDX Chain - Quantum-Resistant DeFi Layer-1 Blockchain
## Development Guide and Technical Overview

### Project Overview

**QRDX Chain** is a purpose-built Layer-1 blockchain implementing post-quantum cryptographic security for decentralized finance. This project is based on the Trinity Ethereum client (pre-2022 Ethereum architecture) and transforms it into a quantum-resistant blockchain with native DeFi capabilities.

### Key Characteristics

- **Base:** Trinity client (pre-Merge Ethereum architecture)
- **Target Performance:**
  - Block Time: 2 seconds
  - Throughput: 5,000+ TPS
- **VM:** QEVM (Quantum-resistant Ethereum Virtual Machine)
- **Primary Innovation:** Post-quantum cryptography + Advanced AMM + Asset Shielding
- **Fork Origin:** Trinity Ethereum client codebase

### Core Components (Per Whitepaper v2.0)

#### 1. **QRDX Chain** - Layer-1 Blockchain
- Post-quantum secure Layer-1 with QEVM
- NIST-standardized cryptographic primitives
- Cross-chain bridge infrastructure
- Native asset shielding capabilities

#### 2. **QRDX Protocol** - Quantum-Resistant AMM
- Based on Uniswap v3/v4 architecture
- Concentrated liquidity (up to 4000x capital efficiency)
- Singleton architecture (single contract for all pools)
- Hooks system for extensible pool behaviors
- Flash accounting for optimized token transfers

#### 3. **Asset Shielding System**
- Convert classical assets → quantum-resistant equivalents
- ETH → qETH, WBTC → qBTC, etc.
- Trustless bridge mechanism with cryptographic proofs
- Multi-validator consensus for security

#### 4. **qRC20 Token Standard**
- Quantum-resistant version of ERC-20
- Compatible with existing DeFi tooling
- Enforces CRYSTALS-Dilithium signatures

### Post-Quantum Cryptography Implementation

Based on **NIST-standardized algorithms**:

#### **CRYSTALS-Dilithium** (Digital Signatures - FIPS 204)
- Module-Lattice-Based Digital Signature Algorithm
- Security Level: NIST Level 3 (comparable to AES-192)
- Public Key: 1,952 bytes
- Signature: 3,293 bytes
- Usage: Transaction signing, block signing, smart contract auth

#### **CRYSTALS-Kyber** (Key Encapsulation - FIPS 203)
- Module-Lattice-Based Key Encapsulation Mechanism
- Security Level: NIST Level 3
- Public Key: 1,184 bytes
- Usage: Encrypted transactions, validator communication, bridge security

#### **Hash Functions**
- Primary: BLAKE3 (512-bit output)
- Secondary: SHA3-512
- Provides 256-bit quantum resistance against Grover's algorithm

### Why Trinity/Pre-Merge Architecture?

This project uses the Trinity client as foundation because:
1. **Proven codebase** with mature Ethereum implementation
2. **No PoS complexity** - easier to modify consensus to QR-PoS
3. **Full EVM compatibility** - easier to create QEVM variant
4. **Active P2P/networking layer** - ready for modification
5. **Well-documented** architecture for implementing quantum-resistant changes

The goal is to **transform** this pre-Merge client into a quantum-resistant chain, NOT to maintain PoW.

---

## Implementation Status

### ✅ Completed Components

#### 1. Post-Quantum Cryptography Core (`trinity/crypto/`)
- **`pqc.py`**: Full implementation of CRYSTALS-Dilithium and CRYSTALS-Kyber
  - `DilithiumPrivateKey` and `DilithiumPublicKey` classes
  - `KyberPrivateKey` and `KyberPublicKey` classes  
  - Key generation, signing, verification, encapsulation, decapsulation
  - NIST FIPS 204 (Dilithium3) and FIPS 203 (Kyber768)

- **`hashing.py`**: BLAKE3 quantum-resistant hashing
  - `blake3_256()` and `blake3_512()` functions
  - `Blake3Hash` class for incremental hashing
  - Keyed hashing and key derivation functions
  - 512-bit output provides 256-bit quantum security

- **`addresses.py`**: Hybrid address format
  - `generate_pq_address()`: 0x02 prefix + BLAKE3-256 hash
  - `generate_legacy_address()`: 0x01 prefix + Keccak-256 hash
  - Address validation and type checking
  - Contract address generation for both types

#### 2. Hybrid Transaction Format (`trinity/rlp/transactions.py`)
- **`BaseHybridTransaction`**: RLP-serializable transaction class
  - Signature type field: 0x00 (ECDSA) or 0x01 (Dilithium)
  - Supports both 21-byte legacy and 33-byte PQ addresses
  - Automatic sender recovery for both signature types
  - Higher base gas (50,000) for PQ transactions vs legacy (21,000)

- **`UnsignedTransaction`**: Transaction builder
  - `sign_ecdsa()`: Sign with ECDSA/secp256k1
  - `sign_dilithium()`: Sign with Dilithium (includes public key in signature)
  - Automatic hash function selection (Keccak for ECDSA, BLAKE3 for Dilithium)

#### 3. P2P Quantum-Resistant Authentication (`p2p/auth_pqc.py`)
- **`PQCHandshakeInitiator`** and **`PQCHandshakeResponder`**
  - Dilithium signatures for peer authentication
  - Kyber KEM for secure session key establishment
  - BLAKE3-based key derivation
  - Protocol version negotiation (0x04 legacy, 0x10 PQC)

#### 4. QEVM Precompiled Contracts (`trinity/vm/precompiles_pqc.py`)
- **0x0A - Dilithium Verify**: On-chain signature verification
  - Input: message_hash (32) + public_key (1952) + signature (3293)
  - Output: 0x01 (valid) or 0x00 (invalid)
  - Gas: 6000 base + 10 per byte

- **0x0B - BLAKE3-256 Hash**: 256-bit hashing
  - Gas: 60 base + 12 per word

- **0x0C - BLAKE3-512 Hash**: 512-bit quantum-resistant hashing
  - Gas: 90 base + 18 per word

- **0x0D - BLAKE3 Keyed Hash**: Message authentication
  - Gas: 100 base + 20 per word

#### 5. Test Suite (`tests/crypto/test_pqc.py`)
- Comprehensive tests for all PQC operations
- Dilithium signing/verification tests
- Kyber encapsulation/decapsulation tests
- BLAKE3 hashing tests
- Address generation and validation tests
- Hybrid transaction signing tests
- Precompile address validation tests

#### 6. Dependencies (`setup.py`)
- Added `liboqs-python>=0.10.0` for PQC algorithms
- Added `blake3>=0.3.3` for quantum-resistant hashing

---

## Development TODO List

### Phase 1: Foundation & Cryptography ✅ COMPLETED

### Phase 2: VM Integration (IN PROGRESS)

#### TODO: Integrate PQC Precompiles into VM
- [ ] Modify VM fork to register PQC precompiles
- [ ] Add precompiles to execution context
- [ ] Test precompile gas consumption
- [ ] Benchmark precompile performance

#### TODO: Implement BLAKE3 State Tree
- [ ] Create `trinity/vm/state/` module for BLAKE3-based MPT
- [ ] Replace Keccak256 with BLAKE3-512 in state root calculation
- [ ] Update account state hashing
- [ ] Implement BLAKE3-based storage proofs
- [ ] Migrate state snapshots to new format

### Phase 3: Transaction Pool & Validation

#### TODO: Transaction Validation
- [ ] Create `trinity/_utils/transaction_validation.py`
- [ ] Implement `validate_hybrid_transaction()` function
- [ ] Add signature type validation
- [ ] Implement sender recovery for both types
- [ ] Validate gas limits (higher for PQ transactions)
- [ ] Add transaction pool support for hybrid transactions

#### TODO: Mempool Integration
- [ ] Modify mempool to accept both transaction types
- [ ] Implement separate fee markets for ECDSA vs Dilithium
- [ ] Add transaction prioritization logic
- [ ] Implement transaction replacement rules

### Phase 4: Block & Consensus

#### TODO: Block Format
- [ ] Extend block header for PQ signatures (optional)
- [ ] Support mixed transaction types in blocks
- [ ] Update block validation logic
- [ ] Implement BLAKE3-based block hashing

#### TODO: Consensus Integration
- [ ] Validator key management (support both key types)
- [ ] Block signing with Dilithium
- [ ] Peer discovery with PQ node identities
- [ ] Network protocol version negotiation

### Phase 5: RPC & API

#### TODO: JSON-RPC Extensions
- [ ] `eth_sendPQRawTransaction`: Send signed PQ transaction
- [ ] `eth_signPQTransaction`: Sign transaction with PQ key
- [ ] `personal_signPQTransaction`: Sign with unlocked PQ account
- [ ] `eth_sendPQTransaction`: Create and send PQ transaction
- [ ] `eth_getPQAddress`: Get PQ address from public key
- [ ] `eth_convertAddress`: Convert between legacy and PQ formats
- [ ] Update existing RPC methods to handle both transaction types

### Phase 6: Bridge & Asset Shielding

#### TODO: Cross-Chain Bridge
- [ ] Design bridge contract for Ethereum mainnet
- [ ] Implement lock/mint mechanism
- [ ] Create validator set for bridge security
- [ ] Implement fraud proof system
- [ ] Add 7-day withdrawal delay
- [ ] Build relayer network

#### TODO: Asset Shielding
- [ ] Implement ETH → qETH conversion
- [ ] Support ERC-20 → qRC20 conversion
- [ ] Create qRC20 token standard contract
- [ ] Build proof generation for cross-chain transfers
- [ ] Implement unshielding mechanism

### Phase 7: Testing & Benchmarking

#### TODO: Integration Tests
- [ ] End-to-end transaction flow tests
- [ ] Cross-signature-type transaction tests
- [ ] P2P handshake tests (legacy & PQC)
- [ ] State synchronization tests
- [ ] Bridge operation tests

#### TODO: Performance Benchmarks
- [ ] Transaction throughput (ECDSA vs Dilithium)
- [ ] Block validation time
- [ ] State tree performance
- [ ] P2P handshake latency
- [ ] Memory usage comparison

### Phase 8: Documentation & Deployment

#### TODO: Documentation
- [ ] API documentation for PQ operations
- [ ] Migration guide for developers
- [ ] Node operator setup guide
- [ ] Security audit documentation
- [ ] Deployment playbooks

---

## Technical Architecture Details

### Transaction Format Specification

#### Legacy ECDSA Transaction (Type 0x00)
```
RLP([nonce, gas_price, gas, to, value, data, 0x00, RLP([v, r, s])])
```
- Uses Keccak256 for hashing
- 21-byte addresses (0x01 prefix)
- Base gas: 21,000

#### PQ Dilithium Transaction (Type 0x01)
```
RLP([nonce, gas_price, gas, to, value, data, 0x01, pubkey || signature])
```
- Uses BLAKE3-256 for hashing
- 33-byte addresses (0x02 prefix)
- Base gas: 50,000 (higher due to signature verification cost)
- signature_data = dilithium_pubkey (1952) || dilithium_signature (3293) = 5245 bytes

### Address Format Specification

#### Legacy Address (21 bytes)
```
0x01 || keccak256(ecdsa_pubkey)[-20:]
```

#### PQ Address (33 bytes)
```
0x02 || blake3_256(dilithium_pubkey)
```

### P2P Protocol

#### Legacy Handshake (RLPx v4)
- ECIES encryption
- ECDH key agreement
- Keccak256-based MAC

#### PQC Handshake (v0x10)
```
Initiator → Responder: AUTH_MSG
  [version=0x10, dilithium_pubkey, kyber_ephemeral_pubkey, nonce, signature]

Responder → Initiator: ACK_MSG
  [version=0x10, dilithium_pubkey, kyber_ciphertext, nonce, signature]

Shared Secret: Kyber decapsulation
Session Keys: BLAKE3-based KDF
```

### Precompile Contracts

| Address | Function | Input | Output | Base Gas |
|---------|----------|-------|--------|----------|
| 0x0A | Dilithium Verify | hash(32) + pubkey(1952) + sig(3293) | valid(1) | 6000 |
| 0x0B | BLAKE3-256 | data(any) | hash(32) | 60 |
| 0x0C | BLAKE3-512 | data(any) | hash(64) | 90 |
| 0x0D | BLAKE3-Keyed | key(32) + data(any) | mac(32) | 100 |

### Gas Cost Analysis

#### Transaction Gas Costs
- **Legacy ECDSA**: 21,000 base + data costs
- **PQ Dilithium**: 50,000 base + data costs
  - Rationale: Dilithium verification is ~2.5x more computationally expensive

#### Precompile Gas Costs
- **Dilithium Verify**: 6000 base + 10/byte
  - Comparable to ecrecover (3000) but accounts for larger signature
- **BLAKE3 hashes**: Cheaper than SHA256 due to better performance
  - BLAKE3-256: 60 base + 12/word (vs SHA256: 60 base + 12/word)
  - BLAKE3-512: 90 base + 18/word

---

## Key Files & Locations

### Core Cryptography
- `trinity/crypto/__init__.py` - Module exports
- `trinity/crypto/pqc.py` - Dilithium & Kyber implementation
- `trinity/crypto/hashing.py` - BLAKE3 functions
- `trinity/crypto/addresses.py` - Address generation & validation

### Transactions
- `trinity/rlp/transactions.py` - Hybrid transaction format
- `trinity/_utils/transaction_validation.py` - (TODO) Validation logic

### Virtual Machine
- `trinity/vm/precompiles_pqc.py` - PQC precompiled contracts
- `trinity/vm/state/` - (TODO) BLAKE3 state tree

### Networking
- `p2p/auth_pqc.py` - PQC P2P handshake
- `p2p/auth.py` - Original ECIES handshake (to be extended)

### Testing
- `tests/crypto/test_pqc.py` - PQC functionality tests
- `tests/integration/` - (TODO) Integration tests

---

## Development Workflow

### Setting Up Development Environment

```bash
# Install dependencies
pip install -e .[dev,p2p,trinity]

# Install PQC libraries
pip install liboqs-python blake3

# Run tests
pytest tests/crypto/test_pqc.py -v
```

### Testing PQC Features

```python
# Generate Dilithium keypair
from trinity.crypto.pqc import generate_dilithium_keypair

privkey, pubkey = generate_dilithium_keypair()

# Create and sign transaction
from trinity.rlp.transactions import create_transaction
from trinity.crypto.addresses import generate_pq_address

recipient = generate_pq_address(pubkey)
tx = create_transaction(
    nonce=0,
    gas_price=1000000000,
    gas=50000,
    to=recipient,
    value=1000000000000000000,  # 1 QRDX
    data=b'',
)

signed_tx = tx.sign_dilithium(privkey)
print(f"Transaction hash: {signed_tx.hash.hex()}")
print(f"Sender address: {signed_tx.sender.hex()}")
```

### Running a Node

```bash
# (TODO) Once integration is complete
trinity --network-id=1337 --data-dir=./qrdx-data --enable-pqc
```

---

## Security Considerations

### Hybrid Mode Rationale
- **Backward Compatibility**: Support existing Ethereum tooling
- **Migration Path**: Users can gradually transition to PQ addresses
- **Network Effect**: Allow mixed transactions in same block
- **Future-Proofing**: Easy to deprecate ECDSA once quantum threat is imminent

### Signature Size Impact
- **Dilithium signatures are large**: 3293 bytes vs 65 bytes (ECDSA)
- **Mitigations**:
  - Higher base gas reflects computational cost
  - Precompiles optimize on-chain verification
  - State tree uses BLAKE3 for efficient hashing
  - Compressed block propagation (TODO)

### Key Management
- **Private key sizes**:
  - ECDSA: 32 bytes
  - Dilithium: 4000 bytes
- **Considerations**:
  - Hardware wallet support (TODO)
  - Secure key storage standards
  - Key derivation (BIP-32 equivalent for PQ)

---

## Performance Targets

### Transaction Throughput
- **Target**: 5,000+ TPS (per whitepaper)
- **Current bottlenecks**:
  - Dilithium verification (~100 microseconds per signature)
  - Larger transaction size
  - State tree updates with BLAKE3

### Optimization Strategies
1. **Batch verification**: Verify multiple Dilithium signatures together
2. **Parallel processing**: Multi-threaded transaction validation
3. **Caching**: Cache verified signatures
4. **Compression**: Compress PQ signatures in block propagation

---

## Contributing

### Code Style
- Follow existing Trinity code conventions
- Type hints for all public functions
- Comprehensive docstrings
- Unit tests for new features

### Pull Request Process
1. Create feature branch from `develop`
2. Implement feature with tests
3. Ensure all tests pass
4. Update CLAUDE.md with changes
5. Submit PR with detailed description

### Testing Requirements
- Unit tests for all PQC operations
- Integration tests for cross-component features
- Performance benchmarks for critical paths
- Security audit for cryptographic code

---

## References

### NIST Post-Quantum Standards
- [FIPS 203: CRYSTALS-Kyber](https://csrc.nist.gov/publications/detail/fips/203/final)
- [FIPS 204: CRYSTALS-Dilithium](https://csrc.nist.gov/publications/detail/fips/204/final)

### Implementation References
- [liboqs-python](https://github.com/open-quantum-safe/liboqs-python)
- [BLAKE3 Specification](https://github.com/BLAKE3-team/BLAKE3-specs)
- [Trinity Client](https://github.com/ethereum/trinity)
- [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf)

### QRDX Resources
- QRDX Whitepaper v2.0 (included in repo)
- QRDX Foundation: research@mail.qrdx.org

---

## Changelog

### 2025-11-06 - Initial Implementation
- ✅ Implemented CRYSTALS-Dilithium (FIPS 204) signatures
- ✅ Implemented CRYSTALS-Kyber (FIPS 203) key encapsulation
- ✅ Implemented BLAKE3 quantum-resistant hashing
- ✅ Created hybrid transaction format (ECDSA + Dilithium)
- ✅ Implemented PQ address generation (33-byte format)
- ✅ Created PQC P2P authentication handshake
- ✅ Implemented QEVM precompiled contracts (0x0A-0x0D)
- ✅ Added comprehensive test suite
- ✅ Updated dependencies (liboqs-python, blake3)


