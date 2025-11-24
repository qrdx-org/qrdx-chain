# Analysis: QRDX Chain Architecture

## Existing Codebase Analysis

### Repository Structure
- **Base**: Trinity (archived Ethereum client) + py-evm (Python EVM implementation)
- **Language**: Python 3.8+
- **Architecture**: Modular design with clear separation of concerns
- **Key Components**:
  - `py-evm/eth/`: Core Ethereum implementation
  - `py-evm/eth/vm/`: Virtual machine and fork implementations
  - `py-evm/eth/rlp/`: RLP serialization for transactions/blocks
  - `trinity/`: Client implementation (networking, syncing)

### Patterns Identified

#### 1. VM Fork Pattern
- Each Ethereum fork has dedicated directory: `eth/vm/forks/{fork_name}/`
- Forks inherit from previous forks (e.g., Shanghai extends Cancun)
- Components: `__init__.py`, `state.py`, `computation.py`, `opcodes.py`
- Precompiles defined in computation class

#### 2. Transaction Pattern
- Legacy transactions: `eth/vm/forks/{fork}/transactions.py`
- Typed transactions: Separate classes for each EIP-2718 type
- Fields: RLP serializable with specific sedes
- APIs: `SignedTransactionAPI`, `UnsignedTransactionAPI`, `TransactionBuilderAPI`

#### 3. Block Header Pattern
- Headers: `eth/rlp/headers.py`
- Fields evolve with forks (PoW → PoS transition in Ethereum)
- Mining headers for signing, full headers with signatures
- Hash calculation: Ethereum uses Keccak256

#### 4. Consensus Pattern
- PoW consensus in original code
- Validator sets, attestations would be new for PoS
- Need to implement from scratch based on Ethereum 2.0 patterns

### Key Conventions

#### Code Style
- Type hints throughout
- Abstract base classes in `eth/abc.py`
- RLP serialization for all network objects
- Cached properties for expensive computations

#### Testing
- Pytest framework
- Integration tests in `tests/`
- Unit tests alongside implementation
- Fixtures for common test data

#### Dependencies
- `rlp`: Recursive Length Prefix encoding
- `eth-typing`: Ethereum types
- `eth-utils`: Utilities
- `eth-keys`: Cryptography (to be replaced)
- `eth-hash`: Hashing (to be replaced)

## QRDX-Specific Architecture

### Quantum-Resistant Crypto Module
**Location**: `py-evm/eth/crypto/`

**Components**:
- `dilithium.py`: ML-DSA-65 signatures (4,032 + 1,952 bytes keys, 3,309 byte signatures)
- `kyber.py`: ML-KEM-768 KEM (2,400 + 1,184 bytes keys, 1,088 byte ciphertext)
- `blake3_hash.py`: BLAKE3 hashing (32-byte output)
- `keys.py`: High-level API for key management
- `addresses.py`: Address derivation from Dilithium public keys

**Design Decisions**:
- Use liboqs-python for NIST-standardized algorithms
- Maintain similar API to eth-keys for compatibility
- BLAKE3 replaces Keccak256 throughout

### Transaction Architecture
**Location**: `py-evm/eth/rlp/qrdx_transactions.py`

**Key Changes**:
- Replace (v, r, s) with (public_key, signature)
- Public key: 1,952 bytes (vs 33 bytes ECDSA)
- Signature: 3,309 bytes (vs 65 bytes ECDSA)
- Total transaction size: ~5.2 KB (vs ~110 bytes)
- Transaction type ID: 0x7f

**Trade-offs**:
- 47x size increase acceptable given 2s blocks and 50M gas limit
- Provides quantum security
- Smart contracts can verify via precompile

### Block Header Architecture
**Location**: `py-evm/eth/rlp/qrdx_headers.py`

**Removed Fields** (PoW):
- `difficulty`
- `nonce`
- `mix_hash`

**Added Fields** (QR-PoS):
- `slot`: 2-second time slots
- `validator_index`: 0-149
- `validator_signature`: 3,309-byte Dilithium signature

**Size**: ~3.7 KB per header (vs ~500 bytes Ethereum)

### Consensus Architecture
**Location**: `py-evm/eth/consensus/qrpos.py`

**Components**:
- `Validator`: Validator state with stake tracking
- `ValidatorSet`: Manages 150 validators
- `ProposerSelection`: Stake-weighted random selection
- `Attestation`: Validator votes for blocks
- `AttestationPool`: Collects attestations
- `FinalityGadget`: BFT finality with 2/3 supermajority

**Parameters**:
- 150 validators (fixed set size)
- 2-second slots
- 32 slots per epoch (64 seconds)
- Single-slot finality (if 2/3 attest)
- 5% slashing penalty

### VM Fork Architecture
**Location**: `py-evm/eth/vm/forks/qrdx/`

**Precompiles** (0x09-0x0c):
- `0x09`: Dilithium verify (50,000 gas)
- `0x0a`: Kyber encapsulate (30,000 gas)
- `0x0b`: Kyber decapsulate (30,000 gas)
- `0x0c`: BLAKE3 hash (60 + 12/word gas)

**Inheritance**: QRDX extends Shanghai fork
- Keeps all Shanghai features
- Adds quantum-resistant precompiles
- Same opcodes, modified gas costs for PQ ops

## Integration Points

### 1. Transaction Signing Flow
```
UnsignedTransaction 
  → create_transaction_signature() [uses Dilithium]
  → QRDXTransaction
  → validate_transaction_signature() [verifies Dilithium]
  → extract_transaction_sender() [derives from public key]
```

### 2. Block Production Flow
```
Validator selected via ProposerSelection
  → Creates QRDXMiningHeader
  → Signs with Dilithium private key
  → Produces QRDXBlockHeader
  → Other validators create Attestations
  → FinalityGadget checks 2/3 majority
```

### 3. Smart Contract Flow
```
Contract calls precompile (e.g., 0x09)
  → QRDXVM routes to DilithiumVerifyPrecompile
  → Executes verification
  → Returns result to contract
  → Charges appropriate gas
```

## Security Considerations

### Quantum Resistance
- All signatures: Dilithium (NIST Level 3)
- All encryption: Kyber (NIST Level 3)
- All hashing: BLAKE3 (quantum-resistant)
- No ECDSA, RSA, or Keccak256 in critical paths

### Slashing Conditions
- Double signing (proposing conflicting blocks)
- Invalid attestations
- Downtime penalties (future work)

### Gas Economics
- Higher base gas for PQ operations
- Precompile gas costs calibrated for security
- Transaction intrinsic gas: 30,000 (vs 21,000)

## Performance Characteristics

### Transaction Throughput
- Block time: 2 seconds
- Block gas limit: 50,000,000
- Average tx gas: ~50,000
- **Theoretical max**: ~1,000 tx/block = 500 TPS
- **Target**: 5,000+ TPS (requires optimization)

### Storage Requirements
- Transaction: ~5.2 KB (vs 110 bytes)
- Block header: ~3.7 KB (vs 500 bytes)
- Attestations: 3,309 bytes each
- **Estimated**: ~10x Ethereum storage requirements

### Network Bandwidth
- Block propagation: ~200 KB blocks (with full attestations)
- 2-second slots = manageable on modern networks
- Attestation gossip: 150 validators × 3.3 KB = ~490 KB per slot
