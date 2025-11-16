# Post-Quantum QRDX Chain Implementation Roadmap

**Version:** 1.0  
**Date:** November 11, 2025  
**Objective:** Transform Trinity Ethereum client into a hybrid classical/post-quantum blockchain with dual signature support (secp256k1 + Dilithium) and PoS consensus.

---

## Executive Summary

This roadmap outlines the systematic transformation of the Trinity Ethereum client into QRDX Chain, a quantum-resistant blockchain supporting:

- **Hybrid Cryptography**: Dual signature validation (ECDSA/secp256k1 + CRYSTALS-Dilithium)
- **Post-Quantum Algorithms**: Dilithium (signatures), Kyber (key encapsulation), BLAKE3 (hashing)
- **Consensus Migration**: Proof-of-Work → Quantum-Resistant Proof-of-Stake (QR-PoS)
- **Enhanced Privacy**: Optional transaction shielding with PQ anonymity (Phase 2)
- **Backward Compatibility**: Support legacy transactions during migration period

**Target Performance**: 5,000+ TPS | 2-second block time | Sub-second finality

---

## Phase 1: Cryptographic Foundation (Months 1-2)

### 1.1 Dependencies & Library Integration

**Files to Modify:**
- `setup.py` - Add PQ dependencies
- `requirements.txt` - Pin versions

**New Dependencies:**
```python
# Post-Quantum Cryptography
"liboqs-python>=0.9.0,<1.0.0",  # CRYSTALS-Dilithium & Kyber (NIST standardized)
"blake3>=0.3.3,<1.0.0",          # BLAKE3 hashing (Rust-backed)

# Alternative/Supplementary:
# "pqcrypto>=0.1.0" - Pure Python fallback
# "cryptography>=41.0.0" - Update for compatibility
```

**Installation Tasks:**
- [ ] Update `setup.py` with PQ dependencies
- [ ] Test installation on Linux (dev container)
- [ ] Verify liboqs shared library compatibility
- [ ] Document build requirements for different platforms

---

### 1.2 Core PQ Crypto Module Structure

**New Directory:** `trinity/crypto/pq/`

```
trinity/crypto/pq/
├── __init__.py           # Public API exports
├── dilithium.py          # Dilithium signature operations
├── kyber.py              # Kyber KEM operations
├── blake3_hash.py        # BLAKE3 hashing utilities
├── keys.py               # Unified key management
├── addresses.py          # PQ address generation
├── constants.py          # Algorithm parameters, key sizes
└── exceptions.py         # PQ-specific exceptions
```

#### 1.2.1 `trinity/crypto/pq/dilithium.py`

**Purpose:** CRYSTALS-Dilithium (FIPS 204) signature operations

**Key Classes:**
```python
class DilithiumPrivateKey:
    """Dilithium private key wrapper"""
    def __init__(self, key_bytes: bytes): ...
    def sign(self, message: bytes) -> bytes: ...
    def public_key(self) -> DilithiumPublicKey: ...
    def to_bytes(self) -> bytes: ...
    @classmethod
    def generate(cls) -> 'DilithiumPrivateKey': ...
    @classmethod
    def from_bytes(cls, data: bytes) -> 'DilithiumPrivateKey': ...

class DilithiumPublicKey:
    """Dilithium public key wrapper"""
    def __init__(self, key_bytes: bytes): ...
    def verify(self, message: bytes, signature: bytes) -> bool: ...
    def to_bytes(self) -> bytes: ...
    @classmethod
    def from_bytes(cls, data: bytes) -> 'DilithiumPublicKey': ...
```

**Implementation Details:**
- Use **Dilithium5** (NIST Level 5, 256-bit security)
- Public key: 2,592 bytes
- Signature: 4,595 bytes
- Deterministic signing for transaction reproducibility

**Library Integration:**
```python
from oqs import Signature

# Initialize Dilithium scheme
dilithium = Signature("Dilithium5")
```

---

#### 1.2.2 `trinity/crypto/pq/kyber.py`

**Purpose:** CRYSTALS-Kyber (FIPS 203) key encapsulation mechanism

**Key Classes:**
```python
class KyberPrivateKey:
    """Kyber private key for key encapsulation"""
    def __init__(self, key_bytes: bytes): ...
    def decapsulate(self, ciphertext: bytes) -> bytes: ...
    def public_key(self) -> KyberPublicKey: ...
    @classmethod
    def generate(cls) -> 'KyberPrivateKey': ...

class KyberPublicKey:
    """Kyber public key for key encapsulation"""
    def __init__(self, key_bytes: bytes): ...
    def encapsulate(self) -> Tuple[bytes, bytes]: ...  # (ciphertext, shared_secret)
    def to_bytes(self) -> bytes: ...
```

**Implementation Details:**
- Use **Kyber1024** (NIST Level 5)
- Public key: 1,568 bytes
- Ciphertext: 1,568 bytes
- Shared secret: 32 bytes

**Use Cases:**
- P2P handshake encryption
- Bridge key exchange
- Optional: Encrypted transaction payloads

---

#### 1.2.3 `trinity/crypto/pq/blake3_hash.py`

**Purpose:** BLAKE3 cryptographic hashing (quantum-resistant)

**Functions:**
```python
def blake3_hash(data: bytes, digest_size: int = 64) -> bytes:
    """Hash data using BLAKE3 with specified output size"""

def blake3_merkle_root(hashes: List[bytes]) -> bytes:
    """Compute Merkle root using BLAKE3"""

def blake3_kdf(
    key: bytes, 
    context: str, 
    output_len: int = 32
) -> bytes:
    """BLAKE3 key derivation function"""
```

**Implementation:**
```python
import blake3

def blake3_hash(data: bytes, digest_size: int = 64) -> bytes:
    """Use 512-bit (64-byte) output for quantum resistance"""
    hasher = blake3.blake3()
    hasher.update(data)
    return hasher.digest(length=digest_size)
```

**Migration Strategy:**
- Phase 1: Parallel hashing (compute both Keccak-256 and BLAKE3)
- Phase 2: Gradual transition to BLAKE3 for new state
- Phase 3: Full BLAKE3 adoption post-migration

---

#### 1.2.4 `trinity/crypto/pq/keys.py`

**Purpose:** Unified key management interface

**Key Classes:**
```python
class HybridPrivateKey:
    """Holds both classical and PQ private keys"""
    def __init__(
        self,
        classical_key: PrivateKey,  # from eth-keys
        pq_key: DilithiumPrivateKey
    ): ...
    
    def sign_hybrid(self, message: bytes) -> HybridSignature: ...
    def sign_classical(self, message: bytes) -> bytes: ...
    def sign_pq(self, message: bytes) -> bytes: ...
    
    @classmethod
    def generate(cls) -> 'HybridPrivateKey': ...
    
    @classmethod
    def from_classical(cls, classical_key: PrivateKey) -> 'HybridPrivateKey':
        """Generate PQ key for existing classical key"""

class HybridSignature:
    """Contains both ECDSA and Dilithium signatures"""
    classical_sig: bytes  # 65 bytes (v, r, s)
    pq_sig: bytes         # ~4,595 bytes
    
    def to_bytes(self) -> bytes: ...
    def validate(self, message: bytes, public_keys: HybridPublicKey) -> bool: ...
```

---

#### 1.2.5 `trinity/crypto/pq/addresses.py`

**Purpose:** PQ address generation and mapping

**Address Formats:**

1. **Classical Ethereum Address** (20 bytes):
   ```
   address = Keccak256(ECDSA_pubkey)[-20:]
   ```

2. **PQ Address** (32 bytes) - **New Format**:
   ```
   pq_address = BLAKE3(Dilithium_pubkey)[:32]
   ```

3. **Hybrid Address Mapping**:
   - Contract-based registry: `classical_address` → `pq_address`
   - On-chain migration tracking
   - Bidirectional lookup

**Functions:**
```python
def generate_pq_address(dilithium_pubkey: DilithiumPublicKey) -> bytes:
    """Generate 32-byte PQ address from Dilithium public key"""
    return blake3_hash(dilithium_pubkey.to_bytes())[:32]

def link_addresses(
    classical_address: bytes,  # 20 bytes
    pq_address: bytes,         # 32 bytes
    signature: bytes           # Proves ownership
) -> bool:
    """Link classical and PQ addresses in registry"""
```

**Address Display:**
- PQ addresses use **bech32m** encoding (like Bitcoin Taproot)
- Prefix: `qrdx1...` (32-byte addresses)
- Example: `qrdx1qw508d6qejxtdg4y5r3zarvary0c5xw7k3jhv9k`

---

### 1.3 Testing Infrastructure

**New Test Files:**

#### `tests/crypto/test_dilithium.py`
```python
def test_dilithium_key_generation(): ...
def test_dilithium_sign_verify(): ...
def test_dilithium_signature_size(): ...
def test_dilithium_deterministic_signing(): ...
def test_dilithium_invalid_signature(): ...
def test_dilithium_key_serialization(): ...
```

#### `tests/crypto/test_kyber.py`
```python
def test_kyber_key_generation(): ...
def test_kyber_encapsulation_decapsulation(): ...
def test_kyber_shared_secret_consistency(): ...
def test_kyber_key_sizes(): ...
```

#### `tests/crypto/test_blake3.py`
```python
def test_blake3_hash_basic(): ...
def test_blake3_variable_output_length(): ...
def test_blake3_merkle_root(): ...
def test_blake3_kdf(): ...
def test_blake3_collision_resistance(): ...
```

#### `tests/crypto/test_hybrid_keys.py`
```python
def test_hybrid_key_generation(): ...
def test_hybrid_signature_validation(): ...
def test_classical_to_hybrid_migration(): ...
def test_pq_address_generation(): ...
def test_address_linking(): ...
```

**Test Vectors:**
- Use NIST Known Answer Tests (KATs) for Dilithium/Kyber
- Include test vectors from FIPS 203/204 specifications

---

## Phase 2: Transaction Layer (Months 3-4)

### 2.1 Transaction Type Extension (EIP-2718 Style)

**Location:** Forked `py-evm` repository (`/workspaces/qrdx-chain/py-evm`)

**New Transaction Types:**

#### **Type 4: Pure PQ Transaction**
```python
# RLP Structure: [chain_id, nonce, gas_limit, to, value, data, pq_pubkey, pq_signature]

class Type4Transaction(BaseTransaction):
    fields = (
        ('chain_id', big_endian_int),
        ('nonce', big_endian_int),
        ('gas_price', big_endian_int),
        ('gas', big_endian_int),
        ('to', address),
        ('value', big_endian_int),
        ('data', binary),
        ('pq_pubkey', binary),      # Dilithium public key (2,592 bytes)
        ('pq_signature', binary),   # Dilithium signature (4,595 bytes)
    )
    
    @property
    def sender(self) -> bytes:
        """Derive sender from PQ signature"""
        message = self.get_message_for_signing()
        pubkey = DilithiumPublicKey.from_bytes(self.pq_pubkey)
        if pubkey.verify(message, self.pq_signature):
            return generate_pq_address(pubkey)
        raise InvalidSignature()
```

#### **Type 5: Hybrid Transaction**
```python
# RLP Structure: [...type4_fields, v, r, s]
# Contains BOTH ECDSA and Dilithium signatures

class Type5Transaction(Type4Transaction):
    fields = Type4Transaction.fields + (
        ('v', big_endian_int),      # ECDSA v
        ('r', big_endian_int),      # ECDSA r
        ('s', big_endian_int),      # ECDSA s
    )
    
    def validate_signatures(self) -> bool:
        """Both signatures must be valid"""
        classical_valid = self.validate_ecdsa()
        pq_valid = self.validate_dilithium()
        return classical_valid and pq_valid
    
    @property
    def sender(self) -> bytes:
        """Return classical address (for compatibility)"""
        return self.recover_ecdsa_sender()
```

**Transaction Size Comparison:**
- Legacy (Type 0): ~110 bytes
- EIP-1559 (Type 2): ~120 bytes
- PQ (Type 4): ~7,400 bytes (67x larger!)
- Hybrid (Type 5): ~7,465 bytes

**Optimization Strategies:**
1. **Signature Aggregation** (Future):
   - Batch multiple transactions with single aggregate PQ signature
   - Similar to BLS signature aggregation in Ethereum 2.0

2. **Compression**:
   - zstd compression for PQ signatures in blocks
   - 30-40% size reduction typical

3. **Witness Data Separation**:
   - Store PQ signatures in separate witness structure
   - Similar to Bitcoin SegWit approach

---

### 2.2 Transaction Pool Modifications

**Files to Modify:**
- `trinity/components/tx_pool/pool.py`
- `trinity/components/tx_pool/validators.py`

**New Validation Logic:**
```python
class PQTransactionValidator:
    def validate_type4_transaction(self, tx: Type4Transaction) -> None:
        """Validate pure PQ transaction"""
        # 1. Check PQ public key format
        if len(tx.pq_pubkey) != DILITHIUM5_PUBKEY_SIZE:
            raise ValidationError("Invalid PQ public key size")
        
        # 2. Verify PQ signature
        message = tx.get_message_for_signing()
        pubkey = DilithiumPublicKey.from_bytes(tx.pq_pubkey)
        if not pubkey.verify(message, tx.pq_signature):
            raise ValidationError("Invalid PQ signature")
        
        # 3. Check address exists in registry
        sender = generate_pq_address(pubkey)
        if not self.state.address_exists(sender):
            raise ValidationError("PQ address not registered")
        
        # 4. Standard checks (nonce, balance, gas)
        self.validate_common(tx, sender)
    
    def validate_type5_transaction(self, tx: Type5Transaction) -> None:
        """Validate hybrid transaction (dual signatures)"""
        # Both signatures must be valid
        # Classical sender must match PQ sender in registry
        classical_sender = tx.recover_ecdsa_sender()
        pq_sender = generate_pq_address(DilithiumPublicKey.from_bytes(tx.pq_pubkey))
        
        if not self.registry.addresses_linked(classical_sender, pq_sender):
            raise ValidationError("Classical and PQ addresses not linked")
```

---

### 2.3 Address Registry Contract

**Purpose:** Map classical ↔ PQ addresses

**Contract Interface:**
```solidity
// Deployed at well-known address: 0x0000000000000000000000000000000000000100

contract AddressRegistry {
    struct AddressLink {
        bytes32 pqAddress;      // 32-byte PQ address
        bytes pqPubkey;         // Dilithium public key
        uint256 migrationBlock; // When migration occurred
        bool isActive;
    }
    
    mapping(address => AddressLink) public classicalToPQ;
    mapping(bytes32 => address) public pqToClassical;
    
    event AddressLinked(
        address indexed classicalAddress,
        bytes32 indexed pqAddress,
        uint256 blockNumber
    );
    
    function linkAddress(
        bytes memory pqPubkey,
        bytes memory pqSignature
    ) external {
        // 1. Verify msg.sender owns classical address
        // 2. Verify PQ signature proves ownership of PQ key
        // 3. Create bidirectional mapping
        bytes32 pqAddr = generatePQAddress(pqPubkey);
        classicalToPQ[msg.sender] = AddressLink({
            pqAddress: pqAddr,
            pqPubkey: pqPubkey,
            migrationBlock: block.number,
            isActive: true
        });
        pqToClassical[pqAddr] = msg.sender;
        emit AddressLinked(msg.sender, pqAddr, block.number);
    }
    
    function getLinkedPQAddress(address classical) external view returns (bytes32) {
        return classicalToPQ[classical].pqAddress;
    }
    
    function getLinkedClassicalAddress(bytes32 pq) external view returns (address) {
        return pqToClassical[pq];
    }
}
```

**Implementation:**
- Pre-deployed at genesis
- Immutable mapping (cannot unlink once linked)
- Gas-optimized for frequent lookups

---

### 2.4 RPC API Extensions

**Files to Modify:**
- `trinity/rpc/modules/eth.py`

**New RPC Methods:**

#### `eth_sendPQTransaction`
```python
async def sendPQTransaction(self, transaction: Dict[str, Any]) -> str:
    """
    Send a Type 4 (pure PQ) transaction
    
    Parameters:
    - from: PQ address (32-byte hex)
    - to: Recipient address
    - value: Wei amount
    - data: Transaction data
    - gas: Gas limit
    - gasPrice: Gas price
    - pqPubkey: Dilithium public key (hex)
    - pqSignature: Dilithium signature (hex)
    
    Returns: Transaction hash
    """
    tx = Type4Transaction(
        chain_id=self.chain_id,
        nonce=await self._get_nonce(transaction['from']),
        gas_price=int(transaction['gasPrice'], 16),
        gas=int(transaction['gas'], 16),
        to=decode_hex(transaction['to']),
        value=int(transaction.get('value', '0x0'), 16),
        data=decode_hex(transaction.get('data', '0x')),
        pq_pubkey=decode_hex(transaction['pqPubkey']),
        pq_signature=decode_hex(transaction['pqSignature']),
    )
    await self.tx_pool.add_transaction(tx)
    return encode_hex(tx.hash)
```

#### `eth_generatePQAddress`
```python
async def generatePQAddress(self) -> Dict[str, str]:
    """
    Generate a new PQ address and key pair
    
    Returns:
    - address: 32-byte PQ address (hex)
    - publicKey: Dilithium public key (hex)
    - privateKey: Dilithium private key (hex) - INSECURE, for testing only
    """
    private_key = DilithiumPrivateKey.generate()
    public_key = private_key.public_key()
    address = generate_pq_address(public_key)
    
    return {
        'address': encode_hex(address),
        'publicKey': encode_hex(public_key.to_bytes()),
        'privateKey': encode_hex(private_key.to_bytes()),  # WARNING: Insecure!
    }
```

#### `eth_migrateAccount`
```python
async def migrateAccount(
    self,
    classicalAddress: str,
    pqPubkey: str,
    pqSignature: str
) -> str:
    """
    Link classical address to PQ address
    
    Returns: Transaction hash of registry call
    """
    # Call AddressRegistry.linkAddress()
    registry_address = to_canonical_address('0x0000000000000000000000000000000000000100')
    data = encode_abi(
        ['bytes', 'bytes'],
        [decode_hex(pqPubkey), decode_hex(pqSignature)]
    )
    
    tx = await self.sendTransaction({
        'from': classicalAddress,
        'to': encode_hex(registry_address),
        'data': encode_hex(data),
        'gas': '0x100000',  # 1M gas
    })
    return tx
```

#### `eth_getAddressMapping`
```python
async def getAddressMapping(self, address: str) -> Dict[str, Optional[str]]:
    """
    Get linked addresses for classical or PQ address
    
    Returns:
    - classicalAddress: 20-byte address (or null)
    - pqAddress: 32-byte address (or null)
    - pqPubkey: Dilithium public key (or null)
    - migrationBlock: Block number (or null)
    """
    registry = self.get_registry_contract()
    
    if len(decode_hex(address)) == 20:
        # Classical address lookup
        result = await registry.functions.classicalToPQ(
            to_canonical_address(address)
        ).call()
        return {
            'classicalAddress': address,
            'pqAddress': encode_hex(result['pqAddress']) if result['isActive'] else None,
            'pqPubkey': encode_hex(result['pqPubkey']) if result['isActive'] else None,
            'migrationBlock': result['migrationBlock'] if result['isActive'] else None,
        }
    else:
        # PQ address lookup
        classical = await registry.functions.pqToClassical(
            decode_hex(address)
        ).call()
        if classical != ZERO_ADDRESS:
            return await self.getAddressMapping(encode_hex(classical))
        return {'classicalAddress': None, 'pqAddress': address, 'pqPubkey': None, 'migrationBlock': None}
```

---

## Phase 3: Consensus Migration (Months 5-7)

### 3.1 Remove PoW Dependencies

**Files to Modify:**
- `trinity/network_configurations.py` - Remove `MiningMethod.Ethash`
- `trinity/config.py` - Remove mining configuration
- Remove all references to `mine_pow_nonce`, `mix_hash`, `nonce` in block headers

**Block Header Changes:**
```python
# OLD (PoW):
class BlockHeader:
    parent_hash: bytes32
    uncles_hash: bytes32
    coinbase: address     # Miner address
    state_root: bytes32
    transaction_root: bytes32
    receipt_root: bytes32
    bloom: bytes256
    difficulty: uint256   # PoW difficulty
    block_number: uint256
    gas_limit: uint256
    gas_used: uint256
    timestamp: uint256
    extra_data: bytes
    mix_hash: bytes32     # PoW ethash mixhash
    nonce: bytes8         # PoW nonce

# NEW (PoS):
class BlockHeader:
    parent_hash: bytes32
    uncles_hash: bytes32  # Always empty (no uncles in PoS)
    proposer: bytes32     # Validator PQ address (32 bytes)
    state_root: bytes32
    transaction_root: bytes32
    receipt_root: bytes32
    bloom: bytes256
    slot: uint64          # Slot number (replaces difficulty)
    block_number: uint256
    gas_limit: uint256
    gas_used: uint256
    timestamp: uint256
    extra_data: bytes
    validator_pubkey: bytes  # Dilithium public key (2,592 bytes)
    validator_signature: bytes  # Dilithium signature (4,595 bytes)
    # signature covers: hash(parent_hash...extra_data)
```

---

### 3.2 QR-PoS Implementation

**New Directory:** `trinity/consensus/qrpos/`

```
trinity/consensus/qrpos/
├── __init__.py
├── constants.py          # Slot time, epoch length, finality params
├── validator.py          # Validator management
├── block_proposal.py     # Block creation with PQ signatures
├── fork_choice.py        # LMD-GHOST fork choice rule
├── finality.py           # Finality gadget (Casper FFG style)
├── rewards.py            # Validator rewards/penalties
└── state.py              # Validator registry state
```

#### 3.2.1 `trinity/consensus/qrpos/constants.py`

```python
# Timing
SLOT_DURATION = 2  # seconds
SLOTS_PER_EPOCH = 32
EPOCH_DURATION = SLOT_DURATION * SLOTS_PER_EPOCH  # 64 seconds

# Validators
MIN_VALIDATOR_STAKE = 32_000 * 10**18  # 32,000 QRDX tokens
MAX_VALIDATORS = 1024
VALIDATOR_ACTIVATION_DELAY = 4  # epochs

# Rewards & Penalties
BASE_REWARD_FACTOR = 64
PROPOSER_REWARD_QUOTIENT = 8
INACTIVITY_PENALTY_QUOTIENT = 2**24

# Finality
FINALITY_THRESHOLD = 2 / 3  # 67% attestations required
JUSTIFIED_CHECKPOINT_AGE = 2  # epochs
```

#### 3.2.2 `trinity/consensus/qrpos/validator.py`

```python
from dataclasses import dataclass
from trinity.crypto.pq import DilithiumPublicKey

@dataclass
class Validator:
    pq_pubkey: DilithiumPublicKey  # Dilithium public key
    pq_address: bytes              # 32-byte PQ address
    stake: int                     # Wei staked
    activation_epoch: int
    exit_epoch: int
    slashed: bool
    effective_balance: int

class ValidatorRegistry:
    def __init__(self, db):
        self.db = db
        self.validators: Dict[bytes, Validator] = {}
    
    def add_validator(
        self,
        pq_pubkey: bytes,
        stake: int,
        current_epoch: int
    ) -> None:
        """Register new validator"""
        if stake < MIN_VALIDATOR_STAKE:
            raise ValueError("Insufficient stake")
        
        pq_address = generate_pq_address(DilithiumPublicKey.from_bytes(pq_pubkey))
        validator = Validator(
            pq_pubkey=DilithiumPublicKey.from_bytes(pq_pubkey),
            pq_address=pq_address,
            stake=stake,
            activation_epoch=current_epoch + VALIDATOR_ACTIVATION_DELAY,
            exit_epoch=2**64 - 1,  # Far future
            slashed=False,
            effective_balance=min(stake, MAX_EFFECTIVE_BALANCE)
        )
        self.validators[pq_address] = validator
    
    def get_active_validators(self, epoch: int) -> List[Validator]:
        """Get validators active in given epoch"""
        return [
            v for v in self.validators.values()
            if v.activation_epoch <= epoch < v.exit_epoch
            and not v.slashed
        ]
    
    def get_proposer(self, slot: int, validators: List[Validator]) -> Validator:
        """Deterministically select block proposer for slot"""
        # Use slot number and validator list to select proposer
        # Weighted by effective balance
        seed = blake3_hash(slot.to_bytes(8, 'big'))
        return self._weighted_random_choice(validators, seed)
```

#### 3.2.3 `trinity/consensus/qrpos/block_proposal.py`

```python
class BlockProposer:
    def __init__(self, validator_key: DilithiumPrivateKey):
        self.validator_key = validator_key
    
    async def propose_block(
        self,
        slot: int,
        parent_hash: bytes,
        transactions: List[SignedTransaction],
        state_root: bytes
    ) -> SignedBlock:
        """Propose new block with PQ signature"""
        
        # 1. Build block header
        header = BlockHeader(
            parent_hash=parent_hash,
            uncles_hash=EMPTY_UNCLE_HASH,
            proposer=generate_pq_address(self.validator_key.public_key()),
            state_root=state_root,
            transaction_root=compute_merkle_root(transactions),
            receipt_root=compute_receipt_root(transactions),
            bloom=compute_bloom(transactions),
            slot=slot,
            block_number=await self.get_block_number(parent_hash) + 1,
            gas_limit=GAS_LIMIT,
            gas_used=sum(tx.gas for tx in transactions),
            timestamp=int(time.time()),
            extra_data=b'QRDX',
            validator_pubkey=self.validator_key.public_key().to_bytes(),
            validator_signature=b'',  # Sign after building
        )
        
        # 2. Sign block header
        signing_root = self.compute_signing_root(header)
        signature = self.validator_key.sign(signing_root)
        header = header.copy(validator_signature=signature)
        
        # 3. Create block
        block = Block(header=header, transactions=transactions, uncles=[])
        return block
    
    def compute_signing_root(self, header: BlockHeader) -> bytes:
        """Compute hash to be signed by validator"""
        # Exclude signature field itself
        return blake3_hash(rlp.encode(header.copy(validator_signature=b'')))
```

#### 3.2.4 `trinity/consensus/qrpos/fork_choice.py`

```python
class LMDGHOSTForkChoice:
    """Latest Message Driven Greedy Heaviest Observed SubTree"""
    
    def __init__(self, validator_registry: ValidatorRegistry):
        self.registry = validator_registry
        self.attestations: Dict[bytes, Set[bytes]] = {}  # block_hash -> validator_addresses
    
    def get_head(self, blocks: List[Block]) -> Block:
        """Get canonical chain head using fork choice rule"""
        # 1. Start from justified checkpoint
        current = self.get_justified_checkpoint()
        
        # 2. Follow heaviest branch (most validator weight)
        while True:
            children = [b for b in blocks if b.parent_hash == current.hash]
            if not children:
                return current
            
            # Calculate weight for each child (sum of attesting validator stakes)
            weights = {
                child: self._calculate_weight(child)
                for child in children
            }
            current = max(children, key=lambda c: weights[c])
    
    def _calculate_weight(self, block: Block) -> int:
        """Sum of effective balance of validators attesting to this block"""
        attesting_validators = self.attestations.get(block.hash, set())
        return sum(
            self.registry.validators[addr].effective_balance
            for addr in attesting_validators
        )
```

---

### 3.3 Validator Staking Contract

**Purpose:** Manage validator deposits and withdrawals

```solidity
contract ValidatorRegistry {
    uint256 public constant MIN_DEPOSIT = 32_000 ether;
    
    struct ValidatorDeposit {
        bytes pqPubkey;        // Dilithium public key
        uint256 amount;
        uint256 depositTime;
        bool active;
    }
    
    mapping(bytes32 => ValidatorDeposit) public validators;
    
    event ValidatorDeposit(
        bytes32 indexed pqAddress,
        bytes pqPubkey,
        uint256 amount
    );
    
    function deposit(bytes calldata pqPubkey) external payable {
        require(msg.value >= MIN_DEPOSIT, "Insufficient deposit");
        require(pqPubkey.length == DILITHIUM_PUBKEY_SIZE, "Invalid pubkey");
        
        bytes32 pqAddress = generatePQAddress(pqPubkey);
        require(!validators[pqAddress].active, "Already registered");
        
        validators[pqAddress] = ValidatorDeposit({
            pqPubkey: pqPubkey,
            amount: msg.value,
            depositTime: block.timestamp,
            active: true
        });
        
        emit ValidatorDeposit(pqAddress, pqPubkey, msg.value);
    }
    
    function withdraw(bytes calldata pqPubkey, bytes calldata signature) external {
        // Withdrawal logic (requires validator exit)
    }
}
```

---

## Phase 4: P2P Protocol Upgrade (Months 8-9)

### 4.1 Hybrid Handshake Protocol

**Files to Modify:**
- `p2p/auth.py` - Authentication logic
- `p2p/handshake.py` - Handshake protocol
- `p2p/ecies.py` - Encryption

**Current Handshake Flow (ECDH-based):**
```
Initiator                          Responder
--------                           ---------
ephemeral_key_i = random()
auth_message = encrypt_with_responder_pubkey(
    signature(ephemeral_key_i),
    ephemeral_key_i_pubkey,
    nonce_i
)
                ---auth_message--->
                                   ephemeral_key_r = random()
                                   ack_message = encrypt_with_initiator_ephemeral(
                                       ephemeral_key_r_pubkey,
                                       nonce_r
                                   )
                <---ack_message----
shared_secret = ECDH(ephemeral_key_i, ephemeral_key_r_pubkey)
aes_key = KDF(shared_secret, nonce_i, nonce_r)
```

**New Hybrid Handshake (ECDH + Kyber):**
```
Initiator                          Responder
--------                           ---------
1. Classical handshake (existing)
2. Kyber key exchange:

kyber_privkey_i = KyberPrivateKey.generate()
                ---kyber_pubkey_i-->
                                   (ciphertext, shared_secret_r) = kyber_pubkey_i.encapsulate()
                <---ciphertext-----
shared_secret_i = kyber_privkey_i.decapsulate(ciphertext)

# Both sides now have same shared_secret
combined_secret = XOR(ecdh_secret, kyber_secret)
aes_key = BLAKE3_KDF(combined_secret)
```

**Implementation:**

```python
# p2p/auth.py

class HybridAuthHandler:
    def __init__(self, privkey: PrivateKey, pq_privkey: Optional[KyberPrivateKey] = None):
        self.classical_key = privkey
        self.pq_key = pq_privkey or KyberPrivateKey.generate()
    
    async def handshake_initiator(self, remote_pubkey: PublicKey) -> HandshakeResult:
        # 1. Classical ECDH handshake
        classical_secret, auth_msg, ack_msg = await self.classical_handshake(remote_pubkey)
        
        # 2. Kyber key exchange
        kyber_secret = await self.kyber_initiator()
        
        # 3. Combine secrets
        combined_secret = xor_bytes(classical_secret, kyber_secret)
        aes_key = blake3_kdf(combined_secret, context="devp2p-v5-hybrid")
        
        return HandshakeResult(aes_key=aes_key, mac_key=...)
    
    async def kyber_initiator(self) -> bytes:
        # Generate Kyber key pair
        kyber_privkey = KyberPrivateKey.generate()
        kyber_pubkey = kyber_privkey.public_key()
        
        # Send public key to responder
        await self.send_message(KyberPubkeyMessage(kyber_pubkey.to_bytes()))
        
        # Receive ciphertext
        ciphertext_msg = await self.receive_message()
        ciphertext = ciphertext_msg.ciphertext
        
        # Decapsulate shared secret
        shared_secret = kyber_privkey.decapsulate(ciphertext)
        return shared_secret
    
    async def kyber_responder(self) -> bytes:
        # Receive public key
        pubkey_msg = await self.receive_message()
        kyber_pubkey = KyberPublicKey.from_bytes(pubkey_msg.pubkey)
        
        # Encapsulate shared secret
        ciphertext, shared_secret = kyber_pubkey.encapsulate()
        
        # Send ciphertext
        await self.send_message(KyberCiphertextMessage(ciphertext))
        
        return shared_secret
```

---

### 4.2 Node Identity & ENR Updates

**Files to Modify:**
- `p2p/kademlia.py` - Node discovery
- `p2p/discovery.py` - Discovery protocol

**Ethereum Node Record (ENR) Extension:**

```python
# Add PQ public key to ENR
class PQNodeRecord(ENR):
    def __init__(
        self,
        sequence: int,
        signature: bytes,
        classical_pubkey: PublicKey,
        pq_pubkey: Optional[DilithiumPublicKey] = None,  # NEW
        **kwargs
    ):
        self.classical_pubkey = classical_pubkey
        self.pq_pubkey = pq_pubkey
        super().__init__(sequence, signature, **kwargs)
    
    def to_dict(self) -> Dict[str, Any]:
        data = super().to_dict()
        if self.pq_pubkey:
            data['pq'] = self.pq_pubkey.to_bytes()
        return data
    
    @property
    def node_id(self) -> bytes:
        """Node ID derived from classical key for backward compatibility"""
        return keccak(self.classical_pubkey.to_bytes())
```

**Migration Strategy:**
- Phase 1: Dual identity (classical + PQ in ENR)
- Phase 2: Prefer PQ peers
- Phase 3: Require PQ identity (deprecate classical-only)

---

## Phase 5: QEVM & Precompiled Contracts (Months 10-11)

### 5.1 PQ Precompiled Contracts

**Location:** Forked `py-evm` → `eth/vm/forks/quantum_resistant/computation.py`

**Precompile Addresses:**
- `0x0A`: Dilithium signature verification
- `0x0B`: Kyber key encapsulation
- `0x0C`: BLAKE3 hashing

#### Precompile 0x0A: Dilithium Verification

```python
def dilithium_verify(computation: ComputationAPI) -> None:
    """
    Input: message (variable) || pubkey (2,592 bytes) || signature (4,595 bytes)
    Output: 1 (valid) or 0 (invalid)
    Gas: 500,000 (expensive due to PQ verification)
    """
    input_data = computation.msg.data
    
    # Parse input
    signature_offset = len(input_data) - DILITHIUM5_SIGNATURE_SIZE
    pubkey_offset = signature_offset - DILITHIUM5_PUBKEY_SIZE
    
    message = input_data[:pubkey_offset]
    pubkey_bytes = input_data[pubkey_offset:signature_offset]
    signature_bytes = input_data[signature_offset:]
    
    # Verify
    try:
        pubkey = DilithiumPublicKey.from_bytes(pubkey_bytes)
        is_valid = pubkey.verify(message, signature_bytes)
        computation.output = b'\x01' if is_valid else b'\x00'
    except Exception:
        computation.output = b'\x00'
    
    # Charge gas
    computation.consume_gas(500_000, reason="Dilithium verification")
```

#### Precompile 0x0B: Kyber Encapsulation

```python
def kyber_encapsulate(computation: ComputationAPI) -> None:
    """
    Input: pubkey (1,568 bytes)
    Output: ciphertext (1,568 bytes) || shared_secret (32 bytes)
    Gas: 100,000
    """
    pubkey_bytes = computation.msg.data
    
    try:
        pubkey = KyberPublicKey.from_bytes(pubkey_bytes)
        ciphertext, shared_secret = pubkey.encapsulate()
        computation.output = ciphertext + shared_secret
    except Exception:
        computation.output = b''
    
    computation.consume_gas(100_000, reason="Kyber encapsulation")
```

#### Precompile 0x0C: BLAKE3 Hash

```python
def blake3_hash_precompile(computation: ComputationAPI) -> None:
    """
    Input: data (variable) || output_length (1 byte, default 32)
    Output: BLAKE3 hash (variable length)
    Gas: 60 + 12 per word (similar to SHA256)
    """
    input_data = computation.msg.data
    
    if len(input_data) == 0:
        output_length = 32
        data = b''
    else:
        output_length = input_data[-1]
        data = input_data[:-1]
    
    hash_output = blake3_hash(data, digest_size=output_length)
    computation.output = hash_output
    
    # Gas calculation
    word_count = (len(data) + 31) // 32
    gas_cost = 60 + 12 * word_count
    computation.consume_gas(gas_cost, reason="BLAKE3 hash")
```

---

### 5.2 New EVM Opcodes (Optional)

**PQRECOVER (0xE0):** Recover PQ address from signature
```
Stack input: message_offset, message_size, signature_offset, pubkey_offset
Stack output: pq_address (32 bytes)
Gas: 500,000
```

**PQCALL (0xE1):** Call with PQ signature validation
```
Similar to CALL but validates PQ signature before execution
```

---

### 5.3 Shielded Transactions (Phase 2 - Future)

**Purpose:** Optional transaction privacy with PQ anonymity

**Approach:** zk-SNARKs with PQ-resistant constructions

**Library:** `libsnark` or `bellman` (Rust) with lattice-based NIZKs

**Transaction Type 6: Shielded Transaction**
```python
class Type6Transaction(BaseTransaction):
    # Public inputs
    nullifier: bytes32      # Spent note identifier
    commitment: bytes32     # New note commitment
    
    # Zero-knowledge proof
    proof: bytes            # PQ-resistant NIZK proof
    
    # Encrypted for recipient
    encrypted_note: bytes   # Kyber-encrypted note details
```

**Implementation Timeline:** Months 12-16 (separate phase)

---

## Phase 6: Testing & Integration (Month 12)

### 6.1 Unit Tests

**Coverage Requirements:**
- PQ crypto primitives: >95%
- Transaction validation: >90%
- Consensus logic: >85%
- P2P protocol: >80%

**Test Files:**
```
tests/crypto/
├── test_dilithium.py          # 20+ tests
├── test_kyber.py              # 15+ tests
├── test_blake3.py             # 10+ tests
└── test_hybrid_keys.py        # 25+ tests

tests/transactions/
├── test_type4_transactions.py # Pure PQ
├── test_type5_transactions.py # Hybrid
└── test_address_registry.py   # Mapping

tests/consensus/
├── test_validator_registry.py
├── test_block_proposal.py
├── test_fork_choice.py
└── test_finality.py

tests/p2p/
├── test_hybrid_handshake.py
└── test_pq_enr.py

tests/integration/
├── test_end_to_end_pq_transaction.py
├── test_hybrid_transaction.py
├── test_account_migration.py
└── test_qevm_precompiles.py
```

---

### 6.2 Integration Tests

**Scenario 1: Classical → PQ Migration**
```python
async def test_account_migration():
    # 1. Create classical account
    classical_key = PrivateKey(os.urandom(32))
    classical_addr = classical_key.public_key.to_address()
    
    # 2. Fund account
    await chain.fund_account(classical_addr, 100 * 10**18)
    
    # 3. Generate PQ key
    pq_key = DilithiumPrivateKey.generate()
    pq_addr = generate_pq_address(pq_key.public_key())
    
    # 4. Link addresses
    tx = await registry.link_address(
        classical_key, pq_key.public_key(), pq_key.sign(b'migration')
    )
    await chain.mine_block()
    
    # 5. Send hybrid transaction
    hybrid_tx = create_type5_transaction(
        classical_key, pq_key, recipient, value
    )
    await chain.add_transaction(hybrid_tx)
    await chain.mine_block()
    
    # 6. Verify balance transferred
    assert await chain.get_balance(recipient) == value
```

**Scenario 2: Pure PQ Transaction Flow**
```python
async def test_pure_pq_transaction():
    # 1. Generate PQ accounts
    sender_key = DilithiumPrivateKey.generate()
    sender_addr = generate_pq_address(sender_key.public_key())
    recipient_addr = generate_pq_address(DilithiumPrivateKey.generate().public_key())
    
    # 2. Fund sender (via registry migration first)
    await fund_pq_account(sender_addr, 100 * 10**18)
    
    # 3. Create Type 4 transaction
    tx = Type4Transaction(
        chain_id=1,
        nonce=0,
        gas_price=1 * 10**9,
        gas=21000,
        to=recipient_addr,
        value=50 * 10**18,
        data=b'',
        pq_pubkey=sender_key.public_key().to_bytes(),
        pq_signature=sender_key.sign(tx_message),
    )
    
    # 4. Validate and mine
    await chain.add_transaction(tx)
    await chain.mine_block()
    
    # 5. Verify
    assert await chain.get_balance(recipient_addr) == 50 * 10**18
```

**Scenario 3: QR-PoS Consensus**
```python
async def test_qrpos_consensus():
    # 1. Register validators
    validators = [DilithiumPrivateKey.generate() for _ in range(10)]
    for val_key in validators:
        await validator_registry.deposit(
            val_key.public_key().to_bytes(),
            value=32_000 * 10**18
        )
    
    # 2. Advance to activation epoch
    for _ in range(4 * 32):  # 4 epochs
        await chain.advance_slot()
    
    # 3. Propose blocks
    for slot in range(100):
        proposer = validator_registry.get_proposer(slot)
        block = await proposer.propose_block(slot, transactions=[])
        await chain.import_block(block)
        
        # Verify signature
        assert verify_block_signature(block, proposer.public_key())
    
    # 4. Check finality
    finalized_block = chain.get_finalized_block()
    assert finalized_block.slot >= 64  # At least 2 epochs finalized
```

---

### 6.3 Performance Benchmarks

**Target Metrics:**
- **Block Time**: 2 seconds
- **Finality**: <5 seconds (2-3 blocks)
- **TPS**: 5,000+ transactions per second
- **P2P Latency**: <100ms additional overhead from Kyber
- **Signature Verification**: <10ms for Dilithium
- **State Growth**: <50% additional overhead vs classical

**Benchmark Tests:**
```python
def benchmark_dilithium_signing():
    key = DilithiumPrivateKey.generate()
    message = os.urandom(100)
    
    start = time.time()
    for _ in range(1000):
        signature = key.sign(message)
    elapsed = time.time() - start
    
    print(f"Dilithium signing: {elapsed/1000*1000:.2f}ms per signature")
    # Target: <5ms

def benchmark_dilithium_verification():
    key = DilithiumPrivateKey.generate()
    pubkey = key.public_key()
    message = os.urandom(100)
    signature = key.sign(message)
    
    start = time.time()
    for _ in range(1000):
        pubkey.verify(message, signature)
    elapsed = time.time() - start
    
    print(f"Dilithium verification: {elapsed/1000*1000:.2f}ms per signature")
    # Target: <10ms
```

---

## Phase 7: Deployment & Migration (Ongoing)

### 7.1 Testnet Deployment

**Testnet Phases:**

1. **Devnet** (Internal, 1 month):
   - Single validator
   - Test all transaction types
   - Debug consensus

2. **Public Testnet** (3 months):
   - 50-100 validators
   - Open participation
   - Faucet for test tokens
   - Explorer and tooling

3. **Mainnet Shadow Fork** (1 month):
   - Mirror mainnet state
   - Test migration at scale
   - Performance tuning

4. **Mainnet Launch**:
   - Genesis validators (50-100)
   - Gradual onboarding
   - Migration tools live

---

### 7.2 Migration Tools

**Wallet Integration:**
```javascript
// MetaMask-style wallet adapter
class QRDXWallet {
    async migrateAccount(classicalPrivateKey) {
        // 1. Generate PQ key pair
        const pqKey = await generateDilithiumKey();
        
        // 2. Create migration signature
        const migrationMessage = createMigrationMessage(
            classicalPrivateKey.address,
            pqKey.publicKey
        );
        const pqSignature = await pqKey.sign(migrationMessage);
        
        // 3. Submit to registry
        const tx = await registryContract.linkAddress(
            pqKey.publicKey,
            pqSignature
        );
        await tx.wait();
        
        // 4. Store PQ key securely
        await this.keystore.saveKey(pqKey, password);
        
        return {
            classicalAddress: classicalPrivateKey.address,
            pqAddress: generatePQAddress(pqKey.publicKey)
        };
    }
}
```

**CLI Migration Tool:**
```bash
# Install
pip install qrdx-migration-tool

# Migrate account
qrdx-migrate \
    --keystore /path/to/classical/keystore.json \
    --password-file password.txt \
    --rpc-url https://mainnet.qrdx.network

# Output:
# ✓ Classical address: 0x742d35Cc6634C0532925a3b8...
# ✓ PQ address: qrdx1qw508d6qejxtdg4y5r3zarvary...
# ✓ Migration transaction: 0xabc123...
# ✓ Confirmed in block 12345
```

---

### 7.3 Monitoring & Observability

**Metrics to Track:**
```python
# Prometheus metrics
pq_transactions_total = Counter('pq_transactions_total', 'Total PQ transactions')
hybrid_transactions_total = Counter('hybrid_transactions_total', 'Total hybrid transactions')
classical_transactions_total = Counter('classical_transactions_total', 'Total classical transactions')

dilithium_verification_duration = Histogram('dilithium_verification_seconds', 'Dilithium verification time')
kyber_handshake_duration = Histogram('kyber_handshake_seconds', 'Kyber handshake time')

active_validators = Gauge('active_validators', 'Number of active validators')
finalized_epoch = Gauge('finalized_epoch', 'Latest finalized epoch')

migration_rate = Counter('migrations_total', 'Total account migrations')
```

---

## Risk Mitigation & Contingency Plans

### Technical Risks

**Risk 1: PQ Library Vulnerabilities**
- **Mitigation**: Use NIST-standardized algorithms (Dilithium, Kyber)
- **Contingency**: Maintain classical fallback for critical operations
- **Monitoring**: Security audit schedule (quarterly)

**Risk 2: Performance Degradation**
- **Mitigation**: Signature aggregation, compression, optimization
- **Contingency**: Adjust block time if needed (2s → 3s)
- **Monitoring**: Real-time TPS tracking, alerting at <3000 TPS

**Risk 3: State Growth Explosion**
- **Mitigation**: State expiry (EIP-4444 style), pruning
- **Contingency**: Increase validator hardware requirements
- **Monitoring**: State size tracking, alert at >1TB

### Ecosystem Risks

**Risk 4: Low Migration Adoption**
- **Mitigation**: Incentives (airdrop for early migrators), education
- **Contingency**: Extend hybrid period (1 year → 2 years)
- **Monitoring**: Migration rate metrics

**Risk 5: Wallet/Tooling Fragmentation**
- **Mitigation**: Reference implementations, SDKs, documentation
- **Contingency**: Core team maintains official wallet
- **Monitoring**: Ecosystem tool compatibility testing

---

## Success Criteria

### Phase 1 (Foundation)
- ✅ All PQ crypto tests passing (>95% coverage)
- ✅ Dilithium signing/verification <10ms
- ✅ BLAKE3 hashing integrated

### Phase 2 (Transactions)
- ✅ Type 4 & 5 transactions validated
- ✅ Address registry contract deployed
- ✅ RPC methods functional

### Phase 3 (Consensus)
- ✅ QR-PoS producing blocks on testnet
- ✅ Finality achieved within 5 seconds
- ✅ No PoW dependencies remain

### Phase 4 (P2P)
- ✅ Hybrid handshake working
- ✅ PQ ENR support
- ✅ Network stable with 100+ nodes

### Phase 5 (QEVM)
- ✅ All precompiles tested
- ✅ Gas costs calibrated
- ✅ Integration tests passing

### Phase 6 (Testing)
- ✅ All integration tests passing
- ✅ Performance benchmarks met
- ✅ Security audit completed

### Phase 7 (Deployment)
- ✅ Mainnet launched
- ✅ >10% accounts migrated in 3 months
- ✅ >5000 TPS sustained

---

## Timeline Summary

| Phase | Duration | Key Deliverables |
|-------|----------|------------------|
| 1. Foundation | 2 months | PQ crypto library, tests |
| 2. Transactions | 2 months | Type 4/5 transactions, RPC API |
| 3. Consensus | 3 months | QR-PoS, validator registry |
| 4. P2P | 2 months | Hybrid handshake, PQ ENR |
| 5. QEVM | 2 months | Precompiles, opcodes |
| 6. Testing | 1 month | Full test coverage, benchmarks |
| 7. Deployment | Ongoing | Testnet → Mainnet |

**Total Development Time:** ~12 months
**Mainnet Target:** Q4 2026

---

## Next Steps (Immediate Actions)

1. **Set up development environment**
   - Install liboqs-python, blake3
   - Configure py-evm fork

2. **Implement PQ crypto foundation**
   - Create `trinity/crypto/pq/` module
   - Build Dilithium wrapper
   - Write unit tests

3. **Design transaction format**
   - Define Type 4/5 RLP structure
   - Create transaction builders
   - Test serialization

4. **Prototype QR-PoS**
   - Simple validator registry
   - Block proposal with signatures
   - Basic fork choice

5. **Document & Review**
   - Architecture decision records (ADRs)
   - Security review
   - Community feedback

---

## Appendix A: Algorithm Specifications

### CRYSTALS-Dilithium (FIPS 204)

**Security Level 5:**
- Public Key: 2,592 bytes
- Secret Key: 4,864 bytes
- Signature: 4,595 bytes
- Security: ~256-bit classical, ~256-bit quantum

**Parameters:**
- q = 8,380,417 (modulus)
- d = 13 (dropped bits)
- τ = 60 (number of ±1's in c)
- γ₁ = 2^19 (coefficient range)
- γ₂ = (q-1)/32

### CRYSTALS-Kyber (FIPS 203)

**Security Level 5 (Kyber1024):**
- Public Key: 1,568 bytes
- Secret Key: 3,168 bytes
- Ciphertext: 1,568 bytes
- Shared Secret: 32 bytes
- Security: ~256-bit classical, ~256-bit quantum

### BLAKE3

**Properties:**
- Parallelizable (uses AVX-512 on x86)
- Arbitrary output length
- Secure against quantum attacks (hash function)
- Faster than SHA3, Blake2

---

## Appendix B: Gas Cost Analysis

**Transaction Costs:**

| Transaction Type | Size | Gas (EIP-2028) | Total Cost (20 gwei) |
|------------------|------|----------------|----------------------|
| Legacy (Type 0) | 110 bytes | 21,000 + 1,760 | ~$0.50 |
| EIP-1559 (Type 2) | 120 bytes | 21,000 + 1,920 | ~$0.55 |
| PQ (Type 4) | 7,400 bytes | 21,000 + 118,400 | ~$3.20 |
| Hybrid (Type 5) | 7,465 bytes | 21,000 + 119,440 | ~$3.25 |

**Cost per byte:** 16 gas (non-zero byte, EIP-2028)

**Mitigation:**
- Reduce gas cost for PQ signatures (new EIP)
- Signature aggregation reduces per-tx cost
- Compression (30% reduction → ~$2.25/tx)

---

## Appendix C: References

1. **NIST Post-Quantum Cryptography Standards**
   - FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM / Kyber)
   - FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA / Dilithium)
   - FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA / SPHINCS+)

2. **Ethereum Specifications**
   - EIP-2718: Typed Transaction Envelope
   - EIP-2930: Optional Access Lists
   - EIP-1559: Fee Market
   - Ethereum 2.0 Beacon Chain Spec

3. **Libraries**
   - liboqs: https://github.com/open-quantum-safe/liboqs
   - liboqs-python: https://github.com/open-quantum-safe/liboqs-python
   - blake3: https://github.com/BLAKE3-team/BLAKE3

4. **Research Papers**
   - "CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme" (2021)
   - "CRYSTALS-Kyber: A CCA-Secure Module-Lattice-Based KEM" (2021)
   - "Post-Quantum Blockchain" - Various academic papers

---

**Document Status:** Living Document
**Last Updated:** November 11, 2025
**Next Review:** Monthly during development

---

*This roadmap is subject to change based on research findings, community feedback, and technical constraints discovered during implementation.*
