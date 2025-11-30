# QR-PoS Validator Next Phase Implementation

## Current Status (Completed ✅)

### Infrastructure
- ✅ 2-node testnet running with P2P connectivity
- ✅ Validator component integrated into Trinity
- ✅ Validator service ticking every 2 seconds
- ✅ Proposer selection working (slot % 150)
- ✅ Dilithium3 key generation working
- ✅ Python 3.12 compatibility fixed

### What's Working
- Validators determine when it's their turn to propose
- Log messages confirm proposal attempts
- Service lifecycle managed properly
- Slots incrementing correctly

### What's NOT Working Yet
- ❌ No actual blocks being created
- ❌ No blocks being broadcast to peers
- ❌ No blocks being imported to chain
- ❌ Chain height stuck at 0 (genesis only)

## Next Phase: Block Production Pipeline

### Phase 1: Block Building (High Priority)
**Goal**: Create actual block objects when validator is proposer

#### 1.1 Access Chain State
**Location**: `trinity/components/builtin/qrpos_validator/component.py`

Need to:
- Get reference to the chain database via event bus
- Access current chain head
- Query pending transactions from mempool
- Get validator's Dilithium public key for block header

**Implementation**:
```python
from trinity.db.eth1.header import (
    BaseAsyncHeaderDB,
)
from eth.rlp.headers import BlockHeader
from eth.vm.forks.istanbul import IstanbulVM  # Or appropriate fork

async def _get_chain_head(self) -> BlockHeader:
    """Get current chain head from DB."""
    # Request from DB manager via event bus
    # Return latest block header
    
async def _get_pending_transactions(self) -> List[Transaction]:
    """Get transactions from mempool."""
    # Query transaction pool component
    # Return list of transactions to include
```

#### 1.2 Build Block Header
**Location**: `trinity/components/builtin/qrpos_validator/component.py`

Create QR-PoS specific block header:
```python
async def _build_block_header(
    self,
    parent_header: BlockHeader,
    transactions: List[Transaction],
) -> BlockHeader:
    """Build new block header with QR-PoS fields."""
    
    # Standard fields
    block_number = parent_header.block_number + 1
    timestamp = int(time.time())
    gas_limit = parent_header.gas_limit
    
    # QR-PoS specific fields (in extra_data)
    slot_number = self.current_slot
    validator_index = self.validator_index
    proposer_pubkey = self.validator_key.public_key().to_bytes()
    
    # Pack QR-PoS data into extra_data
    extra_data = encode_qrpos_extra_data({
        'slot': slot_number,
        'validator_index': validator_index,
        'proposer_pubkey': proposer_pubkey[:32],  # First 32 bytes for ID
    })
    
    # Create unsigned header
    header = BlockHeader(
        parent_hash=parent_header.hash,
        uncles_hash=EMPTY_UNCLE_HASH,
        coinbase=Address(proposer_pubkey[:20]),  # Use pubkey as coinbase
        state_root=compute_state_root(parent_header, transactions),
        transaction_root=compute_transaction_root(transactions),
        receipt_root=compute_receipt_root(transactions),
        bloom=compute_bloom(transactions),
        difficulty=0,  # QR-PoS has no PoW difficulty
        block_number=block_number,
        gas_limit=gas_limit,
        gas_used=compute_gas_used(transactions),
        timestamp=timestamp,
        extra_data=extra_data,
        mix_hash=Hash32(b'\x00' * 32),  # Not used in QR-PoS
        nonce=b'\x00' * 8,  # Not used in QR-PoS
    )
    
    return header
```

#### 1.3 Sign Block with Dilithium
**Location**: `trinity/components/builtin/qrpos_validator/component.py`

```python
def _sign_block(self, header: BlockHeader) -> bytes:
    """Sign block header with Dilithium private key."""
    # Serialize header for signing
    header_bytes = rlp.encode(header)
    
    # Sign with Dilithium key (3,309 byte signature)
    signature = self.validator_key.sign(header_bytes)
    
    return signature
```

#### 1.4 Store Signature
Need to store Dilithium signature with block. Options:

**Option A**: Extend BlockHeader class (requires fork)
```python
class QRPoSBlockHeader(BlockHeader):
    fields = BlockHeader.fields + [
        ('dilithium_signature', Binary(3309, 3309)),
    ]
```

**Option B**: Store in database separately
```python
# In validator component
await self._store_block_signature(block_hash, signature)
```

**Option C**: Include in extra_data (limited to 32 bytes - won't fit)

**Recommendation**: Option A - clean, proper fork implementation

### Phase 2: Block Broadcasting (High Priority)
**Goal**: Send newly created blocks to connected peers

#### 2.1 Create Block Broadcast Event
**Location**: `trinity/protocol/eth/events.py`

```python
from lahja import BaseEvent
from eth.abc import BlockAPI

class NewBlockEvent(BaseEvent):
    """Event broadcast when validator creates new block."""
    
    def __init__(self, block: BlockAPI, signature: bytes):
        self.block = block
        self.signature = signature
```

#### 2.2 Broadcast via Event Bus
**Location**: `trinity/components/builtin/qrpos_validator/component.py`

```python
async def _propose_block(self) -> None:
    """Propose a new block for the current slot."""
    try:
        logger.info(f"Validator {self.validator_index} building block for slot {self.current_slot}")
        
        # Get chain state
        parent_header = await self._get_chain_head()
        transactions = await self._get_pending_transactions()
        
        # Build block
        header = await self._build_block_header(parent_header, transactions)
        signature = self._sign_block(header)
        
        # Create full block
        block = Block(header, transactions, [])  # No uncles in QR-PoS
        
        # Import locally first
        await self._import_block_locally(block, signature)
        
        # Broadcast to peers
        await self.event_bus.broadcast(
            NewBlockEvent(block, signature),
            TO_NETWORKING_BROADCAST_CONFIG
        )
        
        logger.info(
            f"Validator {self.validator_index} successfully proposed block "
            f"#{block.number} for slot {self.current_slot}"
        )
        
    except Exception as e:
        logger.error(
            f"Validator {self.validator_index} failed to propose block: {e}",
            exc_info=True
        )
```

#### 2.3 Peer Protocol Handler
**Location**: `trinity/protocol/eth/peer.py`

Add handler for receiving QR-PoS blocks:
```python
class ETHPeer:
    async def send_new_block(self, block: BlockAPI, signature: bytes) -> None:
        """Send new QR-PoS block to peer."""
        # Encode block + signature
        # Send via ETH protocol NewBlock message
        # Custom encoding for large Dilithium signature
```

### Phase 3: Block Validation & Import (High Priority)
**Goal**: Receive and validate blocks from peers

#### 3.1 QR-PoS Validator Class
**Location**: `py-evm/eth/consensus/qrpos.py`

```python
class QRPoSValidator:
    """Validates QR-PoS blocks."""
    
    def validate_block(
        self,
        block: BlockAPI,
        signature: bytes,
        validator_set: ValidatorSet,
    ) -> None:
        """Validate QR-PoS block and signature."""
        
        # Extract QR-PoS data from extra_data
        qrpos_data = decode_qrpos_extra_data(block.header.extra_data)
        slot = qrpos_data['slot']
        validator_index = qrpos_data['validator_index']
        
        # Verify correct proposer
        expected_proposer = slot % len(validator_set.validators)
        if validator_index != expected_proposer:
            raise ValidationError(f"Wrong proposer: expected {expected_proposer}, got {validator_index}")
        
        # Get validator public key
        validator = validator_set.validators[validator_index]
        public_key = DilithiumPublicKey(validator.pubkey)
        
        # Verify Dilithium signature
        header_bytes = rlp.encode(block.header)
        if not public_key.verify(header_bytes, signature):
            raise ValidationError("Invalid Dilithium signature")
        
        # Validate slot timing
        genesis_time = qrpos_data.get('genesis_time', 0)
        expected_slot = (block.header.timestamp - genesis_time) // SLOT_DURATION
        if slot != expected_slot:
            raise ValidationError(f"Invalid slot: expected {expected_slot}, got {slot}")
```

#### 3.2 Chain Import Handler
**Location**: `trinity/components/builtin/syncer/component.py` or new component

```python
class QRPoSBlockImporter:
    """Handles importing QR-PoS blocks."""
    
    async def import_block(
        self,
        block: BlockAPI,
        signature: bytes,
    ) -> None:
        """Import and validate QR-PoS block."""
        
        # Validate block
        validator = QRPoSValidator()
        validator.validate_block(block, signature, self.validator_set)
        
        # Import to chain
        await self.chain.import_block(block)
        
        # Store signature
        await self.db.store_block_signature(block.hash, signature)
        
        logger.info(f"Imported block #{block.number} from validator {validator_index}")
```

### Phase 4: Chain Progression Testing (Critical)
**Goal**: Verify blocks are being added and chain height increases

#### 4.1 Monitoring Tools
Create script to monitor chain:
```bash
#!/bin/bash
# scripts/monitor_chain.sh

while true; do
    echo "=== Chain Status at $(date) ==="
    
    # Query block height from both nodes
    HEIGHT_0=$(curl -s -X POST http://localhost:9469 \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        | jq -r '.result')
    
    HEIGHT_1=$(curl -s -X POST http://localhost:9470 \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        | jq -r '.result')
    
    echo "Node 0 height: $HEIGHT_0"
    echo "Node 1 height: $HEIGHT_1"
    
    # Check latest blocks
    echo "Latest blocks proposed:"
    grep "successfully proposed block" /tmp/qrdx-node-*/trinity.log | tail -5
    
    echo ""
    sleep 5
done
```

#### 4.2 Success Criteria
- ✅ Block height increasing every 2 seconds
- ✅ Both nodes showing same block height
- ✅ Blocks alternating between validators (slot-based)
- ✅ No import errors
- ✅ Dilithium signatures validating correctly

### Phase 5: Performance & Finality (Medium Priority)

#### 5.1 Attestations
Implement attestation system:
```python
async def _create_attestation(self) -> None:
    """Create attestation for current head."""
    head = await self._get_chain_head()
    
    attestation = Attestation(
        slot=self.current_slot,
        block_hash=head.hash,
        validator_index=self.validator_index,
        signature=self._sign_attestation(head.hash)
    )
    
    # Broadcast attestation
    await self.event_bus.broadcast(
        NewAttestationEvent(attestation),
        TO_NETWORKING_BROADCAST_CONFIG
    )
```

#### 5.2 Finality Gadget
Track justified and finalized checkpoints:
```python
class FinalityTracker:
    def __init__(self):
        self.justified_checkpoint = None
        self.finalized_checkpoint = None
    
    def update_with_attestations(self, attestations: List[Attestation]):
        """Update finality based on attestations."""
        # If 2/3+ validators attest to a block, it becomes justified
        # If justified block has justified child, parent becomes finalized
```

## Implementation Order (Recommended)

### Week 1: Core Block Production
1. ✅ Day 1-2: Implement block building (`_build_block_header`)
2. ✅ Day 2-3: Implement block signing (`_sign_block`)
3. ✅ Day 3-4: Implement local block import
4. ✅ Day 4-5: Test single node creating blocks

### Week 2: Networking
5. ✅ Day 6-7: Implement block broadcasting
6. ✅ Day 7-8: Implement peer handlers for receiving blocks
7. ✅ Day 8-9: Implement block validation on receive
8. ✅ Day 9-10: Test multi-node block propagation

### Week 3: Stability & Finality
9. ✅ Day 11-12: Fix any block import issues
10. ✅ Day 12-13: Implement attestation broadcasting
11. ✅ Day 13-14: Implement finality tracking
12. ✅ Day 14: Full system testing

## Critical Files to Modify

### Primary Implementation
1. `trinity/components/builtin/qrpos_validator/component.py` - Main logic
2. `py-evm/eth/consensus/qrpos.py` - Validation logic
3. `trinity/protocol/eth/events.py` - New events
4. `trinity/protocol/eth/peer.py` - Peer communication

### Supporting Changes
5. `py-evm/eth/rlp/headers.py` - QR-PoS block header (if extending)
6. `trinity/db/eth1/header.py` - Signature storage
7. `trinity/components/builtin/syncer/component.py` - Import coordination

## Testing Strategy

### Unit Tests
- Block building with various transaction counts
- Dilithium signature generation and verification
- Proposer selection at various slots
- Block validation (valid and invalid cases)

### Integration Tests
- 2-node testnet: blocks propagate
- 3-node testnet: chain convergence
- Validator rotation: all validators propose
- Network partition: recovery behavior

### Performance Tests
- Block production latency (should be <1s)
- Signature verification time
- Block propagation time
- Memory usage with long chains

## Known Challenges

### Challenge 1: Large Signatures
Dilithium3 signatures are 3,309 bytes - much larger than ECDSA (65 bytes).
- Need efficient serialization
- May impact network bandwidth
- Consider signature aggregation in future

### Challenge 2: State Root Computation
Computing state root requires executing transactions:
- Need VM instance
- Gas metering
- State trie updates
- Can be expensive for large blocks

### Challenge 3: Transaction Ordering
QR-PoS proposer has full control over transaction ordering:
- MEV considerations
- Fair ordering mechanisms
- Transaction pool prioritization

### Challenge 4: Fork Choice
Need to handle competing blocks at same slot:
- Which chain to follow?
- Use latest message driven (LMD) GHOST?
- Attestation-weighted fork choice?

## Success Metrics

### Immediate (Next Phase)
- ✅ Blocks being created and logged
- ✅ Block height increasing
- ✅ Both nodes synchronized
- ✅ No crashes or errors

### Short Term (1-2 weeks)
- ✅ 100+ blocks produced
- ✅ Multiple validators producing
- ✅ Attestations being broadcast
- ✅ Finality being tracked

### Long Term (1 month)
- ✅ 10,000+ block testnet
- ✅ 10+ validator testnet
- ✅ Network partition recovery
- ✅ Full Ethereum JSON-RPC compatibility
