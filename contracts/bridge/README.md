# QRDX Bridge - ETH<->QRDX Cross-Chain Asset Transfer

## Overview

The QRDX Bridge enables trustless, quantum-resistant cross-chain asset transfers between Ethereum and QRDX networks. It uses a validator-based consensus mechanism with Dilithium signatures for post-quantum security.

## Architecture

### Components

1. **QRDXBridge.sol** - Main bridge smart contract (Ethereum & QRDX)
2. **IQRDXBridge.sol** - Bridge interface
3. **bridge_relay.py** - Python relay service for validators
4. **Merkle Tree** - Inclusion proofs for cross-chain verification

### Security Model

- **Multi-Validator Consensus**: Requires 67% of validators to confirm transfers
- **Quantum-Resistant Signatures**: Dilithium3 (ML-DSA-65) for validator signatures
- **Merkle Proofs**: Cryptographic inclusion proofs using BLAKE3
- **Challenge Period**: 7-day window for fraud detection
- **Time Locks**: 30-day expiration for unclaimed transfers

## Transfer Flow

### Deposit (ETH → QRDX)

```
1. User calls depositETH() or deposit() on Ethereum bridge
   ↓
2. Ethereum bridge locks tokens and emits DepositInitiated event
   ↓
3. Bridge relay monitors event and creates Merkle proof
   ↓
4. Validator signs transfer with Dilithium signature
   ↓
5. Relay submits confirmation to QRDX bridge
   ↓
6. After 67% validator confirmations, transfer is Confirmed
   ↓
7. 7-day challenge period passes
   ↓
8. User calls claim() on QRDX bridge to receive tokens
```

### Withdrawal (QRDX → ETH)

```
1. User calls depositETH() or deposit() on QRDX bridge
   ↓
2. QRDX bridge locks tokens and emits DepositInitiated event
   ↓
3. Bridge relay monitors event and creates Merkle proof
   ↓
4. Validator signs transfer with Dilithium signature
   ↓
5. User calls withdraw() on Ethereum bridge with proof + signatures
   ↓
6. Ethereum bridge verifies Merkle proof and signatures
   ↓
7. After 67% validator confirmations, transfer is Confirmed
   ↓
8. 7-day challenge period passes
   ↓
9. User calls claim() on Ethereum bridge to receive tokens
```

## Smart Contract API

### Deposit Functions

#### `depositETH(address recipient) → bytes32 transferId`
Deposit ETH for transfer to QRDX chain.

**Parameters:**
- `recipient` - Recipient address on QRDX

**Returns:**
- `transferId` - Unique transfer identifier

**Gas Cost:** ~100,000 gas

**Example:**
```solidity
bytes32 transferId = bridge.depositETH{value: 1 ether}(recipientAddress);
```

#### `deposit(address recipient, address token, uint256 amount) → bytes32 transferId`
Deposit ERC20 tokens for transfer to QRDX chain.

**Parameters:**
- `recipient` - Recipient address on QRDX
- `token` - Token contract address
- `amount` - Amount to transfer

**Returns:**
- `transferId` - Unique transfer identifier

**Gas Cost:** ~120,000 gas

**Example:**
```solidity
// Approve first
token.approve(address(bridge), amount);

// Deposit
bytes32 transferId = bridge.deposit(recipientAddress, tokenAddress, amount);
```

### Withdrawal Functions

#### `withdraw(bytes32 transferId, MerkleProof proof, bytes[] signatures) → bool`
Withdraw tokens from QRDX to Ethereum using Merkle proof and validator signatures.

**Parameters:**
- `transferId` - Transfer ID from QRDX chain
- `proof` - Merkle proof of transfer inclusion
- `signatures` - Dilithium signatures from validators

**Returns:**
- `success` - Whether withdrawal was accepted

**Gas Cost:** ~200,000 + (50,000 per signature) gas

**Example:**
```solidity
IQRDXBridge.MerkleProof memory proof = IQRDXBridge.MerkleProof({
    proof: merkleProofPath,
    leaf: transferLeaf,
    index: leafIndex
});

bool success = bridge.withdraw(transferId, proof, validatorSignatures);
```

#### `claim(bytes32 transferId) → uint256 amount`
Claim tokens after transfer is confirmed and challenge period has passed.

**Parameters:**
- `transferId` - Transfer identifier

**Returns:**
- `amount` - Amount claimed

**Gas Cost:** ~80,000 gas

**Example:**
```solidity
uint256 amount = bridge.claim(transferId);
```

### Validator Functions

#### `confirmTransfer(bytes32 transferId, bytes signature) → bool`
Confirm a transfer (validator only). Must provide valid Dilithium signature.

**Parameters:**
- `transferId` - Transfer to confirm
- `signature` - Dilithium signature (3309 bytes)

**Returns:**
- `confirmed` - Whether threshold reached

**Gas Cost:** ~150,000 gas

#### `challengeTransfer(bytes32 transferId, bytes proof, string reason)`
Challenge a potentially fraudulent transfer within challenge period.

**Parameters:**
- `transferId` - Transfer to challenge
- `proof` - Evidence of fraud
- `reason` - Challenge description

**Gas Cost:** ~100,000 gas

### View Functions

#### `getTransfer(bytes32 transferId) → TransferRequest`
Get transfer details.

#### `getValidator(address ethAddress) → Validator`
Get validator information.

#### `isValidator(address ethAddress) → bool`
Check if address is an active validator.

#### `getValidatorCount() → uint256`
Get number of active validators.

#### `getRequiredConfirmations() → uint256`
Get required confirmations (67% of validators).

#### `getTotalLocked(address token) → uint256`
Get total locked value for a token.

## Bridge Relay Service

### Setup

1. **Install Dependencies**
```bash
pip install web3 eth-account asyncio
```

2. **Configure Relay**
```python
relay = QRDXBridgeRelay(
    eth_rpc_url="http://localhost:8545",
    qrdx_rpc_url="http://localhost:8546",
    bridge_eth_address="0x...",
    bridge_qrdx_address="0x...",
    validator_private_key=dilithium_private_key
)
```

3. **Run Relay**
```bash
python trinity/components/bridge_relay.py
```

### Validator Requirements

- Minimum stake: 100 ETH
- Valid Dilithium3 key pair (1952-byte public key)
- Reliable uptime (monitored)
- Ethereum and QRDX full nodes

### Validator Rewards

Validators earn fees from:
- Per-transfer confirmation fee (0.1% of transfer value)
- Slashed stakes from malicious validators
- Protocol governance tokens

## Security Considerations

### Quantum Resistance

1. **Dilithium Signatures**: All validator confirmations use ML-DSA-65
2. **BLAKE3 Hashing**: Merkle trees and transfer IDs use BLAKE3
3. **Future-Proof**: Resistant to Shor's and Grover's algorithms

### Attack Vectors & Mitigations

#### 1. Validator Collusion
**Risk**: 67% of validators collude to steal funds

**Mitigations:**
- High validator count (recommend 150+)
- Geographic distribution
- Regular validator rotation
- Slashing for malicious behavior
- Challenge period for fraud detection

#### 2. Double Spending
**Risk**: Same deposit claimed on both chains

**Mitigations:**
- Unique transfer IDs (BLAKE3 hash of all parameters + nonce)
- Transfer status tracking (Pending → Confirmed → Completed)
- Challenge period to detect duplicates

#### 3. Merkle Proof Forgery
**Risk**: Fake Merkle proof to claim non-existent transfer

**Mitigations:**
- Quantum-resistant BLAKE3 hashing
- Validator signature verification
- On-chain Merkle root verification
- Challenge mechanism

#### 4. Replay Attacks
**Risk**: Replay old transfer on different chain

**Mitigations:**
- Chain-specific contract addresses
- Transfer includes source/target chain IDs
- Timestamp and nonce in transfer ID

#### 5. Griefing Attacks
**Risk**: Spam with invalid transfers to DOS validators

**Mitigations:**
- Minimum transfer amounts
- Gas costs for deposits
- Validator can ignore invalid transfers
- Rate limiting

## Gas Costs

| Operation | Gas Cost | USD @ 50 gwei, ETH=$3000 |
|-----------|----------|--------------------------|
| Deposit ETH | ~100,000 | $15 |
| Deposit ERC20 | ~120,000 | $18 |
| Withdraw | ~200,000 + 50k/sig | $30-60 |
| Claim | ~80,000 | $12 |
| Confirm Transfer | ~150,000 | $22.50 |
| Challenge | ~100,000 | $15 |

## Deployment

### Ethereum Deployment

```solidity
// Deploy bridge
QRDXBridge bridge = new QRDXBridge();

// Add validators
for (uint i = 0; i < validators.length; i++) {
    bridge.addValidator(
        validators[i].ethAddress,
        validators[i].dilithiumPublicKey,
        MIN_VALIDATOR_STAKE
    );
}
```

### QRDX Deployment

Same deployment process on QRDX chain. Both bridges must be configured with:
- Same validator set
- Matching confirmation thresholds
- Synchronized challenge periods

## Usage Examples

### Example 1: Bridge ETH to QRDX

```javascript
const Web3 = require('web3');
const web3 = new Web3('http://localhost:8545');

// Connect to bridge
const bridge = new web3.eth.Contract(bridgeABI, bridgeAddress);

// Deposit 1 ETH
const tx = await bridge.methods.depositETH(recipientAddress).send({
    from: senderAddress,
    value: web3.utils.toWei('1', 'ether'),
    gas: 150000
});

console.log('Transfer ID:', tx.events.DepositInitiated.returnValues.transferId);

// Wait for confirmations (monitored by relay)
// After 7 days, claim on QRDX chain
```

### Example 2: Bridge ERC20 to QRDX

```javascript
// Approve token transfer
await token.methods.approve(bridgeAddress, amount).send({
    from: senderAddress
});

// Deposit tokens
const tx = await bridge.methods.deposit(
    recipientAddress,
    tokenAddress,
    amount
).send({
    from: senderAddress,
    gas: 150000
});

console.log('Transfer ID:', tx.events.DepositInitiated.returnValues.transferId);
```

### Example 3: Withdraw from QRDX to ETH

```javascript
// Get transfer details and Merkle proof from QRDX
const transferData = await qrdxBridge.methods.getTransfer(transferId).call();
const proof = await qrdxRelay.getMerkleProof(transferId);

// Get validator signatures (from relay service)
const signatures = await qrdxRelay.getValidatorSignatures(transferId);

// Submit withdrawal on Ethereum
await ethBridge.methods.withdraw(
    transferId,
    proof,
    signatures
).send({
    from: recipientAddress,
    gas: 500000
});

// Wait 7 days for challenge period
await new Promise(resolve => setTimeout(resolve, 7 * 24 * 60 * 60 * 1000));

// Claim tokens
await ethBridge.methods.claim(transferId).send({
    from: recipientAddress,
    gas: 100000
});
```

## Monitoring & Maintenance

### Bridge Health Metrics

- Total value locked (TVL)
- Active validators count
- Average confirmation time
- Failed transfer rate
- Challenge count

### Validator Performance

- Confirmation participation rate
- Average response time
- Uptime percentage
- Slashing incidents

### Alerts

- Validator offline > 1 hour
- Failed confirmation rate > 5%
- Unusual transfer volume
- Challenge submitted
- Low validator count (< 100)

## Roadmap

### Phase 9 (Current)
- ✅ Bridge smart contracts
- ✅ Python relay service
- ✅ Merkle proof system
- ⏳ Integration testing
- ⏳ Testnet deployment

### Future Enhancements
- Light client verification (eliminate relay trust)
- Optimistic rollup for lower fees
- Cross-chain messaging (not just transfers)
- Multi-chain support (Polygon, BSC, etc.)
- Decentralized validator management
- Insurance fund for slashing

## Testing

See `scripts/test_bridge.py` for comprehensive test suite including:
- Deposit and withdrawal flows
- Merkle proof generation and verification
- Validator signature verification
- Challenge mechanism
- Edge cases and failure modes

## License

MIT License - See LICENSE file for details

## References

- Dilithium Specification: https://pq-crystals.org/dilithium/
- BLAKE3: https://github.com/BLAKE3-team/BLAKE3-specs
- Merkle Trees: https://en.wikipedia.org/wiki/Merkle_tree
- Bridge Security: https://medium.com/immunefi/cross-chain-bridge-hacks-f3e3f98a6d6b

## Support

For questions, issues, or validator onboarding:
- GitHub Issues: [repository]/issues
- Documentation: [repository]/docs/bridge
- Validator Discord: [discord link]
