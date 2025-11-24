# qRC20 Token Standard

## Overview

**qRC20** is a quantum-resistant token standard for the QRDX blockchain. It extends the ERC20 standard with post-quantum cryptography while maintaining full backward compatibility with existing ERC20 tooling and infrastructure.

## Features

### Standard ERC20 Compatibility ✅
- `transfer()`, `approve()`, `transferFrom()`
- `balanceOf()`, `allowance()`, `totalSupply()`
- Standard events: `Transfer`, `Approval`
- 18 decimals (standard)
- Works with existing wallets and dApps

### Quantum-Resistant Extensions 🔐
- **Dilithium Signatures**: ML-DSA-65 (NIST standardized)
- **BLAKE3 Hashing**: Quantum-resistant message construction
- **Public Key Registration**: 1,952-byte Dilithium keys
- **Replay Protection**: Nonce-based security
- **Address Derivation**: BLAKE3(publicKey)[:20]

## Architecture

### Precompiles Used

| Address | Function | Gas Cost | Input | Output |
|---------|----------|----------|-------|--------|
| 0x09 | Dilithium Verify | 50,000 | message + publicKey + signature | 1 byte (0x01=valid) |
| 0x0c | BLAKE3 Hash | 60 + 12/word | data | 32 bytes |

### Storage Layout

```solidity
string _name;                                    // Token name
string _symbol;                                  // Token symbol
uint256 _totalSupply;                           // Total supply
mapping(address => uint256) _balances;          // ERC20 balances
mapping(address => mapping(address => uint256)) _allowances; // ERC20 allowances
mapping(address => bytes) _publicKeys;          // Dilithium public keys (1,952 bytes)
mapping(address => uint256) _nonces;            // Replay protection nonces
mapping(address => bool) _keyRegistered;        // Key registration status
```

## Usage

### Standard ERC20 Transfer

```solidity
// Deploy token
QRC20 token = new QRC20("My Token", "MTK", 1_000_000 ether);

// Standard transfer (works like any ERC20)
token.transfer(recipient, 100 ether);

// Approve and transferFrom
token.approve(spender, 50 ether);
token.transferFrom(owner, recipient, 50 ether);
```

### Quantum-Resistant Transfer

```solidity
// 1. Register public key (one-time, optional)
bytes memory publicKey = ...; // 1,952 bytes Dilithium public key
token.registerPublicKey(publicKey);

// 2. Construct transfer message
address from = 0x...;
address to = 0x...;
uint256 amount = 100 ether;
uint256 nonce = token.nonces(from); // Get current nonce
bytes memory message = constructMessage(from, to, amount, nonce);

// 3. Sign with Dilithium (off-chain)
bytes memory signature = dilithiumSign(message, privateKey); // 3,309 bytes

// 4. Execute quantum transfer
token.quantumTransfer(
    from,
    to,
    amount,
    nonce,
    publicKey,
    signature
);
```

### Message Construction

The transfer message format ensures security against replay attacks:

```solidity
message = BLAKE3(from || to || amount || nonce || contractAddress)
```

This prevents:
- ✅ Cross-contract replay (includes contract address)
- ✅ Nonce reuse (nonce included and incremented)
- ✅ Parameter tampering (all params hashed)

## API Reference

### Standard ERC20 Functions

#### `name() → string`
Returns the token name.

#### `symbol() → string`
Returns the token symbol.

#### `decimals() → uint8`
Returns 18 (standard ERC20 decimals).

#### `totalSupply() → uint256`
Returns the total token supply.

#### `balanceOf(address account) → uint256`
Returns the token balance of `account`.

#### `transfer(address to, uint256 amount) → bool`
Transfers `amount` tokens to `to`.

**Requirements:**
- `to` cannot be zero address
- Caller must have sufficient balance

**Emits:** `Transfer(from, to, amount)`

#### `approve(address spender, uint256 amount) → bool`
Approves `spender` to spend `amount` tokens on behalf of caller.

**Emits:** `Approval(owner, spender, amount)`

#### `allowance(address owner, address spender) → uint256`
Returns remaining tokens `spender` can spend on behalf of `owner`.

#### `transferFrom(address from, address to, uint256 amount) → bool`
Transfers `amount` tokens from `from` to `to` using allowance.

**Requirements:**
- Caller must have sufficient allowance
- `from` must have sufficient balance

**Emits:** `Transfer(from, to, amount)`

### Quantum-Resistant Functions

#### `quantumTransfer(address from, address to, uint256 amount, uint256 nonce, bytes publicKey, bytes signature) → bool`

Executes a quantum-resistant transfer using Dilithium signature verification.

**Parameters:**
- `from`: Source address (must match derived address from publicKey)
- `to`: Destination address
- `amount`: Amount to transfer
- `nonce`: Current nonce for `from` (prevents replay)
- `publicKey`: Dilithium public key (1,952 bytes)
- `signature`: Dilithium signature (3,309 bytes)

**Requirements:**
- `publicKey` must be exactly 1,952 bytes
- `signature` must be exactly 3,309 bytes
- `nonce` must match current nonce for `from`
- Derived address from `publicKey` must equal `from`
- Signature must be valid for the transfer message
- `from` must have sufficient balance

**Message Format:**
```
BLAKE3(from || to || amount || nonce || address(this))
```

**Emits:** 
- `Transfer(from, to, amount)`
- `QuantumTransfer(from, to, amount, publicKey, signature)`

**Gas Cost:** ~150,000 gas
- Dilithium verify: 50,000 gas
- BLAKE3 hashing: ~3,000 gas
- Storage: ~40,000 gas
- Logic: ~57,000 gas

#### `registerPublicKey(bytes publicKey) → bool`

Registers a Dilithium public key for the caller's address.

**Parameters:**
- `publicKey`: Dilithium public key (1,952 bytes)

**Requirements:**
- `publicKey` must be exactly 1,952 bytes
- Caller must not have already registered a key
- Derived address from `publicKey` must match caller

**Gas Cost:** ~80,000 gas

#### `nonces(address account) → uint256`

Returns the current nonce for `account`. Used for replay protection.

#### `getPublicKey(address account) → bytes`

Returns the registered Dilithium public key for `account`. Returns empty bytes if no key is registered.

## Events

### `Transfer(address indexed from, address indexed to, uint256 value)`
Standard ERC20 transfer event.

### `Approval(address indexed owner, address indexed spender, uint256 value)`
Standard ERC20 approval event.

### `QuantumTransfer(address indexed from, address indexed to, uint256 value, bytes publicKey, bytes signature)`
Emitted when a quantum-resistant transfer is executed.

## Security Considerations

### Quantum Resistance
- **Dilithium (ML-DSA-65)**: NIST Level 3 security (~192-bit classical equivalent)
- **BLAKE3**: Not vulnerable to Grover's algorithm speedup
- **Future-proof**: Resistant to quantum attacks via Shor's and Grover's algorithms

### Replay Protection
- **Nonces**: Prevent signature reuse
- **Contract binding**: Message includes contract address
- **Parameter binding**: All parameters hashed in message

### Key Management
- **Public key size**: 1,952 bytes (Dilithium requirement)
- **Address derivation**: `BLAKE3(publicKey)[:20]` ensures binding
- **One-time registration**: Keys cannot be changed once registered

### Gas Limits
- Quantum transfers cost ~3x standard transfers (~150k vs ~50k gas)
- Consider batch operations for multiple transfers
- Standard ERC20 functions available for non-quantum use cases

## Gas Cost Comparison

| Operation | Standard | Quantum | Overhead |
|-----------|----------|---------|----------|
| Transfer | ~50,000 | ~150,000 | 3.0x |
| Approve | ~45,000 | N/A | - |
| TransferFrom | ~60,000 | N/A | - |
| Key Registration | N/A | ~80,000 | - |

## Example Deployment

```solidity
// Deploy with 1 million tokens
QRC20 token = new QRC20(
    "QRDX Test Token",  // name
    "QTEST",            // symbol
    1_000_000 ether     // initial supply (18 decimals)
);

// Initial supply minted to deployer
assert(token.balanceOf(msg.sender) == 1_000_000 ether);
assert(token.totalSupply() == 1_000_000 ether);
```

## Integration with Wallets

### MetaMask / Web3 Wallets
qRC20 tokens are **fully compatible** with existing ERC20 wallet integrations:

```javascript
// Standard ERC20 interface works
const balance = await token.balanceOf(address);
await token.transfer(recipient, amount);
await token.approve(spender, amount);
```

### Quantum-Resistant Wallets
Future quantum-resistant wallets can use the extended API:

```javascript
// Generate Dilithium keypair (off-chain)
const { publicKey, privateKey } = await generateDilithiumKeypair();

// Register public key
await token.registerPublicKey(publicKey);

// Sign transfer
const nonce = await token.nonces(from);
const message = constructMessage(from, to, amount, nonce);
const signature = dilithiumSign(message, privateKey);

// Execute quantum transfer
await token.quantumTransfer(from, to, amount, nonce, publicKey, signature);
```

## Testing

Run the demonstration script:

```bash
cd /workspaces/qrdx-chain
python3 scripts/test_qrc20.py
```

This will:
- ✅ Compile the qRC20 contract
- ✅ Show contract size and gas estimates
- ✅ Demonstrate quantum transfer workflow
- ✅ Display security properties

## Deployment Checklist

- [ ] Compile contract with Solidity 0.8.20+
- [ ] Verify precompiles (0x09, 0x0c) are available on QRDX chain
- [ ] Test standard ERC20 functions
- [ ] Test quantum transfer with test keys
- [ ] Verify nonce increments correctly
- [ ] Test replay attack prevention
- [ ] Perform security audit
- [ ] Deploy to testnet
- [ ] Monitor gas costs in production
- [ ] Deploy to mainnet

## Known Limitations

1. **Gas Overhead**: Quantum transfers cost ~3x standard transfers
2. **Key Size**: Public keys are 1,952 bytes (storage cost)
3. **Signature Size**: Signatures are 3,309 bytes (transaction size)
4. **One-time Keys**: Public keys cannot be changed once registered
5. **Precompile Dependency**: Requires QRDX precompiles (0x09, 0x0c)

## Future Enhancements

- **Batch Transfers**: Multiple quantum transfers in one transaction
- **Key Rotation**: Allow updating public keys with proper safeguards
- **Multi-sig**: Quantum-resistant multi-signature support
- **Time-locks**: Quantum-resistant time-locked transfers
- **Permit**: EIP-2612-like quantum permit functionality

## License

MIT License - See LICENSE file for details

## References

- ERC20 Standard: https://eips.ethereum.org/EIPS/eip-20
- NIST ML-DSA (Dilithium): https://csrc.nist.gov/pubs/fips/204/final
- BLAKE3 Specification: https://github.com/BLAKE3-team/BLAKE3-specs
- QRDX Whitepaper: docs/QRDX-Whitepaper-v2.0.md
