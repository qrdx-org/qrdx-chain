# QRDX Smart Contracts

This directory contains smart contracts for the QRDX post-quantum blockchain.

## AddressRegistry

**Contract:** `AddressRegistry.sol`  
**Canonical Address:** `0x0000000000000000000000000000000000000100`

### Purpose

The AddressRegistry enables migration from classical 20-byte Ethereum addresses to 32-byte post-quantum addresses. It maintains a bidirectional mapping between address types and supports gradual migration.

### Key Functions

#### `linkAddress(bytes32 pqAddress, bytes pqPubkey, bytes pqSignature)`
Link a classical address to a PQ address. Requires:
- Dilithium public key (2,592 bytes)
- Dilithium signature proving ownership (4,595 bytes)
- Signature must be over `keccak256(classicalAddress || pqAddress)`

#### `getLinkedPQAddress(address classicalAddress) → bytes32`
Query the PQ address linked to a classical address.

#### `getLinkedClassicalAddress(bytes32 pqAddress) → address`
Query the classical address linked to a PQ address.

#### `unlinkAddress()`
Remove the mapping (can only be called by the classical address owner).

#### `completeMigration()`
Mark migration as complete (makes classical address deprecated).

### Deployment

The contract must be deployed to the canonical address during genesis:

```python
from trinity.contracts.address_registry import get_address_registry_genesis_config

genesis_config = {
    "alloc": {
        **get_address_registry_genesis_config(),
        # ... other allocations
    }
}
```

### Usage Example

```python
from trinity.contracts.address_registry import AddressRegistryInterface
from trinity.crypto.pq import DilithiumPrivateKey, generate_pq_address
from eth_utils import to_canonical_address

# Generate PQ keys
pq_privkey = DilithiumPrivateKey.generate()
pq_pubkey = pq_privkey.public_key()
pq_address = generate_pq_address(pq_pubkey)

# Create message to sign: keccak256(classicalAddress || pqAddress)
classical_addr = to_canonical_address("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb")
message = keccak256(classical_addr + pq_address)

# Sign with PQ private key
pq_signature = pq_privkey.sign(message)

# Link addresses via registry
registry = AddressRegistryInterface(vm)
tx_hash = registry.link_address(
    classical_addr,
    pq_address,
    pq_pubkey.to_bytes(),
    pq_signature
)
```

## Compilation

To compile contracts:

```bash
# Install solc compiler
pip install py-solc-x
python -m solcx.install v0.8.20

# Compile contracts
cd trinity/contracts
solc --bin --abi --optimize AddressRegistry.sol
```

## Testing

Contract tests are in `tests/contracts/test_address_registry.py`:

```bash
pytest tests/contracts/test_address_registry.py -v
```

## Security Considerations

1. **PQ Signature Verification**: Currently uses placeholder verification. In production, this MUST call the Dilithium precompile at address 0x10.

2. **One-Way Linking**: Once linked, addresses can only be unlinked by the classical address owner. This prevents takeover attacks.

3. **PQ Address Uniqueness**: Each PQ address can only be linked to one classical address. This prevents address collision attacks.

4. **Migration Status**: The `migrationCompleted` flag indicates when a classical address should no longer be used.

## Gas Costs

Estimated gas costs (approximate):

- `linkAddress`: ~100,000 gas (includes PQ signature verification)
- `unlinkAddress`: ~20,000 gas
- `getLinkedPQAddress`: ~3,000 gas (view)
- `getLinkedClassicalAddress`: ~3,000 gas (view)

## Future Enhancements

1. **Bulk Operations**: Add functions for linking multiple addresses in one transaction
2. **Address Migration Tools**: CLI tools for mass migration
3. **Event Indexing**: Off-chain indexer for quick address lookups
4. **Upgrade Mechanism**: Proxy pattern for contract upgrades if needed
