# QRDX v3.0 Modernization - New Module Structure

This directory contains the new modular architecture for QRDX v3.0.

## New Modules Created

### `/qrdx/crypto/` - Cryptographic Primitives
Implements secp256k1 cryptography for Web3 compatibility.

| File | Description | Status |
|------|-------------|--------|
| [`__init__.py`](crypto/__init__.py) | Module exports | ✅ |
| [`keys.py`](crypto/keys.py) | PrivateKey, PublicKey, Signature classes | ✅ |
| [`hashing.py`](crypto/hashing.py) | keccak256, sha256 functions | ✅ |
| [`address.py`](crypto/address.py) | Address derivation, EIP-55 checksum | ✅ |
| [`signing.py`](crypto/signing.py) | Transaction/message signing | ✅ |

### `/qrdx/p2p/` - P2P Networking
DevP2P-style peer-to-peer networking with Kademlia DHT.

| File | Description | Status |
|------|-------------|--------|
| [`__init__.py`](p2p/__init__.py) | Module exports | ✅ |
| [`config.py`](p2p/config.py) | P2P configuration dataclasses | ✅ |
| [`node.py`](p2p/node.py) | Node identity, qnode:// URI parsing | ✅ |
| `discovery/` | Kademlia DHT implementation | 🔲 TODO |
| `transport/` | RLPx encrypted transport | 🔲 TODO |
| `protocol/` | QRDX wire protocol | 🔲 TODO |
| `peer/` | Peer pool management | 🔲 TODO |
| `sync/` | Chain synchronization | 🔲 TODO |

### `/qrdx/rpc/` - JSON-RPC 2.0
Web3-compatible RPC interfaces.

| File | Description | Status |
|------|-------------|--------|
| [`__init__.py`](rpc/__init__.py) | Module exports | ✅ |
| [`config.py`](rpc/config.py) | RPC configuration | ✅ |
| [`server.py`](rpc/server.py) | JSON-RPC server, method registration | ✅ |
| [`modules/eth.py`](rpc/modules/eth.py) | eth_* namespace (Web3 compatible) | ✅ |
| [`modules/net.py`](rpc/modules/net.py) | net_* namespace | ✅ |
| [`modules/web3.py`](rpc/modules/web3.py) | web3_* namespace | ✅ |
| [`modules/qrdx.py`](rpc/modules/qrdx.py) | qrdx_* namespace | ✅ |
| `http/` | HTTP transport | 🔲 TODO |
| `websocket/` | WebSocket transport + subscriptions | 🔲 TODO |
| `legacy/` | Legacy Denaro REST endpoints | 🔲 TODO |

## Configuration Files

| File | Description |
|------|-------------|
| [`/config.example.toml`](/workspaces/qrdx-chain-denaro/config.example.toml) | Example node configuration |
| [`/requirements-v3.txt`](/workspaces/qrdx-chain-denaro/requirements-v3.txt) | New dependencies for v3.0 |

## Documentation

| File | Description |
|------|-------------|
| [`/docs/archive/MODERNIZATION_PLAN.md`](/workspaces/qrdx-chain-denaro/docs/archive/MODERNIZATION_PLAN.md) | Complete modernization plan |
| [`/docs/archive/MODERNIZATION_CHECKLIST.md`](/workspaces/qrdx-chain-denaro/docs/archive/MODERNIZATION_CHECKLIST.md) | Progress tracking checklist |

## Usage Example

```python
# New crypto module
from qrdx.crypto import generate_keypair, sign_message, keccak256

private_key, public_key = generate_keypair()
address = public_key.to_address()  # Returns 0x... checksum address

# Sign a message
signature = sign_message(private_key, b"Hello QRDX!")

# Hash data
hash_bytes = keccak256(b"data")

# P2P node identity
from qrdx.p2p import Node, Address

node = Node.load_or_generate("./node.key", Address("0.0.0.0", 30303))
print(node.to_uri())  # qnode://<pubkey>@0.0.0.0:30303

# RPC server
from qrdx.rpc import RPCServer
from qrdx.rpc.modules import EthModule, QRDXModule

server = RPCServer()
server.register_module(EthModule(context))
server.register_module(QRDXModule(context))

# Handle request
response = await server.handle_request('{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}')
```

## Migration Path

1. **Phase 1 (Current)**: New modules alongside existing code
2. **Phase 2**: Gradual migration of functionality
3. **Phase 3**: Deprecation of legacy code
4. **Phase 4**: Full v3.0 release

See [MODERNIZATION_PLAN.md](../docs/archive/MODERNIZATION_PLAN.md) for complete details.
