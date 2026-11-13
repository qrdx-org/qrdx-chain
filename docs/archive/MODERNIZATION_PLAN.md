# QRDX Blockchain Modernization Plan

## Executive Summary

This document outlines the comprehensive modernization plan for the QRDX blockchain to bring it up to Web3 standards. The modernization will transform the current Denaro-based blockchain into a fully modular, Web3-compliant system with proper P2P networking, post-quantum cryptography support, and standardized RPC interfaces.

**Current State Analysis:**
- Uses FastAPI/HTTP-based communication (no proper P2P)
- Uses P256 (NIST) curve for cryptography
- Custom REST endpoints (non-standard)
- Basic JSON peer management (file-based)
- No WebSocket support
- Limited node discovery (bootstrap node only)

**Target State:**
- Proper devp2p-style P2P with Kademlia DHT
- secp256k1 for transaction signing (Web3 standard)
- Post-quantum encryption for node-to-node communication
- Web3 JSON-RPC 2.0 compliant API
- WebSocket RPC support
- Modular architecture with toggleable components

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Module Structure](#module-structure)
3. [Wallet Compatibility](#wallet-compatibility)
4. [Detailed Implementation Checklist](#detailed-implementation-checklist)
5. [Node URI Schema](#node-uri-schema)
6. [Migration Strategy](#migration-strategy)
7. [Timeline Estimates](#timeline-estimates)

---

## Wallet Compatibility

### Dual Wallet Support

QRDX v3.0 supports **two wallet types** to ensure both Web3 compatibility and future quantum resistance:

| Wallet Type | Curve/Algorithm | Address Prefix | Use Case |
|-------------|-----------------|----------------|----------|
| **Traditional (secp256k1)** | secp256k1 ECDSA | `0x` | Web3 compatibility, existing tooling |
| **Post-Quantum (Dilithium)** | Dilithium3 | `0xPQ` | Future-proof, quantum resistant |

### Address Formats

```
Traditional:  0x742d35Cc6634C0532925a3b844Bc9e7595f8dB21  (40 hex chars)
Post-Quantum: 0xPQ8a3b4c5d6e7f8...  (66 hex chars, includes PQ marker)
```

### Transaction Signing

Transactions can be signed by either wallet type:

1. **secp256k1 Transactions**: Standard ECDSA signatures (65 bytes: r, s, v)
2. **Dilithium Transactions**: PQ signatures (~2420 bytes for Dilithium3)

The transaction format includes a version byte indicating signature type:
- `0x01`: secp256k1 signature
- `0x02`: Dilithium3 signature
- `0x03`: Hybrid (both signatures for maximum security)

### Wallet Interoperability

- Both wallet types can send/receive to each other
- Legacy addresses (Q/R prefix) are supported via migration mapping
- CLI wallet supports both key types with unified interface

---

## Architecture Overview

### Current Architecture
```
┌─────────────────────────────────────────────────────────┐
│                     QRDX Node                           │
├─────────────────────────────────────────────────────────┤
│  FastAPI HTTP Server (main.py - 3000 lines monolith)   │
│  ├── REST Endpoints (/push_tx, /get_block, etc.)       │
│  ├── nodes_manager.py (JSON file-based peers)          │
│  ├── identity.py (P256 ECDSA)                          │
│  └── Async HTTP Client (peer communication)            │
├─────────────────────────────────────────────────────────┤
│  Database Layer (PostgreSQL via asyncpg)               │
├─────────────────────────────────────────────────────────┤
│  Consensus Engine (consensus.py)                       │
└─────────────────────────────────────────────────────────┘
```

### Target Architecture
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           QRDX Node v3.0                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                            API Layer (Toggleable)                            │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────────────────────────┐│
│  │  Web3 JSON-RPC│  │  WebSocket RPC│  │  Legacy Denaro REST (deprecated)  ││
│  │  (eth_*, qrdx_)│ │  (subscriptions)│ │  (/push_tx, /get_block)          ││
│  └───────────────┘  └───────────────┘  └───────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────────────┤
│                              P2P Layer                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  DevP2P Protocol Stack                                                 │  │
│  │  ├── RLPx Transport (encrypted connections)                           │  │
│  │  ├── Node Discovery (Kademlia DHT with ENR)                           │  │
│  │  ├── Peer Management (connection pooling, reputation)                 │  │
│  │  └── Protocol Multiplexing (QRDX protocol + extensions)               │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────────────────┤
│                            Crypto Layer                                      │
│  ┌─────────────────────────┐  ┌────────────────────────────────────────────┐│
│  │  Transaction Crypto     │  │  Node Communication Crypto                  ││
│  │  ├── secp256k1 (ECDSA) │  │  ├── X25519 (key exchange)                  ││
│  │  ├── keccak256 (hash)  │  │  ├── Kyber (PQ key encapsulation)           ││
│  │  └── RLP encoding      │  │  ├── Dilithium (PQ signatures)              ││
│  └─────────────────────────┘  │  └── Hybrid TLS/RLPx handshake             ││
│                               └────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────────────────┤
│                           Core Services                                      │
│  ┌───────────────┐  ┌───────────────┐  ┌─────────────────┐  ┌─────────────┐│
│  │  Blockchain   │  │  Transaction  │  │  Consensus      │  │  State      ││
│  │  Manager      │  │  Pool         │  │  Engine         │  │  Manager    ││
│  └───────────────┘  └───────────────┘  └─────────────────┘  └─────────────┘│
├─────────────────────────────────────────────────────────────────────────────┤
│                          Storage Layer                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  PostgreSQL (blocks, transactions) + LevelDB (state trie, optional)   │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Module Structure

### New Package Layout

```
qrdx/
├── __init__.py
├── config.py                    # Central configuration management
├── constants.py                 # Protocol constants
├── exceptions.py                # Custom exceptions
│
├── core/                        # Core blockchain logic
│   ├── __init__.py
│   ├── block.py                 # Block dataclass and validation
│   ├── transaction.py           # Transaction types
│   ├── state.py                 # State management
│   ├── chain.py                 # Blockchain manager
│   └── mempool.py               # Transaction pool
│
├── consensus/                   # Consensus engine
│   ├── __init__.py
│   ├── engine.py                # Consensus rules
│   ├── pow.py                   # Proof of Work
│   └── fork_choice.py           # Fork choice rules
│
├── crypto/                      # Cryptographic primitives
│   ├── __init__.py
│   ├── keys.py                  # Key management (secp256k1)
│   ├── signing.py               # Transaction signing
│   ├── hashing.py               # Hash functions (keccak256)
│   ├── encoding.py              # RLP encoding
│   └── pq/                      # Post-quantum crypto
│       ├── __init__.py
│       ├── kyber.py             # Key encapsulation
│       └── dilithium.py         # Signatures
│
├── p2p/                         # P2P networking (new)
│   ├── __init__.py
│   ├── config.py                # P2P configuration
│   ├── node.py                  # Node identity (ENR)
│   ├── discovery/               # Node discovery
│   │   ├── __init__.py
│   │   ├── kademlia.py          # Kademlia DHT
│   │   ├── enr.py               # Ethereum Node Records
│   │   └── bootstrap.py         # Bootstrap nodes
│   ├── transport/               # Transport layer
│   │   ├── __init__.py
│   │   ├── rlpx.py              # RLPx encrypted transport
│   │   ├── auth.py              # Handshake/authentication
│   │   └── session.py           # Session management
│   ├── protocol/                # Wire protocol
│   │   ├── __init__.py
│   │   ├── base.py              # Base protocol
│   │   ├── qrdx.py              # QRDX protocol messages
│   │   └── commands.py          # Protocol commands
│   ├── peer/                    # Peer management
│   │   ├── __init__.py
│   │   ├── peer.py              # Peer representation
│   │   ├── pool.py              # Peer pool
│   │   └── reputation.py        # Peer scoring
│   └── sync/                    # Chain synchronization
│       ├── __init__.py
│       ├── full.py              # Full sync
│       └── fast.py              # Fast sync (future)
│
├── rpc/                         # RPC interfaces (new)
│   ├── __init__.py
│   ├── config.py                # RPC configuration
│   ├── server.py                # RPC server manager
│   ├── http/                    # HTTP JSON-RPC
│   │   ├── __init__.py
│   │   └── server.py
│   ├── websocket/               # WebSocket JSON-RPC
│   │   ├── __init__.py
│   │   ├── server.py
│   │   └── subscriptions.py     # Event subscriptions
│   ├── modules/                 # RPC method modules
│   │   ├── __init__.py
│   │   ├── eth.py               # eth_* namespace (Web3 compatible)
│   │   ├── qrdx.py              # qrdx_* namespace (chain-specific)
│   │   ├── net.py               # net_* namespace
│   │   ├── web3.py              # web3_* namespace
│   │   └── admin.py             # admin_* namespace
│   └── legacy/                  # Legacy Denaro endpoints
│       ├── __init__.py
│       └── endpoints.py         # Backward-compatible REST
│
├── db/                          # Database layer
│   ├── __init__.py
│   ├── base.py                  # Abstract database interface
│   ├── postgres.py              # PostgreSQL implementation
│   └── schema.sql               # Database schema
│
├── wallet/                      # Wallet functionality
│   ├── __init__.py
│   ├── account.py               # Account management
│   ├── keystore.py              # Key storage
│   └── signer.py                # Transaction signing
│
├── node/                        # Node orchestration
│   ├── __init__.py
│   ├── main.py                  # Main node runner
│   ├── config.py                # Node configuration
│   └── service.py               # Service manager
│
└── utils/                       # Utilities
    ├── __init__.py
    ├── logging.py               # Logging configuration
    ├── metrics.py               # Prometheus metrics
    └── validation.py            # Input validation
```

---

## Detailed Implementation Checklist

### Phase 1: Cryptographic Foundation

#### 1.1 Switch to secp256k1 Curve
- [ ] **1.1.1** Install `eth-keys` and `eth-account` packages
- [ ] **1.1.2** Create new `qrdx/crypto/keys.py` module
  - [ ] Implement `PrivateKey` class wrapping eth-keys
  - [ ] Implement `PublicKey` class with address derivation
  - [ ] Add key generation, import/export functions
- [ ] **1.1.3** Create `qrdx/crypto/signing.py`
  - [ ] Implement ECDSA signing with secp256k1
  - [ ] Support EIP-155 style signatures (v, r, s)
  - [ ] Add message signing (personal_sign compatible)
- [ ] **1.1.4** Create `qrdx/crypto/hashing.py`
  - [ ] Implement keccak256 (Web3 standard)
  - [ ] Keep sha256 for block hashing (chain continuity)
- [ ] **1.1.5** Update address format
  - [ ] Switch from Base58 Q/R prefix to 0x hex addresses
  - [ ] Implement checksum addresses (EIP-55)
  - [ ] Add address validation utilities
- [ ] **1.1.6** Migration utility for existing addresses
  - [ ] Create mapping tool: old address → new address
  - [ ] Update database schema for dual-format support

#### 1.2 Post-Quantum Cryptography for Node Communication
- [ ] **1.2.1** Integrate liboqs Python bindings
  - [ ] Install `liboqs-python` package
  - [ ] Create `qrdx/crypto/pq/__init__.py`
- [ ] **1.2.2** Implement Kyber key encapsulation
  - [ ] Create `qrdx/crypto/pq/kyber.py`
  - [ ] Support Kyber-768 (NIST Level 3)
  - [ ] Key generation, encapsulation, decapsulation
- [ ] **1.2.3** Implement Dilithium signatures
  - [ ] Create `qrdx/crypto/pq/dilithium.py`
  - [ ] Support Dilithium3 (NIST Level 3)
  - [ ] Sign/verify for node identity proofs
- [ ] **1.2.4** Hybrid crypto scheme
  - [ ] Combine X25519 + Kyber for key exchange
  - [ ] Combine ECDSA + Dilithium for signatures
  - [ ] Graceful fallback for non-PQ peers

#### 1.3 RLP Encoding
- [ ] **1.3.1** Install `pyrlp` package
- [ ] **1.3.2** Create `qrdx/crypto/encoding.py`
  - [ ] Implement RLP encode/decode utilities
  - [ ] Create sedes for transactions, blocks
- [ ] **1.3.3** Update transaction serialization
  - [ ] Convert from custom hex to RLP encoding
  - [ ] Maintain backward compatibility for chain history

---

### Phase 2: P2P Networking Layer

#### 2.1 Node Identity and ENR
- [ ] **2.1.1** Create `qrdx/p2p/node.py`
  - [ ] Implement Node class with identity
  - [ ] Generate node keys (secp256k1 + Dilithium)
  - [ ] Create node_id from public key hash
- [ ] **2.1.2** Implement ENR (Ethereum Node Records)
  - [ ] Create `qrdx/p2p/discovery/enr.py`
  - [ ] Support standard ENR fields (ip, tcp, udp, id)
  - [ ] Add custom QRDX fields (pq_pubkey, chain_id)
- [ ] **2.1.3** Node URI schema
  - [ ] Format: `qnode://<pubkey>@<host>:<port>?pq=<pq_pubkey>`
  - [ ] Parser and serializer functions
  - [ ] Validation utilities

#### 2.2 Node Discovery (Kademlia DHT)
- [ ] **2.2.1** Create `qrdx/p2p/discovery/kademlia.py`
  - [ ] Implement routing table (k-buckets)
  - [ ] Node distance calculation (XOR metric)
  - [ ] Bucket management (add, remove, refresh)
- [ ] **2.2.2** Discovery protocol messages
  - [ ] PING/PONG for liveness
  - [ ] FIND_NODE for neighbor lookup
  - [ ] NEIGHBORS for response
- [ ] **2.2.3** Bootstrap mechanism
  - [ ] Create `qrdx/p2p/discovery/bootstrap.py`
  - [ ] Hardcoded bootstrap nodes
  - [ ] Initial table population
- [ ] **2.2.4** Periodic maintenance
  - [ ] Bucket refresh
  - [ ] Stale node eviction
  - [ ] Random lookups for table health

#### 2.3 Transport Layer (RLPx)
- [ ] **2.3.1** Create `qrdx/p2p/transport/auth.py`
  - [ ] Implement ECIES encryption
  - [ ] Handshake initiator/responder
  - [ ] Session key derivation
- [ ] **2.3.2** Create `qrdx/p2p/transport/rlpx.py`
  - [ ] Frame encryption/decryption
  - [ ] Message framing (header + body)
  - [ ] MAC verification
- [ ] **2.3.3** Post-quantum handshake extension
  - [ ] Embed Kyber key exchange in handshake
  - [ ] Hybrid session key derivation
  - [ ] PQ capability negotiation
- [ ] **2.3.4** Create `qrdx/p2p/transport/session.py`
  - [ ] Session state management
  - [ ] Timeout handling
  - [ ] Graceful disconnection

#### 2.4 Protocol Layer
- [ ] **2.4.1** Create `qrdx/p2p/protocol/base.py`
  - [ ] Base protocol class
  - [ ] Command registration
  - [ ] Message encoding/decoding
- [ ] **2.4.2** Implement QRDX protocol
  - [ ] Create `qrdx/p2p/protocol/qrdx.py`
  - [ ] Status message (chain info exchange)
  - [ ] NewBlock announcement
  - [ ] Transactions broadcast
  - [ ] GetBlockHeaders/BlockHeaders
  - [ ] GetBlockBodies/BlockBodies
  - [ ] GetPooledTransactions/PooledTransactions
- [ ] **2.4.3** Protocol versioning
  - [ ] Version negotiation in handshake
  - [ ] Capability advertisement

#### 2.5 Peer Management
- [ ] **2.5.1** Create `qrdx/p2p/peer/peer.py`
  - [ ] Peer class (connection wrapper)
  - [ ] Peer state tracking
  - [ ] Protocol handlers
- [ ] **2.5.2** Create `qrdx/p2p/peer/pool.py`
  - [ ] Connection pool management
  - [ ] Max peers limit
  - [ ] Dial-out scheduling
  - [ ] Inbound connection handling
- [ ] **2.5.3** Create `qrdx/p2p/peer/reputation.py`
  - [ ] Peer scoring system
  - [ ] Ban list management
  - [ ] Score decay over time

#### 2.6 Chain Synchronization
- [ ] **2.6.1** Create `qrdx/p2p/sync/full.py`
  - [ ] Full sync implementation
  - [ ] Block download pipeline
  - [ ] Header validation
  - [ ] Body validation
- [ ] **2.6.2** Block propagation
  - [ ] NewBlock announcement handling
  - [ ] Block request/response
  - [ ] Orphan block handling

---

### Phase 3: RPC Layer

#### 3.1 JSON-RPC 2.0 Framework
- [ ] **3.1.1** Create `qrdx/rpc/server.py`
  - [ ] JSON-RPC 2.0 request parser
  - [ ] Response formatter
  - [ ] Error handling (standard codes)
  - [ ] Batch request support
- [ ] **3.1.2** Module registration system
  - [ ] Dynamic method registration
  - [ ] Namespace prefixing (eth_, qrdx_, etc.)
  - [ ] Method documentation

#### 3.2 HTTP JSON-RPC Server
- [ ] **3.2.1** Create `qrdx/rpc/http/server.py`
  - [ ] FastAPI-based HTTP server
  - [ ] Single /rpc endpoint
  - [ ] CORS configuration
  - [ ] Rate limiting
- [ ] **3.2.2** Authentication (optional)
  - [ ] JWT token support
  - [ ] API key authentication

#### 3.3 WebSocket JSON-RPC Server
- [ ] **3.3.1** Create `qrdx/rpc/websocket/server.py`
  - [ ] WebSocket handler
  - [ ] Connection management
  - [ ] Heartbeat/keepalive
- [ ] **3.3.2** Create `qrdx/rpc/websocket/subscriptions.py`
  - [ ] Event subscription system
  - [ ] newHeads subscription
  - [ ] logs subscription
  - [ ] pendingTransactions subscription
  - [ ] Subscription ID management

#### 3.4 Web3-Compatible Methods (eth_* namespace)
- [ ] **3.4.1** Create `qrdx/rpc/modules/eth.py`
- [ ] **3.4.2** Implement core methods:
  - [ ] `eth_chainId` - Chain ID
  - [ ] `eth_blockNumber` - Latest block number
  - [ ] `eth_getBlockByNumber` - Block by number
  - [ ] `eth_getBlockByHash` - Block by hash
  - [ ] `eth_getTransactionByHash` - Transaction lookup
  - [ ] `eth_getTransactionReceipt` - Transaction receipt
  - [ ] `eth_getBalance` - Address balance
  - [ ] `eth_getTransactionCount` - Address nonce
  - [ ] `eth_sendRawTransaction` - Submit signed tx
  - [ ] `eth_call` - Read-only call (if applicable)
  - [ ] `eth_estimateGas` - Gas estimation
  - [ ] `eth_gasPrice` - Current gas price
  - [ ] `eth_syncing` - Sync status
  - [ ] `eth_mining` - Mining status
  - [ ] `eth_hashrate` - Network hashrate
  - [ ] `eth_accounts` - (empty, no hosted wallets)
  - [ ] `eth_sign` - Message signing (if wallet enabled)
  - [ ] `eth_getCode` - (return empty, no EVM)
  - [ ] `eth_getLogs` - Log filtering
  - [ ] `eth_subscribe` - WebSocket subscriptions
  - [ ] `eth_unsubscribe` - Cancel subscription

#### 3.5 QRDX-Specific Methods (qrdx_* namespace)
- [ ] **3.5.1** Create `qrdx/rpc/modules/qrdx.py`
- [ ] **3.5.2** Implement chain-specific methods:
  - [ ] `qrdx_getMiningInfo` - Mining template
  - [ ] `qrdx_submitBlock` - Submit mined block
  - [ ] `qrdx_getAddressInfo` - Detailed address info
  - [ ] `qrdx_getPendingTransactions` - Mempool contents
  - [ ] `qrdx_getNetworkInfo` - Network statistics
  - [ ] `qrdx_getPeers` - Connected peers
  - [ ] `qrdx_addPeer` - Add peer manually
  - [ ] `qrdx_removePeer` - Remove peer
  - [ ] `qrdx_getDifficulty` - Current difficulty
  - [ ] `qrdx_getBlockReward` - Current block reward

#### 3.6 Network Methods (net_* namespace)
- [ ] **3.6.1** Create `qrdx/rpc/modules/net.py`
  - [ ] `net_version` - Network ID
  - [ ] `net_listening` - P2P listening status
  - [ ] `net_peerCount` - Connected peer count

#### 3.7 Web3 Methods (web3_* namespace)
- [ ] **3.7.1** Create `qrdx/rpc/modules/web3.py`
  - [ ] `web3_clientVersion` - Client version string
  - [ ] `web3_sha3` - Keccak256 hash

#### 3.8 Legacy Denaro Endpoints (Toggleable)
- [ ] **3.8.1** Create `qrdx/rpc/legacy/endpoints.py`
  - [ ] Map legacy REST to new system
  - [ ] `/push_tx` → internal tx submission
  - [ ] `/get_block` → block retrieval
  - [ ] `/get_blocks` → block range
  - [ ] `/get_mining_info` → mining info
  - [ ] `/get_address_info` → address info
  - [ ] `/get_pending_transactions` → mempool
- [ ] **3.8.2** Deprecation warnings
  - [ ] Log warnings for legacy endpoint usage
  - [ ] Return deprecation headers

---

### Phase 4: Core Refactoring

#### 4.1 Configuration System
- [ ] **4.1.1** Create `qrdx/config.py`
  - [ ] Hierarchical configuration
  - [ ] Environment variable support
  - [ ] Config file (TOML/YAML) support
  - [ ] Command-line overrides
- [ ] **4.1.2** Module toggle configuration
  ```toml
  [rpc]
  enabled = true
  
  [rpc.http]
  enabled = true
  host = "0.0.0.0"
  port = 8545
  
  [rpc.websocket]
  enabled = true
  host = "0.0.0.0"
  port = 8546
  
  [rpc.legacy]
  enabled = false  # Disable legacy REST
  
  [p2p]
  enabled = true
  listen_port = 30303
  max_peers = 50
  
  [p2p.discovery]
  enabled = true
  bootnodes = ["qnode://...@bootnode1.qrdx.network:30303"]
  ```

#### 4.2 Transaction Refactoring
- [ ] **4.2.1** Create `qrdx/core/transaction.py`
  - [ ] Transaction dataclass (typed, immutable)
  - [ ] RLP serialization
  - [ ] Hash calculation (keccak256)
  - [ ] Signature verification (secp256k1)
- [ ] **4.2.2** Legacy transaction support
  - [ ] Conversion from old format
  - [ ] Dual verification during transition

#### 4.3 Block Refactoring  
- [ ] **4.3.1** Create `qrdx/core/block.py`
  - [ ] Block header dataclass
  - [ ] Block body dataclass
  - [ ] RLP serialization
  - [ ] Hash calculation
- [ ] **4.3.2** Backward compatibility
  - [ ] Read old blocks from DB
  - [ ] Convert on-the-fly

#### 4.4 Database Abstraction
- [ ] **4.4.1** Create `qrdx/db/base.py`
  - [ ] Abstract database interface
  - [ ] CRUD operations for blocks
  - [ ] CRUD operations for transactions
  - [ ] State queries
- [ ] **4.4.2** PostgreSQL implementation
  - [ ] Create `qrdx/db/postgres.py`
  - [ ] Async connection pooling
  - [ ] Prepared statements
  - [ ] Migration support

---

### Phase 5: Node Orchestration

#### 5.1 Service Manager
- [ ] **5.1.1** Create `qrdx/node/service.py`
  - [ ] Service lifecycle management
  - [ ] Dependency injection
  - [ ] Graceful startup/shutdown
- [ ] **5.1.2** Service definitions
  - [ ] P2P service
  - [ ] RPC service (HTTP + WS)
  - [ ] Sync service
  - [ ] Consensus service

#### 5.2 Main Node Runner
- [ ] **5.2.1** Create `qrdx/node/main.py`
  - [ ] CLI argument parsing
  - [ ] Configuration loading
  - [ ] Service orchestration
  - [ ] Signal handling (SIGTERM, SIGINT)

#### 5.3 Monitoring and Metrics
- [ ] **5.3.1** Prometheus metrics
  - [ ] P2P peer count
  - [ ] Block height
  - [ ] Transaction throughput
  - [ ] RPC request latency
- [ ] **5.3.2** Health check endpoint
  - [ ] Readiness probe
  - [ ] Liveness probe

---

### Phase 6: Testing and Documentation

#### 6.1 Unit Tests
- [ ] **6.1.1** Crypto tests
  - [ ] Key generation
  - [ ] Signing/verification
  - [ ] Address derivation
- [ ] **6.1.2** P2P tests
  - [ ] Discovery protocol
  - [ ] RLPx handshake
  - [ ] Message encoding
- [ ] **6.1.3** RPC tests
  - [ ] Method implementations
  - [ ] Error handling
  - [ ] Subscriptions

#### 6.2 Integration Tests
- [ ] **6.2.1** Multi-node tests
  - [ ] Peer discovery
  - [ ] Block propagation
  - [ ] Transaction propagation
- [ ] **6.2.2** RPC client tests
  - [ ] web3.py compatibility
  - [ ] WebSocket subscriptions

#### 6.3 Documentation
- [ ] **6.3.1** API documentation
  - [ ] OpenAPI spec for RPC
  - [ ] Method reference
- [ ] **6.3.2** Architecture documentation
  - [ ] Module descriptions
  - [ ] Sequence diagrams
- [ ] **6.3.3** Migration guide
  - [ ] Upgrade instructions
  - [ ] Breaking changes

---

## Node URI Schema

### Proposed Format
```
qnode://<pubkey>@<host>:<port>[?pq=<pq_pubkey>][&chain=<chain_id>]
```

### Components

| Component | Description | Format | Required |
|-----------|-------------|--------|----------|
| `pubkey` | secp256k1 public key (compressed) | 66 hex chars | Yes |
| `host` | IP address or hostname | IPv4/IPv6/DNS | Yes |
| `port` | TCP port for RLPx | Integer | Yes |
| `pq` | Post-quantum public key (Dilithium) | Base64 | No |
| `chain` | Chain ID for multi-chain | Integer | No |

### Examples

```
# Basic node URI
qnode://03a1b2c3d4e5f6...@192.168.1.100:30303

# With post-quantum key
qnode://03a1b2c3d4e5f6...@node.example.com:30303?pq=Base64EncodedDilithiumKey...

# With chain ID
qnode://03a1b2c3d4e5f6...@192.168.1.100:30303?chain=1

# Full example
qnode://03a1b2c3d4e5f6789...@mainnet.qrdx.network:30303?pq=AAAB...&chain=1
```

### Alternative Considerations

1. **ENR (Ethereum Node Record)** format as primary:
   ```
   enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlk...
   ```
   - Pros: Standardized, self-contained, signed
   - Cons: Not human-readable

2. **enode** format (Ethereum legacy):
   ```
   enode://pubkey@host:port
   ```
   - Pros: Simple, widely understood
   - Cons: No extension mechanism

**Recommendation:** Use `qnode://` for human-readable URIs, support ENR for discovery/storage.

---

## Migration Strategy

### Phase 1: Parallel Operation (Non-Breaking)
1. Add new P2P stack alongside existing HTTP
2. Add Web3 RPC alongside legacy REST
3. Run both systems in parallel
4. New features only on new stack

### Phase 2: Gradual Migration
1. Deprecation warnings on legacy endpoints
2. Encourage client migration to Web3 RPC
3. Default new nodes to new P2P only
4. Legacy as opt-in

### Phase 3: Legacy Sunset
1. Remove legacy code paths
2. Full Web3 compliance
3. Clean codebase

### Database Migration
- No schema changes required for blocks/transactions
- New tables for ENR records, peer metadata
- Dual-index addresses (old + new format)

---

## Timeline Estimates

| Phase | Description | Estimated Duration |
|-------|-------------|-------------------|
| Phase 1 | Cryptographic Foundation | 2-3 weeks |
| Phase 2 | P2P Networking Layer | 4-6 weeks |
| Phase 3 | RPC Layer | 2-3 weeks |
| Phase 4 | Core Refactoring | 2-3 weeks |
| Phase 5 | Node Orchestration | 1-2 weeks |
| Phase 6 | Testing & Documentation | 2-3 weeks |

**Total Estimated Time:** 13-20 weeks

---

## Dependencies

### New Python Packages
```
eth-keys>=0.5.0          # secp256k1 keys
eth-account>=0.11.0      # Account management
eth-rlp>=2.1.0           # RLP encoding
eth-hash[pycryptodome]   # Keccak256
eth-typing>=4.0.0        # Type definitions
eth-utils>=3.0.0         # Utilities
pyrlp>=4.0.0             # RLP codec
liboqs-python>=0.9.0     # Post-quantum crypto
websockets>=12.0         # WebSocket support
trio>=0.24.0             # Async I/O (optional, for P2P)
asyncio-dgram>=2.1.2     # UDP for discovery
lru-dict>=1.2.0          # LRU caching
```

### System Dependencies
```
liboqs                   # Post-quantum crypto library
```

---

## Success Criteria

1. **Web3 Compatibility**
   - [ ] web3.py can connect and interact with node
   - [ ] Standard methods return expected formats
   - [ ] WebSocket subscriptions work correctly

2. **P2P Functionality**
   - [ ] Nodes discover each other via Kademlia
   - [ ] Encrypted connections established
   - [ ] Blocks/transactions propagate correctly

3. **Post-Quantum Security**
   - [ ] Node handshakes use hybrid encryption
   - [ ] PQ keys are generated and stored
   - [ ] Graceful degradation for non-PQ peers

4. **Modularity**
   - [ ] Each module can be toggled independently
   - [ ] Clean interfaces between modules
   - [ ] No circular dependencies

5. **Backward Compatibility**
   - [ ] Existing chain history remains valid
   - [ ] Legacy endpoints work (when enabled)
   - [ ] Smooth upgrade path for existing nodes

---

## Next Steps

1. **Review and Approve** this modernization plan
2. **Set Up Development Environment** with new dependencies
3. **Begin Phase 1** with cryptographic foundation
4. **Create Feature Branches** for parallel development
5. **Establish CI/CD** for automated testing

---

*Document Version: 1.0*
*Created: January 4, 2026*
*Author: QRDX Development Team*
