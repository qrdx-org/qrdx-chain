# QRDX Modernization Checklist

> **Status Legend:** ⬜ Not Started | 🟡 In Progress | ✅ Complete | ❌ Blocked

---

## Phase 1: Cryptographic Foundation

### 1.1 Switch to secp256k1 Curve
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 1.1.1 Install `eth-keys` and `eth-account` packages | ⬜ | | |
| 1.1.2 Create `qrdx/crypto/keys.py` module | ⬜ | | |
| 1.1.3 Create `qrdx/crypto/signing.py` | ⬜ | | |
| 1.1.4 Create `qrdx/crypto/hashing.py` (keccak256) | ⬜ | | |
| 1.1.5 Update address format (0x hex + EIP-55) | ⬜ | | |
| 1.1.6 Migration utility for existing addresses | ⬜ | | |

### 1.2 Post-Quantum Cryptography for Node Communication
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 1.2.1 Integrate liboqs Python bindings | ⬜ | | |
| 1.2.2 Implement Kyber key encapsulation | ⬜ | | |
| 1.2.3 Implement Dilithium signatures | ⬜ | | |
| 1.2.4 Hybrid crypto scheme (X25519 + Kyber) | ⬜ | | |

### 1.3 RLP Encoding
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 1.3.1 Install `pyrlp` package | ⬜ | | |
| 1.3.2 Create `qrdx/crypto/encoding.py` | ⬜ | | |
| 1.3.3 Update transaction serialization | ⬜ | | |

---

## Phase 2: P2P Networking Layer

### 2.1 Node Identity and ENR
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 2.1.1 Create `qrdx/p2p/node.py` | ⬜ | | |
| 2.1.2 Implement ENR (Ethereum Node Records) | ⬜ | | |
| 2.1.3 Node URI schema (`qnode://`) parser | ⬜ | | |

### 2.2 Node Discovery (Kademlia DHT)
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 2.2.1 Create `qrdx/p2p/discovery/kademlia.py` | ⬜ | | |
| 2.2.2 Discovery protocol messages (PING/PONG/FIND_NODE) | ⬜ | | |
| 2.2.3 Bootstrap mechanism | ⬜ | | |
| 2.2.4 Periodic maintenance (bucket refresh) | ⬜ | | |

### 2.3 Transport Layer (RLPx)
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 2.3.1 Create `qrdx/p2p/transport/auth.py` (ECIES) | ⬜ | | |
| 2.3.2 Create `qrdx/p2p/transport/rlpx.py` | ⬜ | | |
| 2.3.3 Post-quantum handshake extension | ⬜ | | |
| 2.3.4 Create `qrdx/p2p/transport/session.py` | ⬜ | | |

### 2.4 Protocol Layer
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 2.4.1 Create `qrdx/p2p/protocol/base.py` | ⬜ | | |
| 2.4.2 Implement QRDX wire protocol | ⬜ | | |
| 2.4.3 Protocol versioning | ⬜ | | |

### 2.5 Peer Management
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 2.5.1 Create `qrdx/p2p/peer/peer.py` | ⬜ | | |
| 2.5.2 Create `qrdx/p2p/peer/pool.py` | ⬜ | | |
| 2.5.3 Create `qrdx/p2p/peer/reputation.py` | ⬜ | | |

### 2.6 Chain Synchronization
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 2.6.1 Create `qrdx/p2p/sync/full.py` | ⬜ | | |
| 2.6.2 Block propagation | ⬜ | | |

---

## Phase 3: RPC Layer

### 3.1 JSON-RPC 2.0 Framework
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 3.1.1 Create `qrdx/rpc/server.py` | ⬜ | | |
| 3.1.2 Module registration system | ⬜ | | |

### 3.2 HTTP JSON-RPC Server
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 3.2.1 Create `qrdx/rpc/http/server.py` | ⬜ | | |
| 3.2.2 Authentication (optional) | ⬜ | | |

### 3.3 WebSocket JSON-RPC Server
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 3.3.1 Create `qrdx/rpc/websocket/server.py` | ⬜ | | |
| 3.3.2 Event subscription system | ⬜ | | |

### 3.4 Web3-Compatible Methods (eth_* namespace)
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 3.4.1 Create `qrdx/rpc/modules/eth.py` | ⬜ | | |
| `eth_chainId` | ⬜ | | |
| `eth_blockNumber` | ⬜ | | |
| `eth_getBlockByNumber` | ⬜ | | |
| `eth_getBlockByHash` | ⬜ | | |
| `eth_getTransactionByHash` | ⬜ | | |
| `eth_getTransactionReceipt` | ⬜ | | |
| `eth_getBalance` | ⬜ | | |
| `eth_getTransactionCount` | ⬜ | | |
| `eth_sendRawTransaction` | ⬜ | | |
| `eth_call` | ⬜ | | |
| `eth_estimateGas` | ⬜ | | |
| `eth_gasPrice` | ⬜ | | |
| `eth_syncing` | ⬜ | | |
| `eth_mining` | ⬜ | | |
| `eth_hashrate` | ⬜ | | |
| `eth_accounts` | ⬜ | | |
| `eth_sign` | ⬜ | | |
| `eth_getCode` | ⬜ | | |
| `eth_getLogs` | ⬜ | | |
| `eth_subscribe` | ⬜ | | |
| `eth_unsubscribe` | ⬜ | | |

### 3.5 QRDX-Specific Methods (qrdx_* namespace)
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 3.5.1 Create `qrdx/rpc/modules/qrdx.py` | ⬜ | | |
| `qrdx_getMiningInfo` | ⬜ | | |
| `qrdx_submitBlock` | ⬜ | | |
| `qrdx_getAddressInfo` | ⬜ | | |
| `qrdx_getPendingTransactions` | ⬜ | | |
| `qrdx_getNetworkInfo` | ⬜ | | |
| `qrdx_getPeers` | ⬜ | | |
| `qrdx_addPeer` | ⬜ | | |
| `qrdx_removePeer` | ⬜ | | |
| `qrdx_getDifficulty` | ⬜ | | |
| `qrdx_getBlockReward` | ⬜ | | |

### 3.6 Network Methods (net_* namespace)
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 3.6.1 Create `qrdx/rpc/modules/net.py` | ⬜ | | |
| `net_version` | ⬜ | | |
| `net_listening` | ⬜ | | |
| `net_peerCount` | ⬜ | | |

### 3.7 Web3 Methods (web3_* namespace)
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 3.7.1 Create `qrdx/rpc/modules/web3.py` | ⬜ | | |
| `web3_clientVersion` | ⬜ | | |
| `web3_sha3` | ⬜ | | |

### 3.8 Legacy Denaro Endpoints (Toggleable)
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 3.8.1 Create `qrdx/rpc/legacy/endpoints.py` | ⬜ | | |
| 3.8.2 Deprecation warnings | ⬜ | | |

---

## Phase 4: Core Refactoring

### 4.1 Configuration System
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 4.1.1 Create `qrdx/config.py` | ⬜ | | |
| 4.1.2 Module toggle configuration | ⬜ | | |

### 4.2 Transaction Refactoring
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 4.2.1 Create `qrdx/core/transaction.py` | ⬜ | | |
| 4.2.2 Legacy transaction support | ⬜ | | |

### 4.3 Block Refactoring
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 4.3.1 Create `qrdx/core/block.py` | ⬜ | | |
| 4.3.2 Backward compatibility | ⬜ | | |

### 4.4 Database Abstraction
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 4.4.1 Create `qrdx/db/base.py` | ⬜ | | |
| 4.4.2 PostgreSQL implementation | ⬜ | | |

---

## Phase 5: Node Orchestration

### 5.1 Service Manager
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 5.1.1 Create `qrdx/node/service.py` | ⬜ | | |
| 5.1.2 Service definitions | ⬜ | | |

### 5.2 Main Node Runner
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 5.2.1 Create `qrdx/node/main.py` (new) | ⬜ | | |

### 5.3 Monitoring and Metrics
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 5.3.1 Prometheus metrics | ⬜ | | |
| 5.3.2 Health check endpoint | ⬜ | | |

---

## Phase 6: Testing and Documentation

### 6.1 Unit Tests
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 6.1.1 Crypto tests | ⬜ | | |
| 6.1.2 P2P tests | ⬜ | | |
| 6.1.3 RPC tests | ⬜ | | |

### 6.2 Integration Tests
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 6.2.1 Multi-node tests | ⬜ | | |
| 6.2.2 RPC client tests (web3.py) | ⬜ | | |

### 6.3 Documentation
| Task | Status | Assignee | Notes |
|------|--------|----------|-------|
| 6.3.1 API documentation (OpenAPI) | ⬜ | | |
| 6.3.2 Architecture documentation | ⬜ | | |
| 6.3.3 Migration guide | ⬜ | | |

---

## Summary

| Phase | Total Tasks | Completed | Progress |
|-------|-------------|-----------|----------|
| Phase 1: Crypto | 13 | 0 | 0% |
| Phase 2: P2P | 17 | 0 | 0% |
| Phase 3: RPC | 40 | 0 | 0% |
| Phase 4: Core | 8 | 0 | 0% |
| Phase 5: Orchestration | 5 | 0 | 0% |
| Phase 6: Testing | 8 | 0 | 0% |
| **Total** | **91** | **0** | **0%** |

---

*Last Updated: January 4, 2026*
