# Trinity/QRDX-Chain Modernization TODO List
## Bringing the codebase up to post-2022 Ethereum standards

This document outlines all necessary changes to modernize this archived Trinity client to support current Ethereum standards and network specifications as of 2025.

---

## 1. CONSENSUS LAYER INTEGRATION (The Merge - September 2022)

### 1.1 Proof-of-Stake Transition
- [ ] **Remove PoW Mining Infrastructure**
  - [ ] Remove/deprecate `MiningMethod.Ethash` from `trinity/network_configurations.py`
  - [ ] Remove ethash mining logic and difficulty calculations
  - [ ] Remove PoW block validation code
  - [ ] Remove mining-related RPC methods (`eth_mining`, `eth_hashrate`, `eth_getWork`, `eth_submitWork`)

- [ ] **Implement Beacon Chain Integration**
  - [ ] Add beacon chain client interface (consensus client communication)
  - [ ] Implement Engine API (JSON-RPC interface for consensus-execution communication)
    - [ ] `engine_newPayloadV1`, `engine_newPayloadV2`, `engine_newPayloadV3`
    - [ ] `engine_forkchoiceUpdatedV1`, `engine_forkchoiceUpdatedV2`, `engine_forkchoiceUpdatedV3`
    - [ ] `engine_getPayloadV1`, `engine_getPayloadV2`, `engine_getPayloadV3`
    - [ ] `engine_getPayloadBodiesByHashV1`, `engine_getPayloadBodiesByRangeV1`
    - [ ] `engine_exchangeTransitionConfigurationV1`
  - [ ] Add JWT authentication for Engine API
  - [ ] Implement execution payload structure
  - [ ] Add validator withdrawal processing
  - [ ] Handle safe head, finalized head tracking

### 1.2 Fork Choice Updates
- [ ] Implement LMD-GHOST fork choice rule
- [ ] Replace chain reorganization logic with beacon chain finality
- [ ] Update block import to wait for beacon chain validation
- [ ] Implement optimistic sync mode

---

## 2. NETWORK PROTOCOL UPGRADES

### 2.1 ETH Protocol Versions
- [ ] **Implement ETH/66** (Request IDs - EIP-2481)
  - [ ] Add request ID to all request/response pairs
  - [ ] Update `trinity/protocol/eth/proto.py` to add `ETHProtocolV66`
  - [ ] Update `trinity/protocol/eth/commands.py` for request IDs
  - [ ] Update `trinity/protocol/eth/peer.py` for v66 compatibility
  - [ ] Currently stuck on v65, note in code mentions "Disabled until eth/66 is implemented"

- [ ] **Implement ETH/67** (Remove `GetNodeData` - EIP-4938)
  - [ ] Remove `GetNodeDataV65` and `NodeDataV65` commands
  - [ ] Update state sync to not rely on node data requests
  - [ ] Implement alternative state sync mechanisms

- [ ] **Implement ETH/68** (Transaction type field)
  - [ ] Add transaction type field to announcements
  - [ ] Update `NewPooledTransactionHashes` format

### 2.2 New Protocol: SNAP (Snapshot Protocol)
- [ ] Implement `snap/1` protocol for state snapshots
  - [ ] `GetAccountRange`, `AccountRange`
  - [ ] `GetStorageRanges`, `StorageRanges`
  - [ ] `GetByteCodes`, `ByteCodes`
  - [ ] `GetTrieNodes`, `TrieNodes`
- [ ] Add snapshot sync capability alongside beam/full/light sync
- [ ] Create `trinity/protocol/snap/` directory structure

### 2.3 Discovery Protocol
- [ ] Update to Discovery v5.1
- [ ] Add ENR (Ethereum Node Records) support for consensus layer
- [ ] Update bootnode lists (currently using outdated nodes)

---

## 3. EVM UPDATES & HARD FORKS

### 3.1 London Fork (August 2021)
- [ ] **EIP-1559: Fee Market**
  - [ ] Update transaction structure with `maxFeePerGas` and `maxPriorityFeePerGas`
  - [ ] Implement base fee calculation per block
  - [ ] Add `baseFeePerGas` to block headers
  - [ ] Update gas price logic in transaction pool
  - [ ] Update RPC responses to include EIP-1559 fields
  - [ ] Implement fee burning mechanism
  
- [ ] **EIP-3529: Reduction in gas refunds**
  - [ ] Update SSTORE gas refund calculations
  - [ ] Update SELFDESTRUCT refund rules

- [ ] **EIP-3541: Reject contracts starting with 0xEF**
  - [ ] Add validation for contract code starting with 0xEF byte

### 3.2 Arrow Glacier & Gray Glacier (2021-2022)
- [ ] Implement difficulty bomb delays
- [ ] Add fork block configurations

### 3.3 Paris Fork (The Merge - September 2022)
- [ ] Add `ParisVM` to `trinity/_utils/eip1085.py` (currently stops at `BerlinVM`)
- [ ] **EIP-3675: Upgrade consensus to Proof-of-Stake**
  - [ ] Remove PoW validation from blocks post-merge
  - [ ] Add `withdrawalsRoot` to block header
  - [ ] Handle transition block (terminal total difficulty)
  - [ ] Update DIFFICULTY opcode to return PREVRANDAO
  
### 3.4 Shanghai Fork (April 2023)
- [ ] Add `ShanghaiVM` implementation
- [ ] **EIP-3651: Warm COINBASE**
  - [ ] Update COINBASE gas cost calculation
  
- [ ] **EIP-3855: PUSH0 instruction**
  - [ ] Add PUSH0 opcode (0x5F)
  
- [ ] **EIP-3860: Limit and meter initcode**
  - [ ] Add 49152 byte limit for initcode
  - [ ] Add initcode gas cost (2 gas per 32-byte chunk)
  
- [ ] **EIP-4895: Beacon chain push withdrawals**
  - [ ] Implement withdrawal processing in block execution
  - [ ] Add withdrawals to execution payload
  - [ ] Update state with withdrawal amounts

### 3.5 Cancun Fork (March 2024)
- [ ] Add `CancunVM` implementation
- [ ] **EIP-4844: Proto-Danksharding (Blob transactions)**
  - [ ] Add new transaction type (0x03) for blob transactions
  - [ ] Implement blob gas pricing (separate from regular gas)
  - [ ] Add `blobVersionedHashes` to transactions
  - [ ] Implement blob verification (KZG commitments)
  - [ ] Add `excessBlobGas` and `blobGasUsed` to block headers
  - [ ] Update mempool to handle blob transactions
  - [ ] Implement blob pruning (keep for ~18 days)
  
- [ ] **EIP-1153: Transient storage opcodes**
  - [ ] Add TSTORE opcode (0x5C)
  - [ ] Add TLOAD opcode (0x5D)
  
- [ ] **EIP-4788: Beacon block root in EVM**
  - [ ] Add `parentBeaconBlockRoot` to block header
  - [ ] Store beacon roots in system contract
  
- [ ] **EIP-5656: MCOPY instruction**
  - [ ] Add MCOPY opcode (0x5E) for memory copying
  
- [ ] **EIP-6780: SELFDESTRUCT only in same transaction**
  - [ ] Update SELFDESTRUCT behavior
  
- [ ] **EIP-7516: BLOBBASEFEE opcode**
  - [ ] Add BLOBBASEFEE opcode (0x4A)

### 3.6 Prague/Electra Fork (Expected 2025)
- [ ] Monitor EIP proposals for inclusion
- [ ] **Potential EIPs to implement:**
  - [ ] EIP-2537: BLS12-381 precompiles
  - [ ] EIP-2935: Historical block hashes in state
  - [ ] EIP-6110: Supply validator deposits on-chain
  - [ ] EIP-7002: Execution layer triggerable exits
  - [ ] EIP-7251: Increase max effective balance
  - [ ] EIP-7549: Move committee index outside attestation
  - [ ] EIP-7685: General purpose execution layer requests

---

## 4. RPC API UPDATES

### 4.1 Core JSON-RPC Methods Updates
- [ ] Update `eth_getBlockByNumber` and `eth_getBlockByHash`
  - [ ] Add `baseFeePerGas` field
  - [ ] Add `withdrawals` field (post-Shanghai)
  - [ ] Add `withdrawalsRoot` field
  - [ ] Add `blobGasUsed` field (post-Cancun)
  - [ ] Add `excessBlobGas` field (post-Cancun)
  - [ ] Add `parentBeaconBlockRoot` field (post-Cancun)

- [ ] Update `eth_getTransactionByHash` and related methods
  - [ ] Add EIP-1559 fields (`maxFeePerGas`, `maxPriorityFeePerGas`)
  - [ ] Add `type` field for transaction types
  - [ ] Add `accessList` for type 1 transactions
  - [ ] Add `blobVersionedHashes`, `maxFeePerBlobGas` for type 3 transactions

- [ ] Update `eth_getTransactionReceipt`
  - [ ] Add `blobGasUsed` and `blobGasPrice` fields
  - [ ] Update `effectiveGasPrice` calculation

- [ ] Add new methods:
  - [ ] `eth_maxPriorityFeePerGas` - EIP-1559 fee estimation
  - [ ] `eth_feeHistory` - Historical fee data
  - [ ] `eth_createAccessList` - Generate access lists

### 4.2 Filter & Subscription Updates
- [ ] Update `eth_newBlockFilter` for new block structure
- [ ] Update `eth_subscribe` for new transaction types
- [ ] Add proper handling for pending transaction subscriptions

### 4.3 Debug/Trace APIs
- [ ] Update trace APIs for new opcodes
- [ ] Add support for tracing blob transactions
- [ ] Update `debug_traceTransaction` for transient storage

---

## 5. TRANSACTION TYPES & HANDLING

### 5.1 Existing Transaction Types (Already Partially Implemented)
- [ ] **Type 0 (Legacy)** - Verify full compatibility
- [ ] **Type 1 (EIP-2930: Access Lists)** - Currently has some support, verify completeness
- [ ] **Type 2 (EIP-1559: Dynamic Fee)** - Needs implementation

### 5.2 New Transaction Types
- [ ] **Type 3 (EIP-4844: Blob Transactions)**
  - [ ] Add transaction encoding/decoding
  - [ ] Implement blob verification logic
  - [ ] Update transaction pool handling
  - [ ] Add blob gas price market

### 5.3 Transaction Pool Updates
- [ ] Update pool to handle all transaction types
- [ ] Implement EIP-1559 transaction ordering
- [ ] Add blob transaction pool management
- [ ] Update fee estimation logic
- [ ] Implement proper transaction replacement rules

---

## 6. STATE MANAGEMENT & SYNC

### 6.1 State Sync Modernization
- [ ] Implement Snap Sync (faster than current beam/full sync)
- [ ] Add checkpoint sync capability
- [ ] Implement state expiry/statelessness preparations (if pursuing this)
- [ ] Update state healing mechanisms

### 6.2 Database & Storage
- [ ] Update database schema for new block/transaction fields
- [ ] Implement efficient storage for withdrawals
- [ ] Add blob storage and pruning
- [ ] Optimize state storage (consider moving to newer db backend)
- [ ] Currently uses LevelDB via `plyvel==1.2.0` - consider alternatives

### 6.3 Trie Updates
- [ ] Verify Verkle trie preparation (future-proofing)
- [ ] Optimize MPT implementation for current state sizes
- [ ] Add witness support for stateless validation

---

## 7. TESTING INFRASTRUCTURE

### 7.1 Update Test Fixtures
- [ ] Update to latest Ethereum test fixtures
  - [ ] Currently using outdated fixtures stopping at Berlin fork
  - [ ] Add London fork tests
  - [ ] Add Paris/Merge fork tests
  - [ ] Add Shanghai fork tests
  - [ ] Add Cancun fork tests
  
- [ ] Update `fixtures/` directory with latest test vectors
- [ ] Update RPC test suite in `tests/json-fixtures-over-rpc/`

### 7.2 Integration Tests
- [ ] Add Engine API integration tests
- [ ] Add blob transaction tests
- [ ] Add withdrawal processing tests
- [ ] Test fork transitions (especially The Merge)
- [ ] Add consensus-execution layer interaction tests

### 7.3 Network Tests
- [ ] Test ETH/66, ETH/67, ETH/68 protocol implementations
- [ ] Test SNAP protocol
- [ ] Test peer compatibility with modern clients

---

## 8. DEPENDENCY UPDATES

### 8.1 Core Dependencies
- [ ] **Upgrade Python version**
  - [ ] Current: Python 3.7-3.8
  - [ ] Target: Python 3.10+ (3.12 recommended)
  - [ ] Update in `setup.py`, `tox.ini`, `Dockerfile`
  
- [ ] **Upgrade py-evm**
  - [ ] Current: `py-evm==0.4.0a3` (ancient alpha version)
  - [ ] Target: Latest stable py-evm with all fork support
  - [ ] This is critical - py-evm needs to support London through Cancun
  
- [ ] **Upgrade ethereum libraries**
  - [ ] `eth-utils>=1.9.3,<2` → Latest v2.x or v3.x
  - [ ] `eth-typing>=2.2.2,<3` → Latest v3.x or v4.x
  - [ ] `eth-keys>=0.3.3,<0.4.0` → Latest v0.5.x
  - [ ] `web3>=5.12.1,<6` → Latest v6.x or v7.x
  - [ ] `rlp[rust-backend]>=2,<3` → Latest v4.x

### 8.2 P2P & Networking Dependencies
- [ ] Update `cryptography>=3.0,<3.2` → Latest v42.x (major security updates)
- [ ] Update `coincurve>=15.0.0,<16.0.0` → Latest v19.x or v20.x
- [ ] Update `eth-enr>=0.3.0,<0.4` → Latest with Discovery v5.1 support
- [ ] Update `trio>=0.16.0,<0.17` → Latest v0.24.x or v0.25.x

### 8.3 Other Dependencies
- [ ] Update `aiohttp==3.6.0` → Latest v3.9.x (security fixes)
- [ ] Update `SQLAlchemy>=1.3.3,<2` → v2.x (major version upgrade)
- [ ] Update `ipython>=7.8.0,<7.10.0` → Latest v8.x
- [ ] Update `uvloop==0.14.0` → Latest v0.19.x
- [ ] Update all test dependencies to current versions

### 8.4 Remove Deprecated Dependencies
- [ ] Evaluate if `lahja` event bus is still optimal (v0.17.0 is old)
- [ ] Check if `async-service`, `asyncio-cancel-token` have better alternatives
- [ ] Review `plyvel` vs other LevelDB/database options

---

## 9. NETWORK CONFIGURATION UPDATES

### 9.1 Mainnet Updates
- [ ] Update mainnet configuration in `trinity/network_configurations.py`
- [ ] Add all fork blocks: London, Arrow Glacier, Gray Glacier, Paris (Merge), Shanghai, Cancun
- [ ] Update VM configuration to include all VMs through CancunVM
- [ ] Update genesis parameters if needed
- [ ] Update bootnodes to current active nodes

### 9.2 Testnet Updates
- [ ] **Remove deprecated testnets**
  - [ ] Remove Ropsten (deprecated 2022)
  - [ ] Remove Görli (deprecated 2024)
  
- [ ] **Add current testnets**
  - [ ] Add Sepolia configuration (current main testnet)
  - [ ] Add Holesky configuration (consensus testnet)
  - [ ] Add Devnet configurations for testing upcoming forks

### 9.3 Genesis Files
- [ ] Update `trinity/assets/` EIP-1085 genesis files
- [ ] Add Sepolia genesis
- [ ] Add Holesky genesis
- [ ] Update mainnet genesis if parameters changed

---

## 10. DOCUMENTATION UPDATES

### 10.1 Code Documentation
- [ ] Update all docstrings for modified functions
- [ ] Document Engine API endpoints
- [ ] Document new transaction types
- [ ] Add architecture docs for consensus integration

### 10.2 User Documentation
- [ ] Update `README.md` with current status
- [ ] Update `DEVELOPMENT.md` with new setup requirements
- [ ] Document running with consensus client (e.g., Lighthouse, Prysm)
- [ ] Add configuration examples for post-Merge operation
- [ ] Update CLI documentation

### 10.3 API Documentation
- [ ] Update RPC API documentation
- [ ] Document Engine API
- [ ] Update sync mode documentation
- [ ] Document blob transaction handling

---

## 11. INFRASTRUCTURE & DEVOPS

### 11.1 Docker Updates
- [ ] Update `docker/Dockerfile` to use Python 3.10+
- [ ] Update `docker/beacon.Dockerfile` for consensus integration
- [ ] Add docker-compose setup with consensus client
- [ ] Update DAppNode package in `dappnode/`

### 11.2 CI/CD Updates
- [ ] Update `.circleci/config.yml` for Python 3.10+
- [ ] Add tests for all new forks
- [ ] Add Engine API integration tests in CI
- [ ] Update tox environments in `tox.ini`

### 11.3 Build System
- [ ] Update `setup.py` with new dependencies
- [ ] Update `Makefile` commands if needed
- [ ] Verify `MANIFEST.in` includes all necessary files
- [ ] Update `mypy.ini` for newer mypy versions

---

## 12. SECURITY & COMPLIANCE

### 12.1 Security Updates
- [ ] Audit all cryptography usage for vulnerabilities
- [ ] Implement JWT authentication for Engine API
- [ ] Review DOS attack vectors with new transaction types
- [ ] Audit blob transaction validation
- [ ] Update all dependencies with known CVEs

### 12.2 Compliance
- [ ] Ensure MEV-boost compatibility (if supporting validators)
- [ ] Implement proper handling of censorship-resistant transactions
- [ ] Add metrics for monitoring consensus-execution health

---

## 13. PERFORMANCE OPTIMIZATION

### 13.1 Sync Performance
- [ ] Implement parallel block execution
- [ ] Optimize state sync with Snap protocol
- [ ] Add caching layers for frequent state reads
- [ ] Optimize database queries

### 13.2 EVM Performance
- [ ] Optimize new opcode implementations
- [ ] Add JIT compilation considerations
- [ ] Profile and optimize hot paths
- [ ] Consider move to Rust EVM (like revm) for performance

### 13.3 Network Performance
- [ ] Optimize peer management
- [ ] Implement better bandwidth management for blobs
- [ ] Add connection pooling improvements
- [ ] Optimize block propagation

---

## 14. BACKWARDS COMPATIBILITY & MIGRATION

### 14.1 Database Migration
- [ ] Create migration scripts for existing Trinity databases
- [ ] Handle legacy block/transaction formats
- [ ] Migrate to new schema versions
- [ ] Add rollback capabilities

### 14.2 Configuration Migration
- [ ] Migrate old config files to new format
- [ ] Provide compatibility mode for legacy operations
- [ ] Document breaking changes

---

## 15. MONITORING & OBSERVABILITY

### 15.1 Metrics
- [ ] Add Prometheus metrics for Engine API
- [ ] Add metrics for blob transactions
- [ ] Add consensus-execution sync metrics
- [ ] Monitor memory usage with new features

### 15.2 Logging
- [ ] Update logging for new components
- [ ] Add structured logging for Engine API calls
- [ ] Improve error messages for common issues
- [ ] Add debug modes for troubleshooting

---

## PRIORITY ORDERING

### Phase 1: Critical Foundation (Must-do first)
1. Upgrade Python to 3.10+
2. Upgrade py-evm to latest version with fork support
3. Upgrade all core dependencies
4. Implement London fork (EIP-1559)

### Phase 2: The Merge (Highest Priority)
1. Implement Engine API
2. Add Paris fork support
3. Remove PoW mining
4. Implement beacon chain integration
5. Update to ETH/66 and ETH/67

### Phase 3: Recent Forks
1. Implement Shanghai fork (withdrawals)
2. Implement Cancun fork (blobs/4844)
3. Update RPC APIs for all new fields
4. Implement Snap protocol

### Phase 4: Network & Testing
1. Update network configurations
2. Remove deprecated testnets, add Sepolia/Holesky
3. Update test fixtures
4. Integration testing

### Phase 5: Optimization & Polish
1. Performance optimization
2. Documentation updates
3. Migration tools
4. Monitoring improvements

---

## ESTIMATED EFFORT

- **Total estimated time**: 6-12 months for complete modernization
- **Minimum viable modernized client**: 3-4 months (through Phase 3)
- **Team size recommended**: 3-5 experienced Ethereum protocol developers

---

## ALTERNATIVE APPROACH

Given the massive scope of work required, consider:

1. **Fork Modern Client**: Start with a modern client like Reth (Rust), Erigon (Go), or Nethermind (C#) and adapt to your needs
2. **Focus on Specific Features**: If only certain Trinity features are needed, implement them on top of modern client
3. **Hybrid Approach**: Use Trinity for specific legacy features, modern client for consensus/execution

The Ethereum ecosystem has moved significantly since Trinity was archived. A complete modernization is a major undertaking comparable to building a new client.

---

## NOTES

- Trinity was archived in ~2021, before The Merge
- Current latest fork support: Berlin (April 2021)
- Protocol support: ETH/65 (v66 explicitly noted as not implemented)
- Major gap: No Proof-of-Stake support at all
- This would essentially require rebuilding large portions of the client

**Recommendation**: Unless there are specific Trinity features that cannot be found elsewhere, starting fresh with a modern client codebase or contributing to an existing modern client would likely be more efficient than modernizing Trinity.
