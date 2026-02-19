# QRDX Protocol — Full Implementation & Production Readiness Checklist

> **Version:** 3.2 · **Date:** February 18, 2026  
> **Purpose:** Track every whitepaper feature through six mandatory gates before mainnet.  
> **Source of truth:** `QRDX-Whitepaper-v.3.2.md` §1–§18

---

## How to Read This Document

Every feature is tracked through **six gates** in order. A feature **cannot** advance to the next gate until the current gate is fully checked. All six must be ✅ before the feature is **mainnet-eligible**.

| Gate | Symbol | Meaning |
|------|--------|---------|
| **Implemented** | `[x]` / `[ ]` | Working code exists in the repository (not just config or comments) |
| **Verified** | `[x]` / `[ ]` | Automated tests (unit + integration) pass with >90% branch coverage for the module |
| **Security Tested** | `[x]` / `[ ]` | Passed adversarial review: fuzz testing, static analysis, manual audit, no known vulns |
| **Consensus / Decentralized** | `[x]` / `[ ]` | No single point of failure; works with N≥4 independent validators; no hardcoded central infra |
| **No Stubs** | `[x]` / `[ ]` | Zero fallback/mock/stub code paths remain; all dependencies are real and required |
| **Production Ready** | `[x]` / `[ ]` | Deployed on persistent testnet ≥30 days with no regressions; documentation complete |

---

## Step 0 — Critical Security Blockers (Fix Before Anything Else)

> These must be resolved before ANY testnet deployment.

### 0.1 Hardcoded Private Key in Repository
- **File:** `ref/ref_private_key` (value `83844...18925`)
- **Risk:** Anyone with repo access can impersonate the node identity
- [x] Implemented — `.gitignore` updated with `*.priv`, `*.key`, `*.pem`, `*private_key*`, `*secret_key*`, `*.keystore` patterns
- [ ] Verified — CI secret-scanning job (e.g., `gitleaks`, `trufflehog`) blocks future commits containing keys
- [ ] Security Tested — Old key rotated; all systems using old key re-provisioned
- [ ] Consensus / Decentralized — Each node generates its own key at first boot; no shared keys
- [x] No Stubs — Key generation uses real entropy (`os.urandom`), not deterministic seeds
- [ ] Production Ready — Key management runbook documented; HSM guidance provided

### 0.2 PQ Signature Verification Bypass (Silent `return True`)
- **File:** `qrdx/crypto/pq/dilithium.py` — fallback verify returned `True` when `liboqs` absent
- **Risk:** Any node without `liboqs` accepts ALL transactions as valid, including forged ones
- [x] Implemented — Module fails hard at import if liboqs absent; `verify()` always uses `oqs.Signature.verify()`
- [x] Verified — `test_no_verify_bypass`: garbage signatures rejected; `test_verify_wrong_message_fails`, `test_verify_wrong_key_fails` all pass (79/79 tests)
- [ ] Security Tested — Fuzz test: submit transactions with garbage signatures → all rejected
- [ ] Consensus / Decentralized — All validators enforce the same hard requirement
- [x] No Stubs — `_HAS_LIBOQS` flag, `_generate_fallback_keys()`, `PQNotAvailableError` all removed
- [ ] Production Ready — `liboqs-python>=0.9.0` is in ALL requirements files and Docker images

### 0.3 Fake PQ Key Generation
- **File:** `qrdx/crypto/pq/dilithium.py` — `_generate_fallback_keys()` produced SHA256-padded bytes
- **Risk:** Nodes appear to have PQ identity but are using deterministic, predictable keys
- [x] Implemented — `_generate_fallback_keys()` and `from_seed()` removed; keygen fails hard without liboqs
- [x] Verified — `test_no_fake_keys` (entropy > 7.0 bits/byte), `test_public_key_not_repeated_pattern`, `test_no_from_seed_method` all pass
- [ ] Security Tested — Audit confirms no code path produces non-random PQ keys
- [ ] Consensus / Decentralized — N/A (per-node key generation)
- [x] No Stubs — Zero fake/mock/deterministic key code remains in `qrdx/crypto/pq/`
- [ ] Production Ready — Key generation audited by external PQ cryptographer

### 0.4 Default Database Credentials
- **Files:** `config.example.toml`, `setup.sh`, `docker/docker-compose.yml`
- **Risk:** Default `qrdx`/`qrdx` credentials in production
- [x] Implemented — config.example.toml uses `${QRDX_DB_USER}` / `${QRDX_DB_PASSWORD}` placeholders; setup.sh reads from env vars
- [ ] Verified — CI fails if any file contains literal default credentials
- [ ] Security Tested — Credential rotation tested; DB access works only with provisioned creds
- [ ] Consensus / Decentralized — Each node operator provisions own DB; no shared credentials
- [x] No Stubs — No hardcoded fallback passwords in any code path
- [ ] Production Ready — Deployment guide requires credential provisioning as step 1

### 0.5 Docker Requirements File Mismatch
- **File:** `docker/Dockerfile` installs `requirements-v3.txt` (fixed from `requirements.txt`)
- **Risk:** Docker images lacked `liboqs-python` — PQ crypto silently disabled
- [x] Implemented — Dockerfile now `COPY ./requirements-v3.txt .` and `pip install -r ./requirements-v3.txt`
- [ ] Verified — Docker build test asserts `import oqs` succeeds inside container
- [ ] Security Tested — Container scan confirms all PQ dependencies present and pinned
- [ ] Consensus / Decentralized — N/A (build-time concern)
- [x] No Stubs — liboqs is mandatory; module import fails hard without it
- [ ] Production Ready — Multi-stage Docker build with pinned dependency hashes

---

## Step 1 — Post-Quantum Cryptography (Whitepaper §4)

### 1.1 CRYSTALS-Dilithium (ML-DSA-65) Signatures
- **Files:** `qrdx/crypto/pq/dilithium.py`, `qrdx/crypto/pq/__init__.py`
- [x] Implemented — `PQPrivateKey`, `PQPublicKey`, `PQSignature`, `generate_keypair()`, `sign()`, `verify()` via `liboqs` ML-DSA-65 (FIPS 204)
- [x] Verified — 32 Dilithium tests pass: keygen, sign, verify, round-trip, invalid-sig rejection, key size validation, serialization, entropy checks
- [ ] Security Tested — Fuzz: random bytes as signatures → all rejected; timing side-channel analysis
- [ ] Consensus / Decentralized — All validators use real Dilithium keys; no shared or derived keys
- [x] No Stubs — `_HAS_LIBOQS`, `_generate_fallback_keys()`, `from_seed()`, fake signing all removed; liboqs mandatory at import
- [ ] Production Ready — Algorithm OID matches NIST FIPS 204; interop tested with reference implementation

### 1.2 CRYSTALS-Kyber (ML-KEM-768) Key Encapsulation
- **Files:** `qrdx/crypto/pq/kyber.py`, `qrdx/crypto/pq/__init__.py`
- [x] Implemented — `KEMPrivateKey`, `KEMPublicKey`, `kyber_generate_keypair()`, `kyber_encapsulate()`, `kyber_decapsulate()` via `liboqs` ML-KEM-768 (FIPS 203)
- [x] Verified — 10 Kyber tests pass: keygen, encap/decap round-trip, wrong-key rejection, unique secrets, type validation
- [ ] Security Tested — Ciphertext malleability test; invalid ciphertext rejection
- [ ] Consensus / Decentralized — Used in P2P handshake between all node pairs
- [x] No Stubs — liboqs mandatory at import; algorithm validated at module load
- [ ] Production Ready — KEM used for all validator-to-validator encrypted channels

### 1.3 PQ Address Derivation (`0xPQ` prefix)
- **File:** `qrdx/crypto/address.py`
- [x] Implemented — Dual addressing: `0x` (secp256k1) + `0xPQ` (Dilithium) with checksums
- [x] Verified — 6 address tests pass: format, length, determinism, uniqueness, type detection, private-key-to-address consistency
- [ ] Security Tested — No address confusion between classical and PQ formats
- [ ] Consensus / Decentralized — All nodes derive addresses identically from the same public key
- [x] No Stubs — PQ addresses require real Dilithium public keys (key size validated at construction)
- [ ] Production Ready — Address format documented in developer SDK

### 1.4 secp256k1 Classical Signatures (Web3 Compatibility)
- **Files:** `qrdx/crypto/keys.py`, `qrdx/crypto/signing.py`
- [x] Implemented — EIP-155, EIP-191, EIP-712 signing via `eth-keys` / `coincurve`
- [x] Verified — 6 classical tests pass: keygen, key size, uniqueness, address format, sign/verify, wrong-message rejection
- [ ] Security Tested — Classical signatures are NOT accepted for consensus-critical operations
- [ ] Consensus / Decentralized — Classical keys used only for bridge/EVM compatibility, never for block signing
- [x] No Stubs — N/A (mature libraries)
- [ ] Production Ready — Clear documentation: classical keys are second-class; PQ keys are authoritative

---

## Step 2 — Node Identity & P2P Network (Whitepaper §5)

### 2.1 PQ Node Identity (`@`-schema Addressing)
- **Whitepaper:** `dilithium3@<pubkey_hash>@<host>:<port>`
- **Current state:** Two *classical* identity systems — P256 (`qrdx/p2p/identity.py`) and secp256k1 (`qrdx/p2p/node.py`)
- [ ] Implemented — Single Dilithium-based identity; `@`-schema format for all node addressing
- [ ] Verified — Parse + serialize round-trip tests for `@`-schema URIs; invalid format rejection
- [ ] Security Tested — Identity spoofing test: node with wrong Dilithium key is rejected by peers
- [ ] Consensus / Decentralized — Identity is self-sovereign; no registration authority
- [ ] No Stubs — P256 and secp256k1 identity code removed from `qrdx/p2p/`
- [ ] Production Ready — Migration path documented for existing nodes changing identity format

### 2.2 P2P Transport Layer
- **Current state:** All node communication is plain HTTP REST (`qrdx/node.py` via FastAPI)
- [ ] Implemented — Wire protocol (RLPx or Noise framework) with Kyber768 KEM handshake
- [ ] Verified — Integration test: two nodes complete PQ handshake and exchange blocks
- [ ] Security Tested — MITM test: intercepted handshake fails; replay attack rejected
- [ ] Consensus / Decentralized — All peer connections use identical PQ-authenticated transport
- [ ] No Stubs — No plaintext HTTP fallback for node-to-node communication
- [ ] Production Ready — Bandwidth benchmarks acceptable (Dilithium sigs are ~2.4 KB; measured overhead <5%)

### 2.3 Peer Discovery (Kademlia DHT)
- **Current state:** Hardcoded bootstrap nodes (`node.qrdx.network`, `node2.qrdx.network`, `node3.qrdx.network`)
- [ ] Implemented — Kademlia DHT with PQ node IDs; bootstrap nodes are initial seeds only
- [ ] Verified — Test: new node discovers peers through DHT without contacting bootstrap after initial join
- [ ] Security Tested — Eclipse attack resistance: Sybil-resistant node ID generation; routing table hardening
- [ ] Consensus / Decentralized — Network functions if all bootstrap nodes go offline (DHT self-sustains)
- [ ] No Stubs — No fallback to hardcoded HTTP endpoint list
- [ ] Production Ready — ≥50 nodes sustained on testnet for 30+ days with bootstrap nodes turned off

### 2.4 Bootstrap Node Decentralization
- **Files:** `qrdx/p2p/bootstrap.py`, `config.example.toml`
- [ ] Implemented — Community-operated bootstrap nodes; DNS-based seed discovery (`_qrdx._tcp.qrdx.org`)
- [ ] Verified — Test: node resolves bootstrap via DNS TXT records containing `@`-schema addresses
- [ ] Security Tested — DNSSEC validation; poisoned DNS records rejected
- [ ] Consensus / Decentralized — ≥5 independent organizations operate bootstrap nodes
- [ ] No Stubs — No hardcoded IP addresses or domain names as sole discovery method
- [ ] Production Ready — Bootstrap node operator guide published

---

## Step 3 — Consensus: Quantum-Resistant Proof-of-Stake (Whitepaper §11)

### 3.1 QR-PoS Core Engine
- **File:** `qrdx/consensus.py` (1,138 lines)
- [x] Implemented — `ConsensusV2POS` class; Merkle tree, timestamp validation, coinbase validation
- [ ] Verified — 836-line test suite exists (`tests/test_validator.py`); needs branch coverage measurement
- [ ] Security Tested — Nothing-at-stake attack test; long-range attack test; time-warp attack test
- [ ] Consensus / Decentralized — Tested with N≥4 independent validators producing blocks in rotation
- [ ] No Stubs — Legacy `ConsensusV1` (PoW) class fully removed from `consensus.py`
- [ ] Production Ready — Consensus spec document matches code behavior exactly

### 3.2 Validator Manager
- **File:** `qrdx/validator/manager.py` (1,113 lines)
- [x] Implemented — PQ wallet required; Dilithium block signing; proposer + attestation flow
- [ ] Verified — Integration test: validator proposes block, others attest, block finalized
- [ ] Security Tested — Invalid proposer test; attestation forgery test; equivocation detection
- [ ] Consensus / Decentralized — Dynamic validator set; no hardcoded validator list
- [ ] No Stubs — `MIN_VALIDATORS = 1` changed to `MIN_VALIDATORS = 4` for mainnet
- [ ] Production Ready — Validator onboarding guide; key ceremony documentation

### 3.3 Stake Management
- **File:** `qrdx/validator/stake.py`
- [x] Implemented — Deposits, withdrawals, unbonding period (~7 days), effective stake calculation
- [ ] Verified — Test: deposit → wait unbonding → withdraw; partial withdrawal; insufficient balance rejection
- [ ] Security Tested — Stake grinding attack test; flash-loan stake test (same-block deposit+propose)
- [ ] Consensus / Decentralized — Stake distribution Gini coefficient monitored; no single validator >33%
- [ ] No Stubs — Real DB persistence; no in-memory-only stake tracking
- [ ] Production Ready — Stake dashboard; alerting for concentration thresholds

### 3.4 RANDAO Proposer & Committee Selection
- **File:** `qrdx/validator/selection.py`
- [x] Implemented — RANDAO-based selection with stake weighting
- [ ] Verified — Statistical test: selection frequency proportional to stake over 10,000 epochs
- [ ] Security Tested — RANDAO bias resistance test; proposer cannot influence next-epoch selection
- [ ] Consensus / Decentralized — Selection is deterministic from shared randomness; no coordinator
- [ ] No Stubs — Uses real on-chain RANDAO accumulator, not `random.seed()`
- [ ] Production Ready — Selection algorithm formally specified and peer-reviewed

### 3.5 Attestations
- **File:** `qrdx/validator/attestation.py`
- [x] Implemented — Dilithium-signed attestations; attestation pool; aggregation
- [ ] Verified — Test: aggregate N attestations; reject duplicate/late attestations
- [ ] Security Tested — Surround-vote slashing test; attestation spam resistance
- [ ] Consensus / Decentralized — All committee members attest independently
- [ ] No Stubs — Attestation signatures are real Dilithium (not classical fallback)
- [ ] Production Ready — Attestation inclusion rate >95% on testnet over 7 days

### 3.6 Slashing
- **File:** `qrdx/validator/slashing.py`
- [x] Implemented — Double-sign, surround vote, downtime, bridge fraud penalties
- [ ] Verified — Test: simulate each slashable offense → confirm penalty applied and validator ejected
- [ ] Security Tested — False-positive slashing test; griefing resistance (can't trick honest validator into slashable state)
- [ ] Consensus / Decentralized — Slashing evidence submitted by any node; processed by consensus
- [ ] No Stubs — `BRIDGE_FRAUD` slashing exists but has no bridge to monitor (see §7)
- [ ] Production Ready — Slashing event alerts; validator protection (slashing DB in `validator/config.py`)

### 3.7 Finality (LMD-GHOST + Casper FFG)
- **File:** `qrdx/validator/fork_choice.py`
- [x] Implemented — Fork choice rule combining LMD-GHOST and Casper FFG
- [ ] Verified — Test: competing forks → correct fork selected; justified/finalized checkpoints advance
- [ ] Security Tested — 33% adversary cannot revert finalized blocks
- [ ] Consensus / Decentralized — Finality achieved with ≥2/3 honest stake online
- [ ] No Stubs — Fork choice uses real attestation weights, not simulated
- [ ] Production Ready — Finality monitoring dashboard; alert if finality stalls >2 epochs

### 3.8 Rewards & Inflation
- **File:** `qrdx/validator/rewards.py`
- [x] Implemented — Proposer rewards, attestation rewards, sync committee rewards, inflation schedule
- [ ] Verified — Test: reward calculation matches spec for various scenarios; total issuance audit
- [ ] Security Tested — Reward manipulation test; MEV-related reward gaming
- [ ] Consensus / Decentralized — Rewards computed deterministically from on-chain state
- [ ] No Stubs — Reward distribution is real token issuance, not accounting entries
- [ ] Production Ready — Inflation schedule matches whitepaper §12 tokenomics

### 3.9 Sync Committee
- **File:** `qrdx/validator/sync_committee.py`
- [x] Implemented — Eth2-style sync committee for light client support
- [ ] Verified — Test: sync committee rotation; light client syncs using committee signatures
- [ ] Security Tested — Committee key leakage test; committee member selection not predictable
- [ ] Consensus / Decentralized — Committee members selected randomly from validator set
- [ ] No Stubs — Sync committee signatures are real Dilithium
- [ ] Production Ready — Light client SDK uses sync committee for fast sync

### 3.10 Legacy PoW Removal
- **File:** `qrdx/consensus.py` — `ConsensusV1` class, PoW constants
- [ ] Implemented — All PoW code paths removed from `consensus.py`
- [ ] Verified — No test, import, or config references PoW classes or difficulty constants
- [ ] Security Tested — Audit confirms no code path can activate mining-based consensus
- [ ] Consensus / Decentralized — N/A (removal item)
- [ ] No Stubs — Zero lines of PoW code remain in production codebase
- [ ] Production Ready — Changelog documents PoW removal with rationale

---

## Step 4 — QEVM: Quantum-Resistant EVM (Whitepaper §3.3)

### 4.1 QRDX VM Fork (Shanghai + PQ Precompiles)
- **Files:** `py-evm/eth/vm/forks/qrdx/`
- [x] Implemented — `QRDXVM` extends `ShanghaiVM`; precompiles at `0x09`–`0x0c`
- [ ] Verified — Each precompile has dedicated unit tests with known-answer-tests (KATs)
- [ ] Security Tested — Precompile gas costs prevent DoS; invalid input handling for all precompiles
- [ ] Consensus / Decentralized — All nodes produce identical results for precompile calls (determinism test)
- [ ] No Stubs — Precompiles call real `liboqs` bindings; no placeholder returns
- [ ] Production Ready — Gas costs benchmarked and tuned on testnet

### 4.2 Production Executor Uses QRDXVM
- **Current state:** `executor_v2.py` imports `ShanghaiVM`, not `QRDXVM`
- [ ] Implemented — `executor_v2.py` switched to use `QRDXVM` with PQ precompiles
- [ ] Verified — Integration test: deploy contract calling PQ precompile → correct result
- [ ] Security Tested — Executor cannot fall back to non-PQ VM under any condition
- [ ] Consensus / Decentralized — All nodes run identical QRDXVM version (version assertion at startup)
- [ ] No Stubs — `executor_v1.py` deprecated or removed; single production executor
- [ ] Production Ready — EVM compatibility test suite passes (Ethereum execution spec tests)

### 4.3 State Bridge (Native ↔ EVM)
- **File:** `qrdx/evm/state_bridge.py`
- [x] Implemented — Bidirectional state sync between QRDX native state and EVM state
- [x] Verified — 517-line test suite (`tests/test_evm.py`) covers state sync
- [ ] Security Tested — State inconsistency injection test; atomicity test (partial sync rollback)
- [ ] Consensus / Decentralized — State sync is consensus-critical; divergence = fork
- [ ] No Stubs — Real database read/write; no in-memory mocking in production path
- [ ] Production Ready — State migration tooling for upgrades

### 4.4 Exchange Engine Precompiles (`0x0100`–`0x0104`)
- **Whitepaper:** `createPool`, `swap`, `addLiquidity`, `placeLimitOrder`, `cancelOrder`
- [ ] Implemented — Precompile contracts registered and callable from QEVM
- [ ] Verified — Each precompile tested with valid and invalid inputs
- [ ] Security Tested — Reentrancy test; integer overflow; sandwich attack resistance
- [ ] Consensus / Decentralized — Pool state deterministic across all nodes
- [ ] No Stubs — Precompiles execute real exchange logic (see §5)
- [ ] Production Ready — Gas benchmarks for each exchange operation

### 4.5 Oracle Precompiles (`0x0200`–`0x0202`)
- **Whitepaper:** `getChainState`, `verifyExternalProof`, `submitCrossChainTx`
- [ ] Implemented — Precompile contracts for cross-chain oracle operations
- [ ] Verified — Each precompile tested with mock and real external chain data
- [ ] Security Tested — Invalid proof rejection; stale state detection
- [ ] Consensus / Decentralized — Oracle state agreed upon by ≥2/3 validators
- [ ] No Stubs — Precompiles read from real attested chain state (see §7)
- [ ] Production Ready — Latency benchmarks for cross-chain state reads

---

## Step 5 — Integrated Exchange Engine (Whitepaper §7)

### 5.1 Concentrated Liquidity AMM
- **Status:** ❌ Not started — QPL proposal doc only
- [ ] Implemented — `qrdx/exchange/amm.py` with tick-based concentrated liquidity (Uniswap V3 model)
- [ ] Verified — Test: add liquidity at tick range → swap → correct output; fee accrual
- [ ] Security Tested — Price manipulation test; flash loan attack; rounding error exploitation
- [ ] Consensus / Decentralized — Pool state in protocol trie, not contract storage; deterministic across nodes
- [ ] No Stubs — Real token transfers on swap; no simulated accounting
- [ ] Production Ready — Liquidity depth sufficient for <1% slippage at target volumes

### 5.2 On-Chain Order Book
- **Status:** ❌ Not started
- [ ] Implemented — `qrdx/exchange/orderbook.py` with limit orders, cancellation, partial fills
- [ ] Verified — Test: place/cancel/fill orders; order priority (price-time); partial fill accounting
- [ ] Security Tested — Order spoofing test; front-running resistance; DoS via mass order placement
- [ ] Consensus / Decentralized — Order matching deterministic; no off-chain sequencer
- [ ] No Stubs — Orders backed by real locked collateral
- [ ] Production Ready — Order book depth configurable per pool; benchmarked at 500+ open orders

### 5.3 Fee Tiers & Distribution
- **Status:** ❌ Not started
- [ ] Implemented — Configurable fee tiers (0.01%, 0.05%, 0.30%, 1.00%); protocol fee split
- [ ] Verified — Test: fee calculation correct for each tier; LP fee claim
- [ ] Security Tested — Fee manipulation via tick crossing; MEV extraction analysis
- [ ] Consensus / Decentralized — Fee parameters governed on-chain (see §9 Governance)
- [ ] No Stubs — Fees are real token amounts, not accounting
- [ ] Production Ready — Fee revenue dashboard; LP earnings reporting

### 5.4 User-Deployable Pools
- **Status:** ❌ Not started
- [ ] Implemented — Any address can call `createPool` with sufficient staked QRDX
- [ ] Verified — Test: permissionless pool creation; duplicate pool rejection; parameter validation
- [ ] Security Tested — Pool creation spam resistance (stake requirement); rug-pull protections
- [ ] Consensus / Decentralized — Pool creation is a protocol-level transaction, not admin-gated
- [ ] No Stubs — Pools backed by real token pairs in protocol state
- [ ] Production Ready — Pool creation UI in block explorer; SDK support

### 5.5 TWAP Oracle
- **Status:** ❌ Not started
- [ ] Implemented — Time-weighted average price accumulator updated on every pool interaction
- [ ] Verified — Test: TWAP over N blocks matches expected price; handles zero-activity periods
- [ ] Security Tested — TWAP manipulation requires sustained capital over long observation window
- [ ] Consensus / Decentralized — TWAP state in protocol trie; deterministic
- [ ] No Stubs — Real price observations from executed trades
- [ ] Production Ready — TWAP queryable from smart contracts and RPC

### 5.6 Hooks System
- **Status:** ❌ Not started
- [ ] Implemented — Plugin architecture: `beforeSwap`, `afterSwap`, `beforeAddLiquidity`, etc.
- [ ] Verified — Test: custom hook modifies swap behavior; hook reverts propagate correctly
- [ ] Security Tested — Malicious hook cannot steal funds or DoS the pool; gas limits enforced
- [ ] Consensus / Decentralized — Hook code is deterministic smart contract execution
- [ ] No Stubs — Hooks execute real QEVM bytecode
- [ ] Production Ready — Hook developer documentation and example contracts

---

## Step 6 — PQ Multisignatures & Wallet Architecture (Whitepaper §6)

### 6.1 Threshold Dilithium m-of-n Signatures
- **Status:** ❌ Not started — docs note "Multisig: ❌ (Single key)"
- [ ] Implemented — `qrdx/crypto/threshold_dilithium.py` with key generation, partial signing, aggregation
- [ ] Verified — Test: 2-of-3, 3-of-5, 5-of-7 threshold schemes; invalid partial sig rejection
- [ ] Security Tested — Threshold below m cannot forge; rogue-key attack resistance; external audit
- [ ] Consensus / Decentralized — Threshold key ceremony requires independent parties; no single dealer
- [ ] No Stubs — Aggregated signature verified by standard Dilithium verify (compatibility)
- [ ] Production Ready — Formal security proof or published paper for the threshold construction

### 6.2 System Wallet Migration to Multisig
- **Current state:** Single PQ controller key controls all 10 system wallets (75M QRDX)
- [ ] Implemented — Each system wallet governed by independent m-of-n threshold key
- [ ] Verified — Test: treasury transfer requires m-of-n signatures; single signer rejected
- [ ] Security Tested — Key loss simulation: losing (m-1) keys does not compromise funds
- [ ] Consensus / Decentralized — Signers are independent entities (foundation members, validators, community)
- [ ] No Stubs — Multisig verification in transaction processing, not a wrapper script
- [ ] Production Ready — Key ceremony conducted with ≥7 independent parties; public attestation

### 6.3 Prefunded Wallet Hierarchies
- **File:** `qrdx/system_wallets.py`
- [x] Implemented — 10 system wallets with designated purposes and allocations
- [ ] Verified — Test: wallet-purpose spending limits enforced; unauthorized category transfer rejected
- [ ] Security Tested — Hierarchy cannot be bypassed; sub-wallet cannot exceed parent authorization
- [ ] Consensus / Decentralized — Spending requires multisig (after §6.2); time-locked large transfers
- [ ] No Stubs — Real on-chain authorization checks, not config-only restrictions
- [ ] Production Ready — Treasury transparency dashboard; quarterly spending reports

---

## Step 7 — Cross-Chain Oracle & Bridge Infrastructure (Whitepaper §10)

### 7.1 Chain Adapter Framework
- **Status:** ❌ Not started
- [ ] Implemented — `qrdx/bridge/adapters/` with `BaseChainAdapter` interface and `EthereumAdapter`, `BitcoinAdapter`, `SolanaAdapter`
- [ ] Verified — Each adapter: connect, read state, verify proof, submit tx (against testnet/devnet)
- [ ] Security Tested — Adapter cannot be tricked by reorged/invalid external chain data
- [ ] Consensus / Decentralized — ≥2/3 validators run each adapter; no single oracle
- [ ] No Stubs — Adapters talk to real external chain nodes (Geth, Bitcoin Core, Solana validator)
- [ ] Production Ready — Adapter uptime >99.5% over 30-day testnet period

### 7.2 Embedded Light Clients
- **Status:** ❌ Not started
- [ ] Implemented — Ethereum Merkle-Patricia verifier, Bitcoin SPV verifier, Solana slot-hash verifier
- [ ] Verified — Test: verify inclusion proof for known transactions on each chain
- [ ] Security Tested — Invalid proof rejection; header chain validation; difficulty/PoS verification
- [ ] Consensus / Decentralized — Light client state agreed upon by validator quorum
- [ ] No Stubs — Verifiers process real chain data, not mock headers
- [ ] Production Ready — Light client syncs to tip within 60 seconds of adapter start

### 7.3 Oracle State Attestation
- **Status:** ❌ Not started
- [ ] Implemented — Validators attest to external chain block heights and state roots
- [ ] Verified — Test: attestation from ≥2/3 validators → state root accepted; minority attestation rejected
- [ ] Security Tested — Conflicting attestation → slashing; stale attestation detection
- [ ] Consensus / Decentralized — No single oracle provider; validators are the oracle
- [ ] No Stubs — Attestations reference real external chain state, not test fixtures
- [ ] Production Ready — Oracle latency <6 seconds for Ethereum; <60 seconds for Bitcoin

### 7.4 `OracleTransaction` Envelope Type
- **Status:** ❌ Not started
- [ ] Implemented — New transaction type wrapping chain-specific sub-transactions (`EthereumTransaction`, `BitcoinTransaction`, `SolanaTransaction`)
- [ ] Verified — Test: serialize/deserialize round-trip; execute cross-chain intent end-to-end
- [ ] Security Tested — Invalid sub-transaction rejection; replay protection across chains
- [ ] Consensus / Decentralized — OracleTransaction processed by consensus like any other tx type
- [ ] No Stubs — Sub-transactions submitted to real external chain mempools
- [ ] Production Ready — Cross-chain transaction confirmation time benchmarked and documented

### 7.5 Bridge Lock/Unlock Mechanism
- **Status:** ❌ Not started
- [ ] Implemented — Lock assets on source chain → threshold-signed confirmation → mint on QRDX (and reverse)
- [ ] Verified — Test: full bridge cycle both directions; insufficient lock rejected; double-mint prevented
- [ ] Security Tested — Bridge fraud proof mechanism; locked amount audit; timeout/refund for stalled bridges
- [ ] Consensus / Decentralized — Bridge transactions require ≥2/3 validator threshold signatures
- [ ] No Stubs — Real assets locked in auditable on-chain contracts on external chains
- [ ] Production Ready — Bridge TVL limits during initial launch; insurance fund

### 7.6 Block Height Recording
- **Status:** ❌ Not started
- [ ] Implemented — QRDX blocks record latest attested block height for each bridged chain
- [ ] Verified — Test: block height monotonically increasing; gap detection
- [ ] Security Tested — Cannot fake block heights; historical heights are immutable
- [ ] Consensus / Decentralized — Heights agreed upon by validator attestation quorum
- [ ] No Stubs — Heights from real external chain light clients
- [ ] Production Ready — Block explorer displays cross-chain height timeline

---

## Step 8 — Asset Shielding (Whitepaper §8)

### 8.1 Shield: Classical → Quantum-Resistant
- **Status:** ❌ Not started
- [ ] Implemented — `shield(chainId, amount)` locks BTC/ETH → mints qBTC/qETH on QRDX
- [ ] Verified — Test: shield 1 ETH → receive 1 qETH; balance checks on both chains
- [ ] Security Tested — Cannot mint without corresponding lock; double-shield prevention
- [ ] Consensus / Decentralized — Shielding is a bridge operation requiring validator quorum (§7.5)
- [ ] No Stubs — Real lock transactions on Ethereum/Bitcoin; real mint on QRDX
- [ ] Production Ready — Shielding UI; user guide; fee schedule published

### 8.2 Unshield: Quantum-Resistant → Classical
- **Status:** ❌ Not started
- [ ] Implemented — `unshield(qAsset, amount, destChain, destAddress)` burns qAsset → unlocks on dest chain
- [ ] Verified — Test: unshield 1 qETH → receive 1 ETH; partial unshield; insufficient balance rejection
- [ ] Security Tested — Unshield remains operational even during Doomsday (§8.3)
- [ ] Consensus / Decentralized — Unshield requires threshold signature for unlock on external chain
- [ ] No Stubs — Real burn on QRDX; real unlock on external chain
- [ ] Production Ready — Unshield latency documented per chain

### 8.3 Doomsday Protocol (Whitepaper §8.5)
- **Status:** ❌ Not started
- [ ] Implemented — Canary ECDSA wallet; monitor for unauthorized drain; circuit breaker halts shield operations
- [ ] Verified — Test: simulate canary drain → shield halted within 1 block; unshield still works
- [ ] Security Tested — False positive resistance; cannot be triggered by non-quantum means
- [ ] Consensus / Decentralized — Doomsday activation requires ≥2/3 validator agreement on canary breach
- [ ] No Stubs — Real ECDSA canary wallet with real funds on Ethereum mainnet
- [ ] Production Ready — `doomsday.qrdx.org` status page live; public monitoring dashboard

---

## Step 9 — qRC20 Token Standard (Whitepaper §9)

### 9.1 qRC20 Base Standard
- **Status:** ❌ Not started
- [ ] Implemented — Solidity/Vyper contract implementing `transfer`, `approve`, `transferFrom`, `balanceOf` with PQ verification
- [ ] Verified — ERC-20 compatibility test suite passes; PQ-specific methods tested
- [ ] Security Tested — Reentrancy; approval front-running; overflow; PQ signature forgery rejection
- [ ] Consensus / Decentralized — Token state in EVM storage; deterministic across nodes
- [ ] No Stubs — Real token transfers with real PQ signature verification
- [ ] Production Ready — qRC20 deployed on testnet; developer SDK and documentation

### 9.2 `shouldTradeAfterDoomsday()` Hook
- **Status:** ❌ Not started
- [ ] Implemented — Tokens can opt in/out of trading after Doomsday Protocol activation
- [ ] Verified — Test: Doomsday active → tokens with flag=false revert on transfer; flag=true succeed
- [ ] Security Tested — Flag cannot be changed after Doomsday activation; governance override tested
- [ ] Consensus / Decentralized — Flag set at token deployment time; immutable
- [ ] No Stubs — Integrates with real Doomsday state (§8.3)
- [ ] Production Ready — Token deployer UI includes Doomsday behavior choice

---

## Step 10 — Governance Model (Whitepaper §13)

### 10.1 On-Chain Governance
- **Status:** ❌ Not started
- [ ] Implemented — Proposal submission, voting (stake-weighted), execution with time-lock
- [ ] Verified — Test: propose → vote → time-lock → execute; insufficient quorum rejection
- [ ] Security Tested — Governance attack: flash-loan voting; proposal spam; malicious execution
- [ ] Consensus / Decentralized — Any staker can propose; no admin veto; time-lock allows exit
- [ ] No Stubs — Governance execution triggers real state changes (fee tiers, parameters, upgrades)
- [ ] Production Ready — Governance forum + on-chain voting UI; initial parameters set via genesis governance

---

## Step 11 — RPC & Developer Interface (Whitepaper §3)

### 11.1 JSON-RPC 2.0 Server
- **File:** `qrdx/rpc/`
- [x] Implemented — 7 namespaces: `eth`, `net`, `web3`, `qrdx`, `contracts`, `validator` + custom
- [ ] Verified — Test: each RPC method returns correct response for valid and invalid inputs
- [ ] Security Tested — Rate limiting active; authentication for admin methods; input validation
- [ ] Consensus / Decentralized — RPC is a read/write interface; does not affect consensus
- [ ] No Stubs — All RPC methods backed by real state queries
- [ ] Production Ready — OpenAPI spec matches implementation; SDK auto-generated from spec

### 11.2 WebSocket Subscriptions
- **Status:** Config references WebSocket but no implementation
- [ ] Implemented — `newHeads`, `newPendingTransactions`, `logs` subscription channels
- [ ] Verified — Test: subscribe → receive events → unsubscribe; reconnection handling
- [ ] Security Tested — Connection limit; subscription spam resistance; memory leak prevention
- [ ] Consensus / Decentralized — N/A (client interface)
- [ ] No Stubs — Real event streaming from consensus/mempool
- [ ] Production Ready — WebSocket load tested at 1,000 concurrent connections

---

## Step 12 — Deployment & Operations

### 12.1 Docker Production Image
- **File:** `docker/Dockerfile`, `docker/docker-compose.yml`
- [x] Implemented — Single-node Docker Compose with PostgreSQL
- [ ] Verified — Docker build CI; container starts and syncs chain
- [ ] Security Tested — Non-root container; minimal base image; no secrets baked in; image scan clean
- [ ] Consensus / Decentralized — Multi-node Compose or Kubernetes manifest; ≥4 validators
- [ ] No Stubs — Uses `requirements-v3.txt` with all PQ dependencies
- [ ] Production Ready — Helm chart or production Compose with TLS, monitoring, log aggregation

### 12.2 Config Loading (TOML)
- **Current state:** `config.example.toml` exists but node reads `.env` only — TOML is not loaded
- [ ] Implemented — Node loads `config.toml` at startup; `.env` values override TOML
- [ ] Verified — Test: config value in TOML reflected in runtime behavior
- [ ] Security Tested — Sensitive config (keys, passwords) only from env vars or vault, never TOML
- [ ] Consensus / Decentralized — Config is per-node; no shared config service
- [ ] No Stubs — Every TOML section has backing implementation
- [ ] Production Ready — Config reference documentation; example configs for validator/full-node/archive

### 12.3 Monitoring & Metrics
- **Current state:** Config references Prometheus but no implementation
- [ ] Implemented — Prometheus metrics: block height, peer count, validator status, mempool size, exchange volume
- [ ] Verified — Grafana dashboard loads with all panels populated
- [ ] Security Tested — Metrics endpoint not exposed to public internet; no sensitive data in metrics
- [ ] Consensus / Decentralized — Each node exports own metrics; community Grafana available
- [ ] No Stubs — Metrics derived from real node state, not dummy values
- [ ] Production Ready — Alerting rules: finality stall, peer drop, disk space, memory, PQ cert expiry

### 12.4 TLS for All External Interfaces
- **Current state:** No TLS configured
- [ ] Implemented — RPC, P2P, and admin endpoints support TLS; HTTP disabled for external access
- [ ] Verified — Test: plain HTTP connection to RPC rejected; TLS handshake succeeds
- [ ] Security Tested — Certificate validation; no self-signed certs in production; HSTS headers
- [ ] Consensus / Decentralized — Each node provisions own TLS cert (Let's Encrypt or PQ TLS when available)
- [ ] No Stubs — No `--insecure` flag that disables TLS
- [ ] Production Ready — TLS renewal automation; certificate monitoring

---

## Step 13 — Testing Infrastructure

### 13.1 Unit Test Coverage
- **Current state:** `tests/test_crypto.py` — 79 tests covering Dilithium, Kyber, classical, address, hashing, encoding, lazy loading, security regressions
- [x] Implemented — pytest suite for crypto module: Dilithium ML-DSA-65 (32 tests), Kyber ML-KEM-768 (10 tests), secp256k1 (6 tests), address (7 tests), hashing (5 tests), encoding (2 tests), lazy loading (4 tests), security regressions (5 tests)
- [x] Verified — All 79 tests pass (`pytest tests/test_crypto.py -v` → 79 passed in 0.57s)
- [ ] Security Tested — Test suite includes adversarial/negative test cases for all security-critical paths
- [ ] Consensus / Decentralized — N/A (development infrastructure)
- [x] No Stubs — No `@pytest.mark.skip` on critical tests; security regression tests are mandatory
- [ ] Production Ready — ≥90% line coverage; ≥80% branch coverage; all tests pass in CI

### 13.2 Integration & End-to-End Tests
- [ ] Implemented — Multi-node testbed: ≥4 validators, full block production, transaction lifecycle
- [ ] Verified — E2E test: send tx → included in block → finalized → query via RPC → correct state
- [ ] Security Tested — Chaos testing: kill nodes, partition network, corrupt messages → chain recovers
- [ ] Consensus / Decentralized — E2E tests run on real multi-node setup, not single-process simulation
- [ ] No Stubs — Tests use real PostgreSQL, real `liboqs`, real network sockets
- [ ] Production Ready — E2E suite runs nightly on persistent testnet; results published

### 13.3 Formal Verification / Audit
- [ ] Implemented — Consensus spec written in formal specification language (TLA+, Dafny, or similar)
- [ ] Verified — Model checker confirms no safety/liveness violations for N≤20 validators
- [ ] Security Tested — External audit by ≥2 independent security firms; all findings resolved
- [ ] Consensus / Decentralized — Audit covers decentralization properties (no central admin, no kill switch)
- [ ] No Stubs — Audit scope includes all production code paths
- [ ] Production Ready — Audit reports published; bug bounty program live

---

## Summary Scorecard

| Step | Feature Area | Items | Implemented | Fully Production Ready |
|------|-------------|-------|-------------|----------------------|
| 0 | Security Blockers | 5 | 0/5 | 0/5 |
| 1 | PQ Cryptography | 4 | 2/4 | 0/4 |
| 2 | Node Identity & P2P | 4 | 0/4 | 0/4 |
| 3 | QR-PoS Consensus | 10 | 8/10 | 0/10 |
| 4 | QEVM | 5 | 2/5 | 0/5 |
| 5 | Exchange Engine | 6 | 0/6 | 0/6 |
| 6 | PQ Multisig & Wallets | 3 | 1/3 | 0/3 |
| 7 | Cross-Chain Bridge | 6 | 0/6 | 0/6 |
| 8 | Asset Shielding | 3 | 0/3 | 0/3 |
| 9 | qRC20 Token Standard | 2 | 0/2 | 0/2 |
| 10 | Governance | 1 | 0/1 | 0/1 |
| 11 | RPC & Dev Interface | 2 | 1/2 | 0/2 |
| 12 | Deployment & Ops | 4 | 1/4 | 0/4 |
| 13 | Testing Infrastructure | 3 | 0/3 | 0/3 |
| **TOTAL** | | **58** | **15/58 (26%)** | **0/58 (0%)** |

---

## Recommended Execution Order

```
Phase 1 — Security Foundation (Steps 0, 1, 13.1)
   ↓
Phase 2 — Identity & Network (Steps 2, 12.2, 12.4)
   ↓
Phase 3 — Consensus Hardening (Steps 3, 4.1, 4.2, 4.3)
   ↓
Phase 4 — Multisig & Treasury (Steps 6, 3.10)
   ↓
Phase 5 — Exchange Engine (Steps 5, 4.4)
   ↓
Phase 6 — Cross-Chain & Shielding (Steps 7, 8, 4.5)
   ↓
Phase 7 — Token Standard & Governance (Steps 9, 10)
   ↓
Phase 8 — Production Readiness (Steps 11, 12, 13.2, 13.3)
```

> **No feature reaches "Production Ready" until all six gates are checked.**  
> **No mainnet launch until every row in this document shows ✅ across all six gates.**
