# Mainnet readiness review

**As of 2026-10-27.** Covers the working tree on top of 321da74. This review reads the code
paths a mainnet depends on, the live runs on 4-node networks (the bridge end to end ran on
2026-10-27), and the open items in docs/KNOWN_ISSUES.md. Severity measures what happens on a
mainnet if the item is left as it is.

**Where things stand.** The protocol is built: Casper FFG finality bound to branches,
chain-derived validator sets, enforced slashing, a signed body root, LtHash state roots, the
undo journal, the exchange (perps clearinghouse, unified spot liquidity, trading features,
governance), the EVM, native tokens and the bridge. The test suite passes and the live networks
converge (3,739 tests pass on 2026-10-27). What remains falls into five groups:

1. Bugs, of which four are high.
2. Two pieces a long-running chain cannot do without: checkpoint sync and history pruning.
3. The process gates: audits, a geo-distributed soak, keys, decisions and the bridge's custodians.
4. A whitepaper that promises more than is built.
5. Cleanup, which lowers what the audit costs.

---

## 1. Bugs to fix before launch

| # | Severity | What |
|---|---|---|
| B1 | **High** | Running validators have no slashing protection |
| B2 | **High** | Validator keys are read in plaintext; the password is ignored |
| B3 | **High** | The signature scheme silently falls back to an incompatible one |
| B4 | **High** | Standard EVM wallets cannot send a transaction |
| B5 | Medium | The lockbox has no safe way to return a stuck deposit (decide before deploying) |
| B6 | Medium | Development and release run different PQ crypto builds |
| B7 | Medium | Blocks served over the eth RPC misreport their gas limit, base fee and roots |
| B8 | Low | Dead and leftover code that an auditor would read as live |

### B1 — Running validators have no slashing protection (high)

`ValidatorManager.create` opens the slashing-protection database
(qrdx/validator/manager.py:260). The running node never calls it: it builds the manager directly
(qrdx/validator/node_integration.py:214), so `manager.slashing_protection` is `None` and every
signing check that consults it is skipped.

*Correction (2026-10-27, while fixing it).* FFG votes did have a record, in the chain database
(`ffg.SigningRecord`), but block proposals had none. That vote record was lost with a resync and
never shared with a second machine. It also compared only checkpoints: a validator restarted
mid-epoch could sign a second attestation for the same checkpoints at a later slot, which
importers judge a double vote.

Slashing itself is enforced on chain. A double-signed block or a conflicting FFG vote costs 50 %
of the stake and ejects the validator. These operator mistakes would each trigger it:

* restarting a validator from a restored backup;
* running a hot standby with the same key;
* moving a validator to a new machine while the old one is still up.

**Fix:**

* Open the protection database in the live path.
* Check it before every block signature and every attestation, and write the record before
  broadcasting.
* Refuse to start on a mainnet chain spec without it.
* Add export and import in the EIP-3076 interchange format, so a validator can move between
  machines safely.

### B2 — Validator keys are read in plaintext; the password is ignored (high)

The running validator reads `private_key` as hex from its wallet JSON
(node_integration.py:183-188). `QRDX_VALIDATOR_PASSWORD` is accepted and stored, then never
used. Anyone who can read the data directory holds the key: they can sign as the validator, or
double-sign to get it slashed.

**Fix:**

* Load the encrypted keystore, which `PQWallet.load(path, password)` already reads, and refuse a
  plaintext key on a mainnet chain spec.
* Next, add a remote-signer interface so keys can live in a separate process or an HSM. It
  should sit next to the B1 protection database, as Web3Signer does.

### B3 — The signature scheme silently falls back to an incompatible one (high)

`_get_working_algorithm` (qrdx/crypto/pq/dilithium.py) asks liboqs for ML-DSA-65. If that is
missing, it falls back to the round-3 "Dilithium3", and qrdx/crypto/pq/kyber.py does the same
with Kyber768 for ML-KEM-768.

The two pairs are not interchangeable. FIPS 204 changed the hashing inside ML-DSA, and the
signatures differ in size (3,309 vs 3,293 bytes). A node built against an old liboqs would sign
blocks and transactions the rest of the network rejects, and it would reject theirs: a silent
split.

**Fix:**

* Require exactly ML-DSA-65 and ML-KEM-768, and refuse to start otherwise.
* Run a known-answer test at startup and in CI: the NIST vectors, verified and reproduced.

### B4 — Standard EVM wallets cannot send a transaction (high, for adoption)

`parse_raw_transaction` (qrdx/contracts/evm_mempool.py:301) refuses every typed transaction
except QRDX's own 0x51. That includes EIP-1559 (type 2) and EIP-2930 (type 1). Meanwhile
`eth_getBlockByNumber` reports `baseFeePerGas` on every block (qrdx/rpc/modules/eth.py:452).

MetaMask, ethers v6 and viem see that field and build a type-2 transaction, which the node then
refuses. Today only legacy transactions work. The bridge's own end-to-end run had to force them.

**Fix:**

* Accept types 1 and 2.
* The effective gas price is min(maxFee, baseFee + tip). The base fee is burned, as it is now.
  The tip is credited or burned by the existing fee rule, and its recipient is a protocol
  decision to write down.
* Access lists are charged as EIP-2930 prices them.
* Test with MetaMask, ethers and viem against a live node.

### B5 — The lockbox has no safe way to return a stuck deposit (medium; decide before deploying)

Some deposits are never minted on QRDX:

* a deposit of a token the network does not list;
* a deposit whose recipient QRDX refuses (qrdx/exchange/bridge.py:218).

The tokens stay locked. docs/BRIDGE.md says the custodian "can return it", but the only exit is
`release(withdrawalId, …)`, which takes QRDX's withdrawal ids. A refund would have to borrow one:

* When QRDX later assigns that id to a real withdrawal, the lockbox refuses to pay it ("already
  released").
* `custodian.py reconcile` alarms on the refund as an unknown release.

There is a second problem. If governance later lists that token, the validators would attest the
old deposit and mint it, after it was already refunded.

**Fix:** add `refund(bytes32 depositKey, address token, address to, uint256 amount)` to
QRDXLockbox. The key is the deposit's transaction hash and log index. The function marks the key
refunded and emits `Refunded`. In addition:

* Validators skip deposits whose key the lockbox marks refunded.
* `custodian.py` plans and reconciles refunds.

The lockbox cannot be upgraded, so this has to land, and be audited, **before** the first
deployment. The artifact and its tests rebuild in one step (`compile_lockbox`).

### B6 — Development and release run different PQ crypto builds (medium)

* The development environment runs liboqs 0.15.0 under the 0.14.0 Python wrapper, and prints a
  version warning on every run.
* The release lock pins liboqs-python 0.16.0.1 (release/requirements.lock), and the Dockerfile
  builds liboqs from a pinned commit.
* So the tests exercise a different crypto build from the one that ships.

**Fix:** use one version everywhere, including the dev container, with the known-answer test
from B3 in CI.

liboqs's own documentation does not recommend it for production. That is an audit topic (see
§4, "PQ crypto implementation").

### B7 — Blocks served over the eth RPC misreport their header fields (medium)

`_fmt_block` (qrdx/rpc/modules/eth.py:438-452) returns:

* `gasLimit` 30,000,000. The real limit is 1,000,000, or 3,000,000 on every 240th block
  (`block_limits.evm_gas_limit_at`).
* `baseFeePerGas` 0. `eth_feeHistory` reports the real one.
* `stateRoot` and `receiptsRoot` as zeros, and an empty `logsBloom`.

Wallets cap gas from `gasLimit`, fee estimators read the base fee, and some indexers skip blocks
whose bloom is empty.

**Fix:**

* Report the per-height limit, the block's own base fee and the unified state root.
* Build a real bloom from the block's logs.

### B8 — Dead and leftover code (low; lowers the audit's cost)

* `qrdx/rpc/modules/eth.py.bak`.
* `miner/` (the PoW CPU and CUDA miners inherited from Denaro), `send_system_wallet_tx.py`,
  `verify_state_sync.py` and `test_results.txt` at the repository root.
* The retired `PerpEngine` (qrdx/exchange/perpetual.py), which `ExchangeStateManager` still
  constructs (state_manager.py:413) and the package still exports.
* The old bridge scaffolding: `qrdx/bridge/adapters.py`, `shielding.py` and `doomsday_store.py`.
  Its `BridgeMinter` only tallies totals in memory (KNOWN_ISSUES), and nothing attaches its
  `DoomsdayProtocol` (`set_doomsday_protocol` has no caller).
* About 25 superseded status documents (`*_COMPLETE.md`, `*_SUMMARY.md`, `STATE_INTEGRATION_*`,
  `EVM_INTEGRATION_*`) that contradict the current ones.
* `validator_0.keystore.json` at the root. It is encrypted, but it is a tracked key: make sure no
  mainnet identity is ever derived from it.

Auditors bill by the line, and code that looks live but is not misleads them. Remove it at the
audit freeze.

*Done 2026-10-27:* all of the above is removed, apart from the keystore (a test fixture), and
the superseded documents moved to docs/archive/.

---

## 2. Missing pieces a long-running chain needs

### Checkpoint sync — treat as a launch blocker

A new node replays from genesis (KNOWN_ISSUES: "Still open: checkpoint sync"). At 250 ms slots
the chain adds about 345,600 blocks a day and roughly 126 million a year. Joining gets slower
every week. Within months, a validator that loses its disk can no longer catch up in useful time.

The parts already exist:

* weak-subjectivity checkpoints;
* finalized checkpoints;
* sparse-Merkle proofs of all state (docs/STATE_PROOFS.md);
* attested chain heads.

What is missing is the flow:

1. Fetch a finalized state snapshot from peers.
2. Verify it against the finalized block's state root.
3. Verify the finalized block against the trusted checkpoint.
4. Run forward from there.
5. Optionally backfill history.

*Built 2026-10-28, after committing the validators' state to the root (`validator_state_root`).
A restore verifies a snapshot against a trusted checkpoint and the finalized block's root:
`scripts/node/snapshot.py`, docs/CHECKPOINT_SYNC.md. A snapshot downloads from any HTTP server
(`fetch`); nodes publishing and advertising their own is still open.*

### History pruning and storage modes

Block signatures alone grow the chain about 1.2 GB a day (KNOWN_ISSUES, the 3.3 KB signature).
Only votes and the undo journal are pruned. Full nodes need to drop block bodies below a
retention window behind finality, and an archive mode should keep everything. This depends on
checkpoint sync: once no node replays from genesis, no node needs all of history.

*Built 2026-10-28: `QRDX_HISTORY_RETENTION_BLOCKS` (archive by default). It drops proposer and
vote signatures and sections behind finality, and keeps every header.*

### Guardrails on the bridge

A quorum of validators mints bridged assets, and nothing caps how much. Add:

* a per-asset rate limit, so mints per epoch are bounded and anything beyond waits;
* a global cap per asset while the bridge is young;
* a governance-controlled pause on minting.

These bound the damage from a compromised quorum, or from a bug, to one window's worth.

### Monitoring and alerts

`/metrics` exists, but no alert rules or dashboards ship with it. The minimum set:

* Consensus: finality lag, the depth of any fork seen, missed slots, peer count.
* Bridge: `custodian.py reconcile` and `status` on a schedule, with paging on exit 1.
* Markets and risk: oracle staleness, circuit-breaker trips, the insurance fund and liquidity
  vault equity, and any liquidation backlog.

### Onboarding Ethereum users to the exchange

Exchange senders must be PQ accounts (ACCEPTED in KNOWN_ISSUES), so a MetaMask user cannot trade
until they create and fund a second, PQ key. Agents already exist. An EVM-signed "approve this PQ
agent" operation would let a 0x account trade through a browser-held PQ session key. Together
with B4, that is most of what an Ethereum user needs.

### Hyperliquid parity

The one feature left out, frequent batch auctions, was skipped on purpose (2026-10-22). The fee
schedule and the margin and leverage tiers are among the defaults that still await review (§3).

---

## 3. Process gates

No code change clears these; each needs a person or an outside party.

1. **Commit, then freeze.** Everything since 321da74 is uncommitted: about 90 changed files. Commit it, tag an audit freeze and change only what the audits ask for.
   docs/RELEASES.md also lists three release blockers:
   * the `dvm` gitlink;
   * an unpushed py-evm change;
   * no maintainer keys.
2. **External audits**, in four scopes:
   * consensus: fork choice, FFG, slashing, epoch state, the body commitment, sync;
   * the exchange: the clearinghouse, unified spot, account control and multisig, governance,
     the bridge module;
   * QRDXLockbox and the custodian tooling;
   * the PQ crypto integration: keys, the handshake, B3 and B6.

   The exchange and consensus are large: about 20,000 lines in the four biggest files alone.
   Plan for two firms, or one firm and a competitive audit.
3. **A bug bounty** on the public testnet before launch, and on mainnet from day one.
4. **A geo-distributed soak at production scale.** So far every run has been 4 nodes on one host.
   Mainnet needs:
   * independent operators (at least 21) across continents, for weeks;
   * the adversarial harness: an equivocating proposer, partitions, long-range attempts, a node
     flooding transactions;
   * load at the target throughput.

   **250 ms slots must be measured there.** Round trips between continents are 100–250 ms, before
   Python processing and a 3.3 KB signature per block. The time parameters live in the chain spec
   and rewards accrue per unit of time, so launching at 500 ms or 1 s is a spec change, not a
   redesign. Decide from the soak's numbers.
5. **Decisions** (docs/TOKENOMICS.md "Decisions still open", KNOWN_ISSUES "await review of their
   defaults"):
   * the holders of the prefunded accounts;
   * the genesis validators and their stakes;
   * the reward rate;
   * the free lane's numbers;
   * every trading and risk default listed there;
   * mainnet's chain-spec values.
6. **Chain ids** 762 and 7620, registered (in progress).
7. **The bridge's custodians**, for each source chain:
   * a Safe whose signers are independent people in different places, with a threshold such as
     4 of 7;
   * the lockbox deployed with `scripts/bridge/deploy_lockbox.py --verify-build`;
   * each validator on its own source-chain RPC;
   * `BRIDGE_ASSETS` and `PERP_COLLATERAL_TOKEN` in the spec.
8. **The genesis ceremony and operator documentation:**
   * the validator runbook, including keys (B1 and B2);
   * upgrades;
   * incident response;
   * key rotation.
9. **Legal review** of perpetuals with leverage, and of the front ends' availability by region.
   This is not engineering, but it gates launch for an exchange chain.

---

## 4. Where to improve

### PQ crypto implementation

liboqs is a research library and says so. Evaluate an audited ML-DSA implementation for
signing and verification, for example mldsa-native, PQClean's verified code paths, or a
FIPS-validated module such as AWS-LC's. Keep liboqs only where nothing else exists. Whatever is
chosen, pin it by hash and test it against the NIST vectors (B3, B6).

### Performance

The node is Python on a 250 ms clock.

* Profile it under the soak's load before optimizing anything.
* The likely hot spots are signature verification (parallelize across cores), Decimal arithmetic
  in matching and the AMM, and the exchange tick.
* Move whatever the profile shows into native code (Rust through PyO3, or Cython) behind the same
  interfaces, with the existing equivalence tests as the referee.

### Determinism checks in CI

The rollback-audit plugin, the hash-seed check and the rebuild-equivalence tests catch the bugs
that split a network. Make each one a CI job, and add a nightly multi-node run that compares
state roots.

### Fuzzing and conformance

* Fuzz every decoder that peers or users reach: block bodies, exchange operations, RLP and 0x51
  transactions, p2p messages. Use Hypothesis, or Atheris for the C-backed paths.
* Run the Ethereum state tests (GeneralStateTests) against the EVM, since its world is custom.

### A written specification

The protocol exists only as code and per-feature documents. A consensus spec, in the manner of
Ethereum's consensus-specs, would let auditors check the code against intent. It is also the
first step toward a second client.

### File size

`state_manager.py` (6,800 lines) and `node/main.py` (8,700) are hard to review. Split them along
the lines that already exist (spot, perps, bridge, account control; import, propose, sync) before
the audit freeze.

### Documentation

About 60 documents, a third of them superseded (B8). Add one index, docs/README.md, that links
the living ones.

---

## 5. Where to innovate

The ideas below play to what QRDX already has: post-quantum keys everywhere, an exchange in
consensus, and state proofs of everything.

### A trust-minimized bridge

Replace the custodian, in two steps:

1. **Inbound first.** QRDX already carries attested chain heads (0x0200/0x0201) and verifies
   external proofs. Mint a deposit on a receipt proof against an attested Ethereum header,
   instead of on per-deposit validator votes. This is most of the way there.
2. **Outbound.** Verifying Dilithium in the EVM is too expensive. Instead, prove with a STARK
   that two thirds of the stake signed the finalized checkpoint, and that the withdrawal is in
   its state; the sparse-Merkle proofs already exist. Hash-based STARKs are themselves
   post-quantum, so the bridge would be as quantum-safe as the chain.

This is the "trustless bridge" the whitepaper promises (see §6).

### Smaller blocks after finality

ML-DSA signatures do not aggregate. Two ways out of the 1.2 GB a day:

* Prove each epoch's block signatures with one STARK and drop the signatures from finalized
  history.
* Sign blocks with FN-DSA (Falcon-512, FIPS 206): 666-byte signatures, about a fifth of the size.

### An encrypted mempool

Encrypt transactions to a threshold ML-KEM key held by the validators, and decrypt them only
after the block's order is fixed. Front-running then has nothing to read. It complements the
fair-ordering work, and it is post-quantum by construction.

### Quantum migration as a product

Let Ethereum users register a PQ key against their address now: a commitment on the source chain
and a 0x51 account on QRDX. If ECDSA weakens, they can prove ownership and move with that key.
This is the useful core of the whitepaper's "shielding", and a reason to hold assets on QRDX that
no other exchange chain offers.

*Built 2026-10-28, with the Doomsday Protocol that ends ECDSA's authority:
docs/QUANTUM_MIGRATION.md. What remains is product work: a wallet flow that binds a successor
in one click.*

### PQ smart accounts

Account control, multisig, guardians, recovery and agents already exist. Package them as a
wallet: PQ keys, a session key per device (agents), social recovery and spending limits. A
browser wallet and a TypeScript SDK for 0x51 and exchange operations would make it usable.

*Built 2026-10-28 to 2026-11-02:*
* *the contracts, predeployed at genesis;*
* *the TypeScript SDK (`sdk/typescript`), which sends exchange and 0x51 transactions and creates
  and drives an account.*

*What remains is the browser wallet itself.*

### New markets on the clearinghouse

Options, and prediction markets settled by the oracle committee, reuse its margin, liquidation
and vaults.

---

## 6. The whitepaper and the build

Whitepaper v3.2 promises, among others:

* a "trustless bridge: no centralized custodian required" (§8.1);
* a Bitcoin bridge (§10.4);
* the Doomsday Protocol's automatic circuit breaker (§8.5);
* cross-chain OracleTransactions (§3.8).

What is built:

* An EVM-chain lockbox whose releases a custodian multisig signs.
* No Bitcoin or Solana bridge. The adapters in qrdx/bridge/ cannot read real events
  (KNOWN_ISSUES).
* A Doomsday Protocol that nothing runs.
* OracleTransactions only as data types.

Launching against the current paper invites a credibility problem, and perhaps a legal one.
Publish a v3.3 that describes the launch as built, and move the rest to a dated roadmap. §5 above
is a good start for it.

---

## 7. A suggested order

The durations are rough and assume the current pace.

**Phase 0, about 2 weeks: fixes.**

* Commit everything.
* Fix B1–B7, and B5 in the contract before anything is deployed.
* Remove dead code (B8) and split the two largest files.
* Pin the crypto and add the known-answer tests.

**Phase 1, about 4–6 weeks: completeness.**

* Checkpoint sync and pruning.
* Bridge guardrails, alerts and dashboards.
* A public geo-distributed testnet with outside validators, with the bounty open.
* Decide on slot time and defaults from its numbers.
* Publish whitepaper v3.3.

**Phase 2, about 6–10 weeks, overlapping Phase 1's end: audits.**

* Freeze the code and run both audits.
* Fix what they find, then re-run the soak.

**Phase 3: launch.**

* Keys, chain ids, the genesis ceremony.
* The custodian Safes and the lockbox deployments.
* Launch with guardrails: bridge caps, conservative leverage and open-interest limits, minting
  pausable by governance.

**Phase 4: after launch.**

* Loosen the guardrails as the chain proves itself.
* The trust-minimized inbound bridge, signature compaction, the encrypted mempool, the wallet.

---

## 8. Work plan and status

Started 2026-10-27, on the user's instruction:

* fix the four high bugs;
* implement the rest of this review, including PQ smart accounts;
* make sure the bridge is secure;
* publish whitepaper v3.4 and raise the node version.

The status column records what has actually landed and been tested, never what is planned.
Items that need a person or an outside party (§3) stay with the user.

| Stage | Item | Status |
|---|---|---|
| 1 | B3 exact PQ algorithms + startup known-answer test | **done** (tests/test_pq_algorithms.py) |
| 1 | B2 encrypted validator keystore; plaintext refused on mainnet | **done** (docs/VALIDATOR_KEYS.md) |
| 1 | B1 slashing protection in the live validator path (+ EIP-3076 interchange, doppelganger check) | **done**, verified live |
| 1 | B4 EIP-1559 / EIP-2930 transactions in the EVM (+ up-front gas check) | **done**, verified live |
| 2 | B7 real gas limit, base fee, state root and bloom in eth block headers | **done** |
| 2 | B5 lockbox refund path; validators never mint a refunded deposit; tooling | **done**, verified live |
| 2 | Found: proposer-chosen block timestamps → `slot_timestamps` | **done** |
| 2 | Bridge guardrails: per-asset mint rate limit, cap, governance pause | **done** |
| 2 | B6 one pinned liboqs everywhere | **done** (0.16.0 / 0.16.0.1, known-answer test verified) |
| 2 | B8 dead code and stale documents removed | **done** |
| 3 | Checkpoint sync (finalized snapshot, verified against the state root and a checkpoint) | **done**, verified live (validator state in the root: `validator_state_root`; `scripts/node/snapshot.py`; docs/CHECKPOINT_SYNC.md). Nodes publish and advertise snapshots (`QRDX_SNAPSHOT_DIR`, `/snapshot/`, `fetch --peer`) |
| 3 | History pruning: full and archive modes | **done**, verified live (`QRDX_HISTORY_RETENTION_BLOCKS`; archive by default) |
| 3 | Alert rules and dashboards for the existing metrics | **done** (rules read real metrics; validator/bridge/oracle gauges; Grafana provisioned; reconcile cron) |
| 3 | 0x accounts trade through an EVM-signed PQ agent approval | **done** (AGENT_APPROVE/REVOKE via the write precompile) |
| 4 | PQ smart accounts: session keys, recovery and limits as one account model, plus an SDK | **done** (docs/PQ_SMART_ACCOUNTS.md: factory, ERC-1271, sessions, recovery; implementation and factory predeployed at genesis by `EVM_PREDEPLOYS`; TypeScript SDK `sdk/typescript`, held to the node's own vectors). Audit open |
| 4 | Found: PQ precompiles on Ethereum's addresses → `evm_standard_precompiles` | **done** |
| 4 | Trust-minimized inbound bridge: mint on a proof against an attested header | **done**, verified live against anvil (storage proof of the lockbox's record; BRIDGE_PROVE_DEPOSIT) |
| 4 | Quantum-migration registry (PQ key bound to a 0x address) | **done** (QRDXMigrationRegistry + MIGRATION_CLAIM storage proofs; on QRDX through account control; docs/QUANTUM_MIGRATION.md) |
| 4 | Doomsday Protocol rebuilt on the consensus bridge | **done**, verified live against anvil with the migration registry (hash-derived canary proven spent with DOOMSDAY_PROVE, or governance's declare_quantum_emergency; ECDSA txs and ECRECOVER off, 0x agents revoked, bridge stopped, late commitments void) |
| 5 | Whitepaper v3.4: the protocol as built, and a dated roadmap | **done** (QRDX-Whitepaper-v3.4.md) |
| 5 | Reported 2026-11-02: unfunded exchange transactions carried in blocks for free → `exchange_inclusion` | **done**, verified live (admission checks the payer; the proposer judges its selection first; a block carrying a transaction that cannot run is invalid; fees reserved up front; docs/KNOWN_ISSUES.md). Existing networks schedule the fork |
| 5 | Node version 3.0.0 | **done** (changelogs/2026/10/2026-10-27-release(3.0.0).md) |

Not in this plan, and why:

* The STARK-proven outbound bridge, signature compaction by proof, and the threshold-encrypted
  mempool are research projects (§5). Each needs its own design and audit, so they go in the
  whitepaper's roadmap.
* The audits, the soak, keys, decisions, chain ids and legal review are §3's process gates.
