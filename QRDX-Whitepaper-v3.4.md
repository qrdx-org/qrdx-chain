# QRDX Protocol Whitepaper v3.4

<div align="center">
  <img src="logo.png" alt="QRDX Logo" width="200"/>
</div>

## A post-quantum proof-of-stake chain with an integrated exchange

**Version:** 3.4
**Date:** October 27, 2026
**Node release described:** 3.0.0
**Authors:** QRDX Foundation Research Team
**Contact:** research@mail.qrdx.org

---

## Abstract

QRDX is a proof-of-stake blockchain whose accounts, validators and network handshakes use the
NIST post-quantum standards: ML-DSA-65 for signatures (FIPS 204) and ML-KEM-768 for key agreement
(FIPS 203). Every node proves at startup that its cryptographic library computes those standards.

Blocks come every 250 ms and are finalized by Casper FFG votes. A signed state root commits to
every account, contract, token, and the exchange.

The chain runs an EVM compatible with Ethereum's wallets and tools, and an exchange in consensus:
perpetual futures on a zero-sum clearinghouse, and spot markets where order books and liquidity
pools form one market per pair.

A consensus bridge brings tokens from EVM chains. Validators attest deposits and the protocol
mints them, within limits. A multisig custodian releases withdrawals and refunds the deposits the
chain will never mint.

This version describes the protocol as built in node release 3.0.0. Where v3.2 described designs
that are not built, this paper says so (§12), and moves them to a dated roadmap (§13).

---

## Contents

1. Why QRDX
2. Cryptography
3. Accounts
4. Consensus
5. State and proofs
6. Execution: the QEVM and fees
7. The exchange
8. The bridge
9. Governance
10. Tokenomics
11. Security: what is verified, and what is not yet
12. What changed since v3.2
13. Roadmap

---

## 1. Why QRDX

**The threat.** A large enough quantum computer running Shor's algorithm recovers an ECDSA or
EdDSA private key from its public key. Every chain that signs with elliptic curves then loses
the security of every account whose public key is known: any account that has ever sent a
transaction. Nobody knows when such a machine will exist. Assets recorded today must stay safe
for decades, so the migration has to come before it.

**What QRDX is.** QRDX is built post-quantum from the first block:
* **Signatures:** accounts and validators sign with ML-DSA-65.
* **Key agreement:** nodes agree session keys with ML-KEM-768.
* **Symmetric security:** hashes and keystores keep 128-bit security against Grover's algorithm
  (BLAKE3-512 roots, AES-256-GCM keystores).

**What it offers.** On top of that, QRDX offers what users need from a chain today: Ethereum
compatibility, sub-second blocks, and an exchange whose matching, margin and settlement are part
of consensus, not a contract or an operator.

---

## 2. Cryptography

### 2.1 The algorithms

| Use | Algorithm | Sizes |
|---|---|---|
| Account, validator and node signatures | ML-DSA-65 (FIPS 204), security level 3 | public key 1,952 B; signature 3,309 B |
| Node handshake key agreement | ML-KEM-768 (FIPS 203), security level 3 | public key 1,184 B; ciphertext 1,088 B |
| State roots | BLAKE3-512 | 64 B |
| EVM compatibility | keccak-256, secp256k1 (for `0x` accounts) | as Ethereum |

The algorithm names are fixed in one place (`qrdx/crypto/pq/algorithms.py`). A node never falls
back to the round-3 "Dilithium3" or "Kyber768", or to draft versions of the standards: those are
not compatible, and a node running one would split from the network silently.

### 2.2 Proving the implementation

QRDX uses liboqs 0.16.0, pinned by commit, under its 0.16.0.1 Python wrapper. Before any key is
used, each node runs a **known-answer test**:

* the sizes must be the standards';
* a signature made by an independent FIPS 204 implementation must verify, and a tampered one must
  not;
* a ciphertext made by an independent FIPS 203 implementation must decapsulate to the expected
  secret.

The vectors were cross-checked both ways between liboqs and the independent implementations. A
node whose library fails any check does not start.

### 2.3 Keys at rest

* **Wallet and validator keystores** encrypt the key with AES-256-GCM, under a key derived by
  scrypt (N = 2^18, about 256 MiB and a second per guess).
* **Binding:** the ciphertext is bound to the address and public key the file names, so a swapped
  key does not open.
* **Validators** may run only from an encrypted keystore on a real network, never from a
  plaintext key.

### 2.4 Signing domains

Every consensus signature (blocks, attestations, the network handshake) starts with a domain
derived from the chain id and the genesis. A signature made on one network, or for one purpose,
never verifies as another.

---

## 3. Accounts

### 3.1 Two kinds of key, one account space

| Kind | Address | Signs with | Notes |
|---|---|---|---|
| Post-quantum | `0xPQ` + 64 hex | ML-DSA-65 | The quantum-safe account. |
| Ethereum | `0x` + 40 hex | secp256k1 | For compatibility. Shor's algorithm threatens it once its public key is known. |

Both map to one 20-byte account id. A transfer between the two kinds is an ordinary transfer, and
EVM contracts see every account as an Ethereum address.

**Transactions.**
* **Post-quantum:** a post-quantum account sends EVM transactions in a QRDX envelope, type `0x51`,
  carrying its ML-DSA-65 key and signature.
* **Ethereum:** an Ethereum account sends legacy, EIP-2930 (type 1) or EIP-1559 (type 2)
  transactions, as MetaMask, ethers and viem build them.

### 3.2 Account control

A post-quantum account can do more than sign with one key (docs/ACCOUNT_CONTROL.md):
* **Controllers:** other accounts that may act for it.
* **Multisig:** m-of-n ML-DSA-65 keys, in exchange and EVM transactions alike.
* **Guardians:** they recover the account after a delay.
* **Agents:** session keys that trade but never move funds, with daily limits.
* **Its own key turned off.**

An Ethereum account reaches the exchange through an agent. It approves a post-quantum agent key
with one EVM transaction, and the agent then signs exchange transactions for it.

### 3.3 PQ smart accounts

In the EVM, `PQSmartAccount` is a contract account owned by an ML-DSA-65 key, checked by the
chain's ML-DSA-65 precompile. Each account is a minimal proxy, created at a predictable address by
a factory. It supports:

* batched calls, which anyone may submit;
* ERC-1271 signatures;
* session keys with deadlines and daily limits, which can never administer the account;
* guardian recovery after a delay the owner can use to cancel.

### 3.4 Quantum migration and the Doomsday Protocol

An Ethereum account names, while ECDSA still holds, the post-quantum account that should control
it (docs/QUANTUM_MIGRATION.md). It binds the successor in one of two ways:

* **On QRDX:** with account control, through the EVM.
* **On Ethereum:** with one call to an immutable registry contract, `register(successor)`. Anyone
  then proves the commitment on QRDX against an attested head of that chain (§8.5).

Either way, the successor becomes the account's controller, at the same address.

The **Doomsday Protocol** decides when ECDSA stops counting:

* **The trigger.**
  * A canary on each bridged chain: an address whose public key was derived from a hash, so no
    one knows its key, funded with a bounty. A proof that its nonce rose triggers the protocol.
  * Or a governance declaration.
* **From the triggering block:**
  * ECDSA-signed transactions are refused;
  * `ECRECOVER` recovers nothing;
  * agents of Ethereum accounts are revoked;
  * the bridge neither mints nor withdraws;
  * commitments made after the trigger bind nothing.
* **What remains:** Ethereum accounts act only through the successors they bound beforehand.

---

## 4. Consensus

### 4.1 Slots, epochs and blocks

| Parameter | Value |
|---|---|
| Slot | 250 ms |
| Epoch | 32 slots (8 s) |
| Validators | up to 150 in the active set |

A block's slot must be later than its parent's. Its timestamp is its slot's start time
(genesis time + slot × 250 ms, in whole seconds). The timestamp is the exchange's only clock, so
a proposer can neither move it nor run it backwards. Each block's header commits to its whole
body: votes, evidence, and its exchange and EVM sections (the body root). The block's hash is the
signed header's hash.

### 4.2 Who proposes

The validator set of each epoch is derived from the chain alone: genesis, then every executed
stake deposit and exit. Every node judges a block's proposer against the set of that block's own
parent chain. The proposer of a slot is chosen by stake. Selection by a RANDAO mix is built as a
chain-spec feature, to be enabled on a production-sized validator set.

### 4.3 Finality

Each validator casts one Casper FFG vote per epoch: from its latest justified checkpoint to the
epoch's checkpoint. Votes travel by gossip and ride in blocks.

* **Justified:** a checkpoint whose votes carry two thirds of the stake.
* **Finalized:** a justified checkpoint directly followed by a justified child.
* **Fork choice** never reverts a finalized block, and prefers the branch carrying the most
  justified weight.

### 4.4 Slashing and validator safety

* **Slashable offences:** two blocks at one slot, or two conflicting votes (a double or surround
  vote).
* **Evidence** is self-validating proof carried in blocks, so every node records the same
  offences.
* **Penalty:** 50 % of the stake, and ejection.
* **Stake floor:** a validator whose stake falls below half the activation minimum is ejected.

A validator's own node protects it from slashing:

* **The record.** Every block and vote is written to a slashing-protection record before it is
  signed. Only one process may hold the record, and it moves between machines in EIP-3076's
  interchange format.
* **The doppelganger check.** After starting, a validator listens for several epochs before
  signing. It stops for good if the chain shows its key signing something its record does not
  hold.

### 4.5 Staking

* **Delegation:** delegators join validator pools.
* **Rewards:** minted at a chain-spec rate (5 % a year by default), paid at each epoch's first
  block.
* **Withdrawals:** principal returns through withdrawals carried in blocks, after a withdrawability
  delay.

### 4.6 Weak subjectivity

Nodes trust a published finalized checkpoint, from their release or their operator. A chain that
contradicts it is refused, and reorganizations never go below it.

---

## 5. State and proofs

### 5.1 One root for all state

Each block's signed header carries a **unified state root**: BLAKE3-512 over the roots of

* the account and contract state,
* the token balances,
* the exchange,
* the legacy UTXO set,
* a sparse Merkle tree over the account, storage and token rows.

The account, token and UTXO roots are LtHash accumulators, which database triggers update as each
row changes. A root therefore costs time in proportion to what changed, not to the state's size.

### 5.2 Proofs

The sparse Merkle tree lets anyone prove one balance, storage slot or token holding against a
block's signed root: a light client, a bridge, or a contract (the state-proof precompile at
`0x…0300`).

### 5.3 The validators' state, and joining from a snapshot

The root also commits to the validators' state (feature `validator_state_root`):

* the validator set of the block's epoch (stakes, pools, payouts owed);
* a hash chain over the staking logs each block writes.

So every piece of consensus state a node acts on is under the signed root.

**Joining from a snapshot.** A new node restores another node's database. It trusts only its
own genesis file and a trusted checkpoint:

* it rebuilds genesis;
* hash-verifies history up to the checkpoint;
* steps the state back to a finalized height and recomputes every root from the rows.

The result must be the root that block signs (docs/CHECKPOINT_SYNC.md).

**Pruning.** A full node drops the signatures and sections of blocks far behind finality, the
bulk of history, and keeps every header. Archive nodes keep everything.

---

## 6. Execution: the QEVM and fees

### 6.1 The QEVM

The QEVM is Ethereum's Shanghai EVM with QRDX's state and precompiles:

| Address | Precompile |
|---|---|
| `0x01`–`0x09` | Ethereum's (`0x09` is BLAKE2F) |
| `0x…0200` | an attested source chain's finalized head |
| `0x…0201` | an inclusion proof against an attested head |
| `0x…0300` | a state proof against a QRDX block's root |
| `0x…0400` | read exchange state (prices, positions, account equity, names) |
| `0x…0401` | send an exchange action as the calling account |
| `0x…0500` | ML-DSA-65 signature verification |
| `0x…0501` | BLAKE3-256 |
| each native token, each NFT collection | ERC-20 / ERC-777 and ERC-721 interfaces |

### 6.2 Fees and limits

* **EVM base fee.** EVM transactions pay an EIP-1559 base fee that follows block fullness, with
  a floor of 1 gwei. An EIP-1559 transaction pays the lower of its fee cap and the base fee plus
  its tip. The whole fee is burned, and a tip buys nothing.
* **EVM gas per block:** 1M, or 3M on every 240th block (a big block).
* **The exchange** has its own gas, base fee (floor 0.1 gwei) and per-block budget.
* **Up-front check.** Before running a transaction, the chain checks that its payer can cover all
  its gas at its highest price. One that cannot runs nothing.
* **Ethereum's gas rules** (`evm_conformance`). A transaction's intrinsic gas comes out of its gas
  limit and is paid on top of what it executes. The payer buys the limit up front and gets back
  the unused part with EIP-3529's refund. The sender and recipient start warm. Ethereum's
  Shanghai state tests run against the QEVM in CI; 1,460 of 1,469 agree, and the rest differ
  on purpose (docs/EVM_CONFORMANCE.md).

---

## 7. The exchange

The exchange is part of consensus. Its operations are signed transactions, executed identically
on every node, and its whole state is in the signed root.

### 7.1 Perpetual futures

Perps settle on a **zero-sum clearinghouse**, modelled on Hyperliquid's. Every position has a
counterparty, and profits are paid by losses.

* **Margin:** cross or isolated, with tiered maximum leverage.
* **Funding:** hourly, from the premium of the mark over the oracle price.
* **Liquidation:** at maintenance margin, first by the market's liquidity vault, then by
  auto-deleveraging.
* **Pricing:** validators vote the oracle prices, and the median of the stake-weighted votes is
  used. The mark combines the oracle, the book and other venues' perp prices.
* **Containment:** price bands, circuit breakers and open-interest limits bound what one price
  move can do.
* **Listing:** markets for off-chain assets are listed by governance. A perp on a QRDX token is
  listed by anyone, and priced by the token's own spot market (a time-weighted average of its
  deepest pool), with open interest capped by that market's depth.

### 7.2 Spot: one market per pair

Order books and concentrated-liquidity pools form one market per pair. A trade takes the best
price across resting orders and every pool after fees, splitting between pools as needed. A
crossed book is uncrossed at each block. Swaps can route through QRDX and the settlement asset.

### 7.3 Trading features

* **Order types:** limit, market, post-only, IOC/FOK, reduce-only.
* **Triggers:** stops and take-profits that wait out a gap instead of filling at any price,
  brackets and one-cancels-other.
* **Other features:** TWAPs, a dead man's switch, sub-accounts, user vaults, fee tiers and
  referrals, builder fees, and portfolio margin.
* **Fair ordering:** each block's cancels run before its post-only orders, which run before the
  rest. A proposer cannot trade ahead of a maker's cancel.
* **The free trading lane:** trading operations sent at a gas price of 0 pay nothing, within a
  budget that grows with an account's trading.
* **Only transactions that run:** a block's exchange transactions are judged together before any
  runs. Each must be correctly signed and authorized, continue its nonce sequence, and be paid
  for: its payer must hold the maximum fees of all its transactions in the block, and those
  fees are reserved up front. A block carrying one that fails is invalid, so a transaction
  can't occupy block space without paying.

### 7.4 Native tokens and names

Tokens are a protocol standard, in the manner of Solana's SPL. Issuers can add extensions in the
manner of Token-2022: freeze, pause, transfer fees, hooks. Every token appears in the EVM as an
ERC-20/ERC-777 contract, and every NFT collection as ERC-721. QNS, the QRDX Name Service, sells
human-readable names, priced by length.

---

## 8. The bridge

### 8.1 Deposits

1. **Lock.** A user locks an ERC-20 in the `QRDXLockbox` contract on its home chain, naming a QRDX
   recipient.
2. **Attest.** Each validator reads its own RPC endpoint for that chain, up to the chain's
   finalized block only, and attests the deposit with its block's time.
3. **Mint.** When attestations with identical content carry more than two thirds of the stake,
   the protocol mints the bridged token through a mint authority no key controls. A deposit is
   minted once.

**Proving a deposit.** The lockbox also records each deposit in storage. So a deposit can be
minted without anyone attesting it: anyone proves the record with a Merkle-Patricia storage
proof (`eth_getProof`) against a finalized head of that chain the validators attested
(`BRIDGE_PROVE_DEPOSIT`). The validators then vouch for one state root per head, not for each
deposit, and a network can have them attest heads only.

### 8.2 Withdrawals, releases and refunds

* **Withdrawals.** A withdrawal burns the bridged token on QRDX and records it.
* **Releases.** The home chains cannot verify ML-DSA-65, so a **custodian multisig** releases each
  finalized withdrawal from the lockbox, at most once per withdrawal. The custodian's tooling
  plans releases only from withdrawals that every QRDX node it asks reports identically.
* **The deposit window.** A deposit counts toward a mint only within `BRIDGE_DEPOSIT_WINDOW` of its
  source block's time (7 days by default). After the window it never does.
* **Refunds.** The custodian may refund a deposit QRDX will never mint, once QRDX's *finalized*
  time is past its window. This covers an unlisted token, a recipient QRDX refuses, or a deposit
  held back too long. The lockbox itself allows only a recorded deposit, whole, back to its
  depositor, after a refund delay longer than the window. The custodian's reconciliation alarms
  on any release or refund that does not match QRDX's records.

### 8.3 Guardrails

* **Mint limits.** Each bridged asset has a daily mint limit and a supply cap (`BRIDGE_MINT_LIMITS`).
  On a real network an asset without limits mints nothing.
* **Pause.** Governance can pause minting. A held deposit keeps its attestations and mints later,
  or is refunded after its window.

### 8.4 Trust, stated plainly

| Act | Who must be honest |
|---|---|
| Minting | Validators holding two thirds of the stake: either attesting each deposit, or attesting only the source chain's finalized state root that deposits are then proven against. Each reads its own source-chain endpoint. |
| Releasing and refunding | The custodian multisig. |
| Bounded by | The mint limits, the deposit window, and on-chain reconciliation of every release and refund. |

Replacing head attestation with an on-chain light client of each source chain's finality is on
the roadmap (§13).

### 8.5 Attested chain heads

Validators also attest each bridged chain's finalized head, its hash and state root. Contracts can
verify proofs of that chain's state against it.

---

## 9. Governance

The validator committee votes on proposals by stake. Voting takes 7 days, then a 2-day timelock
runs before execution, and a veto window lets stake block a proposal. Governance can:

* spend from a system wallet;
* list and delist validator-priced perps markets;
* freeze the genesis master controller;
* approve protocol forks, each by the hash of its definition;
* pause bridge minting;
* declare a quantum emergency, the Doomsday Protocol's second trigger (§3.4).

Protocol rules change only through chain-spec forks that validators approve on chain.

---

## 10. Tokenomics

| | |
|---|---|
| Supply at genesis | 10,000,000 QRDX |
| Treasury | 4,993,000 |
| Foundation | 2,496,500 |
| Community fund | 1,497,900 |
| Validator incentive fund (genesis validators' stakes) | 998,600 |
| System wallets (operating budgets) | 14,000 |

* **Fees:** every gas fee, EVM or exchange, is burned.
* **Staking rewards:** minted at the chain-spec rate (5 % a year by default).
* **Exchange fees:** paid to stakers and the liquidity vaults, by the fee schedule.

The holders of the prefunded allocations, the genesis validators and the reward rate are launch
decisions (docs/TOKENOMICS.md).

---

## 11. Security: what is verified, and what is not yet

**Verified in the codebase.**
* About 3,400 automated tests, including:
  * deterministic rebuild-equals-forward checks;
  * a rollback audit of every exchange operation;
  * known-answer tests of the cryptography;
  * an equivalence suite of the EVM against a reference world;
  * Ethereum's Shanghai state tests, run against the QEVM;
  * fuzzing of every decoder that peers and users reach.
* Live multi-node runs on a 4-node network, covering:
  * finality;
  * slashing evidence;
  * a doppelganger caught and stopped;
  * EIP-1559 and EIP-2930 transfers settling identically on every node;
  * the bridge end to end: mint, withdrawal, release, and the refund of an unlisted and of a
    rate-limited deposit.
* docs/KNOWN_ISSUES.md records every defect found and how it was fixed. Recent ones:
  * a proposer could choose the exchange's clock;
  * a restarted validator could double-vote;
  * an EVM payer's balance could go negative;
  * the EVM's PQ precompiles collided with Ethereum's.

**Not yet.**
* External audits of the consensus, the exchange, the lockbox, the smart accounts and the
  cryptographic integration.
* A multi-week soak at production scale across continents. Whether 250 ms slots hold on a global
  validator set is to be measured there.
* A bug bounty.

Mainnet waits on these; the readiness plan is public (docs/MAINNET_READINESS.md).

---

## 12. What changed since v3.2

v3.2 described designs that are not part of the protocol as built:

| v3.2 | Now |
|---|---|
| "Trustless bridge: no centralized custodian required" | The bridge mints by validator attestation and releases through a custodian multisig, with the guardrails of §8. Trust-minimized releases are roadmap items. |
| Bitcoin and Solana bridges | Not built. The bridge supports EVM chains. |
| Doomsday Protocol (canary wallet, automatic circuit breaker) | The earlier prototype never ran in consensus and was removed. It is rebuilt on the bridge's proofs (§3.4): a proven canary spend, or governance, turns ECDSA off in consensus. |
| OracleTransactions (cross-chain transaction types) | Not built. Attested chain heads and proof precompiles cover reading other chains. |
| qRC20 token standard | Replaced by the native token standard (§7.4). |
| ML-DSA verification at EVM address `0x09` | Moved to `0x…0500`: `0x09` is Ethereum's BLAKE2F. The ML-KEM precompiles are removed. |

**New since v3.2:**
* the zero-sum perps clearinghouse;
* unified spot liquidity;
* Casper FFG finality and 250 ms slots;
* incremental state roots and state proofs;
* account control;
* PQ smart accounts;
* EIP-1559 transactions;
* the consensus bridge with refunds and guardrails;
* validator slashing protection.

---

## 13. Roadmap

Targets, not commitments: each depends on the one before it, and on what audits find.

| Phase | Target | Work |
|---|---|---|
| Completeness | Q4 2026 | Nodes publishing and advertising snapshots (checkpoint sync and pruning are built: §5.3). A public testnet across continents with outside validators. A TypeScript SDK for post-quantum wallets and smart accounts. |
| Audits | Q1 2027 | Freeze the code. Audit the consensus, exchange, lockbox, smart accounts and cryptography. Fix what the audits find and soak again. Open the bug bounty. |
| Mainnet | after the audits | Genesis ceremony, registered chain ids, lockboxes and custodians on the first source chains. Launch with conservative guardrails (bridge limits, leverage, open interest), loosened as the chain proves itself. |
| After launch | 2027 | **Light-client heads:** verify a source chain's finality on QRDX (for Ethereum, its sync committee) instead of attesting heads, so proven deposits need no trust in QRDX's validators. **Canaries and registries live:** deploy the migration registry and fund a Doomsday canary on each bridged chain (§3.4). |
| Research | — | **Outbound bridge without a custodian:** a STARK proof of QRDX finality checked on the source chain (hash-based, so itself post-quantum). **Smaller history:** aggregate finalized block signatures into a proof, or sign blocks with FN-DSA (Falcon). **Encrypted mempool:** threshold ML-KEM, so no one can read a transaction before its order is fixed. |

---

*This paper describes node release 3.0.0. The source, the defect register (docs/KNOWN_ISSUES.md)
and the readiness plan (docs/MAINNET_READINESS.md) are the authority where they differ from it.*
