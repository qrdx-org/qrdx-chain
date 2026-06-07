# EVM / Account-Model State — Consensus Integration

> **Status:** Phase 1 implemented (live gossip convergence). Phase 2 (block-level
> inclusion + replay) is required before mainnet.  
> **Date:** June 2026  
> **Related:** `PRODUCTION_DEPLOYMENT.md` §14.8, `QRDX_IMPLEMENTATION_CHECKLIST.md`

---

## 1. Summary

QRDX runs **two state models side by side**:

| Layer | Used for | Storage | Consensus path |
|-------|----------|---------|----------------|
| **UTXO / native** | legacy Denaro transfers | `unspent_outputs` | mempool → gossip → block → re-applied on import |
| **Account / EVM** | `0x`/`0xPQ` transfers, contracts, tokens, AMM | `account_state` | **none — applied locally only** |

The account/EVM layer — which is the *canonical* path for `0x`/`0xPQ` value
transfers and all smart-contract activity — was **not integrated with
consensus**. This document explains the gap, why it matters, the target design,
and the phased remediation. Phase 1 (this change) makes live nodes converge;
Phase 2 (future) makes EVM state durable and consensus-final.

---

## 2. The gap (as found)

### 2.1 `eth_sendRawTransaction` applies state out-of-band

The handler ([qrdx/node/main.py](../qrdx/node/main.py) `eth_sendRawTransaction_handler`):

1. recovers the sender from the signature,
2. syncs sender + recipient native balances into EVM state,
3. executes the transfer/contract call in the EVM,
4. **commits the result directly to `account_state` on the receiving node**,
5. returns the tx hash.

It does **not**:
- add the transaction to the mempool (`pending_transactions`),
- propagate the transaction to peers,
- arrange for the transaction to be included in any block.

### 2.2 Block import never replays EVM transactions

Block import on a peer goes `process_and_create_block` → `create_block`
([qrdx/manager.py](../qrdx/manager.py)). It deserializes the block body with
`Transaction.from_hex` (the **UTXO** format) and applies UTXO effects only. There
is no path that re-executes EVM/contract transactions during import.

### 2.3 Consequences

- **No cross-node visibility (pre-fix):** a transfer executed on node A is
  invisible to nodes B/C/D — their `account_state` is unchanged.
- **Not durable:** because blocks don't carry EVM txs and import doesn't replay
  them, EVM state is lost on a resync / fresh sync from chain history. A node
  rebuilt from blocks would have empty `account_state` beyond genesis.
- **Not consensus-final:** the state root does not commit to EVM state
  transitions, so validators cannot attest to account-model correctness.

> This is why the integration suite's cross-node check (S10) was historically
> only "passing" by reading the *UTXO* balance (unchanged by EVM transfers), not
> by verifying the actual account-model effect propagated.

---

## 3. Target design (Phase 2 — required for mainnet)

EVM transactions must become first-class consensus objects:

1. **Mempool admission.** `eth_sendRawTransaction` adds the raw signed tx to the
   mempool, tagged as an EVM/contract transaction (distinct from UTXO txs), after
   signature + nonce + intrinsic-gas validation.
2. **Gossip.** The raw tx propagates to peers via the existing authenticated
   propagation path, with a seen-cache for loop prevention.
3. **Block inclusion.** The slot proposer selects pending EVM txs, executes them
   (already supported by `ValidatorManager._execute_contract_transactions`), and
   includes them in the block body with a serialization that round-trips.
4. **Deterministic replay on import.** Every node, on importing a block,
   re-executes the included EVM txs in canonical order against the parent state,
   and verifies the resulting **EVM state root** matches the block header. This
   is the missing convergence + durability mechanism.
5. **Unified state root.** The block's `state_root` must commit to *both* the
   UTXO set and the `account_state` trie so attestations cover EVM state.
6. **Nonce / replay protection** enforced at mempool admission and at execution.

### Risks / why this is staged
Getting replay ordering, gas accounting, and state-root agreement exactly
consistent across all validators is consensus-critical: any divergence causes a
chain split. It requires a multi-validator soak test (the
`QRDX_IMPLEMENTATION_CHECKLIST.md` "Production Ready" gate: ≥30 days on a
persistent testnet). It must not be rushed.

---

## 4. Phase 1 (this change) — live gossip convergence

Scope: make all **live** nodes converge on the same `account_state` immediately,
without touching block production/import. This closes the most visible part of
the gap (other nodes never seeing the transfer) and is independently verifiable.

**Mechanism:**
- A node-level seen-cache (`evm_tx_cache`) keyed by the EVM tx hash.
- On `eth_sendRawTransaction`:
  - if the tx hash is already seen → return the hash, do **not** re-execute or
    re-propagate (idempotent; terminates gossip loops);
  - otherwise mark seen, execute locally as before, then **propagate the signed
    raw tx to peers**, which run the identical deterministic execution.
- Because the transaction is fully signed and the EVM execution is deterministic
  (same sender, nonce, value, data, parent state sync), every node applies an
  identical state delta. The nonce check makes re-delivery a safe no-op.

**Explicit limitations of Phase 1 (do not mistake for Phase 2):**
- EVM state is still **not** written into blocks and **not** replayed on import,
  so it is **not durable across a resync** and **not consensus-final**.
- Convergence relies on liveness + connectivity at submission time; a node that
  is offline during gossip will not receive the delta until Phase 2 inclusion.

Phase 1 is a strict improvement (live nodes converge) and a safe stepping stone;
it does not regress any existing behavior.

---

## 5. Verification

The integration scenario **S10 (cross-node consistency)** is strengthened to read
the **account-model** balance via `eth_getBalance` on every node and assert it is
both **consistent across all nodes** and **reflects the transfer** — rather than
reading the unchanged UTXO balance. Run:

```bash
PYTHONPATH=. pytest tests/test_testnet_integration.py::test_full_integration_suite \
  -m integration -s --timeout=520
```

---

## 6. Phase 2 — EVM/account consensus integration (the gating work)

Phase 1 gives *live* convergence but EVM state is still not durable, not
consensus-final, and not part of an enforced state root. The exchange domain
already received full consensus integration (see
`EXCHANGE_PRODUCTION_READINESS.md`, Phases D1–D3 + reorg safety); the EVM/account
domain must receive the **same treatment**, and doing so is the prerequisite for
**D4.2** (enforcing the unified block state root) **and Phase E** (charging
gas/margin against real balances). It mirrors the exchange work step for step:

- **E-D1 — admission gate.** An EVM-tx mempool: decode the RLP tx, recover the
  sender (ECDSA — recovery itself binds the sender, so no separate signature
  check is needed), enforce a nonce window vs the account nonce, dedup by tx
  hash, and cap per-sender/global for DoS. `select_for_block` yields a canonical,
  gap-free, per-sender ordering. *(Mirrors `ExchangeMempool`; first step,
  self-contained + unit-testable, no behavior change — built standalone before
  wiring, exactly as the exchange mempool was.)*
- **E-D2 — block inclusion.** The proposer selects admitted EVM txs and writes a
  canonical `evm_transactions` section into the block body (codec mirroring the
  exchange one), and declares the resulting `account_state_root`
  (`db.get_account_state_root()`, already added in D4.1).
- **E-D3 — deterministic import replay.** Importing nodes re-execute the EVM
  section against the parent account state (the EVM executor is deterministic),
  recompute `account_state_root`, and **reject on mismatch**, reverting on
  failure. Replace Phase-1 gossip with this consensus path; persist the section
  for durability; rebuild from the canonical chain on startup/reorg (mirroring
  `rebuild_exchange_state_from_chain`).
- **E-D4 — unify + enforce.** With UTXO, exchange, **and** account all
  deterministically replayed on import, bind `unified_state_root` into the block
  signing root and enforce it (recompute + reject). This is **D4.2**.
- **E-E — economic integrity (Phase E).** Once account balances are a single
  consensus-replayed ledger, debit gas/stake/margin from the sender's real
  balance in both the exchange and EVM execution paths; reject if underfunded.

**Risk note.** This is base-layer, consensus-critical work; each step must be
verified against the integration testnet (12/12) and unit suite, landed
incrementally, and ultimately covered by the external audit + ≥30-day
multi-validator soak (the `QRDX_IMPLEMENTATION_CHECKLIST.md` Production-Ready
gate). No in-repo code substitutes for those process gates.

### 6.1 Status
- **E-D1 admission gate: ✅ implemented (this change)** — `qrdx/contracts/evm_mempool.py`
  (`EVMMempool` + `parse_eth_raw_tx`), tests in `tests/test_evm_mempool.py`.
  Standalone, not yet wired into the live `eth_sendRawTransaction` path.
- **E-D2 block-body codec: ✅ implemented (this change)** — `qrdx/contracts/evm_block.py`
  (`encode_evm_txs`/`decode_evm_txs`/`evm_txs_canonical_bytes`/
  `extract_evm_transactions_from_dict`, key `evm_transactions`), tests in
  `tests/test_evm_block_codec.py`. Pure codec; round-trips raw txs (authenticity
  preserved — sender re-recovers), JSON-safe, deterministic, order/tamper
  sensitive, backward compatible. Proposer *inclusion* of the section is bundled
  into E-D3, because for EVM it is entangled with replacing the Phase-1 gossip
  path (the section would be an empty no-op until `eth_sendRawTransaction` routes
  through the mempool + replay).
- **E-D3a foundation: ✅ implemented (this change)** — additive, behavior-neutral.
  `block_evm_transactions` table + `add_block_evm_txs`/`get_block_evm_txs`
  (per-block EVM section storage, with `remove_blocks` cleanup); module globals
  `EVM_EXECUTOR`/`EVM_STATE_MANAGER` exposed at contract-system init so block
  production + import can execute EVM txs with the same executor/state as the RPC
  handler; node `EVM_MEMPOOL` + `EVM_PENDING_NONCE` provider. Nothing consumes
  these yet (E-D3b), so behavior is unchanged (integration 12/12). Tests:
  `tests/test_block_evm_storage.py` (4).
- **E-D3b (1/2): execution core factored — ✅ done.** `_execute_evm_raw_tx(...)`
  (`node/main.py`) is the shared, deterministic EVM execution core (decode →
  recover → native↔EVM sync → execute → atomic finalize) now used by the RPC
  handler; the proposer + import paths will call the same function. Behavior-
  neutral (integration 12/12, unit 2009).
- **E-D3b (live admission): ✅ done.** `eth_sendRawTransaction` now passes through
  the EVM mempool admission gate (recover sender, nonce window, dedup, DoS caps)
  before execution — standard Ethereum mempool semantics. Mempool entry transient
  (removed on execute) pending the full flip. Integration 12/12, unit 2009.
- **E-D3b (final flip): pending (atomic, highest-risk).** Remaining steps:
  1. `eth_sendRawTransaction`: admit-only — remove immediate execute; return the
     tx hash always (web3 standard: contract address comes from the receipt);
     gossip becomes mempool propagation (peers admit, not execute).
  2. Proposer (`validator/node_integration.py`, wired from `main.py`):
     `select_for_block()` → execute each via `_execute_evm_raw_tx` →
     `db.get_account_state_root()` → write `evm_transactions` section + declare
     `account_state_root` → `db.add_block_evm_txs` → drain mempool.
  3. Import (`p2p.submitBlock`, `process_and_create_block`): replay the section,
     recompute `account_state_root`, **reject on mismatch**, persist.
  4. Extend `rebuild_*_from_chain` to replay EVM sections (startup + reorg).
  5. Retire the Phase-1 gossip execution role.
  6. Rework S04/S10/S11 for execute-on-mine timing (balance changes on inclusion).

  **🔎 Prerequisite (gates step 3's safe reject-on-mismatch): atomic EVM block
  commit.** Progress + precise structure:
  - ✅ `ContractStateManager` has cache `snapshot()`/`revert()`/`commit()`, and
    `ExecutionContext.finalize_execution(defer_commit=True)` now keeps a
    successful tx's changes in the cache instead of flushing per-tx
    (`tests/test_evm_defer_commit.py`).
  - ⚠️ Still required: the canonical account root is `db.get_account_state_root()`
    (full table, **BLAKE3-512**) — `ContractStateManager.get_state_root()` is
    cache-only + keccak + a partial set, so it is NOT usable as the consensus
    root. Validating the root therefore means flushing the cache to the DB and
    reading it back **before** deciding to keep or discard the block.
  - ⚠️ That flush-read-decide must be one DB transaction with commit-or-rollback,
    but the execution path calls `conn.commit()` at **multiple** points
    (`finalize_execution`, `sync_address_to_evm`, `record_balance_change`), each
    of which would prematurely end the transaction. So the atomic boundary
    requires coordinating *all* of these under a single per-block transaction
    (e.g. thread a `defer_commit`/transaction handle through the state-sync path
    and commit/rollback once per block) — an invasive, consensus-critical change
    to EVM commit semantics, and the natural unit of the focused flip effort
    rather than another standalone primitive. Also delete DB rows for accounts
    *created* during a rolled-back block (the same "remove created entities"
    correctness point as the exchange snapshot fix).

  **Determinism note:** EVM execution syncs the sender's *native* balance in
  (`prepare_execution`); deterministic only while native balances are themselves
  a deterministic function of the chain. Production hardening of the native↔EVM
  coupling is the balance-unification work shared with Phase E. The flip is
  consensus-critical — verify against the full suite over multiple runs + the
  audit/soak gate.
- E-D4 / E-E: pending, in the order above.
