# Exchange — Production Readiness Specification

> **Status:** The exchange *engine* is functionally complete and exercised end to
> end in-process (`tests/test_exchange_e2e_leverage.py`). It is **not yet
> consensus-integrated for production**. This document is the concrete, code-
> grounded list of everything required to run it securely across nodes, plus the
> security properties and certification gates.
> **Date:** June 2026 · **Related:** `docs/EVM_STATE_CONSENSUS_INTEGRATION.md`, `PRODUCTION_DEPLOYMENT.md`

---

## 1. Where it stands

| Capability | State | Evidence |
|------------|-------|----------|
| AMM, order book, perps, router, oracle | ✅ implemented | `qrdx/exchange/*` |
| Deterministic single-entry execution | ✅ `ExchangeStateManager.process_transaction` | state_manager.py |
| In-process E2E (tokens→pair→limit→leverage) | ✅ passing | test_exchange_e2e_leverage.py |
| State-root determinism hooks | ⚠️ exists, unverified | `block_processor.process_exchange_transactions` |
| **Tx signature verification** | ❌ **missing** | `process_transaction` checks only nonce+gas |
| Mempool admission of exchange txs | ❌ no live path | — |
| Block inclusion by the live proposer | ❌ | `ValidatorManager.propose_block` pulls UTXO pending only |
| Import-side replay + state-root validation | ❌ not on live path | `validate_exchange_state_root` unused live |
| Gas/fees charged to account capital | ❌ tracked, not debited | `process_transaction` step 6 |
| Funding-rate / liquidation block duties | ⚠️ coded, unscheduled | `_settle_funding_rates`, `_check_liquidations` |

---

## 2. Critical findings (must fix before mainnet)

1. **No signature verification (security-critical).** `ExchangeTransaction`
   carries `signature` + `public_key` and exposes `signing_bytes()`, but nothing
   verifies them. `process_transaction` trusts `tx.sender` outright — any party
   can submit a transaction *as* any address (open a position, place an order,
   move liquidity) subject only to nonce/gas. **This is a spoofing/theft vector.**
   → Fix: a `verify()` primitive (Dilithium signature over `signing_bytes()` +
   binding `public_key` to `sender` address) enforced at **mempool admission**
   and at **block validation** (see §4). *(Implemented in this change — see §6.)*

2. **Broken consensus scaffolding (PostgreSQL on a SQLite chain).**
   `create_pos_block` / `commit_pos_block` (`qrdx/manager.py`) use
   `database.pool.acquire()` and `$1` placeholders — non-functional on SQLite
   (same class as the genesis-validator `Decimal` bug already fixed). The exchange
   consensus hooks they call are therefore effectively dead on the live path.

3. **Two competing block paths.** (a) `manager.create_pos_block`/`commit_pos_block`
   + `node/validator_integration.py` (has exchange wiring, PG-broken); (b)
   `validator/manager.py` `ValidatorManager.propose_block` + `node/main.py`
   PoS fast-path (the live path, no exchange/EVM inclusion). These must be
   reconciled into **one** audited path before mainnet.

4. **Unified state root not enforced live.** A block header should commit to
   `transactions_root` (UTXO) + `exchange_state_root` + `account_state_root`, and
   **every importing node must recompute and reject on mismatch.** Today
   `exchange_state_root` is computed only in the dead PG path and never validated
   on the live import path.

---

## 3. Target architecture

One block lifecycle, three state domains (UTXO, account/EVM, exchange), one root:

```
mempool ──┬─ UTXO txs ───────────────┐
          ├─ EVM/account txs (eth) ───┤   proposer (single live path):
          └─ exchange txs ────────────┘     1. select admitted txs (sig-verified)
                                            2. execute each domain deterministically
                                            3. roots: utxo_root, account_root, exch_root
                                            4. state_root = H(parent, utxo, account, exch)
                                            5. sign header
        block gossip ─►  importing node:
                                            1. verify proposer + attestations
                                            2. RE-EXECUTE every tx deterministically
                                            3. recompute the three roots
                                            4. REJECT if state_root mismatches
                                            5. commit atomically (or roll back)
```

Durability follows for free: because import re-executes from the block body, a
node rebuilt from chain history reconstructs identical account/exchange state.

---

## 4. Work breakdown (sequenced)

**Phase A — Security primitives (no consensus wire change; do first).**
- A1. `ExchangeTransaction.verify()` — Dilithium sig over `signing_bytes()`, and
  `PQPublicKey(public_key).to_address() == sender`. *(done, §6)*
- A2. `verify_exchange_tx(tx)` admission helper + adversarial tests. *(done, §6)*
- A3. Same primitive for EVM txs already exists (ECDSA recovery in
  `eth_sendRawTransaction`); add explicit nonce/replay guard at admission.

**Phase B — Determinism & state-root verification (consensus-safe to test now).**
- B1. Property tests: identical tx sequence ⇒ identical `exchange_state_root`;
  any tampered tx ⇒ different root; `validate_exchange_state_root` rejects it.
  *(done, §6)*
- B2. Cross-validator determinism: pin Decimal precision/rounding
  (`getcontext().prec`) and canonical ordering; add differential test across two
  fresh engine instances.

**Phase C — Reconcile to one block path (remove PG remnants).**
- C1. Delete or port `create_pos_block`/`commit_pos_block` PG code to SQLite, or
  fold their exchange wiring into the live `ValidatorManager` + `node/main.py`
  path. Exactly one block-commit function may exist.
- C2. Remove `database.pool`/`$1` usages chain-wide (audit: `grep -rn 'database.pool\|\\$1'`).

**Phase D — Mempool → block inclusion → import replay.**
- D1. Admit exchange + EVM txs to the mempool (sig-verified, nonce-checked,
  deduplicated), tagged by domain.
- D2. Proposer selects and includes them; block body serializes them
  (round-trippable `to_dict`/`from_dict` already exist for exchange txs).
- D3. Importing nodes re-execute all domains, recompute roots, reject on mismatch.
- D4. `account_state_root` + `exchange_state_root` added to header + signing root.

**Phase E — Economic integrity.**
- E1. Charge exchange gas/fees against the sender's `account_state` balance
  (capital), not just accumulate `_block_fees`. Reject if underfunded.
- E2. Margin/collateral debited from and returned to account balances on
  open/close/liquidation (today margin lives only inside the perp engine).
- E3. Schedule block-boundary duties every block: funding settlement
  (`_settle_funding_rates`), liquidations (`_check_liquidations`), TWAP oracle
  updates (`build_oracle_update_tx`).

**Phase F — Hardening.**
- F1. Per-market circuit breakers / price-band checks on order placement.
- F2. Oracle manipulation resistance (TWAP windows, staleness already present).
- F3. Rate limits + mempool DoS protection for exchange ops.
- F4. Fuzz/property suite for AMM math, liquidation, funding (overflow, rounding).

---

## 5. Security properties to assert (the bar)

1. **Authenticity:** no exchange/EVM state change without a valid signature whose
   key binds to `sender`. (Phase A)
2. **Determinism:** all honest validators compute byte-identical roots for the
   same block. (Phase B)
3. **Durability:** state survives a full resync (rebuild from blocks). (Phase D)
4. **Solvency:** Σ margins + insurance ≥ Σ position losses; no negative balances;
   gas/fees actually debited. (Phase E)
5. **Replay-safety:** a tx is includable at most once; nonces strictly increase.
6. **Liveness under failure:** a failing exchange tx reverts its own effects and
   charges gas without halting the block.

---

## 6. Implemented in this change

- `ExchangeTransaction.verify()` and `verify_exchange_tx()` — real Dilithium
  signature verification bound to the sender address.
- `tests/test_exchange_consensus.py`:
  - signature: valid passes; tampered params, wrong key, wrong sender, empty sig
    all rejected;
  - determinism: identical sequences ⇒ identical `exchange_state_root`;
  - tamper detection: a mutated tx ⇒ different root and
    `validate_exchange_state_root` returns invalid.

These satisfy parts of gates **A1–A2** and **B1**. The remaining phases (C–F),
plus the certification gates below, remain before mainnet.

---

## 7. Certification gates (process, not code)

Per `QRDX_IMPLEMENTATION_CHECKLIST.md` a feature is mainnet-eligible only after:
- **Security Tested:** external audit of the consensus + exchange math.
- **Production Ready:** ≥30 days on a persistent multi-validator testnet with no
  state-root divergence and no solvency incidents.

No amount of in-repo code substitutes for these; budget for them explicitly.
