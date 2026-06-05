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
