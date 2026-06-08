# Consensus & State Integration — Remaining Work

> **Status date:** June 2026. Snapshot after the consensus-hardening arc
> (execute-on-mine → proposer auth → E-D4 binding → validator-set convergence →
> eligibility & E-D4 enforcement → PQ key-identity hardening).
> **Verified baseline:** integration 12/12, unit ~2043.
> **Companion docs:** `EVM_STATE_CONSENSUS_INTEGRATION.md` (the detailed E-D*
> ledger), `PRODUCTION_DEPLOYMENT.md`, `QRDX_IMPLEMENTATION_CHECKLIST.md`.

## ✅ Done (committed, integration-verified)

- **Exchange domain consensus integration** — admission → block codec → proposer
  inclusion → deterministic import replay with revert-on-mismatch → reorg rebuild.
- **EVM/account execute-on-mine (E-D3b)** — admit-only `eth_sendRawTransaction`,
  proposer executes the EVM section + declares `account_state_root`, importers
  replay with reject-on-mismatch, reorg rebuild, sync section propagation.
- **Proposer authentication on import** — Dilithium signature + pubkey↔address
  binding + **slot-proposer eligibility (enforced)**.
- **E-D4 unified state root** — BLAKE3-512 over (UTXO, account, exchange) bound
  into the signed header; **enforced on live-broadcast import** (bulk-sync stays
  trust-replay).
- **Validator-set convergence** — fixed the Dilithium key-identity load bug, set
  built from the consistent `validators` table, order-independent selection.
  Reorgs ~40 → ~0.
- **Slot clock** — fixed frozen-at-0 genesis-timestamp parse.
- **PQ key-identity hardening** — `_restore_from_bytes` no longer silently
  regenerates a random keypair; raises on address access without a public key.

## ⏳ Remaining — consensus / state

1. **E-D4 sync-path enforcement (settled-state).** E-D4 is enforced only on the
   live-broadcast paths. The bulk-sync path is trust-replay because a catching-up
   node transiently differs mid-reorg. To extend cryptographic enforcement to
   syncing nodes, add a **finalized-height** check: verify the unified root only
   at/under the finalized boundary (where state can no longer reorg), not at the
   churning tip. Prereq: a usable finality marker (see item 3).

2. **Full-node import performance / S10 flake.** S10 (cross-node consistency)
   intermittently fails because the non-validator full node lags ~2 blocks at the
   balance-check moment. Each imported block now does Dilithium signature
   verification + eligibility reconstruction (+ live unified-root recompute), all
   serially during bulk catch-up. Investigate whether per-block PQ verification is
   the bottleneck and, if so, batch/parallelize or cache the validator set;
   separately make S10's convergence poll more tolerant. Decide which is cause vs
   test-strictness before just loosening the test.

3. **Finality / fork-choice maturity.** Residual reorgs are longest-chain
   catch-up from propagation latency (block-time ≈ propagation-time). A finality
   gadget (justified/finalized checkpoints from attestations) would (a) give item
   1 its settled boundary and (b) bound reorg depth. Attestation aggregation
   exists (`AttestationPool`); wiring it into a finality decision is the work.

4. **Validator lifecycle convergence.** The `validators` table is genesis-seeded
   and consistent, but runtime validator set changes (activation/exit queues,
   stake updates via rewards/slashing at epoch boundaries) are not yet propagated
   into a single converged source. Until then the active set is effectively the
   genesis set. Needed before dynamic validator membership.

5. **RANDAO accumulation.** `_randao_mix` is constant (all-zeros) network-wide, so
   proposer selection is deterministic but NOT unpredictable — a known weakness.
   Accumulate RANDAO reveals into the mix (kept consistent across nodes) for
   unbiased/unpredictable proposer selection.

6. **`from_hex`/`from_bytes` caller audit (low).** Core primitive is hardened
   (raises rather than inventing identity). Two `pq_wallet.py` paths
   (`from_private_key`, legacy keystore) still construct address-less wallets;
   confirm no runtime path calls `.address` on them (unit+integration currently
   green, so none tested do).

## ⏳ Remaining — economic integrity (Phase E)

7. **Native↔EVM balance unification.** Gas and exchange margin must debit *real*
   balances. Today EVM execution syncs the sender's native balance in
   (`prepare_execution`) but the account/native coupling isn't a single source of
   truth. Unify so fees/margin/settlement move actual value, deterministically.

## 🔒 Process gates (cannot be satisfied in-repo)

8. **External security audit** of the consensus + crypto + exchange paths.
9. **≥30-day multi-validator soak** (the `QRDX_IMPLEMENTATION_CHECKLIST` "Production
   Ready" gate). The mini-soaks here (3 runs) are smoke-level, not the real gate.

## Suggested next order

Item 2 (import perf / S10) is the most concrete and de-risks the green signal
everything else relies on. Item 3 (finality) unlocks items 1 and 4 and is the
highest-leverage consensus piece. Item 7 (balance unification) is the largest and
gates real economic use.
