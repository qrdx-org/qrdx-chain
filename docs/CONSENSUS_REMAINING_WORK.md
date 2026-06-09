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

2. **Full-node import performance / S10 flake. — ✅ RESOLVED (was a test bug).**
   S10's balance check compared `eth_getBalance` across all nodes without
   requiring equal height; a balance is a function of height, so a full node a few
   blocks behind was compared against caught-up validators and intermittently
   "failed" despite consistent state. Fixed to compare only among nodes at the max
   height (3-run soak: 12/12, full height convergence). The soak's full
   convergence also showed the full node DOES keep up — per-block PQ verification
   is NOT a bottleneck at this scale, so no import-perf work is needed now (revisit
   only if larger validator sets / higher tx rates surface real catch-up lag).

3. **Finality / fork-choice maturity.** Residual reorgs are longest-chain
   catch-up from propagation latency (block-time ≈ propagation-time). A finality
   gadget (justified/finalized checkpoints from attestations) would (a) give item
   1 its settled boundary and (b) bound reorg depth.

   **Scoped (investigated June 2026) — it is an unwired SUBSYSTEM, not a small
   wiring job.** The scaffolding exists but the whole chain is disconnected:
   - **Attestation propagation is not wired.** `ValidatorManager.submit_attestation`
     looks for `self._attestation_broadcast_fn`, which is **never bound** (no
     `set_attestation_broadcast` caller); `qrdx/validator/gossip.py` (which has
     attestation topics) is **not imported by the running node**. So each
     validator holds only its OWN attestations and never sees peers'.
   - **No cross-validator aggregation/inclusion.** Consequently proposed blocks
     carry ~0 attestations (`attestations=0` in logs), so the 2/3-stake finality
     threshold can never be met.
   - **Finality computation is dead code.** `consensus.compute_epoch_state`
     (computes `is_finalized` from attesting-stake ratio ≥ `ATTESTATION_THRESHOLD`)
     has **no callers**.
   - **Epoch-finalize persistence is PostgreSQL-only.**
     `epoch_processing._persist_*` uses `database.pool.acquire()` / `$1` / `NOW()`,
     so on the SQLite testnet the `epochs.finalized/justified` columns are never
     written; `get_pos_chain_head` always reports finalized_epoch=0.

   **Status — links 1–4 BUILT (observe-only), link 5 remains.** Implemented via
   the block-section pattern (attestations ride in block bodies; no separate
   gossip transport): `attestation_block.py` codec, `attestation_votes` DB table +
   SQLite epoch-finality writer, `finality.py` (record+verify votes; simplified
   Casper FFG justified/finalized), wired into the proposer + all import paths.
   **Verified:** integration 12/12, finality advances identically on all 4 nodes
   (observe). `get_pos_chain_head` now reports a real finalized boundary.

   **Link 5(a) — fork-choice finality guard: ✅ DONE (enforced).**
   `finality.finalized_block_height` = deepest height where ≥2/3 stake attested to
   a canonical block at least that deep (stake-weighted DEPTH — same-block
   supermajority was too strict, gave -1 since validators attest divergent heads).
   `handle_reorganization` now REFUSES (returns None, keeps the local finalized
   chain) any reorg below that height, bounding reorg depth to the finality lag.
   Gated by `_ENFORCE_FINALITY_REORG_GUARD`. Verified: finalized_height
   deterministic across nodes (=25 vs tip 34), integration 12/12 with 0 spurious
   refusals.

   **Link 5(b) — E-D4 on bulk-sync: ✅ DONE (observe-only, by design).** The
   bulk-sync path now runs the unified-root check in OBSERVE mode (warn, never
   reject); observed 0 mismatches on all nodes incl. the syncing full node (sync
   state is consistent now that reorgs are ~0 + finality bounds them). Kept
   observe-only deliberately: a node can reorg mid-catch-up and must not reject
   canonical history, and the threat is already covered by live-path enforcement +
   the finality reorg guard (refuses rewrites below finalized) + the sequential
   height check. Full sync enforcement is unnecessary given those.

4. **Validator lifecycle convergence.** The `validators` table is genesis-seeded
   and consistent, but runtime validator set changes (activation/exit queues,
   stake updates via rewards/slashing at epoch boundaries) are not yet propagated
   into a single converged source. Until then the active set is effectively the
   genesis set. Needed before dynamic validator membership.

5. **RANDAO accumulation.** `_randao_mix` is constant (all-zeros) network-wide, so
   proposer selection is deterministic but NOT unpredictable — a known weakness.
   Accumulate RANDAO reveals into the mix (kept consistent across nodes) for
   unbiased/unpredictable proposer selection.

6. **`from_hex`/`from_bytes` caller audit. — ✅ DONE.** Core primitive hardened
   (raises rather than inventing identity), with an actionable error message.
   Audited callers: the consensus/validator path passes the public key; the only
   address-less constructors are `PQWallet.from_private_key` / `from_hex` (CLI
   "import private key", `cli/wallet.py`) and legacy keystores lacking
   `public_key` — these now fail loudly + clearly on `.address` (previously
   returned a silent random address). Sign-only use still works. Follow-up
   (cosmetic): the CLI import-PQ-key-from-private-only flow should prompt for /
   require the public key, since Dilithium cannot recover it.

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
