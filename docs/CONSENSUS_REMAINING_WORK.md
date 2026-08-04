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

1. **E-D4 sync-path enforcement (settled-state). — ✅ DONE (defense-in-depth) + finding.**
   Unblocked once finality became real (item 3 / attestation gossip). The bulk-sync
   path now ENFORCES the unified root for a block at/under the node's `finalized_block_height`
   (`_ED4_ENFORCE_SYNC_FINALIZED=True`): such a block is settled (the reorg guard refuses to
   go below finalized), so a mismatch means divergent state from a corrupt/malicious peer →
   reject. The churning tip stays observe (a catching-up node can transiently differ).
   **Finding (measured: 0 would-rejects):** this is near-vacuous DEFENSE-IN-DEPTH — a node
   only syncs blocks ABOVE its tip, and its local `finalized_height` always trails its tip,
   so a synced block is essentially never at/under the local finalized boundary. The
   steady-state E-D4 coverage is therefore the live-broadcast path (already enforced); the
   finalized-sync check only bites if a finalized block is ever re-synced with divergent
   state (e.g. a restart re-syncing below a retained finalized boundary), where honest
   deterministic replay still matches so it never false-rejects (integration 16/16, 0
   finalized rejections). A non-vacuous "retroactive finalized-state audit" would need state
   replay to a past height; not pursued (low marginal value over live enforcement).

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

   **Scoped (June 2026) — it is TWO disconnected data models, not a quick port.**
   - Consensus reads the **`validators`** table: `db.get_validators()` →
     `block_verification.expected_proposer_for_slot` (proposer selection +
     eligibility, enforced) and `finality` (stake weights).
   - The lifecycle subsystem (`validator/lifecycle.py` `ValidatorLifecycleManager`,
     `validator/epoch_processing.py`) operates on SEPARATE tables
     (`lifecycle_validators`, `lifecycle_deposits`) and is run by
     `node_integration._epoch_processing_loop` → `process_epoch(epoch)` at each
     epoch boundary. So even when it runs, it never touches the table consensus
     reads → the active set stays at genesis.
   - Worse, `epoch_processing.py` still has **PostgreSQL-only SQL** (`$1/$3`,
     `pool.acquire()`, `NOW()`, `LEAST(...)`), so on the SQLite testnet
     `process_epoch` raises and the loop swallows it (`logger.error("Failed to
     process epoch ...")`) — the same PG-only issue fixed for finality earlier.
   - **Work:** (a) port the lifecycle/epoch-processing SQL to SQLite; (b) UNIFY the
     model so the lifecycle-managed set IS the `validators` table consensus reads
     (either write activations/exits/stake-updates into `validators` at the epoch
     boundary, or point `get_validators` at the lifecycle tables) — pick one
     canonical source; (c) deposits/withdrawals must flow from real
     staking transactions into that source; (d) observe→soak→enforce, since this
     changes who may propose (eligibility is enforced — a divergent set halts a
     node). Validator-set convergence + the Dilithium key-identity fix from the
     earlier arc are the prerequisite that makes this safe to attempt.

5. **RANDAO accumulation.** `_randao_mix` is constant (all-zeros) network-wide, so
   proposer selection is deterministic but NOT unpredictable — a known weakness.
   Accumulate RANDAO reveals into the mix (kept consistent across nodes) for
   unbiased/unpredictable proposer selection.

   **OBSERVE primitive BUILT (June 2026).** `qrdx/validator/randao.py`
   `compute_randao_mix(db, up_to_height)` folds every canonical block's reveal into
   a mix — a pure, deterministic, reorg-safe function of the chain (so cross-node
   convergence is automatic, no transport to wire). Exposed at `/get_randao_mix`.
   Selection is UNCHANGED (still the zero constant) → zero consensus risk. Tests:
   `test_randao_accumulation.py` (6).

   **ENFORCE GATE found (observe phase) → root-caused to a real import bug.** The
   mix folds *every* block's reveal, so it surfaces block-level history divergence
   that cumulative *state* roots mask. A clean 4-node run that converged on ONE
   unified state root still had nodes 0/2/3 on a different block at height 2 than
   node1. **Root cause: the import path validates height-SEQUENTIALITY but never
   checks a block's `parent_hash` against the local tip** — so a fork block is
   appended on a parent the node never stored (node0 holds `9cb28d` at h2 but h3's
   parent is `d8207a`, which node0 never stored). Fix:
   `main._check_parent_continuity` wired OBSERVE-only into the sync + p2p live paths
   (`_ENFORCE_PARENT_CONTINUITY=False`); verified it fires on exactly nodes 0/2/3.
   **ENFORCE was tried + reverted (naive reject is unsafe).** A 6-run enforce soak:
   run5 rejected 2 fork blocks yet still ended with 2 RANDAO mixes at equal height
   (didn't converge an equal-height equivalent fork); run6 had a node fall 3 blocks
   behind with a scenario failure (relying on the periodic sync/reorg poll to heal
   is too slow). **Safe enforce needs (1) the mismatch to ACTIVELY drive a reorg onto
   the declared-parent chain immediately, and (2) a deterministic tie-break for
   equal-height equivalent forks** — the real fork-choice work, now designed in
   **`docs/FORK_CHOICE_CONVERGENCE.md`** (two mechanisms + lowest-hash canonical
   rule + observe→soak→enforce rollout + the RANDAO-mix convergence proof). Until
   then keep observe; RANDAO selection stays on the zero constant (this is its gate).

   **UPDATE (2026-06-28) — gate now MET; selection-convergence CONFIRMED (observe).** The
   fork-choice work since then showed block history CONVERGES (the RANDAO mix is byte-
   identical across nodes at the common/finalized height; divergences are tip-local
   transients). A new observe in `fork_choice_reconcile_pass` (`[randao-observe]`) computes
   the real-mix proposer using the FINALIZED mix (settled, below the churning tip) + the
   converged validator set, for a chain-anchored slot, on every node. Measured across a
   16/16 run: for every (slot, finalized-mix) computed on ≥2 nodes, ALL nodes selected the
   **same** real-mix proposer (agree=8, disagree=0; real ≠ zero, so it's a real change). So
   cross-NODE agreement — the eligibility-halt risk — is resolved.

   **ENFORCE design (the remaining prerequisite — cross-TIME stability + soak).** Selection
   must be stable between propose-time and verify-time too. "Current finalized mix" advances
   as finality progresses, so a proposer and a later importer could compute different mixes →
   reject. Enforce therefore needs a DETERMINISTIC mix CHECKPOINT that is a fixed function of
   the BLOCK, not of wall-clock finality.

   **Recommended checkpoint: HEIGHT-based** (cleaner than slot-based — `blocks` has no slot
   column; slot lives in `block_content`). Select the proposer of the block at height H using
   `compute_randao_mix(db, H − LOOKBACK)` for a fixed `LOOKBACK` (~1 epoch of blocks, safely
   below the tip-fork depth, which the fork-choice observe showed is ~≤4). Because H is the
   block's own height, the proposer (building H) and every importer (verifying H) fold the
   identical prefix → same mix regardless of WHEN (cross-time stable); and `H − LOOKBACK` is
   below the churning tip → all nodes agree (cross-node stable, as the `[randao-observe]`
   already confirms for the finalized mix). Early blocks (H ≤ LOOKBACK) fall back to the seed.
   **Mechanism IMPLEMENTED + validated (2026-06-28).** `randao.checkpoint_mix_for_block(db,
   height, lookback)` is the primitive (cross-time stable — unit-tested; default lookback =
   `SLOTS_PER_EPOCH`). The `[randao-observe]` was repointed at it (anchored to the agreed
   finalized block): a 16/16 run shows agree=8 / disagree=0 (all nodes pick the same proposer
   under the checkpoint mix). So the mechanism is proven cross-time + cross-node.

   **Remaining = the ENFORCE flip + soak (halt-risk; own session).** ALL proposer-selection
   sites must switch to `checkpoint_mix_for_block(db, H)` for the block's height H together —
   they currently use the constant `manager._randao_mix` (`b"\x00"*32`) / the zero default:
   (1) `ValidatorManager.is_proposer` (manager.py:457 → `selector.is_proposer(..., self._randao_mix)`),
   (2) `ValidatorManager.validate_block` (manager.py:978 → `select_proposer(..., self._randao_mix)`),
   (3) `block_verification.verify_proposer_eligibility` (the import-path check, ENFORCED via
   `_ENFORCE_PROPOSER_ELIGIBILITY`; uses `expected_proposer_for_slot`'s zero default).
   Simplest wiring: refresh `manager._randao_mix = await checkpoint_mix_for_block(db, next_height)`
   per proposal attempt (covers 1+2), and pass the checkpoint mix into (3) from the block's
   `number`. Gate all on `ENFORCE_RANDAO_SELECTION` (default False = zero mix = today), flip
   together, soak ≥6 runs (gate: 0 eligibility halts, blocks every epoch, 1 unique RANDAO mix).

   **TRIAL (2026-06-28) — the HEIGHT-based checkpoint is WRONG; the chain HALTED.** Wired all
   3 sites (commit 0356692, gated off) and flipped the gate for one trial run: it stalled at
   ~block 10 / slot 17 with "proposer not eligible for slot" mismatches (6% pass). **Root
   cause:** keying the mix off `next_block_id` (proposer) / `block.number` (verifier) makes it
   depend on a node's CURRENT TIP — validators a block apart from propagation lag compute
   DIFFERENT heights for the same slot → different mix → they disagree on who may propose →
   no single agreed proposer → halt. The `[randao-observe]` MISSED this because it anchored to
   the agreed FINALIZED block (a fixed height all nodes share), so it only ever compared the
   mix at one common height — never the per-validator-tip decision.

   **Corrected design — key the checkpoint off the SLOT/EPOCH, not the height — IMPLEMENTED.**
   `randao.epoch_checkpoint_mix(db, epoch)` = mix folded to the last block of epoch−LOOKBACK
   (boundary found by binary search over heights, since block slot is monotonic in height —
   no schema change needed); `selection_mix_for_slot(db, slot)` is the single entry point both
   the proposer (`manager._selection_mix`) and verifier (`verify_proposer_eligibility`) use, so
   the slot→epoch math has one source. Keyed off the epoch → TIP-INDEPENDENT (unit-tested).

   **Corrected enforce TRIAL + SOAK (2026-06-28): no longer halts, but an intermittent
   LIVENESS dip gates it.** Flipping the (now epoch-based) gate no longer halts — the trial +
   most soak runs were 16/16 with 1 unique RANDAO mix (selection converges; 16/16 itself proves
   no cross-node eligibility mismatch, else blocks would be rejected → stall). BUT across 7
   enforce runs ~2 dipped to 81–94% with low block height (49/58 vs ~79) + elevated "not
   eligible" rejections. Widening LOOKBACK to 2 made it WORSE, so it is NOT reorg-boundary mix
   instability. **Root cause is structural:** RANDAO makes exactly ONE validator eligible per
   slot, so with few validators + propagation lag + reorgs an unlucky/uneven schedule
   occasionally leaves a slot unproposed (the primary missed it) or rejects competing blocks,
   dipping liveness. The ≥6-all-green gate is NOT met → kept OFF.

   **Backup-proposer attempt (2026-07-01) — implemented, but WORSENED liveness.** Built the
   top-K eligible set: `selector.proposer_ranking` (primary + deterministic stake-weighted
   backups; unit-tested — rank 0 == the old `select_proposer`), `verify_proposer_eligibility`
   + `manager.validate_block` accept ANY of the slot's top-K, and the proposal loop staggers
   backups (primary immediate; a backup waits then proposes only if no block landed). Gated on
   `RANDAO_PROPOSER_ELIGIBLE_K` (=2), neutral off. Soak: a run hit 75% (WORSE than K=1's
   81–94%), with HIGH block production (107) — so not a stall. Cause: the backup's timing
   checks the LOCAL tip, which races propagation lag — the primary's block exists but has not
   imported on the backup's node yet, so the backup proposes a COMPETING block → reorg churn.

   **Remaining = propagation-aware liveness (a real design, not a tune).** The consensus
   pieces (ranking + top-K acceptance) are correct + kept (neutral off); the flawed piece is
   the backup PROPOSAL TIMING. A working fix needs the backup to wait LONGER than propagation
   before proposing (so it sees the primary's block), or a "slot filled" gossip signal, or
   slot-time-aligned proposal windows. Until that lands, RANDAO selection stays observe/off.
   The epoch_checkpoint_mix mechanism + gated wiring + ranking infra are committed.

   **IMPLEMENTED + SOAKED (2026-06-28) — works, but liveness gate NOT yet met.** Built
   `epoch_checkpoint_mix(db, epoch)` + `selection_mix_for_slot(db, slot)` (boundary height via
   binary search on the slot-monotonic chain; unit-tested incl. tip-independence) and re-pointed
   all 3 sites off the slot's epoch. 5-run enforce soak (flag flipped, then reverted): the
   epoch-based design NO LONGER HALTS (vs the height-based trial) — 4/5 runs 16/16 with selection
   converging (16/16 ⇒ no eligibility mismatch) and 1 unique RANDAO mix when block history
   converges. BUT 1/5 dipped to 94% with slow block production (a node reached block 58 vs ~79)
   + elevated "not eligible" rejections: an intermittent LIVENESS degradation under reorg churn
   (a reorg recomputes the eligible proposer → more in-flight competing blocks rejected). Gate =
   ALL ≥6 green → NOT met. Remaining: damp the reorg/eligibility churn (don't re-reject
   already-validated competing blocks on the losing tip, or widen the lookback) so liveness holds
   across the soak, then flip `ENFORCE_RANDAO_SELECTION`. Mechanism + wiring committed (gated off).

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

7. **Exchange ↔ real-balance integration (the actual Phase E gap).**
   **Scoped (investigated June 2026):** EVM gas IS real — py-evm debits gas+value
   from the EVM balance and `ContractStateManager.commit` writes `account_state`.
   The gap is the **exchange**: `_op_open_position` opens a leveraged perp with
   `margin`/`leverage` but never checks or debits the trader's real `account_state`
   balance; `_op_close_position` computes PnL but never credits/debits it; spot
   `place_order` likewise doesn't lock/settle funds. The exchange engine
   (`exchange/state_manager.py`, `perpetual.py`) is a self-contained simulation —
   positions/margin/PnL are internal bookkeeping with NO connection to real
   balances, so trades move no actual value and margin isn't collateralized.

   **Progress — the perp-margin path is BUILT (observe/gated-off), unit-verified.**
   - ✅ (a) balance bridge: `ExchangeStateManager.set/available/clear_available_balance`
     + per-block `_balance_deltas`; `preload_sender_balances` (async, both block
     paths) loads real `account_state` balances before the sync section.
   - ✅ (b) open: `_op_open_position` computes required margin, records a `-margin`
     delta, and (when `enforce_collateral`) rejects under-collateralized opens;
     `db.apply_account_balance_delta` (QRDX→wei) + `flush_exchange_balance_deltas`
     apply the deltas to `account_state` before the unified root is computed.
     All gated by `block_processor.ENFORCE_EXCHANGE_COLLATERAL` (default False).
     Tests: `test_exchange_collateral_observe.py` (8), `test_account_balance_delta.py`
     (3). Integration 12/12 (flag off = behaviour-neutral).
   - ✅ Cross-node determinism of the enforce/flush path is proven
     (`test_exchange_collateral_determinism.py`): two nodes agree on the
     `account_state` debit AND the exchange root; rejection is deterministic.
   - ✅ **Perp reachability prerequisite DONE.** Added `ExchangeOpType.CREATE_MARKET`
     (+ validation, gas, `_op_create_market`, tests) so a perp market can be created
     via the consensus path; markets are in the exchange state root, so it flows
     through the section pipeline. Perps (`OPEN_POSITION`) are now reachable.
   - ✅ s13 perp-collateral integration scenario built + soaked (CREATE_MARKET +
     OPEN_POSITION flow cross-node; convergence-polled; 13/13).
   - 🚩 **CRUX (found flipping enforce in the s13 soak): the debit targeted the
     WRONG ledger.** Exchange txs are PQ-signed → traders are `0xPQ` addresses whose
     genesis funds lived in the **UTXO ledger** (`unspent_outputs`), NOT
     `account_state`. The flush only touched `account_state`, found no row for a PQ
     trader, and debited NOTHING — so `ENFORCE_EXCHANGE_COLLATERAL=True` was a
     deterministic NO-OP for real traders.
   - ✅ **RESOLVED (June 2026) — ledgers UNIFIED.** Genesis now funds `account_state`
     for ALL addresses (PQ + 0x) in `genesis_init._create_genesis_outputs`, reorg-safe
     via `seed_genesis_account_state` re-seed in `rebuild_account_state_from_chain`.
     A PQ trader's collateral now lives in the same ledger the flush debits.
     `ENFORCE_EXCHANGE_COLLATERAL = True`. Verified: trader = 497000 (500000 genesis −
     3000 margin) on ALL 4 node DBs (no divergence), integration 13/13, 0 E-D4
     rejections.
   - ✅ **Consensus-divergence fix (same pass).** The margin flush ran only on the
     proposer + bulk-sync paths; the live-broadcast paths (p2p `submitBlock`, REST
     `submit_block`) called `apply_block_exchange_section` directly, bypassing
     preload+flush → importers never debited → account_state split (proposer 497000,
     others 500000), which E-D4 did not surface. Fixed by routing ALL import paths
     through `_apply_exchange_section_on_import` (injected `exchange_apply_section`
     hook on the p2p module, mirroring `evm_apply_section`; REST calls it directly).
     Every path now preload→apply→flush BEFORE its E-D4 unified root is checked.
   - ✅ **Reorg-safe.** `rebuild_exchange_state_from_chain(flush_to_account_state=True)`
     re-applies each canonical block's collateral debits onto the freshly reseeded
     account_state during a reorg rebuild (clear+reseed genesis FIRST, then exchange
     re-flush on top). Default flag False keeps startup/restart unchanged (durable
     ledger; flushing would double-debit). Verified: reseed → 500000, rebuild → 497000.
   - ✅ **(c) PnL settlement DONE (June 2026).** `_op_close_position` credits
     `max(0, margin + pnl)`; `_op_partial_close` credits `max(0, margin_released +
     pnl)`; liquidation (`check_liquidation` → block-boundary `_check_liquidations`)
     credits `LiquidationResult.margin_returned = max(0, (margin − penalty) + pnl)` to
     the owner — all via the same `_record_balance_delta` → flush path as margin (so
     convergent + reorg-safe). `_settle_close` centralizes the clamp-at-zero rule.
     With default rates (penalty 2.5% == maintenance 2.5%) the liquidation residual is
     always 0; a positive residual needs maintenance > penalty. Also fixed
     `/get_address_info` to report `get_address_balance` (account_state-first) — s13
     now shows the trader 500000 → 497000 (−3000 margin) live. Tests:
     `test_exchange_collateral_observe.py` (+5 close), `test_exchange_liquidation_settlement.py`
     (4); exchange suite 500 passed, integration 13/13.
   - 🔱 **(d) SPOT — consensus token subsystem IN PROGRESS (June 2026).** Spot needs
     real TOKEN balances, but tokens were ENTIRELY off-consensus (no node-side
     handling, not in any root; the harness wrote `token_balances` directly to ONE
     node's DB). So the token ledger is being made a consensus object first:
     - ✅ inc1 token-balance bridge in `ExchangeStateManager` (mirror of the QRDX
       collateral bridge: `_token_balance_deltas`, `_token_registry_ops`,
       `enforce_spot_settlement`).
     - ✅ inc2 DB layer: `token_registry`+`token_balances` in node `_init_schema`;
       `apply_token_balance_delta`, `get_token_balances_root` (BLAKE3-512),
       `clear_token_balances`, `apply_token_registry_op`.
     - ✅ inc3 `unified_state_root()` gained a 4th TOKEN domain — BOUND AT ZERO for
       now (binding the real per-node root while the harness writes tokens to one
       node diverges → E-D4 stall; ordering fix).
     - ✅ inc4 consensus ops `TOKEN_DEPLOY`/`TOKEN_TRANSFER` (deterministic address
       `blake2b(sender:nonce:symbol)`, mint/registry/transfer deltas, observe/enforce
       overspend) + `flush_token_balance_deltas` wired into proposer + bulk-sync +
       both live importer branches + reorg rebuild. **Proven live (s14): importer
       nodes 1–3 hold the identical consensus-replicated ledger (deployer 999000 +
       recipient 1000) with matching token roots.** Tests: `test_token_ledger_db.py`
       (7), `test_token_consensus_ops.py` (7), s14 (8); suite 14/14.
     - ✅ inc4b: s05/s06 are qRC-20/AMM **library** tests that wrote token_balances
       out-of-band to node0 (polluting its root). Redirected both to a standalone
       `token_lib.db`; node DBs now carry only consensus token state (all 4 nodes 1
       identical token root).
     - ✅ inc3-final: proposer + importer (E-D4 **enforced**) + REST now bind the REAL
       `get_token_balances_root`. The token ledger is cryptographically committed and
       enforced in every block. Verified: 14/14, after s14 all 4 nodes 1 unique token
       root, 0 E-D4 mismatches. **→ token state is a real, enforced, convergent 4th
       consensus domain.**
     - ✅ inc5: spot AMM settlement. `pool_holder_address` = deterministic token-ledger
       holder of pool reserves; `_op_add_liquidity` escrows token0/token1 (V3 amount
       formula) LP→pool, `_op_remove_liquidity` pool→LP, `_op_swap` trader↔pool (pool
       resolved by token pair). New s15: deploy 2 tokens → pool over addresses → add
       liquidity → swap. Verified: conservation (each token = its 1,000,000 supply),
       pool holds real escrowed reserves.
     - ✅ inc6: `ENFORCE_SPOT_SETTLEMENT=True`. `preload_token_balances` feeds the
       sufficiency checks on every path; add_liquidity gained an LP-sufficiency check.
       Verified: suite 15/15 enforced, all 4 nodes 1 unique token root, every token
       conserves. **→ spot settlement is real, enforced, convergent.**

   **✅ PHASE E — primary venues COMPLETE.** The economic operations that move value
   through the primary venues are real, consensus-tracked, enforced, convergent and
   reorg-safe: EVM gas (py-evm), perp margin + PnL + **ADD_MARGIN** (account_state), and
   spot deploy/transfer/**AMM** swap/liquidity (the QRC-20 token ledger — an enforced 4th
   unified-state-root domain). Reorg-safety of 0x genesis funding was fixed (the EVM
   balance-sync registry is now reset on rebuild) and is continuously checked by
   `scripts/phase_e_invariants.py`.

   **Economic-settlement gaps:**
   - ✅ **CLOB order-book — DONE + ENFORCED (2026-08-04, commit 90e04f5).**
     `_op_place_order` escrows the order's funds into a deterministic per-book escrow
     holder (`orderbook_escrow_address`), matched trades settle maker↔taker via that
     escrow, and `_op_cancel_order` refunds exactly. `ENFORCE_ORDERBOOK_SETTLEMENT=True`.
     Two fixes were needed to converge: (1) `_op_place_order`/`_op_cancel_order` must
     canonicalize the pair the way `create_pool` does (it SORTS `token0:token1`), or the
     book lookup misses → the op silently fails → no escrow (added
     `_canonical_pair()`); (2) the reorg rebuild must re-enable
     `enforce_orderbook_settlement` — unlike spot (whose token moves are unconditional;
     the flag only gates a sufficiency CHECK) the CLOB escrow MOVE itself is behind the
     flag, so a reorg-rebuilt node dropped every resting order's escrow. Validated: suite
     17/17 under heavy reorg (17-41/node), 0 FATAL, token conservation holds on all nodes
     incl. qCLOB* (200 escrowed on place → 0 on cancel), account_state converges, E-D4=0;
     a 25-reorg node correctly RECONSTRUCTED the escrow. Follow-up: CLOB *match*
     settlement across two wallets (self-trade prevention makes single-wallet match a
     no-op) has no live scenario yet.
   - 🔱 **`_op_create_pool` stake/burn — BUILT (observe-only, gated off), enforce
     validated once; needs a soak before the flip (2026-08-04).** `create_pool` validated
     `stake_amount >= the per-type minimum` but never DEBITED it, so pool creation was
     free. Added the debit mirroring the perp-margin path: the declared stake is checked
     against the creator's pre-loaded available balance and recorded as a `-stake`
     account_state delta (flushed by the same path as margin), held in
     `pool.state.stake_amount` for a future remove-pool return (staking pools) / forfeit
     (subsidized = burn). Gated by `ENFORCE_POOL_STAKE` (default False) — a SEPARATE gate
     because the shared account_state flush is already enforced for collateral, so the
     DELTA RECORDING itself (not just the flush) must be gated or the stake would debit as
     soon as collateral is. Set on the proposer + importer + reorg-rebuild paths. Tests:
     `test_pool_stake_settlement.py` (7). Enforce validation (1 run, flag flipped then
     reverted): suite 17/17 under heavy reorg (9-44/node), 0 FATAL, 0 spurious rejects,
     and the 10000 stake debit was DETERMINISTIC + CONVERGENT on every caught-up node
     (node0/1/3 all exactly 990000 despite 44/9/27 reorgs — so the debit is reorg-safe,
     reconstructed correctly by the wired rebuild). The one residual was a node trailing 2
     blocks whose derived-state lagged its own stored tip at shutdown (the known
     "balance is a function of height" artifact, cf. item 2 / the S10 fix) — not a
     pool-stake defect, but the suite shut down before it caught up so post-catch-up
     convergence was not observed.
     **6-run soak (2026-08-04, ENFORCE_POOL_STAKE=True, height-gated checker that compares
     only nodes AT the max tip): gate NOT met → kept OFF.** All 6 runs were 17/17 with 0
     spurious pool-stake rejects, and 5/6 had the caught-up set fully converge (account_state
     + token ledger). But run 3 diverged with ALL 4 nodes caught up at the same tip (128,
     no trailing): 1 account_state address AND the TOKEN ROOTS differed. Since pool-stake
     never moves token balances, the token-root divergence proves this is NOT a pool-stake
     defect — it is the pre-existing reorg-derived-state divergence (equal-tip, E-D4=0
     signature; cf. [[phase-e-perp-margin-reorg-divergence]] / item 4-class) resurfacing
     under heavy reorg (~1/6 ≈ 17%, in line with the documented ~30-40% intermittent). Run 4
     also logged a (recovered, non-terminal) FATAL. **Conclusion: the pool-stake debit is
     correct (deterministic, reorg-safe, converges whenever the reorg machinery does), but
     the enforce flip is GATED on resolving the recurring reorg-derived-state divergence —
     which gates every account_state-affecting enforce, not just this one.** Flip
     `ENFORCE_POOL_STAKE` once that divergence is fixed AND a clean multi-run soak passes;
     a REMOVE_POOL return path (staking pools) / burn (subsidized) is the natural companion.

   Then the process gates below.

## 🔒 Process gates (cannot be satisfied in-repo)

8. **External security audit** of the consensus + crypto + exchange paths.
9. **≥30-day multi-validator soak** (the `QRDX_IMPLEMENTATION_CHECKLIST` "Production
   Ready" gate). The mini-soaks here (3 runs) are smoke-level, not the real gate.

## Suggested next order

Item 2 (import perf / S10) is the most concrete and de-risks the green signal
everything else relies on. Item 3 (finality) unlocks items 1 and 4 and is the
highest-leverage consensus piece. Item 7 (balance unification) is the largest and
gates real economic use.
