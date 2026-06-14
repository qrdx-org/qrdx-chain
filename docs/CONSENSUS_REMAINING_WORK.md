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
   equal-height equivalent forks** — the real fork-choice work. Until then keep
   observe; RANDAO selection stays on the zero constant (this is its gate).

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

   **✅ PHASE E COMPLETE.** Every economic operation now moves real, consensus-tracked
   value: EVM gas (py-evm), perp margin + PnL (account_state — enforced, convergent,
   reorg-safe), and spot deploy/transfer/swap/liquidity (the QRC-20 token ledger — an
   enforced 4th unified-state-root domain). Only the process gates below remain.

## 🔒 Process gates (cannot be satisfied in-repo)

8. **External security audit** of the consensus + crypto + exchange paths.
9. **≥30-day multi-validator soak** (the `QRDX_IMPLEMENTATION_CHECKLIST` "Production
   Ready" gate). The mini-soaks here (3 runs) are smoke-level, not the real gate.

## Suggested next order

Item 2 (import perf / S10) is the most concrete and de-risks the green signal
everything else relies on. Item 3 (finality) unlocks items 1 and 4 and is the
highest-leverage consensus piece. Item 7 (balance unification) is the largest and
gates real economic use.
