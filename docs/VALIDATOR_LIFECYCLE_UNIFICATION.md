# Validator Lifecycle Unification — Design

> **Status:** design (June 2026). `CONSENSUS_REMAINING_WORK.md` item 4. Makes the
> consensus validator set a runtime-converged function of the chain (activations,
> exits, stake updates) instead of the static genesis set — the prerequisite for
> dynamic validator membership.
> **Consensus-critical:** proposer selection + slot eligibility are ENFORCED off the
> `validators` table, so a validator set that diverges across nodes HALTS the
> diverging node. Roll out observe → soak → enforce, with the decisive probe being
> *the `validators` table is byte-identical on every node after each epoch*.

## Current state — three gaps

1. **Two epoch processors, only the wrong one is wired.**
   - `validator/epoch_processing.py` computes rewards/penalties/activations/exits and
     writes them INTO the consensus `validators` table (effective_stake, status,
     activation/exit epoch — L545–578). This is the consensus-aware processor — but
     its SQL is **PostgreSQL-only** (`$1/$3`, `NOW()`, `GREATEST/LEAST`,
     `pool.acquire()`), so it raises on the SQLite testnet, and it is **not called**
     by the running node.
   - `validator/lifecycle.py` `ValidatorLifecycleManager.process_epoch` IS wired
     (`node_integration._epoch_processing_loop`, every epoch boundary) and IS
     SQLite-compatible — but it reads/writes separate `lifecycle_validators /
     lifecycle_deposits / lifecycle_exits / lifecycle_withdrawals` tables + in-memory
     state, and **never touches the `validators` table consensus reads**.
   - Net: the wired processor doesn't reach consensus; the consensus-aware processor
     doesn't run. The active set stays at genesis.

2. **No staking-transaction entry.** There is no tx type / endpoint to deposit stake
   (join) or signal a voluntary exit on the testnet. Validators only ever enter via
   `genesis_init` / `manager.register_validator`. So even with a working processor,
   the set can't grow or shrink from real activity.

3. **Schema gaps.** `epoch_processing.py` references `validators.total_slashed` /
   `total_rewards`; the SQLite `validators` schema has neither (only `slashed BOOL`).

## Consensus source of truth (keep it)

The `validators` table already feeds everything consensus-critical:
`db.get_validators()` → `block_verification.expected_proposer_for_slot` (proposer
selection + eligibility) and `finality` (stake weights). **Keep `validators` as the
single canonical source.** Unification = make ONE deterministic epoch processor write
the lifecycle results into it; retire or subordinate the parallel `lifecycle_*` model.

## Determinism requirement (the safety crux)

Epoch processing MUST be a pure deterministic function of the canonical chain so the
`validators` table converges byte-identically on every node — same property as the
unified state root / RANDAO mix. Inputs are already on-chain: attestations (in block
bodies → `attestation_votes`) drive rewards/penalties; deposits/exits will ride in
blocks as txs. No wall-clock, no per-node ordering. (This is why `NOW()` must go and
why the processing runs at a deterministic epoch boundary, not on a timer that could
fire at different chain states per node.)

## Plan (phased, observe → soak → enforce)

**Phase 0 — schema.** Add `total_slashed`, `total_rewards` (and any other columns the
processor needs) to the `validators` table, default 0. Pure additive migration.

**Phase 1 — one SQLite, consensus-aware processor (OBSERVE).** Port
`epoch_processing.py`'s validator-update SQL to SQLite (`?` params, `MIN/MAX` for
`LEAST/GREATEST`, drop `NOW()` → a deterministic constant, single-connection no
`pool.acquire`). Run it in OBSERVE: compute the would-be `validators` updates and LOG
them (per node) WITHOUT applying. Confirm every node computes the *same* deltas at the
same epoch (determinism) before any write. Retire the unwired duplication or make
`lifecycle.py.process_epoch` delegate to this single processor.

**Phase 2 — apply + soak convergence.** Wire `node_integration._epoch_processing_loop`
to the ported processor; let it WRITE the `validators` table at each epoch boundary.
Soak ≥6–8 runs; the decisive probe each run: **hash of the `validators` table is
identical across all 4 nodes after every processed epoch** (and proposer selection /
eligibility never halt a node). Reuse the genesis validator set + rewards/penalties of
existing validators (no new joiners yet) so this phase isolates *processor
convergence* from *membership change*.

**Phase 3 — staking-tx entry.** Add a consensus deposit / voluntary-exit op (mirror
the Phase E exchange-op or a native tx type): a deposit creates a `pending` validator
row + enqueues activation; an exit enqueues exit. Replayed on every node (deterministic
address/stake), so the set change is consensus. Observe → enforce.

**Phase 4 — ENFORCE dynamic membership.** With the set converging and staking txs
flowing, the dynamic `validators` set fully drives proposer selection + eligibility +
finality weights. Verify a deposited validator activates and proposes; an exited one
stops; slashing reduces stake; integration green.

## Implementation log (June 2026)

- **Phase 0/1a/1b done + committed:** schema columns; `db.apply_epoch_validator_updates`
  (SQLite persistence port) + `db.get_validators_table_hash`; `epoch_rewards.compute_epoch_reward_deltas`
  (deterministic, sqrt-free); wired into the epoch loop (observe).
- **Root-cause fix:** the epoch loop imported `ValidatorLifecycleManager` (nonexistent —
  it's `LifecycleManager`); the ImportError silently crashed the loop, so epoch processing
  had NEVER run — the actual reason the set was frozen at genesis. Fixed + made the
  boundary detection robust (process completed epochs, not `slot % N == 0`).
- **Phase 2a/2b:** `SLOTS_PER_EPOCH` env-overridable so epochs fire often in a test run.
  A multi-epoch observe soak showed the deltas DIVERGED across nodes for just-completed
  epochs (still-propagating attestations → different attester sets). Fixed by **gating on
  the FINALIZED epoch** (drain up to `finalized_epoch`): finalized epochs have converged
  attestations, so all nodes compute identical deltas. Verified: epochs 0–4 identical
  rewarded/penalized on all validators.
- **Phase 2c (enforce soak):** 15/15, 0 eligibility halts; the 3 VALIDATORS produced a
  byte-identical validators table (perfect deterministic convergence). **GAP: the full
  node stays at genesis** — the epoch loop is a `ValidatorNode`-only task, so non-validator
  nodes never process epochs. A full node verifies proposer eligibility off its frozen
  table, so once stake changes enough to alter stake-weighted selection it would reject
  validator blocks. → **Phase 2d (DONE):** extracted the finality-gated update into
  `validator/epoch_loop.py` `epoch_validator_update_loop`, started in `node.main` for
  EVERY node (the loop needs only `db` — no validator context); removed the duplicate
  call from the `ValidatorNode` loop. Now all 4 nodes (incl. the full node) process the
  same finalized epochs. Enforce soak (3 runs): 15/15, 0 eligibility halts; 2/3 runs
  PERFECT 4/4 convergence (1 unique validators-table hash across all nodes), 1/3 showed
  3 distinct hashes with 0 halts — a benign EVENTUAL-CONSISTENCY snapshot artifact
  (nodes mid-drain to the common finalized epoch at the snapshot moment → different
  *count* of epochs applied, not different processing; the per-epoch deltas are
  deterministic, so they reconverge as the lagging node catches up). Enabled
  (`epoch_loop._ENFORCE_EPOCH_VALIDATOR_UPDATES=True`).

  **Future hardening (stronger than eventual consistency):** apply the epoch update
  during BLOCK IMPORT at the boundary block (so every node mutates the `validators`
  table at the exact same chain event, eliminating the wall-clock drain window). Needed
  before large stake moves (big deposits / slashing) where a transient stake gap could
  flip stake-weighted selection. With the current tiny rewards it never flips (0 halts).

## Success criteria

- `validators` table **byte-identical across all nodes** after each epoch (a
  per-epoch table hash, like the RANDAO-mix probe) across ≥6–8 `--force` runs.
- Integration suite green every run; **0 proposer-eligibility halts** (the failure
  mode of a divergent set).
- A staking deposit → the validator activates after the delay and is selected to
  propose; a voluntary exit → it stops being selected; both converge on all nodes.
- Rewards/penalties move `effective_stake` deterministically and identically per node.

## Prerequisites already in place

The earlier consensus-hardening arc makes this safe to attempt: validator-set
convergence + the Dilithium key-identity fix (set built from the consistent
`validators` table, order-independent selection, reorgs ~0), enforced proposer
auth + slot eligibility, and finality (justified/finalized from on-chain
attestations) — so the inputs this processor needs are already deterministic and
converged.
