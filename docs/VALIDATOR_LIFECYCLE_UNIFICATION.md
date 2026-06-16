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
