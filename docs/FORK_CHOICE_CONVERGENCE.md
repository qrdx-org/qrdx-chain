# Fork-Choice Convergence — Design

> **Status:** design (June 2026). Prereq for enforcing parent-hash continuity and
> for binding RANDAO into proposer selection. Consensus-critical — roll out
> observe → soak → enforce, the same discipline that caught the naive-enforce
> failure documented below.
> **Companion:** `CONSENSUS_REMAINING_WORK.md` items 3 (finality) & 5 (RANDAO);
> memory `block-history-fork-vs-state-convergence`.

## Update (2026-06-15): the primary reliability cause was a reorg bug, now fixed

Characterizing the intermittent failures (below) first surfaced a **separate,
dominant bug**: `rebuild_account_state_from_chain` raised `name 'logger' is not
defined` (an undefined module logger in `evm_block_apply.py`, from a Phase E
genesis-reseed addition), so **every reorg aborted mid-rebuild and the diverged node
never healed**. That — not the fork-choice gaps below — caused most of the
fork-correlated flakiness (~⅓ of runs failing 12/13 with height spread 2-4). Fixed by
defining the logger; the post-fix soak went to **10/11 runs passing** (height spread
≤1, 0 reorg errors) — a major reliability gain. The fork-choice work below remains
for the *rare* residual (~1/11): an equal-height equivalent fork where both chains are
the same length so the longest-chain reorg never fires — visible through the
RANDAO-mix probe, and the gate for RANDAO-driven selection.

## The problem

Two valid blocks can exist at the **same height** when proposers at adjacent slots
both build on the same parent during a propagation race (block-time ≈
propagation-time). The chain's **cumulative state root converges** (state is replayed
from sections), but the **block history diverges** per node, and nothing reconciles
it. Concretely, from a clean 4-node run:

| height | nodes 0/2/3 | node 1 |
|--------|-------------|--------|
| 1 | `ea0377` slot 4 | `ea0377` slot 4 |
| 2 | `9cb28d` **slot 6** | `d8207a` **slot 5** |
| 3 | `a0c1f7` slot 7, parent **`d8207a`** | `a0c1f7` slot 7, parent `d8207a` |

Height 3 (canonical, on all nodes) builds on `d8207a` (slot 5) — yet nodes 0/2/3
still store `9cb28d` (slot 6) at height 2, and **never stored `d8207a` at all**.
Their parent linkage is broken: `block(3).parent_hash != block(2).hash`.

### Two root causes in the acceptance path

1. **No parent-hash continuity check.** Import validates only that heights are
   sequential (`block_no == next_block_id`), never that `block.parent_hash ==
   local_tip.hash`. So a block on a different fork is appended, and the node ends up
   at the *same height* as canonical → the longest-chain sync never sees it as
   "behind" → the broken linkage persists forever. (Observe check
   `_check_parent_continuity` now detects this; it fired on exactly nodes 0/2/3.)

2. **No equal-height tie-break.** A competing block at an *already-filled* height
   (`block_no < next_block_id`) is rejected as "Block height mismatch"
   (`p2p.submitBlock`). First-come-first-served per node, so different nodes keep
   different blocks at the contested height with no rule to converge.

### Why naive enforce failed (the soak that motivated this doc)

Flipping `_ENFORCE_PARENT_CONTINUITY=True` (reject a mismatched-parent block, rely
on the *periodic* sync/reorg poll to heal) over a 6-run soak:
- **run5**: 2 rejections fired, yet still ended with 2 RANDAO mixes at equal height
  — reject alone can't converge an *equal-height* fork (mechanism 2 missing).
- **run6**: a node fell 3 blocks behind and a scenario failed — the periodic poll
  healed too slowly (mechanism for *prompt* reorg missing).

So a safe fix needs BOTH mechanisms below, and they must act promptly, not on a poll.

## Design

### Deterministic canonical-block rule (per height)

When two valid, proposer-eligible blocks share a height + parent, every node must
pick the SAME one. Options:

- **Lowest block hash** — unbiasable, no proposer can grind toward winning, and it
  is independent of slot timing. **Recommended.**
- *Earliest slot* — matches the observed canonical outcome (slot 5 beat slot 6) and
  is intuitive, but a proposer can influence it (propose earlier), and it interacts
  with eligibility. Use only if a slot-anchored rule is needed elsewhere.

Pick lowest-hash. It is a pure function of the blocks, so all nodes agree.

### Mechanism 1 — parent-continuity + active reorg (block at the next height)

On import of a block at `next_block_id` whose `parent_hash != local_tip.hash`:
1. Do NOT append (it would break linkage).
2. **Immediately** attempt a reorg onto the declared-parent chain — call the reorg
   path inline (fetch the sender/peer's chain, find the common ancestor, roll back,
   re-sync) rather than waiting for the periodic sync loop. This fixes run6.
3. If the declared-parent chain is not better under the canonical rule, reject and
   stay put (the local chain wins; the peer will reorg to us).

### Mechanism 2 — equal-height replacement (block at a filled height)

On import of a valid, eligible block at an *already-filled* height H (currently a
hard "height mismatch" reject): if it shares the parent of the stored block at H and
**wins the canonical rule** (lower hash), reorg from H: roll back to H-1, adopt the
new block at H, re-sync forward. Otherwise drop it (we already hold the winner).
This fixes run5 by converging the contested height deterministically.

### Storage note

`blocks.block_height` is UNIQUE, so only one block per height is stored — a
replacement is an UPDATE/rollback, not a second row. The competing block need not be
persisted as an orphan; the canonical rule is evaluated on arrival. (A future
fork-aware store could retain orphans for faster re-org, but is not required.)

## Rollout (observe → soak → enforce)

1. **Observe (partly done):** `_check_parent_continuity` logs mechanism-1
   mismatches. Add an analogous observe log in `submitBlock` for mechanism-2
   (competing block at a filled height + who would win the canonical rule). Measure
   frequency + that the canonical rule is consistent across nodes.
2. **Enforce mechanism 1** (active reorg) first; soak ≥6 runs. Success: 0 stalls
   (height spread 0), 0 broken parent links, no node falls behind.
3. **Enforce mechanism 2** (equal-height replacement); soak. Success: 1 unique
   RANDAO mix across all nodes (block history fully converged) across ≥6 runs.
4. **Then** bind RANDAO into selection: switch `block_verification`'s verifier AND
   the proposer onto the live `compute_randao_mix` together (item 5).

## Success criteria (the convergence proof)

Across ≥6 clean `--force` runs with both mechanisms enforced:
- integration suite green every run,
- `Final height spread == 0` (no stalls / falls-behind),
- 0 broken parent links on any node (`get_block_by_id(h).hash == block(h+1).parent_hash`),
- **1 unique `compute_randao_mix` across all 4 nodes** — block history converged.

The RANDAO mix is the sharpest convergence probe: it folds *every* block's reveal,
so it only agrees network-wide when block history is identical at every height.
