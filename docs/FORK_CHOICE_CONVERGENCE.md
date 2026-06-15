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
≤1, 0 reorg errors) — a major reliability gain. A follow-up 8-run diagnostic was even
cleaner: **0 broken parent links in all 8 runs**, and the two runs that *did* fork
(6 parent-continuity observe hits each) HEALED to zero broken links — i.e. import-path
forks now reconcile via the working reorg. So the residual below is **rarer than
1/11** and the practical reliability is high.

The fork-choice work below is therefore **low-urgency hardening**, needed mainly as the
**gate for RANDAO-driven proposer selection** (which folds every block's reveal and so
requires perfect block-history convergence): an equal-height equivalent fork where both
chains are the same length so the longest-chain reorg never fires.

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

### Re-soak finding (2026-06-15): mechanism-1 enforce is safe but insufficient

After the logger fix, `_ENFORCE_PARENT_CONTINUITY=True` was re-soaked: **6/6 runs
pass** (one fired 15 parent-rejections and still fully converged), so rejecting a
fork block heals cleanly once reorgs complete — the earlier "unsafe" verdict was the
reorg bug, not the reject. **But it does not fully converge block history**: a
genesis-era equal-height fork still persisted (a node held block1 from one fork +
block2 from another → 1 broken link, 2 RANDAO mixes) on a node with **no reorg in its
log** — so the fork block reached it via a path the import parent-check does NOT cover
(genesis bootstrap and/or proposer self-build). Implications for the plan below:
mechanism-1 must also (a) cover those paths, and (b) be paired with mechanism-2; only
then enforce.

### Mechanism 1 — parent-continuity + active reorg (block at the next height)

On import of a block at `next_block_id` whose `parent_hash != local_tip.hash`:
1. Do NOT append (it would break linkage).
2. **Immediately** attempt a reorg onto the declared-parent chain — call the reorg
   path inline (fetch the sender/peer's chain, find the common ancestor, roll back,
   re-sync) rather than waiting for the periodic sync loop. This fixes run6.
3. If the declared-parent chain is not better under the canonical rule, reject and
   stay put (the local chain wins; the peer will reorg to us).

### Mechanism 2 — confirmed firing (2026-06-15)

A 4-run measurement counting both observe types: run1 logged **10 equal-height
`fork-choice observe` hits** (+ 8 mechanism-1), the others 0 (no fork). So equal-height
competing blocks genuinely reach nodes (~1/4 runs forky), and mechanism-2 is real, not
hypothetical. Crucially every run still passed 15/15 — so mechanism-2 is NOT needed for
height/state convergence (mechanism-1 + the working reorg handle that), only for
**perfect block-history convergence**, i.e. the RANDAO-selection gate. This sets its
priority: implement when RANDAO selection is wanted, not for general reliability.

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

## Mechanism-2 enforce — ready-to-execute implementation spec

The full trace is done; an implementer can follow this directly.

**Reuse the rollback+rebuild sequence** at `main.handle_reorganization`
(main.py ≈ L2592–2634): `db.remove_blocks(N+1)` → `rebuild_account_state_from_chain`
(or clear+`seed_genesis_account_state` when EVM disabled) → `db.clear_token_balances`
→ `rebuild_exchange_state_from_chain(db, flush_to_account_state=True)`. Extract these
~40 lines into `async def _rebuild_derived_state_after_rollback()` and call it from
BOTH `handle_reorganization` and the new path (refactor carefully — this is the
just-fixed reorg path; keep behaviour identical, re-soak after extracting).

**New gated hook** in main.py:
```
_ENFORCE_EQUAL_HEIGHT_TIEBREAK = False   # observe→soak→enforce, like the others

async def _adopt_equal_height_winner(block_no, block_data) -> bool:
    if not _ENFORCE_EQUAL_HEIGHT_TIEBREAK:
        return False
    await db.remove_blocks(block_no)                 # drop the losing tip block
    await _rebuild_derived_state_after_rollback()    # roll state back to block_no-1
    return await process_and_create_block(_to_block_info(block_data))  # import winner
```
Adapt `block_data` (p2p submitBlock shape) to the `block_info` dict
`process_and_create_block` expects (see its callers). The winner shares parent H-1
with the loser, so no chain fetch is needed — it imports cleanly on the rebuilt tip.

**Wire** into `p2p.submitBlock._observe_equal_height_fork`: when `incoming_wins` and
the flag is on, call the injected hook (mirror `check_parent_continuity` injection)
instead of just logging; on success the "too old" return becomes an adoption.

**Lowest-hash rule** is already implemented in `_observe_equal_height_fork`
(`incoming_hash < stored_hash`) and is the deterministic canonical choice.

**Soak gate before enabling:** flip the flag, run ≥6–8 `--force` rounds, require
every round: suite green, `Final height spread == 0`, 0 broken parent links, and the
decisive probe — **1 unique `compute_randao_mix` across all 4 nodes**. Only then leave
the flag True. (Beware: the equal-height fork also reaches nodes via genesis bootstrap
/ proposer self-build — paths the import hook doesn't cover — so confirm the RANDAO
mix actually converges, not just that the suite passes.)

## Success criteria (the convergence proof)

Across ≥6 clean `--force` runs with both mechanisms enforced:
- integration suite green every run,
- `Final height spread == 0` (no stalls / falls-behind),
- 0 broken parent links on any node (`get_block_by_id(h).hash == block(h+1).parent_hash`),
- **1 unique `compute_randao_mix` across all 4 nodes** — block history converged.

The RANDAO mix is the sharpest convergence probe: it folds *every* block's reveal,
so it only agrees network-wide when block history is identical at every height.
