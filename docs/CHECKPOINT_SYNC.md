# Checkpoint sync and history pruning

**Status (2026-10-28): built, verified live (below).**

A new node can join from a snapshot of another node's database without replaying from genesis.
It trusts nothing in the snapshot that it has not checked against a signed state root. A full
node can drop most of history behind finality.

Four pieces:

1. The validators' state is in the signed root (chain-spec feature `validator_state_root`).
2. Snapshots: `scripts/node/snapshot.py create | fetch | restore`.
3. Nodes publishing them: `QRDX_SNAPSHOT_DIR`.
4. History pruning: `QRDX_HISTORY_RETENTION_BLOCKS`.

## Why

At 250 ms slots the chain adds about 345,600 blocks a day. A node joining replays every one of
them, executing every section. Within months a validator that loses its disk cannot catch up in
useful time. And every block body keeps its proposer's 3.3 KB ML-DSA-65 signature, about 1.1 GB
a day, plus the signature and key of every transaction in its sections.

## 1. The validators' state in the root

### What was missing

Validator stakes, the delegation pools, the payouts owed and the withdrawals paid are consensus
state: proposer eligibility, finality's weights and block withdrawals follow them. Before this
feature no block's signed root committed to them. Consensus was safe, since every import
re-checked eligibility against the node's own derived state, but a snapshot's copy could not be
verified.

### The audit, and what it changed

The design listed 14 uncovered tables. Tracing who reads and writes each one showed that
consensus depends on much less:

| Table | What it is | Treatment |
|---|---|---|
| `validator_deposits`, `validator_exits`, `staking_ops`, `staker_fee_income`, `validator_withdrawals`, `staking_payouts` | Logs block application writes, one row per executed operation, reversed on rollback | **Committed**: a hash chain over their rows (below) |
| `validator_epoch_states` | A cache of `S_E`, the validator set of epoch E, written lazily (its rows differ between nodes) | **Committed** through `S_E` itself, which has a canonical hash |
| `validators` | The display copy for the RPC and the explorer; consensus never reads it | Rebuilt |
| `epochs` | The display copy of finality | Rebuilt |
| `system_wallets` | Written by genesis, never after | Taken from the node's own genesis |
| `validator_stakes`, `validator_states`, `stake_deposits`, `stake_withdrawals` | Legacy, unused by consensus | Ignored |

A table cannot be hashed as it is stored. Row ids are each node's own AUTOINCREMENT counter,
and some columns are a clock (`created_at`). So the commitment covers only the columns every
node writes identically.

### The commitment

A block at height h, in epoch E:

```
validator_root = BLAKE3-512("qrdx-validators|" · state_hash(S_E on its parent's chain) · "|" · log_root(h))
log_root(h)    = log_root(h−1)                                         if block h logged nothing
               = BLAKE3-256("qrdx-validator-logs" · log_root(h−1) · h · its rows)  otherwise
```

`validator_root` becomes a sixth input of the unified state root, after the proof root.

* **`S_E`**:
  * covers every validator's stake, effective stake and status, the pools, and the payouts not
    yet paid;
  * is computed by every path that judges the block's proposer;
  * has its hash memoized on the state, so the cost is one hash per epoch.
* **The log root**:
  * is a hash chain, not a set hash, because the transition depends on the order of a block's
    rows (a delegation and its undelegation in one block);
  * numbers are normalized ("1E+3" and "1000.0" hash alike);
  * the root of the parent is memoized per (height, block hash) and stored every 256 blocks for
    restarts;
  * an entry counts only while its hash is still the canonical block at that height.
* **State proofs and the `0x…0300` precompile** carry the validator root as one more part. For
  a block under the feature, the precompile's input has a 64-byte validator root after the token
  root.

Code: `qrdx/validator/validator_root.py`. Tests: `tests/test_validator_root.py`. The feature is
in `GENESIS_DEFAULT_FEATURES`, so new networks have it from genesis. An existing network
schedules it as a fork, approved by governance like any other.

## 2. Snapshots

```
python scripts/node/snapshot.py create --db /data/qrdx.db --out snapshot-2026-10-28/
python scripts/node/snapshot.py fetch --url https://snapshots.example/qrdx/ --out snapshot-2026-10-28/
python scripts/node/snapshot.py restore --snapshot snapshot-2026-10-28/ --db /new/qrdx.db \
    --checkpoint 2048123:9f2c…
```

**`create`**:

* takes SQLite's online backup of a node's database, running or not, plus a manifest with a
  checksum;
* needs a persisted exchange checkpoint, which a node writes every 1,024 finalized blocks.

**`fetch`** downloads a published snapshot directory from any HTTP server, resuming a cut
download. The checksum catches a broken transfer early; it vouches for nothing.

**`restore`** runs with the node's own environment (`QRDX_GENESIS_FILE`). It writes nothing
unless every step holds:

1. **Genesis.** The node builds its network's genesis in a scratch database from its genesis
   file. The snapshot's block 0 must be that block. What genesis writes is taken from the
   scratch database:
   * the system wallets;
   * block 0's records (allocations, system wallets, predeployed contracts), which every later
     rebuild seeds the state from;
   * the chain metadata, so the server's recorded finality and forks are not kept.
2. **History.** A trusted checkpoint at or above the snapshot's exchange checkpoint must be on
   its chain. It comes from `--checkpoint`, the chain spec or `QRDX_TRUSTED_CHECKPOINT`.
   Every block from 1 to that checkpoint must:
   * hash to its signed header;
   * link to its parent;
   * carry the body its `body_root` signs.

   A pruned block is accepted only below the last few epochs before the exchange checkpoint,
   whose votes the next validator-set transitions read. Hashing only: nothing is executed.
3. **State at the exchange checkpoint, block C.**
   * Step the database back from the snapshot's tip to C through its undo journal.
   * Remove the blocks above C.
   * Load the exchange state with a restricted unpickler (below).
   * Check every exchange commitment against its entries from scratch.
   * Recompute every root from the rows: the LtHash accumulators, the state-proof tree, the
     exchange tree, and the validator root, with stored log roots discarded.
   * The unified root must equal the one block C signs.

   Every cache a root could be read from is discarded first, so rows and commitments cannot
   disagree. Of the validator states the snapshot stored, only the verified `S_E` is kept.

   Then every contract's code must hash to the key it is stored under. The root commits to each
   account's code hash, not to the code table. A server could otherwise put other code under a
   contract's hash: the node would follow the chain until that contract ran, and answer
   `eth_call` with the substitute meanwhile.
4. **The node's database.**
   * The chain index is rebuilt from the verified blocks.
   * Node-local tables start empty: peers, pending transactions, transaction and trading
     history, receipts.
   * The undo journal starts at C, and the exchange checkpoint is re-persisted by this node.
   * C becomes a reorg floor (`checkpoints.reorg_floor`).

The node then starts as usual. Its startup takes the checkpoint fast path at C, and it syncs
the blocks above C from its peers, verifying them as any import.

**The exchange checkpoint is not unpickled as such.** The node persists it with pickle, which
can run code named in the data. A snapshot's copy is read by an unpickler that resolves only:

* the classes, and the `_encode_*` / `_rebuild_*` functions, defined in the exchange's data
  modules, with `ExchangeStateManager` excluded;
* a few standard containers.

Anything else refuses the snapshot before any of it is loaded: `os.system`, `builtins.eval`, a
dotted path, an imported name, a function. A state that unpickles is then checked against the
signed root like the rest.

**What a snapshot cannot prove, it cannot use to deceive.**

* A field the root does not cover (a display counter, a cache) that a server altered makes the
  restored node compute different roots for the next blocks: it stops following the chain
  rather than follow a wrong one.
* In a pruned snapshot, the votes and slashing evidence of pruned blocks are not vouched for.
  They feed only epochs already finalized, and any effect on the validator set shows in the
  `S_E` hash the restore checks.

Code: `qrdx/snapshot.py`. Tests: `tests/test_snapshot.py`.

### Publishing

A node started with `QRDX_SNAPSHOT_DIR` publishes snapshots of its own database:

* **When:** each time it persists a newer exchange checkpoint (every 1,024 finalized blocks). It
  keeps only the newest. A background poller does the work in a thread, off the block path,
  through SQLite's online backup.
* **Where:** `/snapshot/manifest.json` and `/snapshot/qrdx.db` on its API port, with range
  requests, so `fetch` resumes a cut download.
* **Advertised:** `p2p_getStatus` carries the manifest under `snapshot`.
* **Left out:** what a restore discards anyway. That is the node's own tables (peers, pending
  transactions, the transaction index, trading history, display copies) and the tables a
  restore recomputes or rebuilds. Their pages are overwritten (`secure_delete`), not only
  unlinked, and the file is compacted.

A joining node takes the newest snapshot from the nodes it names:

```
python scripts/node/snapshot.py fetch --peer http://node-a:3007 --peer http://node-b:3007 \
    --out snapshot/
```

Publishing gives the snapshot no authority. The restore still needs a trusted checkpoint at or
above the snapshot's exchange checkpoint, and verifies everything against it.

Code: `qrdx/snapshot_publisher.py`. Tests: `tests/test_snapshot_publishing.py`.

## 3. History pruning

`QRDX_HISTORY_RETENTION_BLOCKS`:

* **unset or 0:** an archive node, which keeps everything (the default);
* **N:** a full node. As finality moves, it prunes the bodies of blocks more than N below the
  finalized block, at most 2,000 blocks a step.

N must be at least `min_retention()` (4,096 blocks), or the node refuses to start.

**A pruned block loses:**

* the proposer's signature (the block hash, its signing root, does not cover it, so the hash
  chain still verifies);
* the signatures of the votes it carried (the votes stay, for the chain index);
* its exchange and EVM sections.

**It keeps** every field its hash covers, its votes, its slashing evidence, and
`"pruned": True`. The chain index, the staking logs, the validator states and every state table
are untouched.

**The window** covers the persisted exchange checkpoint (up to 1,024 blocks behind finality),
which restarts and reorganizations replay from. It also covers the epochs of votes a snapshot
needs.

**What a pruned node cannot do:**

* Replay from genesis. A forced replay (`QRDX_STARTUP_FULL_REBUILD`) or a missing checkpoint
  stops the node with a message to restore from a snapshot.
* Serve blocks below its pruning point. A syncing peer is told to ask an archive node.
* Answer for transactions in pruned sections.

SQLite reuses the freed pages. The file shrinks only after a `VACUUM` with the node stopped.

Code: `qrdx/history_pruning.py`. Tests: `tests/test_history_pruning.py`.

## Verified live (2026-10-28)

* **The validator root on a network.** A 4-node network passed all 21 integration scenarios.
  These include validator membership (deposit, activation, exit, withdrawal), staking pools,
  perps, spot, the bridge and governance. A soak followed, with one node killed and restarted.
  Every block's root, validator part included, was verified on import, with 0 mismatches on
  every node across five runs, and the restarted node re-synced to the tip.
* **A restore.** A snapshot of node 1 (tip 3046, exchange checkpoint 2067) was checked against
  node 0's block 2995 as the trusted checkpoint:
  * genesis rebuilt and matched;
  * blocks 1–2995 hash-verified;
  * stepped back to 2067;
  * every root recomputed, equal to the signed `9da9ebf3…`.
* **Six attacks on that snapshot were refused, and nothing was written:**

  | Attack | Caught by |
  |---|---|
  | A forged balance (on an account no later block touched) | The state root |
  | A staking-log row | The new validator root |
  | A block body | Its `body_root` |
  | An exchange nonce, validly re-pickled | The state root |
  | A malicious pickle | Its name, before any code ran |
  | A wrong trusted hash | No trusted checkpoint on the chain |
* **Joining.** The restored database replaced node 1's. The node started from block 2067, synced
  from its peers, and at block 3893 had the same hash and state root as the other three.
* **Pruning.**
  * A copy of node 0 pruned below block 1800 (7.9 MB freed) was snapshotted and restored, with
    the same verified root.
  * A copy pruned into the needed window was refused ("block 1939 is pruned").
  * A node started on its pruned database through the checkpoint fast path.
  * A forced replay from genesis stopped it with the expected message.

* **Publishing (2026-11-02).** Four nodes each published from `QRDX_SNAPSHOT_DIR`.
  * Node 0's first snapshot (exchange checkpoint 31, tip 175, 1.7 MB with its own tables left
    out) appeared a minute after startup.
  * `p2p_getStatus` advertised it, and `/snapshot/qrdx.db` answered a range request with 206.
  * `fetch --peer` (three nodes, one of them down) took the newest offered.
  * The restore verified it against block 120 taken from a third node: block 31's state root
    as signed.
  * The same snapshot with one byte of the predeployed factory's code changed passed the state
    root and was then refused by the code check; nothing was written.

## What was in place already

* Weak-subjectivity checkpoints and the reorg floor at finality (docs/WEAK_SUBJECTIVITY.md).
* Recomputing the LtHash accumulators from rows at startup, and verifying the exchange's
  committed collections from scratch.
* The undo journal, which steps a snapshot back to its checkpoint.
* Signed body roots (`body_root`), so a block's content is bound to its hash.
* Slashing protection kept outside the chain database (docs/VALIDATOR_KEYS.md), so restoring a
  snapshot never resets what a validator has signed.
