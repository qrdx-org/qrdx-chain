# The node's store

The node kept everything in one SQLite database, through `aiosqlite`. Under load that database
became the largest part of the cost of a block. For each transfer, importing a 500-transfer block
spent about 26 µs flushing balances, 31 µs writing proof-tree nodes, 17 µs storing the section
and 14 µs preloading balances: about 90 µs of the 175 µs the import cost (docs/PERFORMANCE.md).

The cost had four sources:

* **Round trips.** Every statement was a round trip to aiosqlite's worker thread.
* **Triggers.** Every changed row fired SQL triggers that called back into Python: the state
  commitment's LtHash, the proof tree's mark and the undo journal's record.
* **Section rows.** Each block's section was stored as hundreds of rows.
* **SQL itself.** Each statement was parsed and planned.

The store replaces that database, table by table, with ordered tables in one
[MDBX](https://libmdbx.dqdkfa.ru/) file, kept by the native module (`native/qrdx-native/src/store`,
`qrdx/store.py`). MDBX is the B-tree file Reth and Erigon keep Ethereum's state in. It is an
embedded library, so reads come from memory-mapped pages in the node's own process.

## How it works

**Tables.** A table maps a key, the tuple of its key columns, to a value, the tuple of its
other columns. Each tuple is packed with the FoundationDB tuple layer's encoding, so packed keys
sort as their tuples do:

* a range scan by key prefix replaces `WHERE key_col = ?`;
* key order replaces `ORDER BY`.

`qrdx/store.py` declares each table's columns and their SQLite affinities. A value is stored as
SQLite would store it (text in a TEXT column, an int in an INTEGER column), so a row reads back
as it did and commits to the same entry.

**Writes wait in memory.** A put or delete lands in the table's layer, a sorted map, and reads
look there first. `commit` writes every layer in one MDBX transaction and `rollback` drops them.
Committing or rolling back the SQLite connection does the same to the store, store first
(`DatabaseSQLite._couple_store`), so every caller that ends a block's transaction ends both.

**What the triggers did, the store does natively**, as each row changes, so no write path can
forget it:

* **Commitments** (qrdx/state_commitment.py). A table can feed a domain's LtHash accumulator.
  A changed row is folded in once, when the accumulator is read or the layer committed, however
  often it changed. Entries are computed in parallel, without Python's lock. The Python encoders
  remain the reference: the store hands them any row it cannot read exactly. `full_acc`
  recomputes a domain from every row, and a restored snapshot is reconciled with it.
* **The undo journal** (qrdx/undo_journal.py). While a block's height is set, the first change a
  block makes to each row of a journaled table records the row as it was, in the store's own
  `__undo` table, keyed by (height, sequence). `undo_rollback(h)` writes the rows back, newest
  first, and the commitments and marks follow.
* **Marks for the proof tree** (qrdx/state_proofs.py). Every changed row of a tracked table is
  marked in `__marks` until the tree folds the marks in. On a network that does not keep the tree,
  nothing is marked.

**Durability.** Commits are not flushed to disk as they happen (MDBX's `SafeNoSync`). A thread
flushes the file every second. A crash of the process loses nothing committed. A crash of the
machine loses at most the last second, and the file stays consistent. A node that loses blocks
that way syncs them again from its peers.

**Secondary indexes.** A table can declare indexes on any of its columns (`Spec(indexes=...)`):
the store keeps an index table for each, keyed by those columns then the row's key, natively
with every write — a journal rollback and a clear included. `Table.scan_index` reads the rows in
an index's order. The chain index finds its slots, epochs, vote targets and offenders this way;
a block is found by its hash.

**One handle per file per process.** MDBX allows only one. A snapshot of the running node shares
its handle (`store.opened`) and copies the file with MDBX's online copy, a consistent read while
the node keeps writing (`Store.copy_to`).

**The store needs the native module.** No Python implementation exists, and `QRDX_NATIVE=0` does
not turn the store off.

## Status

| Phase | Tables | State |
|---|---|---|
| S1 engine | — | done: layers, commit and rollback, the hooks, the online copy |
| S2 ledger | `account_state`, `contract_storage`, `contract_code`, `token_balances`, `token_registry`, `unspent_outputs`, `evm_balance_sync_registry`, `evm_balance_changes`; the proof tree (`smt_*`, `state_root_parts`); `post_roots`; the accumulators and the undo journal | done |
| S3a sections | each block's exchange and EVM sections, whole: one value a block (they were a row an item) | done |
| S3 chain | blocks (header by height, by hash through an index; body apart), transactions, chain metadata, the chain index (its votes, offenders and FFG votes) | done |
| S3b | votes and finality (`attestation_votes`, `epochs`, `slashing_events`), the exchange checkpoint | to do |
| S4 validators | validators, stakes, lifecycle, epoch states, withdrawals, slashing, staking | to do |
| S5 the node's own | pending transactions, peers, slashing protection, transaction and trading history | to do |
| S6 | SQLite and aiosqlite removed | to do |

The chain index used to count writes to `blocks` with SQLite triggers. The database's block
writers now tell it (`chain_index.blocks_changed`, `rolled_back`), so a write the index must
notice goes through them.

Until S6, a crash between the store's commit and SQLite's can leave the store a block ahead.
The startup rebuild handles this case as it handles every other partial write. It replays the
derived state from the newest exchange checkpoint, which steps the store back through its own
journal first (docs/KNOWN_ISSUES.md, "a restart replayed exchange state").

A checkpoint-sync snapshot is now two files: `qrdx.db` and `qrdx.db.store` (format 2,
docs/CHECKPOINT_SYNC.md).

A database from before the store is refused at startup with a message naming the tables it
still holds. Its ledger, journal and sections would otherwise be silently left behind. Start
such a node from a new database (sync, or restore a format-2 snapshot).

## Measured

**The import path** (`scripts/bench/exchange_block.py`'s block, 500 transfers among 2,048
accounts, phase by phase):

| Phase | SQLite | The store |
|---|---:|---:|
| Account balances | 25.6 | 5.3 |
| Domain roots (now with the commitments' fold) | 0.6 | 5.7 |
| Proof tree | 31.4 | 19.1 |
| Storing the block, with the store's commit | 2.2 | 5.9 |
| Storing the section | 16.5 | 8.6 |
| **Total** | **76** | **45** |

All figures are µs a transfer.

The proof tree's remaining cost:

* the native tree update, about 6 ms a block;
* writing its nodes;
* reading the marked rows.

Each row's entry, which Python computed at about 21 µs, is now native (`smt_entries`), with
Python for any value it does not reproduce exactly.

**Live**, four nodes on one host at 1,500 transfers a second:

| | SQLite | The store |
|---|---:|---:|
| Median import | 119 ms | 78 ms |
| Database round trips per import (median) | 61 | 36 |
| Exchange phase, p90 | 130 ms | 89 ms |

The block rate did not move (2.70–2.80 blocks a second): the import is not what holds the chain
there. A proposer sends its block a median 157 ms into its 250 ms slot, its event loop still
busy with the block before it (docs/PERFORMANCE.md, 35).

**A block-shaped write.** 1,000 accounts changed (read, then written with their commitment,
journal entry and mark), 3,000 proof-tree nodes and a 3.5 MB section, then committed. The store
had 200,000 accounts.

| | ms |
|---|---:|
| The store, every hook | 17 |
| SQLite through `sqlite3` directly, no triggers, the same rows | 27 |

The store's 17 ms:

| Step | ms |
|---|---:|
| Reading the accounts | 0.7 |
| Writing them | 1.8 |
| Folding the commitments | 3.3 |
| The nodes | 0.7 |
| The section | 0.6 |
| The commit | 6.0 |
| Packing keys | 2.4 |

The first version took 25 ms to store the section alone. PyO3 read each `bytes` argument into a
vector one element at a time, the same trap the signature batch fell into (docs/NATIVE.md). It now
borrows the bytes in place.
