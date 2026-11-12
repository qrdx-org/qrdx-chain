# A second core per node (a design; not built)

A node does its work on one Python thread: it imports blocks, builds its own, admits
transactions and indexes them, all on one event loop. The native module's threads (signature
batches, the store's commit, the peer transport) barely register beside it. This document
describes moving the work that is not consensus — admission's stateless checks and the
transaction index — into a second process, so that a node uses a second core. It is the
alternative to making that work cheaper in place (docs/PERFORMANCE.md, 39; docs/NATIVE.md).
Neither excludes the other.

## Why

Measured on four nodes on one host at 1,500 transfers a second (docs/PERFORMANCE.md, 37), a
validator's loop was busy about two thirds of the time:

| Work | Share of the loop |
|---|---:|
| Importing peers' blocks | 35% |
| Admitting transactions | 19% |
| Building its own blocks | 17% |
| The transaction index | 10% |
| Everything else (RPC, sync, fork choice) | ~19% |

At 2,000 a second the loop is 70–80% busy. Blocks then arrive and import late, the next
proposer races them, and a backlog grows. The host has 24 cores; each node uses about one.

Of that work, admission and the index are not part of consensus: no block's validity depends
on them, and a node that admitted or indexed nothing would still follow the chain.

## What moves, and what stays

| | Moves to the second process | Stays in the node |
|---|---|---|
| **Admission** | Reading a transaction (wire or JSON), its structure, its fee floor, its signature and the binding of its key to its sender; the `exchange_sendTransaction` RPC itself | The checks that read the exchange's state (nonce window, the payer's balance, the signer's authority, the free lane's budget) and the mempool |
| **Index** | `tx_index_poller` and `history_poller`: reading each block's operations and receipts, and writing the index and trading history | Nothing; the node serves history RPC from the index's file |
| **Everything else** | | Blocks, state, the store, the peer transport, consensus RPC |

The mempool stays in the node because a proposer selects from it at every slot, on the path a
block waits on: a round trip to another process there would cost more than admission does.

## Admission

### The second process

It is started by the node, with its own event loop, and runs:

* an HTTP server for `exchange_sendTransaction` (a second port; the node's RPC forwards that
  one method when the second process runs);
* the stateless checks: `wire.decode` (natively, `wire_read`), `validate_basic`,
  `validate_fee`, the gas limit's cover, `chain_error`, and the signature with its binding
  (`mldsa65_verify_bind_batch`), in batches.

A transaction that passes is sent to the node; one that fails is answered there.

### The channel

A Unix socket, one frame per batch (a batch closes after 5 ms or 512 transactions). Each
transaction in a frame:

* its binary form (the bytes `wire.encode` writes);
* its hash, and the hash of its canonical bytes;
* flags: verified, a plain transfer prepared for the native lane.

The node reads a frame natively and builds each transaction through `wire._from_read`. The
admitter's verdict is taken only when the hash of the canonical bytes the node computes matches
the one sent, so a frame cannot vouch for a transaction other than the one it carries. The node
then marks it verified (`_verified`) and runs the stateful checks and `mempool.admit` as now.

### Peers' transactions

The peer transport (src/net) runs in the node. Its received transactions go to the second
process over the same socket in the other direction, raw, and come back verified. Today the
transport's verdicts already ride with each transaction (`netd._admit`); this extends that.

### What the node still pays

Building each transaction object (about 3 µs natively) and the stateful checks and mempool
insertion (about 15 µs) stay. Measured on the importer bench (`scripts/bench/import_block.py`),
admission costs about 75–90 µs a transfer in the node; about 60% of that would move.

## The index

The index needs, for each canonical block: its operations, each one's receipt, and the block's
height and hash. The operations and the block are in the store; the receipts are in the
exchange journal, in the node's memory.

* **Receipts.** The node writes each block's receipts to a store table as it commits the
  block. The table is small: a status, a fee and an error per operation.
* **The second process** opens the node's store file read-only (MDBX allows readers in other
  processes) and follows the chain index. It writes `tx_index`, `tx_participants` and the
  trading history to a store file of its own (`<database>.index`). A reorg it notices by a
  changed hash at an indexed height, as now.
* **The node's RPC** for history (`tx_*`, `market_*`, wallet history) opens the index file
  read-only and answers from it.

Lag: the index follows the tip by its polling interval (one second now), as it does today.

## Risks and costs

* **Two processes to run and supervise.** The node starts the second one and restarts it if it
  exits; the node works without it (falling back to admitting and indexing in-process).
* **MDBX across processes.** A reader in another process is supported. The node's handle opens
  the file with `WriteMap`; readers in other processes must use the same lock file and map
  size, so the second process opens it with the node's geometry.
* **A socket hop per batch.** About 50 µs a batch, nothing a transaction.
* **Verdicts across processes.** Covered above: the node checks that a verdict is for the very
  transaction it receives.

## Expected gain, and order

At 2,000 transfers a second, moving the stateless part of admission frees about 11% of the
node's loop, and moving the index about 6–10%. That is about what separates the loop at 2,000
a second (70–80% busy) from what it sustains at 1,500 (about 65%).

Native admission and import (docs/PERFORMANCE.md, 39) shrink the same work in place, and are
simpler to run. The index's move is worth making in any case; the admission front end, once
native admission has taken what it can.
