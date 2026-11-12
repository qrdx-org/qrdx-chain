# Performance under load

docs/MAINNET_READINESS.md §4 asks for a profile under load before anything is optimized. This
is that profile, the changes it led to, and what limits throughput next.

## How it is measured

`integration_tests/load.py` starts a fresh 4-node network (3 validators, 250 ms slots, one
host). It funds post-quantum accounts from validator 0, then sends QRDX transfers between them
as exchange transactions, spread over the four nodes, at a series of target rates for 30 s
each. For each rate it reports:

* the rate the chain **executed** while the load lasted, from the accounts' nonces on the chain;
* the inclusion latency, from the moment a transaction is sent to its receipt, sampled;
* the block rate.

With `--profile` it also records py-spy over node 0 for each step, counting only samples that
hold the GIL, which is the node's Python CPU time.

Every block a node builds or imports logs its time by phase, which is the first thing to read
when blocks are slow:

```
Accepted PoS block 141 via RPC (175 ms: proposer 5, eligibility 3, parent 1, rules 13, journal 1,
    exchange 48, withdrawals 7, root 38, store 8, finality 52)
📦 Proposed block #142 at slot 362: d9b0… (158 ms: checks 4, select 18, preload 57, execute 15,
    flush 9, evm+withdrawals 10, root 35, sign 9)
```

**Across machines, emulated.** `--hosts containers` runs each node in a Docker container of its
own CPUs (`--cpus`, default 2), behind a relay that delays every connection into it both ways
(`--delay-ms`, default 25, so a round trip between nodes is 50 ms; `--jitter-ms`, `--mbps`).
Peers reach a node only through its relay, over HTTP and the peer transport alike
(`integration_tests/multihost.py`, `integration_tests/delay_proxy.py`). Latency is added in user
space because the kernel this ran on (WSL2's) has no netem. It is an emulation: the containers
still share one machine's memory bandwidth and disk.

```
python -m integration_tests.load --force --rates 300,600,1000 --seconds 30 --accounts 2048 \
    --hosts containers --image qrdx-node:multihost --cpus 2 --delay-ms 25
```

The image must hold the node's dependencies, liboqs and the native module (docker/Dockerfile
builds one). Each container mounts the test tree at its own path and runs as the invoking user.

```
python -m integration_tests.load --force --rates 100,200,300,400 --seconds 30 --accounts 512 --profile
```

The load comes from one address, so the run raises the nodes' per-address RPC limit
(`QRDX_RPC_CLIENT_RPS`). Otherwise the limit is all it would measure.

Above 100 transfers a second, the generator measured itself before it measured the chain. It
was fixed in five places:

* **Declared gas.** Each transfer declared 200,000 gas against a cost of 40,000, and blocks and
  the base fee count declared gas. Blocks looked five times fuller than they were, and from 200
  a second the base fee priced the generator's fixed bid out, block after block.
* **Counting.** Executions were counted after the latency samples' receipts, up to 90 s after
  the step, and divided by the step's 30 s. A backlog the chain cleared in a minute was
  reported as throughput.
* **Polling.** Receipts were polled every 0.1 s. Under a backlog, the pollers saturated the
  generator's event loop, and its sends timed out before reaching a node. A send that never
  arrived left a nonce gap that stranded its account.
* **Signing.** Transactions were signed in the send loop, which capped it near 225 a second.
  They are now signed before the clock starts.
* **Connections.** Thousands of requests queued on a 2,000-connection pool stalled httpcore,
  which scans both to match them. Sends are now bounded at 256 in flight. Measurement calls
  have a client of their own, so the queue of sends does not delay them.

## Results (2026-11-12)

After items 36–43 below (native admission and commitments, each node's share of the cores, a
signed block leaving when it is signed, the block's QRDX balances held natively, LtHash entries
eight blocks at a time). Four nodes, 2,048 accounts, 30 s a step.

| Load (transfers/s) | One host | Across emulated machines (2 CPUs a node, 25 ms each way) |
|---|---|---|
| 1,000 | 4.03 blocks/s, p95 0.30 s | 3.99 blocks/s, p95 0.49 s |
| 1,500 | 3.99 blocks/s, p95 0.39 s | 4.02 blocks/s, p95 0.52 s |
| 2,000 | **4.01 blocks/s, p95 0.60 s** | **4.02–4.03 blocks/s, every slot proposed, p95 0.54–0.65 s** |
| 2,500 | 2.98 blocks/s, backlog | 4.03 blocks/s, every transfer executed, p95 2.9 s |

(One host: with a profiler attached to one node. Every executed transfer counted; no
refusals at 1,000–2,000.) Offline an importing validator spends about 120 µs of its thread on
a transfer, admission included (it was 225). What limits it next is below.

## Results (2026-11-05)

After the fifth round (below, 26–29: plain transfers and the exchange's commitments native, a
block's fixed costs in memory, blocks and votes over the peer transport). Four nodes on one host,
2,048 accounts, 30 s a step:

| Load (transfers/s) | Executed | Blocks/s (slots: 4/s) | Latency p50 / p95 |
|---|---|---|---|
| 600 | 600.0 | 3.98 | 0.26 s / 0.31 s |
| 1,000 | 1,000.0 | 3.96 | 0.31 s / 0.73 s |
| 1,500 | 1,462 | 2.52 | 15.8 s / 38.5 s |
| 2,000 | 1,909 | 2.38 | 45.1 s / 66.5 s |

**Across emulated machines** (2 CPUs a node, 25 ms each way between nodes):

| Load (transfers/s) | Executed | Blocks/s | Latency p50 / p95 |
|---|---|---|---|
| 600 | 599.6 | 4.03 | 0.26 s / 0.49 s |
| 1,000 | 1,000.0 | 3.89 | 0.34 s / 0.80 s |
| 1,500 | 882.6 | 1.42 | 42.4 s / 73.9 s |

* **1,000 a second fills every slot, on one host and across machines**, at a third of a second
  to inclusion. Before this round it was past capacity on both (782 executed at 3.00 blocks a
  second on one host, 593 at 2.57 across machines). On one host with 64 accounts, 1,200 a
  second filled every slot too (p50 0.29 s, p95 0.59 s).
* **Across machines, 1,500 a second is past what two CPUs a node import:** one node fell 144
  blocks behind during that step and was catching up by sync when the run ended, on the same
  chain as the others.
* **Past it, a block carries up to about 800 transfers** (it was about 570): the 2,000 step
  executes 1,909 a second at 2.38 blocks a second.
* **An idle block imports in 6–8 ms with 40 database round trips** (it was 12–16 ms and
  132–178), and the chain makes all four blocks a second idle.
* **Blocks and votes travel on the transport.** Each node took every block from its three
  peers and set the copies aside before Python read them (about 820 blocks in, 180–280 new, in
  the first minutes); no peer exceeded its budget.
* The forks under overload (8–17 a node at 1,500 and 2,000 a second, none at 1,000) were each
  taken back out by their blocks' records; the four nodes ended on the same tip, hash and state
  commitments.

After the fourth round (22–25: pipelined execution, blocks taken back out by their own
records, the fixed costs of a block). Four nodes, 2,048 accounts, 30 s a step.

**On one host** (the dev container, loopback between nodes):

| Load (transfers/s) | Executed | Blocks/s (slots: 4/s) | Latency p50 / p95 |
|---|---|---|---|
| 600 | 599.5 | 3.99 | 0.29 s / 0.51 s |
| 1,000 | 782.4 | 3.00 | 1.6 s / 26.9 s |
| 1,500 | 1,349 | 2.37 | 23.8 s / 45.7 s |

**Across emulated machines** (2 CPUs a node, 25 ms each way between nodes):

| Load (transfers/s) | Executed | Blocks/s | Latency p50 / p95 |
|---|---|---|---|
| 300 | 299.9 | 4.01 | 0.26 s / 0.49 s |
| 600 | 600.0 | 3.90 | 0.29 s / 0.58 s |
| 1,000 | 592.8 | 2.57 | 4.4 s / 30.0 s |

* **600 a second fills every slot, on one host and across machines**, at a third of a second
  to inclusion. Before this round it was past capacity on both (across machines: 463 executed
  at 3.54 blocks a second).
* **Past it, a block carries up to about 570 transfers** (the 1,500 step drains the 1,000
  step's backlog at 1,349 a second, 2.37 blocks a second).
* **Every reorg in these runs took its blocks back out by their records** (4–8 a node), none
  through a checkpoint.
* An idle block imports in 12–16 ms (it took 30–47 ms) and a proposer sends its block 4–9 ms
  after it starts (it ran the block first: 17 ms idle, 100–290 ms under load).

After the third round (below, 14–21: the peer transport, blocks before transactions, the
proposer sized by its whole build, the mempool's selection, the native trigger function):

**On one host:**

| Load (transfers/s) | Executed | Blocks/s (slots: 4/s) | Latency p50 / p95 |
|---|---|---|---|
| 400 | 399.9 | 3.99 | 0.28 s / 0.51 s |
| 700 | 412.2 | 3.16 | 5.2 s / 29.8 s |
| 1,000 | 618.6 | 3.13 | 22.4 s / 41.7 s |

**Across emulated machines** (2 CPUs a node, 25 ms each way between nodes):

| Load (transfers/s) | Executed | Blocks/s | Latency p50 / p95 |
|---|---|---|---|
| 300 | 287–300 | 3.43–3.86 | 0.27–0.34 s / 0.58–4.4 s |
| 600 | 462.6 | 3.54 | 0.61 s / 26.5 s |
| 1,000 | 507.8 | 2.76 | 22.0 s / 45.3 s |

* **Up to 400 a second on one host, and 300 across machines,** every slot gets its block.
* **Past capacity the chain degrades instead of stalling.** Blocks keep coming at three a
  second and more while the backlog waits in the mempool. Before this round, past capacity
  the block rate fell to one a second and the executed rate fell with it.
* **Capacity is about 600 a second on one host** and about 460–510 across machines: Python's
  cost per transaction in every block, built and imported (below, "Why the ceiling").
* Across machines, 300 a second varied between runs: the two runs had 0 and 4–9 forks a node,
  and each fork costs its rollback about a second (below).

After the second round (compact blocks, announced gossip, the native module, the C HTTP
stack, the proposer's budget, the raised limit), on one host:

| Load (transfers/s) | Executed | Blocks/s (slots: 4/s) | Latency p50 / p95 |
|---|---|---|---|
| 200 | 200.0 | 3.93 | 0.49 s / 0.51 s |
| 300 | 299.8 | 3.61 | 0.27 s / 0.83 s |
| 500 | 397–471 | 1.8–2.1 | 0.53–0.88 s / 7–11 s |
| 800 | 340–372 | 1.2 | 11–15 s / 35–41 s |

* **Up to 300 a second,** nearly every slot gets its block, at one or two slots of latency.
* **The live ceiling is about 450 a second** on this host. Past it the backlog grows.
* **Runs vary** by about 15% at the ceiling; ranges are over two runs.

Before that round:

| Load (transfers/s) | Executed | Blocks/s | Latency p50 / p95 |
|---|---|---|---|
| 100 | 100.0 | 3.98 | 0.26 s / 0.27 s |
| 200 | 200.0 | 2.74 | 0.50 s / 1.36 s |
| 300 | 265.0 | 1.50 | 2.63 s / 15.99 s |
| 400 | 237.7 | 1.90 | 2.55 s / 7.77 s |

### Why the ceiling is about 600–800 a second at full block rate, not 4,000

What follows was measured after the second round, at about 450 a second. The third round
removed the stalls (a node frozen by its transport, blocks that grew past the slot, a selection
that read the whole mempool); the fourth took the proposer's run of its own block off the path
between slots, and a fork's replay. What remains is the cost per transaction:

* **Each phase of a block costs Python 30–65 µs a transaction** (offline: preload 53, execute
  66, flush 32, unified root 50, store 41, inclusion 15), and every node builds or imports every
  block. No phase dominates, so no single optimization moves the ceiling far.
* **A block must be run once within a slot,** because the next proposer runs it before it
  signs its own (pipelined execution took the proposer's run off that path; before it, a block
  had to be built and imported in one slot). A block that arrives late becomes a fork; its
  rollback now costs one undo a block.

The protocol allows 4,000 transfers a second sustained (below, "Against Hyperliquid"). One
node's Python does not keep up.

* **Every node handles every transaction, on one thread.** It admits each one, imports the
  block that carries it, and relays it. At the ceiling, each node's event loop thread is at
  100% CPU, while the database thread and the native module's threads are mostly idle.
* **A block takes longer than a slot.** A block of 400–500 transfers took 120–290 ms to build
  and 120–210 ms to import (p50 and p90), against a 250 ms slot. The next proposer often has
  not imported it yet, builds a competing block at the same height, and every node spends
  time choosing between them: 6–10 fork switches a node every 40 s at 500 a second.
  * Waiting longer for the parent does not help: the block that is late is usually still
    being built.
  * Building smaller blocks does not help either. A block's fixed costs (database reads, the
    inclusion judgment, the state root) then dominate, and the proposer's budget shrinks to its
    floor.
* **Offline, one core runs 4,450 transfers a second through a block** (below). Live, with
  admission, relaying and imports sharing the thread, the import alone ran about three times
  slower.

What would reach 2,000–4,000 a second live, in order:

1. **Execution in native code.** Preload, execution, flush and storage are about 150 µs a
   transfer in Python. Every node imports every block, so at 4,000 a second import alone needs
   0.6 s of every node's second. The signature checks and the body root are native already
   (docs/NATIVE.md).
2. **Admission and relaying off the block thread.** A separate process, or the native module,
   would take parsing, checking and relaying transactions. The thread that builds and imports
   blocks would then do only that.
3. **Pipelined blocks.** A proposer could announce a block's operations as it selects them,
   so peers execute while it finishes, rather than after.
4. **A multi-host test.** Four nodes on one machine share it, with no network latency between
   them. The geo-distributed soak (§3.4) is the real measure.

**Earlier the same day,** before the changes below, 50 a second was the limit at full block
rate, and 100 a second missed half the slots:

| Load (transfers/s) | Executed | Blocks/s | Latency p50 / p95 |
|---|---|---|---|
| 50 | 50.0 | 4.02 | 0.31 s / 0.42 s |
| 100 | 100.0 | 1.88 | 0.55 s / 1.69 s |

**Before the gossip change,** 50 a second was already past the limit: blocks fell to 1.05 a
second, and latency was 1.06 s at the median and 2.20 s at p95.

## What the profiles showed, and what changed

1. **Transaction gossip, one signed call per transaction per peer.** A node forwarded each
   admitted exchange transaction to every peer in its own JSON-RPC request. Each request was
   signed, and the peer checked the signature, so a loaded node's event loop was busy enough
   that blocks reached peers late. Proposers then built on stale parents: 356 blocks were
   refused for a parent mismatch, and there were 30–40 fork resolutions per node. **Fixed:** a
   node forwards what it admitted in the last 50 ms to each peer as one signed JSON-RPC batch
   (`ExchangeSubmitter`, `NodeInterface._rpc_batch`). This doubled the rate sustained at full
   block rate.
2. **A database query on every HTTP request**, from the legacy transaction re-propagation
   middleware. It now runs at most every 5 s.
3. **Every refused EVM transaction logged at ERROR, with a traceback.** It is now logged at DEBUG.
4. **The RPC limiter let public traffic starve peers**, and a batch passed every limit
   (docs/KNOWN_ISSUES.md). Fixed. Peers have a pool of their own.
5. **Each peer was held to the public per-address limit,** 50 calls a second. Gossip is a call
   per transaction per peer, so from about 50 transactions a second (or, with the load test's
   raised limits, about 170 a second, at the peers' pool) gossip, blocks and votes were refused.
   The symptoms were forks, stranded senders and latencies of a minute. **Fixed:** a peer has a
   limit of its own, sized for the protocol's rate (`QRDX_RPC_PEER_RPS` 4,000 a peer,
   `QRDX_RPC_PEER_POOL_RPS` 16,000 for all peers).

The second round, toward 2,000–4,000 a second:

6. **Blocks travel compact** (`qrdx/node/block_relay.py`). A block's exchange operations go to
   peers as their hashes, about 70 bytes each instead of 10 KB. A peer rebuilds the section
   from its mempool, fetches only what it lacks, and checks the result against the signed
   `body_root` as before.
   * A block a node already has (its own, echoed back by each relay, or one it took from
     another peer) is dropped before it is rebuilt. Rebuilding those fetched every operation
     from the sender. This alone took 500 a second from 293 executed to 471.
   * A block arriving from several relays at once is rebuilt once.
7. **Gossip is pushed once and announced after.**
   * The node a wallet sent to pushes the transaction to its peers.
   * Nodes that relay it send only its hash (`exchange_announceTransactions`), and the
     transaction itself to peers that answer that they lack it. Each node received each
     transaction once from every peer before.
   * A node forwards everything waiting each 50 ms, not 64 a peer (about 1,280 a second).
   * Each batch is encoded and signed once for all peers.
8. **A transaction is checked once.** Admission verifies it; a block that carries it then finds
   it verified, for the exact bytes it was verified for (`block_processor.is_verified`). The
   import path also decodes a section once, not three times.
9. **Signatures in parallel, in Rust** (docs/NATIVE.md). A block's 2,000 signatures take 7 ms,
   against 130 ms. What arrives together at admission (a peer's gossip batch) is checked in one
   batch, and its payers' balances are read in one query.
10. **The HTTP stack.**
    * uvicorn parsed every request in pure Python (h11): `httptools` and `uvloop` replace it.
    * `POST /rpc` skips the two request middlewares, which spawned tasks and wrapped the body
      of every multi-megabyte batch (`main._FastRPC`).
    * A request is parsed once, not twice.
    * Responses and relayed batches are written by orjson (`qrdx/fastjson.py`), nine times
      faster. Parsing stays Python's `json`: orjson reads an integer beyond 64 bits as a
      float.
11. **The proposer sizes its blocks** to what it runs in 40% of a slot
    (`EXCHANGE_BUILD_SHARE`). It grows a block while full blocks run inside that share and cuts
    it when one does not. Filled to the new limit, a block took a second to build and as long to
    import, and the chain stalled.
12. **The base fee read the parent's whole section** back from the database, for every block
    built or imported on it. A block's fee inputs are now kept by its hash.
13. **The mempool swept itself on every proposal.** It now sweeps at most once a second.

The third round, toward 4 blocks a second at load (2026-11-05):

14. **A peer transport, in Rust** (docs/NETWORK.md). Transactions travel between peers over
    one encrypted connection per pair (ML-DSA-65 node keys, an ML-KEM-768 session key).
    Reading them, setting duplicates aside, checking signatures and relaying run on its threads;
    Python only admits. Under load its first version froze a node: two locks taken in opposite
    orders, one while holding the GIL. It now has one lock and releases the GIL.
15. **Blocks before transactions.** An import awaits the database dozens of times, and each
    await resumed only after every callback queued before it: under load, hundreds from
    admission. Admission now waits while a block is imported or built (a slot at most,
    `SignallingLock.until_free`). The transaction index used to index up to 200 blocks a pass
    holding the block lock; it indexes one a hold, when no block is pending.
16. **A block is broadcast as soon as it is signed,** while its proposer stores it.
17. **A proposer sizes its block by its whole build,** start to signature, against 30% of the
    slot (`QRDX_EXCHANGE_BUILD_SHARE`). It measured only the exchange section, about 60% of a
    build, so a backlog grew blocks to 300–990 transfers, build and import outran the slot, the
    next proposer built beside them, and the block rate fell to one a second. At 1,000 a second
    offered, the chain now executes 619 at 3.13 blocks a second, where it executed 558 at 1.01.
18. **A proposer whose tip moved while it waited for the lock builds on the new tip,** in the
    same slot, while half the slot is left. It used to give the slot up.
19. **The mempool's selection read every queued transaction,** per proposal, and swept the pool
    once a second inside the build (30–90 ms with a backlog). Each nonce lane is now indexed by
    nonce, and a block clears the lanes it consumed as it is applied.
20. **The state commitment's trigger function is native** (17.5 µs a changed row to 7.8 µs;
    docs/NATIVE.md).
21. **A compact block reads the peer transport** for operations its node received but has not
    admitted yet. Across machines, blocks often arrived before their operations were admitted,
    and the whole section was fetched again from the sender: a round trip and a megabyte. At
    600 a second across machines, this took the executed rate from 273 to 463.

The fourth round, consensus changes for the regenesis (2026-11-05):

22. **Pipelined execution** (chain-spec feature `deferred_execution`, a genesis default;
    qrdx/post_state.py). A block's signed root is the root of the state its parent left, not of
    its own, so:
    * a proposer judges its block on its parent's state (the inclusion rule needs nothing
      more), signs it with that state's root — computed when it applied the parent — and sends
      it, then runs it. It sends 4–9 ms after starting;
    * every importer checks the root against the state it holds before running the block, then
      runs it and keeps the root of what it leaves for the next block;
    * running a signed block cannot make it invalid: an EVM transaction that cannot run (a nonce
      or a balance it no longer has) is skipped and changes nothing. Otherwise a transaction the
      mempool admitted but the block could not run would cost every proposer its slot in turn;
    * the state after block h is signed by block h + 1: state proofs and snapshots are checked
      against it (docs/STATE_PROOFS.md, docs/CHECKPOINT_SYNC.md).

    The next proposer still runs the parent before it can sign, so a slot holds one run of a
    block, not a build and an import: the proposer sizes its block by its whole work against
    half the slot (`QRDX_DEFERRED_BUILD_SHARE`). Signing two blocks back (31, below) is the rule
    that lets it stop waiting.
23. **A reorg takes its blocks back out** (qrdx/exchange/block_undo.py). Each block runs in an
    exchange undo scope, with what no scope records (the manager's own fields, the plain
    attributes of each engine, book and market) kept beside it, and the indexes derived from
    the state dropped by an undo, to be rebuilt. A rollback undoes the database by its journal
    and the exchange by these records, newest first; each must reproduce the exchange root its
    block found, or the checkpoint and replay run as before. A block that runs and is not stored
    is taken back out the same way. A one-block fork cost up to an epoch of blocks replayed,
    about a second under load.
24. **The chain index was checked against the chain on every read**, five or six database round
    trips each time, and eligibility, the validators' root and finality read it many times a
    block. It is now one query when nothing changed: the chain still holds, at the index's top,
    the block it indexed there, and the index still holds its row. Reads that fetched in a
    second round trip (aiosqlite's `execute`, then `fetchone`) now take one. An empty block's
    import made 427 round trips; it makes 132–178.
25. **Every feature check deep-copied the whole chain spec** (`chain_spec.is_active`); it now
    reads the genesis features the spec keeps.

26. **Plain transfers run natively** (`qrdx/exchange/transfer_lane.py`, `lane.rs`;
    docs/NATIVE.md). Python checks each one's form, fee floor, amount and recipient once; the
    inclusion judgment and the run over consecutive transfers (nonces, what each payer owes,
    balances, deltas, fees) are Rust, in Python's `Decimal` arithmetic exactly, bailing to
    Python for anything it would not reproduce.
27. **The proof trees and the exchange's accumulators are native.** The database's tree update
    walked its nodes one awaited read at a time (23 ms a block of 500); the exchange's
    in-memory trees allocated a Python object per level of every changed path (22 ms for 1,000
    changes to a collection of 100,000 entries, now 4–7). The accumulators' 4 KB vectors are
    built in parallel. A commitment of 1,000 changed entries went from 33.6 ms to 15.
28. **A block's fixed costs are in memory.** The chain index answered dozens of questions a
    block (an epoch's validator set, finality, the validators' root), each a check that the
    chain had not changed and a read: two round trips to aiosqlite's thread. The connection now
    counts its writes to `blocks` and its rollbacks (a TEMP trigger and a wrapped
    `rollback`), so the check costs nothing while nothing changed, and the newest 16,384
    heights' hashes and slots are kept beside the index (qrdx/chain_index.py). The tip, the
    finalized checkpoint, the validators' log tables (one query, not six), the undo journal's
    missing tables (looked for again only when the schema changes), the parent's fee inputs
    and the realtime feed's hashes followed. With `QRDX_VERIFY_CHAIN_INDEX=1` (the test suite)
    every answer from memory is checked against the database. An idle node made 87,000 round
    trips in its first 105 s; now 32,000.
29. **Blocks and votes over the peer transport** (docs/NETWORK.md). A block goes compact to
    every peer on the transport, its copies set aside before Python reads them; a compact
    block's missing operations are asked of its sender there before HTTP. The transaction index
    reads a block it just stored from memory (it re-read and parsed the section, a megabyte a
    block at load, holding the block lock).
30. **Exchange transactions in binary** (chain-spec feature `binary_exchange_txs`, a genesis
    default; qrdx/exchange/wire.py, native/qrdx-native/src/wire.rs). A transaction's signature
    and key travel as bytes, its other fields as varints: a transfer is 5.5 KB rather than
    10.9 KB of JSON, 7.3 KB as the base64 a block body carries. Every block hashes for its body
    root, stores and relays a third less; peers relay each other the bytes (the transport's
    native reader checks either form). What a transaction signs and its hash are unchanged.
    Decoding one costs about what its JSON did (11 µs, the base64 and fields native).
31. **Execution deferred a second block** (chain-spec feature `two_block_deferral`, a genesis
    default with `deferred_execution` and `exchange_inclusion`; qrdx/post_state.py). Block N
    signs the root after block N−2, so a proposer needs only its grandparent's state to sign.
    To judge its block's fees without having run its parent it needs a lower bound on what each
    payer holds after the parent, from the state before it and the parent's contents. The **fee
    reserve** gives one: within a block, nothing but fees takes an account below
    min(`FEE_RESERVE_QRDX`, 1 QRDX by default, and its balance as the block began) less the fees
    the block reserved from it (`ExchangeStateManager.fee_floor`). An operation that would is
    refused, unless the account's own transaction sets `params.spend_reserve` (a wallet sending
    its last QRDX); EVM transactions are the account's own and take at most their signed cost.
    Protocol holders (pools, escrows, the perps holder) and system wallets have no floor. So
    after its parent a payer holds at least min(R, its balance before the parent) less its fees
    and EVM costs in the parent — unless the parent spent its reserve, when it waits a block.
    Importers still judge a block on the state its parent left; a block judged on the bound is
    one they accept (tests/test_two_block_deferral.py builds chains that way: every block is
    accepted with the reserve, and without it most chains reach a block that is refused).
    The roots a block is checked against are kept by block hash in the database too
    (`post_roots`): the state a node holds is past them, so they cannot be recomputed after a
    restart, and a snapshot restore keeps its checkpoint's parent's from the trusted history.
    The native lanes hold the floor: the order lane leaves an operation that would cross it to
    Python, and the transfer lane a run whose senders could.
32. **A proposer that builds before its parent has run** (qrdx/validator/pipeline.py; node-local,
    `QRDX_PIPELINED_PROPOSER=0` turns it off). When the live import verifies a block whose next
    slot this node proposes, and the block arrived within half a slot of that slot's start or
    after it, it builds the next block first and sends it at once — signed with the root of the
    state it holds (the grandparent's), stamped with its slot's start (importers take a slot up
    to a second ahead of their clock) — then runs the parent and its own block, each in its own
    journal and undo scope. (Waiting for the slot's start instead, holding the lock, kept the
    parent and every block behind it waiting.) The judgment uses only that state and the
    parent's contents: each lane's nonce after the parent, each payer's fees on
    min(R, its balance) less its fees in the parent, nothing from a payer that spent its reserve
    or sent EVM transactions in it, free operations only on a QRDX holding and only from accounts
    with none in the parent, no oracle vote from a voter in it, the parent's votes not carried
    again, base fees from its header and sections. A parent carrying anything else (authority,
    staking, governance, token administration…), or opening an epoch, runs first as before.
    What waits stays in the mempool. The slot loop waits up to half a slot for an in-flight
    parent (it used to build on the grandparent at once and race it): a parent arriving during
    the wait is built on before it runs.

    With it on, a proposer whose tip moved while it prepared (most often the previous slot's
    block landing late) builds again on the new tip while a twentieth of its slot is left, not
    only half: the next proposer builds on a late block before running it, so building late no
    longer makes every block after it late, and a skipped slot is a block lost for good.

    On one host this changes little — the parent's trip is 40 ms of a 250 ms slot, and what binds
    there is each node's own work (below). It is for real networks, where the trip is 100–200 ms.
    Live (4 nodes, one host, 2,048 accounts): 1,000 transfers a second fill 4.0 blocks a second
    (p95 0.7 s); at 1,500 a tenth of blocks are built ahead, none failed to run, and the chain
    still falls behind (2.7 blocks a second), as it did without it (2.4–2.6).
33. **Slots a proposer lost without trying.** In a 2,000-a-second step a fifth of slots saw no
    attempt: the proposer's slot loop was still busy when its slot came and went.
    * After proposing, the loop waited for the broadcast — for peers' replies, which come once
      they have imported the block (100–300 ms under load), so a validator proposing two slots
      running (a third of the time with three) lost the second. The broadcast now finishes on
      its own and is logged when it does.
    * A validator two or more blocks behind the network (a peer sent a block that high, its
      proposer's signature checked, within the last second) proposed on its stale tip: the
      block lost the fork, the node rolled back and stopped to sync, and missed several slots
      more. It now waits to catch up instead.
    * With `QRDX_LOOP_LAG_LOG=1` a node logs each time its event loop was held 100 ms or more,
      and what it was running: under load, a block's synchronous exchange run. Inside the
      block's undo scope it cost about a third more (62 → 82 µs a transfer), most of it
      recording a block's own scratch — its balance deltas and the balances loaded for it, which
      every block starts afresh. A block's scope no longer records them (``keep_entry(...,
      transient=True)``; an operation that fails still puts them back): 82 → 70 µs.

    One host: 1,000 a second at 4.0 blocks a second (p95 0.6 s); 2,000 a second for 30 s on a
    fresh network executed 1,973 at 3.4 blocks a second; 40 s steps after 1,000 and 1,500
    executed 1,700–1,875 at 2.6–3.2 — still behind at 1,500 and 2,000.
34. **Less work a transfer on the import path** (bench: 234 → 218 µs a transfer, 500 to a block):
    * A block's balance changes are folded into the account accumulator once
      (`state_commitment.batched`), and journaled for undo in one statement written ahead of
      them (`undo_journal.written_ahead`), instead of a trigger rewriting the accumulator and
      another inserting a journal row for every account row (flush 45–49 → 34 µs). Held to the
      triggers' own result by twin databases fed the same blocks: the same journal, rows and
      accumulator after each, and a rollback by the journal restores the earlier state.
    * The JSON a transaction hashes and an exchange commitment digests is written directly for
      plain strings and whole numbers, to the same bytes (`json.dumps`'s, checked on 40,000
      random values).
    * A stored section's gas is summed from its operations when the caller holds them, not by
      reading every binary item's head twice.

35. **The node's store** (docs/STORAGE.md). The ledger, its commitments, the undo journal, the
    proof tree and each block's sections moved from SQLite to a native store on MDBX. What
    SQLite's triggers did, the store does natively as each row changes. The database's part of
    an import fell from 76 to 45 µs a transfer on the bench.
    * Live at 1,500 a second the median import fell from 119 to 78 ms and its database round
      trips from 61 to 36.
    * The block rate stayed at 2.7 blocks a second, and 2,000 a second executed 1,734 at 2.72.
      Slot accounting shows why: proposers sent their blocks a median 157 ms into their slot
      (p90 358 ms, past its end), their event loop still busy with the block before. The next
      step is the event loop, not the database.
    * With the chain's tables in the store too (blocks, transactions, the chain index), an
      import's database round trips fell to a median 11. Live, 1,000 a second at 3.97 blocks a
      second; 1,500 at 2.74; 2,000 executed 1,877 at 2.84.
    * Every table then moved (S6): no SQLite is left in the node's database, so a commit is no
      longer a round trip to aiosqlite's thread.

Each block's phase line ends with its store commits (`db N`; they were SQLite round trips).

36. **The garbage collector stopped every validator for a slot every few seconds**
    (qrdx/node/gc_policy.py). Profiled live at 1,500 transfers a second, each validator's event
    loop was busy about two thirds of the time, not saturated. But phases that take 15–60 ms
    sometimes took 200–400 ms ("sign 348", "run 361"), anywhere. CPython's full collections ran
    every 2–3 seconds on each validator, 200–335 ms each: about 5 of every 55 seconds, one slot
    at a time. They freed almost nothing (34 of them found 1,161 objects in all, most none): a
    node's garbage is freed by reference counting. Once the node has started, what is alive is
    now frozen, full collections no longer run automatically, and one runs every
    `QRDX_GC_FULL_SECONDS` (10 minutes) for the few cycles that do become garbage. Young
    collections are unchanged; under load they take a few milliseconds in ten seconds.
    `QRDX_GC_POLICY=0` keeps CPython's defaults.

    | 4 nodes, one host, 2,048 accounts | Before | After |
    |---|---:|---:|
    | 1,500 a second: blocks a second | 2.75–3.12 | 3.74–3.89 |
    | 1,500 a second: latency p50 / p95 | 3–9 s / 29–46 s | 0.5–0.6 s / 1.7 s |
    | 1,500 a second: slots with a proposal | 171–175 of 224 | 214 of 224 |
    | 1,500 a second: proposal sent into its slot (median) | 151–160 ms | 37 ms |
    | 1,500 a second: reorgs in 55 s | 22–29 | 6 |
    | 2,000 a second: blocks a second (executed) | 2.75 (1,844) | 3.05–3.59 (1,842–1,909) |

    1,000 a second is unchanged (4.0 blocks a second). 2,000 still falls behind.

    With `QRDX_LOOP_LAG_LOG=1` a node also logs each collection of 20 ms or more and, every ten
    seconds, the collections per generation. Its proposal lines say when the slot loop woke and
    how long it waited for an in-flight parent (`grace`).

37. **What 2,000 a second still costs a validator.** Profiled at 1,500 a second, a validator's
    loop was active about two thirds of the time: importing blocks 35%, admitting transactions
    19%, building its own blocks 17%, the transaction index 10%. At 2,000 a second each
    validator imports 2.7 blocks a second (~140 ms each) and builds 1.3, and a node that falls a
    little behind queues blocks on the block lock. Its next proposer then raced the queued block
    from the grandparent, the two competed at one height, and the lowest-hash tie-break rolled
    back half the network. What changed:
    * **A proposer waits for a parent being imported** (`pipeline.incoming_block`). A block is
      noted from the moment it arrives, before it waits for the lock. A proposer whose parent is
      noted keeps waiting past the grace until only 30% of its slot is left
      (`QRDX_PARENT_WAIT_LEFT`), and the import builds its block on that parent first (32).
    * **The proof tree's nodes are cached natively** and its writes come back packed (NATIVE.md).
    * **The transport reads bytes in place** (NATIVE.md): its relay was 14% of admission.
    * **A transaction's canonical bytes are remembered** with its hash, while every field they
      are made of is unchanged: the signature's check, each "already checked?" and the hash had
      each serialized them again.
    * **The transaction index writes its rows natively** (`Table.put_rows`: packed in Rust,
      `_coerce` only for a value not already of its column's type, the same bytes as `put`).

    | 4 nodes, one host, 2,048 accounts | Before (after 36) | After |
    |---|---:|---:|
    | 1,500 a second: blocks a second | 3.74–3.89 | 3.79 |
    | 1,500 a second: slots with a proposal; reorgs | 214 of 224; 6 | 160 of 163; 0 |
    | 2,000 a second: blocks a second (executed) | 2.87–3.59 (1,871–1,971) | 3.63 (1,899) |
    | 2,000 a second: reorgs in 40 s | 16–24 | 7 |

    2,000 a second still builds a backlog (latency p50 ~15 s).

38. **Blocks first, and a block that overtakes its parent.**
    * **A block that arrives before its parent is held** (qrdx/rpc/modules/p2p.py
      `_hold_early`) and submitted once its parent is imported; a proposer waits for it as for
      one being imported. Under load a block often overtook its parent. It was dropped, fetched
      again by fork resolution (which takes the block lock), and meanwhile the next slot's
      proposer built a competing block over it. Its parent not imported within a second, it
      goes to fork resolution as before.
    * **Admission yields to blocks twice:** after the batch's signature check too. When the
      check finished, every submission of the batch resumed even if a block had arrived
      meanwhile, and ran inside its import's awaits (an import's exchange phase took about
      twice its CPU time).
    * **The proof tree's update walks sorted changes by position** instead of copying them at
      every level, and writes its nodes into the store itself (no Python object a node): 6.4 →
      4.8 ms for 1,000 of 2,048 leaves, and the store writes that `put_raw` did.

    | 4 nodes, one host, 2,048 accounts | Before (after 37) | After |
    |---|---:|---:|
    | 1,500 a second: blocks a second | 3.79 | 3.97 |
    | 1,500 a second: latency p50 / p95 | 0.53 s / 1.75 s | 0.48–0.52 s / 0.89–1.02 s |
    | 1,500 a second: proof root in an import (median) | 21–25 ms | 15 ms |
    | 2,000 a second: blocks a second (executed) | 3.63 (1,899) | 3.03–3.41 (1,864–1,912) |
    | 2,000 a second: branch switches (whole run) | 26 | 13 |

    At 1,500 a second every operation is executed, with p95 latency about a second. 2,000 a
    second still falls behind: each validator's loop is about 70–80% busy there (an import of
    ~500 operations is ~140 ms, ~90 of it CPU), so blocks arrive and import late, the next
    proposer races them, and the backlog grows. What moves it now is less work per operation on
    the loop: the exchange's state and admission natively, or a second core per node.

39. **Admission and import, per operation** (`scripts/bench/import_block.py`: what an importing
    validator does with a block's transfers, admitted from peers and then imported from its
    mempool, phase by phase).
    * **A transaction is read whole, natively** (`wire_read`; NATIVE.md "Transactions read
      whole"): its fields, its signed bytes and its hash in one call, and its binary form and
      text remembered on it. Each had been computed again by its hash, its signature's check,
      its relay, a compact block's rebuild and storage.
    * **Its signature and its sender's binding in one batch** (`mldsa65_verify_bind_batch`): a
      transaction that passes is marked verified without the per-transaction Python around the
      verdict.
    * **A block's QRDX transfers name their senders once:** the token pre-load read every
      sender's balance again after the sender pre-load had (`known`).
    * **A plain transfer is prepared for the native lane when it is admitted**
      (`transfer_lane.prepare`, a function of its fields): the block that carries it, built or
      imported on the path every block waits on, finds it done.
    * **No module imported per call in the hot helpers** (the minimum gas price, the chain id,
      the wire form, the mempool's state lookups): about 0.35 µs each, 25 an admitted transfer.
    * **What arrives together is admitted together** (`ExchangeSubmitter.submit_batch`): a
      peer's gossip batch, and a client's JSON-RPC batch of `exchange_sendTransaction` (the
      server runs a method's batch form, `batched_by`, for a batch's calls of it). The
      signatures in one batch and the payers' balances in one read, as before; but no
      coroutine, future and wait a transaction — a third of admission's time — and the
      fingerprints of the transactions it has just read held for the batch (they were computed
      eight times a transaction, once a remembered value). The same checks and answers as
      `submit`, call by call (tests/test_gossip_announce.py).

    | µs a transfer (500 a block, 2,048 accounts) | Before | After |
    |---|---:|---:|
    | Admission (decode, checks, mempool) | 99 | 67, with the lane's preparation (about 10) moved into it |
    | Import: balance pre-loads | 15 | 11 |
    | Import: execution | 49 | 35 |
    | Import, in all | 111 | 89 |
    | In all | 210 | 157 |

    Live (4 nodes, 2,048 accounts): 1,500 a second at 4.00 blocks a second, every slot proposed,
    latency p50 0.34 s, p95 0.68 s; an import's median 96–110 → 74 ms at 1,000 a second.
    2,000 a second executes nearly all of it (1,885–1,977 a second) but at 2.8–2.9 blocks a
    second, with a backlog (p50 4–6 s).

    The alternative — a second process per node for admission and the index — is designed in
    docs/SECOND_CORE.md.
40. **The commitments on the module's threads, a transaction checked once, a section's heads
    read together, and each node's share of the cores.**
    * **LtHash on the pool** (docs/NATIVE.md, "The exchange's accumulators"): an entry is
      added into a running sum (no 2 KB vector each), and a run of entries is split evenly
      across the module's threads; fewer than 48 are summed on the calling thread (2–47 had
      cost about 30 µs each, waking the pool). The store's fold and full recomputation sum
      rows the same way. 1,000 entries: 3.3 ms on one thread, 0.5–0.9 ms now.
    * **The proof tree's update split across threads** (NATIVE.md, "The proof trees"): the
      subtrees a few levels down are updated apart and put back in the serial walk's order.
      4.5 → 3.2 ms a block of 500 transfers.
    * **A transaction checked once at admission:** `validate_basic` remembers a pass under the
      transaction's fingerprint (it was asked three times a transaction); no module imported
      per call on admission's path (seven a transaction); an account without a policy shares
      one default.
    * **A section's heads in one call** (`wire.heads`, natively `wire_heads`): the block's gas
      limit, its fee rules and the gas a stored block declares each read every item's head
      with Python's `peek`, 3.4 µs an item. Live, a block's rules took 15 ms at 2,000 a second;
      now 5.
    * **A block holds its transactions' fingerprints while it runs** (`fingerprints_held`): its
      hash, signed bytes, lane preparation and validation were each asked of a transaction,
      each computing one.
    * **Each node its share of the cores in the multi-node harnesses**
      (`QRDX_NATIVE_THREADS`: scripts/testnet.sh and the orchestrator write the machine's
      cores divided among the nodes, at least 2; a container node, its CPUs). Each node's
      pool had every core, so four nodes' bursts — commitments, proof trees, signature batches
      — competed for the cores their event loops ran on. A node alone on its machine keeps the
      default (every core).

    | µs a transfer (500 a block, 2,048 accounts) | Before | After |
    |---|---:|---:|
    | Admission (decode, checks, mempool) | 57 | 43 |
    | Import: execution | 34 | 29 |
    | Import: flush | 9.5 | 8.2 |
    | Import: unified state root | 17.7 | 14.4 |
    | In all | 150 | 125 |

    Live (4 nodes, 2,048 accounts, steps of 30 s):

    | | 1,000 a second | 1,500 | 2,000 | 2,500 |
    |---|---|---|---|---|
    | Before (after 39) | p95 0.49 s | p95 0.68 s | 2.84 blocks/s, p50 3.85 s | — |
    | The code above, every core a node | p95 0.32 s | p95 0.59 s | 3.59 blocks/s, p50 0.65 s, p95 1.93 s | 2.91 blocks/s (first step) |
    | …and 6 threads a node | p95 0.35 s | p95 0.53 s | **3.99 blocks/s, p50 0.48 s, p95 0.87 s** | 2.81–3.31 blocks/s, backlog |

    At 2,000 a second every slot was proposed, with no fork or reorganization; an import's
    median was 88 ms for a median 456 operations (it had been 134 ms for 586, the backlog's
    blocks being bigger). 2,000 a second as the first step sustained with every core a node
    too (p95 0.66 s); after the steps before it, only with the cores shared. 2,500 a second
    builds a backlog either way.

    Across emulated machines (`--hosts containers`: 2 CPUs a node, 25 ms each way) 1,000 and
    1,500 a second hold (p95 0.51 and 0.63 s), and 2,000 does not: 2.67 blocks a second, 99 of
    132 slots proposed, blocks sent a median 142 ms into their slot and imported in 133 ms.
    There a slot holds a build, a round trip and an import, on two CPUs.

41. **A signed block leaves when it is signed.** The proposer scheduled its block's broadcast
    as a task and went on to run the block: tens of milliseconds without a pause (more under
    load), and, for a block built on a parent still being imported (pipelining), the rest of the
    parent's import too. The task, and the send, waited for that. Across emulated machines at
    1,500 a second, blocks were logged "sent" a median 55 ms into their slot and reached their
    peers' event loops at 156 ms, 101 ms over a 25 ms link. Now the block goes on the peer
    transport synchronously when signed (`peers.send_block_now`), and the broadcast task
    carries it over HTTP to the peers off the transport only.

    An import's log line now counts from when the transport handed the block to Python, with
    what rebuilding it from its operations' hashes took first: `queued` (waiting for the event
    loop), `pool`, `held N`/`asked N`/`fetched N` (operations found on the transport, asked of
    the sender, fetched over HTTP), `encode`. That is how the gap was found: a block's
    operations were nearly always in the mempool already (`asked` never appeared), and the
    blocks sat on the sender, not on the receiver (`queued` a median 2 ms). The containers'
    CPU quota (`--cpus 2`) was checked too: 0–3 of each ~57 periods throttled, too little to
    explain it.

    | Across emulated machines (2 CPUs a node, 25 ms each way) | 1,500 a second, first step | 2,000 |
    |---|---|---|
    | Before | 2.70–2.90 blocks/s, p95 11–24 s; sent +55 ms, arrived +156 ms | 2.68 blocks/s |
    | After | **3.99 blocks/s, p95 0.72 s**; sent +36 ms, arrived +65 ms, imported by +178 ms | 3.54 blocks/s, backlog |

    At 2,000 a second there, an import of a median 388 operations takes 142 ms (execution 54,
    the store 24, the roots 20), and ends a median 285 ms into the slot: what remains is each
    node's own work, on an event loop that also admits 2,000 transactions a second.

42. **The block's QRDX balances held natively, plain collections committed natively.**
    * **The balance plane** (docs/NATIVE.md, "The balance plane"): the exchange's per-block QRDX
      dicts — available balances, balances as the block began, deltas, fees reserved, what the
      block owes — are the maps of one native object, which Python reads and writes through
      views that are the dicts they stand for. The transfer lane judges and runs on them in
      place (it had converted every value it touched to text and back, each run, about 7 µs a
      transfer inside the native call alone); the fee floors, the reservations, the pre-loads
      and the flush's wei amounts are native too, and the order lane reads them directly.
    * **Plain collections committed together** (`commit_plain`): nonces, shares and allowances
      — entries of two plain strings — have every changed entry's canonical bytes, digest and
      tree key made, the accumulator mixed and the proof tree updated in one call. A block of
      500 transfers changes 500 nonces: about 6 µs an entry in Python.
    * **Smaller:** the token pre-load read the routing hubs (and the perps' collateral token)
      for every operation, and set again every QRDX balance the sender pre-load had just set;
      a balance read packed its key through the generic coercion (3 µs); a receipt read an
      enum's name three times and called the fill and order recorders for operations that have
      neither.

    | µs a transfer (500 a block, 2,048 accounts) | Before | After |
    |---|---:|---:|
    | Import: pre-loads | 11.0 | 8.0 |
    | Import: execution (with the exchange root) | 28.5 | 18.5 |
    | Import: flush | 9.0 | 7.5 |
    | In all, with admission | 137 | 122 |

    Across emulated machines (2 CPUs a node, 25 ms each way; image with this module):

    | | 1,000 a second | 1,500 | 2,000 |
    |---|---|---|---|
    | After 41 | p95 0.51 s | p95 0.72 s; import 105 ms for ~330 operations | 3.54 blocks/s, p50 11.9 s |
    | After 42 | p95 0.49 s | **p95 0.52 s; import 66 ms for ~373** (execution 26) | 3.39 blocks/s, p50 0.90 s, p95 6.6 s |

    At 2,000 an import of ~494 operations takes 118 ms there: execution 45, the store 22, the
    roots 21 — the store and the roots now cost what execution does.

43. **LtHash entries eight output blocks at a time.** Every changed row of the database's
    domains and every changed entry of the exchange's collections adds an LtHash entry, 4 KB of
    BLAKE3 output: a transfer about six (its nonce, its two account rows, each out and in). The
    `blake3` crate computes long outputs a block at a time without AVX-512 — 2.8 µs an entry, on
    a node of two CPUs most of the roots' time. `src/xof.rs` computes them eight blocks at a time
    with AVX2 (docs/NATIVE.md, "The exchange's accumulators"): 0.93 µs an entry on one thread.
    The bench on two threads (a container's share): import 144 → 135 µs a transfer (execution
    20.5 → 18.4, the roots 17.7 → 15.3), and the second thread's time freed besides.

    With the transaction index's own trim (each row reads only the keys present and writes its
    detail with the native canonical JSON: 21 → 17 µs a transaction), across emulated machines
    (2 CPUs a node, 25 ms each way, steps of 30 s, 2,048 accounts):

    | | 1,000 a second | 1,500 | 2,000 | 2,500 |
    |---|---|---|---|---|
    | After 41 | p95 0.51 s | p95 0.72 s | 3.54 blocks/s, p50 11.9 s | — |
    | After 42 | p95 0.49 s | p95 0.52 s | 3.39 blocks/s, p50 0.90 s | — |
    | **After 43** | p95 0.49 s | p95 0.52 s | **4.02–4.03 blocks/s, p50 0.32–0.39 s, p95 0.54–0.65 s** | 4.03 blocks/s, every transfer executed, p50 0.94 s, p95 2.9 s |

    At 2,000 a second there every slot was proposed (151 of 151, 156 of 156 in the repeat), with
    no fork or reorganization; an import of a median 462 operations took 93 ms and ended a
    median 156 ms into its slot (p90 217). Every node's database ended on the same tip with its
    accumulators equal to their recomputation. On one host 2,000 holds too (p95 0.60 s, with a
    profiler attached to a node), and 2,500 builds a backlog there (the four nodes share the
    host's cores and memory).

## The block pipeline, measured offline

`scripts/bench/exchange_block.py` times one block's exchange section on a real database.
It covers what the proposer does (the inclusion judgment, the balance preloads, execution, the
flush, the unified state root, storing the block) and what an importer adds (verifying the
signatures). It runs on one core with no network, so it measures the node's own cost per
transaction.

```
python scripts/bench/exchange_block.py --txs 2000 --accounts 400 --blocks 3
```

2,000 transfers a block from 400 accounts, after the fifth round (2026-11-05):

| Phase | ms a block | µs a transaction |
|---|---:|---:|
| verify signatures | 62.5 | 31.3 |
| inclusion judgment | 31.6 | 15.8 |
| preload balances | 12.3 | 6.2 |
| execute | 34.9 | 17.5 |
| flush to the database | 39.6 | 19.8 |
| unified state root | 10.6 | 5.3 |
| store the block | 70.3 | 35.1 |
| **total** | **261.8** | **130.9**, about 7,640 transactions a second |

Before it (2026-11-04):

| Phase | ms a block | µs a transaction |
|---|---:|---:|
| verify signatures | 118.1 | 59.1 |
| inclusion judgment | 23.7 | 11.9 |
| preload balances | 65.4 | 32.7 |
| execute | 84.5 | 42.3 |
| flush to the database | 35.3 | 17.7 |
| unified state root | 19.4 | 9.7 |
| store the block | 102.5 | 51.3 |
| **total** | **449.1** | **224.6**, about 4,450 transactions a second |

The same block cost 457 µs a transaction before the changes below, about 2,190 a second.

1. **Database round trips, one per account per step.** Every balance was read with its own
   query and written with its own statement, each a hop to aiosqlite's worker thread. Balances
   are now read with one `IN` query per 500 holders and written with `executemany`
   (`DatabaseSQLite.get_address_balances`, `get_token_balances_of`,
   `apply_account_balance_deltas`, `apply_token_balance_deltas`).
   * Every node must reach the same state, so each batched form keeps its one-row form's exact
     rules: rounding, the clamp at zero, an overdraft's log, and one account under two address
     forms applied in order. `tests/test_batched_db_io.py` holds each to its one-row form on
     random deltas.
   * This change alone took 457 µs to 298 µs.
2. **Signatures verified twice on import, one at a time.** The importer verified a section and
   then verified it again while applying it. It now verifies once. A section of 64 or more
   transactions is verified across a thread pool (liboqs releases the GIL), sized by
   `QRDX_VERIFY_THREADS`.
3. **Work repeated per transaction:**
   * deriving an address from a public key, and an account id from an address (now cached);
   * a new ML-DSA verifier object per check (now one per thread);
   * a decimal conversion and a multisig signer count per gas query (now remembered);
   * a long `if` chain to find each operation's handler (now a table).

Peer traffic changed too:

* **Signing hashed the canonical JSON of the whole body.** For a 1 MB block, that cost about
  as much as sending it. A request's signature now covers the SHA-256 of the exact bytes sent
  (`x-body-hash: sha256`). Receivers accept both forms. They sign different messages, so
  neither can be downgraded into the other.
* **A block was encoded and signed once per peer.** It is now prepared once and the same bytes
  go to every peer. A nonce only needs to be unique per receiver.

## Against Hyperliquid

Hyperliquid reports about 200,000 orders a second. At 250 ms slots, QRDX is bounded well below
that by three things.

* **The protocol's own cap.** `BLOCK_EXCHANGE_GAS_LIMIT` is 80 million gas a block for new
  networks (docs/BLOCK_LIMITS.md), a chain-spec parameter. A transfer or spot order costs 40,000
  gas and a perp order 60,000. That is 2,000 transfers or 1,333 perp orders a block: **8,000
  transfers or 5,333 perp orders a second**, however fast the node is.
  * **Sustained, half that.** The exchange's base fee targets half the limit, as EIP-1559
    does. Demand above 4,000 transfers a second raises the price, block after block, until
    demand falls back to the target.
  * A block counts the gas each transaction *declares*, not what it uses. A wallet that
    declares more than an operation costs takes more of the block than it uses.
  * A `BATCH` (up to 20 actions under one signature) adds 10,000 gas to its actions' own, so it
    saves signatures, not gas.
* **The size of a post-quantum transaction.** Each exchange transaction carries an ML-DSA-65
  signature (3,309 bytes) and the signer's public key (1,952 bytes), both hex in JSON: about
  10.5 KB.
  * At 2,000 a second, that is 21 MB a second into every node before it relays anything.
  * At 200,000 a second, it would be 2 GB a second.
  * Hyperliquid's Ethereum-style signature is 65 bytes, and the key is recovered from it
    rather than sent.
* **The node.** One core runs about 3,400–4,450 transfers a second through the block pipeline
  offline (above). Live, the network tops out near 600 a second on one host and 460 across
  emulated machines, because every node builds or imports every block in Python and a block
  must be built, sent and imported within a 250 ms slot. The binding limit today is the
  Python cost per transaction in each block.

What would close the gap, in the order it pays:

1. **Raise the gas limit to what the network sustains.** Measure it on the geo-distributed soak
   (§3.4); the node has headroom. This is a chain-spec change, so a fork.
2. **Amortize the signature.** Raise `BATCH_MAX_ACTIONS` and price a batched action below a
   standalone one. One 5 KB signature then covers many orders, as a market maker's batch does
   on Hyperliquid.
3. **A compact wire format.**
   * Binary instead of hex JSON halves every transaction.
   * Naming the signer's key by a registry index, rather than carrying it, saves a further
     1.95 KB.
   * Together they take a transfer from about 10.5 KB to about 3.4 KB, mostly the signature.
   * This changes what is signed, so it is also a fork.
4. **A native engine.** Execution, the order book and the state root in Rust (through PyO3).
   The Python per-transaction costs above then become microseconds, and the database leaves
   the hot path, kept as a snapshot store as Hyperliquid keeps its state in memory.

A post-quantum signature and key take about 80 times the bytes of an Ethereum-style
signature. That ratio is a hard floor on raw orders a second per unit of bandwidth, and
batching is the lever that moves it.

## What limits it next

In the order they would pay, toward four blocks a second at 2,000–4,000 transfers:

1. **What is left of the exchange's state in Python.** After 42 an importing validator spends
   about 68 µs of its one thread on each transfer outside admission (bench): execution 18.5,
   the store 17, the roots 15, the pre-loads 8, the flush 7.5. In execution and the flush, what
   remains a transfer is Python objects: the result and receipt each transaction gets (about
   6 µs: the receipts are what the journal and the transaction index read), the lane's own
   preparation and payer checks, the nonces written back to their committed dict. Native
   receipts (made into dicts when read), and the nonces held natively as the balances are, are
   the next steps there. The token balances are still Python's dicts (the balance plane holds
   QRDX only). A second core per node (docs/SECOND_CORE.md) is the alternative for admission
   and the index.
2. **What an import costs beside execution** — since 42 as much as execution itself. The rules
   a block is judged by (since 40 about 5 ms a block, most of it the body root: SHA-256 over the
   section's ~4 MB of text), storing its section (about 11 KB of text an operation; the store's
   three commits a block, the section's JSON, the transaction index's rows) and the roots (the
   database's accumulators and proof tree, native since 37–38, split across threads since 40)
   are paid by every validator for every block.
3. **The size of what a block stores and hashes.** Binary transactions (30, above) took a third
   off; the rest is the signature itself (3.3 KB) and a key (1.9 KB) in every transaction. A
   key named by its account once the chain has seen it would take the key out, but no registry
   of accounts' keys exists (only validators'): one is new consensus state (kept through
   reorgs, snapshots and checkpoint sync).
4. **The protocol cap and transaction size,** above.
5. **Real machines.** The emulation shares one machine's memory and disk; the geo-distributed
   soak (§3.4) is the real measure.
