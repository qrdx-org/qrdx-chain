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

## Results (2026-11-04, dev container, all four nodes on one host)

After the second round of changes (below: compact blocks, announced gossip, the native
module, the C HTTP stack, the proposer's budget, the raised limit):

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

### Why the ceiling is about 450 a second, not 4,000

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

## The block pipeline, measured offline

`scripts/bench/exchange_block.py` times one block's exchange section on a real SQLite database.
It covers what the proposer does (the inclusion judgment, the balance preloads, execution, the
flush, the unified state root, storing the block) and what an importer adds (verifying the
signatures). It runs on one core with no network, so it measures the node's own cost per
transaction.

```
python scripts/bench/exchange_block.py --txs 2000 --accounts 400 --blocks 3
```

2,000 transfers a block from 400 accounts (2026-11-04):

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

* **The protocol's own cap.** `BLOCK_EXCHANGE_GAS_LIMIT` is 20 million gas a block, a chain-spec
  parameter. A transfer or spot order costs 40,000 gas and a perp order 60,000. That is 500
  transfers or 333 perp orders a block: **2,000 transfers or 1,333 perp orders a second**,
  however fast the node is.
  * **Sustained, half that.** The exchange's base fee targets half the limit, as EIP-1559
    does. Demand above 1,000 transfers a second raises the price, block after block, until
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
* **The node.** One core runs about 4,450 transfers a second through the block pipeline
  (above), twice the protocol cap. Live, on one host, the network tops out near 250 a second,
  because blocks of post-quantum transactions take longer than a 250 ms slot to propagate
  under load. The binding limit today is propagation, not execution.

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

* **Block propagation against 250 ms slots.** Live, forks cost a quarter of node 0's time at
  200 a second. The compact wire format above cuts the bytes to propagate by two thirds, which
  is the first lever. Sending a block's header and transaction hashes, rather than transactions
  every peer already holds from gossip, removes most of the rest.
* **Re-gossip.** Each transaction reaches a node once from every peer
  (docs/KNOWN_ISSUES.md). Announcing hashes and fetching only what is missing would cut that.
* **The protocol cap and transaction size,** above.
* **One host.** Four nodes on one machine share its cores, and their network has no latency.
  The geo-distributed soak (§3.4) must measure 250 ms slots with real round trips. Since time
  parameters live in the chain spec, a longer slot is a spec change if it is needed.
