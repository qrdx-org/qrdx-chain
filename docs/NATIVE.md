# The native module (Rust)

`native/qrdx-native` is a Rust extension (PyO3) for the work in a block that Python does
slowly: checking its signatures, committing to its body and to the state it changes, running its
plain transfers, and carrying transactions, blocks and votes between peers. The node and the validator call it through `qrdx/native.py`, and
each function there has a pure-Python path that gives the same result. A node without the
module, or with `QRDX_NATIVE=0`, runs those paths and agrees with every other node byte for
byte.

## What it does

| Function | Stands in for | Used by |
|---|---|---|
| `mldsa65_verify_batch(items)` | liboqs through `oqs-python`, one signature at a time | `block_processor.verify_exchange_txs`: a block's section on import; a gossip batch on admission (`ExchangeSubmitter`) |
| `canonical_json(obj, compact, default_str)` | `json.dumps(obj, sort_keys=True, ensure_ascii=True)` | `qrdx/native.py` |
| `body_root_sha256(prefix, body)` | `sha256(prefix + json.dumps(body, ...))` | `block_verification.body_root`, on every block |
| `Store`, `store_pack`, `store_unpack` | (no Python path) | the node's store: the ledger, its commitments, the undo journal and the proof tree (docs/STORAGE.md) |
| `smt_entries(kind, items, columns)` | `state_proofs.identity` and the entry functions | the database proof tree's entries of the rows a block changed (`state_proofs._changes`) |
| `smt_update(root, changes, version, cache)` | `smt.Tree.update` | the database's proof tree, once a block (`state_proofs.proof_root`) |
| `smt_update_into(root, changes, version, nodes)`, `SmtNodes` | `smt.Tree.update` | the same over a native node cache, its writes packed for the store (the node's path) |
| `mt_build`, `mt_update`, `mt_prove`, `MNode` | `smt._py_build`, `_py_update`, `_py_prove`, `smt.MNode` | the exchange's in-memory proof trees, every collection and order book a block touches (`smt.m_*`) |
| `lt_mix_entries(acc, tag, removed, added)` | `commitment._apply` of each entry's `lthash.entry` | the exchange's accumulators, every collection a block touches (`commitment._apply_digests`) |
| `lane_judge`, `lane_run` | `section_errors` and `process_transaction` for plain QRDX transfers | a block's runs of plain transfers, judged and run (`qrdx/exchange/transfer_lane.py`) where the balances are dicts; `lane_judge` judges plain spot orders and cancels too |
| `Plane`, `PlaneView` | the exchange's per-block QRDX dicts | the block's balances (`qrdx/exchange/balance_plane.py`): the transfer lane judged and run on them in place, the fee reservations, the pre-loads, the flush's amounts; the order lane reads them |
| `commit_plain(tag, acc, tree, update_tree, items)` | `CommittedDict.commitment`'s loop over a collection of plain entries | nonces, shares, allowances: every changed entry of such a collection, committed together |
| `NativeBook` | `orderbook.OrderBook` | every spot pair's book, behind the Python book's interface (`qrdx/exchange/native_book.py`; docs/EXCHANGE_ENGINE.md) |
| `order_lane_run` | `process_transaction` for plain spot orders (limit and market), cancels and swaps: matching, the pools and the router (`router.rs`), settlement, fees, escrow | a block's runs of them over the native books (`qrdx/exchange/order_lane.py`) |
| `wire_parse`, `wire_build`, `wire_text` | `wire.py_decode`, `py_encode`, `base64` | exchange transactions' binary form: every block section decoded on import, encoded by its proposer (`qrdx/exchange/wire.py`) |
| `wire_heads(items)` | `wire.peek` of each item | a section's gas and fee rules and the gas a stored block declares (`wire.heads`) |
| `tx_read` | the transport's own reading of a relayed transaction (its JSON or binary form): its hash and signed bytes | tests (`tests/test_exchange_wire.py`) |
| `wire_read(item)` | `wire.decode` and the hash, signed bytes and binary form computed after it | every exchange transaction read in the common form: admission, block sections (`wire._from_read`) |
| `mldsa65_verify_bind_batch(items)` | `mldsa65_verify_batch` and `verify`'s binding of a key to its sender's address | a batch's signatures (`block_processor._verify_natively`) |
| `NetService` | signed HTTP batches of JSON between peers | the peer transport for transactions, blocks and votes (docs/NETWORK.md, `qrdx/node/netd.py`) |

On a block of 2,000 transfers (`scripts/bench/exchange_block.py`, 24 cores):

| | Python | Native |
|---|---:|---:|
| Its 2,000 signatures | 130 ms (threads did not help) | 7 ms |
| Its body root (a 22 MB body) | 50 ms | 26 ms (16 ms of it SHA-256) |

### Signatures

The module links the system liboqs, the same library `oqs-python` loads (`ldd` shows
`liboqs.so.9`), and calls `OQS_SIG_ml_dsa_65_verify` on a thread pool (rayon), without Python's
lock. A signature is therefore judged by the same code either way.

Only the signature verdicts come from the batch. `verify_exchange_tx` still runs every other
check in Python: structure, chain id, gas, the key's binding to the sender, and multisig. It
reads each verdict where it would have asked liboqs (`dilithium.precomputed`). A transaction
that passed is marked with the exact bytes it passed for, so it is not checked again
(`block_processor.is_verified`). Change its payload, signature or key and it is checked afresh.

Python reached a block's signatures one at a time even on eight threads: `oqs-python` holds the
lock for its own work around each call. The first native version was no faster either, and the
reason was in the module itself: PyO3 converted each `bytes` to a vector element by element.
It now reads the bytes in place. The peer transport fell into the same trap twice over: every
transaction it relayed (5 KB) and every block it sent (megabytes) went through a `Vec<u8>`
argument, until it too read them in place (`bytes_of`, src/net). A Python-facing function takes
`&[u8]`, `PyBytes` or `PyAny`, never `Vec<u8>`.

### The store

The node's store (`Store`, src/store; docs/STORAGE.md) replaced SQLite's state tables and the
triggers that kept their commitments. It folds each changed row into its domain's LtHash
accumulator natively, from the row's packed columns. It computes what Python's encoders compute,
and hands Python each row it would not compute exactly: a value that is not text or an integer
(Python's `str` of it is what is hashed), or a token balance that is not a plain decimal numeral
(whose zeroness Python's `Decimal` judges).

`smt_entries` computes the database proof tree's entries for the rows a block changed: each
row's key and payload, from account ids, plain numerals and 32-byte words. Any other form (a
PQ address, text hashed into a word, a numeral `Decimal` reads differently) it hands to Python's
entry functions. In Python this took about 21 µs a row.

The store has no Python path, unlike every other function here: the node needs the module.

### The proof trees

The database's proof tree (`smt.Tree`, nodes stored by `version:depth:path`) is updated once a
block from the rows it changed. In Python the update walked the tree one awaited node at a
time, about 1,200 nodes for a block of 500 transfers: 23 ms. `smt_update` is the same walk,
with the same node encoding, hashes, writes (in Python's dict order, deleted keys re-inserted at
the end) and stale list. A node that is neither among its writes nor in the caller's cache is
not loaded by it: it names every missing node, the caller reads them in one query, and the
update runs again.

On the node's path the cache is native too (`SmtNodes`, the most recently used 200,000
nodes), and `smt_update_into` hands back the new and stale nodes packed as the store keeps them.
The update had read each node through a Python dict, and Python had packed its ~3,000 writes a
block one at a time (the bench's state root: 11.9 → 9.0 ms a block). Nodes an update loaded are
never evicted before it settles.

An update of 256 changes or more is split: the walk from the root first finds the subtrees a
few levels down (about four a thread) that have changes below them, each is updated on the
module's threads with its own writes, stale list and missing nodes, and the walk from the root
then takes each one's result where it would have made it itself — so the writes and stale
nodes come out in the serial walk's order, byte for byte. The cache's use stamps are atomic so
the subtrees can share it. 1,000 changes to 2,048 accounts: 3.1 → 2.3 ms for the walk; the rest
is packing its ~3,500 writes.

The exchange keeps a tree per collection and order book in memory, deep-copied with the state
every block. Each Python update allocated and hashed a node object per level of each changed
path: 22 ms for 1,000 changes to a collection of 100,000 entries. The native tree has the same
shape and hashes, its nodes immutable and shared (`Arc`), so copying a tree is returning it;
1,000 changes cost 4–7 ms. A native node has a Python node's attributes, pickles as its entries
(`smt.m_from_entries`), and is refused by the native functions if it is a Python one (that tree
stays in Python). Keys must be 32 bytes and distinct in a call, which every caller's are; the
native functions raise `ValueError` otherwise rather than give the input a meaning.

### The exchange's accumulators

A collection's commitment is an LtHash of its entries' digests. Python built each changed
entry's 4 KB vector as a big integer: about 6 ms for 1,000 changed entries, plus the sums.
`lt_mix_entries` builds the vectors without Python's lock and mixes them into the accumulator
lane by lane. An accumulator that is not well formed is handed back to Python.

Each entry is added into a running sum, never held as a vector of its own, and a run of entries
is split evenly across the module's threads, each folding its share into one sum; fewer than
48 are summed on the calling thread, where waking the pool cost more than the work (2–47
entries took about 30 µs each). The store folds changed rows and recomputes a domain from every
row the same way.

An entry's 4 KB is BLAKE3's extendable output of a short input: 64 output blocks, each the same
compression of the input's root node with its own counter. The `blake3` crate computes several
at once only with AVX-512; elsewhere it computes them one after another, about 2.8 µs an entry
on one thread here (AVX2, no AVX-512). `src/xof.rs` computes the root node of a one-chunk input
(≤ 1,024 bytes: every entry the node makes) and then eight output blocks at a time in AVX2
lanes, adding each word's low 16 bits into the sum as it goes: 0.93 µs an entry on one thread,
0.55 µs on two. A longer input, or a CPU without AVX2, goes to the crate. The output is the
crate's byte for byte (its tests, at every length of a chunk, and the commitments against
Python's).

Together, a commitment of 1,000 changed entries in a collection of 100,000 went from 33.6 ms
to 15 ms; the rest is Python encoding each entry.

For the collections of plain values (`encode_value`: nonces, shares, allowances — an entry is
`[key, str(value)]`, two strings JSON writes as they are), that encoding is native too:
`commit_plain` takes every changed entry (its key, its value's text, the digest held for it)
and makes each one's canonical bytes, digest and tree key, mixes the accumulator and updates the
proof tree, in one call and without Python's lock. A key or value that is not such a string
(printable ASCII with no quote or backslash), a tree that is Python's, and the collection is
committed by Python's loop. A block of 500 transfers changes 500 nonces: about 6 µs an entry in
Python, the whole commitment now about 1 ms.

### The balance plane

The exchange keeps per-block dicts of QRDX amounts by address: the available balances loaded
for the block, each account's balance as the block began, the block's net change to each
account (flushed to `account_state` after the block, in the order addresses entered it), the
fees it reserved from each payer, and, while a block is judged, what each payer's transactions
may cost. Held in Python, the transfer lane converted each value it touched to text and back,
each run, and the pre-loads, the reservations and the flush went through them a value at a time.

They are the five maps of one native `Plane` (native/qrdx-native/src/plane.rs): a table of
addresses and a map of values for each. The state manager holds a `PlaneView` of each, which is
the dict it stands for — the same keys in the same order (insertion order; a key removed and set
again goes last), a `Decimal` back for what was set, every method Python's code and the undo
scopes use — so Python's own operations read and write them as before. A value is kept natively
when it is a `Decimal` whose text the module reads back to the same text (src/dec.rs, the port
of Python's `Decimal`); anything else is kept as it is, and a native path that meets one hands
its work to Python. Natively, in place:

* the transfer lane's judgment (against the plane's balances and what the block owes) and its
  run, the fee floors checked there too; each computes its whole run first and writes nothing
  when it bails;
* the fee reservations of a section (`reserve_section_fees`) and the pre-loaded balances
  (`set_available_balances`);
* each delta's amount in wei for the flush (`Plane.wei`: `int(Decimal(str(d)) * 10**18)`);
* the order lane reads the QRDX balances from it, and writes back through the views.

Native paths run only where Python's decimal context is the exchange's (precision 78,
half-even, as `amm` sets it for the process: the arithmetic they reproduce) and no operation's
undo scope is open (a block's scope does not record these per-block values). `QRDX_NATIVE_PLANE=0`
keeps plain dicts.

### Plain transfers

Most of a loaded block is transfers of native QRDX, each signed by its own account's key.
`qrdx/exchange/transfer_lane.py` prepares each with Python's own checks (its form, fee floor,
amount, recipient and memo, under the exchange's decimal context) and hands runs of them to
`lane_judge` (the inclusion judgment: nonces and what each payer owes) and `lane_run` (the
execution: nonces, available balances, balance deltas, fees). The arithmetic is Python's
`Decimal` exactly: values travel as `<coefficient>E<exponent>`, and a value past 128 bits, a
negative zero or a nonce out of sequence makes the call bail, and Python runs the run. What it
writes back goes through the same dicts and undo records, new keys in the order Python's would
have inserted them. Anything else in a block (another token, another operation, an agent's or a
multisig's signature) is Python's. Where the balances are the balance plane's (below), the lane
judges and runs on them in place (`Plane.judge`, `Plane.run`), with nothing converted.

### Transactions read whole

`wire_read` reads an exchange transaction in the common form — the binary form exactly as
`wire.encode` writes it, no signer, a whole gas price, a timestamp set, params a flat object of
plain strings, keys sorted — and returns its fields with what the node would otherwise compute
again: the bytes it is signed and hashed over, its hash, its binary form and whether the text it
came as is that form's own. `wire._from_read` builds the transaction from them as `from_dict`
would, and remembers the rest on it under the keys `tx_hash`, `to_wire` and `to_text` keep
them. Anything else goes the Python way.

Two conditions keep a remembered form honest. The bytes must be the ones `wire.encode` writes
(a varint is read only in its shortest form), and a text is remembered only if it is the one
`b64encode` writes: Python's decoder accepts stray bits in the last character before the
padding. A non-canonical form remembered would make a compact block rebuilt by another node
differ from its proposer's.

`mldsa65_verify_bind_batch` checks each signature and whether its key's PQ address
(`0xPQ` and keccak-256 of the key, compared without regard to case) is the address it signs
for, on the module's threads. A transaction that passes both, and the checks
`verify_exchange_tx` makes besides them (its form, its chain id, its gas limit's cover), is
marked verified at once; any other goes through `verify_exchange_tx` with the batch's verdicts,
so a refusal is worded as before. tests/test_wire_read.py and tests/test_native.py hold both to
the Python path: every field and its type, the hash, the signed bytes, both forms and every
verdict.

### Plain spot orders and cancels

A plain limit or market order (any time in force, hidden or iceberg), a cancel or a swap
between two tokens (its best path), signed by its account's own key, is prepared by `qrdx/exchange/order_lane.py` with Python's own parsing and checks, and
judged with the plain transfers (`lane_judge`: its nonce, its payer's fees). `order_lane_run`
then runs a run of them over the native books: the nonce, the operation all or nothing —
the pools' legs where they price better than the book (`router.rs`: the pools' swap math and the
router's walk, Python's own logarithm, square root and power asked for), matching (`book.rs`),
each fill's settlement (base and quote moved, each side's fee by its fee
tier, staking discount and referral, the referrer's reward, the stakers' part, the treasury's),
the remainder into the book's escrow, or a cancelled order's escrow back, and on a pair quoted in
the perps' settlement asset each fill's volume toward fee tiers — then the gas. Python gathers
per pair what no operation of a run can change: where its pools start to fill, where its
waiting triggers fire, which orders have brackets, paused and freezing tokens, each sender's
payer, each trader's fee inputs. The run stops before the first operation it would not reproduce
exactly (a fill reaching a trigger's price, a frozen sender, a value past its decimals);
Python runs that one and the run goes on. Ledger entries are read from Python's dicts when first
needed and written back through them with the same undo records, new keys in the order Python's
would have inserted them. Anything else (trigger orders, brackets, builder fees, a swap's
explicit path, pool or venue, an agent's or a multisig's signature, the free lane) is Python's.

### Canonical JSON

The encoder writes what Python's `json` writes:

* keys sorted by code point;
* `\uXXXX` escapes in lowercase, with surrogate pairs above U+FFFF;
* the short escapes, and DEL escaped;
* integers of any size, as `int.__repr__` writes them;
* floats as `float.__repr__` writes them, and `NaN`, `Infinity`, `-Infinity`;
* tuples as arrays, and subclasses of str, int, float, dict and list.

Anything it does not reproduce exactly raises `Unsupported`, and `qrdx/native.py` encodes the
object with Python's `json` instead: a key that is not a string, an unpaired surrogate, nesting
past 900. An object `json` cannot serialize raises `TypeError`, as in Python.

## How it is held to Python

`tests/test_native.py` checks it against Python itself, on random inputs:

* 4,000 random structures, in both separator styles;
* `default=str` with `Decimal`, the fallbacks, and the errors;
* body roots with the module and without it;
* 60 signatures, valid and tampered (another message, a flipped bit, another key, a short
  signature), against liboqs through Python;
* a section of transactions, some tampered and some bound to the wrong sender, with the
  module and without it;
* the store's accumulators after random writes to every domain (text, integers, None, floats
  and bytes; plain, odd and invalid decimals), against Python's encoders over the rows
  (tests/test_native.py, tests/test_state_commitment.py); the store itself against a dict
  (tests/test_store.py);
* the proof tree's entries over random rows of every kind with odd values, each computed one
  against Python's (tests/test_state_proofs.py);
* the database tree's update over 39 versions of random changes from an empty cache (the same
  root, writes in the same order and stale nodes), and a malformed root or key refused;
* the in-memory tree over 60 rounds of random changes (deep shared prefixes too): the same root
  each round as Python's, the same proof of held, deleted and never-held keys, the same entries,
  an old root unchanged by later updates, a pickle round trip;
* the accumulator mix against Python's over random digests, and a malformed accumulator handed
  back;
* the transfer lane over random blocks (tests/test_transfer_lane.py), run with and without it,
  on dicts and on the balance plane: the same judgment and refusals, results, fees, nonces,
  deltas (and the order they entered), available balances and root, and every block taken back
  out by its undo record;
* a view of the balance plane against a dict over thousands of random operations (values it
  keeps natively and others, every method), its reservations and pre-loads against Python's
  loops, its flush amounts against Python's arithmetic, and inside an operation's undo scope
  (tests/test_balance_plane.py);
* the commitment of plain collections against Python's loop over random blocks of changes: the
  accumulator, every digest and the proof tree (tests/test_exchange_commitment.py);
* the native book against Python's (tests/test_native_book.py) and the exchange with each
  (tests/test_native_spot_equivalence.py) — docs/EXCHANGE_ENGINE.md;
* the order lane over random blocks of orders and cancels among what only Python runs
  (tests/test_order_lane.py), with and without it: every result and field, nonces, deltas and
  balances (and the order keys entered), fees, staker fees, fee tokens, the books and their
  history, the root, every block taken back out; and random sections with refusals judged the
  same.

The test suite also runs with `QRDX_VERIFY_STATE_COMMITMENTS=1`, which checks every exchange
commitment against Python's from-scratch recomputation: the accumulator by Python's vectors, the
tree by Python's `_py_build`.

The transport has its own tests (tests/test_net_transport.py, docs/NETWORK.md).

The tests skip when the module is not installed. CI builds it, so they run there.

## Its threads

The module's parallel work (signature batches, the commitments, the proof tree) runs on one
pool of threads, every core by default. `QRDX_NATIVE_THREADS` sizes it (it sets rayon's
`RAYON_NUM_THREADS` before the pool starts: qrdx/native.py, which the store imports first).
Nodes that share a machine should split its cores: scripts/testnet.sh and the test harness give
each node the machine's cores divided among the nodes (at least 2), and a container node its
own CPUs. With every core in each of four nodes, their pools' bursts competed for the cores the
nodes' event loops ran on (docs/PERFORMANCE.md, 40).

## Building it

```
curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain 1.86.0
pip install maturin==1.7.4
cd native/qrdx-native
maturin build --release --auditwheel skip -o dist
pip install --no-deps dist/qrdx_native-0.1.0-cp310-abi3-linux_x86_64.whl
```

* **Toolchain:** pinned to Rust 1.86.0 by `rust-toolchain.toml`; `Cargo.lock` pins every crate.
* **liboqs:** the module links the liboqs in `/usr/local/lib` (`QRDX_OQS_LIB_DIR` to look
  elsewhere). That is why the wheel is not "repaired" to bundle it: the node must check
  signatures with one library, the one `oqs-python` uses.
* **Wheel:** abi3, so one wheel serves Python 3.10 and later.
* **Threads:** `RAYON_NUM_THREADS` caps the threads a batch uses. By default it uses every core.

## What is not native yet

Execution beyond plain transfers, plain spot orders and swaps (liquidity, trigger orders, perps,
tokens), each entry's encoding for the exchange's commitments beyond the plain collections, the
token balances (the QRDX ones are the balance plane's), the receipts and the database writes
still run in Python. So do sync between peers, fork choice and the validator client
(docs/PERFORMANCE.md, "What limits it next"). The Python versions stay as the reference the
native ones are tested against.
