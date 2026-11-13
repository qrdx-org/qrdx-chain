# The peer transport

Nodes carry transactions, blocks and votes to each other over an encrypted connection between
every pair of peers, run by the native module (`native/qrdx-native/src/net`) on threads of its
own. Python (`qrdx/node/netd.py`) only does what needs the chain's state. This page covers what travels on
it, how it is secured and bounded, and how it fits with the HTTP peer interface the node keeps.

## Why it exists

Peers used to send each other transactions as signed HTTP batches of JSON. Every part of
receiving them ran on the node's one Python thread: the HTTP request, verifying the request's
signature, decoding the JSON, checking each transaction's signature, and relaying it on. Under
load that was most of the node's time (docs/PERFORMANCE.md). On the transport:

| | over HTTP | over the transport |
|---|---|---|
| connection | a request per batch, signed by the sender's node key | one per peer, kept open |
| reading a transaction | Python | Rust, in parallel |
| duplicates | found after decoding | found before the signature is checked |
| signature | Python (liboqs) | Rust (the same liboqs), in parallel |
| relaying | Python, HTTP to each peer | Rust: one frame to each peer |
| what Python does | everything | admission: nonce, balance, mempool |

## Who may connect

* **Node keys.** A connection is between two node keys (ML-DSA-65, the key behind the node id,
  `qrdx/node/identity.py`). Each side proves it holds its key by signing the handshake.
* **Admitted peers only.** A node lets the transport keep only peers it admitted through its
  usual peer handshake (`NodesManager`): `netd._keep_peers` hands the transport that list
  every two seconds (`NetService.allow`) and dials the peers that are not connected. A dialer
  whose claimed node id is not on the list is refused after its first message, before the
  node signs anything or runs a KEM for it. One that is still connected when it leaves the
  list is disconnected.
* **The right node.** A node dials a peer with the node id it expects. If the other end proves
  another key, the connection is dropped.
* **One chain.** The handshake carries the chain id and the genesis hash. A peer on another
  chain is refused.
* **One connection per pair.** When two nodes dial each other at once, both keep the
  connection the node with the lower id opened.

## The handshake

Three messages, each a 4-byte big-endian length then its bytes (at most 16 KiB), within 10
seconds:

```
M1  initiator → responder   "QRDXP2P1" | chain id (u64) | genesis hash (32)
                            | initiator node key (ML-DSA-65, 1,952) | ML-KEM-768 public key | nonce (32)
M2  responder → initiator   "QRDXP2P1" | chain id | genesis hash | responder node key
                            | ML-KEM-768 ciphertext | nonce (32)
                            | signature over T("responder", M1, M2 without its signature)
M3  initiator → responder   signature over T("initiator", M1, M2)
```

`T(label, parts…)` is SHA-256 over `"qrdx-p2p-v1/" | label | (length u64, part)…`. Both
signatures cover both nonces, both keys and the KEM exchange, so neither message can be
replayed or spliced into another session. The shared secret from ML-KEM-768 goes through
HKDF-SHA256, salted with `T("keys", M1, M2)`, into one key per direction.

## Frames

After the handshake each direction is a stream of frames: a 4-byte length, then a
ChaCha20-Poly1305 ciphertext of the message, with that direction's key and a counter as the
nonce. A frame is between 16 bytes and 16 MiB. A frame that does not open, or a message that
does not decode, ends the connection.

Messages are a type byte, then their fields:

| type | message | fields | bound |
|---|---|---|---|
| 1 | push | count, then (length, transaction JSON) each | 4,096 transactions; 128 KiB each |
| 2 | announce | count, then 32-byte hashes | 16,384 hashes |
| 3 | get | count, then 32-byte hashes | 16,384 hashes |
| 4 | block | length, then the block's JSON | 1 byte to 15 MiB |
| 5 | votes | count, then (length, attestation JSON) each | 1,024 votes; 16 KiB each |
| 6 | block operations, asked | request id (u64), count, then 32-byte hashes | 1,024 hashes |
| 7 | block operations, answered | request id, count, then (length, transaction JSON) each; length 0 for one not held | 1,024 |
| 16 | ping | u64 | |
| 17 | pong | u64 | |

Every count and length is checked against what the frame holds before anything is allocated.

## Gossip

* **A wallet's transaction** (one this node admitted from its RPC) goes whole to every peer.
* **A peer's transaction** that this node admitted is announced by hash to its other peers.
  A peer asks (`get`) for the ones it has not seen and has not already asked someone else
  for in the last 5 seconds. The node answers from a pool of the last 262,144 transactions.
* **Only what Python admitted is relayed.** The transport reads, checks and hands Python a
  peer's transactions, but relays one only when Python calls `relay` after admitting it. A
  transaction that fails admission (a used nonce, an empty balance) goes no further.
* **Duplicates** are set aside by hash (the last 1,048,576 handled) before any signature is
  checked, so a transaction arriving from several peers costs one check.
* **Queues.** At most 4,096 messages wait for one peer. Beyond that, messages to that peer are
  dropped (counted as `dropped_out`), not buffered: a peer that does not read cannot use up the
  node's memory.

## Blocks and votes

* **A block** goes in its compact form (its exchange operations named by hash,
  docs/PERFORMANCE.md) to every peer on the transport, and over HTTP to the peers that are not
  (`peers.propagate`). A peer passes a block on only once it has taken it, as over HTTP. A block
  its proposer signs goes on the transport at once, synchronously (`peers.send_block_now`):
  the proposer runs it next without pausing, and a send left to a task waited for that
  (PERFORMANCE.md item 41).
* **What Python does with one** is what it does with one that came over HTTP: the same handler
  (`P2PModule.submitCompactBlock`, `submitBlock`), with the peer the transport authenticated as
  the verified sender (`rpc_caller`). Whatever the block itself names as its sender is dropped.
  A block above this node's tip starts fork choice with that peer, which fetches the blocks
  between.
* **A compact block's operations** that this node holds neither in its mempool nor in the
  transport's pool are asked of the peer that sent the block (types 6 and 7), which answers from
  its pool. A node keeps the operations of each block it sends there. An answer it did not ask
  for, from another peer than it asked, or with another count, ends that connection; an
  operation that is not the one named is refused, and what is not answered within 2 seconds is
  fetched over HTTP by position (`p2p_getBlockTxs`).
* **A vote** (an attestation) goes to every peer on the transport and is taken as a gossiped
  one is (`peers._add_remote_attestation`: verified against the attester's key, pooled,
  relayed once).
* **Copies** of a block or vote are set aside by the hash of their bytes (the last 4,096 blocks
  and 262,144 votes handled), before Python reads them. One a node sent itself is among them.
* **Budgets.** A peer may send 32 blocks, 16,384 votes and requests for 32,768 operations a
  second, beyond a burst of twice that. More is dropped and counted (`dropped_in`), not queued:
  a node relays each slot's block once and each validator's vote once.

## What the transport reads, and what Python trusts of it

For each transaction, the transport computes what Python would: the signed bytes
(`ExchangeTransaction.signing_bytes`, reproduced byte for byte in `src/tx.rs`), the hash, and
the signature verdict from liboqs. What it cannot reproduce exactly (a float in the params, an
operation named instead of numbered, a missing field) it hands to Python unread, with the
reason.

Python uses the transport's verdict only when **the signed bytes it computes itself are the
bytes the transport checked** (`netd._admit`). Otherwise Python checks the signature itself. A
transport that is wrong about the bytes can make Python do work, but cannot get a forgery
admitted. Tests: `tests/test_net_transport.py` (the signed bytes and hash against Python's
for randomized params, and a forgery the transport calls valid being refused).

## Misbehaving peers

* A transaction whose signature fails is the sender's fault, since peers relay only what they
  admitted. Three such transactions disconnect the peer.
* A malformed message, a frame that does not open, or a frame of the wrong size ends the
  connection, as does an answer to a request the node did not make of that peer.
* A banned peer (the reputation manager's) is disconnected and not dialled: the transport keeps
  only the admitted peers that are not banned.
* At most 16 handshakes run at once. A connection beyond that is closed before anything is
  read, and the dialer retries later.

## Running it

| setting | default | |
|---|---|---|
| `QRDX_P2P` | on | `0` turns the transport off: transactions, blocks and votes travel over HTTP as before |
| `QRDX_P2P_PORT` | HTTP port + `QRDX_P2P_PORT_OFFSET` | the port it listens on |
| `QRDX_P2P_PORT_OFFSET` | 10,000 | |
| `QRDX_P2P_HOST` | `0.0.0.0` | the address it listens on |
| `QRDX_P2P_MAX_PEERS` | 64 | |
| `QRDX_P2P_THREADS` | 4 | the runtime's threads (signatures use rayon's pool) |

A node finds a peer's transport at the host of the peer's HTTP URL, on the peer's HTTP port
plus the offset. Open that port between nodes. When the native module is missing, or the
transport cannot listen, the node logs it and uses HTTP.

## What still travels over HTTP

Sync (a node catching up fetches blocks in batches), fork choice's branch fetches, peer
discovery, the peer handshake, a block's operations by position when its sender's transport
does not hold them, and everything to a peer that is not on the transport.

## Tests

`tests/test_net_transport.py` runs services in one process and covers: the handshake binding
node keys and the chain, refusals (another chain, itself, a node not admitted, an unexpected
node id), push, announce and get, duplicates, invalid signatures and strikes, garbage on the
socket, the signed bytes and hash against Python's, what goes to Python unread, Python taking a
verdict only for its own signed bytes, and relaying while peers announce (a lock-order deadlock
froze a node under load once); a block reaching every peer once and its copies set aside, votes
the same, a block's operations asked of its sender (held, missing, not connected), a peer
flooding blocks cut to its budget without being disconnected, and the size bounds. The
messages' encoding and their bounds have Rust tests (`cargo test`, `src/net/proto.rs`).
`tests/test_block_relay.py` covers the node's side: a block from the transport taken by the same
handler with the transport's peer as its sender, a block and a vote sent over the transport and
over HTTP only to the rest, and a compact block's missing operations asked of its sender
before HTTP.
