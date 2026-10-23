# State proofs — proving one entry against a signed root

A block's signed `state_root` commits to all of QRDX's state, but its domain roots are LtHash
accumulators: cheap to keep, unable to prove that one entry is in them. With the chain-spec
feature **`provable_state`** (genesis default on new networks), the unified root also commits to
sparse Merkle trees over **all** of the state — the database (accounts, contract storage, token
balances) and the in-memory exchange (every committed collection, every order-book level, every
market's, pool's and book's own fields, the oracle) — so one entry, or its absence, can be proven
against any block's signed root by anyone who does not execute the chain: a light client, a
bridge, or a contract on QRDX itself. Nothing is provable only by trusting a node.

| | |
|---|---|
| Tree | `qrdx/crypto/smt.py` — a compressed binary sparse Merkle tree (BLAKE2b-256) |
| Keeping it | `qrdx/state_proofs.py` (database), `qrdx/exchange/proofs.py` + `qrdx/exchange/commitment.py` (exchange) |
| Precompile | `0x0000…0300` — `qrdx/contracts/state_proof_evm.py` |
| RPC | `state_getProof`, `state_verifyProof`, `state_proofInput` |
| Tests | `tests/test_smt.py`, `tests/test_state_proofs.py`, `tests/test_exchange_proofs.py` |

## 1. What is committed

Entries are typed, fixed-width payloads, so a contract can build one with `abi.encodePacked`.
An entry whose value is all zero is **absent** (an empty account, a zero slot, a zero balance).

| Entry | Payload |
|---|---|
| account | `0x01` · account id (20) · balance in wei (32) · nonce (32) · code hash (32) · storage root (32) |
| storage | `0x02` · contract id (20) · slot (32) · value (32) |
| token | `0x03` · holder id (20) · token address (20) · balance × 10¹⁸ (32) |

Ids are canonical 20-byte account ids (`qrdx/crypto/account_id.py`), so a `0xPQ…` address and
its EVM form prove the same entry. An entry's key is `BLAKE2b("qrdx/smt/key/v1\0" · type ·
identity)`; its leaf commits to `BLAKE2b("qrdx/smt/value/v1\0" · payload)`.

The tree's shape is a function of its entries alone: an empty subtree is 32 zero bytes, a subtree
with one entry is that entry's leaf at its top, a subtree with more is
`BLAKE2b("qrdx/smt/node/v1\0" · left · right)`. Updates and proofs cost about log₂(entries)
hashes.

### The exchange

The exchange's state lives in memory (rebuilt from the chain at startup), so its tree does too —
built from immutable nodes shared by every copy of the state, so a snapshot costs nothing and a
restored state brings its trees back with it. Two levels:

- **Each committed collection keeps its own tree** (`CommittedDict`, `CommittedSet`), updated in
  `commitment()` from exactly the entries whose digest changed — the same changes, at the same
  moment, as its LtHash — and undone with it. An entry's key is `key_of(0x20 · canonical(key))`,
  its payload `canonical([key, encoded value])`: the very bytes its digest hashes. Each order
  book's price levels likewise (`key_of(0x21 · side price)`, payload the level's orders).
- **The top tree** has a leaf per non-empty collection or book holding its tree's root, and a
  leaf per **part** holding canonical JSON: each market's header (`market:<id>`), each pool's
  fields (`pool:<id>`), each book's fields (`bookhdr:spot:<pair>`, `bookhdr:perp:<id>`), the
  oracle votes and outliers (`oracle`), the spot oracles, and the components' counters.

| Top leaf | Key | Payload |
|---|---|---|
| collection | `key_of(0x11 · path)` | `0x11 · root (32) · path` |
| book levels | `key_of(0x13 · name)` | `0x13 · root (32) · name` |
| part | `key_of(0x12 · name)` | `0x12 · name · 0x00 · JSON` |

A collection's path is its tag (`qns.names`, `ch.accounts`, `nfts.items`, …), suffixed by its
market, pool or pair when there is one each (`ch.market_orders:BTC-QRDX-PERP`,
`pool.positions:<pool>`). The top tree is updated by comparing every leaf's payload with what it
holds — by content, so it is right whatever the state was restored from.

**Binding.** The two trees' roots combine into the **proof root**, a fifth input of the unified
root:

    proof     = BLAKE2b( "qrdx/proof-root/v1\0" · database tree root · exchange tree root )
    state_root = BLAKE3-512( utxo | account | exchange | token | proof )

A proof therefore carries the other tree's root and the four domain roots; a verifier recomputes
the unified root and compares it to the block's signed `state_root`. Nothing else is trusted.

## 2. How the tree is kept

**The database tree.** TEMP triggers on the node's own connection mark every changed `account_state`,
`contract_storage` and `token_balances` row, in the writing statement's transaction (the same
rows the accumulators fold). When a block's root is computed — by the proposer and by every
importer, at the point the other roots are — the marked rows are folded into the tree and the
root recorded for that height. All of it is in the block's transaction: a rolled-back block
takes its tree changes with it. A rollback forgets the orphaned heights' roots; the rows it
rewrites are marked and fold in next.

Nodes are stored by `version:depth:path`, where the version is an internal counter that never
repeats, so earlier roots keep every node they reach. Nodes a later version replaced are pruned
once no retained height reaches them: heights older than `QRDX_STATE_PROOF_RETENTION_BLOCKS`
(node-local, default 100,000) can no longer be proven by that node. Cost, measured: folding 200
changed accounts into a 20,000-account tree ~26 ms; the first fold of 20,000 entries 0.67 s.

Rows written where the triggers do not run (another connection, a tool) are caught at startup:
the LtHash accumulators are recomputed from the rows then, and a domain they had to repair makes
the tree rebuild itself from the rows (a deleted row included).

**The exchange tree** is computed by every path at the point the exchange root is, and kept in
memory for the last 256 heights, for proofs.

## 3. Proving and verifying off chain

`state_getProof(kind, a, b?, height?)`:

| kind | a | b |
|---|---|---|
| `account` | address | — |
| `storage` | contract | slot |
| `token` | token | holder |
| `exchange` | a collection's path (`qns.names`, `ch.accounts`, …) or a book (`spot:<pair>`, `perp:<market>`) | the entry's key as JSON (`"alice.qrdx"`, `["0x…", 7]`), or a level (`"b65000"`) |
| `exchange_part` | `market:<id>`, `pool:<id>`, `oracle`, … | — |

`height` defaults to the newest provable block (an exchange proof: one of the last 256). A
database proof:

```json
{"height": 1234, "block_hash": "…", "state_root": "…",
 "kind": "account", "key": "…", "identity": "…",
 "entry": "01…" | null, "fields": {"balance_wei": "…", …},
 "siblings": ["…", …], "terminal": null | {"key": "…", "value_hash": "…"},
 "proof_root": "…", "roots": {"utxo": "…", "account": "…", "exchange": "…", "token": "…"}}
```

An exchange proof adds the collection's path, the entry's key in it, the inner path and the outer
path (`siblings`, `terminal`, `outer_siblings`, `outer_terminal`); both carry
`database_tree_root` and `exchange_tree_root`. `entry: null` proves absence: the walk along the
key ends at an empty subtree, or at another key's leaf (`terminal`) — an exchange entry is absent
too when its whole collection is. `state_verifyProof(proof, state_root?)` checks it; a light
client does the same with `state_proofs.verify_against(state_root, proof)` and a signed header it
trusts.

## 4. Proving on chain — the precompile

`0x0000000000000000000000000000000000000300` verifies a proof against an **ancestor** block of
the executing chain (`1 ≤ height < block.number`), reading that block's signed `state_root` from
its stored body — the same on every node. Input, packed:

| Field | Bytes |
|---|---|
| height | 32 |
| utxo root, account root, exchange root, token root | 32, 64, 64, 64 |
| database tree root, exchange tree root | 32, 32 |
| domain | 1: `0` database entry, `1` exchange entry, `2` exchange part |
| domain 0 | entry length (32) · entry — the full payload, or type · identity for absence · path |
| domain 1 | kind (1: `0x11` collection, `0x13` book) · name length (32) · name · entry key (32) · entry length (32) · entry (empty for absence) · path · outer path |
| domain 2 | entry length (32) · entry · outer path |
| path | sibling count (32) · siblings (32 each, root first) · terminal (1: `0`, or `1` then key 32 · value hash 32) |

Output: 32 bytes, `1` if the proof holds, else `0` (a malformed input included — it never
reverts). Gas: 50,000 plus 300 a sibling. `state_proofInput(proof)` encodes a proof from
`state_getProof` as this input. A contract proving an exchange entry passes the entry's bytes
(canonical JSON) — it can check them against bytes it expects; parsing JSON on chain is
impractical, so the typed database entries are the ones a contract reads fields from.

## 5. Not covered

- The legacy UTXO set is committed (its root is a domain root) but not in a tree.
- A node that synced a height by trust-replay without checking its root has no proof root
  recorded for it; another node's proof is still verifiable against the signed root.
