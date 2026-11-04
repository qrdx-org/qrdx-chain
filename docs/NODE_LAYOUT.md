# Node layout

`qrdx/node/main.py` was a single 8,904-line module. It now holds only the app, the node's
state, and startup and shutdown. The node's behaviour lives in one module per concern.

## Where things are

| Module | Lines | What it holds |
|---|---:|---|
| `qrdx/node/main.py` | 1,215 | The FastAPI app, the rate limiter and CORS, the JSON-RPC server and its modules, `/rpc`, the request middleware, **the node's state** (below), and `startup` / `shutdown` |
| `qrdx/node/block_import.py` | 719 | `process_and_create_block`, the one path every block takes into the chain. Also the checks every block passes (`_verify_chain_rules`, `_check_parent_continuity`, `_verify_unified_state_root`, the E-D4 gates) and the exchange, withdrawal and tick sections it applies |
| `qrdx/node/evm_runtime.py` | 623 | `_execute_evm_raw_tx`, nonce rehydration, failed-transaction charges, `_eth_call`, and producing and importing a block's EVM section |
| `qrdx/node/derived_state.py` | 279 | Rebuilding derived state (exchange, EVM, withdrawals): after a rollback, at startup, and after a rejected block |
| `qrdx/node/fork_choice.py` | 580 | Rollback, reorganization, `resolve_fork_with_peer`, the fork-resolution scheduler and the reconciliation pass |
| `qrdx/node/sync.py` | 668 | `_sync_blockchain`, push-sync to peers that are behind, the catch-up a validator waits on, the initial-sync gate and the periodic update fetcher |
| `qrdx/node/peers.py` | 704 | Signed-request verification (`get_verified_sender`), the handshake, validator proofs and peer admission, dial-backs, unreachable peers, our own reachability, and propagation of blocks, transactions and attestations |
| `qrdx/node/discovery.py` | 400 | The Kademlia DHT and its bridge to the peer table, bootstrap nodes and the periodic discovery loop |
| `qrdx/node/chain_identity.py` | 184 | Which chain the database and each peer are on: chain spec, genesis, passed forks, trusted checkpoints |
| `qrdx/node/security.py` | 750 | Request and peer security: challenges, signature validation, input validation, peer reputation, rate-limit keys |
| `qrdx/node/api/` | 3,227 | The REST API, by area: `observability` (health, metrics, streams), `transactions`, `exchange`, `blocks` (blocks pushed by peers and validators), `chain`, `accounts` |

## How the split was checked

The code was moved mechanically. The tool used the AST and symtable to rewrite each reference
to node state or to another module, and no code was retyped by hand. Then:

* **Function bodies.** With the `_node.` and module prefixes taken off, 172 of the 173
  functions and classes have syntax trees identical to the originals. The 173rd lost a local
  `import traceback` that repeated a module-level import.
* **Module-level statements.** Every one survived verbatim.
* **The app.** Before and after, it has the same 76 routes with the same parameters, the same
  middleware in the same order, the same startup hook and the same 22 rate limits.
* **Relative imports.** Function-local relative imports in code that moved into `api/` (one
  package deeper) were made absolute. Every relative import in `qrdx/node/` was checked to
  resolve.

## The node's state stays in main

The database (`db`), the HTTP client, the EVM and exchange runtimes (`EVM_EXECUTOR`,
`EVM_STATE_MANAGER`, `EVM_MEMPOOL`, `EVM_PENDING_NONCE`, `EXCHANGE_MEMPOOL`, ...), this node's
identity, the genesis hash, the DHT handles and `block_processing_lock` are module globals of
`qrdx.node.main`. Two parties change them while the node runs:

* `startup()` binds them;
* tests replace them, as in `monkeypatch.setattr(node_main, "db", ...)`.

So the other modules never copy them at import. They read them when called, as `_node.db`
(`from qrdx.node import main as _node`).

## Calls between the modules go through the module

A module calls a function in another module through that module, for example
`_sync._sync_blockchain(...)` or `_import.process_and_create_block(...)`, not through a name
it imported. Each name therefore lives in one place. Replacing it there, in a test or a hot
fix, changes every caller, and a stale reference fails loudly instead of being silently
ignored.

## Import order

The modules import each other, and main imports them all at its end, after it has defined
everything they read. Whichever module is imported first, main runs before any of them uses
anything:

* the non-API modules use one another only inside functions;
* the API modules need only `app` and `limiter` while they load;
* `Depends(verified_sender)` (`qrdx/node/api/__init__.py`) looks up
  `peers.get_verified_sender` per request.

Do not reload `qrdx.node.main`. A reload builds a new `app` with no REST routes, because the
API modules are already imported and do not register again. To re-read a flag's
environment default, reload the module that defines the flag (for example
`importlib.reload(block_import)`).

## Tests that read the node's source

Tests that check how the node is wired (for example, that every import path ticks or
restores) read all of these modules through `tests/node_source.py`, not just main.py.
