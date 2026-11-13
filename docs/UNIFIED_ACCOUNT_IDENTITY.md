# Unified Account Identity (0x ↔ 0xPQ)

**Status: implemented.** Native value moves in both directions between traditional
(secp256k1) and post-quantum (Dilithium/ML-DSA-65) accounts, through one ledger,
one EVM, and one state root. **Requires a regenesis** — see §6.

---

## 1. The problem

QRDX has two credential families:

| Family | Address | Bytes | Signature |
|---|---|---|---|
| Traditional | `0x…` (EIP-55) | 20 | secp256k1 `(v, r, s)`, 65 bytes, sender *recovered* |
| Post-quantum | `0xPQ…` | 32 | ML-DSA-65, 1952-byte key + 3309-byte signature, no recovery |

`account_state` already held balances for both, so the *storage* was unified. But
execution was not:

* The EVM — and therefore Solidity's `address` type, the ABI, every deployed
  contract, and all Ethereum tooling — is irreducibly **20-byte addressed**. A
  32-byte account can never be named by a contract, be `msg.sender`, or fit an RLP
  `to` field.
* Every VM boundary called `to_canonical_address()`, which throws on a 68-character
  `0xPQ…`. PQ rows could never enter the VM.
* `generate_contract_address()` did `bytes.fromhex("PQ…")` → a PQ account could not
  deploy.
* There was no transfer operation a Dilithium key could sign at all: the exchange
  op set has no native-QRDX transfer, and an RLP transaction cannot carry a
  Dilithium signature.

Net effect: a PQ account was a second-class citizen — fundable, but unable to
send, be paid by a contract, hold ERC-20s, or deploy.

## 2. The design: one derived 20-byte account id

The ledger is keyed by a **20-byte account id**. `0xPQ…` is demoted to what it
actually is — a credential fingerprint for display and signature binding. Both
forms name the same single `account_state` row.

```
traditional  0x + 40 hex    →  itself                              (identity)
post-quantum 0xPQ + 64 hex  →  keccak(DOMAIN:pq     ‖ raw32 )[-20:]
multisig     0xPQMS+38 hex  →  keccak(DOMAIN:ms     ‖ raw19 )[-20:]
legacy       Q/R base58     →  keccak(DOMAIN:legacy ‖ ascii )[-20:]
```

`DOMAIN = b"QRDX-ACCOUNT-ID-v1"`. See [`qrdx/crypto/account_id.py`](../qrdx/crypto/account_id.py).

**Traditional addresses are their own account id.** That identity is what keeps
QRDX web3-compatible: existing accounts, contract addresses, MetaMask, ethers,
hardhat and every deployed contract are untouched.

### Derive, never register

The account id is a **pure function** of the display address — no lookup table, no
registry row, no resolution step that can be missing.

The rejected alternative was an alias backed by a registry. That needs a
reconciliation path for "a contract paid an alias this node never registered", and
reconciling two representations into one row is precisely the bug class that has
repeatedly broken this chain's reorg rebuild (a sync registry surviving a
`clear_account_state`; rebuild enforce-flags drifting from the forward path). A
derived id has no second representation to reconcile: a contract paying the
20-byte form credits the exact row the PQ key controls, because they *are* the
same account.

### Security trade-off (deliberate)

Truncating to 20 bytes puts the account id at ~80 bits of collision resistance
(grinding two Dilithium keypairs to the same id) versus ~128 for the 32-byte form.
This is **exactly Ethereum's own bound** and is the unavoidable price of EVM
compatibility — a 32-byte account cannot be expressed to a contract.

It does **not** weaken the post-quantum property that motivates the PQ credential:
quantum resistance here is about *signature forgery* (Shor breaking secp256k1 key
recovery), and a Dilithium signature still authorises every spend. Second-preimage
against a *specific existing* account remains ~2^160.

Do not widen this to 32 bytes "for safety" — that re-partitions the ledger and
un-does the unification.

## 3. The authorisation half: transaction type 0x51

A Dilithium signature cannot fit the legacy 9-field RLP shape (no recovery, ~5.3KB
of key + signature). EIP-2718 provides the envelope, and the type-byte space was
entirely unused — the mempool rejected every typed transaction.

```
0x51 ‖ rlp([chain_id, nonce, gas_price, gas_limit, to, value, data,
            public_key, signature])

sig_hash = keccak(0x51 ‖ rlp([chain_id, nonce, gas_price, gas_limit,
                              to, value, data]))
```

See [`qrdx/transactions/pq_tx.py`](../qrdx/transactions/pq_tx.py).

* `0x51` is ASCII `'Q'`, outside every Ethereum-assigned type (0x01–0x04).
* `tx_hash = keccak(raw)` — the Ethereum rule, so receipts need no special case.
* **There is no sender field on the wire.** The sender is derived from the embedded
  public key, so a transaction can only ever spend from the account its key derives
  to. Nothing to forge.
* Because the sender is 20 bytes, **the EVM required no changes at all** to execute
  a PQ transaction, and a contract sees an ordinary `address`.

### Web3 compatibility

| Operation | Works? |
|---|---|
| `eth_sendRawTransaction` with a type-0x51 payload | ✅ it is just bytes |
| `eth_getTransactionByHash` / `…Receipt` | ✅ standard keccak tx hash |
| `eth_getBalance` / `getTransactionCount` / `getCode` on a `0x` account | ✅ unchanged |
| …same, passing a `0xPQ…` address | ✅ resolved by derivation (a QRDX extension) |
| MetaMask *sending to* a PQ account (by account id) | ✅ an ordinary 20-byte address |
| MetaMask *signing* a PQ transaction | ❌ needs a QRDX wallet — no client can sign ML-DSA-65 |
| Solidity `transfer(pqAccountId)`, ERC-20 balances, `msg.sender` | ✅ ordinary `address` |

`qrdx_getAccountId` resolves any address form for wallets and explorers;
`qrdx_getAddressInfo` now also returns `accountId`.

### Gas

A PQ transaction's intrinsic floor prices its envelope:

```
21000 (base) + 40000 (ML-DSA-65 verify) + 32000 (if create)
      + calldata + 16/byte over the 5261-byte key+signature
      ≈ 145,000 gas for a plain transfer
```

Below that floor the transaction is **invalid** (as in Ethereum), not merely
reverting — so the shared parser rejects it and a block carrying one is rejected.

## 4. Where normalization happens

`to_account_id` is applied at every ledger boundary, and is **idempotent** so
layering is safe:

| Layer | Site |
|---|---|
| Genesis funding | `genesis_init._create_genesis_outputs`, `db.seed_genesis_account_state` |
| Balance reads | `db.get_address_balance` |
| Balance deltas (exchange, margin, stake) | `db.apply_account_balance_delta` |
| Token ledger holders | `db.apply_token_balance_delta`, `db.get_token_balance` |
| EVM state, async + **sync** | every accessor in `ContractStateManager` |
| EVM ↔ native sync | `StateSyncManager`, `ExecutionContext` |
| Transaction authentication | `parse_eth_raw_tx` (both envelopes) |

The sync wrappers matter as much as the async ones: the EVM executor reaches state
*only* through the sync surface and passes checksummed strings, while genesis and
the exchange use the async surface. If the two normalized differently, one account
would occupy two cache entries — the gas debit landing on one, the funded balance
on the other — and the state root would diverge.

This also fixes a latent hazard that predates PQ: `account_state.address` is a
`TEXT PRIMARY KEY` with exact matching, so a checksummed write and a lowercase
write were *two rows* for one account.

## 5. Two pre-existing bugs found on the way

Both are independent of unification and were found by asserting exact amounts.

1. **Native transfers double-counted.** `QRDXEVMExecutor.execute` applied `value` a
   second time by hand after `_sync_from_evm` had already written back the VM's
   post-transfer balances. Every native transfer credited the recipient **2x** and
   debited the sender **2x**; a *reverted* call still moved funds, since the VM
   rolls its own transfer back but the manual credit did not. Deterministic, so it
   never forked — which is why root-convergence soaks could not see it, and why
   `s04`'s "balance increased" assertion passed.
   Pinned by [`tests/test_evm_value_transfer_conservation.py`](../tests/test_evm_value_transfer_conservation.py).

2. **Plain transfers were free.** This executor runs py-evm's `apply_message`,
   which does no transaction-level gas accounting, so `gas_used == 0` for an
   EOA-to-EOA transfer and nothing was charged. `execute()` now charges
   `min(gas_limit, max(consumed, intrinsic))`. This also makes the PQ floor
   actually *debited* rather than merely *required*.

## 6. Regenesis required

`get_account_state_root` hashes address strings, and genesis previously wrote
display addresses. Re-keying to account ids changes the root, as does charging
intrinsic gas. There is no migration path — wipe node databases and start from a
new genesis. The integration harness already does this
(`TestnetOrchestrator(force_regenerate=True)`).

## 6b. Protocol-internal holders

The exchange holds its own state under synthetic addresses — `0xPOOL…` for AMM pool
reserves, `0xCLOB…` for CLOB resting-order escrow — which are `0x`-prefixed but not hex.
These are part of the keyspace via an explicit allow-list
(`SYNTHETIC_HOLDER_PREFIXES`), domain-separated by prefix, with a validated body. They
are not user credentials: no key signs for them.

Making the keyspace strict without covering them silently dropped every credit into a
pool or escrow. See [EXCHANGE_AND_VALIDATOR_STAKE_AUDIT.md §1.3(b)](EXCHANGE_AND_VALIDATOR_STAKE_AUDIT.md)
— including why a green 19/19 integration run did not catch it.

## 7. What is still not unified

* **`qrdx-wallet send --from-system-wallet`** now fails with an explicit message.
  It built a UTXO transaction, and the UTXO set is empty from genesis onward, so it
  could only ever fail with "No UTXOs found"; it needs rebuilding on the account
  path.
* **Exchange operations remain PQ-only senders.** `ExchangeTransaction` binds to a
  Dilithium key, so a `0x` account cannot open a perp position or place a CLOB
  order. Native transfers and contract calls are now symmetric; exchange ops are
  not.
* **The legacy UTXO ledger** is vestigial — still read as a fallback in
  `get_address_balance`, never written after genesis.

## 8. Tests

| File | Covers |
|---|---|
| `tests/test_account_id.py` | derivation contract: determinism, idempotence, injectivity, domain separation, strict rejection |
| `tests/test_pq_transaction.py` | type-0x51 envelope, sender binding, tamper rejection, intrinsic floor, parser + mempool integration, legacy path untouched |
| `tests/test_unified_ledger_cross_type.py` | one ledger row per account; **both transfer directions through the real EVM**; PQ contract-creation sender |
| `tests/test_pq_reorg_rebuild_equivalence.py` | the reorg gate: rebuild == forward apply for chains with PQ allocations and PQ transactions |
| `tests/test_evm_value_transfer_conservation.py` | exact-amount transfers; supply conservation; gas floor charged |
| `integration_tests/scenarios/s04b_cross_type_transfers.py` | end-to-end on real nodes, both directions, cross-node agreement |
