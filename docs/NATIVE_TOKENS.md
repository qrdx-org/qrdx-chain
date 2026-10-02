# Native tokens

Every fungible token on QRDX is a **native token**: a registry entry plus balances in the
consensus token ledger. There is no token contract to deploy or audit — like an SPL mint on
Solana or a HIP-1 token on Hyperliquid, a token is data and authorities. Spot pools, the order
books and perps collateral all move native tokens; the code is `qrdx/exchange/tokens.py`.

Status (2026-10-02): the standard is live in consensus (operations, API, CLI, forward ≡ rebuild
equivalence, integration scenario S20), and web3 wallets read native tokens as ERC-20s (§6).
Not yet: contracts using native tokens, and retiring the old `qrdx/tokens/qrc20.py` class
([KNOWN_ISSUES.md](KNOWN_ISSUES.md)).

---

## 1. A token

| field | meaning |
|---|---|
| `token_address` | `0x` + 40 hex, derived from the deploy: `blake2b(sender:nonce:symbol, 20 bytes)`. Every node derives the same one; it is also the address the EVM view will use |
| `name`, `symbol` | 1–64 and 1–16 printable characters (no spaces or `:` in a symbol). Symbols are **not** unique — identify a token by its address |
| `decimals` | 0–18, how wallets display it. The ledger itself counts in units of 1e-18 for every token |
| `total_supply` | minted − burned; always equal to the sum of all balances |
| `max_supply` | optional cap on minting |
| `mint_authority` | may mint. None = the supply is fixed forever |
| `freeze_authority` | may freeze and thaw accounts. None = no account can ever be frozen |
| `creator`, `created_height` | who deployed it, and when |

Authorities are addresses in any form (`0xPQ…`, `0x…`); they are shown as given and compared by
account id, so every form of one account is the same authority — and the same holder.

## 2. Operations

Exchange transactions, signed with a post-quantum key (see [PERPS_API.md §1](PERPS_API.md)).

| op | # | params | who |
|---|---|---|---|
| `TOKEN_DEPLOY` | 13 | `name`, `symbol`, `decimals` (18), `total_supply` (0), `max_supply`, `mint_authority`, `freeze_authority` | anyone; a token needs an initial supply or a mint authority. The supply goes to the deployer |
| `TOKEN_MINT` | 26 | `token_address`, `amount`, `to` (default: the sender) | the mint authority, within `max_supply` |
| `TOKEN_BURN` | 27 | `token_address`, `amount` | any holder, from its own balance |
| `TOKEN_TRANSFER` | 14 | `token_address`, `to`, `amount` | any holder |
| `TOKEN_APPROVE` | 28 | `token_address`, `spender`, `amount` (sets it; 0 revokes) | any holder |
| `TOKEN_TRANSFER_FROM` | 29 | `token_address`, `from`, `to`, `amount` | a spender, within its allowance, which it uses up |
| `TOKEN_SET_AUTHORITY` | 30 | `token_address`, `authority` (`mint` \| `freeze`), `new_authority` (empty renounces) | the current authority. Renouncing is irreversible |
| `TOKEN_FREEZE` / `TOKEN_THAW` | 31 / 32 | `token_address`, `account` | the freeze authority |

Amounts are positive decimals with at most 18 places. An operation that cannot execute is
refused whole and changes nothing; the receipt says why.

**Freezing.** A frozen account cannot move its balance of the token by any path — transfer,
`transfer_from`, burn, a swap, an order, a liquidity deposit, a perps deposit — but it can still
receive. Tokens it had already committed elsewhere (a resting order's escrow, a liquidity
position, perps collateral) are no longer its balance: the freeze does not reach them, and
whatever they pay back lands in the frozen balance.

**Allowances.** At most 256 non-zero allowances per owner across all tokens (approvals are state
every node carries); revoke one (approve 0) to make room.

## 3. Consensus

* The **registry, allowances and frozen accounts** are exchange state: replayed from the chain on
  every path — the proposer, importers, a restart, a reorg rebuild — and committed in the exchange
  state root. The **balances** are the token ledger (`token_balances`), committed by the token
  root. Both roots are part of the unified block state root every importer checks.
* The `token_registry` table is a mirror of the registry for queries, rewritten for each token a
  block changes and cleared with the ledger before a rebuild.
* Each block preloads the balances its operations will debit. Under enforcement (the default) a
  debit whose balance was not loaded is **refused** — never applied unchecked — so a gap in that
  list fails safe instead of overdrawing the ledger.
* Tested: `tests/test_native_tokens.py` (every operation and refusal; randomized activity keeps
  supply = Σ balances; a refused operation changes nothing; the registry reverts with a block),
  `tests/test_reorg_rebuild_equivalence.py::test_rebuild_equivalence_native_token_ops` (forward ≡
  rebuild: token root, registry, mirror), integration scenario S20 (cross-node). Soaked: 21/21
  scenarios (S20 17/17 — all four nodes agree on supply, authority, balances, allowance and
  token root), then the fault-injecting soak: SOAK PASS, with no overdraft, lost value or
  refused not-loaded debit in any node's log.

## 4. Reading

| REST | JSON-RPC | |
|---|---|---|
| `GET /get_tokens` | `exchange_getTokens` | every token |
| `GET /get_token?token_address=` | `exchange_getToken` | one token (+ how many accounts are frozen) |
| `GET /get_token_balance?token_address=&address=` | `exchange_getTokenAccount` | balance and `frozen` (`exchange_getTokenBalance` returns the balance alone) |
| `GET /get_token_allowance?token_address=&owner=&spender=` | `exchange_getAllowance` | an allowance |

## 5. CLI — `qrdx-wallet token`

```
qrdx-wallet token list | info <token> | balance <token> <address> | allowance <token> <owner> <spender>
qrdx-wallet token deploy   wallet.json "Bridged USD" qUSD --decimals 6 --mint-authority self [--max-supply N] [--freeze-authority self]
qrdx-wallet token mint     wallet.json <token> 1000 [--to <address>]
qrdx-wallet token burn     wallet.json <token> 5
qrdx-wallet token transfer wallet.json <token> <to> 25
qrdx-wallet token approve  wallet.json <token> <spender> 100
qrdx-wallet token transfer-from wallet.json <token> <owner> <to> 40
qrdx-wallet token set-authority wallet.json <token> mint <new | none>
qrdx-wallet token freeze | thaw wallet.json <token> <account>
qrdx-wallet token receipt <tx_hash>
```

Writes accept `--wait` (print the receipt) and `--yes` (no confirmation).

## 6. Web3 wallets: the ERC-20 read view

A wallet that adds a token by its address (MetaMask's "import token") reads it with `eth_call`:
`name()`, `symbol()`, `decimals()`, `totalSupply()`, `balanceOf(owner)`,
`allowance(owner, spender)`. For a native token's address the node answers those from the
registry and the ledger (`qrdx/exchange/erc20_view.py`), in the token's base units
(10^-`decimals`, rounded down — the ledger counts 1e-18, so dust below a token's decimals is
not shown). A `0x` account's balance is its account id's balance; a PQ account's EVM-visible id
is its derived account id.

What it is not:

* **Not a write path.** `transfer` / `approve` / `transferFrom` called on a native token revert
  with a pointer to the exchange operations, and an EVM transaction sent to a native token's
  address is refused at mempool admission and by `eth_estimateGas` — there is no EVM code
  there, so it would run as a no-op that still costs gas while the tokens never move.
* **Not visible to contracts.** The view lives in the RPC layer, not in EVM execution: a
  contract calling a native token's address sees an empty account.

## 7. Next: contracts, and one token system

* **Contracts.** Letting EVM contracts hold and move native tokens means EVM execution reading
  and writing this ledger synchronously, and undoing a move when an enclosing call reverts. The
  alternative Hyperliquid's HyperEVM uses is a linked ERC-20 contract per token, with explicit
  transfers between the two ledgers through a system address at block boundaries — no shared
  state inside execution. The choice is open.
* **Retire** `qrdx/tokens/qrc20.py` (used by no consensus path; integration scenarios S05/S06
  still drive it on a scratch database). The simulated EVM exchange precompiles 0x0100–0x0104
  are retired already: reserved, they revert.
* **Bridges.** A bridged stablecoin is a token deployed with zero supply and the bridge as mint
  authority: minted when a deposit is proven, burned by the holder to withdraw. That is the piece
  mainnet perps wait on ([PERPS_CLEARINGHOUSE.md](PERPS_CLEARINGHOUSE.md)).
