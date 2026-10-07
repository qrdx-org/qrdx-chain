# Native tokens

Every fungible token on QRDX is a **native token**: a registry entry plus balances in the
consensus token ledger. There is no token contract to deploy or audit — like an SPL mint on
Solana or a HIP-1 token on Hyperliquid, a token is data and authorities. Spot pools, the order
books and perps collateral all move native tokens; the code is `qrdx/exchange/tokens.py`.

Status (2026-10-06): the standard is live in consensus (operations, API, CLI, forward ≡ rebuild
equivalence, integration scenarios S20/S21), and every native token is an ERC-20 and ERC-777
inside the EVM (§6) — wallets send it, contracts hold and move it. Tokens opt into
Token-2022-style **extensions** (§7): metadata, transfer fees, soulbound, default-frozen,
permanent delegate, pause, ERC-777 operators. **NFTs** are native too (§8): collections of
supply-1 tokens, each collection an ERC-721 in the EVM. Native QRDX trades against any token
with no wrapping ([PERPS_API.md §7](PERPS_API.md)). Not yet: retiring the old
`qrdx/tokens/qrc20.py` class ([KNOWN_ISSUES.md](KNOWN_ISSUES.md)).

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
| `extensions` | the extensions it was deployed with, and their state (§7); `{}` for a plain token |

Authorities are addresses in any form (`0xPQ…`, `0x…`); they are shown as given and compared by
account id, so every form of one account is the same authority — and the same holder.

## 2. Operations

Exchange transactions, signed with a post-quantum key (see [PERPS_API.md §1](PERPS_API.md)).

| op | # | params | who |
|---|---|---|---|
| `TOKEN_DEPLOY` | 13 | `name`, `symbol`, `decimals` (18), `total_supply` (0), `max_supply`, `mint_authority`, `freeze_authority` | anyone; a token needs an initial supply or a mint authority. The supply goes to the deployer |
| `TOKEN_MINT` | 26 | `token_address`, `amount`, `to` (default: the sender) | the mint authority, within `max_supply` |
| `TOKEN_BURN` | 27 | `token_address`, `amount`, `from` (default: the sender) | any holder, from its own balance; another holder's: its operator or the permanent delegate |
| `TOKEN_TRANSFER` | 14 | `token_address`, `to`, `amount`, `memo` (≤ 256 bytes) | any holder |
| `TOKEN_APPROVE` | 28 | `token_address`, `spender`, `amount` (sets it; 0 revokes) | any holder |
| `TOKEN_TRANSFER_FROM` | 29 | `token_address`, `from`, `to`, `amount`, `memo` | a spender within its allowance (which it uses up), an operator of `from`'s, or the permanent delegate — the receipt's `via` says which |
| `TOKEN_SET_AUTHORITY` | 30 | `token_address`, `authority` (`mint` \| `freeze` \| `metadata` \| `fee` \| `withdraw` \| `pause` \| `permanent_delegate`), `new_authority` (empty renounces) | the current authority. Renouncing is irreversible |
| `TOKEN_FREEZE` / `TOKEN_THAW` | 31 / 32 | `token_address`, `account` | the freeze authority |
| `TOKEN_UPDATE_METADATA` | 33 | `token_address`, `name`, `symbol`, `uri`, `fields` (`{key: value}`; null removes) | the metadata authority |
| `TOKEN_SET_TRANSFER_FEE` | 34 | `token_address`, `transfer_fee_bps`, `max_transfer_fee` | the fee authority; applies 100 blocks later |
| `TOKEN_WITHDRAW_FEES` | 35 | `token_address`, `to` (default: the sender) | the withdraw authority |
| `TOKEN_PAUSE` / `TOKEN_RESUME` | 36 / 37 | `token_address` | the pause authority |
| `TOKEN_AUTHORIZE_OPERATOR` / `TOKEN_REVOKE_OPERATOR` | 38 / 39 | `token_address`, `operator` | any holder |

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
| | `exchange_isTokenOperator(token, holder, operator)` | an operator (authorized or default) |

A token's `extensions` are part of `/get_token` and `exchange_getToken`. The transfer fees a
token has withheld are the balance of the token's own address (`/get_token_balance` with
`address` = the token).

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

# extensions, chosen at deploy (§7)
qrdx-wallet token deploy wallet.json "Ext" EXT --supply 1000 --uri ipfs://… --field site=qrdx.org \
    --transfer-fee-bps 25 [--max-transfer-fee 5] [--non-transferable] [--default-frozen] \
    [--permanent-delegate self] [--pausable] [--default-operator <address>]
qrdx-wallet token metadata wallet.json <token> [--name] [--symbol] [--uri] [--field k=v | k=]
qrdx-wallet token set-fee  wallet.json <token> <bps> [--max-fee N]
qrdx-wallet token withdraw-fees wallet.json <token> [--to <address>]
qrdx-wallet token pause | resume wallet.json <token>
qrdx-wallet token operator | revoke-operator wallet.json <token> <operator>
qrdx-wallet token transfer wallet.json <token> <to> 25 --memo "invoice 42"
```

Writes accept `--wait` (print the receipt) and `--yes` (no confirmation).

## 6. In the EVM: every native token is an ERC-20 (and an ERC-777)

A call to a native token's address runs a precompile over the native ledger
(`qrdx/contracts/native_token_evm.py`): `name()`, `symbol()`, `decimals()`, `totalSupply()`,
`balanceOf(owner)`, `allowance(owner, spender)`, `transfer(to, amount)`,
`approve(spender, amount)`, `transferFrom(from, to, amount)`, with the standard `Transfer` and
`Approval` logs. The ERC-777 interface is there too — `granularity()` (1),
`defaultOperators()`, `isOperatorFor(operator, holder)`, `authorizeOperator(operator)`,
`revokeOperator(operator)`, `send(to, amount, data)`, `operatorSend(from, to, amount, data,
operatorData)`, `burn(amount, data)`, `operatorBurn(from, amount, data, operatorData)`, with the
`Sent`, `Burned`, `AuthorizedOperator` and `RevokedOperator` events (no `tokensReceived` hooks)
— and ERC-1046's `tokenURI()` (the metadata uri) and `paused()`. `transferFrom` also accepts
the holder's operators and the permanent delegate. There is one ledger and one set of allowances: an `approve` from the EVM is
the allowance `TOKEN_TRANSFER_FROM` spends, and a balance moved by either side is the other's.
So a web3 wallet adds the token by its address and sends it like any ERC-20, and contracts —
DEXes, vaults, escrows — hold and move native tokens.

* **Units:** the token's base units, 10^-`decimals`; `balanceOf` rounds down (the ledger counts
  1e-18 for every token, so dust below a token's decimals is neither shown nor movable here).
* **Accounts:** a `0x` account is its own id; a PQ account's EVM id is its derived account id.
  A contract's balance is keyed by the contract's address.
* **Rules:** a frozen account cannot send, a paused or non-transferable token does not move,
  a transfer fee is withheld at the token's address (a second `Transfer` log shows it); a
  transfer to the zero address, beyond the balance, or beyond the allowance reverts with a
  reason; QRDX sent with the call, `DELEGATECALL` and writes inside a static call revert.
* **Consistency:** a transaction's moves are journaled on its EVM state, so a reverted call
  frame undoes them; a block's moves are written to the ledger only when its EVM section is
  accepted, and later transactions in the block see earlier ones'.
* **Code size:** inside the EVM a token's address reports a one-byte stub, so Solidity's
  `extcodesize` check passes even for functions that return nothing (ERC-777 `send`). The
  stub is never stored: `eth_getCode` returns empty, and the precompile always runs instead.

## 7. Extensions (Token-2022-style) and operators (ERC-777)

Like an SPL Token-2022 mint, a token opts into extensions **when it is deployed**
(`TOKEN_DEPLOY` parameters); a token without them is committed exactly as before they existed.

| extension | deploy parameters | behaviour |
|---|---|---|
| metadata | `uri` (≤ 256), `metadata` (≤ 16 `{key: value}`), `metadata_authority` (default: the deployer; empty = immutable) | the authority edits name, symbol, uri and fields (`TOKEN_UPDATE_METADATA`); EVM `tokenURI()` |
| transfer fee | `transfer_fee_bps` (0–10000), `max_transfer_fee`, `fee_authority`, `withdraw_authority` (both default: the deployer) | every holder-to-holder transfer (native or EVM) withholds `amount × bps / 10000` (rounded up to 1e-18, capped) from what the recipient gets; it is held by the token's own address until `TOKEN_WITHDRAW_FEES`. A new rate (`TOKEN_SET_TRANSFER_FEE`) applies **100 blocks** later, so no transfer is surprised by it |
| non-transferable | `non_transferable: true` | soulbound: minted and burned, never moved between holders |
| default-frozen | `default_frozen: true` (needs a freeze authority) | every account starts frozen until the freeze authority thaws it (KYC'd assets); the deployer starts thawed, and the token's own address (its fee vault) is never frozen by default |
| permanent delegate | `permanent_delegate` | may transfer (`TOKEN_TRANSFER_FROM`) and burn (`TOKEN_BURN` with `from`) anyone's balance without an allowance — a regulated issuer's clawback. Frozen balances stay frozen |
| pausable | `pausable: true`, `pause_authority` (default: the deployer) | `TOKEN_PAUSE` stops every transfer, mint and burn of the token — spot and perps moves included — until `TOKEN_RESUME` |
| default operators | `default_operators` (≤ 8 addresses) | ERC-777: operators for every holder, until that holder revokes one |

**Operators (ERC-777).** Any holder may authorize operators (`TOKEN_AUTHORIZE_OPERATOR`, at
most 64 per holder across tokens) that move and burn its balance without an allowance, and
revoke them — default operators included. A holder is always its own operator.

**Spot.** Transfer-fee and non-transferable tokens cannot be pooled or traded on a book
(`CREATE_POOL` refuses them): spot moves are exact, and a fee withheld on the way into a pool
would break its accounting. A paused token's pool and book stop with it.

Tested: `tests/test_token_extensions.py` (every extension natively and through the EVM, the
ERC-777 interface, supply = Σ balances with fees withheld, the registry committed and
reverted, the CLI); integration scenario S21 (a fee token across the live nodes).

## 8. NFTs

NFTs are native, defined by data and authorities like fungible tokens
(`qrdx/exchange/nfts.py`). A **collection** is a token group (Token-2022's group extension,
Metaplex's collection): name, symbol, metadata uri, an optional size cap, royalty information
(`royalty_bps`, `royalty_recipient` — for marketplaces, ERC-2981), an **update authority** and
a **mint authority** (both the creator unless given; either can be handed over or renounced).
Each **NFT** is a member with a supply of one and no decimals: its token id (sequential from 1,
or chosen at mint), its owner, its own uri and name. Only the mint authority mints into a
collection, so every member is verified. A collection may be soulbound (`non_transferable`).

| op | # | params | who |
|---|---|---|---|
| `NFT_CREATE_COLLECTION` | 40 | `name`, `symbol`, `uri`, `max_supply`, `royalty_bps`, `royalty_recipient`, `update_authority`, `mint_authority`, `non_transferable` | anyone; the address derives from the transaction |
| `NFT_MINT` | 41 | `collection`, `to` (default: the sender), `uri`, `name`, `token_id` (default: the next) | the mint authority, within `max_supply` |
| `NFT_TRANSFER` | 42 | `collection`, `token_id`, `to`, `from` (default: the sender), `memo` | the owner, the NFT's approved account, or an operator of the owner's |
| `NFT_BURN` | 43 | `collection`, `token_id` | the same |
| `NFT_APPROVE` | 44 | `collection`, `token_id`, `spender` (empty clears) | the owner or its operator |
| `NFT_SET_APPROVAL_FOR_ALL` | 45 | `collection`, `operator`, `approved` (default true) | any owner (≤ 64 operators) |
| `NFT_UPDATE` | 46 | `collection`, `token_id` (an NFT; else the collection), `name`, `symbol`, `uri`, `royalty_bps`, `royalty_recipient` | the update authority |
| `NFT_SET_AUTHORITY` | 47 | `collection`, `authority` (`update` \| `mint`), `new_authority` (empty renounces) | the current authority |

A transfer clears the NFT's approval. The registry (collections, NFTs, approvals, operators)
is exchange state — replayed on every path and committed in the exchange root once the first
collection exists.

**In the EVM every collection is an ERC-721** at its address (`qrdx/contracts/nft_evm.py`):
`name`, `symbol`, `totalSupply`, `balanceOf`, `ownerOf`, `tokenURI`, `getApproved`,
`isApprovedForAll`, `approve`, `setApprovalForAll`, `transferFrom`, both `safeTransferFrom`s
(a contract recipient must answer `onERC721Received`), ERC-165 `supportsInterface`, ERC-2981
`royaltyInfo` and `contractURI` — with the standard events, journaled and committed like the
token precompile's. Minting, burning and metadata are the native operations'.

| REST | JSON-RPC | |
|---|---|---|
| `GET /get_nft_collections` | `exchange_getNftCollections` | every collection |
| `GET /get_nft_collection?collection=` | `exchange_getNftCollection` | one collection |
| `GET /get_nft?collection=&token_id=` | `exchange_getNft` | one NFT, with its collection's royalties |
| `GET /get_nfts?owner=&collection=` | `exchange_getNftsOf` | an owner's NFTs (0x or 0xPQ form) |
| | `exchange_isNftOperator(collection, owner, operator)` | an operator |

```
qrdx-wallet nft collections | info <collection> | show <collection> <id> | owned <owner>
qrdx-wallet nft create   wallet.json "Quantum Art" QART --uri ipfs://… --royalty-bps 500 [--max-supply N] [--soulbound]
qrdx-wallet nft mint     wallet.json <collection> [--to <address>] [--uri …] [--name …] [--token-id N]
qrdx-wallet nft transfer wallet.json <collection> <id> <to> [--from <owner>] [--memo …]
qrdx-wallet nft approve | burn | approve-all [--revoke] | update | set-authority …
```

Tested: `tests/test_nfts.py` (every operation and refusal, owners under either address form,
the ERC-721 interface incl. safe transfers to contracts, forward ≡ rebuild, the CLI);
integration scenario S21 (a collection minted, moved natively and by an ERC-721 `transferFrom`,
read on every node natively and through `ownerOf`).

## 9. Next

* **Retire** `qrdx/tokens/qrc20.py` (used by no consensus path; integration scenarios S05/S06
  still drive it on a scratch database). The simulated EVM exchange precompiles 0x0100–0x0104
  are retired already: reserved, they revert.
* **Bridges.** A bridged stablecoin is a token deployed with zero supply and the bridge as mint
  authority: minted when a deposit is proven, burned by the holder to withdraw. That is the piece
  mainnet perps wait on ([PERPS_CLEARINGHOUSE.md](PERPS_CLEARINGHOUSE.md)).
