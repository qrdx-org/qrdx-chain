# QNS — the QRDX Name Service

Human-readable names for addresses, at the protocol level. A name is a **native NFT**
(docs/NATIVE_TOKENS.md §8) in a protocol collection, so it transfers, approves, shows in wallets
and works in the EVM as an ERC-721, like any NFT.

| | |
|---|---|
| Code | `qrdx/exchange/qns.py`, the `QNS_*` operations in `qrdx/exchange/state_manager.py` |
| Collection | `QNS_COLLECTION` (fixed address), symbol `QNS`; mint and update authority `QNS_AUTHORITY` (`0xQNSA…`, no key) |
| Price | `QNS_PRICE_PER_YEAR` (chain-spec) — **0.0125 QRDX a year** (~$5) by default for 5 or more characters; 32× for 4 characters, 128× for 3 (`qns.price_factor`); paid to the treasury |
| Tests | `tests/test_qns.py` |

## Names

A name is `label.qrdx`. The label is 3–59 of `a-z`, `0-9` and `-`, and does not start or end
with a hyphen. Names are lowercased, and the `.qrdx` may be left off when registering. A name's
NFT has token id `blake2b-256(name)`, its NFT name is the name itself, and its uri is
`qns://<name>`.

Only QNS operations mint into the collection; no key can. An owner may burn the NFT, which
gives the name up at once.

## Operations

| op | # | params | gas |
|---|---|---|---|
| `QNS_REGISTER` | 71 | `name`, `years` (1–10, default 1), `target` (default: the sender) | 80,000 + the price |
| `QNS_RENEW` | 72 | `name`, `years` — anyone may pay; at most 10 years ahead | 40,000 + the price |
| `QNS_SET_RECORD` | 73 | `name`, `key`, `value` — `address` (where it resolves; `""` clears) or a text record (up to 16; key ≤ 32, value ≤ 256 characters) | 30,000 |
| `QNS_SET_PRIMARY` | 74 | `name` (`""` clears) — the sender's reverse record | 25,000 |

Records are set by the name's owner: whoever holds the NFT, or an account it approved for the
NFT, or an operator.

## Lifetime

A name resolves until it **expires**. During the 30-day **grace period** after that, it doesn't
resolve, but only renewal is open: no one else can register it. After the grace period anyone
may register it, the old NFT is burned and its records are cleared.

A **primary name** (reverse record) counts only while that name resolves to the account that set
it. Transfer the name, point it elsewhere, or let it expire, and the reverse lookup returns
nothing.

## Reading

| method | |
|---|---|
| `qns_resolve(name)` | The address it resolves to (null: unregistered, expired, or no address record) |
| `qns_reverse(address)` | Its primary name, while valid |
| `qns_getName(name)` | Owner, token id, expiry, grace, records |
| `qns_namesOf(address)` | The names it owns |
| `qns_price(years)` | QRDX for that many years |

`account_getControlled(address)` lists the names an address owns too.
