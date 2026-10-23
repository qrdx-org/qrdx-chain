# Account control — binding wallets, multisig, turning a key off

Who may sign for an account is consensus state. An account can bind other wallets to it as
**controllers**, turn its **own key** off, and put a **delay** on changes its own key makes.
**Multisig** wallets (m-of-n Dilithium) sign like any other key, on the exchange and in the EVM.

| Code | What |
|---|---|
| `qrdx/exchange/authority.py` | Policies and waiting changes (committed in the exchange root) |
| `qrdx/crypto/multisig_wire.py` | Multisig keys and signatures in a transaction's fields |
| `qrdx/exchange/state_manager.py` | `ACCOUNT_POLICY`, `signer_error` (who may sign), the tick applying waiting changes |
| `qrdx/contracts/evm_mempool.py` | `verify_delegated_spend`: the same rules for EVM transactions |
| `qrdx/transactions/pq_tx.py` | Type-0x51 EVM transactions signed by a multisig |
| Tests | `tests/test_account_control.py` |

---

## 1. A policy

| Field | |
|---|---|
| `controllers` | Up to 5 accounts — a `0xPQ…` key or a `0xPQMS…` multisig — that may sign **anything** for the account |
| `own_key` | Whether the account's own key may still sign (default on). Off: only its controllers sign for it |
| `delay` | Seconds of block time a change signed by the account's own key waits (default 0; at most 30 days) |
| `guardians` | Up to 7 addresses, a `threshold` and a `recovery_delay` (1–30 days, default 7): social recovery (§6) |

**Controllers are the root of trust.** A change a controller signs applies at once, and any
controller may cancel a waiting change. A change the account's own key signs waits out the delay
(lengthening the delay excepted) and applies in the tick of the first block after it is due —
unless the own key was turned off meanwhile, or the change no longer fits the policy.

So the usual setup is a hot wallet bound to a cold one (or to a 2-of-3 multisig of your devices),
with a delay. A stolen hot key's attempt to bind a thief sits in the open for a day; the cold
wallet cancels it, or turns the stolen key off at once. With the own key off, the hot address's
key signs nothing at all — on the exchange or in the EVM — and its funds move only by its
controllers.

**Rules that hold at every step:**

- An account whose own key is off keeps at least one controller.
- A controller is never the account itself.
- A key whose own account turned it off signs for nothing — not as a controller, not as an agent.
  Agent keys an account approved act only while that account's own key is on.
- Controllers are direct: a controller of a controller is not a controller.

To need several signers, make the controller a multisig.

## 2. `ACCOUNT_POLICY` (70)

`{"action": …}`, 40,000 gas, signed by the account's own key or by a controller (as `signer`):

| action | params | signed by its own key |
|---|---|---|
| `add_controller` | `controller` | waits |
| `remove_controller` | `controller` | waits |
| `own_key` | `enabled` (true / false) | waits |
| `delay` | `seconds` | lengthening at once, shortening waits |
| `guardians` | `guardians` (list), `threshold`, `recovery_delay` (seconds) — `[]` clears | waits |
| `cancel` | `change_id` | — (cancels a waiting change, a recovery included) |

Signed by a controller, every action applies at once. The receipt says whether it applied, or the
`change_id` and when it is `due`. Agents, sub-account masters and vault leaders cannot change a
policy. At most 10 changes wait per account.

## 3. Acting for an account

**Exchange.** A transaction with `sender` the account and `signer` a controller — signed by the
controller's key or multisig — may be any operation (withdrawals included). Its nonce comes from
the `sender|signer` lane (`exchange_getNonce(address, signer)`); the account pays its gas. A
transaction refused for authority consumes nothing.

**EVM.** A type-0x51 transaction signed by a controller with `on_behalf_of` the account runs **as
the account**: value leaves it, and contracts see it as `msg.sender` (`tx.origin` is the
controller). The controller pays the gas and its nonce is used. An account whose own key is off
cannot sign a 0x51 transaction for itself. The check runs at mempool admission, when a proposer
builds its section and when every node imports it, against the policies applied up to that
block's exchange section — each block's exchange section runs before its EVM section on every
path, so every node reaches the same verdict.

Policies are filed under canonical account ids (`qrdx/crypto/account_id.py`), so the exchange,
which names accounts as signed, and the EVM, which uses 20-byte ids, agree.

## 4. Multisig

A `0xPQMS…` address is derived from an m-of-n keyset: its sorted Dilithium public keys and its
threshold (`qrdx/crypto/threshold_dilithium.py`). A transaction signed by one carries:

- **`public_key`**: the keyset, `{"m", "n", "public_keys": [hex…]}`, as canonical JSON. A keyset
  is never the length of a single Dilithium key (1,952 bytes), which is how the two are told
  apart: a raw key may begin with any byte.
- **`signature`**: the aggregate, at least m members' Dilithium signatures over the
  domain-tagged message.

The address is derived from the keyset, never taken as sent. Keysets that sign transactions hold
at most 20 keys.

- **Exchange transactions:** a multisig may be the `sender` (a multisig account) or the `signer`
  (a multisig controller). Each partial signature costs 20,000 gas
  (`MULTISIG_GAS_PER_SIGNATURE`); admission refuses a gas limit that does not cover them before
  verifying anything.
- **EVM:** a type-0x51 transaction may be signed by a multisig. Its sender is the multisig's
  account id, and each partial signature costs `PQ_TX_VERIFY_GAS` (40,000), on top of the
  envelope's per-byte gas.

`multisig_wire.sign(keyset, member_keys, message)` produces the two fields for a wallet that
coordinates the signers.

## 5. Agent spending limits

`AGENT_APPROVE {agent, valid_until?, name?, max_notional_per_day?}` (docs/TRADING_FEATURES.md):
a limited agent may **place** at most `max_notional_per_day` a block day, in the perps settlement
asset — every order at its full size × limit price, filled or not, so what a stolen bot key can
trade is bounded. Cancels count nothing; a failed operation counts nothing. What cannot be valued
before it runs is refused to a limited agent: a spot market order, a swap or a spot TWAP that does
not spend the settlement asset, a spot pair not priced in it. A batch counts its actions. The
limit follows the agent wherever it acts for its grantor (the grantor's sub-accounts and vaults).
`account_getAuthority` shows each agent's limit and what it has placed today; revoking an agent
forgets its count.

## 6. Social recovery

For an account whose keys are all lost. Its policy names `guardians` (post-quantum keys or
multisigs, never the account itself), a `threshold` and a `recovery_delay`:

1. A guardian backs a new controller: `ACCOUNT_RECOVER (75) {account, new_controller}`, 40,000
   gas, signed by the guardian. `new_controller: ""` withdraws its backing; backing another
   replaces it.
2. When `threshold` guardians back the same controller, a `recover` change is queued, due after
   the `recovery_delay` — visible in `account_getAuthority`'s `pending_changes`.
3. Meanwhile the account's own key, or any controller, may `cancel` it (`ACCOUNT_POLICY cancel
   {change_id}`, at once).
4. When due, it binds the new controller **in place of all others** and turns the own key off.
   The backing is spent.

Setting guardians is a policy change like any: signed by the own key it waits out the account's
`delay`, so a stolen key cannot quietly name its own guardians and recover the account to itself.
A controller sets them at once. `account_getControlled(guardian)` lists `guardian_of`.

## 7. Limits

- **Legacy `0x` accounts can't hold a policy.** They are secp256k1 keys, and exchange
  transactions are post-quantum only, so a policy cannot be created for one. To protect funds in
  a legacy account, move them to a post-quantum account and turn its key over to controllers.
- **The legacy UTXO ledger ignores policies.** It is vestigial (KNOWN_ISSUES).
- **A controller has full authority.** Bind only wallets you control, and prefer a multisig for
  the cold side.
