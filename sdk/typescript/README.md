# @qrdx/sdk

QRDX in TypeScript, for browsers and Node.js (22.18 or later):

* **Keys and addresses.** ML-DSA-65 (FIPS 204) keys through
  [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum). They interoperate with
  the node's liboqs: same encodings, and signatures verify both ways. Derives the `0xPQ…` address
  and the 20-byte account id.
* **Exchange transactions.** Signed bytes and hash exactly as the node computes them, including
  params rendered as Python's `json.dumps(sort_keys=True)`.
* **PQ EVM transactions (type `0x51`).** An ML-DSA-65 key sends to the EVM with no Ethereum key.
* **PQ smart accounts.** `executeHash`, signed `execute` calldata, ERC-1271 signatures, the
  account's address before it exists, and the settings calls (session keys, guardians, owner
  key, recovery). The implementation and factory are predeployed at genesis.
* **A JSON-RPC client** that fills in nonces, prices and the chain id.

```ts
import { PQKey, QrdxClient } from "@qrdx/sdk";

const node = new QrdxClient("http://127.0.0.1:3007/rpc");
const key = PQKey.generate(); // or PQKey.fromSecretKey(wallet.private_key)

// The exchange
const hash = await node.sendExchange(key, "PERP_ORDER", {
  market_id: "BTC-QRDX-PERP", side: "buy", size: "0.01", price: "30000", tif: "alo",
});
await node.waitForExchangeReceipt(hash);

// A smart account: its address is known before it exists, so it can be funded first.
const account = node.smartAccountAddress(key);
await node.waitForReceipt(await node.createSmartAccount(key));
await node.executeFromSmartAccount(account, key, [{ target: "0x…", value: 10n ** 18n }]);
```

Amounts and prices in exchange params are decimal strings. A float is refused, because Python
prints floats differently and the signature would not match.

## Development

```
npm ci --ignore-scripts
npm test            # against vectors the node's own code computed
npm run typecheck
npm run build       # dist/
```

The vectors come from `python scripts/sdk/make_vectors.py`. On the Python side,
`tests/test_sdk_vectors.py` fails when they are stale. It checks the smart-account values
against the contract running in the QRDX EVM, and verifies with liboqs what this SDK signs.

Not audited. Like the smart-account contract it drives, it guards funds: have it reviewed before
relying on it for value.
