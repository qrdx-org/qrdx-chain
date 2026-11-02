// The SDK against vectors the node's own code computed (scripts/sdk/make_vectors.py): every byte a
// wallet signs or sends must be the node's.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  EXCHANGE_OPS,
  PQKey,
  accountId,
  bytesToHex,
  encodeCreate,
  encodeExecute,
  encodePQTx,
  encodeSetGuardians,
  encodeSetSessionKey,
  erc1271Digest,
  executeHash,
  exchangeTxHash,
  hexToBytes,
  pqTxIntrinsicGas,
  pqTxSigningHash,
  predictAccount,
  pyJsonDumps,
  signExchangeTx,
  signExecute,
  signingBytes,
  verify,
  type ExchangeOpName,
  type PQTxFields,
} from "../src/index.ts";
import { abiEncode } from "../src/abi.ts";
import { DOMAIN, IMPLEMENTATION_ADDRESS, FACTORY_ADDRESS } from "../src/smartAccount.ts";

const V = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));
const key = PQKey.fromSecretKey(V.key.secret_key, V.key.public_key);

test("a key from the node's wallet format, and its addresses", () => {
  assert.equal(bytesToHex(key.publicKey), V.key.public_key);
  assert.equal(key.address, V.key.address);
  assert.equal(key.accountId, V.key.account_id);
  assert.equal(key.keyHash, V.key.key_hash);
  for (const [address, id] of Object.entries(V.account_ids)) assert.equal(accountId(address), id);
  assert.throws(() => PQKey.fromSecretKey(V.key.secret_key, "00".repeat(1952)), /does not belong/);
});

test("a deterministic key from a seed", () => {
  const a = PQKey.generate(new Uint8Array(32).fill(7));
  const b = PQKey.generate(new Uint8Array(32).fill(7));
  assert.equal(a.address, b.address);
  assert.notEqual(a.address, PQKey.generate().address);
});

test("Python's json.dumps(sort_keys=True), to the byte", () => {
  for (const { value, text } of V.pyjson) assert.equal(pyJsonDumps(value), text);
  assert.equal(pyJsonDumps({ n: 2n ** 70n }), '{"n": 1180591620717411303424}');
  assert.throws(() => pyJsonDumps({ price: 1.5 }), /decimal string/);
});

test("exchange transactions: signed bytes, hash, and signatures both ways", () => {
  for (const v of V.exchange) {
    const f = v.fields;
    const fields = {
      op: f.op as ExchangeOpName,
      sender: f.sender,
      signer: f.signer || undefined,
      nonce: f.nonce,
      params: f.params,
      gasLimit: f.gas_limit,
      gasPrice: f.gas_price,
      chainId: f.chain_id,
    };
    assert.equal(EXCHANGE_OPS[f.op as ExchangeOpName], f.op_type);
    assert.equal(bytesToHex(signingBytes(fields)), v.canonical);
    assert.equal(exchangeTxHash(fields), v.tx_hash);
    assert.ok(verify(key.publicKey, signingBytes(fields), v.signature), "the node's signature");
    const signed = signExchangeTx(fields, key);
    assert.equal(signed.tx_hash, v.tx_hash);
    assert.ok(verify(key.publicKey, hexToBytes(v.canonical), signed.signature), "ours");
  }
  const other = PQKey.generate();
  const f = V.exchange[0].fields;
  assert.throws(
    () => signExchangeTx({ ...f, op: f.op, gasPrice: f.gas_price, chainId: f.chain_id }, other),
    /not 0xPQ/,
  );
});

test("PQ transactions (0x51): signing hash, wire bytes, hash, intrinsic gas", () => {
  for (const v of V.pq_tx) {
    const f = v.fields;
    const fields: PQTxFields = {
      chainId: f.chain_id,
      nonce: f.nonce,
      gasPrice: f.gas_price,
      gasLimit: f.gas_limit,
      to: f.to,
      value: f.value,
      data: f.data,
    };
    assert.equal(bytesToHex(pqTxSigningHash(fields)), v.signing_hash);
    const encoded = encodePQTx(fields, key.publicKey, hexToBytes(v.signature));
    assert.equal(encoded.raw, "0x" + v.raw);
    assert.equal(encoded.hash, "0x" + v.hash);
    assert.equal(pqTxIntrinsicGas(fields), BigInt(v.intrinsic_gas));
    assert.ok(verify(key.publicKey, pqTxSigningHash(fields), v.signature));
  }
});

test("smart accounts: executeHash, calldata, ERC-1271, CREATE2 address", () => {
  const s = V.smart_account;
  assert.equal(DOMAIN, s.domain);
  assert.equal(IMPLEMENTATION_ADDRESS, s.implementation);
  assert.equal(FACTORY_ADDRESS, s.factory);
  const request = {
    chainId: s.chain_id,
    account: s.account,
    nonce: s.nonce,
    validUntil: s.valid_until,
    calls: s.calls,
  };
  assert.equal(executeHash(request), s.execute_hash);
  assert.equal(encodeExecute(request, key.publicKey, s.fake_signature), s.execute_calldata);
  assert.equal(erc1271Digest(s.chain_id, s.account, s.message), s.erc1271_digest);
  assert.equal(bytesToHex(abiEncode(["bytes", "bytes"], [key.publicKey, s.fake_signature]), true), s.erc1271_param);
  assert.equal(predictAccount(s.owner_key, s.salt), s.account);
  assert.equal(encodeCreate(s.owner_key, s.salt), s.create_calldata);
  assert.equal(encodeSetSessionKey(s.owner_key, 1_900_000_000, 5n * 10n ** 18n), s.session_calldata);
  assert.equal(encodeSetGuardians(s.guardians, 2, 86_400), s.guardians_calldata);
  const calldata = signExecute(request, key);
  assert.equal(calldata.slice(0, 10), s.execute_calldata.slice(0, 10));
});
