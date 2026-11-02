/**
 * Exchange transactions (qrdx/exchange/transactions.py): built, hashed and signed exactly as the
 * node does, then sent with `exchange_sendTransaction`.
 *
 * The signed bytes are
 *   "QRDX-EXCHANGE-TX-v1\0" · chain id (8 bytes) · op (1) · sender (UTF-8) · nonce (8) ·
 *   params as Python's json.dumps(sort_keys=True) · gas limit (8) · gas price (decimal text)
 *   [· "\0signer:" · signer]
 * and the transaction hash is BLAKE2b-256 of them.
 */

import { blake2b } from "@noble/hashes/blake2.js";

import { bytesToHex, concat, toBigInt, uintBytes, utf8 } from "./bytes.ts";
import { type PQKey } from "./keys.ts";
import { EXCHANGE_OPS, type ExchangeOpName } from "./ops.ts";
import { pyJsonDumps } from "./pyjson.ts";

const TAG = concat(utf8("QRDX-EXCHANGE-TX-v1"), Uint8Array.of(0));

type Int = number | bigint | string;

export interface ExchangeTxFields {
  /** The operation: its name (`"PERP_ORDER"`) or number. */
  op: ExchangeOpName | number;
  /** The account it acts for (`0xPQ…`). */
  sender: string;
  nonce: Int;
  /** Amounts and prices as decimal strings; integers as numbers or bigints. */
  params: Record<string, unknown>;
  gasLimit?: Int;
  /** Wei per gas: at least `exchange_gasPrice` (0 only in the free trading lane). */
  gasPrice: Int;
  chainId: Int;
  /** The key that signs, when it is not the sender's own: an approved agent, a controller, a
   *  sub-account's master. Its nonces are its own lane (`exchange_getNonce(sender, signer)`). */
  signer?: string;
}

/** The JSON object `exchange_sendTransaction` takes. */
export interface SignedExchangeTx {
  op_type: number;
  sender: string;
  nonce: bigint;
  params: Record<string, unknown>;
  gas_limit: bigint;
  gas_price: string;
  timestamp: number;
  signature: string;
  public_key: string;
  chain_id: bigint;
  signer?: string;
  tx_hash: string;
}

export function opNumber(op: ExchangeOpName | number): number {
  const n = typeof op === "number" ? op : EXCHANGE_OPS[op];
  if (n === undefined || !Number.isInteger(n) || n < 0 || n > 255) throw new RangeError(`unknown op ${op}`);
  return n;
}

function normalized(fields: ExchangeTxFields) {
  const signer = fields.signer && fields.signer !== fields.sender ? fields.signer : "";
  return {
    op: opNumber(fields.op),
    sender: fields.sender,
    nonce: toBigInt(fields.nonce),
    params: fields.params,
    gasLimit: toBigInt(fields.gasLimit ?? 100_000),
    gasPrice: toBigInt(fields.gasPrice),
    chainId: toBigInt(fields.chainId),
    signer,
  };
}

/** The bytes the signer signs. */
export function signingBytes(fields: ExchangeTxFields): Uint8Array {
  const f = normalized(fields);
  const parts = [
    TAG,
    uintBytes(f.chainId, 8),
    Uint8Array.of(f.op),
    utf8(f.sender),
    uintBytes(f.nonce, 8),
    utf8(pyJsonDumps(f.params)),
    uintBytes(f.gasLimit, 8),
    utf8(f.gasPrice.toString()),
  ];
  if (f.signer) parts.push(concat(Uint8Array.of(0), utf8("signer:" + f.signer)));
  return concat(...parts);
}

/** The transaction hash (hex, no prefix), as the node reports it. */
export function exchangeTxHash(fields: ExchangeTxFields): string {
  return bytesToHex(blake2b(signingBytes(fields), { dkLen: 32 }));
}

/** Sign with `key`, which must be the signer's (or the sender's own). */
export function signExchangeTx(fields: ExchangeTxFields, key: PQKey): SignedExchangeTx {
  const f = normalized(fields);
  const signing = f.signer || f.sender;
  if (key.address.toLowerCase() !== signing.toLowerCase()) {
    throw new Error(`this key is ${key.address}, not ${signing}`);
  }
  const bytes = signingBytes(fields);
  return {
    op_type: f.op,
    sender: f.sender,
    nonce: f.nonce,
    params: f.params,
    gas_limit: f.gasLimit,
    gas_price: f.gasPrice.toString(),
    timestamp: Math.floor(Date.now() / 1000), // (not signed: the node sets its own if absent)
    signature: bytesToHex(key.sign(bytes)),
    public_key: bytesToHex(key.publicKey),
    chain_id: f.chainId,
    ...(f.signer ? { signer: f.signer } : {}),
    tx_hash: bytesToHex(blake2b(bytes, { dkLen: 32 })),
  };
}
