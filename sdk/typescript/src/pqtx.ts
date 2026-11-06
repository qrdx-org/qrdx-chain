/**
 * PQ EVM transactions, type 0x51 (qrdx/transactions/pq_tx.py): an ML-DSA-65 key sends to the EVM
 * with no Ethereum key — transfers, contract calls (a PQ smart account's `execute`), deployments.
 *
 *   wire     0x51 · rlp([chain_id, nonce, gas_price, gas_limit, to, value, data, on_behalf_of,
 *                        public_key, signature])
 *   signed   keccak256(0x51 · rlp([the first eight]))
 *   hash     keccak256(wire)
 *
 * The sender is the key's account id; there is no sender field to forge. Send the wire bytes
 * with `eth_sendRawTransaction`.
 */

import { keccak_256 } from "@noble/hashes/sha3.js";

import { bytesToHex, concat, minimalBytes, toBytes, type BytesLike } from "./bytes.ts";
import { type PQKey } from "./keys.ts";

export const PQ_TX_TYPE = 0x51;
const BASE_GAS = 21_000n;
const VERIFY_GAS = 40_000n;
const CREATE_GAS = 32_000n;
const ENVELOPE_BYTE_GAS = 16n;

type Int = number | bigint | string;
export type RlpItem = Uint8Array | RlpItem[];

function rlpLength(length: number, offset: number): Uint8Array {
  if (length < 56) return Uint8Array.of(offset + length);
  const len = minimalBytes(length);
  return concat(Uint8Array.of(offset + 55 + len.length), len);
}

export function rlpEncode(item: RlpItem): Uint8Array {
  if (item instanceof Uint8Array) {
    if (item.length === 1 && item[0] < 0x80) return item;
    return concat(rlpLength(item.length, 0x80), item);
  }
  const body = concat(...item.map(rlpEncode));
  return concat(rlpLength(body.length, 0xc0), body);
}

export interface PQTxFields {
  chainId: Int;
  nonce: Int;
  /** Wei per gas: at least the block's base fee (`eth_gasPrice`). */
  gasPrice: Int;
  gasLimit: Int;
  /** The recipient (20-byte `0x…`, or an account id); absent to deploy a contract. */
  to?: string | null;
  value?: Int;
  data?: BytesLike;
  /** A system wallet to spend from, by its controller (rare). */
  onBehalfOf?: string | null;
}

function unsigned(f: PQTxFields): Uint8Array[] {
  return [
    minimalBytes(f.chainId),
    minimalBytes(f.nonce),
    minimalBytes(f.gasPrice),
    minimalBytes(f.gasLimit),
    f.to ? address20(f.to) : new Uint8Array(),
    minimalBytes(f.value ?? 0),
    toBytes(f.data ?? new Uint8Array()),
    f.onBehalfOf ? address20(f.onBehalfOf) : new Uint8Array(),
  ];
}

function address20(address: string): Uint8Array {
  const b = toBytes(address);
  if (b.length !== 20) throw new TypeError(`not a 20-byte address: ${address}`);
  return b;
}

/** The 32-byte digest the key signs. */
export function pqTxSigningHash(f: PQTxFields): Uint8Array {
  return keccak_256(concat(Uint8Array.of(PQ_TX_TYPE), rlpEncode(unsigned(f))));
}

/** The wire bytes of the transaction signed by `key`, and its hash (both `0x…`). */
export function signPQTx(f: PQTxFields, key: PQKey): { raw: string; hash: string } {
  const signature = key.sign(pqTxSigningHash(f));
  return encodePQTx(f, key.publicKey, signature);
}

export function encodePQTx(
  f: PQTxFields,
  publicKey: Uint8Array,
  signature: Uint8Array,
): { raw: string; hash: string } {
  const raw = concat(Uint8Array.of(PQ_TX_TYPE), rlpEncode([...unsigned(f), publicKey, signature]));
  return { raw: bytesToHex(raw, true), hash: bytesToHex(keccak_256(raw), true) };
}

/** The least gas the transaction must offer before it runs: 21,000, the signature's
 *  verification and its 5.3 KB envelope, the calldata, and a deployment's surcharge. */
export function pqTxIntrinsicGas(f: PQTxFields, publicKeyLength = 1952, signatureLength = 3309): bigint {
  let gas = BASE_GAS + VERIFY_GAS + (f.to ? 0n : CREATE_GAS);
  for (const byte of toBytes(f.data ?? new Uint8Array())) gas += byte === 0 ? 4n : 16n;
  return gas + BigInt(publicKeyLength + signatureLength) * ENVELOPE_BYTE_GAS;
}
