/**
 * Solidity ABI encoding — as much as the SDK's contracts need: unsigned integers, addresses,
 * bytes32, bytes, arrays and tuples, with head/tail encoding of dynamic values.
 */

import { keccak_256 } from "@noble/hashes/sha3.js";

import { bytesToHex, concat, toBigInt, toBytes, uintBytes, utf8, type BytesLike } from "./bytes.ts";

export type AbiType =
  | "uint256"
  | "uint128"
  | "uint64"
  | "address"
  | "bytes32"
  | "bytes"
  | { array: AbiType }
  | { tuple: AbiType[] };

function isDynamic(t: AbiType): boolean {
  if (t === "bytes") return true;
  if (typeof t === "string") return false;
  if ("array" in t) return true;
  return t.tuple.some(isDynamic);
}

function word(n: bigint): Uint8Array {
  return uintBytes(n, 32);
}

function encodeOne(t: AbiType, v: unknown): Uint8Array {
  if (t === "uint256" || t === "uint128" || t === "uint64") {
    const n = toBigInt(v as number | bigint | string);
    const bits = BigInt(t.slice(4));
    if (n >= 1n << bits) throw new RangeError(`${n} does not fit ${t}`);
    return word(n);
  }
  if (t === "address") {
    const b = toBytes(v as string);
    if (b.length !== 20) throw new TypeError(`not an address: ${v}`);
    return concat(new Uint8Array(12), b);
  }
  if (t === "bytes32") {
    const b = toBytes(v as BytesLike);
    if (b.length !== 32) throw new TypeError("bytes32 must be 32 bytes");
    return b;
  }
  if (t === "bytes") {
    const b = toBytes(v as BytesLike);
    const padded = new Uint8Array(Math.ceil(b.length / 32) * 32);
    padded.set(b);
    return concat(word(BigInt(b.length)), padded);
  }
  if ("array" in t) {
    const items = v as unknown[];
    return concat(word(BigInt(items.length)), encodeSequence(items.map(() => t.array), items));
  }
  return encodeSequence(t.tuple, v as unknown[]);
}

function encodeSequence(types: AbiType[], values: unknown[]): Uint8Array {
  if (types.length !== values.length) throw new TypeError("wrong number of values");
  const heads: Uint8Array[] = [];
  const tails: Uint8Array[] = [];
  let tailOffset = types.reduce((n, t) => n + (isDynamic(t) ? 32 : headSize(t)), 0);
  types.forEach((t, i) => {
    const encoded = encodeOne(t, values[i]);
    if (isDynamic(t)) {
      heads.push(word(BigInt(tailOffset)));
      tails.push(encoded);
      tailOffset += encoded.length;
    } else {
      heads.push(encoded);
    }
  });
  return concat(...heads, ...tails);
}

function headSize(t: AbiType): number {
  if (typeof t === "string") return 32;
  if ("tuple" in t) return t.tuple.reduce((n, x) => n + headSize(x), 0);
  return 32;
}

/** `abi.encode(values...)`. */
export function abiEncode(types: AbiType[], values: unknown[]): Uint8Array {
  return encodeSequence(types, values);
}

/** The 4-byte selector of a function signature, e.g. `"create(bytes32,bytes32)"`. */
export function selector(signature: string): Uint8Array {
  return keccak_256(utf8(signature)).slice(0, 4);
}

/** Calldata: the selector, then the arguments; `0x…`. */
export function encodeCall(signature: string, types: AbiType[], values: unknown[]): string {
  return bytesToHex(concat(selector(signature), abiEncode(types, values)), true);
}
