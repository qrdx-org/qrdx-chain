/**
 * ML-DSA-65 (FIPS 204) keys, through @noble/post-quantum. Interoperable with the node's liboqs:
 * the same key encodings (a 1,952-byte public key, a 4,032-byte secret key) and 3,309-byte
 * signatures, verified both ways (`tests/test_sdk_vectors.py`).
 */

import { keccak_256 } from "@noble/hashes/sha3.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import { accountId, pqAddress } from "./address.ts";
import { bytesToHex, equalBytes, toBytes, type BytesLike } from "./bytes.ts";

export const PUBLIC_KEY_LENGTH = 1952;
export const SECRET_KEY_LENGTH = 4032;
export const SIGNATURE_LENGTH = 3309;

export class PQKey {
  readonly publicKey: Uint8Array;
  readonly #secretKey: Uint8Array;

  private constructor(secretKey: Uint8Array, publicKey: Uint8Array) {
    this.#secretKey = secretKey;
    this.publicKey = publicKey;
  }

  /** A new key; from `seed` (32 bytes) deterministically, else from the platform's randomness. */
  static generate(seed?: Uint8Array): PQKey {
    const { secretKey, publicKey } = ml_dsa65.keygen(seed);
    return new PQKey(secretKey, publicKey);
  }

  /** A key from its secret key (the node's wallet format: `private_key` hex). The public key is
   *  derived; if `publicKey` is given too, it must match. */
  static fromSecretKey(secretKey: BytesLike, publicKey?: BytesLike): PQKey {
    const sk = toBytes(secretKey);
    if (sk.length !== SECRET_KEY_LENGTH) throw new RangeError(`a secret key is ${SECRET_KEY_LENGTH} bytes`);
    const pk = ml_dsa65.getPublicKey(sk);
    if (publicKey !== undefined && !equalBytes(pk, toBytes(publicKey))) {
      throw new Error("the public key does not belong to this secret key");
    }
    return new PQKey(sk, pk);
  }

  /** The `0xPQ…` address. */
  get address(): string {
    return pqAddress(this.publicKey);
  }

  /** The 20-byte account id (balances, `msg.sender`). */
  get accountId(): string {
    return accountId(this.address);
  }

  /** keccak256 of the public key: what a PQ smart account stores as its owner or session key. */
  get keyHash(): string {
    return bytesToHex(keccak_256(this.publicKey), true);
  }

  sign(message: Uint8Array): Uint8Array {
    return ml_dsa65.sign(message, this.#secretKey);
  }

  /** The secret key, hex: handle with care. */
  exportSecretKey(): string {
    return bytesToHex(this.#secretKey);
  }
}

export function verify(publicKey: BytesLike, message: Uint8Array, signature: BytesLike): boolean {
  try {
    return ml_dsa65.verify(toBytes(signature), message, toBytes(publicKey));
  } catch {
    return false;
  }
}

