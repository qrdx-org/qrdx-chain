/**
 * QRDX addresses (qrdx/crypto/address.py, qrdx/crypto/account_id.py).
 *
 * - A PQ account's address is `0xPQ` + the first 32 bytes of keccak256(its ML-DSA-65 public key),
 *   checksummed like EIP-55.
 * - Its account id, the 20-byte address the ledger and the EVM know it by (`msg.sender`, balances),
 *   is the last 20 bytes of keccak256("QRDX-ACCOUNT-ID-v1:pq:" + those 32 bytes).
 * - A `0x` address is its own account id.
 */

import { keccak_256 } from "@noble/hashes/sha3.js";

import { bytesToHex, concat, hexToBytes, utf8 } from "./bytes.ts";

const PQ = "0xPQ";
const ACCOUNT_ID_DOMAIN = "QRDX-ACCOUNT-ID-v1";

function checksum(lowerHex: string): string {
  const hash = bytesToHex(keccak_256(utf8(lowerHex)));
  let out = "";
  for (let i = 0; i < lowerHex.length; i++) {
    const ch = lowerHex[i];
    out += /[0-9]/.test(ch) ? ch : parseInt(hash[i % hash.length], 16) >= 8 ? ch.toUpperCase() : ch;
  }
  return out;
}

/** The `0xPQ…` address of an ML-DSA-65 public key. */
export function pqAddress(publicKey: Uint8Array): string {
  return PQ + checksum(bytesToHex(keccak_256(publicKey).slice(0, 32)));
}

/** A 20-byte `0x` address in EIP-55 form. */
export function checksumAddress(address: string): string {
  const h = address.toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{40}$/.test(h)) throw new TypeError(`not a 20-byte address: ${address}`);
  return "0x" + checksum(h);
}

export function isPQAddress(address: string): boolean {
  return /^0x[Pp][Qq][0-9a-fA-F]{64}$/.test(address);
}

/** The lowercase `0x` account id any address form names (`0xPQ…` or `0x…`). */
export function accountId(address: string): string {
  if (isPQAddress(address)) {
    const payload = hexToBytes(address.slice(4).toLowerCase());
    const digest = keccak_256(concat(utf8(ACCOUNT_ID_DOMAIN + ":pq:"), payload));
    return bytesToHex(digest.slice(12), true);
  }
  const h = address.toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{40}$/.test(h)) throw new TypeError(`unrecognised address: ${address}`);
  return "0x" + h;
}
