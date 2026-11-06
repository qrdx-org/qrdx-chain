/**
 * PQ smart accounts (contracts/accounts/PQSmartAccount.sol, docs/PQ_SMART_ACCOUNTS.md): contract
 * accounts owned by an ML-DSA-65 key, with session keys, ERC-1271 and guardian recovery. The
 * implementation and the factory are predeployed at genesis.
 *
 * An account runs a batch of calls when its owner (or a session key) signs `executeHash`; anyone
 * may submit the signed `execute` — a relayer, or the owner's own key in a type-0x51 transaction.
 */

import { keccak_256 } from "@noble/hashes/sha3.js";

import { abiEncode, encodeCall, type AbiType } from "./abi.ts";
import { bytesToHex, concat, hexToBytes, toBytes, utf8, type BytesLike } from "./bytes.ts";
import { type PQKey } from "./keys.ts";

export const IMPLEMENTATION_ADDRESS = "0x0000000000000000000000000000000000000600";
export const FACTORY_ADDRESS = "0x0000000000000000000000000000000000000601";
export const DOMAIN = bytesToHex(keccak_256(utf8("QRDX PQSmartAccount v1")), true);

const CALLS: AbiType = { array: { tuple: ["address", "uint256", "bytes"] } };
const CALLS_SIG = "(address,uint256,bytes)[]";
const PROXY_HEAD = hexToBytes("3d602d80600a3d3981f3363d3d373d3d3d363d73");
const PROXY_TAIL = hexToBytes("5af43d82803e903d91602b57fd5bf3");

type Int = number | bigint | string;

export interface Call {
  target: string;
  value?: Int;
  data?: BytesLike;
}

function callTuples(calls: Call[]): unknown[] {
  return calls.map((c) => [c.target, c.value ?? 0, c.data ?? new Uint8Array()]);
}

export interface ExecuteRequest {
  chainId: Int;
  account: string;
  /** The account's next nonce (`nonce()`). */
  nonce: Int;
  /** Unix time after which the signature is no good; 0 for none. */
  validUntil?: Int;
  calls: Call[];
}

/** What the owner or a session key signs for `execute` (the contract's `executeHash`). */
export function executeHash(r: ExecuteRequest): string {
  return bytesToHex(
    keccak_256(
      abiEncode(
        ["bytes32", "uint256", "address", "uint256", "uint256", CALLS],
        [DOMAIN, r.chainId, r.account, r.nonce, r.validUntil ?? 0, callTuples(r.calls)],
      ),
    ),
    true,
  );
}

/** `execute(calls, nonce, validUntil, publicKey, signature)` calldata. */
export function encodeExecute(
  r: ExecuteRequest,
  publicKey: BytesLike,
  signature: BytesLike,
): string {
  return encodeCall(
    `execute(${CALLS_SIG},uint256,uint256,bytes,bytes)`,
    [CALLS, "uint256", "uint256", "bytes", "bytes"],
    [callTuples(r.calls), r.nonce, r.validUntil ?? 0, publicKey, signature],
  );
}

/** Sign the batch with `key` (the owner's or a session key) and return the calldata. */
export function signExecute(r: ExecuteRequest, key: PQKey): string {
  const signature = key.sign(hexToBytes(executeHash(r)));
  return encodeExecute(r, key.publicKey, signature);
}

/** What the owner signs for an application to check with ERC-1271 `isValidSignature(hash, …)`. */
export function erc1271Digest(chainId: Int, account: string, hash: BytesLike): string {
  return bytesToHex(
    keccak_256(abiEncode(["bytes32", "uint256", "address", "bytes32"], [DOMAIN, chainId, account, hash])),
    true,
  );
}

/** The `signature` argument of `isValidSignature(hash, signature)`: abi.encode(publicKey, sig). */
export function erc1271Signature(key: PQKey, chainId: Int, account: string, hash: BytesLike): string {
  const signature = key.sign(hexToBytes(erc1271Digest(chainId, account, hash)));
  return bytesToHex(abiEncode(["bytes", "bytes"], [key.publicKey, signature]), true);
}

/** Where the factory creates the account of `ownerKeyHash` and `salt` (CREATE2), before it
 *  exists: fund it there first, then create it. */
export function predictAccount(
  ownerKeyHash: BytesLike,
  salt: BytesLike = new Uint8Array(32),
  factory: string = FACTORY_ADDRESS,
  implementation: string = IMPLEMENTATION_ADDRESS,
): string {
  const init = concat(PROXY_HEAD, toBytes(implementation), PROXY_TAIL);
  const s = keccak_256(abiEncode(["bytes32", "bytes32"], [ownerKeyHash, salt]));
  const hash = keccak_256(concat(Uint8Array.of(0xff), toBytes(factory), s, keccak_256(init)));
  return bytesToHex(hash.slice(12), true);
}

/** Calldata: the factory's `create(ownerKey, salt)`. */
export function encodeCreate(ownerKeyHash: BytesLike, salt: BytesLike = new Uint8Array(32)): string {
  return encodeCall("create(bytes32,bytes32)", ["bytes32", "bytes32"], [ownerKeyHash, salt]);
}

// The account's own settings: each is a call to the account itself, run through `execute`.

export function encodeSetSessionKey(keyHash: BytesLike, validUntil: Int, valuePerDay: Int): string {
  return encodeCall("setSessionKey(bytes32,uint64,uint128)", ["bytes32", "uint64", "uint128"], [
    keyHash,
    validUntil,
    valuePerDay,
  ]);
}

export function encodeSetOwnerKey(keyHash: BytesLike): string {
  return encodeCall("setOwnerKey(bytes32)", ["bytes32"], [keyHash]);
}

export function encodeSetGuardians(guardians: string[], threshold: Int, delaySeconds: Int): string {
  return encodeCall(
    "setGuardians(address[],uint256,uint256)",
    [{ array: "address" }, "uint256", "uint256"],
    [guardians, threshold, delaySeconds],
  );
}

export function encodeCancelRecovery(): string {
  return encodeCall("cancelRecovery()", [], []);
}

// Guardians and anyone else call these directly.

export function encodeApproveRecovery(newOwnerKeyHash: BytesLike): string {
  return encodeCall("approveRecovery(bytes32)", ["bytes32"], [newOwnerKeyHash]);
}

export function encodeCompleteRecovery(): string {
  return encodeCall("completeRecovery()", [], []);
}

// Reads (eth_call).

export const READ = {
  nonce: encodeCall("nonce()", [], []),
  ownerKey: encodeCall("ownerKey()", [], []),
  implementation: encodeCall("implementation()", [], []),
} as const;
