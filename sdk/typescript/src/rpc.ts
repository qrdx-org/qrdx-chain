/**
 * A JSON-RPC client for a QRDX node (its `/rpc` endpoint): the exchange, PQ EVM transactions, and
 * PQ smart accounts. Request bodies are rendered as the node's Python reads them, so integers of
 * any size (bigints) arrive exact.
 */

import { bytesToHex, hexToBytes, toBigInt, type BytesLike } from "./bytes.ts";
import { signExchangeTx, type ExchangeTxFields, type SignedExchangeTx } from "./exchange.ts";
import { type PQKey } from "./keys.ts";
import { type ExchangeOpName } from "./ops.ts";
import { pqTxIntrinsicGas, signPQTx, type PQTxFields } from "./pqtx.ts";
import { pyJsonDumps } from "./pyjson.ts";
import {
  FACTORY_ADDRESS,
  READ,
  encodeCreate,
  predictAccount,
  signExecute,
  type Call,
} from "./smartAccount.ts";

export class RpcError extends Error {
  readonly code: number | undefined;
  readonly data: unknown;

  constructor(method: string, error: { code?: number; message?: string; data?: unknown }) {
    super(`${method}: ${error.message ?? "error"}`);
    this.code = error.code;
    this.data = error.data;
  }
}

type Fetch = (url: string, init: { method: string; headers: Record<string, string>; body: string }) =>
  Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

export interface ClientOptions {
  fetch?: Fetch;
  /** How long `wait*` helpers poll before giving up. */
  timeoutMs?: number;
  pollMs?: number;
}

type Int = number | bigint | string;

export class QrdxClient {
  readonly url: string;
  #fetch: Fetch;
  #id = 0;
  #chainId: bigint | undefined;
  readonly timeoutMs: number;
  readonly pollMs: number;

  constructor(url: string, options: ClientOptions = {}) {
    this.url = url;
    this.#fetch = options.fetch ?? (globalThis.fetch as unknown as Fetch);
    this.timeoutMs = options.timeoutMs ?? 60_000;
    this.pollMs = options.pollMs ?? 500;
  }

  async call<T = unknown>(method: string, params: unknown[] = []): Promise<T> {
    const body = pyJsonDumps({ jsonrpc: "2.0", id: ++this.#id, method, params });
    const res = await this.#fetch(this.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
    const reply = (await res.json()) as { result?: T; error?: { code?: number; message?: string } };
    if (reply.error) throw new RpcError(method, reply.error);
    if (!res.ok) throw new RpcError(method, { code: res.status, message: `HTTP ${res.status}` });
    return reply.result as T;
  }

  async chainId(): Promise<bigint> {
    this.#chainId ??= toBigInt(await this.call<string>("eth_chainId"));
    return this.#chainId;
  }

  // ── the exchange ──────────────────────────────────────────────────────────────────────────

  async exchangeNonce(sender: string, signer?: string): Promise<bigint> {
    return toBigInt(await this.call<Int>("exchange_getNonce", [sender, signer ?? null]));
  }

  async exchangeGasPrice(): Promise<bigint> {
    return toBigInt(await this.call<Int>("exchange_gasPrice"));
  }

  /** Submit a signed transaction; returns its hash. The node refuses one whose payer cannot pay
   *  `gas_limit × gas_price` now. */
  async sendExchangeTx(tx: SignedExchangeTx): Promise<string> {
    return await this.call<string>("exchange_sendTransaction", [tx]);
  }

  async exchangeReceipt(txHash: string): Promise<Record<string, unknown> | null> {
    return await this.call("exchange_getTransactionReceipt", [txHash]);
  }

  async waitForExchangeReceipt(txHash: string): Promise<Record<string, unknown>> {
    return await this.#wait(`exchange transaction ${txHash}`, () => this.exchangeReceipt(txHash));
  }

  /** Build, sign and submit an exchange operation, filling in the nonce, price and chain id. */
  async sendExchange(
    key: PQKey,
    op: ExchangeOpName | number,
    params: Record<string, unknown>,
    options: { sender?: string; gasLimit?: Int; gasPrice?: Int } = {},
  ): Promise<string> {
    const sender = options.sender ?? key.address;
    const signer = sender === key.address ? undefined : key.address;
    const fields: ExchangeTxFields = {
      op,
      sender,
      signer,
      params,
      nonce: await this.exchangeNonce(sender, signer),
      gasLimit: options.gasLimit ?? 200_000,
      gasPrice: options.gasPrice ?? (await this.exchangeGasPrice()),
      chainId: await this.chainId(),
    };
    return await this.sendExchangeTx(signExchangeTx(fields, key));
  }

  // ── the EVM ───────────────────────────────────────────────────────────────────────────────

  async balance(address: string): Promise<bigint> {
    return toBigInt(await this.call<string>("eth_getBalance", [address, "latest"]));
  }

  async gasPrice(): Promise<bigint> {
    return toBigInt(await this.call<string>("eth_gasPrice"));
  }

  async ethCall(to: string, data: BytesLike): Promise<string> {
    const input = typeof data === "string" ? data : bytesToHex(data, true);
    return await this.call<string>("eth_call", [{ to, data: input }, "latest"]);
  }

  async receipt(txHash: string): Promise<Record<string, unknown> | null> {
    return await this.call("eth_getTransactionReceipt", [txHash]);
  }

  async waitForReceipt(txHash: string): Promise<Record<string, unknown>> {
    return await this.#wait(`transaction ${txHash}`, () => this.receipt(txHash));
  }

  /** Send a type-0x51 transaction from `key`'s account; returns its hash. The nonce, price
   *  (twice the current, for headroom) and chain id are filled in; the gas limit defaults to the
   *  intrinsic gas plus 300,000. */
  async sendPQTransaction(
    key: PQKey,
    tx: { to?: string | null; value?: Int; data?: BytesLike; gasLimit?: Int; gasPrice?: Int },
  ): Promise<string> {
    const fields: PQTxFields = {
      chainId: await this.chainId(),
      nonce: toBigInt(await this.call<string>("eth_getTransactionCount", [key.accountId, "pending"])),
      gasPrice: tx.gasPrice ?? (await this.gasPrice()) * 2n,
      gasLimit: 0,
      to: tx.to ?? null,
      value: tx.value ?? 0,
      data: tx.data ?? new Uint8Array(),
    };
    fields.gasLimit = tx.gasLimit ?? pqTxIntrinsicGas(fields) + 300_000n;
    const { raw } = signPQTx(fields, key);
    return await this.call<string>("eth_sendRawTransaction", [raw]);
  }

  // ── PQ smart accounts ─────────────────────────────────────────────────────────────────────

  /** The account `key` owns at `salt` (it may not exist yet). */
  smartAccountAddress(key: PQKey, salt?: BytesLike): string {
    return predictAccount(key.keyHash, salt);
  }

  async smartAccountExists(account: string): Promise<boolean> {
    const owner = await this.ethCall(account, READ.ownerKey).catch(() => "0x");
    return hexToBytes(owner).some((b) => b !== 0);
  }

  async smartAccountNonce(account: string): Promise<bigint> {
    return toBigInt(await this.ethCall(account, READ.nonce));
  }

  /** Create `key`'s account through the predeployed factory, sent by `key` itself (0x51). */
  async createSmartAccount(key: PQKey, salt?: BytesLike): Promise<string> {
    return await this.sendPQTransaction(key, {
      to: FACTORY_ADDRESS,
      data: encodeCreate(key.keyHash, salt),
    });
  }

  /** Run `calls` from `account`, signed by `key` (its owner or a session key) and submitted by
   *  `submitter` (default: the same key, from its own account, paying the gas). */
  async executeFromSmartAccount(
    account: string,
    key: PQKey,
    calls: Call[],
    options: { validUntil?: Int; submitter?: PQKey; gasLimit?: Int } = {},
  ): Promise<string> {
    const data = signExecute(
      {
        chainId: await this.chainId(),
        account,
        nonce: await this.smartAccountNonce(account),
        validUntil: options.validUntil ?? 0,
        calls,
      },
      key,
    );
    return await this.sendPQTransaction(options.submitter ?? key, {
      to: account,
      data,
      gasLimit: options.gasLimit,
    });
  }

  async #wait<T>(what: string, poll: () => Promise<T | null>): Promise<T> {
    const deadline = Date.now() + this.timeoutMs;
    for (;;) {
      const got = await poll();
      if (got) return got;
      if (Date.now() > deadline) throw new Error(`${what}: not included within ${this.timeoutMs} ms`);
      await new Promise((resolve) => setTimeout(resolve, this.pollMs));
    }
  }
}
