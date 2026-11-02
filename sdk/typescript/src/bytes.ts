/** Byte helpers shared by the SDK. Hex in and out is lowercase; a `0x` prefix is accepted. */

export type Hex = string;
export type BytesLike = Uint8Array | Hex;

export function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) {
    throw new TypeError(`not hex: ${hex.slice(0, 20)}…`);
  }
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function bytesToHex(bytes: Uint8Array, prefix = false): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return prefix ? "0x" + s : s;
}

export function toBytes(value: BytesLike): Uint8Array {
  return typeof value === "string" ? hexToBytes(value) : value;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function toBigInt(value: number | bigint | string): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new TypeError(`${value} is not a safe integer: pass a bigint or a decimal string`);
    }
    return BigInt(value);
  }
  if (!/^(0x[0-9a-fA-F]+|[0-9]+)$/.test(value)) throw new TypeError(`not an integer: ${value}`);
  return BigInt(value);
}

/** Big-endian, exactly `width` bytes. */
export function uintBytes(value: number | bigint | string, width: number): Uint8Array {
  let v = toBigInt(value);
  if (v < 0n || v >= 1n << BigInt(8 * width)) throw new RangeError(`${v} does not fit ${width} bytes`);
  const out = new Uint8Array(width);
  for (let i = width - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Big-endian, no leading zeros (zero is empty): RLP's integer form. */
export function minimalBytes(value: number | bigint | string): Uint8Array {
  let v = toBigInt(value);
  if (v < 0n) throw new RangeError("negative integer");
  const out: number[] = [];
  while (v > 0n) {
    out.unshift(Number(v & 0xffn));
    v >>= 8n;
  }
  return Uint8Array.from(out);
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}
