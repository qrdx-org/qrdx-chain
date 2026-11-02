/**
 * Python's `json.dumps(value, sort_keys=True)`, exactly: an exchange transaction's signed bytes
 * contain its params rendered that way (qrdx/exchange/transactions.py), so a wallet must produce
 * the same text to the byte. Keys sorted by code point; ", " and ": " separators; every
 * character outside printable ASCII escaped as \uXXXX (UTF-16), as `ensure_ascii` does.
 *
 * Numbers must be integers (a safe integer or a bigint): Python prints a float differently from
 * JavaScript (1.0 vs 1), so amounts and prices go as decimal strings, as the node expects.
 */

const SHORT: Record<string, string> = {
  '"': '\\"',
  "\\": "\\\\",
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
  "\b": "\\b",
  "\f": "\\f",
};

function quote(text: string): string {
  let out = '"';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const code = text.charCodeAt(i); // (a UTF-16 unit: astral characters come as two)
    if (SHORT[ch] !== undefined) out += SHORT[ch];
    else if (code < 0x20 || code > 0x7e) out += "\\u" + code.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

function byCodePoint(a: string, b: string): number {
  const x = Array.from(a);
  const y = Array.from(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = (x[i].codePointAt(0) as number) - (y[i].codePointAt(0) as number);
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

export function pyJsonDumps(value: unknown): string {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") return quote(value);
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new TypeError(`${value}: give a decimal string (Python prints floats differently)`);
    }
    return String(value);
  }
  if (Array.isArray(value)) return "[" + value.map(pyJsonDumps).join(", ") + "]";
  if (typeof value === "object") {
    const keys = Object.keys(value as object).sort(byCodePoint);
    const items = keys
      .filter((k) => (value as Record<string, unknown>)[k] !== undefined)
      .map((k) => quote(k) + ": " + pyJsonDumps((value as Record<string, unknown>)[k]));
    return "{" + items.join(", ") + "}";
  }
  throw new TypeError(`cannot render ${typeof value} as JSON`);
}
