//! Writing JSON as Python's `json` writes it with `ensure_ascii=True`: the pieces shared by the
//! encoder of Python objects (lib.rs, a block's body root) and of parsed JSON (tx.rs, a
//! transaction's signed bytes).

use serde_json::Value;

pub trait Sink {
    fn put(&mut self, bytes: &[u8]);
}

impl Sink for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

pub const HEX: &[u8; 16] = b"0123456789abcdef";

fn write_u16_escape<S: Sink>(out: &mut S, unit: u16) {
    out.put(&[
        b'\\',
        b'u',
        HEX[(unit >> 12) as usize & 0xf],
        HEX[(unit >> 8) as usize & 0xf],
        HEX[(unit >> 4) as usize & 0xf],
        HEX[unit as usize & 0xf],
    ]);
}

/// A JSON string as Python's ensure_ascii encoder writes it: printable ASCII as is (bar `"` and
/// `\`), the short escapes, every other character as `\uXXXX` (lowercase hex; a surrogate pair
/// above U+FFFF).
pub fn write_str<S: Sink>(out: &mut S, s: &str) {
    out.put(b"\"");
    let bytes = s.as_bytes();
    // Most strings need no escape at all (hex, addresses): written in one piece.
    if !bytes
        .iter()
        .any(|&b| !(0x20..=0x7e).contains(&b) || b == b'"' || b == b'\\')
    {
        out.put(bytes);
        out.put(b"\"");
        return;
    }
    let mut start = 0;
    for (i, ch) in s.char_indices() {
        let c = ch as u32;
        let plain = (0x20..=0x7e).contains(&c) && ch != '"' && ch != '\\';
        if plain {
            continue;
        }
        if start < i {
            out.put(&bytes[start..i]);
        }
        start = i + ch.len_utf8();
        match ch {
            '"' => out.put(b"\\\""),
            '\\' => out.put(b"\\\\"),
            '\n' => out.put(b"\\n"),
            '\r' => out.put(b"\\r"),
            '\t' => out.put(b"\\t"),
            '\u{08}' => out.put(b"\\b"),
            '\u{0c}' => out.put(b"\\f"),
            _ => {
                let mut units = [0u16; 2];
                for unit in ch.encode_utf16(&mut units) {
                    write_u16_escape(out, *unit);
                }
            }
        }
    }
    if start < bytes.len() {
        out.put(&bytes[start..]);
    }
    out.put(b"\"");
}

/// A parsed value that cannot be written here exactly as Python would write what `json.loads`
/// made of it.
#[derive(Debug)]
pub struct NotExact;

/// `json.dumps(json.loads(text), sort_keys=True, ensure_ascii=True)` with the given separators,
/// for JSON already parsed (numbers keep their text: serde_json's arbitrary_precision).
/// Python reads a number with a fraction or an exponent as a float and writes it back by its
/// own rules: those, and `-0`, are not written here.
pub fn write_value<S: Sink>(
    out: &mut S,
    value: &Value,
    item: &[u8],
    key: &[u8],
    depth: u32,
) -> Result<(), NotExact> {
    if depth > 900 {
        return Err(NotExact);
    }
    match value {
        Value::Null => out.put(b"null"),
        Value::Bool(b) => out.put(if *b { b"true" } else { b"false" }),
        Value::String(s) => write_str(out, s),
        Value::Number(n) => {
            let text = n.to_string();
            if text.contains(['.', 'e', 'E']) || text == "-0" {
                return Err(NotExact);
            }
            out.put(text.as_bytes());
        }
        Value::Array(items) => {
            out.put(b"[");
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.put(item);
                }
                write_value(out, v, item, key, depth + 1)?;
            }
            out.put(b"]");
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            // Python sorts keys by code point; UTF-8 bytes sort the same.
            entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.put(b"{");
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.put(item);
                }
                write_str(out, k);
                out.put(key);
                write_value(out, v, item, key, depth + 1)?;
            }
            out.put(b"}");
        }
    }
    Ok(())
}
