//! Exchange transactions in binary (qrdx/exchange/wire.py): the form's fields read and written
//! natively — a block's every operation is decoded on import — and its base64 text, strict.
//!
//! The layout is the Python module's. Reading gives the fields as Python reads them; Python then
//! builds the transaction with its own checks (``from_dict``), so a field no transaction could
//! have is refused there, as it is from JSON. A whole number past 64 bits comes back as its
//! digits (Python reads any size); anything malformed is a ``ValueError``.

use num_bigint::BigUint;
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};

const VERSION: u8 = 1;
const MAX_LEN: usize = 1 << 22;
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn bad(why: &str) -> PyErr {
    PyValueError::new_err(why.to_string())
}

/// Standard base64 with padding (``base64.b64encode``).
pub(crate) fn b64_encode(raw: &[u8]) -> String {
    let mut out = Vec::with_capacity(raw.len().div_ceil(3) * 4);
    let mut chunks = raw.chunks_exact(3);
    for c in &mut chunks {
        let n = (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
        out.extend_from_slice(&[
            ALPHABET[(n >> 18) as usize & 63],
            ALPHABET[(n >> 12) as usize & 63],
            ALPHABET[(n >> 6) as usize & 63],
            ALPHABET[n as usize & 63],
        ]);
    }
    let rest = chunks.remainder();
    if !rest.is_empty() {
        let n = (u32::from(rest[0]) << 16) | (u32::from(*rest.get(1).unwrap_or(&0)) << 8);
        out.push(ALPHABET[(n >> 18) as usize & 63]);
        out.push(ALPHABET[(n >> 12) as usize & 63]);
        out.push(if rest.len() == 2 { ALPHABET[(n >> 6) as usize & 63] } else { b'=' });
        out.push(b'=');
    }
    String::from_utf8(out).expect("the base64 alphabet is ASCII")
}

/// Each byte's base64 value; 255 for anything outside the alphabet.
const DECODE: [u8; 256] = {
    let mut t = [255u8; 256];
    let mut i = 0;
    while i < 64 {
        t[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    t
};

/// ``base64.b64decode(text, validate=True)``: only the alphabet, padding only at the end, the
/// length a multiple of four.
pub(crate) fn b64_decode(text: &[u8]) -> Option<Vec<u8>> {
    if text.len() % 4 != 0 {
        return None;
    }
    if text.is_empty() {
        return Some(Vec::new());
    }
    let (body, last) = text.split_at(text.len() - 4);
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for q in body.chunks_exact(4) {
        let (a, b, c, d) =
            (DECODE[q[0] as usize], DECODE[q[1] as usize], DECODE[q[2] as usize], DECODE[q[3] as usize]);
        if (a | b | c | d) == 255 || a > 63 || b > 63 || c > 63 || d > 63 {
            return None;
        }
        let n = (u32::from(a) << 18) | (u32::from(b) << 12) | (u32::from(c) << 6) | u32::from(d);
        out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
    }
    let pad = last.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return None;
    }
    let mut n = 0u32;
    for &c in &last[..4 - pad] {
        let v = DECODE[c as usize];
        if v > 63 {
            return None;
        }
        n = (n << 6) | u32::from(v);
    }
    n <<= 6 * pad as u32;
    out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8][..3 - pad]);
    Some(out)
}

struct Reader<'a> {
    raw: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> PyResult<u8> {
        let b = *self.raw.get(self.at).ok_or_else(|| bad("a binary transaction ends early"))?;
        self.at += 1;
        Ok(b)
    }
    fn varint(&mut self) -> PyResult<BigUint> {
        let mut n = BigUint::default();
        let mut shift = 0u64;
        loop {
            let b = self.byte()?;
            n |= BigUint::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                return Ok(n);
            }
            shift += 7;
            if shift > 70 {
                return Err(bad("a varint is too long"));
            }
        }
    }
    fn take(&mut self, n: usize) -> PyResult<&'a [u8]> {
        if n > MAX_LEN {
            return Err(bad("a binary transaction ends early"));
        }
        let end = self.at.checked_add(n).ok_or_else(|| bad("a binary transaction ends early"))?;
        let out = self.raw.get(self.at..end).ok_or_else(|| bad("a binary transaction ends early"))?;
        self.at = end;
        Ok(out)
    }
    fn field(&mut self) -> PyResult<&'a [u8]> {
        let n = usize::try_from(self.varint()?).map_err(|_| bad("a field is too long"))?;
        self.take(n)
    }
    fn text(&mut self) -> PyResult<&'a str> {
        std::str::from_utf8(self.field()?).map_err(|_| bad("a binary transaction's text is not UTF-8"))
    }
}

/// A whole number as Python takes it: an int that fits 64 bits, else its digits.
fn number(py: Python<'_>, n: BigUint) -> PyObject {
    match u64::try_from(&n) {
        Ok(v) => v.into_py(py),
        Err(_) => n.to_string().into_py(py),
    }
}

type Parsed = (
    u8,
    PyObject,
    PyObject,
    PyObject,
    (bool, PyObject),
    f64,
    String,
    String,
    String,
    PyObject,
    PyObject,
);

/// The fields of a transaction in its binary form or its text: (op_type, chain_id, nonce,
/// gas_limit, (gas price as text?, the price), timestamp, sender, signer, params JSON,
/// signature, public_key).
#[pyfunction]
pub fn wire_parse(py: Python<'_>, item: &Bound<'_, PyAny>) -> PyResult<Parsed> {
    let decoded;
    let raw: &[u8] = if let Ok(s) = item.downcast::<PyString>() {
        decoded = b64_decode(s.to_str()?.as_bytes())
            .ok_or_else(|| bad("a binary transaction's text is not base64"))?;
        &decoded
    } else if let Ok(b) = item.downcast::<PyBytes>() {
        b.as_bytes()
    } else {
        return Err(PyTypeError::new_err("a binary transaction is bytes or its text"));
    };
    let mut r = Reader { raw, at: 0 };
    if r.byte()? != VERSION {
        return Err(bad("unknown binary transaction version"));
    }
    let op_type = r.byte()?;
    let (chain_id, nonce, gas_limit) = (r.varint()?, r.varint()?, r.varint()?);
    let price = match r.byte()? {
        0 => (false, number(py, r.varint()?)),
        1 => (true, r.text()?.into_py(py)),
        _ => return Err(bad("unknown gas price form")),
    };
    let ts = r.take(8)?;
    let timestamp = f64::from_be_bytes(ts.try_into().expect("8 bytes"));
    let sender = r.text()?.to_string();
    let signer = r.text()?.to_string();
    let params = r.text()?.to_string();
    let signature = PyBytes::new_bound(py, r.field()?).into_py(py);
    let public_key = PyBytes::new_bound(py, r.field()?).into_py(py);
    if r.at != raw.len() {
        return Err(bad("bytes after a binary transaction"));
    }
    Ok((
        op_type,
        number(py, chain_id),
        number(py, nonce),
        number(py, gas_limit),
        price,
        timestamp,
        sender,
        signer,
        params,
        signature,
        public_key,
    ))
}

fn varint(out: &mut Vec<u8>, n: &BigUint) {
    let mut n = n.clone();
    let low = BigUint::from(0x7Fu8);
    loop {
        let b = u8::try_from(&n & &low).expect("seven bits");
        n >>= 7;
        if n == BigUint::default() {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn whole(v: &Bound<'_, PyAny>) -> PyResult<BigUint> {
    if let Ok(n) = v.extract::<u64>() {
        return Ok(BigUint::from(n));
    }
    let text = v.str()?;
    text.to_str()?
        .parse::<BigUint>()
        .map_err(|_| bad("a field is a whole number, not negative"))
}

fn field(out: &mut Vec<u8>, raw: &[u8]) {
    varint(out, &BigUint::from(raw.len()));
    out.extend_from_slice(raw);
}

/// The binary form from the fields (``wire.encode``'s layout); ``gas_price`` an int, or text
/// for a price that is not a whole number.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
pub fn wire_build<'py>(
    py: Python<'py>,
    op_type: u8,
    chain_id: &Bound<'_, PyAny>,
    nonce: &Bound<'_, PyAny>,
    gas_limit: &Bound<'_, PyAny>,
    gas_price: &Bound<'_, PyAny>,
    timestamp: f64,
    sender: &str,
    signer: &str,
    params: &str,
    signature: &[u8],
    public_key: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let mut out = Vec::with_capacity(64 + sender.len() + params.len() + signature.len() + public_key.len());
    out.push(VERSION);
    out.push(op_type);
    varint(&mut out, &whole(chain_id)?);
    varint(&mut out, &whole(nonce)?);
    varint(&mut out, &whole(gas_limit)?);
    if let Ok(text) = gas_price.downcast::<PyString>() {
        out.push(1);
        field(&mut out, text.to_str()?.as_bytes());
    } else {
        out.push(0);
        varint(&mut out, &whole(gas_price)?);
    }
    out.extend_from_slice(&timestamp.to_be_bytes());
    field(&mut out, sender.as_bytes());
    field(&mut out, signer.as_bytes());
    field(&mut out, params.as_bytes());
    field(&mut out, signature);
    field(&mut out, public_key);
    Ok(PyBytes::new_bound(py, &out))
}

/// ``base64.b64encode(raw).decode()``.
#[pyfunction]
pub fn wire_text(raw: &[u8]) -> String {
    b64_encode(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_as_python() {
        for (raw, text) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"\xff\x00\x10", "/wAQ"),
        ] {
            assert_eq!(b64_encode(raw), text);
            assert_eq!(b64_decode(text.as_bytes()).as_deref(), Some(raw));
        }
        for text in ["Zg=", "Z===", "Zg==Zg==", "Zm9v!", "Zm9", "=Zm9"] {
            assert_eq!(b64_decode(text.as_bytes()), None, "{text}");
        }
    }
}

/// ``peek`` of each item (qrdx/exchange/wire.py): ``(op_type, gas_limit, gas_price)`` read from
/// the head of a transaction's text — its first 64 characters, decoded strictly — where Python's
/// reader takes the fast path (a whole price); None for anything else (bytes, a price written
/// as text, a head Python would read whole, anything malformed), which ``peek`` reads or refuses.
/// A section's gas and fee rules read every item's head: in Python, about 3.4 µs each.
#[pyfunction]
pub fn wire_heads(py: Python<'_>, items: &Bound<'_, pyo3::types::PyList>) -> PyResult<PyObject> {
    let out = pyo3::types::PyList::empty_bound(py);
    for item in items.iter() {
        let head = item.downcast::<PyString>().ok().and_then(|s| {
            let text = s.to_str().ok()?.as_bytes();
            let prefix = &text[..text.len().min(64)];
            if !prefix.is_ascii() {
                return None;
            }
            head_of(&b64_decode(prefix)?)
        });
        match head {
            Some((op, gas, price)) => out.append((op, gas, price))?,
            None => out.append(py.None())?,
        }
    }
    Ok(out.into_py(py))
}

/// The fast path of ``peek``'s reader over a head: version, operation, chain id, nonce, gas
/// limit, then a whole price (tag 0). Varints as ``_Reader.varint`` reads them: up to 11 bytes,
/// any form.
fn head_of(raw: &[u8]) -> Option<(u8, u128, u128)> {
    fn varint(bytes: &mut impl Iterator<Item = u8>) -> Option<u128> {
        let (mut n, mut shift) = (0u128, 0u32);
        loop {
            let b = bytes.next()?;
            n |= u128::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                return Some(n);
            }
            shift += 7;
            if shift > 70 {
                return None;
            }
        }
    }
    let mut bytes = raw.iter().copied();
    if bytes.next()? != VERSION {
        return None;
    }
    let op = bytes.next()?;
    varint(&mut bytes)?; // (chain id)
    varint(&mut bytes)?; // (nonce)
    let gas = varint(&mut bytes)?;
    if bytes.next()? != 0 {
        return None; // (a price written as text: Python decodes the whole)
    }
    let price = varint(&mut bytes)?;
    Some((op, gas, price))
}
