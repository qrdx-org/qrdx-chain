//! An exchange transaction read natively, whole, when it is in the common form (qrdx/exchange/
//! wire.py ``decode``; docs/NATIVE.md "Transactions read whole"): its fields, the bytes it is
//! signed and hashed over (``ExchangeTransaction._canonical_bytes``) and its hash, in one call —
//! and its signature checked together with the address its key derives (``verify``'s binding).
//!
//! The common form: the binary form exactly as ``wire.encode`` writes it (so the bytes may be
//! remembered and sent on as they came), no ``signer`` (the account signs for itself), a whole
//! gas price, a timestamp set, and params a flat object of plain strings (printable ASCII without
//! ``"`` or ``\``), keys sorted, as ``json.dumps(params, sort_keys=True, separators=(",", ":"))``
//! writes them. Anything else returns None and Python reads it, as before.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList, PyString};
use rayon::prelude::*;
use sha3::Keccak256;

use crate::oqs;
use crate::wire::b64_decode;

const VERSION: u8 = 1;
const SIGNING_TAG: &[u8] = b"QRDX-EXCHANGE-TX-v1\x00";
const PUBLIC_KEY_SIZE: usize = 1952;

struct Reader<'a> {
    raw: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Option<u8> {
        let b = *self.raw.get(self.at)?;
        self.at += 1;
        Some(b)
    }

    /// A varint that fits 64 bits, in its shortest form (anything else: not the common form).
    fn varint(&mut self) -> Option<u64> {
        let (mut n, mut shift, start) = (0u64, 0u32, self.at);
        loop {
            let b = self.byte()?;
            if shift == 63 && b & 0x7E != 0 {
                return None; // (past 64 bits)
            }
            n |= u64::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                let mut shortest = Vec::new();
                put_varint(&mut shortest, n);
                return (shortest.len() == self.at - start).then_some(n);
            }
            shift += 7;
            if shift > 63 {
                return None;
            }
        }
    }

    fn field(&mut self) -> Option<&'a [u8]> {
        let n = usize::try_from(self.varint()?).ok()?;
        let end = self.at.checked_add(n)?;
        let out = self.raw.get(self.at..end)?;
        self.at = end;
        Some(out)
    }
}

fn put_varint(out: &mut Vec<u8>, mut n: u64) {
    loop {
        let b = (n & 0x7F) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

/// Printable ASCII without ``"`` or ``\`` (``transactions._plain``): written in JSON as is.
fn plain(s: &[u8]) -> bool {
    s.iter().all(|&c| (0x20..0x7F).contains(&c) && c != b'"' && c != b'\\')
}

/// ``{"k":"v",...}`` of plain strings, keys strictly ascending: the pairs.
fn flat_params(text: &[u8]) -> Option<Vec<(&str, &str)>> {
    let inner = text.strip_prefix(b"{")?.strip_suffix(b"}")?;
    let mut out: Vec<(&str, &str)> = Vec::new();
    if inner.is_empty() {
        return Some(out);
    }
    let mut rest = inner;
    loop {
        let (key, after) = quoted(rest)?;
        let after = after.strip_prefix(b":")?;
        let (value, after) = quoted(after)?;
        if let Some(last) = out.last() {
            if last.0.as_bytes() >= key.as_bytes() {
                return None; // (not sorted, or a key twice)
            }
        }
        out.push((key, value));
        if after.is_empty() {
            return Some(out);
        }
        rest = after.strip_prefix(b",")?;
    }
}

fn quoted(s: &[u8]) -> Option<(&str, &[u8])> {
    let s = s.strip_prefix(b"\"")?;
    let end = s.iter().position(|&c| c == b'"')?;
    let body = &s[..end];
    if !plain(body) {
        return None;
    }
    Some((std::str::from_utf8(body).ok()?, &s[end + 1..]))
}

/// ``transactions._params_json``: ``json.dumps(params, sort_keys=True)`` (", " and ": ").
fn params_json(pairs: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + pairs.iter().map(|(k, v)| k.len() + v.len() + 8).sum::<usize>());
    out.push(b'{');
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(b", ");
        }
        out.push(b'"');
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b"\": \"");
        out.extend_from_slice(v.as_bytes());
        out.push(b'"');
    }
    out.push(b'}');
    out
}


/// An exchange transaction in the common form (the module's documentation): ``(op_type,
/// chain_id, nonce, gas_limit, gas_price, timestamp, sender, [(key, value)] of params,
/// signature, public_key, canonical bytes, hash hex, binary form, whether the text given is
/// that form's own text)``; None for anything else (Python reads it, and says what is wrong).
#[pyfunction]
pub fn wire_read(py: Python<'_>, item: &Bound<'_, PyAny>) -> PyResult<PyObject> {
    let decoded;
    let (raw, given_text): (&[u8], Option<&str>) = if let Ok(s) = item.downcast::<PyString>() {
        let text = s.to_str()?;
        match b64_decode(text.as_bytes()) {
            Some(d) => decoded = d,
            None => return Ok(py.None()),
        }
        (&decoded, Some(text))
    } else if let Ok(b) = item.downcast::<PyBytes>() {
        (b.as_bytes(), None)
    } else {
        return Ok(py.None());
    };
    let Some(parsed) = parse(raw) else {
        return Ok(py.None());
    };
    let Parsed { op_type, chain_id, nonce, gas_limit, gas_price, timestamp, sender, pairs, signature, public_key } =
        parsed;
    let mut canonical = Vec::with_capacity(96 + sender.len() + 64 * pairs.len());
    canonical.extend_from_slice(SIGNING_TAG);
    canonical.extend_from_slice(&chain_id.to_be_bytes());
    canonical.push(op_type);
    canonical.extend_from_slice(sender.as_bytes());
    canonical.extend_from_slice(&nonce.to_be_bytes());
    canonical.extend_from_slice(&params_json(&pairs));
    canonical.extend_from_slice(&gas_limit.to_be_bytes());
    canonical.extend_from_slice(gas_price.to_string().as_bytes());
    let hash: [u8; 32] = Blake2b::<U32>::digest(&canonical).into();
    let hash_hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    let own_text = given_text.is_some_and(canonical_text);
    let params: Vec<(String, String)> =
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let fields: Vec<PyObject> = vec![
        op_type.into_py(py),
        chain_id.into_py(py),
        nonce.into_py(py),
        gas_limit.into_py(py),
        gas_price.into_py(py),
        timestamp.into_py(py),
        sender.into_py(py),
        params.into_py(py),
        PyBytes::new_bound(py, signature).into_py(py),
        PyBytes::new_bound(py, public_key).into_py(py),
        PyBytes::new_bound(py, &canonical).into_py(py),
        hash_hex.into_py(py),
        PyBytes::new_bound(py, raw).into_py(py),
        own_text.into_py(py),
    ];
    Ok(pyo3::types::PyTuple::new_bound(py, fields).into_py(py))
}

/// Whether base64 the decoder took (``b64_decode``: the alphabet, padding only at the end, a
/// length of whole quanta) is the text ``b64encode`` writes of what it decodes to: the bits the
/// last character before the padding carries past the data are zero.
fn canonical_text(text: &str) -> bool {
    let t = text.as_bytes();
    let pad = t.iter().rev().take_while(|&&c| c == b'=').count();
    if pad == 0 || t.len() < 4 {
        return true;
    }
    let last = sextet(t[t.len() - 1 - pad]);
    let spare = if pad == 1 { 0b11 } else { 0b1111 };
    last & spare == 0
}

fn sextet(c: u8) -> u8 {
    match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => 0xFF,
    }
}

struct Parsed<'a> {
    op_type: u8,
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    gas_price: u64,
    timestamp: f64,
    sender: &'a str,
    pairs: Vec<(&'a str, &'a str)>,
    signature: &'a [u8],
    public_key: &'a [u8],
}

fn parse(raw: &[u8]) -> Option<Parsed<'_>> {
    let mut r = Reader { raw, at: 0 };
    if r.byte()? != VERSION {
        return None;
    }
    let op_type = r.byte()?;
    let (chain_id, nonce, gas_limit) = (r.varint()?, r.varint()?, r.varint()?);
    if chain_id >= 1 << 63 {
        return None;
    }
    if r.byte()? != 0 {
        return None; // (a price written as text: not a whole number of wei)
    }
    let gas_price = r.varint()?;
    let ts = raw.get(r.at..r.at + 8)?;
    r.at += 8;
    let timestamp = f64::from_be_bytes(ts.try_into().ok()?);
    if timestamp == 0.0 || !timestamp.is_finite() {
        return None; // (unset: Python would stamp it with the time it is read)
    }
    let sender = std::str::from_utf8(r.field()?).ok()?;
    let signer = r.field()?;
    if !signer.is_empty() || sender.is_empty() {
        return None;
    }
    let pairs = flat_params(r.field()?)?;
    let signature = r.field()?;
    let public_key = r.field()?;
    if r.at != raw.len() {
        return None;
    }
    Some(Parsed { op_type, chain_id, nonce, gas_limit, gas_price, timestamp, sender, pairs, signature, public_key })
}

/// ``"0xpq"`` and the hex of the first 32 bytes of keccak256(key): a PQ address, lowercase
/// (``dilithium._address_of``, which ``verify`` compares lowercase).
fn pq_address_lower(public_key: &[u8]) -> String {
    let digest = Keccak256::digest(public_key);
    let mut out = String::with_capacity(68);
    out.push_str("0xpq");
    for b in &digest[..32] {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// For each ``(public_key, message, signature, address)``: (whether the signature is a valid
/// ML-DSA-65 signature of the message by the key, whether the key's PQ address is ``address``,
/// any case). On the module's threads, without Python's lock.
#[pyfunction]
pub fn mldsa65_verify_bind_batch(py: Python<'_>, items: &Bound<'_, PyList>) -> PyResult<Vec<(bool, bool)>> {
    oqs::init();
    let mut held = Vec::with_capacity(items.len());
    for item in items.iter() {
        let (pk, msg, sig, address): (Bound<'_, PyBytes>, Bound<'_, PyBytes>, Bound<'_, PyBytes>, String) =
            item.extract()?;
        held.push((pk, msg, sig, address.to_ascii_lowercase()));
    }
    let views: Vec<(&[u8], &[u8], &[u8], &str)> = held
        .iter()
        .map(|(pk, msg, sig, a)| (pk.as_bytes(), msg.as_bytes(), sig.as_bytes(), a.as_str()))
        .collect();
    Ok(py.allow_threads(|| {
        views
            .par_iter()
            .map(|(pk, msg, sig, address)| {
                let bound = pk.len() == PUBLIC_KEY_SIZE && pq_address_lower(pk) == *address;
                (oqs::dsa_verify(pk, msg, sig), bound)
            })
            .collect()
    }))
}
