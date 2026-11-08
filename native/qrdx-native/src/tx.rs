//! Exchange transactions as they travel — their JSON form (`ExchangeTransaction.to_dict`) or
//! their binary form (`to_wire`, qrdx/exchange/wire.py) — their signed bytes, their hash and
//! their ML-DSA-65 signature, worked out exactly as qrdx/exchange/transactions.py works them
//! out (`from_dict`, `__post_init__`, `_canonical_bytes`, `tx_hash`).
//!
//! What is not reproduced exactly is not guessed at: a float in the params, an operation named
//! rather than numbered, a gas price that is not whole, a missing gas price (Python takes the
//! network's floor). Those go to Python as they are (`Read::Python`). The node never takes a
//! verdict from here on trust either: Python compares the signed bytes it computes itself with
//! these before it uses the verdict (qrdx/node/netd.py).

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use serde_json::{Map, Value};

use crate::canon::{write_value, Sink};
use crate::oqs;

const SIGNING_TAG: &[u8] = b"QRDX-EXCHANGE-TX-v1\x00";

/// The most a single transaction's JSON may be.
pub const MAX_TX_BYTES: usize = 128 * 1024;

pub struct Checked {
    pub hash: [u8; 32],
    /// The bytes the sender signed (`signing_bytes`).
    pub signed: Vec<u8>,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Checked {
    /// The ML-DSA-65 verdict over the signed bytes; None for a key that is not a plain
    /// ML-DSA-65 key (a multisig keyset): Python checks it.
    pub fn verdict(&self) -> Option<bool> {
        if self.public_key.len() == oqs::DSA_PUBLIC_KEY_LEN
            && self.signature.len() == oqs::DSA_SIGNATURE_LEN
        {
            Some(oqs::dsa_verify(&self.public_key, &self.signed, &self.signature))
        } else if self.signature.is_empty() || self.public_key.is_empty() {
            Some(false)
        } else {
            None
        }
    }
}

pub enum Read {
    Checked(Checked),
    /// Read and checked by Python: valid or not, this module does not reproduce it exactly.
    Python(&'static str),
    /// No transaction could be this (Python refuses it too).
    Malformed(&'static str),
}

fn whole_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => {
            let t = n.to_string();
            if t.bytes().all(|b| b.is_ascii_digit()) {
                t.parse::<u64>().ok()
            } else {
                None
            }
        }
        _ => None,
    }
}

fn digits(text: &str) -> Option<String> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let trimmed = text.trim_start_matches('0');
    Some(if trimmed.is_empty() { "0".to_string() } else { trimmed.to_string() })
}

fn hex_field(obj: &Map<String, Value>, key: &str) -> Result<Vec<u8>, &'static str> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(s)) if s.is_empty() => Ok(Vec::new()),
        Some(Value::String(s)) => decode_hex(s).ok_or("not hex"),
        Some(Value::Bool(false)) => Ok(Vec::new()),
        _ => Err("not hex"),
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks_exact(2) {
        out.push((nib(pair[0])? << 4) | nib(pair[1])?);
    }
    Some(out)
}

/// The binary form's version byte (qrdx/exchange/wire.py ``VERSION``); JSON starts with `{`.
const WIRE_VERSION: u8 = 1;

struct Wire<'a> {
    raw: &'a [u8],
    at: usize,
}

impl<'a> Wire<'a> {
    fn byte(&mut self) -> Option<u8> {
        let b = *self.raw.get(self.at)?;
        self.at += 1;
        Some(b)
    }
    fn varint(&mut self) -> Option<u64> {
        let (mut n, mut shift) = (0u64, 0u32);
        loop {
            let b = self.byte()?;
            let part = u64::from(b & 0x7F);
            if shift >= 64 || (shift > 0 && part >> (64 - shift) != 0) {
                return None; // (past 64 bits: Python's range checks refuse it)
            }
            n |= part << shift;
            if b & 0x80 == 0 {
                return Some(n);
            }
            shift += 7;
        }
    }
    /// A varint of any size (a gas price or a chain id: Python reads any whole number).
    fn varint_big(&mut self) -> Option<num_bigint::BigUint> {
        let mut n = num_bigint::BigUint::default();
        let mut shift = 0u64;
        loop {
            let b = self.byte()?;
            n |= num_bigint::BigUint::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                return Some(n);
            }
            shift += 7;
            if shift > 64 * 1024 {
                return None;
            }
        }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let out = self.raw.get(self.at..end)?;
        self.at = end;
        Some(out)
    }
    fn field(&mut self) -> Option<&'a [u8]> {
        let n = usize::try_from(self.varint()?).ok()?;
        self.take(n)
    }
}

/// Read a transaction's binary form (``wire.encode``).
fn read_binary(raw: &[u8]) -> Read {
    let mut w = Wire { raw, at: 1 };
    let fields = (|| {
        let op_type = w.byte()?;
        let chain_id = u64::try_from(w.varint_big()?).ok();
        let (nonce, gas_limit) = (w.varint()?, w.varint()?);
        let tag = w.byte()?;
        let gas_price = if tag == 0 { Some(w.varint_big()?.to_string()) } else { w.field().map(|_| None)? };
        w.take(8)?; // (the timestamp: not signed)
        let sender = std::str::from_utf8(w.field()?).ok()?;
        let signer = std::str::from_utf8(w.field()?).ok()?;
        let params = w.field()?;
        let (signature, public_key) = (w.field()?, w.field()?);
        (w.at == raw.len()).then_some((
            op_type, chain_id, nonce, gas_limit, gas_price, sender, signer, params, signature,
            public_key,
        ))
    })();
    let Some((op_type, chain_id, nonce, gas_limit, gas_price, sender, signer, params, sig, key)) =
        fields
    else {
        return Read::Malformed("not a binary transaction");
    };
    let Some(gas_price) = gas_price else {
        return Read::Python("a gas price that is not a whole number");
    };
    let Some(chain_id) = chain_id.filter(|c| *c < (1u64 << 63)) else {
        return Read::Python("a chain id written otherwise");
    };
    let Ok(params) = serde_json::from_slice::<Value>(params) else {
        return Read::Malformed("params that are not JSON");
    };
    let signer = if signer == sender { "" } else { signer };
    checked(op_type, chain_id, sender, nonce, &params, gas_limit, &gas_price, signer, sig, key)
}

/// The signed bytes and the hash (``_canonical_bytes``, ``tx_hash``).
#[allow(clippy::too_many_arguments)]
fn checked(
    op_type: u8,
    chain_id: u64,
    sender: &str,
    nonce: u64,
    params: &Value,
    gas_limit: u64,
    gas_price: &str,
    signer: &str,
    signature: &[u8],
    public_key: &[u8],
) -> Read {
    let mut signed: Vec<u8> = Vec::with_capacity(512);
    signed.put(SIGNING_TAG);
    signed.put(&chain_id.to_be_bytes());
    signed.put(&[op_type]);
    signed.put(sender.as_bytes());
    signed.put(&nonce.to_be_bytes());
    // json.dumps(params, sort_keys=True, default=str): Python's default separators.
    if write_value(&mut signed, params, b", ", b": ", 0).is_err() {
        return Read::Python("params Python writes by its own rules");
    }
    signed.put(&gas_limit.to_be_bytes());
    signed.put(gas_price.as_bytes());
    if !signer.is_empty() {
        signed.put(b"\x00signer:");
        signed.put(signer.as_bytes());
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&Blake2b::<U32>::digest(&signed));
    Read::Checked(Checked {
        hash,
        signed,
        public_key: public_key.to_vec(),
        signature: signature.to_vec(),
    })
}

/// Read one transaction (its JSON or its binary form): its signed bytes and hash (its signature
/// is checked by `Checked::verdict`, after a duplicate is set aside).
pub fn read(raw: &[u8]) -> Read {
    if raw.len() > MAX_TX_BYTES {
        return Read::Malformed("too large");
    }
    if raw.first() == Some(&WIRE_VERSION) {
        return read_binary(raw);
    }
    let value: Value = match serde_json::from_slice(raw) {
        Ok(v) => v,
        Err(_) => return Read::Malformed("not JSON"),
    };
    let Value::Object(obj) = value else {
        return Read::Malformed("an exchange transaction is an object");
    };
    // Anything unusual from here goes to Python rather than being refused: Python is the rule,
    // and refusing what it would accept loses a valid transaction.
    for key in ["op_type", "sender", "nonce", "params"] {
        if !obj.contains_key(key) {
            return Read::Python("missing a field");
        }
    }
    let op_type = match &obj["op_type"] {
        Value::Number(_) => match whole_u64(&obj["op_type"]) {
            Some(n) if n <= 255 => n as u8,
            _ => return Read::Python("an operation type of another form"),
        },
        _ => return Read::Python("an operation given by name"),
    };
    let Value::String(sender) = &obj["sender"] else {
        return Read::Python("a sender of another type");
    };
    let Some(nonce) = whole_u64(&obj["nonce"]) else {
        return Read::Python("a nonce of another form");
    };
    let gas_limit = match obj.get("gas_limit") {
        None => 100_000,
        Some(v) => match whole_u64(v) {
            Some(n) => n,
            None => return Read::Python("a gas limit of another form"),
        },
    };
    // __post_init__: a whole number of wei signs as its digits, however it was written.
    let gas_price = match obj.get("gas_price") {
        None => return Read::Python("no gas price: the network's floor"),
        Some(Value::Number(n)) => match digits(&n.to_string()) {
            Some(d) => d,
            None => return Read::Python("a gas price that is not a whole number as written"),
        },
        Some(Value::String(s)) => match digits(s) {
            Some(d) => d,
            None => return Read::Python("a gas price written otherwise"),
        },
        Some(_) => return Read::Python("a gas price of another type"),
    };
    // from_dict: `chain_id or 0`; __post_init__ reads text as an integer.
    let chain_id = match obj.get("chain_id") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => 0,
        Some(v @ Value::Number(_)) => match whole_u64(v) {
            Some(n) if n < (1u64 << 63) => n,
            _ => return Read::Python("a chain id written otherwise"),
        },
        Some(Value::String(s)) if s.is_empty() => 0,
        Some(Value::String(s)) => match digits(s).and_then(|d| d.parse::<u64>().ok()) {
            Some(n) if n < (1u64 << 63) => n,
            _ => return Read::Python("a chain id written otherwise"),
        },
        Some(_) => return Read::Python("a chain id of another type"),
    };
    // from_dict: `signer or ""`; __post_init__: the sender itself is no signer.
    let signer = match obj.get("signer") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => String::new(),
        Some(Value::String(s)) => {
            if s == sender {
                String::new()
            } else {
                s.clone()
            }
        }
        Some(_) => return Read::Python("a signer of another type"),
    };
    let signature = match hex_field(&obj, "signature") {
        Ok(b) => b,
        Err(_) => return Read::Python("a signature written otherwise"),
    };
    let public_key = match hex_field(&obj, "public_key") {
        Ok(b) => b,
        Err(_) => return Read::Python("a key written otherwise"),
    };

    checked(
        op_type, chain_id, sender, nonce, &obj["params"], gas_limit, &gas_price, &signer,
        &signature, &public_key,
    )
}

/// ``read`` as Python sees it (for tests): ("checked", hash hex, the signed bytes), or
/// ("python" / "malformed", the reason, None).
#[pyo3::pyfunction]
pub fn tx_read(py: pyo3::Python<'_>, raw: &[u8]) -> (String, String, Option<pyo3::PyObject>) {
    use pyo3::IntoPy;
    match read(raw) {
        Read::Checked(c) => (
            "checked".into(),
            c.hash.iter().map(|b| format!("{b:02x}")).collect(),
            Some(pyo3::types::PyBytes::new_bound(py, &c.signed).into_py(py)),
        ),
        Read::Python(why) => ("python".into(), why.into(), None),
        Read::Malformed(why) => ("malformed".into(), why.into(), None),
    }
}
