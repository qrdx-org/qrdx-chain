//! The database domains' LtHash trigger function, `qrdx_lt_apply` (qrdx/state_commitment.py).
//!
//! SQLite calls it for every row a block changes in `account_state`, `contract_storage`,
//! `token_balances` and `unspent_outputs`, on the database's thread, holding the GIL: in Python
//! it took about 20 µs a row (two 4 KB BLAKE3 outputs, then big-integer lane arithmetic), two
//! or three rows a transfer. Here it is the same computation, natively.
//!
//! What it does not reproduce exactly it hands to the Python function, whole: an accumulator
//! that is not a well-formed 4,096 bytes, a token balance that is not a plain decimal numeral,
//! a value that is not text. So its answer is always Python's (tests/test_native.py).

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString, PyTuple};

pub(crate) const LANES: usize = 1024;
pub(crate) const SIZE: usize = 4 * LANES;
const WIDTH: usize = 5; // the widest committed row (state_commitment._WIDTH)

pub(crate) type Vector = Box<[u16; LANES]>;

/// lthash.entry: the low 16 bits of each little-endian u32 of 4,096 bytes of BLAKE3 over
/// tag | len(data) (u32 LE) | data.
pub(crate) fn entry(tag: &[u8], data: &[u8]) -> Option<Vector> {
    let len = u32::try_from(data.len()).ok()?;
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(&len.to_le_bytes());
    h.update(data);
    let mut out = [0u8; SIZE];
    h.finalize_xof().fill(&mut out);
    let mut v: Vector = Box::new([0u16; LANES]);
    for (i, lane) in v.iter_mut().enumerate() {
        *lane = u16::from_le_bytes([out[4 * i], out[4 * i + 1]]);
    }
    Some(v)
}

/// ``lthash.Accumulator`` over ``items`` (each ``entry(tag, item)``): the digest's 4,096 bytes.
pub(crate) fn accumulate<'a>(tag: &[u8], items: impl Iterator<Item = &'a [u8]>) -> Option<Vec<u8>> {
    let mut total = [0u16; LANES];
    for item in items {
        let v = entry(tag, item)?;
        for (t, x) in total.iter_mut().zip(v.iter()) {
            *t = t.wrapping_add(*x);
        }
    }
    let mut out = vec![0u8; SIZE];
    for (i, lane) in total.iter().enumerate() {
        out[4 * i..4 * i + 2].copy_from_slice(&lane.to_le_bytes());
    }
    Some(out)
}

/// Python's `str(value)`, "" for None (state_commitment._s), or None to hand the call over.
fn text(value: &Bound<'_, PyAny>) -> Option<String> {
    if value.is_none() {
        return Some(String::new());
    }
    if let Ok(s) = value.downcast::<PyString>() {
        return s.to_str().ok().map(str::to_owned);
    }
    // (an INTEGER column: Python's str of it; anything else is handed over)
    if value.is_exact_instance_of::<pyo3::types::PyLong>() {
        return value.str().ok()?.to_str().ok().map(str::to_owned);
    }
    None
}

/// "\x00".join(texts).encode()
fn fields(row: &[Bound<'_, PyAny>]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for (i, v) in row.iter().enumerate() {
        if i > 0 {
            out.push(0);
        }
        out.extend_from_slice(text(v)?.as_bytes());
    }
    Some(out)
}

/// Whether a plain decimal numeral (sign, digits, one point, an exponent: nothing else) is
/// zero; None for anything else, which Python's Decimal judges.
fn plain_zero(s: &str) -> Option<bool> {
    let b = s.as_bytes();
    let mut i = 0;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    let mut digits = 0;
    let mut nonzero = false;
    let mut point = false;
    while i < b.len() {
        match b[i] {
            b'0'..=b'9' => {
                digits += 1;
                nonzero |= b[i] != b'0';
            }
            b'.' if !point => point = true,
            _ => break,
        }
        i += 1;
    }
    if digits == 0 {
        return None;
    }
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        i += 1;
        if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
            i += 1;
        }
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        // (none, or so many digits that Decimal's exponent limits come into it)
        if i == start || i - start > 6 {
            return None;
        }
    }
    (i == b.len()).then_some(!nonzero)
}

enum Encoded {
    Vector(Vector),
    Nothing, // (a zero token balance: no entry)
}

/// The row's vector, by kind (state_commitment.TABLES); None to hand the call over.
fn encode(kind: &str, row: &[Bound<'_, PyAny>]) -> Option<Encoded> {
    let (tag, n): (&[u8], usize) = match kind {
        "account" => (b"qrdx/account/v1", 5),
        "storage" => (b"qrdx/storage/v1", 3),
        "token" => (b"qrdx/token/v1", 3),
        "utxo" => (b"qrdx/utxo/v1", 4),
        _ => return None,
    };
    if kind == "token" && plain_zero(&text(&row[2])?)? {
        return Some(Encoded::Nothing);
    }
    Some(Encoded::Vector(entry(tag, &fields(&row[..n])?)?))
}

/// `state_commitment._udf_apply(acc, kind, has_old, has_new, *old_row, *new_row)`.
#[pyfunction]
#[pyo3(signature = (*args))]
pub fn lt_apply<'py>(py: Python<'py>, args: &Bound<'py, PyTuple>) -> PyResult<PyObject> {
    match apply(args) {
        Some(Some(out)) => Ok(PyBytes::new_bound(py, &out).into_any().unbind()),
        Some(None) => Ok(args.get_item(0)?.unbind()), // (unchanged: the same accumulator)
        None => {
            let python = py.import_bound("qrdx.state_commitment")?.getattr("_udf_apply")?;
            Ok(python.call1(args.clone())?.unbind())
        }
    }
}

/// Some(Some(new accumulator)), Some(None) if unchanged, None to hand the call to Python.
fn apply(args: &Bound<'_, PyTuple>) -> Option<Option<Vec<u8>>> {
    if args.len() != 4 + 2 * WIDTH {
        return None;
    }
    let items: Vec<Bound<'_, PyAny>> = args.iter().collect();
    let acc = items[0].downcast::<PyBytes>().ok()?.as_bytes();
    if acc.len() != SIZE || acc.chunks(4).any(|slot| slot[2] != 0 || slot[3] != 0) {
        return None;
    }
    let kind = items[1].downcast::<PyString>().ok()?.to_str().ok()?;
    if !matches!(kind, "account" | "storage" | "token" | "utxo") {
        return None; // (Python's KeyError, whatever the flags say)
    }
    let flag = |v: &Bound<'_, PyAny>| -> Option<bool> {
        if !v.is_exact_instance_of::<pyo3::types::PyLong>() {
            return None;
        }
        Some(v.extract::<i64>().ok()? != 0)
    };
    let (has_old, has_new) = (flag(&items[2])?, flag(&items[3])?);
    let old = if has_old { encode(kind, &items[4..4 + WIDTH])? } else { Encoded::Nothing };
    let new = if has_new { encode(kind, &items[4 + WIDTH..])? } else { Encoded::Nothing };
    let (remove, add) = match (old, new) {
        (Encoded::Nothing, Encoded::Nothing) => return Some(None),
        (Encoded::Vector(a), Encoded::Vector(b)) if a == b => return Some(None),
        (o, n) => (o, n),
    };
    let mut out = acc.to_vec();
    for i in 0..LANES {
        let mut lane = u16::from_le_bytes([acc[4 * i], acc[4 * i + 1]]);
        if let Encoded::Vector(r) = &remove {
            lane = lane.wrapping_sub(r[i]);
        }
        if let Encoded::Vector(a) = &add {
            lane = lane.wrapping_add(a[i]);
        }
        out[4 * i..4 * i + 2].copy_from_slice(&lane.to_le_bytes());
    }
    Some(Some(out))
}

/// ``commitment._apply`` over entries' digests (qrdx/exchange/commitment.py): ``acc`` − the
/// vectors of ``removed`` + the vectors of ``added``, each ``entry(tag, digest)``, lane by lane
/// mod 2^16. The vectors are computed in parallel, without Python's lock. None if ``acc`` is
/// not a well-formed accumulator: Python computes it.
#[pyfunction]
pub fn lt_mix_entries<'py>(
    py: Python<'py>,
    acc: &[u8],
    tag: &[u8],
    removed: Vec<Vec<u8>>,
    added: Vec<Vec<u8>>,
) -> Option<Bound<'py, PyBytes>> {
    let out = py.allow_threads(|| mix(acc, tag, &removed, &added))?;
    Some(PyBytes::new_bound(py, &out))
}

/// ``lt_mix_entries`` without Python: the new accumulator, or None if ``acc`` is not well formed.
pub(crate) fn mix(acc: &[u8], tag: &[u8], removed: &[Vec<u8>], added: &[Vec<u8>]) -> Option<Vec<u8>> {
    use rayon::prelude::*;

    if acc.len() != SIZE || acc.chunks(4).any(|slot| slot[2] != 0 || slot[3] != 0) {
        return None;
    }
    let sum = |items: &[Vec<u8>]| -> Option<[u16; LANES]> {
        items
            .par_iter()
            .map(|d| entry(tag, d))
            .try_fold(
                || [0u16; LANES],
                |mut total, v| {
                    let v = v?;
                    for (t, x) in total.iter_mut().zip(v.iter()) {
                        *t = t.wrapping_add(*x);
                    }
                    Some(total)
                },
            )
            .try_reduce(
                || [0u16; LANES],
                |mut a, b| {
                    for (x, y) in a.iter_mut().zip(b.iter()) {
                        *x = x.wrapping_add(*y);
                    }
                    Some(a)
                },
            )
    };
    let (minus, plus) = (sum(removed)?, sum(added)?);
    let mut out = acc.to_vec();
    for i in 0..LANES {
        let lane = u16::from_le_bytes([acc[4 * i], acc[4 * i + 1]])
            .wrapping_sub(minus[i])
            .wrapping_add(plus[i]);
        out[4 * i..4 * i + 2].copy_from_slice(&lane.to_le_bytes());
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::plain_zero;

    #[test]
    fn plain_numerals() {
        for (s, want) in [
            ("0", Some(true)),
            ("-0.000", Some(true)),
            ("0E-18", Some(true)),
            (".0", Some(true)),
            ("0.", Some(true)),
            ("1", Some(false)),
            ("0.0001", Some(false)),
            ("1e5", Some(false)),
            ("", None),
            (" 0", None),
            ("0_0", None),
            ("NaN", None),
            ("1e", None),
            (".", None),
            ("0..0", None),
            ("1e1234567", None),
        ] {
            assert_eq!(plain_zero(s), want, "{s:?}");
        }
    }
}
