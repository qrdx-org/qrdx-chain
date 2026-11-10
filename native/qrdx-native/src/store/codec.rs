//! The store's tuple encoding (qrdx/store.py): a row's key and its value are each a tuple of
//! None, int, str, bytes and float, packed so that packed keys sort as their tuples do — the
//! FoundationDB tuple layer's encoding of those types:
//!
//! * None `0x00`; bytes `0x01` and str `0x02` (UTF-8), each followed by its bytes with every
//!   `0x00` written `0x00 0xFF`, then `0x00`;
//! * an int of n ≤ 8 bytes `0x14 + n` and its big-endian bytes (zero is `0x14` alone), a negative
//!   one `0x14 − n` and the one's complement of its magnitude's; longer, `0x1D` and a length
//!   byte (negative: `0x0B`, the length's complement, the magnitude's complement);
//! * a float `0x21` and its IEEE bits, big-endian, the sign bit flipped (all bits if negative).
//!
//! A packed tuple is the concatenation of its elements, so a tuple's packing is a prefix of the
//! packing of every tuple that extends it, and the bytes after a prefix never start with `0xFF`
//! (a range over a prefix ends at the prefix and `0xFF`). A bool packs as the int it is, as
//! SQLite stores it.

use num_bigint::{BigInt, Sign};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyByteArray, PyBytes, PyFloat, PyLong, PyMemoryView, PyString, PyTuple};

const NULL: u8 = 0x00;
const BYTES: u8 = 0x01;
const STRING: u8 = 0x02;
const NEG_BIG: u8 = 0x0B;
const INT_ZERO: u8 = 0x14;
const POS_BIG: u8 = 0x1D;
const DOUBLE: u8 = 0x21;

/// One element, read without Python (the store's commitments read rows natively).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Field {
    Null,
    Bytes(Vec<u8>),
    Str(String),
    /// Sign and big-endian magnitude.
    Int(bool, Vec<u8>),
    Float(f64),
}

impl Field {
    /// Python's ``str()`` of the value, "" for None (qrdx/state_commitment.py ``_s``), or None
    /// where only Python can say (bytes).
    pub(crate) fn text(&self) -> Option<String> {
        match self {
            Field::Null => Some(String::new()),
            Field::Str(s) => Some(s.clone()),
            Field::Int(negative, magnitude) => {
                let n = BigInt::from_bytes_be(if *negative { Sign::Minus } else { Sign::Plus }, magnitude);
                Some(n.to_string())
            }
            Field::Float(_) | Field::Bytes(_) => None,
        }
    }
}

fn escaped(out: &mut Vec<u8>, tag: u8, data: &[u8]) {
    out.push(tag);
    for &b in data {
        out.push(b);
        if b == 0 {
            out.push(0xFF);
        }
    }
    out.push(0);
}

fn int_bytes(out: &mut Vec<u8>, negative: bool, magnitude: &[u8]) -> PyResult<()> {
    let start = magnitude.iter().position(|&b| b != 0).unwrap_or(magnitude.len());
    let m = &magnitude[start..];
    let n = m.len();
    if n == 0 {
        out.push(INT_ZERO);
    } else if n <= 8 {
        if negative {
            out.push(INT_ZERO - n as u8);
            out.extend(m.iter().map(|b| !b));
        } else {
            out.push(INT_ZERO + n as u8);
            out.extend_from_slice(m);
        }
    } else if n <= 255 {
        if negative {
            out.push(NEG_BIG);
            out.push(!(n as u8));
            out.extend(m.iter().map(|b| !b));
        } else {
            out.push(POS_BIG);
            out.push(n as u8);
            out.extend_from_slice(m);
        }
    } else {
        return Err(PyValueError::new_err("an int of more than 255 bytes"));
    }
    Ok(())
}

pub(crate) fn pack_one(value: &Bound<'_, PyAny>, out: &mut Vec<u8>) -> PyResult<()> {
    if value.is_none() {
        out.push(NULL);
    } else if let Ok(s) = value.downcast::<PyString>() {
        escaped(out, STRING, s.to_str()?.as_bytes());
    } else if let Ok(b) = value.downcast::<PyBytes>() {
        escaped(out, BYTES, b.as_bytes());
    } else if value.is_instance_of::<PyBool>() {
        let v = value.extract::<bool>()?;
        int_bytes(out, false, &[v as u8])?;
    } else if value.is_instance_of::<PyLong>() {
        if let Ok(v) = value.extract::<i64>() {
            int_bytes(out, v < 0, &v.unsigned_abs().to_be_bytes())?;
        } else {
            let negative = value.lt(0)?;
            let magnitude = if negative { value.neg()? } else { value.clone() };
            let bits: usize = magnitude.call_method0("bit_length")?.extract()?;
            let raw = magnitude.call_method1("to_bytes", ((bits + 7) / 8, "big"))?;
            int_bytes(out, negative, raw.downcast::<PyBytes>()?.as_bytes())?;
        }
    } else if value.is_instance_of::<PyFloat>() {
        let bits = value.extract::<f64>()?.to_bits();
        let flipped = if bits >> 63 == 1 { !bits } else { bits ^ (1 << 63) };
        out.push(DOUBLE);
        out.extend_from_slice(&flipped.to_be_bytes());
    } else if let Ok(b) = value.downcast::<PyByteArray>() {
        escaped(out, BYTES, &b.to_vec());
    } else if value.is_instance_of::<PyMemoryView>() {
        let raw = value.call_method0("tobytes")?;
        escaped(out, BYTES, raw.downcast::<PyBytes>()?.as_bytes());
    } else {
        return Err(PyTypeError::new_err(format!(
            "the store keeps None, int, str, bytes and float, not {}",
            value.get_type().name()?
        )));
    }
    Ok(())
}

pub(crate) fn pack_tuple(values: &Bound<'_, PyTuple>) -> PyResult<Vec<u8>> {
    let mut out = Vec::with_capacity(16 * values.len());
    for v in values.iter() {
        pack_one(&v, &mut out)?;
    }
    Ok(out)
}

fn unescape(data: &[u8], mut i: usize) -> Result<(Vec<u8>, usize), &'static str> {
    let mut out = Vec::new();
    loop {
        match data.get(i) {
            None => return Err("an unterminated string"),
            Some(0) => {
                if data.get(i + 1) == Some(&0xFF) {
                    out.push(0);
                    i += 2;
                } else {
                    return Ok((out, i + 1));
                }
            }
            Some(&b) => {
                out.push(b);
                i += 1;
            }
        }
    }
}

/// The fields of a packed tuple.
pub(crate) fn fields(data: &[u8]) -> Result<Vec<Field>, &'static str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let tag = data[i];
        i += 1;
        match tag {
            NULL => out.push(Field::Null),
            BYTES => {
                let (b, next) = unescape(data, i)?;
                out.push(Field::Bytes(b));
                i = next;
            }
            STRING => {
                let (b, next) = unescape(data, i)?;
                out.push(Field::Str(String::from_utf8(b).map_err(|_| "a string not UTF-8")?));
                i = next;
            }
            0x0C..=0x1C => {
                let n = tag as i32 - INT_ZERO as i32;
                let len = n.unsigned_abs() as usize;
                let raw = data.get(i..i + len).ok_or("a short int")?;
                let magnitude: Vec<u8> = if n < 0 { raw.iter().map(|b| !b).collect() } else { raw.to_vec() };
                out.push(Field::Int(n < 0, magnitude));
                i += len;
            }
            POS_BIG | NEG_BIG => {
                let len_byte = *data.get(i).ok_or("a short int")?;
                let negative = tag == NEG_BIG;
                let len = if negative { !len_byte } else { len_byte } as usize;
                let raw = data.get(i + 1..i + 1 + len).ok_or("a short int")?;
                let magnitude: Vec<u8> = if negative { raw.iter().map(|b| !b).collect() } else { raw.to_vec() };
                out.push(Field::Int(negative, magnitude));
                i += 1 + len;
            }
            DOUBLE => {
                let raw: [u8; 8] = data.get(i..i + 8).ok_or("a short float")?.try_into().unwrap();
                let bits = u64::from_be_bytes(raw);
                let original = if bits >> 63 == 1 { bits ^ (1 << 63) } else { !bits };
                out.push(Field::Float(f64::from_bits(original)));
                i += 8;
            }
            _ => return Err("an unknown type code"),
        }
    }
    Ok(out)
}

pub(crate) fn to_python<'py>(py: Python<'py>, field: &Field) -> PyResult<Bound<'py, PyAny>> {
    Ok(match field {
        Field::Null => py.None().into_bound(py),
        Field::Bytes(b) => PyBytes::new_bound(py, b).into_any(),
        Field::Str(s) => PyString::new_bound(py, s).into_any(),
        Field::Float(f) => PyFloat::new_bound(py, *f).into_any(),
        Field::Int(negative, magnitude) => {
            if magnitude.len() <= 8 {
                let mut buf = [0u8; 8];
                buf[8 - magnitude.len()..].copy_from_slice(magnitude);
                let m = u64::from_be_bytes(buf) as i128;
                (if *negative { -m } else { m }).into_py(py).into_bound(py)
            } else {
                let int = py.get_type_bound::<PyLong>();
                let m = int.call_method1("from_bytes", (PyBytes::new_bound(py, magnitude), "big"))?;
                if *negative { m.neg()? } else { m }
            }
        }
    })
}

pub(crate) fn unpack<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyTuple>> {
    let fields = fields(data).map_err(PyValueError::new_err)?;
    let items: PyResult<Vec<Bound<'py, PyAny>>> = fields.iter().map(|f| to_python(py, f)).collect();
    Ok(PyTuple::new_bound(py, items?))
}

/// ``store_pack(values)``: a tuple packed (the module's encoding).
#[pyfunction]
pub fn store_pack<'py>(py: Python<'py>, values: &Bound<'py, PyTuple>) -> PyResult<Bound<'py, PyBytes>> {
    Ok(PyBytes::new_bound(py, &pack_tuple(values)?))
}

/// ``store_unpack(data)``: the tuple ``data`` packs.
#[pyfunction]
pub fn store_unpack<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyTuple>> {
    unpack(py, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ints_sort_as_numbers() {
        let mut packed = Vec::new();
        for n in [-70000i64, -256, -255, -1, 0, 1, 255, 256, 70000, i64::MAX] {
            let mut out = Vec::new();
            int_bytes(&mut out, n < 0, &n.unsigned_abs().to_be_bytes()).unwrap();
            packed.push(out);
        }
        let mut sorted = packed.clone();
        sorted.sort();
        assert_eq!(packed, sorted);
    }

    #[test]
    fn strings_round_trip_with_zero_bytes() {
        let mut out = Vec::new();
        escaped(&mut out, STRING, b"a\x00b");
        assert_eq!(fields(&out).unwrap(), vec![Field::Str("a\x00b".into())]);
    }
}
