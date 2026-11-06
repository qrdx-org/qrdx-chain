//! Native hot paths for the QRDX node and validator (docs/NATIVE.md).
//!
//! Each function here has a pure-Python counterpart that produces the same result
//! (`qrdx/native.py`), and the node runs without this module. Consensus never depends on which
//! one ran:
//!
//! * `mldsa65_verify_batch` checks ML-DSA-65 signatures with the system liboqs, the library the
//!   Python node verifies with, in parallel and without Python's lock;
//! * `canonical_json` writes what `json.dumps(obj, sort_keys=True, ensure_ascii=True)` writes,
//!   with either separator style, byte for byte: a float as `float.__repr__` writes it, as
//!   Python's encoder does. Anything it does not reproduce exactly (a key that is not a string,
//!   an unpaired surrogate) raises `Unsupported`, and the caller falls back to Python;
//! * `body_root_sha256` is a block's body root (`block_verification.body_root`): the canonical
//!   JSON of its body, hashed as it is written.

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyDict, PyFloat, PyList, PyLong, PyString, PyTuple};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

mod book;
mod canon;
pub mod dec;
mod lane;
mod lthash;
pub mod net;
mod mtree;
mod smt;
mod oqs;
mod tx;

create_exception!(_native, Unsupported, PyException);

// ── ML-DSA-65 through liboqs (src/oqs.rs) ────────────────────────────────────────────────

/// Whether each `(public_key, message, signature)` (each `bytes`) is a valid ML-DSA-65
/// signature, in order. The bytes are read in place: converting each to a vector went element by
/// element, and took longer than checking the signatures.
#[pyfunction]
fn mldsa65_verify_batch(py: Python<'_>, items: &Bound<'_, PyList>) -> PyResult<Vec<bool>> {
    oqs::init();
    let mut held: Vec<(Bound<'_, PyBytes>, Bound<'_, PyBytes>, Bound<'_, PyBytes>)> =
        Vec::with_capacity(items.len());
    for item in items.iter() {
        let (pk, msg, sig): (Bound<'_, PyBytes>, Bound<'_, PyBytes>, Bound<'_, PyBytes>) =
            item.extract()?;
        held.push((pk, msg, sig));
    }
    let views: Vec<(&[u8], &[u8], &[u8])> = held
        .iter()
        .map(|(pk, msg, sig)| (pk.as_bytes(), msg.as_bytes(), sig.as_bytes()))
        .collect();
    // (bytes are immutable, and `held` keeps them alive while the threads read them)
    Ok(py.allow_threads(|| {
        views
            .par_iter()
            .map(|(pk, msg, sig)| oqs::dsa_verify(pk, msg, sig))
            .collect()
    }))
}

/// A new ML-DSA-65 key pair: (public key, secret key). For tests and tools.
#[pyfunction]
fn mldsa65_keypair<'py>(py: Python<'py>) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (pk, sk) = oqs::dsa_keypair()
        .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("key generation failed"))?;
    Ok((PyBytes::new_bound(py, &pk), PyBytes::new_bound(py, &sk)))
}

/// The threads a batch is checked on.
#[pyfunction]
fn threads() -> usize {
    rayon::current_num_threads()
}

// ── canonical JSON (Python's json.dumps, sort_keys=True, ensure_ascii=True) ────────────────

use crate::canon::{write_str, Sink, HEX};

struct Style {
    item: &'static [u8],
    key: &'static [u8],
    default_str: bool,
}

const MAX_DEPTH: u32 = 900;

fn encode<S: Sink>(obj: &Bound<'_, PyAny>, out: &mut S, style: &Style, depth: u32) -> PyResult<()> {
    if depth > MAX_DEPTH {
        return Err(Unsupported::new_err("nested too deeply"));
    }
    if obj.is_none() {
        out.put(b"null");
        return Ok(());
    }
    if let Ok(b) = obj.downcast::<PyBool>() {
        out.put(if b.is_true() { b"true" } else { b"false" });
        return Ok(());
    }
    if let Ok(s) = obj.downcast::<PyString>() {
        let text = s
            .to_str()
            .map_err(|_| Unsupported::new_err("a string that is not valid Unicode"))?;
        write_str(out, text);
        return Ok(());
    }
    if obj.is_instance_of::<PyLong>() {
        match obj.extract::<i64>() {
            Ok(v) => out.put(v.to_string().as_bytes()),
            Err(_) => {
                // int.__repr__, as Python's encoder writes any int (and an int subclass).
                let text = obj.py().get_type_bound::<PyLong>().call_method1("__repr__", (obj,))?;
                out.put(text.extract::<String>()?.as_bytes());
            }
        }
        return Ok(());
    }
    if obj.is_instance_of::<PyFloat>() {
        // As Python's encoder (allow_nan=True): the specials by name, else float.__repr__.
        let value: f64 = obj.extract()?;
        if value.is_nan() {
            out.put(b"NaN");
        } else if value.is_infinite() {
            out.put(if value > 0.0 { b"Infinity" } else { b"-Infinity" });
        } else {
            let text = obj.py().get_type_bound::<PyFloat>().call_method1("__repr__", (obj,))?;
            out.put(text.extract::<String>()?.as_bytes());
        }
        return Ok(());
    }
    if let Ok(list) = obj.downcast::<PyList>() {
        out.put(b"[");
        for (i, item) in list.iter().enumerate() {
            if i > 0 {
                out.put(style.item);
            }
            encode(&item, out, style, depth + 1)?;
        }
        out.put(b"]");
        return Ok(());
    }
    if let Ok(tuple) = obj.downcast::<PyTuple>() {
        out.put(b"[");
        for (i, item) in tuple.iter().enumerate() {
            if i > 0 {
                out.put(style.item);
            }
            encode(&item, out, style, depth + 1)?;
        }
        out.put(b"]");
        return Ok(());
    }
    if let Ok(dict) = obj.downcast::<PyDict>() {
        let mut entries: Vec<(String, Bound<'_, PyAny>)> = Vec::with_capacity(dict.len());
        for (k, v) in dict.iter() {
            let key = k
                .downcast::<PyString>()
                .map_err(|_| Unsupported::new_err("a key that is not a string"))?
                .to_str()
                .map_err(|_| Unsupported::new_err("a key that is not valid Unicode"))?
                .to_owned();
            entries.push((key, v));
        }
        // Python sorts keys by code point; UTF-8 bytes sort the same.
        entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        out.put(b"{");
        for (i, (k, v)) in entries.iter().enumerate() {
            if i > 0 {
                out.put(style.item);
            }
            write_str(out, k);
            out.put(style.key);
            encode(v, out, style, depth + 1)?;
        }
        out.put(b"}");
        return Ok(());
    }
    if style.default_str {
        // json.dumps(default=str): the object's str(), as a string.
        let text = obj.str()?;
        let text = text
            .to_str()
            .map_err(|_| Unsupported::new_err("a string that is not valid Unicode"))?;
        write_str(out, text);
        return Ok(());
    }
    Err(PyTypeError::new_err(format!(
        "Object of type {} is not JSON serializable",
        obj.get_type().name()?
    )))
}

fn style(compact: bool, default_str: bool) -> Style {
    if compact {
        Style { item: b",", key: b":", default_str }
    } else {
        Style { item: b", ", key: b": ", default_str }
    }
}

/// `json.dumps(obj, sort_keys=True, ensure_ascii=True)` as bytes: with `separators=(",", ":")`
/// when `compact`, Python's default separators otherwise; `default=str` when `default_str`.
#[pyfunction]
#[pyo3(signature = (obj, compact=true, default_str=false))]
fn canonical_json<'py>(
    py: Python<'py>,
    obj: &Bound<'py, PyAny>,
    compact: bool,
    default_str: bool,
) -> PyResult<Bound<'py, PyBytes>> {
    let mut out: Vec<u8> = Vec::with_capacity(4096);
    encode(obj, &mut out, &style(compact, default_str), 0)?;
    Ok(PyBytes::new_bound(py, &out))
}

/// `sha256(prefix + canonical_json(body))`, hex.
#[pyfunction]
fn body_root_sha256(py: Python<'_>, prefix: &[u8], body: &Bound<'_, PyAny>) -> PyResult<String> {
    let mut encoded: Vec<u8> = Vec::with_capacity(1 << 20);
    encoded.extend_from_slice(prefix);
    encode(body, &mut encoded, &style(true, false), 0)?;
    // (one pass over the whole: thousands of small updates cost more than the hash)
    let digest = py.allow_threads(|| Sha256::digest(&encoded));
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0xf) as usize] as char);
    }
    Ok(hex)
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("Unsupported", m.py().get_type_bound::<Unsupported>())?;
    m.add_function(wrap_pyfunction!(mldsa65_verify_batch, m)?)?;
    m.add_function(wrap_pyfunction!(threads, m)?)?;
    m.add_function(wrap_pyfunction!(mldsa65_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(canonical_json, m)?)?;
    m.add_function(wrap_pyfunction!(body_root_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(lthash::lt_apply, m)?)?;
    m.add_function(wrap_pyfunction!(smt::smt_update, m)?)?;
    m.add_function(wrap_pyfunction!(mtree::mt_build, m)?)?;
    m.add_function(wrap_pyfunction!(mtree::mt_update, m)?)?;
    m.add_function(wrap_pyfunction!(mtree::mt_prove, m)?)?;
    m.add_class::<mtree::MNode>()?;
    m.add_function(wrap_pyfunction!(lthash::lt_mix_entries, m)?)?;
    m.add_function(wrap_pyfunction!(dec::dec_eval, m)?)?;
    m.add_class::<book::NativeBook>()?;
    m.add_function(wrap_pyfunction!(book::float_repr, m)?)?;
    m.add_function(wrap_pyfunction!(book::blake2b_person, m)?)?;
    m.add_function(wrap_pyfunction!(lane::lane_judge, m)?)?;
    m.add_function(wrap_pyfunction!(lane::lane_run, m)?)?;
    m.add_class::<net::NetService>()?;
    Ok(())
}
