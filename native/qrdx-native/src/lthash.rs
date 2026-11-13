//! LtHash (qrdx/crypto/lthash.py): an element's vector, accumulators, and the exchange's
//! accumulator update (``lt_mix_entries``). The node's store folds the database domains' rows
//! with them (src/store, qrdx/state_commitment.py).

use pyo3::prelude::*;
use pyo3::types::PyBytes;

pub(crate) const LANES: usize = 1024;
pub(crate) const SIZE: usize = 4 * LANES;

pub(crate) type Vector = Box<[u16; LANES]>;

/// lthash.entry — the low 16 bits of each little-endian u32 of 4,096 bytes of BLAKE3 over
/// tag | len(data) (u32 LE) | data — added into ``total`` lane by lane (wrapping), with nothing
/// allocated.
#[inline]
pub(crate) fn add_entry(total: &mut [u16; LANES], tag: &[u8], data: &[u8]) -> Option<()> {
    let len = u32::try_from(data.len()).ok()?;
    crate::xof::add4096(&[tag, &len.to_le_bytes(), data], total);
    Some(())
}

/// ``a += b`` lane by lane (wrapping).
#[inline]
pub(crate) fn add_lanes(a: &mut [u16; LANES], b: &[u16; LANES]) {
    for (x, y) in a.iter_mut().zip(b.iter()) {
        *x = x.wrapping_add(*y);
    }
}

/// Fewer items than this are summed on the calling thread: waking the pool costs more.
pub(crate) const SERIAL_BELOW: usize = 48;

/// How many items each of the pool's threads takes at once: one run of ``n`` split evenly, so a
/// thread folds its share into one sum (a task an item cost more than the item).
pub(crate) fn chunk_for(n: usize) -> usize {
    n.div_ceil(rayon::current_num_threads().max(1)).max(16)
}

/// Σ ``entry(tag, item)`` over ``items``, on the module's threads when there are many; None if
/// an item is too long to be an entry.
pub(crate) fn sum<D: AsRef<[u8]> + Sync>(tag: &[u8], items: &[D]) -> Option<[u16; LANES]> {
    use rayon::prelude::*;

    let fold = |part: &[D]| -> Option<[u16; LANES]> {
        let mut total = [0u16; LANES];
        for d in part {
            add_entry(&mut total, tag, d.as_ref())?;
        }
        Some(total)
    };
    if items.len() < SERIAL_BELOW {
        return fold(items);
    }
    items.par_chunks(chunk_for(items.len())).map(fold).try_reduce(
        || [0u16; LANES],
        |mut a, b| {
            add_lanes(&mut a, &b);
            Some(a)
        },
    )
}

/// ``lthash.Accumulator`` over ``items`` (each ``entry(tag, item)``): the digest's 4,096 bytes.
pub(crate) fn accumulate<'a>(tag: &[u8], items: impl Iterator<Item = &'a [u8]>) -> Option<Vec<u8>> {
    let mut total = [0u16; LANES];
    for item in items {
        add_entry(&mut total, tag, item)?;
    }
    let mut out = vec![0u8; SIZE];
    for (i, lane) in total.iter().enumerate() {
        out[4 * i..4 * i + 2].copy_from_slice(&lane.to_le_bytes());
    }
    Some(out)
}

/// Whether a plain decimal numeral (sign, digits, one point, an exponent: nothing else) is
/// zero; None for anything else, which Python's Decimal judges.
pub(crate) fn plain_zero(s: &str) -> Option<bool> {
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

#[pyfunction]
pub fn lt_mix_entries<'py>(
    py: Python<'py>,
    acc: &[u8],
    tag: &[u8],
    removed: &Bound<'py, PyAny>,
    added: &Bound<'py, PyAny>,
) -> PyResult<Option<Bound<'py, PyBytes>>> {
    // (the digests read where they are: a Vec<u8> each was copied a byte at a time)
    let held = |items: &Bound<'py, PyAny>| -> PyResult<Vec<Bound<'py, PyBytes>>> {
        items.iter()?.map(|item| Ok(item?.downcast_into::<PyBytes>()?)).collect()
    };
    let (removed, added) = (held(removed)?, held(added)?);
    let minus: Vec<&[u8]> = removed.iter().map(|b| b.as_bytes()).collect();
    let plus: Vec<&[u8]> = added.iter().map(|b| b.as_bytes()).collect();
    let out = py.allow_threads(|| mix(acc, tag, &minus, &plus));
    Ok(out.map(|out| PyBytes::new_bound(py, &out)))
}

/// ``lt_mix_entries`` without Python: the new accumulator, or None if ``acc`` is not well formed.
pub(crate) fn mix<D: AsRef<[u8]> + Sync>(acc: &[u8], tag: &[u8], removed: &[D], added: &[D]) -> Option<Vec<u8>> {
    if acc.len() != SIZE || acc.chunks(4).any(|slot| slot[2] != 0 || slot[3] != 0) {
        return None;
    }
    let (minus, plus) = (sum(tag, removed)?, sum(tag, added)?);
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
