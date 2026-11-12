//! A committed collection's changed entries, committed together (qrdx/exchange/commitment.py,
//! ``CommittedDict.commitment``).
//!
//! The exchange commits each keyed collection entry by entry: an entry's canonical bytes are
//! ``canonical([key, encoded value])``, its digest their BLAKE2b (person ``qrdx-exch-v1``), the
//! collection's accumulator the LtHash of its entries' digests, and its proof tree holds each
//! entry under ``key_of(TREE_KEY | canonical(key))``. For the collections of plain values —
//! nonces, shares, allowances: an entry ``[key, str(value)]`` of two strings JSON writes as they
//! are — Python spent about 6 µs an entry on that, a block of transfers changing hundreds of
//! nonces. ``commit_plain`` does it for every changed entry in one call; any key or value that
//! is not such a string, and Python commits the collection itself.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};

use crate::book::blake2b_personal;
use crate::lthash;
use crate::mtree::{self, MNode};
use crate::smt;

const PERSON: &[u8] = b"qrdx-exch-v1";
const TREE_KEY: u8 = 0x20;

/// ``commitment._plain``: printable ASCII with nothing JSON escapes.
fn plain(s: &str) -> bool {
    s.bytes().all(|c| (0x20..=0x7e).contains(&c) && c != b'"' && c != b'\\')
}

/// What one changed entry commits: its new digest (None: removed), and whether it changed.
type Out<'py> = (Bound<'py, PyBytes>, Option<MNode>, Vec<Option<Bound<'py, PyBytes>>>);

/// ``CommittedDict.commitment`` over ``items`` = [(key, ``str`` of its value or None where the
/// key is gone, the digest held for it or None)]: (the accumulator, the proof tree when
/// ``update_tree``, each entry's digest now). None where a key or value is not plain, or the
/// accumulator not one: Python commits them.
#[pyfunction]
#[pyo3(signature = (tag, acc, tree, update_tree, items))]
#[allow(clippy::type_complexity)]
pub fn commit_plain<'py>(
    py: Python<'py>,
    tag: &[u8],
    acc: &[u8],
    tree: Option<PyRef<'py, MNode>>,
    update_tree: bool,
    items: Vec<(Bound<'py, PyString>, Option<Bound<'py, PyString>>, Option<Bound<'py, PyBytes>>)>,
) -> PyResult<Option<Out<'py>>> {
    // Each entry's canonical bytes, and its key's (the tree's identity of it).
    let mut entries: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::with_capacity(items.len());
    let mut held: Vec<Option<Bound<'py, PyBytes>>> = Vec::with_capacity(items.len());
    for (key, value, old) in items {
        let key = key.to_cow()?;
        if !plain(&key) {
            return Ok(None);
        }
        let raw = match value {
            None => None,
            Some(v) => {
                let v = v.to_cow()?;
                if !plain(&v) {
                    return Ok(None);
                }
                let mut raw = Vec::with_capacity(key.len() + v.len() + 7);
                raw.extend_from_slice(b"[\"");
                raw.extend_from_slice(key.as_bytes());
                raw.extend_from_slice(b"\",\"");
                raw.extend_from_slice(v.as_bytes());
                raw.extend_from_slice(b"\"]");
                Some(raw)
            }
        };
        let mut identity = Vec::with_capacity(key.len() + 3);
        identity.push(TREE_KEY);
        identity.push(b'"');
        identity.extend_from_slice(key.as_bytes());
        identity.push(b'"');
        entries.push((identity, raw));
        held.push(old);
    }
    // (the digests held, read where they are: the bytes outlive the threads' use of them)
    let olds: Vec<Option<&[u8]>> = held.iter().map(|o| o.as_ref().map(|b| b.as_bytes())).collect();
    let root = tree.map(|t| t.0.clone());
    let done = py.allow_threads(|| {
        let mut digests: Vec<Option<[u8; 32]>> = Vec::with_capacity(entries.len());
        let mut removed: Vec<Vec<u8>> = Vec::new();
        let mut added: Vec<[u8; 32]> = Vec::new();
        let mut changes: Vec<mtree::Change> = Vec::new();
        for ((identity, raw), old) in entries.iter().zip(olds.iter()) {
            let new: Option<[u8; 32]> = raw.as_ref().map(|r| {
                let d = blake2b_personal(r, PERSON);
                let mut out = [0u8; 32];
                out.copy_from_slice(&d);
                out
            });
            digests.push(new);
            let old = *old;
            if old != new.as_ref().map(|d| &d[..]) {
                if let Some(o) = old {
                    removed.push(o.to_vec());
                }
                if let Some(n) = new {
                    added.push(n);
                }
                if update_tree {
                    changes.push((smt::key_of(identity).to_vec(), raw.clone()));
                }
            }
        }
        let acc = if removed.is_empty() && added.is_empty() {
            Some(acc.to_vec())
        } else {
            lthash::mix(acc, tag, &removed, &added.iter().map(|d| d.to_vec()).collect::<Vec<_>>())
        }?;
        changes.sort_by(|a, b| a.0.cmp(&b.0));
        let tree = if update_tree && !changes.is_empty() {
            mtree::update(&root, &changes, 0)
        } else {
            root
        };
        Some((acc, tree, digests))
    });
    let Some((acc, tree, digests)) = done else {
        return Ok(None);
    };
    Ok(Some((
        PyBytes::new_bound(py, &acc),
        tree.map(MNode),
        digests
            .into_iter()
            .map(|d| d.map(|d| PyBytes::new_bound(py, &d)))
            .collect(),
    )))
}
