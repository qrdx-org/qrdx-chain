//! The exchange's in-memory proof trees, natively (qrdx/crypto/smt.py ``m_build``, ``m_update``,
//! ``m_prove``; qrdx/exchange/commitment.py, qrdx/exchange/orderbook.py, qrdx/exchange/proofs.py).
//!
//! Every exchange collection keeps a sparse Merkle tree of its entries, updated each block from
//! the entries that changed. In Python each update allocated and hashed one node object per
//! level of every changed path: about 22 ms for 1,000 changes to a collection of 100,000
//! entries. Here a tree is the same shape with the same hashes (smt.rs's), its nodes immutable
//! and shared (``Arc``), so a copy of a tree costs nothing — the exchange state is deep-copied
//! every block — and an update allocates only the paths it changes.
//!
//! Keys are 32 bytes (``smt.key_of``) and a call's keys are distinct; anything else is refused
//! (``ValueError``) rather than given a meaning Python's functions never gave it.

use std::sync::Arc;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList, PyTuple};

use crate::smt::{bit, leaf_hash, node_hash, value_hash, EMPTY};

const KEY_BYTES: usize = 32;
const MAX_DEPTH: usize = 8 * KEY_BYTES;

#[derive(Debug)]
pub(crate) struct Node {
    hash: [u8; 32],
    key: Vec<u8>, // a leaf's key; empty for an internal node (Python's ``is_leaf``)
    payload: Vec<u8>,
    left: Option<Arc<Node>>,
    right: Option<Arc<Node>>,
}

impl Node {
    fn is_leaf(&self) -> bool {
        !self.key.is_empty()
    }
}

pub(crate) type Tree = Option<Arc<Node>>;
pub(crate) type Change = (Vec<u8>, Option<Vec<u8>>);

pub(crate) fn hash_of(t: &Tree) -> &[u8; 32] {
    t.as_ref().map_or(&EMPTY, |n| &n.hash)
}

fn same(a: &Tree, b: &Tree) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => Arc::ptr_eq(x, y),
        _ => false,
    }
}

fn leaf(key: &[u8], payload: &[u8]) -> Arc<Node> {
    Arc::new(Node {
        hash: leaf_hash(key, payload),
        key: key.to_vec(),
        payload: payload.to_vec(),
        left: None,
        right: None,
    })
}

fn internal(left: Tree, right: Tree) -> Arc<Node> {
    Arc::new(Node {
        hash: node_hash(hash_of(&left), hash_of(&right)),
        key: Vec::new(),
        payload: Vec::new(),
        left,
        right,
    })
}

/// ``m_build``: the subtree of ``live`` (sorted, distinct, sharing their first ``depth`` bits).
fn build(live: &[(&[u8], &[u8])], depth: usize) -> Tree {
    match live.len() {
        0 => None,
        1 => Some(leaf(live[0].0, live[0].1)),
        _ => {
            // (distinct 256-bit keys part before their last bit)
            assert!(depth < MAX_DEPTH, "distinct keys");
            let split = live.partition_point(|(k, _)| !bit(k, depth));
            let (l, r) = live.split_at(split);
            Some(internal(build(l, depth + 1), build(r, depth + 1)))
        }
    }
}

/// ``m_update``: ``node``'s subtree with ``changes`` (sorted, distinct, sharing the subtree's
/// first ``depth`` bits) applied; ``node`` itself where nothing below it changed.
pub(crate) fn update(node: &Tree, changes: &[Change], depth: usize) -> Tree {
    if changes.is_empty() {
        return node.clone();
    }
    let n = match node {
        None => {
            let live: Vec<(&[u8], &[u8])> = changes
                .iter()
                .filter_map(|(k, v)| v.as_deref().map(|v| (k.as_slice(), v)))
                .collect();
            return build(&live, depth);
        }
        Some(n) => n,
    };
    if n.is_leaf() {
        // the leaf's entry, unless a change names its key, then the changes; sorted, live
        let mut merged: Vec<(&[u8], Option<&[u8]>)> = Vec::with_capacity(changes.len() + 1);
        if changes.binary_search_by(|(k, _)| k.as_slice().cmp(&n.key)).is_err() {
            merged.push((&n.key, Some(&n.payload)));
        }
        merged.extend(changes.iter().map(|(k, v)| (k.as_slice(), v.as_deref())));
        merged.sort_by(|a, b| a.0.cmp(b.0));
        let live: Vec<(&[u8], &[u8])> =
            merged.into_iter().filter_map(|(k, v)| v.map(|v| (k, v))).collect();
        if live.len() == 1 && live[0].0 == n.key.as_slice() && live[0].1 == n.payload.as_slice() {
            return node.clone();
        }
        return build(&live, depth);
    }
    assert!(depth < MAX_DEPTH, "an internal node above the keys' last bit");
    let split = changes.partition_point(|(k, _)| !bit(k, depth));
    let (lc, rc) = changes.split_at(split);
    let l = if lc.is_empty() { n.left.clone() } else { update(&n.left, lc, depth + 1) };
    let r = if rc.is_empty() { n.right.clone() } else { update(&n.right, rc, depth + 1) };
    if same(&l, &n.left) && same(&r, &n.right) {
        return node.clone();
    }
    match (&l, &r) {
        (None, None) => return None,
        (Some(one), None) | (None, Some(one)) if one.is_leaf() => {
            return Some(one.clone()); // (one entry left below: its leaf rises)
        }
        _ => {}
    }
    Some(internal(l, r))
}

fn check_key(key: &[u8]) -> PyResult<()> {
    if key.len() != KEY_BYTES {
        return Err(PyValueError::new_err("a proof-tree key is 32 bytes"));
    }
    Ok(())
}

/// The changes sorted by key, every key 32 bytes and none twice.
fn sorted_changes(mut changes: Vec<Change>) -> PyResult<Vec<Change>> {
    for (k, _) in &changes {
        check_key(k)?;
    }
    changes.sort_by(|a, b| a.0.cmp(&b.0));
    if changes.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(PyValueError::new_err("a key changed twice in one update"));
    }
    Ok(changes)
}

/// A node of a tree (Python's ``smt.MNode``): immutable, so copying one is returning it.
#[pyclass(frozen, module = "qrdx_native", name = "MNode")]
pub struct MNode(pub(crate) Arc<Node>);

fn wrap(t: Tree) -> Option<MNode> {
    t.map(MNode)
}

fn unwrap(node: Option<PyRef<'_, MNode>>) -> Tree {
    node.map(|n| n.0.clone())
}

#[pymethods]
impl MNode {
    #[getter]
    fn hash<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.0.hash)
    }

    #[getter]
    fn key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.0.key)
    }

    #[getter]
    fn payload<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.0.payload)
    }

    #[getter]
    fn left(&self) -> Option<MNode> {
        self.0.left.clone().map(MNode)
    }

    #[getter]
    fn right(&self) -> Option<MNode> {
        self.0.right.clone().map(MNode)
    }

    #[getter]
    fn is_leaf(&self) -> bool {
        self.0.is_leaf()
    }

    fn __copy__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    fn __deepcopy__(slf: Py<Self>, _memo: &Bound<'_, PyAny>) -> Py<Self> {
        slf
    }

    /// Pickled as its entries (``smt.m_from_entries`` builds the same tree from them).
    fn __reduce__<'py>(&self, py: Python<'py>) -> PyResult<(PyObject, Bound<'py, PyTuple>)> {
        let mut entries = Vec::new();
        collect(&self.0, &mut entries);
        let list = PyList::empty_bound(py);
        for (k, v) in entries {
            list.append((PyBytes::new_bound(py, k), PyBytes::new_bound(py, v)))?;
        }
        let rebuild = py.import_bound("qrdx.crypto.smt")?.getattr("m_from_entries")?;
        Ok((rebuild.unbind(), PyTuple::new_bound(py, [list])))
    }
}

/// Every (key, payload) below ``n``, in key order.
fn collect<'a>(n: &'a Node, out: &mut Vec<(&'a [u8], &'a [u8])>) {
    if n.is_leaf() {
        out.push((&n.key, &n.payload));
        return;
    }
    for child in [&n.left, &n.right].into_iter().flatten() {
        collect(child, out);
    }
}

/// ``m_build(live)``: the tree of ``live`` [(key, payload)].
#[pyfunction]
pub fn mt_build(py: Python<'_>, live: Vec<(Vec<u8>, Vec<u8>)>) -> PyResult<Option<MNode>> {
    let changes = sorted_changes(live.into_iter().map(|(k, v)| (k, Some(v))).collect())?;
    let tree = py.allow_threads(|| update(&None, &changes, 0));
    Ok(wrap(tree))
}

/// ``m_update(node, changes)``: ``node``'s tree with ``changes`` [(key, payload or None)].
#[pyfunction]
#[pyo3(signature = (node, changes))]
pub fn mt_update(
    py: Python<'_>,
    node: Option<PyRef<'_, MNode>>,
    changes: Vec<Change>,
) -> PyResult<Option<MNode>> {
    let changes = sorted_changes(changes)?;
    let root = unwrap(node);
    let tree = py.allow_threads(|| update(&root, &changes, 0));
    Ok(wrap(tree))
}

/// What ``m_prove`` returns: the siblings from the root down, the leaf the walk ends at (its key
/// and its payload's hash) and that leaf's payload.
type Proof<'py> = (
    Vec<Bound<'py, PyBytes>>,
    Option<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)>,
    Option<Bound<'py, PyBytes>>,
);

/// ``m_prove(root, key)``.
#[pyfunction]
#[pyo3(signature = (root, key))]
pub fn mt_prove<'py>(
    py: Python<'py>,
    root: Option<PyRef<'_, MNode>>,
    key: Vec<u8>,
) -> PyResult<Proof<'py>> {
    check_key(&key)?;
    let mut siblings = Vec::new();
    let mut node = unwrap(root);
    let mut depth = 0;
    while let Some(n) = node {
        if n.is_leaf() {
            let terminal = (
                PyBytes::new_bound(py, &n.key),
                PyBytes::new_bound(py, &value_hash(&n.payload)),
            );
            return Ok((siblings, Some(terminal), Some(PyBytes::new_bound(py, &n.payload))));
        }
        let (next, other) = if bit(&key, depth) {
            (&n.right, &n.left)
        } else {
            (&n.left, &n.right)
        };
        siblings.push(PyBytes::new_bound(py, hash_of(other)));
        node = next.clone();
        depth += 1;
    }
    Ok((siblings, None, None))
}
