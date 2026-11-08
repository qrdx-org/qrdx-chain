//! The state-proof tree's update, natively (qrdx/crypto/smt.py ``Tree.update``; qrdx/state_proofs.py).
//!
//! Every block folds the database rows it changed into a compressed sparse Merkle tree whose
//! nodes are stored by ``version:depth:path``. In Python the update walked the tree one awaited
//! node at a time, about 1,200 nodes for a block of 500 transfers: 23 ms. Here it is the same
//! walk, with the same node encoding, hashes, writes and stale list, byte for byte.
//!
//! Nodes come from the update's own writes, then from the caller's cache (``nkey`` → bytes).
//! One that is in neither is not loaded here: the update stops and names it, the caller loads it
//! and runs the update again (it is a pure function of the tree, the changes and the version).

use std::collections::HashMap;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyString};

pub(crate) const EMPTY: [u8; 32] = [0u8; 32];
const LEAF: &[u8] = b"qrdx/smt/leaf/v1\x00";
const NODE: &[u8] = b"qrdx/smt/node/v1\x00";
const VALUE: &[u8] = b"qrdx/smt/value/v1\x00";

pub(crate) fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut d = Blake2b::<U32>::new();
    for p in parts {
        d.update(p);
    }
    d.finalize().into()
}

/// ``smt.key_of``: an entry's 32-byte key in a tree.
pub(crate) fn key_of(identity: &[u8]) -> [u8; 32] {
    h(&[b"qrdx/smt/key/v1\x00", identity])
}

pub(crate) fn value_hash(payload: &[u8]) -> [u8; 32] {
    h(&[VALUE, payload])
}

pub(crate) fn leaf_hash(key: &[u8], payload: &[u8]) -> [u8; 32] {
    h(&[LEAF, key, &value_hash(payload)])
}

pub(crate) fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    h(&[NODE, left, right])
}

pub(crate) fn bit(key: &[u8], i: usize) -> bool {
    (key[i >> 3] >> (7 - (i & 7))) & 1 == 1
}

/// The first ``depth`` bits of ``key`` as a number, in lowercase hex without leading zeros
/// (Python's ``f"{path:x}"``).
fn path_hex(key: &[u8], depth: usize) -> String {
    let mut digits: Vec<u8> = Vec::new(); // big-endian bits → nibbles
    let mut value: Vec<bool> = (0..depth).map(|i| bit(key, i)).collect();
    if value.is_empty() {
        return "0".to_string();
    }
    let pad = (4 - value.len() % 4) % 4;
    let mut bits: Vec<bool> = vec![false; pad];
    bits.append(&mut value);
    for chunk in bits.chunks(4) {
        let n = chunk.iter().fold(0u8, |acc, &b| (acc << 1) | b as u8);
        digits.push(n);
    }
    let first = digits.iter().position(|&d| d != 0).unwrap_or(digits.len() - 1);
    digits[first..]
        .iter()
        .map(|&d| char::from_digit(d as u32, 16).expect("a nibble"))
        .collect()
}

#[derive(Clone, PartialEq, Eq)]
struct Ref {
    hash: [u8; 32],
    nkey: String,
    leaf: bool,
}

impl Ref {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(if self.leaf { 2 } else { 1 });
        out.extend_from_slice(&self.hash);
        out.push(self.nkey.len() as u8);
        out.extend_from_slice(self.nkey.as_bytes());
    }

    fn decode(data: &[u8], at: usize) -> Option<(Option<Ref>, usize)> {
        let flag = *data.get(at)?;
        if flag == 0 {
            return Some((None, at + 1));
        }
        let hash: [u8; 32] = data.get(at + 1..at + 33)?.try_into().ok()?;
        let n = *data.get(at + 33)? as usize;
        let nkey = std::str::from_utf8(data.get(at + 34..at + 34 + n)?).ok()?;
        Some((
            Some(Ref {
                hash,
                nkey: nkey.to_string(),
                leaf: flag == 2,
            }),
            at + 34 + n,
        ))
    }
}

fn encode_ref(r: &Option<Ref>, out: &mut Vec<u8>) {
    match r {
        None => out.push(0),
        Some(r) => r.encode(out),
    }
}

enum Node {
    Leaf { key: Vec<u8>, payload: Vec<u8> },
    Internal { left: Option<Ref>, right: Option<Ref> },
}

impl Node {
    fn encode(&self) -> Vec<u8> {
        match self {
            Node::Leaf { key, payload } => {
                let mut out = Vec::with_capacity(1 + key.len() + payload.len());
                out.push(b'L');
                out.extend_from_slice(key);
                out.extend_from_slice(payload);
                out
            }
            Node::Internal { left, right } => {
                let mut out = vec![b'I'];
                encode_ref(left, &mut out);
                encode_ref(right, &mut out);
                out
            }
        }
    }

    fn decode(data: &[u8]) -> Option<Node> {
        if data.first() == Some(&b'L') {
            return Some(Node::Leaf {
                key: data.get(1..33)?.to_vec(),
                payload: data.get(33..)?.to_vec(),
            });
        }
        let (left, at) = Ref::decode(data, 1)?;
        let (right, _) = Ref::decode(data, at)?;
        Some(Node::Internal { left, right })
    }
}

type Change = (Vec<u8>, Option<Vec<u8>>);

/// What a node read needs: in the writes, in the cache, or missing.
struct Missing(String);

struct Tree<'a, 'py> {
    cache: &'a Bound<'py, PyDict>,
    version: u64,
    /// The writes, as a Python dict keeps them: insertion order, a deleted key re-inserted at
    /// the end.
    writes: Vec<Option<(String, Vec<u8>)>>,
    index: HashMap<String, usize>,
    stale: Vec<String>,
    /// Nodes found missing: every one this pass could reach, so one load serves them all.
    missing: Vec<String>,
}

impl<'a, 'py> Tree<'a, 'py> {
    fn nkey(&self, depth: usize, key: &[u8]) -> String {
        format!("{}:{}:{}", self.version, depth, path_hex(key, depth))
    }

    fn write(&mut self, nkey: String, data: Vec<u8>) {
        if let Some(&i) = self.index.get(&nkey) {
            self.writes[i] = Some((nkey, data));
        } else {
            self.index.insert(nkey.clone(), self.writes.len());
            self.writes.push(Some((nkey, data)));
        }
    }

    fn node(&self, r: &Ref) -> Result<Node, Missing> {
        let data: Vec<u8> = match self.index.get(&r.nkey) {
            Some(&i) => self.writes[i].as_ref().expect("an indexed write").1.clone(),
            None => match self.cache.get_item(&r.nkey).ok().flatten() {
                Some(v) => match v.downcast::<PyBytes>() {
                    Ok(b) => b.as_bytes().to_vec(),
                    Err(_) => return Err(Missing(r.nkey.clone())),
                },
                None => return Err(Missing(r.nkey.clone())),
            },
        };
        Node::decode(&data).ok_or_else(|| Missing(r.nkey.clone()))
    }

    fn node_or_note(&mut self, r: &Ref) -> Result<Node, Missing> {
        self.node(r).map_err(|m| {
            self.missing.push(m.0.clone());
            m
        })
    }

    fn put(&mut self, depth: usize, key: &[u8], node: Node, hash: [u8; 32]) -> Ref {
        let nkey = self.nkey(depth, key);
        let leaf = matches!(node, Node::Leaf { .. });
        self.write(nkey.clone(), node.encode());
        Ref { hash, nkey, leaf }
    }

    fn leaf(&mut self, depth: usize, key: &[u8], payload: &[u8]) -> Ref {
        let hash = leaf_hash(key, payload);
        let node = Node::Leaf {
            key: key.to_vec(),
            payload: payload.to_vec(),
        };
        self.put(depth, key, node, hash)
    }

    fn discard(&mut self, r: &Ref) {
        if let Some(i) = self.index.remove(&r.nkey) {
            self.writes[i] = None; // (written by this update, then replaced by it)
        } else {
            self.stale.push(r.nkey.clone());
        }
    }

    /// The subtree of ``live`` (sorted, distinct keys, all present) below ``depth``.
    fn build(&mut self, depth: usize, live: &[(Vec<u8>, Vec<u8>)]) -> Option<Ref> {
        match live.len() {
            0 => None,
            1 => Some(self.leaf(depth, &live[0].0, &live[0].1)),
            _ => {
                let (l, r): (Vec<_>, Vec<_>) =
                    live.iter().cloned().partition(|c| !bit(&c.0, depth));
                let lref = self.build(depth + 1, &l);
                let rref = self.build(depth + 1, &r);
                Some(self.internal(depth, &live[0].0, lref, rref))
            }
        }
    }

    fn internal(&mut self, depth: usize, key: &[u8], l: Option<Ref>, r: Option<Ref>) -> Ref {
        let hash = node_hash(
            l.as_ref().map(|x| &x.hash).unwrap_or(&EMPTY),
            r.as_ref().map(|x| &x.hash).unwrap_or(&EMPTY),
        );
        self.put(depth, key, Node::Internal { left: l, right: r }, hash)
    }

    fn update(
        &mut self,
        r: Option<Ref>,
        changes: &[Change],
        depth: usize,
    ) -> Result<Option<Ref>, Missing> {
        if changes.is_empty() {
            return Ok(r);
        }
        let Some(r) = r else {
            let live: Vec<(Vec<u8>, Vec<u8>)> = changes
                .iter()
                .filter_map(|(k, v)| v.clone().map(|v| (k.clone(), v)))
                .collect();
            return Ok(self.build(depth, &live));
        };
        match self.node_or_note(&r)? {
            Node::Leaf { key, payload } => {
                let mut merged: Vec<(Vec<u8>, Option<Vec<u8>>)> = vec![(key.clone(), Some(payload.clone()))];
                for (k, v) in changes {
                    if let Some(slot) = merged.iter_mut().find(|m| &m.0 == k) {
                        slot.1 = v.clone();
                    } else {
                        merged.push((k.clone(), v.clone()));
                    }
                }
                let mut live: Vec<(Vec<u8>, Vec<u8>)> = merged
                    .into_iter()
                    .filter_map(|(k, v)| v.map(|v| (k, v)))
                    .collect();
                live.sort();
                if live.len() == 1 && live[0].0 == key && live[0].1 == payload {
                    return Ok(Some(r)); // unchanged
                }
                self.discard(&r);
                Ok(self.build(depth, &live))
            }
            Node::Internal { left, right } => {
                let (lc, rc): (Vec<Change>, Vec<Change>) =
                    changes.iter().cloned().partition(|c| !bit(&c.0, depth));
                // (both sides, even if one is missing a node: every missing node in one pass)
                let lres = if lc.is_empty() {
                    Ok(left.clone())
                } else {
                    self.update(left.clone(), &lc, depth + 1)
                };
                let rres = if rc.is_empty() {
                    Ok(right.clone())
                } else {
                    self.update(right.clone(), &rc, depth + 1)
                };
                let (lref, rref) = (lres?, rres?);
                if lref == left && rref == right {
                    return Ok(Some(r));
                }
                self.discard(&r);
                if lref.is_none() && rref.is_none() {
                    return Ok(None);
                }
                let lone = match (&lref, &rref) {
                    (None, Some(x)) => Some(x.clone()),
                    (Some(x), None) => Some(x.clone()),
                    _ => None,
                };
                if let Some(lone) = lone.filter(|x| x.leaf) {
                    // one entry left below: its leaf rises to here
                    let Node::Leaf { key, payload } = self.node_or_note(&lone)? else {
                        return Err(Missing(lone.nkey.clone()));
                    };
                    self.discard(&lone);
                    return Ok(Some(self.leaf(depth, &key, &payload)));
                }
                // (a key under this node: the path of the node at this depth)
                let any = changes[0].0.clone();
                Ok(Some(self.internal(depth, &any, lref, rref)))
            }
        }
    }
}

/// ``Tree(load, version).update(root, changes)`` over the nodes in ``cache``. Returns
/// ``("ok", root as encode_ref writes it, [(nkey, data)] in the dict's order, [stale nkey])``, or
/// ``("missing", [nkey, ...])``: nodes neither written nor cached (load them into the cache, and
/// call again).
#[pyfunction]
pub fn smt_update<'py>(
    py: Python<'py>,
    root: &[u8],
    changes: &Bound<'py, PyList>,
    version: u64,
    cache: &Bound<'py, PyDict>,
) -> PyResult<PyObject> {
    let (root, _) = Ref::decode(root, 0).ok_or_else(|| PyValueError::new_err("bad root ref"))?;
    let mut parsed: Vec<Change> = Vec::with_capacity(changes.len());
    for item in changes.iter() {
        let (k, v): (Vec<u8>, Option<Vec<u8>>) = item.extract()?;
        if k.len() != 32 {
            return Err(PyValueError::new_err("a key is 32 bytes"));
        }
        parsed.push((k, v));
    }
    let mut tree = Tree {
        cache,
        version,
        writes: Vec::new(),
        index: HashMap::new(),
        stale: Vec::new(),
        missing: Vec::new(),
    };
    match tree.update(root, &parsed, 0) {
        Err(_) => {
            let mut missing = tree.missing;
            missing.sort();
            missing.dedup();
            Ok(("missing", missing).into_py(py))
        }
        Ok(new_root) => {
            let mut encoded = Vec::new();
            encode_ref(&new_root, &mut encoded);
            let writes = PyList::empty_bound(py);
            for (k, v) in tree.writes.into_iter().flatten() {
                writes.append((PyString::new_bound(py, &k), PyBytes::new_bound(py, &v)))?;
            }
            Ok((
                "ok",
                PyBytes::new_bound(py, &encoded),
                writes,
                tree.stale,
            )
                .into_py(py))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::path_hex;

    #[test]
    fn paths_are_pythons_hex() {
        let key = [0b1011_0000u8; 32];
        assert_eq!(path_hex(&key, 0), "0");
        assert_eq!(path_hex(&key, 1), "1");
        assert_eq!(path_hex(&key, 2), "2"); // 0b10
        assert_eq!(path_hex(&key, 4), "b");
        assert_eq!(path_hex(&key, 5), "16"); // 0b10110
        let zero = [0u8; 32];
        assert_eq!(path_hex(&zero, 9), "0");
    }
}
