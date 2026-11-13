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
//!
//! The cache is a Python dict (``smt_update``) or, on the node's path, ``SmtNodes``: the nodes
//! held here, so a read crosses no Python object, and ``smt_update_into`` hands back the new and
//! stale nodes already packed as the store keeps them (the node's ~3,000 a block were packed one
//! at a time in Python).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

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
    if depth == 0 {
        return "0".to_string();
    }
    // The first ``depth`` bits as a number: padded at the front to whole nibbles.
    let pad = (4 - depth % 4) % 4;
    let mut out = String::with_capacity(depth / 4 + 1);
    let mut started = false;
    let mut at = 0usize; // (the next bit of the key)
    for j in 0..(depth + pad) / 4 {
        let mut n = 0u32;
        for b in 0..4 {
            let i = j * 4 + b;
            let one = if i < pad {
                false
            } else {
                let one = bit(key, at);
                at += 1;
                one
            };
            n = (n << 1) | one as u32;
        }
        if n != 0 || started {
            started = true;
            out.push(char::from_digit(n, 16).expect("a nibble"));
        }
    }
    if out.is_empty() {
        out.push('0');
    }
    out
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

/// Where an update reads the nodes it did not write.
trait NodeSource {
    fn with_node<R>(&self, nkey: &str, f: impl FnOnce(&[u8]) -> R) -> Option<R>;
}

impl<'py> NodeSource for Bound<'py, PyDict> {
    fn with_node<R>(&self, nkey: &str, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
        let v = self.get_item(nkey).ok().flatten()?;
        let b = v.downcast::<PyBytes>().ok()?;
        Some(f(b.as_bytes()))
    }
}

struct Tree<'a, C: NodeSource> {
    cache: &'a C,
    version: u64,
    /// The writes, as a Python dict keeps them: insertion order, a deleted key re-inserted at
    /// the end.
    writes: Vec<Option<(String, Vec<u8>)>>,
    index: HashMap<String, usize>,
    stale: Vec<String>,
    /// Nodes found missing: every one this pass could reach, so one load serves them all.
    missing: Vec<String>,
    /// Subtrees already updated on other threads (``update_split``): at this depth, by the
    /// position of their first change.
    parts: Option<(usize, HashMap<usize, Part>)>,
}

/// A subtree's update, done apart: what ``update`` returned, and what it wrote, made stale and
/// found missing, in order.
struct Part {
    out: Result<Option<Ref>, Missing>,
    writes: Vec<Option<(String, Vec<u8>)>>,
    stale: Vec<String>,
    missing: Vec<String>,
}

/// Fewer changes than this are applied on the calling thread.
const SPLIT_FROM: usize = 256;

impl<'a, C: NodeSource> Tree<'a, C> {
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
        let decoded = match self.index.get(&r.nkey) {
            Some(&i) => Node::decode(&self.writes[i].as_ref().expect("an indexed write").1),
            None => self.cache.with_node(&r.nkey, Node::decode).flatten(),
        };
        decoded.ok_or_else(|| Missing(r.nkey.clone()))
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

    /// The subtree of ``live`` (sorted, distinct keys, all present) below ``depth``. Sorted keys
    /// sharing their first ``depth`` bits split at one point by the next.
    fn build(&mut self, depth: usize, live: &[(Vec<u8>, Vec<u8>)]) -> Option<Ref> {
        match live.len() {
            0 => None,
            1 => Some(self.leaf(depth, &live[0].0, &live[0].1)),
            _ => {
                let split = live.partition_point(|c| !bit(&c.0, depth));
                let lref = self.build(depth + 1, &live[..split]);
                let rref = self.build(depth + 1, &live[split..]);
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

    /// ``changes`` (sorted; ``at``: the position of the first among all of the update's) applied
    /// below ``r`` at ``depth``.
    fn update(
        &mut self,
        r: Option<Ref>,
        changes: &[Change],
        depth: usize,
        at: usize,
    ) -> Result<Option<Ref>, Missing> {
        if changes.is_empty() {
            return Ok(r);
        }
        if let Some(part) = self.parts.as_mut().filter(|(d, _)| *d == depth).and_then(|(_, p)| p.remove(&at)) {
            for (nkey, data) in part.writes.into_iter().flatten() {
                self.write(nkey, data);
            }
            self.stale.extend(part.stale);
            self.missing.extend(part.missing);
            return part.out;
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
                // (sorted, under one node: the changes split at one point by this depth's bit)
                let split = changes.partition_point(|c| !bit(&c.0, depth));
                let (lc, rc) = (&changes[..split], &changes[split..]);
                // (both sides, even if one is missing a node: every missing node in one pass)
                let lres = if lc.is_empty() {
                    Ok(left.clone())
                } else {
                    self.update(left.clone(), lc, depth + 1, at)
                };
                let rres = if rc.is_empty() {
                    Ok(right.clone())
                } else {
                    self.update(right.clone(), rc, depth + 1, at + split)
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

impl<'a, C: NodeSource + Sync> Tree<'a, C> {
    /// ``update(root, changes, 0, 0)``, the subtrees some levels down updated on the module's
    /// threads: the levels above them are walked first (``plan``), each subtree below is
    /// updated apart, and the walk from the root then takes each one's result, writes, stale
    /// nodes and missing ones where it would have made them itself — the same in every byte
    /// and in the same order.
    fn update_split(&mut self, root: Option<Ref>, changes: &[Change]) -> Result<Option<Ref>, Missing> {
        use rayon::prelude::*;

        let threads = rayon::current_num_threads();
        if changes.len() < SPLIT_FROM || threads < 2 {
            return self.update(root, changes, 0, 0);
        }
        // (about four subtrees a thread, each with enough changes to be worth one)
        let mut depth = 1;
        while (1usize << depth) < 4 * threads && changes.len() >> depth >= 32 && depth < 12 {
            depth += 1;
        }
        let mut tasks: Vec<(usize, Option<Ref>, usize)> = Vec::new();
        self.plan(root.clone(), changes, 0, 0, depth, &mut tasks);
        if tasks.len() < 2 {
            return self.update(root, changes, 0, 0);
        }
        let (cache, version) = (self.cache, self.version);
        let done: Vec<Part> = tasks
            .par_iter()
            .map(|(at, r, n)| {
                let mut t = Tree {
                    cache,
                    version,
                    writes: Vec::new(),
                    index: HashMap::new(),
                    stale: Vec::new(),
                    missing: Vec::new(),
                    parts: None,
                };
                let out = t.update(r.clone(), &changes[*at..*at + *n], depth, *at);
                Part { out, writes: t.writes, stale: t.stale, missing: t.missing }
            })
            .collect();
        self.parts = Some((depth, tasks.iter().map(|(at, ..)| *at).zip(done).collect()));
        let out = self.update(root, changes, 0, 0);
        self.parts = None;
        out
    }

    /// The subtrees at ``depth`` the walk from ``r`` reaches through internal nodes with changes
    /// below them: (position of the first change, the subtree, how many changes).
    fn plan(
        &self,
        r: Option<Ref>,
        changes: &[Change],
        at: usize,
        level: usize,
        depth: usize,
        tasks: &mut Vec<(usize, Option<Ref>, usize)>,
    ) {
        if changes.is_empty() {
            return;
        }
        if level == depth {
            tasks.push((at, r, changes.len()));
            return;
        }
        // (a leaf, nothing, or a node not held: the walk from the root does it there)
        let Some(r) = r else { return };
        let Ok(Node::Internal { left, right }) = self.node(&r) else { return };
        let split = changes.partition_point(|c| !bit(&c.0, level));
        self.plan(left, &changes[..split], at, level + 1, depth, tasks);
        self.plan(right, &changes[split..], at + split, level + 1, depth, tasks);
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
    let parsed = parse_changes(changes)?;
    let mut tree = Tree {
        cache,
        version,
        writes: Vec::new(),
        index: HashMap::new(),
        stale: Vec::new(),
        missing: Vec::new(),
        parts: None,
    };
    match tree.update(root, &parsed, 0, 0) {
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

/// The state tree's nodes this process holds (qrdx/state_proofs.py), by node key: the most
/// recently used kept, down to ``capacity`` after each update (``smt_update_into``). Loads
/// past twice ``capacity`` evict too, but only nodes last used before the latest update
/// settled: an update's missing nodes, loaded between its passes, stay until it settles.
#[pyclass(module = "qrdx_native")]
pub struct SmtNodes {
    map: HashMap<String, (Vec<u8>, AtomicU64)>,
    tick: AtomicU64,
    capacity: usize,
    settled: u64,
}

impl SmtNodes {
    fn stamp(&self) -> u64 {
        self.tick.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn put(&mut self, nkey: String, data: Vec<u8>) {
        let t = self.stamp();
        self.map.insert(nkey, (data, AtomicU64::new(t)));
    }

    /// Down to nine tenths of the capacity once past ``limit``, the least recently used first,
    /// evicting none used after ``protect``.
    fn trim(&mut self, limit: usize, protect: u64) {
        if self.map.len() <= limit {
            return;
        }
        let keep = self.capacity * 9 / 10;
        let mut stamps: Vec<u64> =
            self.map.values().map(|(_, t)| t.load(Ordering::Relaxed)).filter(|&t| t <= protect).collect();
        let drop = (self.map.len() - keep).min(stamps.len());
        if drop == 0 {
            return;
        }
        let (_, &mut cut, _) = stamps.select_nth_unstable(drop - 1);
        self.map.retain(|_, (_, t)| t.load(Ordering::Relaxed) > cut);
    }
}

impl NodeSource for SmtNodes {
    fn with_node<R>(&self, nkey: &str, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
        let (data, t) = self.map.get(nkey)?;
        t.store(self.stamp(), Ordering::Relaxed);
        Some(f(data))
    }
}

#[pymethods]
impl SmtNodes {
    #[new]
    #[pyo3(signature = (capacity=200_000))]
    fn new(capacity: usize) -> Self {
        SmtNodes { map: HashMap::new(), tick: AtomicU64::new(0), capacity: capacity.max(1), settled: 0 }
    }

    fn __len__(&self) -> usize {
        self.map.len()
    }

    fn __contains__(&self, nkey: &str) -> bool {
        self.map.contains_key(nkey)
    }

    /// A node's bytes (None if not held).
    fn get<'py>(&self, py: Python<'py>, nkey: &str) -> Option<Bound<'py, PyBytes>> {
        self.with_node(nkey, |d| PyBytes::new_bound(py, d))
    }

    /// Hold nodes: ``[(nkey, bytes)]``.
    fn insert_many(&mut self, items: &Bound<'_, PyList>) -> PyResult<()> {
        for item in items.iter() {
            let (k, v): (String, Bound<'_, PyBytes>) = item.extract()?;
            self.put(k, v.as_bytes().to_vec());
        }
        let (limit, protect) = (2 * self.capacity, self.settled);
        self.trim(limit, protect);
        Ok(())
    }

    fn clear(&mut self) {
        self.map.clear();
    }
}

fn parse_changes(changes: &Bound<'_, PyList>) -> PyResult<Vec<Change>> {
    let mut parsed: Vec<Change> = Vec::with_capacity(changes.len());
    for item in changes.iter() {
        let (k, v): (Bound<'_, PyBytes>, Option<Bound<'_, PyBytes>>) = item.extract()?;
        let k = k.as_bytes();
        if k.len() != 32 {
            return Err(PyValueError::new_err("a key is 32 bytes"));
        }
        parsed.push((k.to_vec(), v.map(|v| v.as_bytes().to_vec())));
    }
    // (the walk splits sorted changes by position: in key order, a later duplicate after an
    // earlier one, as a stable sort leaves them)
    parsed.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(parsed)
}

/// ``smt_update`` over the nodes ``nodes`` holds, writing the new ones to it. Returns
/// ``("ok", root as encode_ref writes it, [(store key, store value)] of the new nodes,
/// [(store key, b"")] of the stale ones)`` — as ``smt_nodes`` (``(nkey,)`` → ``(data,)``) and
/// ``smt_stale`` (``(version, nkey)`` → ``()``) keep them — or ``("missing", [nkey, ...])``.
/// Given ``store`` and its ``(smt_nodes, smt_stale)`` table ids, it writes them there itself
/// and returns how many of each instead (``("ok", root, n_new, n_stale)``).
#[pyfunction]
#[pyo3(signature = (root, changes, version, nodes, store=None, tables=None))]
pub fn smt_update_into<'py>(
    py: Python<'py>,
    root: &[u8],
    changes: &Bound<'py, PyList>,
    version: u64,
    nodes: &Bound<'py, SmtNodes>,
    store: Option<&Bound<'py, crate::store::Store>>,
    tables: Option<(usize, usize)>,
) -> PyResult<PyObject> {
    use crate::store::codec::{escaped_into, uint_into, BYTES_TAG, STRING_TAG};

    let (root, _) = Ref::decode(root, 0).ok_or_else(|| PyValueError::new_err("bad root ref"))?;
    let parsed = parse_changes(changes)?;
    let mut held = nodes.borrow_mut();
    let (outcome, writes, stale, missing) = {
        let mut tree = Tree {
            cache: &*held,
            version,
            writes: Vec::new(),
            index: HashMap::new(),
            stale: Vec::new(),
            missing: Vec::new(),
            parts: None,
        };
        let outcome = py.allow_threads(|| tree.update_split(root, &parsed));
        (outcome, tree.writes, tree.stale, tree.missing)
    };
    match outcome {
        Err(_) => {
            let mut missing = missing;
            missing.sort();
            missing.dedup();
            Ok(("missing", missing).into_py(py))
        }
        Ok(new_root) => {
            let mut encoded = Vec::new();
            encode_ref(&new_root, &mut encoded);
            if let (Some(store), Some((nodes_table, stale_table))) = (store, tables) {
                let mut prefix = Vec::with_capacity(9);
                uint_into(&mut prefix, version);
                let gone: Vec<(Vec<u8>, Vec<u8>)> = stale
                    .iter()
                    .map(|k| {
                        let mut key = prefix.clone();
                        escaped_into(&mut key, STRING_TAG, k.as_bytes());
                        (key, Vec::new())
                    })
                    .collect();
                let mut packed: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(writes.len());
                for (k, v) in writes.into_iter().flatten() {
                    let mut key = Vec::with_capacity(k.len() + 2);
                    escaped_into(&mut key, STRING_TAG, k.as_bytes());
                    let mut value = Vec::with_capacity(v.len() + 8);
                    escaped_into(&mut value, BYTES_TAG, &v);
                    packed.push((key, value));
                    held.put(k, v);
                }
                let (capacity, now) = (held.capacity, held.tick.load(Ordering::Relaxed));
                held.trim(capacity, now);
                held.settled = held.tick.load(Ordering::Relaxed);
                let (n_new, n_stale) = (packed.len(), gone.len());
                let store = store.borrow();
                store.write_packed(nodes_table, packed)?;
                store.write_packed(stale_table, gone)?;
                return Ok(("ok", PyBytes::new_bound(py, &encoded), n_new, n_stale).into_py(py));
            }
            let packed = PyList::empty_bound(py);
            for (k, v) in writes.into_iter().flatten() {
                let mut key = Vec::with_capacity(k.len() + 2);
                escaped_into(&mut key, STRING_TAG, k.as_bytes());
                let mut value = Vec::with_capacity(v.len() + 8);
                escaped_into(&mut value, BYTES_TAG, &v);
                packed.append((PyBytes::new_bound(py, &key), PyBytes::new_bound(py, &value)))?;
                held.put(k, v);
            }
            let (capacity, now) = (held.capacity, held.tick.load(Ordering::Relaxed));
            held.trim(capacity, now);
            held.settled = held.tick.load(Ordering::Relaxed);
            let gone = PyList::empty_bound(py);
            let mut prefix = Vec::with_capacity(9);
            uint_into(&mut prefix, version);
            let nothing = PyBytes::new_bound(py, b"");
            for k in stale {
                let mut key = prefix.clone();
                escaped_into(&mut key, STRING_TAG, k.as_bytes());
                gone.append((PyBytes::new_bound(py, &key), nothing.clone()))?;
            }
            Ok(("ok", PyBytes::new_bound(py, &encoded), packed, gone).into_py(py))
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

// ── the database tree's entries (qrdx/state_proofs.py ``_changes``) ──────────────────────────

use crate::store::codec::{self, Field};
use num_bigint::{BigInt, Sign};

/// ``_id20``: a 20-byte account id — here only from an account id itself (``0x`` and 40 hex
/// digits), which ``to_account_id`` lowercases; any other form is Python's.
fn id20(f: &Field) -> Option<[u8; 20]> {
    let Field::Str(s) = f else { return None };
    let b = s.as_bytes();
    if b.len() != 42 || b[0] != b'0' || (b[1] != b'x' && b[1] != b'X') {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, pair) in b[2..].chunks(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// ``_addr20``: a token's address as is (``0x`` and 40 hex digits); a symbol is Python's.
fn addr20(f: &Field) -> Option<[u8; 20]> {
    id20(f)
}

fn hex32(h: &str) -> Option<[u8; 32]> {
    let b = h.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in b.chunks(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

fn int32(negative: bool, magnitude: &[u8]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    if negative {
        return Some(out); // (max(0, n))
    }
    let start = magnitude.iter().position(|&b| b != 0).unwrap_or(magnitude.len());
    let m = &magnitude[start..];
    if m.len() > 32 {
        return None; // (Python's to_bytes overflows)
    }
    out[32 - m.len()..].copy_from_slice(m);
    Some(out)
}

/// ``_word``: None or "" as zero, an int as is, 64 hex digits (after an optional ``0x``) as
/// their bytes; anything else (text hashed, a negative int, odd hex) is Python's.
fn word(f: &Field) -> Option<[u8; 32]> {
    match f {
        Field::Null => Some([0u8; 32]),
        Field::Int(negative, magnitude) => int32(*negative, magnitude),
        Field::Str(s) if s.is_empty() => Some([0u8; 32]),
        Field::Str(s) => {
            let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
            hex32(h)
        }
        _ => None,
    }
}

/// ``_int(value, scale)``: max(0, int(Decimal(value) × 10^scale)) — here from an int, or a
/// plain ASCII numeral (a sign, digits, one point); anything else is Python's.
fn int_scaled(f: &Field, scale: u32) -> Option<[u8; 32]> {
    let (negative, digits, frac): (bool, String, String) = match f {
        Field::Null => return Some([0u8; 32]),
        Field::Int(negative, magnitude) => {
            if scale == 0 {
                return int32(*negative, magnitude);
            }
            let n = BigInt::from_bytes_be(if *negative { Sign::Minus } else { Sign::Plus }, magnitude);
            let s = n.to_string();
            let (neg, d) = match s.strip_prefix('-') {
                Some(d) => (true, d.to_string()),
                None => (false, s),
            };
            (neg, d, String::new())
        }
        Field::Str(s) if s.is_empty() => return Some([0u8; 32]),
        Field::Str(s) => {
            let (neg, body) = match s.as_bytes().first() {
                Some(b'-') => (true, &s[1..]),
                Some(b'+') => (false, &s[1..]),
                _ => (false, &s[..]),
            };
            let (whole, frac) = match body.split_once('.') {
                Some((w, f)) => (w, f),
                None => (body, ""),
            };
            if whole.is_empty() && frac.is_empty() {
                return None;
            }
            if !whole.bytes().all(|c| c.is_ascii_digit()) || !frac.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            (neg, whole.to_string(), frac.to_string())
        }
        _ => return None,
    };
    // value × 10^scale, truncated toward zero: the whole digits, then `scale` digits of the fraction
    let mut text = digits;
    let take: String = frac.chars().chain(std::iter::repeat('0')).take(scale as usize).collect();
    text.push_str(&take);
    let n = num_bigint::BigUint::parse_bytes(if text.is_empty() { b"0" } else { text.as_bytes() }, 10)?;
    if negative {
        return Some([0u8; 32]); // (a negative truncates to ≤ 0: max(0, ·))
    }
    int32(false, &n.to_bytes_be())
}

/// One marked row's (key, payload or None), or None where Python must compute it.
fn entry(kind: &str, key: &[Field], row: Option<&[Field]>) -> Option<([u8; 32], Option<Vec<u8>>)> {
    let identity: Vec<u8> = match kind {
        "account" => [&[1u8][..], &id20(key.first()?)?].concat(),
        "storage" => [&[2u8][..], &id20(key.first()?)?, &word(key.get(1)?)?].concat(),
        "token" => [&[3u8][..], &id20(key.get(1)?)?, &addr20(key.first()?)?].concat(),
        _ => return None,
    };
    let ekey = key_of(&identity);
    let Some(r) = row else { return Some((ekey, None)) };
    let payload = match kind {
        "account" => {
            let body = [int_scaled(r.get(1)?, 0)?, int_scaled(r.get(2)?, 0)?, word(r.get(3)?)?, word(r.get(4)?)?].concat();
            if body.iter().all(|&b| b == 0) {
                None
            } else {
                Some([&[1u8][..], &id20(r.first()?)?, &body].concat())
            }
        }
        "storage" => {
            let v = word(r.get(2)?)?;
            if v == [0u8; 32] {
                None
            } else {
                Some([&[2u8][..], &id20(r.first()?)?, &word(r.get(1)?)?, &v].concat())
            }
        }
        _ => {
            let amount = int_scaled(r.get(2)?, 18)?;
            if amount == [0u8; 32] {
                None
            } else {
                Some([&[3u8][..], &id20(r.get(1)?)?, &addr20(r.first()?)?, &amount].concat())
            }
        }
    };
    Some((ekey, payload))
}

/// ``state_proofs._changes`` for one table's marked rows: each (packed key, packed value or
/// None) to (entry key, payload or None) — ``columns`` pick the payload's columns from the key's
/// fields followed by the value's — or None where only Python can compute it exactly.
#[pyfunction]
pub fn smt_entries<'py>(
    py: Python<'py>,
    kind: &str,
    items: &Bound<'py, PyList>,
    columns: Vec<usize>,
) -> PyResult<Bound<'py, PyList>> {
    let out = PyList::empty_bound(py);
    for item in items.iter() {
        let (k, v): (Bound<'py, PyBytes>, Option<Bound<'py, PyBytes>>) = item.extract()?;
        let key = codec::fields(k.as_bytes()).ok();
        let row = match (&key, &v) {
            (Some(key), Some(v)) => codec::fields(v.as_bytes()).ok().map(|vals| {
                let all: Vec<Field> = key.iter().cloned().chain(vals).collect();
                columns.iter().filter_map(|&i| all.get(i).cloned()).collect::<Vec<Field>>()
            }),
            _ => None,
        };
        let got = match (&key, &v, &row) {
            (Some(key), None, _) => entry(kind, key, None),
            (Some(key), Some(_), Some(row)) if row.len() == columns.len() => entry(kind, key, Some(row)),
            _ => None,
        };
        match got {
            Some((ekey, payload)) => out.append((
                PyBytes::new_bound(py, &ekey),
                payload.map(|p| PyBytes::new_bound(py, &p)),
            ))?,
            None => out.append(py.None())?,
        }
    }
    Ok(out)
}
