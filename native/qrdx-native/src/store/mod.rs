//! The node's store (qrdx/store.py, docs/STORAGE.md): ordered tables of byte keys and values in
//! one MDBX file, with what the node's SQLite database did by triggers done here, natively, as
//! each row changes.
//!
//! * **Writes wait in memory until a commit.** Every put and delete lands in the table's layer
//!   (a sorted map); reads look there first, then in the file. A commit writes every layer in one
//!   MDBX transaction; a rollback drops them. Nothing a block wrote reaches the file unless the
//!   block is committed whole.
//! * **Commitments.** A table can feed a domain's LtHash accumulator (qrdx/state_commitment.py):
//!   each changed row's entry is removed as it was before the change and added as it is after.
//!   Rows are folded in when the accumulator is read or the layer committed, once per row however
//!   often it changed, their entries computed in parallel.
//! * **The undo journal** (qrdx/undo_journal.py). While a block's height is set, the first change
//!   a block makes to each row of a journaled table records the row as it was, keyed by the
//!   height, in the `__undo` table: `undo_rollback(h)` writes back every row the blocks above `h`
//!   changed, newest first. A change while no height is set (and recording is not suspended) is
//!   recorded at height -1, unattributed: the journal then cannot vouch for a rollback.
//! * **Marks** for the state proof tree (qrdx/state_proofs.py): every changed row of a tracked
//!   table is marked in `__marks` until `take_marks` hands the marks over.
//!
//! The internal tables are written in the same layers, so they commit and roll back with the
//! rows they describe.

pub mod codec;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Bound as Edge;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use libmdbx::{
    Database, DatabaseOptions, Mode, PageSize, ReadWriteOptions, SyncMode, TableFlags,
    Transaction, WriteFlags, WriteMap, RO,
};
use pyo3::exceptions::{PyKeyError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyTuple};

use crate::lthash::{self, Vector, LANES, SIZE};
use codec::Field;

const UNDO: &str = "__undo";
const MARKS: &str = "__marks";
const META: &str = "__meta";
const UNATTRIBUTED: i64 = -1;

type Bytes = Vec<u8>;

fn err<E: std::fmt::Display>(e: E) -> PyErr {
    PyRuntimeError::new_err(format!("store: {e}"))
}

/// A height as 8 bytes that sort as the heights do.
fn height_key(height: i64) -> [u8; 8] {
    ((height as u64) ^ (1 << 63)).to_be_bytes()
}

fn height_of(key: &[u8]) -> i64 {
    (u64::from_be_bytes(key[..8].try_into().unwrap()) ^ (1 << 63)) as i64
}

/// A table's name and a key in one byte string (the internal tables' rows name other tables').
fn named(name: &str, key: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(1 + name.len() + key.len());
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(key);
    out
}

fn unnamed(data: &[u8]) -> Option<(&str, &[u8])> {
    let n = *data.first()? as usize;
    let name = std::str::from_utf8(data.get(1..1 + n)?).ok()?;
    Some((name, &data[1 + n..]))
}

/// What the commitment of a table's row is made of (qrdx/state_commitment.py ``TABLES``).
struct Commitment {
    kind: String,
    domain: usize,
    /// The committed columns: indices into the row's key fields followed by its value fields.
    columns: Vec<usize>,
    /// Python's encoder for the kind, given the committed columns: the rows only it can read.
    fallback: PyObject,
}

struct TableInfo {
    name: String,
    commitment: Option<Commitment>,
    journaled: bool,
    tracked: bool,
    /// Secondary indexes: (the index's table, the columns it is keyed by — indices into the
    /// row's key fields followed by its value fields). An index row's key is those columns'
    /// packing followed by the row's key; its value, the row's key.
    indexes: Vec<(usize, Vec<usize>)>,
}

/// The key of ``row``'s entry in an index on ``columns``: those fields' packing, then the key.
fn index_key(key: &[u8], value: &[u8], columns: &[usize]) -> PyResult<Bytes> {
    let ks = codec::spans(key).map_err(PyValueError::new_err)?;
    let vs = codec::spans(value).map_err(PyValueError::new_err)?;
    let mut out = Vec::with_capacity(key.len() + 32);
    for &c in columns {
        let piece = if c < ks.len() {
            &key[ks[c].0..ks[c].1]
        } else {
            match vs.get(c - ks.len()) {
                Some(&(a, b)) => &value[a..b],
                None => &[0u8][..], // (a column the row predates: None)
            }
        };
        out.extend_from_slice(piece);
    }
    out.extend_from_slice(key);
    Ok(out)
}

#[derive(Default)]
struct Layer {
    writes: BTreeMap<Bytes, Option<Bytes>>,
    /// Every row the file holds is gone (``clear``): reads do not look past the layer.
    cleared: bool,
}

struct Inner {
    env: Arc<Database<WriteMap>>,
    tables: Vec<TableInfo>,
    by_name: HashMap<String, usize>,
    layers: Vec<Layer>,
    domains: Vec<String>,
    accs: Vec<Bytes>,
    committed_accs: Vec<Bytes>,
    /// Rows changed since their domain was last folded: the row as it was then.
    pending: HashMap<(usize, Bytes), Option<Bytes>>,
    height: Option<i64>,
    suspended: u32,
    touched: HashSet<(usize, Bytes)>,
    seq: u64,
    undo: usize,
    marks: usize,
    meta: usize,
    commits: u64,
    commit_seconds: f64,
}

enum Encoded {
    Vector(Vector),
    Nothing,
    /// Only Python can say.
    Python,
}

/// The row's entry, natively (lthash.rs ``encode``), from its committed columns.
fn encode(kind: &str, row: &[Field]) -> Encoded {
    let tag: &[u8] = match kind {
        "account" => b"qrdx/account/v1",
        "storage" => b"qrdx/storage/v1",
        "token" => b"qrdx/token/v1",
        "utxo" => b"qrdx/utxo/v1",
        _ => return Encoded::Python,
    };
    let mut texts = Vec::with_capacity(row.len());
    for f in row {
        match f.text() {
            Some(t) => texts.push(t),
            None => return Encoded::Python,
        }
    }
    if kind == "token" {
        match texts.get(2).and_then(|t| lthash::plain_zero(t)) {
            Some(true) => return Encoded::Nothing,
            Some(false) => {}
            None => return Encoded::Python,
        }
    }
    match lthash::entry(tag, texts.join("\x00").as_bytes()) {
        Some(v) => Encoded::Vector(v),
        None => Encoded::Python,
    }
}

/// The cursor's next row in [lo, hi) (the first, if ``first``), None past the range.
fn step(
    cursor: &mut libmdbx::Cursor<'_, RO>,
    first: bool,
    reverse: bool,
    lo: Option<&[u8]>,
    hi: Option<&[u8]>,
) -> PyResult<Option<(Bytes, Bytes)>> {
    let item = match (first, reverse) {
        (true, true) => match hi {
            Some(h) => match cursor.set_range::<Bytes, Bytes>(h).map_err(err)? {
                Some(_) => cursor.prev::<Bytes, Bytes>().map_err(err)?,
                None => cursor.last::<Bytes, Bytes>().map_err(err)?,
            },
            None => cursor.last::<Bytes, Bytes>().map_err(err)?,
        },
        (true, false) => match lo {
            Some(l) => cursor.set_range::<Bytes, Bytes>(l).map_err(err)?,
            None => cursor.first::<Bytes, Bytes>().map_err(err)?,
        },
        (false, true) => cursor.prev::<Bytes, Bytes>().map_err(err)?,
        (false, false) => cursor.next::<Bytes, Bytes>().map_err(err)?,
    };
    Ok(item.filter(|(k, _)| lo.map_or(true, |l| k.as_slice() >= l) && hi.map_or(true, |h| k.as_slice() < h)))
}

impl Inner {
    fn table(&self, t: usize) -> PyResult<&TableInfo> {
        self.tables.get(t).ok_or_else(|| PyKeyError::new_err(format!("no table {t}")))
    }

    fn ro(&self) -> PyResult<Transaction<'_, RO, WriteMap>> {
        self.env.begin_ro_txn().map_err(err)
    }

    fn file_get(&self, txn: &Transaction<'_, RO, WriteMap>, t: usize, key: &[u8]) -> PyResult<Option<Bytes>> {
        let table = txn.open_table(Some(&self.tables[t].name)).map_err(err)?;
        txn.get::<Bytes>(&table, key).map_err(err)
    }

    fn read_in(&self, txn: &Transaction<'_, RO, WriteMap>, t: usize, key: &[u8]) -> PyResult<Option<Bytes>> {
        let layer = &self.layers[t];
        if let Some(v) = layer.writes.get(key) {
            return Ok(v.clone());
        }
        if layer.cleared {
            return Ok(None);
        }
        self.file_get(txn, t, key)
    }

    fn read(&self, t: usize, key: &[u8]) -> PyResult<Option<Bytes>> {
        let layer = &self.layers[t];
        if let Some(v) = layer.writes.get(key) {
            return Ok(v.clone());
        }
        if layer.cleared {
            return Ok(None);
        }
        let txn = self.ro()?;
        self.file_get(&txn, t, key)
    }

    /// The rows of ``t`` in [lo, hi), merged from the layer and the file, in order (or reversed).
    fn scan(
        &self,
        t: usize,
        lo: Option<&[u8]>,
        hi: Option<&[u8]>,
        reverse: bool,
        limit: Option<usize>,
    ) -> PyResult<Vec<(Bytes, Bytes)>> {
        if let (Some(l), Some(h)) = (lo, hi) {
            if l >= h {
                return Ok(Vec::new()); // (an empty range: BTreeMap panics on one reversed)
            }
        }
        let layer = &self.layers[t];
        let lo_b = lo.map_or(Edge::Unbounded, |k| Edge::Included(k.to_vec()));
        let hi_b = hi.map_or(Edge::Unbounded, |k| Edge::Excluded(k.to_vec()));
        let mut over: Box<dyn Iterator<Item = (&Bytes, &Option<Bytes>)>> = if reverse {
            Box::new(layer.writes.range((lo_b, hi_b)).rev())
        } else {
            Box::new(layer.writes.range((lo_b, hi_b)))
        };
        let limit = limit.unwrap_or(usize::MAX);
        let mut out = Vec::new();
        let txn = self.ro()?;
        let table = txn.open_table(Some(&self.tables[t].name)).map_err(err)?;
        let mut cursor = txn.cursor(&table).map_err(err)?;
        let mut f = if layer.cleared { None } else { step(&mut cursor, true, reverse, lo, hi)? };
        let mut o = over.next();
        enum Pick {
            File,
            Layer,
            Both,
        }
        while out.len() < limit {
            let pick = match (&f, &o) {
                (None, None) => break,
                (Some(_), None) => Pick::File,
                (None, Some(_)) => Pick::Layer,
                (Some((fk, _)), Some((ok, _))) => {
                    if fk == *ok {
                        Pick::Both
                    } else if (ok.as_slice() < fk.as_slice()) != reverse {
                        Pick::Layer
                    } else {
                        Pick::File
                    }
                }
            };
            match pick {
                Pick::File => {
                    out.push(f.take().unwrap());
                    f = step(&mut cursor, false, reverse, lo, hi)?;
                }
                Pick::Layer | Pick::Both => {
                    if let Pick::Both = pick {
                        // (the layer's write replaces the file's row)
                        f = step(&mut cursor, false, reverse, lo, hi)?;
                    }
                    let (k, v) = o.unwrap();
                    if let Some(v) = v {
                        out.push((k.clone(), v.clone()));
                    }
                    o = over.next();
                }
            }
        }
        Ok(out)
    }

    /// The keys of ``t`` in [lo, hi), in order: ``scan`` without reading a value from the file.
    fn keys(&self, t: usize, lo: Option<&[u8]>, hi: Option<&[u8]>) -> PyResult<Vec<Bytes>> {
        if let (Some(l), Some(h)) = (lo, hi) {
            if l >= h {
                return Ok(Vec::new());
            }
        }
        let layer = &self.layers[t];
        let mut out: BTreeMap<Bytes, bool> = BTreeMap::new();
        if !layer.cleared {
            let txn = self.ro()?;
            let table = txn.open_table(Some(&self.tables[t].name)).map_err(err)?;
            let mut cursor = txn.cursor(&table).map_err(err)?;
            let mut item = match lo {
                Some(l) => cursor.set_range::<Bytes, ()>(l).map_err(err)?,
                None => cursor.first::<Bytes, ()>().map_err(err)?,
            };
            while let Some((k, ())) = item {
                if hi.map_or(false, |h| k.as_slice() >= h) {
                    break;
                }
                out.insert(k, true);
                item = cursor.next::<Bytes, ()>().map_err(err)?;
            }
        }
        let lo_b = lo.map_or(Edge::Unbounded, |k| Edge::Included(k.to_vec()));
        let hi_b = hi.map_or(Edge::Unbounded, |k| Edge::Excluded(k.to_vec()));
        for (k, v) in layer.writes.range((lo_b, hi_b)) {
            out.insert(k.clone(), v.is_some());
        }
        Ok(out.into_iter().filter(|(_, present)| *present).map(|(k, _)| k).collect())
    }

    fn recording(&self, t: usize) -> Option<i64> {
        if !self.tables[t].journaled || self.suspended > 0 {
            return None;
        }
        Some(self.height.unwrap_or(UNATTRIBUTED))
    }

    /// Put (Some) or delete (None) one row, with every hook the table has.
    fn write(&mut self, t: usize, key: Bytes, value: Option<Bytes>) -> PyResult<bool> {
        let info = &self.tables[t];
        let hooked = info.commitment.is_some()
            || info.tracked
            || !info.indexes.is_empty()
            || self.recording(t).is_some();
        if !hooked {
            let existed = match self.layers[t].writes.get(&key) {
                Some(v) => v.is_some(),
                None => value.is_none() && !self.layers[t].cleared && self.read(t, &key)?.is_some(),
            };
            self.layers[t].writes.insert(key, value);
            return Ok(existed);
        }
        let old = self.read(t, &key)?;
        if old == value {
            return Ok(old.is_some());
        }
        let existed = old.is_some();
        if self.tables[t].commitment.is_some() {
            self.pending.entry((t, key.clone())).or_insert_with(|| old.clone());
        }
        if let Some(height) = self.recording(t) {
            if self.touched.insert((t, key.clone())) {
                let mut k = Vec::with_capacity(16);
                k.extend_from_slice(&height_key(height));
                k.extend_from_slice(&self.seq.to_be_bytes());
                self.seq += 1;
                let mut v = named(&self.tables[t].name, &(key.len() as u32).to_be_bytes());
                v.extend_from_slice(&key);
                match &old {
                    Some(o) => {
                        v.push(1);
                        v.extend_from_slice(o);
                    }
                    None => v.push(0),
                }
                let undo = self.undo;
                self.layers[undo].writes.insert(k, Some(v));
            }
        }
        if self.tables[t].tracked {
            let mark = named(&self.tables[t].name, &key);
            let marks = self.marks;
            self.layers[marks].writes.insert(mark, Some(Vec::new()));
        }
        let indexes = self.tables[t].indexes.clone();
        for (it, columns) in &indexes {
            if let Some(o) = &old {
                let k = index_key(&key, o, columns)?;
                self.layers[*it].writes.insert(k, None);
            }
            if let Some(v) = &value {
                let k = index_key(&key, v, columns)?;
                self.layers[*it].writes.insert(k, Some(key.clone()));
            }
        }
        self.layers[t].writes.insert(key, value);
        Ok(existed)
    }

    /// The row's committed columns as fields, or None if it cannot be read.
    fn columns(key: &[u8], value: &[u8], columns: &[usize]) -> Option<Vec<Field>> {
        let mut row = codec::fields(key).ok()?;
        row.extend(codec::fields(value).ok()?);
        columns.iter().map(|&i| row.get(i).cloned()).collect()
    }

    /// Fold every pending row into its domain's accumulator.
    fn fold(&mut self, py: Python<'_>) -> PyResult<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        use rayon::prelude::*;

        let pending: Vec<((usize, Bytes), Option<Bytes>)> = self.pending.drain().collect();
        let txn = self.ro()?;
        // (domain, kind, columns of the old row, of the new) for each row that changed
        let mut work: Vec<(usize, usize, Option<Vec<Field>>, Option<Vec<Field>>, bool, bool)> =
            Vec::with_capacity(pending.len());
        for ((t, key), old) in pending {
            let new = self.read_in(&txn, t, &key)?;
            if new == old {
                continue;
            }
            let c = self.tables[t].commitment.as_ref().unwrap();
            let cols = |v: &Option<Bytes>| v.as_ref().and_then(|v| Inner::columns(&key, v, &c.columns));
            work.push((c.domain, t, cols(&old), cols(&new), old.is_some(), new.is_some()));
        }
        drop(txn);
        let kinds: Vec<String> = self.tables.iter().map(|i| i.commitment.as_ref().map_or(String::new(), |c| c.kind.clone())).collect();
        let encoded: Vec<(Encoded, Encoded)> = py.allow_threads(|| {
            work.par_iter()
                .map(|(_, t, old, new, had_old, has_new)| {
                    let one = |cols: &Option<Vec<Field>>, present: bool| match (cols, present) {
                        (_, false) => Encoded::Nothing,
                        (Some(c), true) => encode(&kinds[*t], c),
                        (None, true) => Encoded::Python,
                    };
                    (one(old, *had_old), one(new, *has_new))
                })
                .collect()
        });
        let mut sums: HashMap<usize, ([u16; LANES], [u16; LANES])> = HashMap::new();
        for ((domain, t, old, new, _, _), (o, n)) in work.iter().zip(encoded) {
            let entry = sums.entry(*domain).or_insert(([0; LANES], [0; LANES]));
            for (which, enc, cols) in [(0, o, old), (1, n, new)] {
                let vector = match enc {
                    Encoded::Vector(v) => Some(v),
                    Encoded::Nothing => None,
                    Encoded::Python => self.python_entry(py, *t, cols)?,
                };
                if let Some(v) = vector {
                    let total = if which == 0 { &mut entry.0 } else { &mut entry.1 };
                    for (x, y) in total.iter_mut().zip(v.iter()) {
                        *x = x.wrapping_add(*y);
                    }
                }
            }
        }
        for (domain, (minus, plus)) in sums {
            let acc = &mut self.accs[domain];
            for i in 0..LANES {
                let lane = u16::from_le_bytes([acc[4 * i], acc[4 * i + 1]])
                    .wrapping_sub(minus[i])
                    .wrapping_add(plus[i]);
                acc[4 * i..4 * i + 2].copy_from_slice(&lane.to_le_bytes());
            }
            let key = format!("acc/{}", self.domains[domain]).into_bytes();
            let value = self.accs[domain].clone();
            let meta = self.meta;
            self.layers[meta].writes.insert(key, Some(value));
        }
        Ok(())
    }

    /// Python's encoder for a row native code could not read (or None for a row it judges
    /// to have no entry).
    fn python_entry(&self, py: Python<'_>, t: usize, cols: &Option<Vec<Field>>) -> PyResult<Option<Vector>> {
        let c = self.tables[t].commitment.as_ref().unwrap();
        let cols = cols.as_ref().ok_or_else(|| PyValueError::new_err("a committed row the store cannot read"))?;
        let items: PyResult<Vec<Bound<'_, PyAny>>> = cols.iter().map(|f| codec::to_python(py, f)).collect();
        let row = PyTuple::new_bound(py, items?);
        let v = c.fallback.call1(py, (row,))?;
        if v.is_none(py) {
            return Ok(None);
        }
        let raw = v.call_method1(py, "to_bytes", (SIZE, "little"))?;
        let raw = raw.downcast_bound::<PyBytes>(py)?.as_bytes();
        let mut out: Vector = Box::new([0u16; LANES]);
        for (i, lane) in out.iter_mut().enumerate() {
            *lane = u16::from_le_bytes([raw[4 * i], raw[4 * i + 1]]);
        }
        Ok(Some(out))
    }

    fn commit(&mut self, py: Python<'_>) -> PyResult<()> {
        self.fold(py)?;
        if self.layers.iter().all(|l| l.writes.is_empty() && !l.cleared) {
            return Ok(());
        }
        let started = Instant::now();
        let layers = std::mem::take(&mut self.layers);
        let names: Vec<String> = self.tables.iter().map(|t| t.name.clone()).collect();
        let env = self.env.clone();
        let result = py.allow_threads(|| -> Result<(), libmdbx::Error> {
            let txn = env.begin_rw_txn()?;
            for (name, layer) in names.iter().zip(layers.iter()) {
                if layer.writes.is_empty() && !layer.cleared {
                    continue;
                }
                let table = txn.open_table(Some(name))?;
                if layer.cleared {
                    txn.clear_table(&table)?;
                }
                for (k, v) in &layer.writes {
                    match v {
                        Some(v) => txn.put(&table, k, v, WriteFlags::UPSERT)?,
                        None => {
                            txn.del(&table, k, None)?;
                        }
                    }
                }
            }
            txn.commit()?;
            Ok(())
        });
        self.layers = (0..self.tables.len()).map(|_| Layer::default()).collect();
        match result {
            Ok(()) => {
                self.committed_accs = self.accs.clone();
                self.commits += 1;
                self.commit_seconds += started.elapsed().as_secs_f64();
                Ok(())
            }
            Err(e) => {
                // (nothing reached the file: the store is as at the last commit)
                self.accs = self.committed_accs.clone();
                self.pending.clear();
                self.touched.clear();
                Err(err(e))
            }
        }
    }

    fn rollback(&mut self) {
        for layer in self.layers.iter_mut() {
            *layer = Layer::default();
        }
        self.pending.clear();
        self.accs = self.committed_accs.clone();
        // (a row changed again records again: a duplicate entry restores the same row)
        self.touched.clear();
    }
}

/// The node's store: see the module's documentation.
#[pyclass(module = "qrdx_native")]
pub struct Store {
    inner: Mutex<Option<Inner>>,
    stop: Arc<AtomicBool>,
}

impl Store {
    fn lock(&self) -> PyResult<MutexGuard<'_, Option<Inner>>> {
        self.inner.lock().map_err(|_| PyRuntimeError::new_err("store: poisoned"))
    }
}

macro_rules! with {
    ($self:ident, $inner:ident, $body:block) => {{
        let mut guard = $self.lock()?;
        let $inner = guard.as_mut().ok_or_else(|| PyRuntimeError::new_err("store: closed"))?;
        $body
    }};
}

impl Store {
    /// Rows already packed, written as ``put_many`` writes them: for the crate's other modules
    /// (the proof tree writes its nodes here without a Python object each).
    pub(crate) fn write_packed(&self, t: usize, items: Vec<(Vec<u8>, Vec<u8>)>) -> PyResult<()> {
        with!(self, inner, {
            inner.table(t)?;
            for (k, v) in items {
                inner.write(t, k, Some(v))?;
            }
            Ok(())
        })
    }
}

#[pymethods]
impl Store {
    /// Open (or create) the store at ``path`` (a file) with ``tables``. ``max_gb``: the most
    /// the file may grow to (address space is reserved for it); ``growth_mb``: the steps it
    /// grows (and shrinks) by.
    #[new]
    #[pyo3(signature = (path, tables, max_gb = 256.0, sync_seconds = 1.0, growth_mb = 16.0))]
    fn new(path: &str, tables: Vec<String>, max_gb: f64, sync_seconds: f64, growth_mb: f64) -> PyResult<Self> {
        let mut names = tables.clone();
        for internal in [UNDO, MARKS, META] {
            if names.iter().any(|n| n == internal) {
                return Err(PyValueError::new_err(format!("{internal} is the store's own")));
            }
            names.push(internal.to_string());
        }
        if names.iter().any(|n| n.len() > 255 || n.is_empty()) {
            return Err(PyValueError::new_err("a table name of 1 to 255 bytes"));
        }
        let growth = ((growth_mb.max(0.0625) * 1024.0 * 1024.0) as isize + 4095) / 4096 * 4096;
        let options = DatabaseOptions {
            no_sub_dir: true,
            max_tables: Some((names.len() + 16) as u64),
            page_size: Some(PageSize::Set(4096)),
            liforeclaim: true,
            mode: Mode::ReadWrite(ReadWriteOptions {
                sync_mode: SyncMode::SafeNoSync,
                min_size: Some(growth),
                max_size: Some((max_gb * 1024.0 * 1024.0 * 1024.0) as isize),
                growth_step: Some(growth),
                shrink_threshold: Some(2 * growth),
            }),
            ..Default::default()
        };
        let env = Arc::new(Database::<WriteMap>::open_with_options(path, options).map_err(err)?);
        {
            let txn = env.begin_rw_txn().map_err(err)?;
            for n in &names {
                txn.create_table(Some(n), TableFlags::default()).map_err(err)?;
            }
            txn.commit().map_err(err)?;
        }
        let n = names.len();
        let mut inner = Inner {
            env: env.clone(),
            tables: names
                .iter()
                .map(|name| TableInfo {
                    name: name.clone(),
                    commitment: None,
                    journaled: false,
                    tracked: false,
                    indexes: Vec::new(),
                })
                .collect(),
            by_name: names.iter().enumerate().map(|(i, n)| (n.clone(), i)).collect(),
            layers: (0..n).map(|_| Layer::default()).collect(),
            domains: Vec::new(),
            accs: Vec::new(),
            committed_accs: Vec::new(),
            pending: HashMap::new(),
            height: None,
            suspended: 0,
            touched: HashSet::new(),
            seq: 0,
            undo: n - 3,
            marks: n - 2,
            meta: n - 1,
            commits: 0,
            commit_seconds: 0.0,
        };
        // (the journal's sequence continues from its newest entry)
        // (heights only grow as entries are recorded, but for unattributed entries, which sort
        // first: the newest entry is the last, or the last unattributed one)
        let mut seq = 0u64;
        let (lo, hi) = (height_key(UNATTRIBUTED), height_key(UNATTRIBUTED + 1));
        let newest = inner.scan(inner.undo, None, None, true, Some(1))?;
        let unattributed = inner.scan(inner.undo, Some(&lo), Some(&hi), true, Some(1))?;
        for (k, _) in newest.iter().chain(unattributed.iter()) {
            if k.len() == 16 {
                seq = seq.max(u64::from_be_bytes(k[8..16].try_into().unwrap()) + 1);
            }
        }
        inner.seq = seq;
        let stop = Arc::new(AtomicBool::new(false));
        if sync_seconds > 0.0 {
            // (SafeNoSync: commits are not flushed; this makes them durable within a second, and
            // lets MDBX reuse the pages the last flushed commit kept)
            let (env, stop) = (Arc::downgrade(&env), stop.clone());
            std::thread::Builder::new()
                .name("qrdx-store-sync".into())
                .spawn(move || loop {
                    std::thread::sleep(Duration::from_secs_f64(sync_seconds));
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    match env.upgrade() {
                        Some(env) => {
                            let _ = env.sync(true);
                        }
                        None => return,
                    }
                })
                .map_err(err)?;
        }
        Ok(Store { inner: Mutex::new(Some(inner)), stop })
    }

    /// The id of table ``name`` (KeyError if the store was not opened with it).
    fn table_id(&self, name: &str) -> PyResult<usize> {
        with!(self, inner, {
            inner.by_name.get(name).copied().ok_or_else(|| PyKeyError::new_err(name.to_string()))
        })
    }

    /// Feed table ``t``'s rows into ``domain``'s accumulator as ``kind`` (qrdx/state_commitment.py):
    /// ``columns`` index the row's key fields then its value fields; ``fallback(columns)`` is the
    /// kind's Python encoder, for rows only it can read.
    fn set_commitment(&self, t: usize, kind: &str, domain: &str, columns: Vec<usize>, fallback: PyObject) -> PyResult<()> {
        with!(self, inner, {
            inner.table(t)?;
            let d = match inner.domains.iter().position(|x| x == domain) {
                Some(d) => d,
                None => {
                    let key = format!("acc/{domain}").into_bytes();
                    let acc = inner.read(inner.meta, &key)?.unwrap_or_else(|| vec![0u8; SIZE]);
                    inner.domains.push(domain.to_string());
                    inner.accs.push(acc.clone());
                    inner.committed_accs.push(acc);
                    inner.domains.len() - 1
                }
            };
            inner.tables[t].commitment = Some(Commitment { kind: kind.to_string(), domain: d, columns, fallback });
            Ok(())
        })
    }

    fn set_journaled(&self, t: usize, on: bool) -> PyResult<()> {
        with!(self, inner, {
            inner.table(t)?;
            inner.tables[t].journaled = on;
            Ok(())
        })
    }

    /// Keep table ``index`` as an index of table ``t`` on ``columns`` (see ``TableInfo``).
    fn set_index(&self, t: usize, index: usize, columns: Vec<usize>) -> PyResult<()> {
        with!(self, inner, {
            inner.table(t)?;
            inner.table(index)?;
            inner.tables[t].indexes.push((index, columns));
            Ok(())
        })
    }

    /// The rows of ``t`` whose entries in its index ``index`` lie in [lo, hi), in the index's
    /// order, as (key tuple, value tuple).
    #[pyo3(signature = (t, index, lo = None, hi = None, reverse = false, limit = None))]
    fn index_rows<'py>(
        &self,
        py: Python<'py>,
        t: usize,
        index: usize,
        lo: Option<&[u8]>,
        hi: Option<&[u8]>,
        reverse: bool,
        limit: Option<usize>,
    ) -> PyResult<Bound<'py, PyList>> {
        with!(self, inner, {
            inner.table(t)?;
            inner.table(index)?;
            let entries = inner.scan(index, lo, hi, reverse, limit)?;
            let txn = inner.ro()?;
            let out = PyList::empty_bound(py);
            for (_ik, key) in entries {
                if let Some(v) = inner.read_in(&txn, t, &key)? {
                    out.append((codec::unpack(py, &key)?, codec::unpack(py, &v)?))?;
                }
            }
            Ok(out)
        })
    }

    fn set_tracked(&self, t: usize, on: bool) -> PyResult<()> {
        with!(self, inner, {
            inner.table(t)?;
            inner.tables[t].tracked = on;
            Ok(())
        })
    }

    // ── reads ─────────────────────────────────────────────────────────────────────────────

    fn get<'py>(&self, py: Python<'py>, t: usize, key: &[u8]) -> PyResult<Option<Bound<'py, PyBytes>>> {
        with!(self, inner, {
            inner.table(t)?;
            Ok(inner.read(t, key)?.map(|v| PyBytes::new_bound(py, &v)))
        })
    }

    fn get_many<'py>(&self, py: Python<'py>, t: usize, keys: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyList>> {
        with!(self, inner, {
            inner.table(t)?;
            let txn = inner.ro()?;
            let out = PyList::empty_bound(py);
            for k in keys.iter()? {
                let k = k?;
                match inner.read_in(&txn, t, k.downcast::<PyBytes>()?.as_bytes())? {
                    Some(v) => out.append(PyBytes::new_bound(py, &v))?,
                    None => out.append(py.None())?,
                }
            }
            Ok(out)
        })
    }

    /// The rows in [lo, hi) as (key, value) bytes, in key order (``reverse``: from the end).
    #[pyo3(signature = (t, lo = None, hi = None, reverse = false, limit = None))]
    fn scan<'py>(
        &self,
        py: Python<'py>,
        t: usize,
        lo: Option<&[u8]>,
        hi: Option<&[u8]>,
        reverse: bool,
        limit: Option<usize>,
    ) -> PyResult<Bound<'py, PyList>> {
        with!(self, inner, {
            inner.table(t)?;
            let rows = inner.scan(t, lo, hi, reverse, limit)?;
            let out = PyList::empty_bound(py);
            for (k, v) in rows {
                out.append((PyBytes::new_bound(py, &k), PyBytes::new_bound(py, &v)))?;
            }
            Ok(out)
        })
    }

    /// ``scan``, each key and value unpacked into its tuple.
    #[pyo3(signature = (t, lo = None, hi = None, reverse = false, limit = None))]
    fn scan_rows<'py>(
        &self,
        py: Python<'py>,
        t: usize,
        lo: Option<&[u8]>,
        hi: Option<&[u8]>,
        reverse: bool,
        limit: Option<usize>,
    ) -> PyResult<Bound<'py, PyList>> {
        with!(self, inner, {
            inner.table(t)?;
            let rows = inner.scan(t, lo, hi, reverse, limit)?;
            let out = PyList::empty_bound(py);
            for (k, v) in rows {
                out.append((codec::unpack(py, &k)?, codec::unpack(py, &v)?))?;
            }
            Ok(out)
        })
    }

    /// The keys of the rows in [lo, hi), in key order (no value is read).
    #[pyo3(signature = (t, lo = None, hi = None))]
    fn keys<'py>(&self, py: Python<'py>, t: usize, lo: Option<&[u8]>, hi: Option<&[u8]>) -> PyResult<Bound<'py, PyList>> {
        with!(self, inner, {
            inner.table(t)?;
            let out = PyList::empty_bound(py);
            for k in inner.keys(t, lo, hi)? {
                out.append(PyBytes::new_bound(py, &k))?;
            }
            Ok(out)
        })
    }

    /// The number of rows in [lo, hi).
    #[pyo3(signature = (t, lo = None, hi = None))]
    fn count(&self, t: usize, lo: Option<&[u8]>, hi: Option<&[u8]>) -> PyResult<usize> {
        with!(self, inner, {
            inner.table(t)?;
            if lo.is_none() && hi.is_none() && !inner.layers[t].cleared {
                // (the file's count, corrected by the layer's writes)
                let txn = inner.ro()?;
                let table = txn.open_table(Some(&inner.tables[t].name)).map_err(err)?;
                let mut n = txn.table_stat(&table).map_err(err)?.entries() as i64;
                for (k, v) in &inner.layers[t].writes {
                    let before = inner.file_get(&txn, t, k)?.is_some();
                    n += v.is_some() as i64 - before as i64;
                }
                return Ok(n as usize);
            }
            Ok(inner.keys(t, lo, hi)?.len())
        })
    }

    // ── writes ────────────────────────────────────────────────────────────────────────────

    fn put(&self, t: usize, key: &[u8], value: &[u8]) -> PyResult<()> {
        with!(self, inner, {
            inner.table(t)?;
            inner.write(t, key.to_vec(), Some(value.to_vec()))?;
            Ok(())
        })
    }

    /// Whole rows (every column in order, the first ``nk`` the key), each value as SQLite's
    /// affinity for its column stores it (``affinities``: "TEXT", "INTEGER", "BLOB" or "REAL").
    /// A value already of its column's type (or None) is packed here; any other goes through
    /// ``coerce(value, affinity)``, qrdx/store.py's ``_coerce``, first. ``Table.put`` for each
    /// row, without its Python per value.
    fn put_rows(
        &self,
        t: usize,
        nk: usize,
        affinities: Vec<String>,
        rows: &Bound<'_, PyAny>,
        coerce: &Bound<'_, PyAny>,
    ) -> PyResult<usize> {
        #[derive(Clone, Copy)]
        enum Aff {
            Text,
            Integer,
            Blob,
            Real,
        }
        let affs: Vec<Aff> = affinities
            .iter()
            .map(|a| match a.as_str() {
                "TEXT" => Ok(Aff::Text),
                "INTEGER" => Ok(Aff::Integer),
                "BLOB" => Ok(Aff::Blob),
                "REAL" => Ok(Aff::Real),
                other => Err(PyValueError::new_err(format!("unknown affinity {other}"))),
            })
            .collect::<PyResult<_>>()?;
        if nk == 0 || nk > affs.len() {
            return Err(PyValueError::new_err("a key of 1 to every column"));
        }
        let names: Vec<Bound<'_, pyo3::types::PyString>> = affinities
            .iter()
            .map(|a| pyo3::types::PyString::new_bound(rows.py(), a))
            .collect();
        let mut packed: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for row in rows.iter()? {
            let row = row?;
            let n = row.len()?;
            if n != affs.len() {
                return Err(PyValueError::new_err(format!(
                    "a row of {n} values for {} columns",
                    affs.len()
                )));
            }
            let (mut key, mut value) = (Vec::with_capacity(32), Vec::with_capacity(64));
            for i in 0..n {
                let v = row.get_item(i)?;
                let fits = v.is_none()
                    || match affs[i] {
                        Aff::Text => v.is_instance_of::<pyo3::types::PyString>(),
                        Aff::Integer => v.is_exact_instance_of::<pyo3::types::PyLong>(),
                        Aff::Blob => v.is_instance_of::<PyBytes>(),
                        Aff::Real => v.is_exact_instance_of::<pyo3::types::PyFloat>(),
                    };
                let v = if fits { v } else { coerce.call1((v, &names[i]))? };
                codec::pack_one(&v, if i < nk { &mut key } else { &mut value })?;
            }
            packed.push((key, value));
        }
        let n = packed.len();
        with!(self, inner, {
            inner.table(t)?;
            for (k, v) in packed {
                inner.write(t, k, Some(v))?;
            }
            Ok(n)
        })
    }

    fn put_many(&self, t: usize, items: &Bound<'_, PyAny>) -> PyResult<()> {
        with!(self, inner, {
            inner.table(t)?;
            for item in items.iter()? {
                let item = item?;
                let (k, v): (Bound<'_, PyBytes>, Bound<'_, PyBytes>) = item.extract()?;
                inner.write(t, k.as_bytes().to_vec(), Some(v.as_bytes().to_vec()))?;
            }
            Ok(())
        })
    }

    /// Delete a row; whether it was there.
    fn delete(&self, t: usize, key: &[u8]) -> PyResult<bool> {
        with!(self, inner, {
            inner.table(t)?;
            inner.write(t, key.to_vec(), None)
        })
    }

    fn delete_many(&self, t: usize, keys: &Bound<'_, PyAny>) -> PyResult<usize> {
        with!(self, inner, {
            inner.table(t)?;
            let mut n = 0;
            for k in keys.iter()? {
                let k = k?;
                n += inner.write(t, k.downcast::<PyBytes>()?.as_bytes().to_vec(), None)? as usize;
            }
            Ok(n)
        })
    }

    /// Delete the rows in [lo, hi); how many.
    #[pyo3(signature = (t, lo = None, hi = None))]
    fn delete_range(&self, t: usize, lo: Option<&[u8]>, hi: Option<&[u8]>) -> PyResult<usize> {
        with!(self, inner, {
            inner.table(t)?;
            let keys = inner.keys(t, lo, hi)?;
            let n = keys.len();
            for k in keys {
                inner.write(t, k, None)?;
            }
            Ok(n)
        })
    }

    /// Empty table ``t``, its rows not folded out of their domain — for a reset of a whole
    /// domain, whose caller then sets its accumulator (``set_acc``). Every row is still marked
    /// (a tracked table: the proof tree drops them) and journaled (while recording).
    fn clear(&self, t: usize) -> PyResult<()> {
        with!(self, inner, {
            inner.table(t)?;
            let (tracked, recording) = (inner.tables[t].tracked, inner.recording(t));
            if tracked || recording.is_some() {
                let rows = inner.scan(t, None, None, false, None)?;
                // (the commitment is the caller's: no row is folded out)
                let commitment = inner.tables[t].commitment.take();
                let result = rows.into_iter().try_for_each(|(k, _)| inner.write(t, k, None).map(|_| ()));
                inner.tables[t].commitment = commitment;
                result?;
            }
            inner.layers[t] = Layer { writes: BTreeMap::new(), cleared: true };
            for (it, _) in inner.tables[t].indexes.clone() {
                inner.layers[it] = Layer { writes: BTreeMap::new(), cleared: true };
            }
            inner.pending.retain(|(table, _), _| *table != t);
            Ok(())
        })
    }

    /// ``domain``'s accumulator recomputed from every row of its tables (a check; O(state)).
    fn full_acc<'py>(&self, py: Python<'py>, domain: &str) -> PyResult<Bound<'py, PyBytes>> {
        use rayon::prelude::*;

        with!(self, inner, {
            let mut total = [0u16; LANES];
            for t in 0..inner.tables.len() {
                let Some(c) = inner.tables[t].commitment.as_ref() else { continue };
                if inner.domains[c.domain] != domain {
                    continue;
                }
                let rows = inner.scan(t, None, None, false, None)?;
                let kind = c.kind.clone();
                let columns = c.columns.clone();
                let encoded: Vec<(Encoded, Option<Vec<Field>>)> = py.allow_threads(|| {
                    rows.par_iter()
                        .map(|(k, v)| {
                            let cols = Inner::columns(k, v, &columns);
                            let e = match &cols {
                                Some(c) => encode(&kind, c),
                                None => Encoded::Python,
                            };
                            (e, cols)
                        })
                        .collect()
                });
                for (e, cols) in encoded {
                    let v = match e {
                        Encoded::Vector(v) => Some(v),
                        Encoded::Nothing => None,
                        Encoded::Python => inner.python_entry(py, t, &cols)?,
                    };
                    if let Some(v) = v {
                        for (x, y) in total.iter_mut().zip(v.iter()) {
                            *x = x.wrapping_add(*y);
                        }
                    }
                }
            }
            let mut out = vec![0u8; SIZE];
            for (i, lane) in total.iter().enumerate() {
                out[4 * i..4 * i + 2].copy_from_slice(&lane.to_le_bytes());
            }
            Ok(PyBytes::new_bound(py, &out))
        })
    }

    // ── transactions ──────────────────────────────────────────────────────────────────────

    /// Write every table's layer to the file, in one transaction.
    fn commit(&self, py: Python<'_>) -> PyResult<()> {
        with!(self, inner, { inner.commit(py) })
    }

    /// Drop every write since the last commit.
    fn rollback(&self) -> PyResult<()> {
        with!(self, inner, {
            inner.rollback();
            Ok(())
        })
    }

    /// The number of writes waiting for a commit.
    fn pending_writes(&self) -> PyResult<usize> {
        with!(self, inner, { Ok(inner.layers.iter().map(|l| l.writes.len() + l.cleared as usize).sum()) })
    }

    // ── commitments ───────────────────────────────────────────────────────────────────────

    /// ``domain``'s accumulator (4,096 bytes), every changed row folded in.
    fn acc<'py>(&self, py: Python<'py>, domain: &str) -> PyResult<Bound<'py, PyBytes>> {
        with!(self, inner, {
            inner.fold(py)?;
            match inner.domains.iter().position(|d| d == domain) {
                Some(d) => Ok(PyBytes::new_bound(py, &inner.accs[d])),
                None => Ok(PyBytes::new_bound(py, &vec![0u8; SIZE])),
            }
        })
    }

    /// Set ``domain``'s accumulator (a reset, or a repair from every row).
    fn set_acc(&self, py: Python<'_>, domain: &str, acc: &[u8]) -> PyResult<()> {
        with!(self, inner, {
            if acc.len() != SIZE {
                return Err(PyValueError::new_err("an accumulator is 4,096 bytes"));
            }
            inner.fold(py)?;
            let d = inner
                .domains
                .iter()
                .position(|d| d == domain)
                .ok_or_else(|| PyKeyError::new_err(domain.to_string()))?;
            inner.accs[d] = acc.to_vec();
            let meta = inner.meta;
            inner.layers[meta].writes.insert(format!("acc/{domain}").into_bytes(), Some(acc.to_vec()));
            Ok(())
        })
    }

    // ── the undo journal ──────────────────────────────────────────────────────────────────

    /// The block whose changes are being recorded (None: none).
    #[pyo3(signature = (height = None))]
    fn set_height(&self, height: Option<i64>) -> PyResult<()> {
        with!(self, inner, {
            if inner.height != height {
                inner.touched.clear();
            }
            inner.height = height;
            Ok(())
        })
    }

    fn height(&self) -> PyResult<Option<i64>> {
        with!(self, inner, { Ok(inner.height) })
    }

    /// Writes from now until ``resume`` are not journaled.
    fn suspend(&self) -> PyResult<()> {
        with!(self, inner, {
            inner.suspended += 1;
            Ok(())
        })
    }

    fn resume(&self) -> PyResult<()> {
        with!(self, inner, {
            inner.suspended = inner.suspended.saturating_sub(1);
            Ok(())
        })
    }

    fn journaling(&self, t: usize) -> PyResult<bool> {
        with!(self, inner, {
            inner.table(t)?;
            Ok(inner.recording(t).is_some())
        })
    }

    /// Whether the journal holds an entry at ``height`` (-1: an unattributed write).
    fn undo_has(&self, height: i64) -> PyResult<bool> {
        with!(self, inner, {
            let lo = height_key(height).to_vec();
            let hi = height_key(height + 1).to_vec();
            Ok(!inner.scan(inner.undo, Some(&lo), Some(&hi), false, Some(1))?.is_empty())
        })
    }

    /// Write back every row the blocks above ``height`` changed, newest first, and drop their
    /// entries (the commitments and marks follow the rows). The number of entries.
    fn undo_rollback(&self, height: i64) -> PyResult<usize> {
        with!(self, inner, {
            let lo = height_key(height + 1).to_vec();
            let entries = inner.scan(inner.undo, Some(&lo), None, true, None)?;
            inner.suspended += 1;
            let result = (|| -> PyResult<()> {
                for (k, v) in &entries {
                    let (name, rest) = unnamed(v).ok_or_else(|| PyValueError::new_err("a malformed undo entry"))?;
                    let t = *inner.by_name.get(name).ok_or_else(|| PyKeyError::new_err(name.to_string()))?;
                    let n = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
                    let key = rest[4..4 + n].to_vec();
                    let old = match rest[4 + n] {
                        1 => Some(rest[5 + n..].to_vec()),
                        _ => None,
                    };
                    inner.write(t, key, old)?;
                    let undo = inner.undo;
                    inner.layers[undo].writes.insert(k.clone(), None);
                }
                Ok(())
            })();
            inner.suspended -= 1;
            result?;
            Ok(entries.len())
        })
    }

    /// Drop the entries of blocks [0, ``height``] (no reorg reaches below finality).
    fn undo_prune(&self, height: i64) -> PyResult<usize> {
        with!(self, inner, {
            let lo = height_key(0).to_vec();
            let hi = height_key(height + 1).to_vec();
            let rows = inner.scan(inner.undo, Some(&lo), Some(&hi), false, None)?;
            let undo = inner.undo;
            for (k, _) in &rows {
                inner.layers[undo].writes.insert(k.clone(), None);
            }
            Ok(rows.len())
        })
    }

    /// Forget the whole journal.
    fn undo_reset(&self) -> PyResult<()> {
        with!(self, inner, {
            let undo = inner.undo;
            inner.layers[undo] = Layer { writes: BTreeMap::new(), cleared: true };
            inner.touched.clear();
            Ok(())
        })
    }

    /// (height, table, key, the row before or None) of every entry, oldest first (tests).
    fn undo_entries<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        with!(self, inner, {
            let out = PyList::empty_bound(py);
            for (k, v) in inner.scan(inner.undo, None, None, false, None)? {
                let (name, rest) = unnamed(&v).unwrap();
                let n = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
                let old = (rest[4 + n] == 1).then(|| PyBytes::new_bound(py, &rest[5 + n..]));
                out.append((height_of(&k), name, PyBytes::new_bound(py, &rest[4..4 + n]), old))?;
            }
            Ok(out)
        })
    }

    // ── marks ─────────────────────────────────────────────────────────────────────────────

    /// The (table name, key) of every row marked since the last call, and the marks dropped.
    fn take_marks<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        with!(self, inner, {
            let rows = inner.scan(inner.marks, None, None, false, None)?;
            let out = PyList::empty_bound(py);
            let marks = inner.marks;
            for (k, _) in rows {
                if let Some((name, key)) = unnamed(&k) {
                    out.append((name, PyBytes::new_bound(py, key)))?;
                }
                inner.layers[marks].writes.insert(k, None);
            }
            Ok(out)
        })
    }

    /// Mark a row of a tracked table (a row whose entry must be recomputed).
    fn mark(&self, t: usize, key: &[u8]) -> PyResult<()> {
        with!(self, inner, {
            inner.table(t)?;
            let mark = named(&inner.tables[t].name, key);
            let marks = inner.marks;
            inner.layers[marks].writes.insert(mark, Some(Vec::new()));
            Ok(())
        })
    }

    // ── the file ──────────────────────────────────────────────────────────────────────────

    /// A consistent copy of the committed store at ``path`` (a new file), compacted, taken
    /// while writes go on (MDBX's online copy, in its own read transaction).
    fn copy_to(&self, py: Python<'_>, path: &str) -> PyResult<()> {
        let env = with!(self, inner, { PyResult::Ok(inner.env.clone()) })?;
        let dest = std::ffi::CString::new(path).map_err(|_| PyValueError::new_err("a path with a NUL"))?;
        let rc = py.allow_threads(|| unsafe {
            // (the env outlives the call: ``env`` holds it)
            mdbx_sys::mdbx_env_copy(
                env.ptr().0,
                dest.as_ptr(),
                mdbx_sys::MDBX_CP_COMPACT | mdbx_sys::MDBX_CP_FORCE_DYNAMIC_SIZE,
            )
        });
        if rc != 0 {
            return Err(err(format!("copy to {path} failed (MDBX error {rc})")));
        }
        Ok(())
    }

    /// Flush the file to disk now.
    fn sync(&self, py: Python<'_>) -> PyResult<()> {
        with!(self, inner, {
            let env = inner.env.clone();
            py.allow_threads(|| env.sync(true)).map_err(err)?;
            Ok(())
        })
    }

    /// Counters: commits, seconds spent committing, writes waiting, the file's size.
    fn info<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        with!(self, inner, {
            let d = PyDict::new_bound(py);
            d.set_item("commits", inner.commits)?;
            d.set_item("commit_seconds", inner.commit_seconds)?;
            d.set_item("pending", inner.layers.iter().map(|l| l.writes.len()).sum::<usize>())?;
            let info = inner.env.info().map_err(err)?;
            d.set_item("map_size", info.map_size())?;
            let stat = inner.env.stat().map_err(err)?;
            d.set_item("page_size", stat.page_size())?;
            d.set_item("pages", stat.leaf_pages() + stat.branch_pages() + stat.overflow_pages())?;
            Ok(d)
        })
    }

    /// Close the file (writes not committed are dropped). Later calls raise.
    fn close(&self) -> PyResult<()> {
        self.stop.store(true, Ordering::Relaxed);
        let mut guard = self.lock()?;
        if let Some(inner) = guard.take() {
            let env = inner.env.clone();
            drop(inner);
            let _ = env.sync(true);
        }
        Ok(())
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}
