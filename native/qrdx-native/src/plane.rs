//! A block's QRDX balances, held natively (qrdx/exchange/balance_plane.py; docs/NATIVE.md, "The
//! balance plane").
//!
//! The exchange keeps per-block dicts of QRDX amounts by address: each loaded account's available
//! balance (``_available_balances``) and its balance as the block began (``_start_balances``),
//! the block's net change to each account (``_balance_deltas``, flushed to ``account_state``
//! after the block in the order addresses entered it), the fees the block reserved from each
//! payer (``_fees_reserved``) and, while a block is judged, what each payer's transactions in it
//! may cost (``owed``). Held in Python, the native transfer lane converted every value it touched
//! to text and back, each run, and the pre-loads, the fee reservations and the flush each went
//! through them a value at a time.
//!
//! Here they are one table of addresses and five maps of values. Python reads and writes each
//! map through a view (``PlaneView``) that behaves as the dict did: the same keys in the same
//! order (insertion order; a key removed and set again goes last), a ``Decimal`` back for what
//! was set. A value is kept natively when it is a ``Decimal`` whose text this module reads back
//! to the same text (src/dec.rs); any other object is kept as it is, and a lane that meets one
//! hands its run to Python. The lanes, the fee reservations and the pre-loads change the maps in
//! place; a lane computes its whole run first and writes nothing if it bails.
//!
//! The arithmetic is the exchange's context's (precision 78, half-even: ``dec::EXCHANGE``), the
//! one Python's balance code runs under (``amm`` sets it for the process).

use std::cmp::Ordering;
use std::collections::HashMap;

use pyo3::exceptions::{PyKeyError, PyRuntimeError, PyTypeError};
use pyo3::prelude::*;
use pyo3::pyclass::CompareOp;
use pyo3::sync::GILOnceCell;
use pyo3::types::{PyDict, PyList, PyString, PyTuple, PyType};

use crate::dec::{Dec, Rounding, EXCHANGE};

pub const AVAIL: usize = 0;
pub const START: usize = 1;
pub const DELTA: usize = 2;
pub const RESERVED: usize = 3;
pub const OWED: usize = 4;
const NMAPS: usize = 5;
const TOMB: u32 = u32::MAX;

/// What a map holds for a key.
enum V {
    /// A ``Decimal`` this module reproduces exactly.
    D(Dec),
    /// Anything else, as it was set.
    O(PyObject),
}

impl V {
    fn dup(&self, py: Python<'_>) -> V {
        match self {
            V::D(d) => V::D(d.clone()),
            V::O(o) => V::O(o.clone_ref(py)),
        }
    }
}

static DECIMAL: GILOnceCell<Py<PyType>> = GILOnceCell::new();

fn decimal_type(py: Python<'_>) -> PyResult<&Bound<'_, PyType>> {
    Ok(DECIMAL
        .get_or_try_init(py, || -> PyResult<Py<PyType>> {
            Ok(py
                .import_bound("decimal")?
                .getattr("Decimal")?
                .downcast_into::<PyType>()?
                .unbind())
        })?
        .bind(py))
}

/// ``Decimal(text)`` (exact: Python reads a numeral without rounding it).
fn to_decimal<'py>(py: Python<'py>, d: &Dec) -> PyResult<Bound<'py, PyAny>> {
    decimal_type(py)?.call1((d.to_python_string(),))
}

/// A ``Decimal`` whose text reads back to the same text, natively; anything else as it is.
fn from_py(v: &Bound<'_, PyAny>) -> PyResult<V> {
    let py = v.py();
    if v.get_type().is(decimal_type(py)?) {
        let text = v.str()?;
        let text = text.to_cow()?;
        if let Some(d) = Dec::parse(&text) {
            if d.to_python_string() == text {
                return Ok(V::D(d));
            }
        }
    }
    Ok(V::O(v.clone().unbind()))
}

fn to_py<'py>(py: Python<'py>, v: &V) -> PyResult<Bound<'py, PyAny>> {
    match v {
        V::D(d) => to_decimal(py, d),
        V::O(o) => Ok(o.bind(py).clone()),
    }
}

/// A numeral as Python's ``Decimal(text)`` reads it, exactly (None: anything else).
fn parse(text: &str) -> Option<Dec> {
    let d = Dec::parse(text)?;
    (d.to_python_string() == text).then_some(d)
}

fn add(a: &Dec, b: &Dec) -> Option<Dec> {
    a.add(b, &EXCHANGE)
}

fn sub(a: &Dec, b: &Dec) -> Option<Dec> {
    a.sub(b, &EXCHANGE)
}

fn less(a: &Dec, b: &Dec) -> bool {
    a.cmp(b) == Ordering::Less
}

/// One dict: a value by slot, and the slots in the order they entered (``TOMB`` where one left).
#[derive(Default)]
struct Map {
    vals: Vec<Option<V>>,
    pos: Vec<u32>,
    order: Vec<u32>,
    len: usize,
}

impl Map {
    fn get(&self, s: u32) -> Option<&V> {
        self.vals.get(s as usize).and_then(|v| v.as_ref())
    }

    fn set(&mut self, s: u32, v: V) {
        let i = s as usize;
        if i >= self.vals.len() {
            self.vals.resize_with(i + 1, || None);
            self.pos.resize(i + 1, TOMB);
        }
        if self.vals[i].is_none() {
            self.pos[i] = self.order.len() as u32;
            self.order.push(s);
            self.len += 1;
        }
        self.vals[i] = Some(v);
    }

    fn remove(&mut self, s: u32) -> Option<V> {
        let i = s as usize;
        let old = self.vals.get_mut(i)?.take()?;
        let at = self.pos[i] as usize;
        self.order[at] = TOMB;
        self.pos[i] = TOMB;
        self.len -= 1;
        if self.order.len() > 64 && self.order.len() > 4 * self.len {
            self.compact();
        }
        Some(old)
    }

    fn compact(&mut self) {
        let live: Vec<u32> = self.order.iter().copied().filter(|&s| s != TOMB).collect();
        for (at, &s) in live.iter().enumerate() {
            self.pos[s as usize] = at as u32;
        }
        self.order = live;
    }

    fn clear(&mut self) {
        self.vals.clear();
        self.pos.clear();
        self.order.clear();
        self.len = 0;
    }

    fn slots(&self) -> impl Iterator<Item = u32> + '_ {
        self.order.iter().copied().filter(|&s| s != TOMB)
    }
}

/// The block's balances: see the module's documentation.
#[pyclass(module = "qrdx_native")]
pub struct Plane {
    index: HashMap<String, u32>,
    names: Vec<Py<PyString>>,
    maps: [Map; NMAPS],
}

impl Plane {
    fn find(&self, key: &str) -> Option<u32> {
        self.index.get(key).copied()
    }

    fn slot(&mut self, key: &Bound<'_, PyString>) -> PyResult<u32> {
        let text = key.to_cow()?;
        if let Some(&s) = self.index.get(text.as_ref()) {
            return Ok(s);
        }
        let s = self.names.len() as u32;
        self.index.insert(text.into_owned(), s);
        self.names.push(key.clone().unbind());
        Ok(s)
    }

    /// A native value of map ``m`` at ``s``: Some(None) when absent, None when it holds what
    /// native code does not compute with.
    fn native(&self, m: usize, s: u32) -> Option<Option<Dec>> {
        match self.maps[m].get(s) {
            None => Some(None),
            Some(V::D(d)) => Some(Some(d.clone())),
            Some(V::O(_)) => None,
        }
    }

    /// Forget addresses no map holds once they are most of the table (it grows a block at a
    /// time otherwise).
    fn maybe_shrink(&mut self) {
        let live: usize = self.maps.iter().map(|m| m.len).sum();
        if self.names.len() < 4096 || self.names.len() < 4 * live {
            return;
        }
        let mut renumber = vec![TOMB; self.names.len()];
        let mut names = Vec::new();
        for (old, name) in std::mem::take(&mut self.names).into_iter().enumerate() {
            if self.maps.iter().any(|m| m.get(old as u32).is_some()) {
                renumber[old] = names.len() as u32;
                names.push(name);
            }
        }
        self.names = names;
        self.index.retain(|_, s| {
            let new = renumber[*s as usize];
            *s = new;
            new != TOMB
        });
        for map in self.maps.iter_mut() {
            let mut vals: Vec<(u32, V)> = Vec::with_capacity(map.len);
            for s in map.slots().collect::<Vec<_>>() {
                if let Some(v) = map.vals[s as usize].take() {
                    vals.push((renumber[s as usize], v));
                }
            }
            map.clear();
            for (s, v) in vals {
                map.set(s, v);
            }
        }
    }
}

fn busy() -> PyErr {
    PyRuntimeError::new_err("the balance plane is in use")
}

/// Each transfer of a run as the lanes take it: its lane, nonce, sender, recipient, amount,
/// payer, the fee reserved for it and the fee it pays.
type RunTx<'py> = (
    Bound<'py, PyString>,
    u64,
    Bound<'py, PyString>,
    Bound<'py, PyString>,
    Bound<'py, PyString>,
    Bound<'py, PyString>,
    Bound<'py, PyString>,
    Bound<'py, PyString>,
);

#[pymethods]
impl Plane {
    #[new]
    fn new() -> Plane {
        Plane {
            index: HashMap::new(),
            names: Vec::new(),
            maps: Default::default(),
        }
    }

    /// Empty map ``m`` (``dict.clear``).
    fn clear(&mut self, m: usize) -> PyResult<()> {
        self.maps.get_mut(m).ok_or_else(|| PyKeyError::new_err(m))?.clear();
        self.maybe_shrink();
        Ok(())
    }

    /// ``set_available_balance`` for each (holder, balance): the available balance and the
    /// balance as the block began.
    fn load(&mut self, items: &Bound<'_, PyList>) -> PyResult<()> {
        for item in items.iter() {
            let (holder, value): (Bound<'_, PyString>, Bound<'_, PyAny>) = item.extract()?;
            let v = from_py(&value)?;
            let s = self.slot(&holder)?;
            self.maps[AVAIL].set(s, v.dup(items.py()));
            self.maps[START].set(s, v);
        }
        Ok(())
    }

    /// ``_reserve_fee`` for each (payer, fee as ``str(Decimal)``), in order: the fees reserved
    /// (``floors``: when the fee floors apply), the delta and the available balance (where one
    /// is loaded) of each. True if done; False (nothing changed) where a value is not native —
    /// Python reserves them itself.
    fn reserve(&mut self, items: Vec<(Bound<'_, PyString>, Bound<'_, PyString>)>, floors: bool) -> PyResult<bool> {
        // Computed on copies first, each (map, slot) once in the order Python's dicts would
        // have it enter; written together.
        let mut next: HashMap<(usize, u32), Dec> = HashMap::new();
        let mut order: Vec<(usize, u32)> = Vec::new();
        let maps: &[usize] = if floors { &[RESERVED, DELTA, AVAIL] } else { &[DELTA, AVAIL] };
        for (payer, fee) in &items {
            let Some(fee) = parse(&fee.to_cow()?) else {
                return Ok(false);
            };
            let s = self.slot(payer)?;
            for &m in maps {
                let cur = match next.get(&(m, s)) {
                    Some(d) => Some(d.clone()),
                    None => match self.native(m, s) {
                        None => return Ok(false),
                        Some(d) => d,
                    },
                };
                let value = match (m, cur) {
                    (AVAIL, None) => continue, // (only where a balance is loaded)
                    (RESERVED, cur) => add(&cur.unwrap_or_else(Dec::zero), &fee),
                    (_, cur) => sub(&cur.unwrap_or_else(Dec::zero), &fee),
                };
                let Some(value) = value else {
                    return Ok(false);
                };
                if next.insert((m, s), value).is_none() {
                    order.push((m, s));
                }
            }
        }
        for key in order {
            let v = next.remove(&key).expect("a planned value");
            self.maps[key.0].set(key.1, V::D(v));
        }
        Ok(true)
    }

    /// Each entry of map ``m`` as the flush applies it: (address, ``int(Decimal(str(v)) *
    /// Decimal(10**18))`` — wei, truncated toward zero —, whether ``v < 0``), in order. None
    /// where an entry is not native (Python flushes them all).
    fn wei<'py>(&self, py: Python<'py>, m: usize) -> PyResult<Option<Vec<(Bound<'py, PyString>, Bound<'py, PyAny>, bool)>>> {
        let map = self.maps.get(m).ok_or_else(|| PyKeyError::new_err(m))?;
        let scale = Dec::parse("1000000000000000000").expect("10**18");
        let mut out = Vec::with_capacity(map.len);
        for s in map.slots() {
            let Some(V::D(d)) = map.get(s) else {
                return Ok(None);
            };
            let Some(scaled) = d.mul(&scale, &EXCHANGE) else {
                return Ok(None);
            };
            let text = scaled.rescale(0, Rounding::Down).to_python_string();
            let wei: Bound<'py, PyAny> = match text.parse::<i128>() {
                Ok(n) => n.into_py(py).into_bound(py),
                Err(_) => py.import_bound("builtins")?.getattr("int")?.call1((text.as_str(),))?,
            };
            let negative = less(d, &Dec::zero());
            out.push((self.names[s as usize].bind(py).clone(), wei, negative));
        }
        Ok(Some(out))
    }

    /// ``section_errors`` over a run of plain transfers, judged against this plane's available
    /// balances and what the block owes (``OWED``): ``txs`` = [(lane, nonce, payer, max fee)],
    /// ``nonces`` = {lane: expected}. Returns each lane's next nonce, the owed amounts written,
    /// if every one may be in the block; else None (nothing written: Python judges the run).
    #[allow(clippy::type_complexity)]
    fn judge<'py>(
        &mut self,
        py: Python<'py>,
        txs: Vec<(Bound<'py, PyString>, u64, Bound<'py, PyString>, Bound<'py, PyString>)>,
        nonces: &Bound<'py, PyDict>,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let mut expected: HashMap<String, u64> = HashMap::with_capacity(txs.len());
        let mut owed: HashMap<u32, Dec> = HashMap::new();
        let mut owed_order: Vec<u32> = Vec::new();
        for (lane, nonce, payer, max_fee) in &txs {
            let lane = lane.to_cow()?;
            let want = match expected.get(lane.as_ref()) {
                Some(n) => *n,
                None => match nonces.get_item(lane.as_ref())? {
                    Some(n) => n.extract::<u64>()?,
                    None => return Ok(None),
                },
            };
            if *nonce != want {
                return Ok(None);
            }
            let Some(s) = self.find(&payer.to_cow()?) else {
                return Ok(None); // (no balance loaded for it)
            };
            let Some(fee) = parse(&max_fee.to_cow()?) else {
                return Ok(None);
            };
            let so_far = match owed.get(&s) {
                Some(d) => d.clone(),
                None => match self.native(OWED, s) {
                    Some(d) => d.unwrap_or_else(Dec::zero),
                    None => return Ok(None),
                },
            };
            let Some(need) = add(&so_far, &fee) else {
                return Ok(None);
            };
            let held = match self.native(AVAIL, s) {
                Some(Some(d)) => d,
                _ => return Ok(None),
            };
            if less(&held, &need) {
                return Ok(None);
            }
            if !owed.contains_key(&s) {
                owed_order.push(s);
            }
            owed.insert(s, need);
            expected.insert(lane.into_owned(), nonce + 1);
        }
        for s in owed_order {
            let v = owed.remove(&s).expect("an owed payer");
            self.maps[OWED].set(s, V::D(v));
        }
        let out = PyDict::new_bound(py);
        for (lane, n) in expected {
            out.set_item(lane, n)?;
        }
        Ok(Some(out))
    }

    /// ``process_transaction`` over a run of plain transfers judged includable, in place:
    /// ``txs`` as ``RunTx``; ``nonces`` = {lane: expected}; ``fees``: the block's fees so far;
    /// ``reserve``: the fee reserve (``_fee_reserve``) when the floors apply. Returns (each
    /// transaction's outcome — it ran, or the available balance it found —, each lane's next
    /// nonce, the block's fees), or None: nothing written, Python runs the run (a nonce out of
    /// sequence, a value not native, a sender that could cross its fee floor).
    #[allow(clippy::type_complexity)]
    #[pyo3(signature = (txs, nonces, fees, reserve=None))]
    fn run<'py>(
        &mut self,
        py: Python<'py>,
        txs: Vec<RunTx<'py>>,
        nonces: &Bound<'py, PyDict>,
        fees: &str,
        reserve: Option<&str>,
    ) -> PyResult<Option<(Vec<(bool, Option<Bound<'py, PyAny>>)>, Vec<(String, u64)>, String)>> {
        let Some(mut block_fees) = parse(fees) else {
            return Ok(None);
        };
        // Every address the run names, and the values it starts from.
        struct Tx {
            lane: usize,
            nonce: u64,
            sender: u32,
            to: u32,
            amount: Dec,
            payer: u32,
            back: Dec,
            fee: Dec,
        }
        let mut lanes: Vec<(String, u64)> = Vec::new();
        let mut lane_at: HashMap<String, usize> = HashMap::new();
        let mut run: Vec<Tx> = Vec::with_capacity(txs.len());
        for (lane, nonce, sender, to, amount, payer, reserved, fee) in &txs {
            let lane = lane.to_cow()?;
            let at = match lane_at.get(lane.as_ref()) {
                Some(&at) => at,
                None => {
                    let Some(n) = nonces.get_item(lane.as_ref())? else {
                        return Ok(None);
                    };
                    let at = lanes.len();
                    lanes.push((lane.to_string(), n.extract::<u64>()?));
                    lane_at.insert(lane.into_owned(), at);
                    at
                }
            };
            let (Some(amount), Some(reserved), Some(fee)) = (
                parse(&amount.to_cow()?),
                parse(&reserved.to_cow()?),
                parse(&fee.to_cow()?),
            ) else {
                return Ok(None);
            };
            let Some(back) = sub(&reserved, &fee) else {
                return Ok(None);
            };
            run.push(Tx {
                lane: at,
                nonce: *nonce,
                sender: self.slot(sender)?,
                to: self.slot(to)?,
                amount,
                payer: self.slot(payer)?,
                back,
                fee,
            });
        }
        let _ = py;

        // The values the run starts from (a value not native: Python's run).
        let mut delta: HashMap<u32, Option<Dec>> = HashMap::new();
        let mut avail: HashMap<u32, Option<Dec>> = HashMap::new();
        for t in &run {
            for s in [t.sender, t.to, t.payer] {
                if let std::collections::hash_map::Entry::Vacant(e) = delta.entry(s) {
                    let Some(d) = self.native(DELTA, s) else {
                        return Ok(None);
                    };
                    e.insert(d);
                }
                if let std::collections::hash_map::Entry::Vacant(e) = avail.entry(s) {
                    let Some(a) = self.native(AVAIL, s) else {
                        return Ok(None);
                    };
                    e.insert(a);
                }
            }
        }

        // The fee floors (``_above_floors``): every sender keeps its floor even if all its
        // transfers in the run ran and nothing came in.
        if let Some(reserve) = reserve {
            let Some(reserve) = parse(reserve) else {
                return Ok(None);
            };
            let mut sent: HashMap<u32, Dec> = HashMap::new();
            let mut senders: Vec<u32> = Vec::new();
            for t in &run {
                let total = match sent.get(&t.sender) {
                    Some(d) => add(d, &t.amount),
                    None => {
                        senders.push(t.sender);
                        add(&Dec::zero(), &t.amount)
                    }
                };
                let Some(total) = total else {
                    return Ok(None);
                };
                sent.insert(t.sender, total);
            }
            for s in senders {
                let name = self.names[s as usize].bind(py).to_cow()?.into_owned();
                let head = &name.as_bytes()[..name.len().min(6)];
                if !head.is_ascii() {
                    return Ok(None); // (Python's upper() of anything else: Python's)
                }
                let head = head.to_ascii_uppercase();
                if !(head.starts_with(b"0XPQ") || head == b"0XSUBA") {
                    continue; // (pays no fees: no floor)
                }
                let start = match self.native(START, s) {
                    Some(Some(d)) => d,
                    Some(None) => continue, // (not loaded: no floor)
                    None => return Ok(None),
                };
                let reserved = match self.native(RESERVED, s) {
                    Some(d) => d.unwrap_or_else(Dec::zero),
                    None => return Ok(None),
                };
                let low = if less(&start, &reserve) { start } else { reserve.clone() };
                let Some(floor) = sub(&low, &reserved) else {
                    return Ok(None);
                };
                let Some(held) = avail[&s].clone() else {
                    return Ok(None); // (no balance held: Python refuses the transfer)
                };
                let Some(left) = sub(&held, &sent[&s]) else {
                    return Ok(None);
                };
                if less(&left, &floor) {
                    return Ok(None);
                }
            }
        }

        // The run, on copies.
        let mut entered: Vec<u32> = Vec::new(); // (addresses new to the deltas, in order)
        let mut record = |delta: &mut HashMap<u32, Option<Dec>>,
                          avail: &mut HashMap<u32, Option<Dec>>,
                          s: u32,
                          d: &Dec|
         -> Option<()> {
            let cur = delta.get_mut(&s)?;
            if cur.is_none() {
                entered.push(s);
            }
            *cur = Some(add(cur.as_ref().unwrap_or(&Dec::zero()), d)?);
            let next = match avail.get(&s) {
                Some(Some(a)) => Some(add(a, d)?),
                _ => None,
            };
            if let Some(n) = next {
                avail.insert(s, Some(n));
            }
            Some(())
        };
        let mut outcomes: Vec<(bool, Option<Dec>)> = Vec::with_capacity(run.len());
        let mut touched_avail: Vec<u32> = Vec::new();
        for t in &run {
            let lane = &mut lanes[t.lane];
            if lane.1 != t.nonce {
                return Ok(None);
            }
            let found = avail[&t.sender].clone();
            let short = match &found {
                None => true,
                Some(a) => less(a, &t.amount),
            };
            if short {
                outcomes.push((false, found));
            } else {
                if record(&mut delta, &mut avail, t.sender, &t.amount.neg()).is_none()
                    || record(&mut delta, &mut avail, t.to, &t.amount).is_none()
                {
                    return Ok(None);
                }
                touched_avail.push(t.sender);
                touched_avail.push(t.to);
                outcomes.push((true, None));
            }
            lane.1 = t.nonce + 1;
            if record(&mut delta, &mut avail, t.payer, &t.back).is_none() {
                return Ok(None);
            }
            touched_avail.push(t.payer);
            let Some(next) = add(&block_fees, &t.fee) else {
                return Ok(None);
            };
            block_fees = next;
        }

        // Written: the deltas (existing keys in place, new ones in the order they entered), the
        // available balances changed.
        for t in &run {
            for s in [t.sender, t.to, t.payer] {
                if self.maps[DELTA].get(s).is_some() {
                    if let Some(Some(d)) = delta.get(&s) {
                        self.maps[DELTA].set(s, V::D(d.clone()));
                    }
                }
            }
        }
        for s in entered {
            if self.maps[DELTA].get(s).is_none() {
                if let Some(Some(d)) = delta.get(&s) {
                    self.maps[DELTA].set(s, V::D(d.clone()));
                }
            }
        }
        for s in touched_avail {
            if let Some(Some(a)) = avail.get(&s) {
                if self.maps[AVAIL].get(s).is_some() {
                    self.maps[AVAIL].set(s, V::D(a.clone()));
                }
            }
        }
        let outcomes = outcomes
            .into_iter()
            .map(|(ran, found)| -> PyResult<(bool, Option<Bound<'py, PyAny>>)> {
                Ok((ran, found.map(|d| to_decimal(py, &d)).transpose()?))
            })
            .collect::<PyResult<Vec<_>>>()?;
        Ok(Some((outcomes, lanes, block_fees.to_python_string())))
    }
}

/// One of the plane's maps, as the dict it stands for.
#[pyclass(module = "qrdx_native", mapping)]
pub struct PlaneView {
    plane: Py<Plane>,
    m: usize,
}

impl PlaneView {
    fn with<T>(&self, py: Python<'_>, f: impl FnOnce(&Plane) -> PyResult<T>) -> PyResult<T> {
        let p = self.plane.bind(py).try_borrow().map_err(|_| busy())?;
        f(&p)
    }

    fn with_mut<T>(&self, py: Python<'_>, f: impl FnOnce(&mut Plane) -> PyResult<T>) -> PyResult<T> {
        let mut p = self.plane.bind(py).try_borrow_mut().map_err(|_| busy())?;
        f(&mut p)
    }

    fn lookup<'py>(&self, key: &Bound<'py, PyAny>) -> PyResult<Option<Bound<'py, PyAny>>> {
        let py = key.py();
        let Ok(key) = key.downcast::<PyString>() else {
            return Ok(None);
        };
        let text = key.to_cow()?;
        self.with(py, |p| match p.find(&text).and_then(|s| p.maps[self.m].get(s)) {
            None => Ok(None),
            Some(v) => Ok(Some(to_py(py, v)?)),
        })
    }

    fn items_of<'py>(&self, py: Python<'py>) -> PyResult<Vec<(Bound<'py, PyString>, Bound<'py, PyAny>)>> {
        self.with(py, |p| {
            let map = &p.maps[self.m];
            map.slots()
                .map(|s| -> PyResult<_> {
                    Ok((
                        p.names[s as usize].bind(py).clone(),
                        to_py(py, map.get(s).expect("a live slot"))?,
                    ))
                })
                .collect()
        })
    }

    fn dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new_bound(py);
        for (k, v) in self.items_of(py)? {
            d.set_item(k, v)?;
        }
        Ok(d)
    }
}

/// The native value a view holds for ``key``: Some(None) when it holds none, None when it holds
/// what native code does not compute with (the order lane: src/order_lane.rs).
pub(crate) fn view_value(view: &Bound<'_, PlaneView>, key: &str) -> Option<Option<Dec>> {
    let me = view.borrow();
    let plane = me.plane.bind(view.py()).try_borrow().ok()?;
    match plane.find(key) {
        None => Some(None),
        Some(s) => plane.native(me.m, s),
    }
}

#[pymethods]
impl PlaneView {
    #[new]
    fn new(plane: Py<Plane>, m: usize) -> PyResult<PlaneView> {
        if m >= NMAPS {
            return Err(PyKeyError::new_err(m));
        }
        Ok(PlaneView { plane, m })
    }

    #[getter]
    fn plane(&self, py: Python<'_>) -> Py<Plane> {
        self.plane.clone_ref(py)
    }

    #[getter]
    fn map(&self) -> usize {
        self.m
    }

    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        self.with(py, |p| Ok(p.maps[self.m].len))
    }

    fn __contains__(&self, key: &Bound<'_, PyAny>) -> PyResult<bool> {
        let Ok(key) = key.downcast::<PyString>() else {
            return Ok(false);
        };
        let text = key.to_cow()?;
        self.with(key.py(), |p| {
            Ok(p.find(&text).is_some_and(|s| p.maps[self.m].get(s).is_some()))
        })
    }

    fn __getitem__<'py>(&self, key: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        self.lookup(key)?
            .ok_or_else(|| PyKeyError::new_err(key.clone().unbind()))
    }

    fn __setitem__(&self, key: &Bound<'_, PyAny>, value: &Bound<'_, PyAny>) -> PyResult<()> {
        let Ok(key) = key.downcast::<PyString>() else {
            return Err(PyTypeError::new_err("a balance plane's keys are addresses (str)"));
        };
        let v = from_py(value)?;
        self.with_mut(key.py(), |p| {
            let s = p.slot(key)?;
            p.maps[self.m].set(s, v);
            Ok(())
        })
    }

    fn __delitem__(&self, key: &Bound<'_, PyAny>) -> PyResult<()> {
        if self.pop_value(key)?.is_none() {
            return Err(PyKeyError::new_err(key.clone().unbind()));
        }
        Ok(())
    }

    fn __iter__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        PyList::new_bound(py, self.keys(py)?).call_method0("__iter__")
    }

    fn __richcmp__(&self, other: &Bound<'_, PyAny>, op: CompareOp) -> PyResult<PyObject> {
        let py = other.py();
        let mine = self.dict(py)?;
        let theirs: Bound<'_, PyAny> = match other.downcast::<PlaneView>() {
            Ok(view) => view.borrow().dict(py)?.into_any(),
            Err(_) => other.clone(),
        };
        Ok(mine.as_any().rich_compare(theirs, op)?.unbind())
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(self.dict(py)?.repr()?.to_string())
    }

    #[pyo3(signature = (key, default=None))]
    fn get<'py>(&self, key: &Bound<'py, PyAny>, default: Option<Bound<'py, PyAny>>) -> PyResult<Option<Bound<'py, PyAny>>> {
        Ok(self.lookup(key)?.or(default))
    }

    #[pyo3(signature = (key, *default))]
    fn pop<'py>(&self, key: &Bound<'py, PyAny>, default: &Bound<'py, PyTuple>) -> PyResult<Bound<'py, PyAny>> {
        match self.pop_value(key)? {
            Some(v) => Ok(v),
            None if !default.is_empty() => default.get_item(0),
            None => Err(PyKeyError::new_err(key.clone().unbind())),
        }
    }

    #[pyo3(signature = (key, default=None))]
    fn setdefault<'py>(&self, key: &Bound<'py, PyAny>, default: Option<Bound<'py, PyAny>>) -> PyResult<Bound<'py, PyAny>> {
        if let Some(v) = self.lookup(key)? {
            return Ok(v);
        }
        let value = default.unwrap_or_else(|| key.py().None().into_bound(key.py()));
        self.__setitem__(key, &value)?;
        Ok(value)
    }

    fn popitem<'py>(&self, py: Python<'py>) -> PyResult<(Bound<'py, PyString>, Bound<'py, PyAny>)> {
        self.with_mut(py, |p| {
            let Some(s) = p.maps[self.m].slots().last() else {
                return Err(PyKeyError::new_err("popitem(): dictionary is empty"));
            };
            let v = p.maps[self.m].remove(s).expect("a live slot");
            Ok((p.names[s as usize].bind(py).clone(), to_py(py, &v)?))
        })
    }

    fn clear(&self, py: Python<'_>) -> PyResult<()> {
        self.with_mut(py, |p| p.clear(self.m))
    }

    fn keys<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyString>>> {
        self.with(py, |p| {
            Ok(p.maps[self.m]
                .slots()
                .map(|s| p.names[s as usize].bind(py).clone())
                .collect())
        })
    }

    fn values<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyAny>>> {
        Ok(self.items_of(py)?.into_iter().map(|(_, v)| v).collect())
    }

    fn items<'py>(&self, py: Python<'py>) -> PyResult<Vec<(Bound<'py, PyString>, Bound<'py, PyAny>)>> {
        self.items_of(py)
    }

    fn copy<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        self.dict(py)
    }

    #[pyo3(signature = (other=None, **kwargs))]
    fn update(&self, py: Python<'_>, other: Option<&Bound<'_, PyAny>>, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<()> {
        let pairs = PyDict::new_bound(py);
        if let Some(other) = other {
            if let Ok(view) = other.downcast::<PlaneView>() {
                pairs.update(view.borrow().dict(py)?.as_mapping())?;
            } else if other.hasattr("keys")? {
                for key in other.call_method0("keys")?.iter()? {
                    let key = key?;
                    pairs.set_item(&key, other.get_item(&key)?)?;
                }
            } else {
                for item in other.iter()? {
                    let (k, v): (Bound<'_, PyAny>, Bound<'_, PyAny>) = item?.extract()?;
                    pairs.set_item(k, v)?;
                }
            }
        }
        if let Some(kwargs) = kwargs {
            pairs.update(kwargs.as_mapping())?;
        }
        for (k, v) in pairs.iter() {
            self.__setitem__(&k, &v)?;
        }
        Ok(())
    }
}

impl PlaneView {
    fn pop_value<'py>(&self, key: &Bound<'py, PyAny>) -> PyResult<Option<Bound<'py, PyAny>>> {
        let py = key.py();
        let Ok(key) = key.downcast::<PyString>() else {
            return Ok(None);
        };
        let text = key.to_cow()?;
        self.with_mut(py, |p| {
            let Some(s) = p.find(&text) else {
                return Ok(None);
            };
            match p.maps[self.m].remove(s) {
                None => Ok(None),
                Some(v) => Ok(Some(to_py(py, &v)?)),
            }
        })
    }
}
