//! The order book, natively (qrdx/exchange/orderbook.py; docs/EXCHANGE_ENGINE.md, E2).
//!
//! A port of the Python book, method by method: price levels in time priority, the order index,
//! parked stop orders, matching (limit, market, post-only, IOC, fill-or-kill, hidden and iceberg
//! orders, self-trade prevention, a budget of makers), fees, deterministic trade ids, the
//! per-block rate limit, owner nonces and counts, expiry, pausing — and the book's digest, from
//! the same payloads. Its decimals are Python's (`dec.rs`), every value spelled as Python spells
//! it, because those spellings reach trades, receipts and the digest.
//!
//! The state is persistent (`im`): copying a book — a snapshot, an undo scope's record of it,
//! the savepoint an operation that fails is rolled back to — is a pointer copy.
//!
//! `tests/test_native_book.py` drives this book and the Python one with the same random
//! operations and compares every trade, order, level, error and digest.

use std::cmp::Ordering;
use std::sync::Arc;

use blake2::digest::core_api::{Buffer, UpdateCore, VariableOutputCore};
use blake2::digest::{Update, VariableOutput};
use blake2::{Blake2bVar, Blake2bVarCore};
use im::{HashMap as IMap, OrdMap, Vector};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use crate::dec::{Dec, Rounding, EXCHANGE};

/// An order id or an owner: shared, so copying a map node that holds it bumps a count rather
/// than allocating (the state is persistent: every operation's savepoint shares it).
pub type Id = Arc<str>;

// orderbook.py's limits
const MAX_ORDERS_PER_BLOCK_PER_ADDRESS: i64 = 50;
const MAX_STOP_ORDERS_PER_ADDRESS: i64 = 50;
const MAX_RECENT_TRADES: usize = 1000;

// ── values ────────────────────────────────────────────────────────────────────────────────

/// A failed operation: Python's ``ValueError`` and its message, or a value this book does not
/// compute with (``Native``: the caller hands the operation to Python).
#[derive(Debug)]
pub enum Fail {
    Refused(String),
    Native,
}

type R<T> = Result<T, Fail>;

fn refused<T>(message: impl Into<String>) -> R<T> {
    Err(Fail::Refused(message.into()))
}

fn add(a: &Dec, b: &Dec) -> R<Dec> {
    a.add(b, &EXCHANGE).ok_or(Fail::Native)
}

fn sub(a: &Dec, b: &Dec) -> R<Dec> {
    a.sub(b, &EXCHANGE).ok_or(Fail::Native)
}

fn mul(a: &Dec, b: &Dec) -> R<Dec> {
    a.mul(b, &EXCHANGE).ok_or(Fail::Native)
}

fn lt(a: &Dec, b: &Dec) -> bool {
    a.cmp(b) == Ordering::Less
}

fn le(a: &Dec, b: &Dec) -> bool {
    a.cmp(b) != Ordering::Greater
}

fn positive(a: &Dec) -> bool {
    !a.is_zero() && !a.neg
}

/// Python's ``min(a, b)``: ``a`` unless ``b`` is smaller (the spelling of a tie is ``a``'s).
fn py_min(a: &Dec, b: &Dec) -> Dec {
    if lt(b, a) {
        b.clone()
    } else {
        a.clone()
    }
}

/// Python's ``max(a, b)``.
fn py_max(a: &Dec, b: &Dec) -> Dec {
    if lt(a, b) {
        b.clone()
    } else {
        a.clone()
    }
}

fn zero() -> Dec {
    Dec::zero()
}

/// Python's ``repr`` of a float (what ``f"{x}"`` writes): the shortest digits that read back,
/// in fixed notation for exponents −4 to 15, else ``1e+16``-style.
pub fn py_float_repr(x: f64) -> String {
    if x.is_nan() {
        return "nan".into();
    }
    if x.is_infinite() {
        return if x > 0.0 { "inf".into() } else { "-inf".into() };
    }
    // Ryū's digits: the shortest that read back, and of those the closest to the value — what
    // Python's repr writes (Rust's own formatting can pick another of equal length).
    let mut buffer = ryu::Buffer::new();
    let text = buffer.format_finite(x); // "1.5e-5", "1e16", "123.0", "0.0001"
    let (sign, text) = match text.strip_prefix('-') {
        Some(t) => ("-", t),
        None => ("", text),
    };
    let (mantissa, given_exp) = match text.split_once('e') {
        Some((m, e)) => (m, e.parse::<i32>().expect("an integer exponent")),
        None => (text, 0),
    };
    // the significant digits and the exponent of the first of them
    let (int, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let all = format!("{int}{frac}");
    let lead = all.len() - all.trim_start_matches('0').len();
    let digits = all.trim_start_matches('0').trim_end_matches('0').to_string();
    if digits.is_empty() {
        return format!("{sign}0.0");
    }
    let exp = given_exp + int.len() as i32 - 1 - lead as i32;
    if (-4..16).contains(&exp) {
        if exp >= 0 {
            let e = exp as usize;
            let (int, frac) = if digits.len() > e + 1 {
                (digits[..e + 1].to_string(), digits[e + 1..].to_string())
            } else {
                (format!("{}{}", digits, "0".repeat(e + 1 - digits.len())), String::new())
            };
            let frac = if frac.is_empty() { "0".to_string() } else { frac };
            format!("{sign}{int}.{frac}")
        } else {
            format!("{sign}0.{}{}", "0".repeat((-exp - 1) as usize), digits)
        }
    } else {
        let m = if digits.len() > 1 {
            format!("{}.{}", &digits[..1], &digits[1..])
        } else {
            digits
        };
        let es = if exp < 0 { "-" } else { "+" };
        format!("{sign}{m}e{es}{:02}", exp.abs())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Buy,
    Sell,
}

impl Side {
    pub(crate) fn value(self) -> &'static str {
        match self {
            Side::Buy => "buy",
            Side::Sell => "sell",
        }
    }
    fn parse(s: &str) -> Option<Side> {
        match s {
            "buy" => Some(Side::Buy),
            "sell" => Some(Side::Sell),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Limit,
    Market,
    StopLoss,
}

impl Kind {
    fn value(self) -> &'static str {
        match self {
            Kind::Limit => "limit",
            Kind::Market => "market",
            Kind::StopLoss => "stop_loss",
        }
    }
    fn parse(s: &str) -> Option<Kind> {
        match s {
            "limit" => Some(Kind::Limit),
            "market" => Some(Kind::Market),
            "stop_loss" => Some(Kind::StopLoss),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Open,
    PartiallyFilled,
    Filled,
    Cancelled,
    Triggered,
}

impl Status {
    fn value(self) -> &'static str {
        match self {
            Status::Open => "open",
            Status::PartiallyFilled => "partially_filled",
            Status::Filled => "filled",
            Status::Cancelled => "cancelled",
            Status::Triggered => "triggered",
        }
    }
    fn parse(s: &str) -> Option<Status> {
        Some(match s {
            "open" => Status::Open,
            "partially_filled" => Status::PartiallyFilled,
            "filled" => Status::Filled,
            "cancelled" => Status::Cancelled,
            "triggered" => Status::Triggered,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stp {
    Reject,
    CancelMaker,
    CancelBoth,
    CancelTaker,
}

impl Stp {
    fn parse(s: &str) -> Option<Stp> {
        Some(match s {
            "reject" => Stp::Reject,
            "cancel_maker" => Stp::CancelMaker,
            "cancel_both" => Stp::CancelBoth,
            "cancel_taker" => Stp::CancelTaker,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Order {
    pub id: Id,
    pub owner: Id,
    pub side: Side,
    pub kind: Kind,
    pub price: Dec,
    pub amount: Dec,
    pub filled: Dec,
    pub status: Status,
    pub timestamp: f64,
    pub stop_price: Option<Dec>,
    pub nonce: i64,
    pub expire_time: f64,
    pub tif: Id,
    pub hidden: bool,
    pub display_size: Dec,
    pub shown: Dec,
}

impl Order {
    pub(crate) fn remaining(&self) -> R<Dec> {
        sub(&self.amount, &self.filled)
    }
    fn is_iceberg(&self) -> bool {
        positive(&self.display_size)
    }
    fn visible(&self) -> R<Dec> {
        if self.hidden {
            return Ok(zero());
        }
        if self.is_iceberg() {
            return Ok(py_min(&self.shown, &self.remaining()?));
        }
        self.remaining()
    }
    fn reserve(&self) -> R<Dec> {
        sub(&self.remaining()?, &self.visible()?)
    }
    pub(crate) fn is_active(&self) -> bool {
        matches!(self.status, Status::Open | Status::PartiallyFilled)
    }
    fn expired(&self, now: Option<f64>) -> bool {
        self.expire_time > 0.0 && now.is_some_and(|n| n > self.expire_time)
    }
}

#[derive(Clone, Debug)]
pub struct Trade {
    pub id: String,
    pub maker_order_id: Id,
    pub taker_order_id: Id,
    pub price: Dec,
    pub amount: Dec,
    pub maker_fee: Dec,
    pub taker_fee: Dec,
    pub buyer: Id,
    pub seller: Id,
    pub sequence: u64,
    pub timestamp: f64, // (the wall clock, as the Python book's: display only, never hashed)
}

/// A price as a map key: equal values are one key, whatever their spelling.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PKey(Dec);

impl PKey {
    fn of(price: &Dec) -> PKey {
        PKey(price.normalized())
    }
}

impl Ord for PKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for PKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A price level: its price as its first order spelled it (the dict key), its orders in time
/// priority.
#[derive(Clone, Debug)]
struct Level {
    price: Dec,
    orders: Vector<Id>,
}

/// How many resting orders one placement may visit (``orderbook.MatchBudget``).
#[derive(Clone, Copy, Debug)]
pub struct Budget {
    pub left: i64,
    pub visited: i64,
    pub exhausted: bool,
}

impl Budget {
    fn take(&mut self) -> bool {
        if self.left <= 0 {
            self.exhausted = true;
            return false;
        }
        self.left -= 1;
        self.visited += 1;
        true
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub pool_id: String,
    pub max_depth: usize,
    pub maker_fee_rate: Dec,
    pub taker_fee_rate: Dec,
    pub stp: Stp,
    pub min_order_size: Dec,
    pub max_orders_per_address: i64,
}

/// The book's state: everything a snapshot or an undo record holds.
#[derive(Clone, Debug)]
pub struct State {
    bids: OrdMap<PKey, Level>,
    asks: OrdMap<PKey, Level>,
    orders: IMap<Id, Arc<Order>>, // resting orders (``_orders``)
    order_seq: IMap<Id, u64>,     // (their insertion order, for expiry)
    next_seq: u64,
    pub(crate) stop_ids: Vector<Id>, // parked stop orders, in the order they were placed
    stops: IMap<Id, Arc<Order>>,
    owner_order_count: IMap<Id, i64>,
    owner_stop_count: IMap<Id, i64>,
    block_order_count: IMap<Id, i64>,
    trade_sequence: u64,
    last_price: Option<Dec>,
    total_volume: Dec,
    total_trades: u64,
    paused: bool,
    now: Option<f64>,
    has_expiring: bool,
    pub(crate) block_height: Option<i64>,
    recent: Vector<Trade>, // the display history (never consensus)
    // The incremental commitment (``cached_digest``): each level's digest, their LtHash, the
    // levels touched since, the levels' proof tree. ``level_digests`` None: recompute in full.
    level_digests: Option<OrdMap<(u8, PKey), [u8; 32]>>,
    level_acc: Arc<Vec<u8>>,
    dirty: im::OrdSet<(u8, PKey)>,
    level_tree: crate::mtree::Tree,
    tree_on: bool,
}

impl State {
    fn new() -> State {
        State {
            bids: OrdMap::new(),
            asks: OrdMap::new(),
            orders: IMap::new(),
            order_seq: IMap::new(),
            next_seq: 0,
            stop_ids: Vector::new(),
            stops: IMap::new(),
            owner_order_count: IMap::new(),
            owner_stop_count: IMap::new(),
            block_order_count: IMap::new(),
            trade_sequence: 0,
            last_price: None,
            total_volume: zero(),
            total_trades: 0,
            paused: false,
            now: None,
            has_expiring: false,
            block_height: None,
            recent: Vector::new(),
            level_digests: None,
            level_acc: Arc::new(vec![0u8; crate::lthash::SIZE]),
            dirty: im::OrdSet::new(),
            level_tree: None,
            tree_on: false,
        }
    }
}

fn blake2b(data: &[u8], size: usize) -> Vec<u8> {
    let mut h = Blake2bVar::new(size).expect("a BLAKE2b size");
    h.update(data);
    let mut out = vec![0u8; size];
    h.finalize_variable(&mut out).expect("the size given");
    out
}

/// ``hashlib.blake2b(data, digest_size=32, person=persona)`` (unkeyed).
pub(crate) fn blake2b_personal(data: &[u8], persona: &[u8]) -> Vec<u8> {
    let mut core = Blake2bVarCore::new_with_params(&[], persona, 0, 32);
    let mut buffer: Buffer<Blake2bVarCore> = Default::default();
    buffer.digest_blocks(data, |blocks| core.update_blocks(blocks));
    let mut full = Default::default();
    core.finalize_variable_core(&mut buffer, &mut full);
    full[..32].to_vec()
}

pub struct Book {
    pub config: Config,
    pub state: State,
    /// Every order the operation in progress changed, as it last was: in Python the order a
    /// caller placed is the object the book indexes, so a stop triggered later in the same
    /// placement can fill it, and the caller sees it.
    pub(crate) last: std::collections::HashMap<Id, Order>,
    /// The placing owner's last book nonce, read from Python's committed nonces (``_nonces``),
    /// and the one this placement set: the book's nonces stay Python's, committed and provable.
    pub(crate) last_nonce: i64,
    pub(crate) new_nonce: Option<i64>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Book {
    pub fn new(config: Config) -> Book {
        Book::with_state(config, State::new())
    }

    pub fn with_state(config: Config, state: State) -> Book {
        Book {
            config,
            state,
            last: std::collections::HashMap::new(),
            last_nonce: 0,
            new_nonce: None,
        }
    }

    fn side_mut(&mut self, side: Side) -> &mut OrdMap<PKey, Level> {
        match side {
            Side::Buy => &mut self.state.bids,
            Side::Sell => &mut self.state.asks,
        }
    }

    fn side(&self, side: Side) -> &OrdMap<PKey, Level> {
        match side {
            Side::Buy => &self.state.bids,
            Side::Sell => &self.state.asks,
        }
    }

    fn put_order(&mut self, order: Order) {
        if !self.state.orders.contains_key(&order.id) {
            let seq = self.state.next_seq;
            self.state.next_seq += 1;
            self.state.order_seq.insert(order.id.clone(), seq);
        }
        self.last.insert(order.id.clone(), order.clone());
        self.touch(order.side, &order.price);
        self.state.orders.insert(order.id.clone(), Arc::new(order));
    }

    /// A resting order, as a value to change.
    fn resting(&self, id: &str) -> Option<Order> {
        self.state.orders.get(id).map(|o| (**o).clone())
    }

    /// The order leaves the book, ``order`` as it ended.
    fn drop_order(&mut self, order: &Order) {
        self.last.insert(order.id.clone(), order.clone());
        self.touch(order.side, &order.price);
        self.state.orders.remove(&order.id);
        self.state.order_seq.remove(&order.id);
    }

    fn level_total(&self, level: &Level) -> R<Dec> {
        let mut total = zero();
        for id in level.orders.iter() {
            if let Some(o) = self.state.orders.get(id) {
                if o.is_active() {
                    total = add(&total, &o.remaining()?)?;
                }
            }
        }
        Ok(total)
    }

    fn level_visible(&self, level: &Level) -> R<Dec> {
        let mut total = zero();
        for id in level.orders.iter() {
            if let Some(o) = self.state.orders.get(id) {
                if o.is_active() {
                    total = add(&total, &o.visible()?)?;
                }
            }
        }
        Ok(total)
    }

    /// A side's level prices, best first (``level_prices``): bids high to low, asks low to high.
    pub fn level_prices(&self, bids: bool) -> Vec<Dec> {
        if bids {
            self.state.bids.values().rev().map(|l| l.price.clone()).collect()
        } else {
            self.state.asks.values().map(|l| l.price.clone()).collect()
        }
    }

    /// ``record_price``: the pair's last price, set from a fill outside the book (a pool's).
    pub(crate) fn record_price(&mut self, price: Dec) {
        self.state.last_price = Some(price);
    }

    /// ``OrderBook.fill_queue`` of the level at ``price``: its active orders' displayed amounts
    /// in time order, then their hidden ones — (owner, what it offers).
    pub(crate) fn fill_queue(&self, bids: bool, price: &Dec) -> R<Vec<(Id, Dec)>> {
        let side = if bids { &self.state.bids } else { &self.state.asks };
        let Some(level) = side.get(&PKey::of(price)) else {
            return Ok(Vec::new());
        };
        let orders: Vec<&Arc<Order>> = level
            .orders
            .iter()
            .filter_map(|id| self.state.orders.get(id))
            .filter(|o| o.is_active())
            .collect();
        let mut queue = Vec::new();
        for o in &orders {
            let v = o.visible()?;
            if positive(&v) {
                queue.push((o.owner.clone(), v));
            }
        }
        for o in &orders {
            let r = o.reserve()?;
            if positive(&r) {
                queue.push((o.owner.clone(), r));
            }
        }
        Ok(queue)
    }

    /// The best price that shows something (``_best``).
    pub fn best(&self, bids: bool) -> R<Option<Dec>> {
        let levels: Box<dyn Iterator<Item = &Level>> = if bids {
            Box::new(self.state.bids.values().rev())
        } else {
            Box::new(self.state.asks.values())
        };
        for level in levels {
            if positive(&self.level_visible(level)?) {
                return Ok(Some(level.price.clone()));
            }
        }
        Ok(None)
    }

    // ── placement ───────────────────────────────────────────────────────────────────────────

    /// ``place_order``: the trades it made and the order as it ended. A failure leaves the book
    /// as it was, and gives the order as it stood when it failed (in Python the caller's object
    /// keeps what matching did to it: a fill-or-kill that matched, then failed).
    pub fn place_order(
        &mut self,
        order: Order,
        protocol: bool,
        budget: &mut Option<Budget>,
    ) -> Result<(Vec<Trade>, Order), (Fail, Order)> {
        let saved = self.state.clone();
        self.last.clear();
        self.new_nonce = None;
        let mut order = order;
        match self.place(&mut order, protocol, budget) {
            Ok(trades) => {
                let id = order.id.clone();
                let ended = self.last.remove(&id).unwrap_or(order);
                Ok((trades, ended))
            }
            Err(e) => {
                self.state = saved;
                Err((e, order))
            }
        }
    }

    fn place(
        &mut self,
        order: &mut Order,
        protocol: bool,
        budget: &mut Option<Budget>,
    ) -> R<Vec<Trade>> {
        if self.state.paused {
            return refused("Order book is paused — emergency mode");
        }
        self.validate(order)?;
        if &*order.tif == "alo" && self.would_match(order)? {
            return refused("post-only order would match a resting order");
        }
        if !protocol {
            self.check_rate_limit(&order.owner)?;
            self.check_nonce(order)?;
        }
        if order.kind == Kind::StopLoss {
            return self.place_stop(order);
        }
        let trades = if order.kind == Kind::Market {
            self.match_market(order, budget)?
        } else {
            self.match_limit(order, budget)?
        };
        if &*order.tif == "fok" && positive(&order.remaining()?) {
            return refused("fill-or-kill order could not fill completely");
        }
        Ok(trades)
    }

    fn would_match(&self, order: &Order) -> R<bool> {
        let buy = order.side == Side::Buy;
        let opposite = self.side(if buy { Side::Sell } else { Side::Buy });
        for level in opposite.values() {
            let crosses = if buy {
                le(&level.price, &order.price)
            } else {
                le(&order.price, &level.price)
            };
            if crosses && positive(&self.level_total(level)?) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn validate(&self, order: &Order) -> R<()> {
        let min = &self.config.min_order_size;
        if !positive(&order.amount) {
            return refused("Order amount must be positive");
        }
        if lt(&order.amount, min) {
            return refused(format!("Order amount below minimum ({})", min.to_python_string()));
        }
        if order.kind == Kind::Limit && !positive(&order.price) {
            return refused("Limit order price must be positive");
        }
        if order.kind == Kind::StopLoss && !order.stop_price.as_ref().is_some_and(positive) {
            return refused("Stop-loss requires positive stop_price");
        }
        if !matches!(&*order.tif, "gtc" | "ioc" | "fok" | "alo") {
            return refused("unknown time in force (gtc, ioc, fok, alo)");
        }
        if &*order.tif == "alo" && order.kind != Kind::Limit {
            return refused("a post-only order must be a limit order");
        }
        if &*order.tif != "gtc" && order.kind == Kind::StopLoss {
            return refused("a stop order is good till cancelled");
        }
        if (order.hidden || order.is_iceberg())
            && (order.kind != Kind::Limit || !matches!(&*order.tif, "gtc" | "alo"))
        {
            return refused("only a resting limit order (gtc or alo) can be hidden");
        }
        if order.display_size.neg && !order.display_size.is_zero() {
            return refused("display size must not be negative");
        }
        if order.is_iceberg() {
            if order.hidden {
                return refused("an order is hidden or an iceberg, not both");
            }
            if lt(&order.display_size, min) || le(&order.amount, &order.display_size) {
                return refused("an iceberg's display size must be below its amount");
            }
        }
        if order.owner.is_empty() {
            return refused("Order must have an owner address");
        }
        if order.id.is_empty() {
            return refused("Order must have an ID");
        }
        if self.state.orders.contains_key(&order.id) || self.state.stops.contains_key(&order.id) {
            return refused(format!("Duplicate order ID: {}", order.id));
        }
        if order.expired(self.state.now) {
            return refused("Order has already expired");
        }
        Ok(())
    }

    fn check_nonce(&mut self, order: &Order) -> R<()> {
        if order.nonce > 0 {
            let last = self.last_nonce;
            if order.nonce <= last {
                return refused(format!(
                    "Nonce replay: got {}, expected > {}",
                    order.nonce, last
                ));
            }
            self.new_nonce = Some(order.nonce);
        }
        Ok(())
    }

    /// A level changed (an order added, filled, cancelled, reduced, re-queued, or the level
    /// gone): its digest is redone at the next commitment (``_touch``).
    fn touch(&mut self, side: Side, price: &Dec) {
        let tag = if side == Side::Buy { b'b' } else { b'a' };
        self.state.dirty.insert((tag, PKey::of(price)));
    }

    fn check_rate_limit(&mut self, owner: &str) -> R<()> {
        let count = self.state.block_order_count.get(owner).copied().unwrap_or(0);
        if count >= MAX_ORDERS_PER_BLOCK_PER_ADDRESS {
            return refused(format!(
                "Rate limit: max {MAX_ORDERS_PER_BLOCK_PER_ADDRESS} orders per block"
            ));
        }
        self.state.block_order_count.insert(Id::from(owner), count + 1);
        Ok(())
    }

    fn decrement_owner_count(&mut self, owner: &str, stop: bool) {
        let counts = if stop {
            &mut self.state.owner_stop_count
        } else {
            &mut self.state.owner_order_count
        };
        let n = counts.get(owner).copied().unwrap_or(0);
        counts.insert(Id::from(owner), (n - 1).max(0));
    }

    fn place_stop(&mut self, order: &mut Order) -> R<Vec<Trade>> {
        if order.stop_price.is_none() {
            return refused("Stop-loss order requires stop_price");
        }
        let count = self.state.owner_stop_count.get(&order.owner).copied().unwrap_or(0);
        if count >= MAX_STOP_ORDERS_PER_ADDRESS {
            return refused(format!(
                "Max stop orders per address reached ({MAX_STOP_ORDERS_PER_ADDRESS})"
            ));
        }
        if !self.state.stops.contains_key(&order.id) {
            self.state.stop_ids.push_back(order.id.clone());
        }
        self.state.stops.insert(order.id.clone(), Arc::new(order.clone()));
        self.state.owner_stop_count.insert(order.owner.clone(), count + 1);
        Ok(Vec::new())
    }

    // ── matching ────────────────────────────────────────────────────────────────────────────

    fn match_market(&mut self, taker: &mut Order, budget: &mut Option<Budget>) -> R<Vec<Trade>> {
        let mut trades = Vec::new();
        let opposite = if taker.side == Side::Buy { Side::Sell } else { Side::Buy };
        let prices = self.level_prices(opposite == Side::Buy);
        for price in prices {
            if !positive(&taker.remaining()?) || taker.status == Status::Cancelled {
                break;
            }
            if budget.as_ref().is_some_and(|b| b.exhausted) {
                break;
            }
            trades.extend(self.match_at_level(taker, opposite, &price, budget)?);
            self.drop_level_if_empty(opposite, &price)?;
        }
        if taker.status == Status::Cancelled {
        } else if positive(&taker.remaining()?) {
            taker.status = if positive(&taker.filled) {
                Status::Filled
            } else {
                Status::Cancelled
            };
        } else {
            taker.status = Status::Filled;
        }
        self.check_stop_triggers()?;
        Ok(trades)
    }

    fn match_limit(&mut self, taker: &mut Order, budget: &mut Option<Budget>) -> R<Vec<Trade>> {
        let mut trades = Vec::new();
        let opposite = if taker.side == Side::Buy { Side::Sell } else { Side::Buy };
        let prices: Vec<Dec> = if taker.side == Side::Buy {
            self.state
                .asks
                .values()
                .take_while(|l| le(&l.price, &taker.price))
                .map(|l| l.price.clone())
                .collect()
        } else {
            self.state
                .bids
                .values()
                .rev()
                .take_while(|l| le(&taker.price, &l.price))
                .map(|l| l.price.clone())
                .collect()
        };
        for price in prices {
            if !positive(&taker.remaining()?) || taker.status == Status::Cancelled {
                break;
            }
            if budget.as_ref().is_some_and(|b| b.exhausted) {
                break;
            }
            trades.extend(self.match_at_level(taker, opposite, &price, budget)?);
            self.drop_level_if_empty(opposite, &price)?;
        }
        let exhausted = budget.as_ref().is_some_and(|b| b.exhausted);
        if taker.status == Status::Cancelled {
        } else if positive(&taker.remaining()?) && (exhausted || &*taker.tif == "ioc" || &*taker.tif == "fok")
        {
            taker.status = if positive(&taker.filled) {
                Status::Filled
            } else {
                Status::Cancelled
            };
        } else if positive(&taker.remaining()?) {
            taker.status = if taker.filled.is_zero() {
                Status::Open
            } else {
                Status::PartiallyFilled
            };
            self.add_to_book(taker)?;
        } else {
            taker.status = Status::Filled;
        }
        self.check_stop_triggers()?;
        Ok(trades)
    }

    fn drop_level_if_empty(&mut self, side: Side, price: &Dec) -> R<()> {
        let key = PKey::of(price);
        let empty = match self.side(side).get(&key) {
            Some(level) => self.level_total(level)?.is_zero(),
            None => false,
        };
        if empty {
            self.touch(side, price);
            self.side_mut(side).remove(&key);
        }
        Ok(())
    }

    fn remove_from_level(&mut self, side: Side, price: &Dec, id: &str) {
        self.touch(side, price);
        let key = PKey::of(price);
        if let Some(level) = self.side_mut(side).get_mut(&key) {
            if let Some(i) = level.orders.iter().position(|o| &**o == id) {
                level.orders.remove(i);
            }
        }
    }

    fn match_at_level(
        &mut self,
        taker: &mut Order,
        side: Side,
        price: &Dec,
        budget: &mut Option<Budget>,
    ) -> R<Vec<Trade>> {
        let mut trades = Vec::new();
        let mut spent: Vec<Id> = Vec::new();
        self.fill_from_level(taker, side, price, budget, &mut trades, &mut spent)?;
        // a spent iceberg shows its next slice at the back of the queue
        for id in spent {
            let Some(maker) = self.resting(&id) else {
                continue;
            };
            if maker.is_active() && positive(&maker.remaining()?) && !positive(&maker.shown) {
                let mut maker = maker;
                maker.shown = py_min(&maker.display_size, &maker.remaining()?);
                self.put_order(maker);
                let key = PKey::of(price);
                if let Some(level) = self.side_mut(side).get_mut(&key) {
                    if let Some(i) = level.orders.iter().position(|o| *o == id) {
                        level.orders.remove(i);
                    }
                    level.orders.push_back(id);
                }
            }
        }
        Ok(trades)
    }

    fn fill_from_level(
        &mut self,
        taker: &mut Order,
        side: Side,
        price: &Dec,
        budget: &mut Option<Budget>,
        trades: &mut Vec<Trade>,
        spent: &mut Vec<Id>,
    ) -> R<()> {
        let key = PKey::of(price);
        for shown_tier in [true, false] {
            let queue: Vec<Id> = match self.side(side).get(&key) {
                Some(level) => level.orders.iter().cloned().collect(),
                None => Vec::new(),
            };
            for maker_id in queue {
                if !positive(&taker.remaining()?) || taker.status == Status::Cancelled {
                    break;
                }
                let Some(mut maker) = self.resting(&maker_id) else {
                    continue; // (left the book this pass)
                };
                if !maker.is_active() {
                    continue;
                }
                let available = if shown_tier {
                    maker.visible()?
                } else {
                    maker.reserve()?
                };
                if !positive(&available) {
                    continue;
                }
                if let Some(b) = budget.as_mut() {
                    if !b.take() {
                        break;
                    }
                }
                if maker.owner == taker.owner {
                    match self.config.stp {
                        Stp::Reject => continue,
                        Stp::CancelMaker | Stp::CancelBoth => {
                            maker.status = Status::Cancelled;
                            self.remove_from_level(side, price, &maker.id);
                            self.drop_order(&maker);
                            self.decrement_owner_count(&maker.owner, false);
                            if self.config.stp == Stp::CancelBoth {
                                taker.status = Status::Cancelled;
                                return Ok(());
                            }
                            continue;
                        }
                        Stp::CancelTaker => {
                            taker.status = Status::Cancelled;
                            return Ok(());
                        }
                    }
                }
                let fill = py_min(&taker.remaining()?, &available);
                let notional = mul(&fill, price)?;
                let fee = |rate: &Dec| -> R<Dec> {
                    mul(&notional, rate)?
                        .quantize(-8, Rounding::HalfUp, &EXCHANGE)
                        .ok_or(Fail::Native)
                };
                let maker_fee = fee(&self.config.maker_fee_rate)?;
                let taker_fee = fee(&self.config.taker_fee_rate)?;
                let (buyer, seller) = if taker.side == Side::Buy {
                    (taker.owner.clone(), maker.owner.clone())
                } else {
                    (maker.owner.clone(), taker.owner.clone())
                };
                self.state.trade_sequence += 1;
                let seq = self.state.trade_sequence;
                let id_bytes = blake2b(format!("{}:{}:{}", maker.id, taker.id, seq).as_bytes(), 8);
                let trade = Trade {
                    id: hex(&id_bytes),
                    maker_order_id: maker.id.clone(),
                    taker_order_id: taker.id.clone(),
                    price: price.clone(),
                    amount: fill.clone(),
                    maker_fee,
                    taker_fee,
                    buyer,
                    seller,
                    sequence: seq,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0.0, |d| d.as_secs_f64()),
                };
                self.state.recent.push_back(trade.clone());
                while self.state.recent.len() > MAX_RECENT_TRADES {
                    self.state.recent.pop_front();
                }
                trades.push(trade);
                self.state.last_price = Some(price.clone());
                self.state.total_volume = add(&self.state.total_volume, &notional)?;
                self.state.total_trades += 1;

                maker.filled = add(&maker.filled, &fill)?;
                taker.filled = add(&taker.filled, &fill)?;
                if maker.is_iceberg() && shown_tier {
                    maker.shown = py_max(&zero(), &sub(&maker.shown, &fill)?);
                }
                if !positive(&maker.remaining()?) {
                    maker.status = Status::Filled;
                    self.remove_from_level(side, price, &maker.id);
                    self.drop_order(&maker);
                    self.decrement_owner_count(&maker.owner, false);
                } else {
                    maker.status = Status::PartiallyFilled;
                    if maker.is_iceberg() && !positive(&maker.shown) && !spent.contains(&maker.id) {
                        spent.push(maker.id.clone());
                    }
                    self.put_order(maker);
                }
            }
            if !positive(&taker.remaining()?) || taker.status == Status::Cancelled {
                return Ok(());
            }
            if budget.as_ref().is_some_and(|b| b.exhausted) {
                return Ok(());
            }
        }
        Ok(())
    }

    fn check_stop_triggers(&mut self) -> R<()> {
        let Some(last) = self.state.last_price.clone() else {
            return Ok(());
        };
        let mut triggered = Vec::new();
        for id in self.state.stop_ids.iter() {
            let Some(order) = self.state.stops.get(id) else {
                continue;
            };
            let Some(stop) = &order.stop_price else {
                continue;
            };
            let fire = match order.side {
                Side::Buy => le(stop, &last),
                Side::Sell => le(&last, stop),
            };
            if fire {
                triggered.push(id.clone());
            }
        }
        for id in triggered {
            let Some(order) = self.state.stops.get(&*id).map(|o| (**o).clone()) else {
                continue; // (already triggered by an inner check)
            };
            self.state.stops.remove(&id);
            if let Some(i) = self.state.stop_ids.iter().position(|o| *o == id) {
                self.state.stop_ids.remove(i);
            }
            self.decrement_owner_count(&order.owner, true);
            let mut order = order;
            order.kind = Kind::Market;
            order.status = Status::Triggered;
            self.match_market(&mut order, &mut None)?;
            self.last.insert(order.id.clone(), order);
        }
        Ok(())
    }

    fn add_to_book(&mut self, order: &mut Order) -> R<()> {
        let key = PKey::of(&order.price);
        let exists = self.side(order.side).contains_key(&key);
        if !exists && self.side(order.side).len() >= self.config.max_depth {
            return refused(format!(
                "Order book depth limit reached ({} levels)",
                self.config.max_depth
            ));
        }
        let count = self.state.owner_order_count.get(&order.owner).copied().unwrap_or(0);
        if count >= self.config.max_orders_per_address {
            return refused(format!(
                "Max orders per address reached ({})",
                self.config.max_orders_per_address
            ));
        }
        if order.expire_time != 0.0 {
            self.state.has_expiring = true;
        }
        if order.is_iceberg() {
            order.shown = py_min(&order.display_size, &order.remaining()?);
        }
        let price = order.price.clone();
        let id = order.id.clone();
        let levels = self.side_mut(order.side);
        let level = levels.entry(key).or_insert_with(|| Level {
            price,
            orders: Vector::new(),
        });
        level.orders.push_back(id);
        self.put_order(order.clone());
        self.state.owner_order_count.insert(order.owner.clone(), count + 1);
        Ok(())
    }

    // ── other operations ────────────────────────────────────────────────────────────────────

    /// ``cancel_order``: the cancelled order, or None if there is none to cancel.
    /// A fee settlement charged on a trade (``maker``: the maker's, else the taker's), into the
    /// display history — the newest trade with that id. Whether there was one.
    pub(crate) fn set_trade_fee(&mut self, id: &str, maker: bool, fee: Dec) -> bool {
        let recent = &mut self.state.recent;
        let Some(i) = (0..recent.len()).rev().find(|&i| recent[i].id == id) else {
            return false;
        };
        let mut t = recent[i].clone();
        if maker {
            t.maker_fee = fee;
        } else {
            t.taker_fee = fee;
        }
        recent.set(i, t);
        true
    }

    pub fn cancel_order(&mut self, id: &str, caller: &str) -> R<Option<Order>> {
        if let Some(order) = self.state.stops.get(id).map(|o| (**o).clone()) {
            if !caller.is_empty() && &*order.owner != caller {
                return refused("Only order owner can cancel");
            }
            self.state.stops.remove(id);
            if let Some(i) = self.state.stop_ids.iter().position(|o| &**o == id) {
                self.state.stop_ids.remove(i);
            }
            let mut order = order;
            order.status = Status::Cancelled;
            self.decrement_owner_count(&order.owner, true);
            return Ok(Some(order));
        }
        let Some(order) = self.resting(id) else {
            return Ok(None);
        };
        if !caller.is_empty() && &*order.owner != caller {
            return refused("Only order owner can cancel");
        }
        if !order.is_active() {
            return Ok(None);
        }
        let mut order = order;
        order.status = Status::Cancelled;
        self.remove_from_level(order.side, &order.price, id);
        self.drop_level_if_empty(order.side, &order.price)?;
        self.drop_order(&order);
        self.decrement_owner_count(&order.owner, false);
        Ok(Some(order))
    }

    /// ``reduce_order``.
    pub fn reduce_order(&mut self, id: &str, amount: Dec, caller: &str) -> R<Order> {
        let order = match self.resting(id) {
            Some(o) if o.is_active() => o,
            _ => return refused(format!("no resting order {id}")),
        };
        if &*order.owner != caller {
            return refused("Only order owner can modify");
        }
        if !(lt(&order.filled, &amount) && lt(&amount, &order.amount)) {
            return refused("a reduced order must be smaller, and above what has filled");
        }
        if order.is_iceberg() && le(&amount, &order.display_size) {
            return refused("an iceberg's display size must be below its amount");
        }
        let mut order = order;
        order.amount = amount;
        if order.is_iceberg() {
            order.shown = py_min(&order.shown, &order.remaining()?);
        }
        self.put_order(order.clone());
        Ok(order)
    }

    /// ``fill_resting``: ``amount`` more of a resting order filled away from the book.
    pub fn fill_resting(&mut self, id: &str, amount: Dec) -> R<Order> {
        let order = match self.resting(id) {
            Some(o) if o.is_active() => o,
            _ => return refused(format!("no resting order {id}")),
        };
        if !(positive(&amount) && le(&amount, &order.remaining()?)) {
            return refused("a fill must be positive and at most what the order has left");
        }
        let mut order = order;
        order.filled = add(&order.filled, &amount)?;
        if positive(&order.remaining()?) {
            order.status = Status::PartiallyFilled;
            if order.is_iceberg() {
                order.shown = py_min(&order.shown, &order.remaining()?);
            }
            self.put_order(order.clone());
            return Ok(order);
        }
        order.status = Status::Filled;
        self.remove_from_level(order.side, &order.price, id);
        self.drop_level_if_empty(order.side, &order.price)?;
        self.drop_order(&order);
        self.decrement_owner_count(&order.owner, false);
        Ok(order)
    }

    /// ``new_block``: the per-block rate limits reset, expired orders cancelled.
    pub fn new_block(&mut self, now: Option<f64>) -> R<()> {
        self.state.block_order_count = IMap::new();
        if let Some(n) = now {
            self.state.now = Some(n);
        }
        if !self.state.has_expiring {
            return Ok(());
        }
        let mut ids: Vec<(u64, Id)> = self
            .state
            .order_seq
            .iter()
            .map(|(id, seq)| (*seq, id.clone()))
            .collect();
        ids.sort();
        for (_, id) in ids {
            let expired = self
                .state
                .orders
                .get(&*id)
                .is_some_and(|o| o.expired(self.state.now) && o.is_active());
            if expired {
                self.cancel_order(&id, "")?;
            }
        }
        Ok(())
    }

    // ── the digest (``state_digest``) ───────────────────────────────────────────────────────

    fn level_payload(&self, tag: char, level: &Level) -> Vec<u8> {
        let mut out = format!("{}{}", tag, level.price.canonical_text());
        for id in level.orders.iter() {
            let Some(o) = self.state.orders.get(id) else {
                continue;
            };
            out.push('|');
            out.push_str(&format!(
                "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
                o.id,
                o.owner,
                o.side.value(),
                o.kind.value(),
                o.price.to_python_string(),
                o.amount.to_python_string(),
                o.filled.to_python_string(),
                o.status.value(),
                o.nonce,
                py_float_repr(o.expire_time)
            ));
            if o.hidden {
                out.push_str(":hidden");
            } else if o.is_iceberg() {
                out.push_str(&format!(
                    ":iceberg:{}:{}",
                    o.display_size.to_python_string(),
                    o.shown.to_python_string()
                ));
            }
        }
        out.into_bytes()
    }

    fn header(&self) -> Vec<String> {
        let s = &self.state;
        let mut parts = vec![
            self.config.pool_id.clone(),
            s.trade_sequence.to_string(),
            s.total_trades.to_string(),
            s.total_volume.to_python_string(),
            s.last_price
                .as_ref()
                .map_or("None".to_string(), |p| p.to_python_string()),
        ];
        let mut ids: Vec<&Id> = s.stops.keys().collect();
        ids.sort();
        for id in ids {
            let o = &s.stops[&**id];
            parts.push(format!(
                "s{}:{}:{}:{}:{}:{}:{}:{}:{}",
                o.id,
                o.owner,
                o.side.value(),
                o.stop_price
                    .as_ref()
                    .map_or("None".to_string(), |p| p.to_python_string()),
                o.amount.to_python_string(),
                o.filled.to_python_string(),
                o.status.value(),
                o.nonce,
                py_float_repr(o.expire_time)
            ));
        }
        parts
    }

    /// The owners' nonces' commitment (``CommittedDict.full_commitment`` of ``book.nonces``).
    fn nonces_commitment(nonces: &[(String, i64)]) -> R<Vec<u8>> {
        let mut digests = Vec::new();
        for (owner, nonce) in nonces {
            let mut raw = Vec::new();
            raw.push(b'[');
            crate::canon::write_str(&mut raw, owner);
            raw.push(b',');
            crate::canon::write_str(&mut raw, &nonce.to_string());
            raw.push(b']');
            digests.push(blake2b_personal(&raw, b"qrdx-exch-v1"));
        }
        crate::lthash::accumulate(b"qrdx/exchange/book.nonces", digests.iter().map(|d| d.as_slice()))
            .ok_or(Fail::Native)
    }

    fn compose(&self, levels: &[u8], nonces: &[u8]) -> Vec<u8> {
        let mut all = self.header().join("|").into_bytes();
        all.extend_from_slice(levels);
        all.extend_from_slice(nonces);
        blake2b(&all, 32)
    }

    /// ``state_digest()`` from scratch, given the owners' nonces.
    pub fn state_digest(&self, nonces: &[(String, i64)]) -> R<Vec<u8>> {
        let mut level_digests = Vec::new();
        for (tag, levels) in [('b', &self.state.bids), ('a', &self.state.asks)] {
            for level in levels.values() {
                level_digests.push(blake2b(&self.level_payload(tag, level), 32));
            }
        }
        let levels = crate::lthash::accumulate(
            b"qrdx/exchange/book.level",
            level_digests.iter().map(|d| d.as_slice()),
        )
        .ok_or(Fail::Native)?;
        Ok(self.compose(&levels, &Self::nonces_commitment(nonces)?))
    }

    fn level_key(tag: u8, price: &Dec) -> [u8; 32] {
        let mut identity = vec![0x21u8, tag];
        identity.extend_from_slice(price.canonical_text().as_bytes());
        crate::smt::key_of(&identity)
    }

    /// ``cached_digest``'s levels part, brought up to date: the levels' LtHash, redoing only
    /// the levels touched since the last call, and their proof tree from the same changes
    /// (``trees``: the network keeps proof trees; rebuilt whole when the digests were).
    pub fn commitment(&mut self, trees: bool) -> R<Vec<u8>> {
        let full = self.state.level_digests.is_none();
        let mut digests = self.state.level_digests.take().unwrap_or_default();
        let dirty: Vec<(u8, PKey)> = if full {
            let mut all: Vec<(u8, PKey)> = Vec::new();
            all.extend(self.state.bids.keys().map(|k| (b'b', k.clone())));
            all.extend(self.state.asks.keys().map(|k| (b'a', k.clone())));
            all
        } else {
            self.state.dirty.iter().cloned().collect()
        };
        let acc = if full {
            vec![0u8; crate::lthash::SIZE]
        } else {
            self.state.level_acc.as_ref().clone()
        };
        let mut removed = Vec::new();
        let mut added = Vec::new();
        let mut tree_changes: Vec<crate::mtree::Change> = Vec::new();
        for (tag, key) in dirty {
            let old = digests.remove(&(tag, key.clone()));
            let side = if tag == b'b' { &self.state.bids } else { &self.state.asks };
            let payload = side
                .get(&key)
                .map(|level| self.level_payload(tag as char, level));
            let new = payload.as_ref().map(|p| {
                let d = blake2b(p, 32);
                let mut out = [0u8; 32];
                out.copy_from_slice(&d);
                out
            });
            if let Some(d) = new {
                digests.insert((tag, key.clone()), d);
            }
            if old != new {
                if let Some(d) = old {
                    removed.push(d.to_vec());
                }
                if let Some(d) = new {
                    added.push(d.to_vec());
                }
                if trees {
                    tree_changes.push((Self::level_key(tag, &key.0).to_vec(), payload));
                }
            }
        }
        let acc = crate::lthash::mix(&acc, b"qrdx/exchange/book.level", &removed, &added)
            .ok_or(Fail::Native)?;
        self.state.level_acc = Arc::new(acc.clone());
        self.state.level_digests = Some(digests);
        self.state.dirty = im::OrdSet::new();
        if !trees {
            self.state.level_tree = None;
            self.state.tree_on = false;
        } else if full || !self.state.tree_on {
            let mut all: Vec<crate::mtree::Change> = Vec::new();
            for (tag, levels) in [(b'b', &self.state.bids), (b'a', &self.state.asks)] {
                for level in levels.values() {
                    all.push((
                        Self::level_key(tag, &level.price).to_vec(),
                        Some(self.level_payload(tag as char, level)),
                    ));
                }
            }
            all.sort_by(|a, b| a.0.cmp(&b.0));
            self.state.level_tree = crate::mtree::update(&None, &all, 0);
            self.state.tree_on = true;
        } else if !tree_changes.is_empty() {
            tree_changes.sort_by(|a, b| a.0.cmp(&b.0));
            self.state.level_tree = crate::mtree::update(&self.state.level_tree, &tree_changes, 0);
        }
        Ok(acc)
    }

    /// ``cached_digest()``: the commitment, composed with the nonces' accumulator.
    pub fn cached_digest(&mut self, trees: bool, nonces_acc: &[u8]) -> R<Vec<u8>> {
        let levels = self.commitment(trees)?;
        Ok(self.compose(&levels, nonces_acc))
    }
}

// ── Python ────────────────────────────────────────────────────────────────────────────────

fn dec_of(text: &str) -> PyResult<Dec> {
    Dec::parse(text).ok_or_else(|| PyValueError::new_err(format!("not a decimal: {text}")))
}

fn order_of(d: &Bound<'_, PyDict>) -> PyResult<Order> {
    let get = |k: &str| -> PyResult<Bound<'_, PyAny>> {
        d.get_item(k)?
            .ok_or_else(|| PyTypeError::new_err(format!("an order needs {k}")))
    };
    let text = |k: &str, default: &str| -> PyResult<String> {
        match d.get_item(k)? {
            Some(v) if !v.is_none() => v.extract::<String>(),
            _ => Ok(default.to_string()),
        }
    };
    let side = Side::parse(&get("side")?.extract::<String>()?)
        .ok_or_else(|| PyValueError::new_err("side"))?;
    let kind = Kind::parse(&get("order_type")?.extract::<String>()?)
        .ok_or_else(|| PyValueError::new_err("order_type"))?;
    let status = Status::parse(&text("status", "open")?)
        .ok_or_else(|| PyValueError::new_err("status"))?;
    let stop_price = match d.get_item("stop_price")? {
        Some(v) if !v.is_none() => Some(dec_of(&v.extract::<String>()?)?),
        _ => None,
    };
    let float = |k: &str| -> PyResult<f64> {
        match d.get_item(k)? {
            Some(v) if !v.is_none() => v.extract::<f64>(),
            _ => Ok(0.0),
        }
    };
    Ok(Order {
        id: Id::from(get("id")?.extract::<String>()?),
        owner: Id::from(get("owner")?.extract::<String>()?),
        side,
        kind,
        price: dec_of(&text("price", "0")?)?,
        amount: dec_of(&get("amount")?.extract::<String>()?)?,
        filled: dec_of(&text("filled", "0")?)?,
        status,
        timestamp: float("timestamp")?,
        stop_price,
        nonce: match d.get_item("nonce")? {
            Some(v) if !v.is_none() => v.extract()?,
            _ => 0,
        },
        expire_time: float("expire_time")?,
        tif: Id::from(text("tif", "gtc")?),
        hidden: match d.get_item("hidden")? {
            Some(v) => v.is_truthy()?,
            None => false,
        },
        display_size: dec_of(&text("display_size", "0")?)?,
        shown: dec_of(&text("shown", "0")?)?,
    })
}

pub(crate) fn order_dict<'py>(py: Python<'py>, o: &Order) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new_bound(py);
    d.set_item("id", &*o.id)?;
    d.set_item("owner", &*o.owner)?;
    d.set_item("side", o.side.value())?;
    d.set_item("order_type", o.kind.value())?;
    d.set_item("price", o.price.to_python_string())?;
    d.set_item("amount", o.amount.to_python_string())?;
    d.set_item("filled", o.filled.to_python_string())?;
    d.set_item("status", o.status.value())?;
    d.set_item("timestamp", o.timestamp)?;
    d.set_item("stop_price", o.stop_price.as_ref().map(|p| p.to_python_string()))?;
    d.set_item("nonce", o.nonce)?;
    d.set_item("expire_time", o.expire_time)?;
    d.set_item("tif", &*o.tif)?;
    d.set_item("hidden", o.hidden)?;
    d.set_item("display_size", o.display_size.to_python_string())?;
    d.set_item("shown", o.shown.to_python_string())?;
    Ok(d)
}

fn trade_dict<'py>(py: Python<'py>, t: &Trade) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new_bound(py);
    d.set_item("id", &t.id)?;
    d.set_item("maker_order_id", &*t.maker_order_id)?;
    d.set_item("taker_order_id", &*t.taker_order_id)?;
    d.set_item("price", t.price.to_python_string())?;
    d.set_item("amount", t.amount.to_python_string())?;
    d.set_item("maker_fee", t.maker_fee.to_python_string())?;
    d.set_item("taker_fee", t.taker_fee.to_python_string())?;
    d.set_item("buyer", &*t.buyer)?;
    d.set_item("seller", &*t.seller)?;
    d.set_item("sequence", t.sequence)?;
    d.set_item("timestamp", t.timestamp)?;
    Ok(d)
}

fn fail(e: Fail) -> PyErr {
    match e {
        Fail::Refused(m) => PyValueError::new_err(m),
        Fail::Native => crate::Unsupported::new_err("a value the native book does not compute with"),
    }
}

/// The native book, as Python holds it (``qrdx/exchange/native_book.py`` puts the Python
/// book's interface over it): orders and trades as dicts, decimals as Python's ``str`` of them.
/// Every call that changes orders reports each order it changed, as it ended, so the ``Order``
/// objects Python handed out stay what the book holds.
#[pyclass(module = "qrdx_native._native")]
pub struct NativeBook {
    pub(crate) book: Book,
}

fn changed_list<'py>(py: Python<'py>, book: &mut Book) -> PyResult<Bound<'py, PyList>> {
    let out = PyList::empty_bound(py);
    for (_, o) in book.last.drain() {
        out.append(order_dict(py, &o)?)?;
    }
    Ok(out)
}

impl NativeBook {
    /// Run ``f``; on a failure the book is as it was (its savepoint restored).
    fn atomic<T>(&mut self, f: impl FnOnce(&mut Book) -> R<T>) -> PyResult<T> {
        let saved = self.book.state.clone();
        self.book.last.clear();
        match f(&mut self.book) {
            Ok(v) => Ok(v),
            Err(e) => {
                self.book.state = saved;
                self.book.last.clear();
                Err(fail(e))
            }
        }
    }
}

type Placed<'py> = (
    Bound<'py, PyList>,
    Bound<'py, PyDict>,
    Option<(i64, bool)>,
    Bound<'py, PyList>,
    Option<i64>,
);

#[pymethods]
impl NativeBook {
    #[new]
    #[pyo3(signature = (pool_id, max_depth, maker_fee_rate, taker_fee_rate, self_trade_action, min_order_size, max_orders_per_address))]
    fn new(
        pool_id: String,
        max_depth: usize,
        maker_fee_rate: &str,
        taker_fee_rate: &str,
        self_trade_action: &str,
        min_order_size: &str,
        max_orders_per_address: i64,
    ) -> PyResult<Self> {
        Ok(NativeBook {
            book: Book::new(Config {
                pool_id,
                max_depth,
                maker_fee_rate: dec_of(maker_fee_rate)?,
                taker_fee_rate: dec_of(taker_fee_rate)?,
                stp: Stp::parse(self_trade_action)
                    .ok_or_else(|| PyValueError::new_err("self_trade_action"))?,
                min_order_size: dec_of(min_order_size)?,
                max_orders_per_address,
            }),
        })
    }

    /// A copy (a pointer copy: the state is shared until either changes).
    fn copy(&self) -> Self {
        NativeBook {
            book: Book::with_state(self.book.config.clone(), self.book.state.clone()),
        }
    }

    /// ``place_order``: (trades, the order as it ended, (makers visited, budget exhausted) or
    /// None, every order it changed, the owner's new book nonce or None). ``last_nonce``: the
    /// owner's last book nonce (Python keeps them).
    #[pyo3(signature = (order, protocol=false, budget=None, last_nonce=0))]
    fn place_order<'py>(
        &mut self,
        py: Python<'py>,
        order: &Bound<'py, PyDict>,
        protocol: bool,
        budget: Option<i64>,
        last_nonce: i64,
    ) -> PyResult<Placed<'py>> {
        let order = order_of(order)?;
        let mut budget = budget.map(|makers| Budget {
            left: makers.max(0),
            visited: 0,
            exhausted: false,
        });
        self.book.last_nonce = last_nonce;
        let result = self.book.place_order(order, protocol, &mut budget);
        let used = budget.map(|b| (b.visited, b.exhausted));
        let (trades, order) = match result {
            Ok(v) => v,
            Err((Fail::Refused(m), at)) => {
                // (the makers it visited before failing are paid for, and the order is as it
                // stood: both carried on the error)
                let e = PyValueError::new_err(m);
                e.value_bound(py).setattr("makers_visited", used.map_or(0, |u| u.0))?;
                e.value_bound(py).setattr("order_state", order_dict(py, &at)?)?;
                self.book.last.clear();
                return Err(e);
            }
            Err((e, _)) => {
                self.book.last.clear();
                return Err(fail(e));
            }
        };
        let list = PyList::empty_bound(py);
        for t in &trades {
            list.append(trade_dict(py, t)?)?;
        }
        let ended = order_dict(py, &order)?;
        let changed = changed_list(py, &mut self.book)?;
        Ok((list, ended, used, changed, self.book.new_nonce))
    }

    #[pyo3(signature = (order_id, caller=""))]
    fn cancel_order<'py>(
        &mut self,
        py: Python<'py>,
        order_id: &str,
        caller: &str,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let o = self.atomic(|b| b.cancel_order(order_id, caller))?;
        self.book.last.clear();
        o.map(|o| order_dict(py, &o)).transpose()
    }

    fn reduce_order<'py>(
        &mut self,
        py: Python<'py>,
        order_id: &str,
        amount: &str,
        caller: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
        let amount = dec_of(amount)?;
        let o = self.atomic(|b| b.reduce_order(order_id, amount, caller))?;
        self.book.last.clear();
        order_dict(py, &o)
    }

    fn fill_resting<'py>(
        &mut self,
        py: Python<'py>,
        order_id: &str,
        amount: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
        let amount = dec_of(amount)?;
        let o = self.atomic(|b| b.fill_resting(order_id, amount))?;
        self.book.last.clear();
        order_dict(py, &o)
    }

    fn record_price(&mut self, price: &str) -> PyResult<()> {
        self.book.state.last_price = Some(dec_of(price)?);
        Ok(())
    }

    /// A fee settlement charged on a trade (``maker``: the maker's, else the taker's), into the
    /// display history — the newest trade with that id. Whether there was one.
    fn set_trade_fee(&mut self, id: &str, maker: bool, fee: &str) -> PyResult<bool> {
        Ok(self.book.set_trade_fee(id, maker, dec_of(fee)?))
    }

    /// ``new_block``: every order it changed (expired orders, cancelled).
    #[pyo3(signature = (now=None))]
    fn new_block<'py>(&mut self, py: Python<'py>, now: Option<f64>) -> PyResult<Bound<'py, PyList>> {
        self.atomic(|b| b.new_block(now))?;
        changed_list(py, &mut self.book)
    }

    /// ``enter_block``: every order it changed.
    fn enter_block<'py>(&mut self, py: Python<'py>, height: i64, now: f64) -> PyResult<Bound<'py, PyList>> {
        if self.book.state.block_height == Some(height) {
            return Ok(PyList::empty_bound(py));
        }
        let changed = self.new_block(py, Some(now))?;
        self.book.state.block_height = Some(height);
        Ok(changed)
    }

    fn pause(&mut self) {
        self.book.state.paused = true;
    }

    fn unpause(&mut self) {
        self.book.state.paused = false;
    }

    #[getter]
    fn is_paused(&self) -> bool {
        self.book.state.paused
    }

    #[getter]
    fn has_expiring(&self) -> bool {
        self.book.state.has_expiring
    }

    #[getter]
    fn now(&self) -> Option<f64> {
        self.book.state.now
    }

    #[getter]
    fn block_height(&self) -> Option<i64> {
        self.book.state.block_height
    }

    fn best(&self, bids: bool) -> PyResult<Option<String>> {
        Ok(self.book.best(bids).map_err(fail)?.map(|p| p.to_python_string()))
    }

    fn level_prices(&self, bids: bool) -> Vec<String> {
        self.book
            .level_prices(bids)
            .iter()
            .map(|p| p.to_python_string())
            .collect()
    }

    /// (price, what it shows) of each level that shows something, best first (``iter_levels``).
    fn iter_levels(&self, bids: bool) -> PyResult<Vec<(String, String)>> {
        let side = if bids { Side::Buy } else { Side::Sell };
        let levels: Vec<&Level> = if bids {
            self.book.side(side).values().rev().collect()
        } else {
            self.book.side(side).values().collect()
        };
        let mut out = Vec::new();
        for level in levels {
            let shown = self.book.level_visible(level).map_err(fail)?;
            if positive(&shown) {
                out.push((level.price.to_python_string(), shown.to_python_string()));
            }
        }
        Ok(out)
    }

    /// The resting orders at a level, in time priority (None: no such level).
    fn level_orders<'py>(
        &self,
        py: Python<'py>,
        bids: bool,
        price: &str,
    ) -> PyResult<Option<Bound<'py, PyList>>> {
        let side = if bids { Side::Buy } else { Side::Sell };
        let Some(level) = self.book.side(side).get(&PKey::of(&dec_of(price)?)) else {
            return Ok(None);
        };
        let out = PyList::empty_bound(py);
        for id in level.orders.iter() {
            if let Some(o) = self.book.state.orders.get(id) {
                out.append(order_dict(py, o)?)?;
            }
        }
        Ok(Some(out))
    }

    /// The price a level is keyed by (its first order's spelling), or None.
    fn level_price(&self, bids: bool, price: &str) -> PyResult<Option<String>> {
        let side = if bids { Side::Buy } else { Side::Sell };
        Ok(self
            .book
            .side(side)
            .get(&PKey::of(&dec_of(price)?))
            .map(|l| l.price.to_python_string()))
    }

    fn level_count(&self, bids: bool) -> usize {
        self.book.side(if bids { Side::Buy } else { Side::Sell }).len()
    }

    fn get_order<'py>(&self, py: Python<'py>, order_id: &str) -> PyResult<Option<Bound<'py, PyDict>>> {
        let s = &self.book.state;
        match s.orders.get(order_id).or_else(|| s.stops.get(order_id)) {
            Some(o) => Ok(Some(order_dict(py, o)?)),
            None => Ok(None),
        }
    }

    fn resting_order<'py>(&self, py: Python<'py>, order_id: &str) -> PyResult<Option<Bound<'py, PyDict>>> {
        match self.book.state.orders.get(order_id) {
            Some(o) => Ok(Some(order_dict(py, o)?)),
            None => Ok(None),
        }
    }

    fn stop_order<'py>(&self, py: Python<'py>, order_id: &str) -> PyResult<Option<Bound<'py, PyDict>>> {
        match self.book.state.stops.get(order_id) {
            Some(o) => Ok(Some(order_dict(py, o)?)),
            None => Ok(None),
        }
    }

    /// The resting orders' ids, in the order they were indexed.
    fn order_ids(&self) -> Vec<String> {
        let mut ids: Vec<(u64, &Id)> = self
            .book
            .state
            .order_seq
            .iter()
            .map(|(id, seq)| (*seq, id))
            .collect();
        ids.sort();
        ids.into_iter().map(|(_, id)| id.to_string()).collect()
    }

    fn order_count(&self) -> usize {
        self.book.state.orders.len()
    }

    fn has_order(&self, order_id: &str) -> bool {
        self.book.state.orders.contains_key(order_id)
    }

    /// The parked stop orders' ids, in the order they were placed.
    fn stop_ids(&self) -> Vec<String> {
        self.book.state.stop_ids.iter().map(|id| id.to_string()).collect()
    }

    fn owner_count(&self, owner: &str) -> i64 {
        self.book.state.owner_order_count.get(owner).copied().unwrap_or(0)
    }

    fn owner_counts(&self) -> Vec<(String, i64)> {
        self.book
            .state
            .owner_order_count
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect()
    }

    /// (trade sequence, total trades, total volume, last price or None)
    fn totals(&self) -> (u64, u64, String, Option<String>) {
        let s = &self.book.state;
        (
            s.trade_sequence,
            s.total_trades,
            s.total_volume.to_python_string(),
            s.last_price.as_ref().map(|p| p.to_python_string()),
        )
    }

    /// The display history's last ``count`` trades (never consensus).
    fn recent_trades<'py>(&self, py: Python<'py>, count: usize) -> PyResult<Bound<'py, PyList>> {
        let out = PyList::empty_bound(py);
        let n = self.book.state.recent.len();
        for t in self.book.state.recent.iter().skip(n.saturating_sub(count)) {
            out.append(trade_dict(py, t)?)?;
        }
        Ok(out)
    }

    fn header(&self) -> Vec<String> {
        self.book.header()
    }

    /// The levels' LtHash, brought up to date (``trees``: their proof tree too).
    fn commitment<'py>(&mut self, py: Python<'py>, trees: bool) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(py, &self.book.commitment(trees).map_err(fail)?))
    }

    /// The levels' proof tree as of the last ``commitment`` (None: empty, or trees off).
    #[getter]
    fn level_tree(&self) -> Option<crate::mtree::MNode> {
        self.book.state.level_tree.clone().map(crate::mtree::MNode)
    }

    /// Every level's (proof-tree key, payload): what ``verify_digest`` rebuilds the tree from.
    fn level_entries<'py>(&self, py: Python<'py>) -> Vec<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        let mut out = Vec::new();
        for (tag, side) in [(b'b', &self.book.state.bids), (b'a', &self.book.state.asks)] {
            for level in side.values() {
                out.push((
                    PyBytes::new_bound(py, &Book::level_key(tag, &level.price)),
                    PyBytes::new_bound(py, &self.book.level_payload(tag as char, level)),
                ));
            }
        }
        out
    }

    /// ``cached_digest()``, given the nonces' accumulator.
    fn cached_digest<'py>(
        &mut self,
        py: Python<'py>,
        trees: bool,
        nonces_acc: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(
            py,
            &self.book.cached_digest(trees, nonces_acc).map_err(fail)?,
        ))
    }

    /// ``state_digest()`` from scratch, given the owners' nonces: [(owner, nonce)].
    fn state_digest<'py>(
        &self,
        py: Python<'py>,
        nonces: Vec<(String, i64)>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new_bound(py, &self.book.state_digest(&nonces).map_err(fail)?))
    }

    /// Everything the book holds, as data (a pickle of it): the levels' orders in time
    /// priority, the order index's order, the stop orders, the counts, the book's own fields,
    /// the display history.
    fn export<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let s = &self.book.state;
        let d = PyDict::new_bound(py);
        let levels = PyList::empty_bound(py);
        for (tag, side) in [("b", &s.bids), ("a", &s.asks)] {
            for level in side.values() {
                let orders = PyList::empty_bound(py);
                for id in level.orders.iter() {
                    if let Some(o) = s.orders.get(id) {
                        orders.append(order_dict(py, o)?)?;
                    }
                }
                levels.append((tag, level.price.to_python_string(), orders))?;
            }
        }
        d.set_item("levels", levels)?;
        d.set_item("order_ids", self.order_ids())?;
        let stops = PyList::empty_bound(py);
        for id in s.stop_ids.iter() {
            if let Some(o) = s.stops.get(id) {
                stops.append(order_dict(py, o)?)?;
            }
        }
        d.set_item("stops", stops)?;
        let counts = |m: &IMap<Id, i64>| -> Vec<(String, i64)> {
            m.iter().map(|(k, v)| (k.to_string(), *v)).collect()
        };
        d.set_item("owner_order_count", counts(&s.owner_order_count))?;
        d.set_item("owner_stop_count", counts(&s.owner_stop_count))?;
        d.set_item("block_order_count", counts(&s.block_order_count))?;
        d.set_item("trade_sequence", s.trade_sequence)?;
        d.set_item("last_price", s.last_price.as_ref().map(|p| p.to_python_string()))?;
        d.set_item("total_volume", s.total_volume.to_python_string())?;
        d.set_item("total_trades", s.total_trades)?;
        d.set_item("paused", s.paused)?;
        d.set_item("now", s.now)?;
        d.set_item("has_expiring", s.has_expiring)?;
        d.set_item("block_height", s.block_height)?;
        let recent = PyList::empty_bound(py);
        for t in s.recent.iter() {
            recent.append(trade_dict(py, t)?)?;
        }
        d.set_item("recent", recent)?;
        Ok(d)
    }

    /// A book from ``export``'s data (its commitment is recomputed in full).
    #[staticmethod]
    #[allow(clippy::too_many_arguments)]
    fn from_export(
        pool_id: String,
        max_depth: usize,
        maker_fee_rate: &str,
        taker_fee_rate: &str,
        self_trade_action: &str,
        min_order_size: &str,
        max_orders_per_address: i64,
        data: &Bound<'_, PyDict>,
    ) -> PyResult<Self> {
        let mut nb = NativeBook::new(
            pool_id,
            max_depth,
            maker_fee_rate,
            taker_fee_rate,
            self_trade_action,
            min_order_size,
            max_orders_per_address,
        )?;
        let need = |k: &str| -> PyResult<Bound<'_, PyAny>> {
            data.get_item(k)?
                .ok_or_else(|| PyValueError::new_err(format!("a book's data needs {k}")))
        };
        let s = &mut nb.book.state;
        let mut by_id: std::collections::HashMap<String, Order> = std::collections::HashMap::new();
        for item in need("levels")?.iter()? {
            let (tag, price, orders): (String, String, Vec<Bound<'_, PyDict>>) = item?.extract()?;
            let price = dec_of(&price)?;
            let mut ids = Vector::new();
            for od in orders {
                let o = order_of(&od)?;
                ids.push_back(o.id.clone());
                by_id.insert(o.id.to_string(), o);
            }
            let level = Level {
                price: price.clone(),
                orders: ids,
            };
            let side = if tag == "b" { &mut s.bids } else { &mut s.asks };
            side.insert(PKey::of(&price), level);
        }
        for id in need("order_ids")?.extract::<Vec<String>>()? {
            let o = by_id
                .remove(&id)
                .ok_or_else(|| PyValueError::new_err(format!("an indexed order {id} rests nowhere")))?;
            s.order_seq.insert(o.id.clone(), s.next_seq);
            s.next_seq += 1;
            s.orders.insert(o.id.clone(), Arc::new(o));
        }
        if let Some(id) = by_id.keys().min() {
            return Err(PyValueError::new_err(format!("a resting order {id} is not indexed")));
        }
        for od in need("stops")?.iter()? {
            let o = order_of(od?.downcast::<PyDict>()?)?;
            s.stop_ids.push_back(o.id.clone());
            s.stops.insert(o.id.clone(), Arc::new(o));
        }
        let counts = |k: &str| -> PyResult<IMap<Id, i64>> {
            Ok(need(k)?
                .extract::<Vec<(String, i64)>>()?
                .into_iter()
                .map(|(o, n)| (Id::from(o), n))
                .collect())
        };
        s.owner_order_count = counts("owner_order_count")?;
        s.owner_stop_count = counts("owner_stop_count")?;
        s.block_order_count = counts("block_order_count")?;
        s.trade_sequence = need("trade_sequence")?.extract()?;
        s.last_price = match need("last_price")?.extract::<Option<String>>()? {
            Some(p) => Some(dec_of(&p)?),
            None => None,
        };
        s.total_volume = dec_of(&need("total_volume")?.extract::<String>()?)?;
        s.total_trades = need("total_trades")?.extract()?;
        s.paused = need("paused")?.extract()?;
        s.now = need("now")?.extract()?;
        s.has_expiring = need("has_expiring")?.extract()?;
        s.block_height = need("block_height")?.extract()?;
        for td in need("recent")?.iter()? {
            let td = td?;
            let td = td.downcast::<PyDict>()?;
            let text = |k: &str| -> PyResult<String> {
                td.get_item(k)?
                    .ok_or_else(|| PyValueError::new_err(format!("a trade needs {k}")))?
                    .extract()
            };
            s.recent.push_back(Trade {
                id: text("id")?,
                maker_order_id: Id::from(text("maker_order_id")?),
                taker_order_id: Id::from(text("taker_order_id")?),
                price: dec_of(&text("price")?)?,
                amount: dec_of(&text("amount")?)?,
                maker_fee: dec_of(&text("maker_fee")?)?,
                taker_fee: dec_of(&text("taker_fee")?)?,
                buyer: Id::from(text("buyer")?),
                seller: Id::from(text("seller")?),
                sequence: td
                    .get_item("sequence")?
                    .ok_or_else(|| PyValueError::new_err("a trade needs sequence"))?
                    .extract()?,
                timestamp: match td.get_item("timestamp")? {
                    Some(v) => v.extract()?,
                    None => 0.0,
                },
            });
        }
        Ok(nb)
    }
}

/// For the tests: Python's ``repr`` of a float, and ``blake2b(person=…)``.
#[pyfunction]
pub fn float_repr(x: f64) -> String {
    py_float_repr(x)
}

#[pyfunction]
pub fn blake2b_person<'py>(py: Python<'py>, data: &[u8], persona: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new_bound(py, &blake2b_personal(data, persona))
}
