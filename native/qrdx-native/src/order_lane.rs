//! A block's runs of plain spot orders and cancels, run natively over the native books
//! (qrdx/exchange/order_lane.py; docs/EXCHANGE_ENGINE.md, E3b).
//!
//! What a plain limit order or a cancel does is Python's ``process_transaction`` around
//! ``_op_place_order`` / ``_op_cancel_order``: the nonce, then the operation all or nothing —
//! the book's matching, each fill's settlement (the base and the quote moved, each side's fee
//! out of what it receives, less a referrer's reward, the stakers' part to the fee holder, the
//! rest to the treasury), the resting remainder into the book's escrow; or a cancelled order's
//! escrow back to its owner — then the gas. Python prepares each operation with its own parsing
//! and checks, and gathers what no operation of a run can change: where each pair's pools
//! start to fill (an order that reaches one takes from a pool, which is Python's), where its
//! waiting triggers fire (a fill that reaches one marks it: Python's), whether a fill could
//! reach a bracket, which tokens are paused or freeze a sender. Fills on a pair quoted in the
//! perps' settlement asset count toward each side's fee tier (``_record_volume``), here too.
//! This runs the operations in order, and stops before the first one it would not run exactly
//! as Python does — which Python runs, and the run continues after it.
//!
//! The ledger stays Python's. An entry (a block delta, a loaded balance) is read from Python's
//! own dict the first time an operation needs it, and every entry written goes back in the
//! order it was first written: a new key enters its dict where Python's would have. Values are
//! ``dec::Dec``, Python's ``Decimal`` exactly, under the exchange's context; whatever Python
//! would raise on makes the operation Python's.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use im::{HashMap as IMap, Vector};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::book::{Budget, Fail, Id, Kind, NativeBook, Order, Side, Status, Trade};
use crate::dec::{Dec, Rounding, EXCHANGE};
use crate::router::{self, Bail, Plan, Pool, Transcendental, RR};

/// Why an operation stopped: it fails as Python's fails (its error, and the gas Python's
/// handler reports — 0 for the base cost), or Python runs it.
enum Stop {
    Refused(String, i64),
    Python,
}

type R<T> = Result<T, Stop>;

fn exact(v: Option<Dec>) -> R<Dec> {
    v.ok_or(Stop::Python)
}
fn add(a: &Dec, b: &Dec) -> R<Dec> {
    exact(a.add(b, &EXCHANGE))
}
fn sub(a: &Dec, b: &Dec) -> R<Dec> {
    exact(a.sub(b, &EXCHANGE))
}
fn mul(a: &Dec, b: &Dec) -> R<Dec> {
    exact(a.mul(b, &EXCHANGE))
}
fn div(a: &Dec, b: &Dec) -> R<Dec> {
    exact(a.div(b, &EXCHANGE))
}
/// ``x.quantize(SPOT_FEE_QUANTUM, rounding)`` (1E-18).
fn q18(a: &Dec, rounding: Rounding) -> R<Dec> {
    exact(a.quantize(-18, rounding, &EXCHANGE))
}
/// Python's ``-x`` (rounded to the context, as every operation is).
fn negate(a: &Dec) -> R<Dec> {
    exact(a.neg().fix(&EXCHANGE))
}
fn lt(a: &Dec, b: &Dec) -> bool {
    a.cmp(b) == Ordering::Less
}
/// ``x > 0`` (and so ``x and x > 0``).
fn positive(a: &Dec) -> bool {
    !a.is_zero() && !a.neg
}
fn int(n: i64) -> R<Dec> {
    exact(Dec::parse(&n.to_string()))
}
fn parse(s: &str) -> R<Dec> {
    exact(Dec::parse(s))
}
fn text(d: &Dec) -> String {
    d.to_python_string()
}
/// ``s[:n]`` in a message: an address or a token is ASCII (anything else: Python words it).
fn head(s: &str, n: usize) -> R<&str> {
    if s.is_ascii() {
        Ok(&s[..n.min(s.len())])
    } else {
        Err(Stop::Python)
    }
}

fn refused<T>(message: String, gas: i64) -> R<T> {
    Err(Stop::Refused(message, gas))
}

/// A Python ``Decimal`` read from a dict (None: no entry).
fn read(d: &Bound<'_, PyDict>, key: impl ToPyObject) -> R<Option<Dec>> {
    let Ok(found) = d.get_item(key) else {
        return Err(Stop::Python);
    };
    match found {
        None => Ok(None),
        Some(v) => {
            let s = v.str().map_err(|_| Stop::Python)?;
            Ok(Some(parse(&s.to_cow().map_err(|_| Stop::Python)?)?))
        }
    }
}

// ── the ledger ──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Eq, Hash)]
enum Key {
    Qrdx(Id),
    Token(Id, Id),
}

#[derive(Clone)]
struct Entry {
    delta: Option<Dec>,
    avail: Option<Dec>,
}

/// Python's dicts: ``_balance_deltas`` / ``_available_balances`` (QRDX) and
/// ``_token_balance_deltas`` / ``_available_token_balances`` (tokens).
struct Dicts<'py> {
    deltas: Bound<'py, PyDict>,
    avail: Bound<'py, PyDict>,
    token_deltas: Bound<'py, PyDict>,
    token_avail: Bound<'py, PyDict>,
}

#[derive(Clone)]
struct Asset {
    name: Id,
    native: bool,
    paused: bool,
}

impl Asset {
    fn key(&self, holder: &Id) -> Key {
        if self.native {
            Key::Qrdx(holder.clone())
        } else {
            Key::Token(holder.clone(), self.name.clone())
        }
    }
}

/// What a run has changed: everything an operation's failure puts back (a copy is a pointer
/// copy). The lanes' nonces and the block's fees are not here: a failed operation pays its gas
/// and takes its nonce.
#[derive(Clone)]
struct Changes {
    entries: IMap<Key, Entry>,
    written: IMap<Key, ()>,
    order: Vector<Key>,
    book_nonces: IMap<(usize, Id), i64>,
    book_nonce_order: Vector<(usize, Id)>,
    fee_tokens: IMap<Id, Dec>,
    fee_token_order: Vector<Id>,
    staker_fees: Dec,
    owners: IMap<Id, Owner>,
    // the clearinghouse's volume dicts the run wrote, each in the order first written
    volume_order: Vector<Id>,
    lifetime_order: Vector<Id>,
    referral_order: Vector<Id>,
    // each pair's pools as the run moved them, the plans applied (pair, pool, plan) in order,
    // the pairs whose book a taker closed to at its own order after moving a pool
    pools: IMap<(usize, usize), Pool>,
    applied: Vector<(usize, usize, Plan)>,
    uncross: Vector<usize>,
    swaps: usize,
}

/// What decides an owner's spot fee, and what its fills count toward: its staking discount (fixed
/// for the block), its volume by day (``volumes``), its lifetime volume, its referral (referrer,
/// volume since it joined).
#[derive(Clone)]
struct Owner {
    discount: Dec,
    days: Vector<(i64, Dec)>,
    lifetime: Dec,
    referral: Option<(Id, Dec)>,
    written: u8, // VOLUME | LIFETIME | REFERRAL
    rates: (Dec, Dec), // ``fee_rates`` for its volume now (redone as its volume moves)
}

const VOLUME: u8 = 1;
const LIFETIME: u8 = 2;
const REFERRAL: u8 = 4;

struct Pair<'py> {
    nonces: Bound<'py, PyDict>,
    name: String,
    base: Asset,
    quote: Asset,
    escrow: Id,
    pool_count: usize,
    holders: Vec<Id>,
    places_bail: bool,
    tier: bool,
    has_stops: bool,
    handed: HashSet<String>,
    // where its waiting triggers fire: the lowest price a rising one waits for, the highest a
    // falling one waits for
    min_above: Option<Dec>,
    max_below: Option<Dec>,
}

struct Consts {
    treasury: Id,
    staker_holder: Id,
    staker_share: Dec,
    referee_keep: Dec,
    referrer_share: Dec,
    wei: Dec,
    height: i64,
    now: f64,
    place_gas: i64,
    cancel_gas: i64,
    per_maker: i64,
    tiers: Vec<(Dec, Dec, Dec)>,
    volume_days: i64,
    day: i64,
    vault: Id,
    protocol: Id,
    referral_cap: Dec,
    router_paused: bool,
    swap_gas: i64,
}

struct Run<'a, 'py> {
    py: Python<'py>,
    books: Vec<PyRefMut<'py, NativeBook>>,
    pairs: &'a [Pair<'py>],
    dicts: Dicts<'py>,
    fee_tokens_dict: Bound<'py, PyDict>,
    owner_fn: Bound<'py, PyAny>,
    amm_fn: Bound<'py, PyAny>,
    frozen: HashSet<(String, String)>,
    parents: HashSet<String>,
    c: Consts,
    changes: Changes,
    // what the operation in progress changed of its book's orders: (book, order) as it last was
    changed: Vec<(usize, Order)>,
    // the router's order-book sequence (its ids): a failed operation does not take it back
    clob_sequence: i64,
    // each fee payer's QRDX floor (``two_block_deferral``: ``fee_floor``): an operation that
    // would take an account below its floor is Python's (which refuses it)
    floors: HashMap<Id, Dec>,
}

/// Python's own values for the pools (``router::Transcendental``): ``amm(op, value)``.
struct PyMath<'a, 'py>(&'a Bound<'py, PyAny>);

impl Transcendental for PyMath<'_, '_> {
    fn tick_at(&mut self, s: &Dec) -> RR<i64> {
        self.0.call1(("tick_at", text(s))).and_then(|v| v.extract()).map_err(|_| Bail)
    }
    fn sqrt(&mut self, x: &Dec) -> RR<Dec> {
        let v: String = self.0.call1(("sqrt", text(x))).and_then(|v| v.extract()).map_err(|_| Bail)?;
        Dec::parse(&v).ok_or(Bail)
    }
    fn squared(&mut self, q96: &Dec) -> RR<Dec> {
        let v: String =
            self.0.call1(("squared", text(q96))).and_then(|v| v.extract()).map_err(|_| Bail)?;
        Dec::parse(&v).ok_or(Bail)
    }
}

impl From<Bail> for Stop {
    fn from(_: Bail) -> Stop {
        Stop::Python
    }
}

impl Run<'_, '_> {
    fn entry(&mut self, key: &Key) -> R<Entry> {
        if let Some(e) = self.changes.entries.get(key) {
            return Ok(e.clone());
        }
        let e = match key {
            Key::Qrdx(a) => Entry {
                delta: read(&self.dicts.deltas, &**a)?,
                avail: read(&self.dicts.avail, &**a)?,
            },
            Key::Token(a, t) => Entry {
                delta: read(&self.dicts.token_deltas, (&**a, &**t))?,
                avail: read(&self.dicts.token_avail, (&**a, &**t))?,
            },
        };
        self.changes.entries.insert(key.clone(), e.clone());
        Ok(e)
    }

    /// ``_record_balance_delta`` / ``_record_token_delta``: the delta, and the loaded balance
    /// in step if there is one.
    fn record(&mut self, key: Key, d: &Dec) -> R<()> {
        let mut e = self.entry(&key)?;
        e.delta = Some(add(e.delta.as_ref().unwrap_or(&Dec::zero()), d)?);
        if let Some(a) = &e.avail {
            e.avail = Some(add(a, d)?);
        }
        if let (Key::Qrdx(holder), Some(a)) = (&key, &e.avail) {
            if let Some(floor) = self.floors.get(holder) {
                if lt(d, &Dec::zero()) && lt(a, floor) {
                    return Err(Stop::Python); // (below its fee reserve: Python refuses it)
                }
            }
        }
        self.changes.entries.insert(key.clone(), e);
        if !self.changes.written.contains_key(&key) {
            self.changes.written.insert(key.clone(), ());
            self.changes.order.push_back(key);
        }
        Ok(())
    }

    /// ``_settle_token_move`` (not covered): ``amount`` of ``asset`` from ``frm`` to ``to``.
    /// ``release``: an escrow handing funds back (a paused token still goes back).
    fn transfer(&mut self, frm: &Id, to: &Id, asset: &Asset, amount: &Dec, release: bool) -> R<()> {
        if !positive(amount) {
            return Ok(());
        }
        if !asset.native {
            if self.frozen.contains(&(frm.to_string(), asset.name.to_string())) {
                return Err(Stop::Python);
            }
            if asset.paused && !release {
                return Err(Stop::Python);
            }
        }
        let key = asset.key(frm);
        match self.entry(&key)?.avail {
            None => {
                return refused(
                    format!(
                        "{}…'s {}… balance was not loaded for this block",
                        head(frm, 16)?,
                        head(&asset.name, 12)?
                    ),
                    0,
                )
            }
            Some(a) if lt(&a, amount) => {
                return refused(
                    format!(
                        "{}… cannot cover {} of {}… (holds {})",
                        head(frm, 16)?,
                        text(amount),
                        head(&asset.name, 12)?,
                        text(&a)
                    ),
                    0,
                )
            }
            Some(_) => {}
        }
        self.record(key, &negate(amount)?)?;
        self.record(asset.key(to), amount)
    }

    fn owner(&mut self, owner: &Id) -> R<Owner> {
        if let Some(o) = self.changes.owners.get(owner) {
            return Ok(o.clone());
        }
        type Got = (String, Vec<(i64, String)>, Option<String>, Option<(String, String)>);
        let got: Got = self
            .owner_fn
            .call1((&**owner,))
            .and_then(|v| v.extract())
            .map_err(|_| Stop::Python)?;
        let mut days = Vector::new();
        for (d, n) in got.1 {
            days.push_back((d, parse(&n)?));
        }
        let o = Owner {
            discount: parse(&got.0)?,
            days,
            lifetime: match got.2 {
                Some(v) => parse(&v)?,
                None => Dec::zero(),
            },
            referral: match got.3 {
                Some((r, v)) => Some((Id::from(r.as_str()), parse(&v)?)),
                None => None,
            },
            written: 0,
            rates: (Dec::zero(), Dec::zero()),
        };
        let mut o = o;
        o.rates = self.fee_rates(&o)?;
        self.changes.owners.insert(owner.clone(), o.clone());
        Ok(o)
    }

    /// ``Clearinghouse.fee_rates``: (taker, maker) for the owner's volume of the last
    /// FEE_VOLUME_DAYS days, less its staking discount (a rebate is kept whole).
    fn fee_rates(&self, o: &Owner) -> R<(Dec, Dec)> {
        let first = self.c.day - self.c.volume_days + 1;
        let mut volume = Dec::zero();
        for (d, n) in o.days.iter() {
            if *d >= first {
                volume = add(&volume, n)?;
            }
        }
        let (mut taker, mut maker) = (self.c.tiers[0].1.clone(), self.c.tiers[0].2.clone());
        for (floor, t, mk) in &self.c.tiers {
            if !lt(&volume, floor) {
                taker = t.clone();
                maker = mk.clone();
            }
        }
        if positive(&o.discount) {
            let keep = sub(&Dec::parse("1").expect("one"), &o.discount)?;
            taker = mul(&taker, &keep)?;
            if positive(&maker) {
                maker = mul(&maker, &keep)?;
            }
        }
        Ok((taker, maker))
    }

    /// ``_spot_fee``: (fee, referral reward, referrer) on ``value`` ``owner`` receives.
    fn spot_fee(&mut self, owner: &Id, is_maker: bool, value: &Dec) -> R<(Dec, Dec, Option<Id>)> {
        if !self.changes.owners.contains_key(owner) {
            self.owner(owner)?;
        }
        let o = &self.changes.owners[owner];
        spot_fee_of(o, &o.rates, &self.c, is_maker, value)
    }

    /// ``Clearinghouse._record_volume``: a fill's notional counts toward the owner's fee tier,
    /// its lifetime volume and (under the cap) its referral's.
    fn record_volume(&mut self, owner: &Id, notional: &Dec) -> R<()> {
        if *owner == self.c.vault || *owner == self.c.protocol {
            return Ok(());
        }
        let mut o = self.owner(owner)?;
        let day = self.c.day;
        let mut days: Vector<(i64, Dec)> =
            o.days.iter().filter(|(d, _)| *d > day - self.c.volume_days).cloned().collect();
        match days.back().cloned() {
            Some((d, n)) if d == day => {
                let i = days.len() - 1;
                days.set(i, (day, add(&n, notional)?));
            }
            _ => days.push_back((day, notional.clone())),
        }
        o.days = days;
        o.lifetime = add(&o.lifetime, notional)?;
        let mut wrote = VOLUME | LIFETIME;
        if let Some((r, v)) = &o.referral {
            if lt(v, &self.c.referral_cap) {
                o.referral = Some((r.clone(), add(v, notional)?));
                wrote |= REFERRAL;
            }
        }
        for (bit, order) in [
            (VOLUME, &mut self.changes.volume_order),
            (LIFETIME, &mut self.changes.lifetime_order),
            (REFERRAL, &mut self.changes.referral_order),
        ] {
            if wrote & bit != 0 && o.written & bit == 0 {
                order.push_back(owner.clone());
            }
        }
        o.written |= wrote;
        o.rates = self.fee_rates(&o)?;
        self.changes.owners.insert(owner.clone(), o);
        Ok(())
    }

    /// ``_accrue_staker_fee``.
    fn accrue(&mut self, asset: &Asset, amount: &Dec) -> R<()> {
        if &*asset.name == "QRDX" {
            self.changes.staker_fees = add(&self.changes.staker_fees, amount)?;
            return Ok(());
        }
        let pending = match self.changes.fee_tokens.get(&asset.name) {
            Some(p) => p.clone(),
            None => {
                let found = self
                    .fee_tokens_dict
                    .get_item(&*asset.name)
                    .map_err(|_| Stop::Python)?;
                match found {
                    None => Dec::zero(),
                    Some(v) => {
                        let first = v.get_item(0).and_then(|x| x.str()).map_err(|_| Stop::Python)?;
                        parse(&first.to_cow().map_err(|_| Stop::Python)?)?
                    }
                }
            }
        };
        if !self.changes.fee_tokens.contains_key(&asset.name) {
            self.changes.fee_token_order.push_back(asset.name.clone());
        }
        self.changes.fee_tokens.insert(asset.name.clone(), add(&pending, amount)?);
        Ok(())
    }

    /// ``_settle_spot_trade``: one fill, the taker's side live, the maker's from the escrow.
    fn settle_trade(&mut self, pair: usize, tr: &mut Trade, taker: &Id) -> R<()> {
        let p = &self.pairs[pair];
        let (base, quote, escrow) = (p.base.clone(), p.quote.clone(), p.escrow.clone());
        let base_src = if tr.seller == *taker { taker.clone() } else { escrow.clone() };
        let quote_src = if tr.buyer == *taker { taker.clone() } else { escrow };
        let f = tr.amount.clone();
        let notional = mul(&f, &tr.price)?;
        let sides = [
            (tr.buyer.clone(), base, f, base_src),
            (tr.seller.clone(), quote, notional, quote_src),
        ];
        for (owner, asset, value, src) in sides {
            let (fee, reward, referrer) = self.spot_fee(&owner, owner != *taker, &value)?;
            self.transfer(&src, &owner, &asset, &sub(&value, &fee)?, false)?;
            let protocol = sub(&fee, &reward)?;
            let staker = if positive(&protocol) {
                q18(&mul(&protocol, &self.c.staker_share)?, Rounding::Down)?
            } else {
                Dec::zero()
            };
            if positive(&staker) {
                let holder = self.c.staker_holder.clone();
                self.transfer(&src, &holder, &asset, &staker, false)?;
                self.accrue(&asset, &staker)?;
            }
            let treasury = self.c.treasury.clone();
            self.transfer(&src, &treasury, &asset, &sub(&protocol, &staker)?, false)?;
            if positive(&reward) {
                if let Some(r) = &referrer {
                    self.transfer(&src, r, &asset, &reward, false)?;
                }
            }
            if owner == *taker {
                tr.taker_fee = fee;
            } else {
                tr.maker_fee = fee;
            }
        }
        Ok(())
    }

    fn book_nonce(&mut self, pair: usize, owner: &Id) -> R<i64> {
        if let Some(n) = self.changes.book_nonces.get(&(pair, owner.clone())) {
            return Ok(*n);
        }
        let found = self.pairs[pair].nonces.get_item(&**owner).map_err(|_| Stop::Python)?;
        match found {
            None => Ok(0),
            Some(v) if v.is_none() => Ok(0),
            Some(v) => v.extract::<i64>().map_err(|_| Stop::Python),
        }
    }

    fn set_book_nonce(&mut self, pair: usize, owner: &Id, n: i64) {
        let key = (pair, owner.clone());
        if !self.changes.book_nonces.contains_key(&key) {
            self.changes.book_nonce_order.push_back(key.clone());
        }
        self.changes.book_nonces.insert(key, n);
    }

    /// The orders the book's last call changed, for the objects Python handed out.
    fn take_changed(&mut self, pair: usize) {
        let handed = &self.pairs[pair].handed;
        for (id, o) in self.books[pair].book.last.drain() {
            if handed.contains(&*id) {
                self.changed.push((pair, o));
            }
        }
    }

    /// ``_op_place_order`` for a plain limit or market order: (gas, data). The caller keeps the
    /// book and the changes from before it, and puts them back if it stops.
    fn place(&mut self, op: &OpIn, p: &PlaceIn) -> R<(i64, Bound<'_, PyDict>)> {
        let pair = op.pair;
        let pr = &self.pairs[pair];
        if pr.places_bail {
            return Err(Stop::Python);
        }
        let buy = p.side == Side::Buy;
        let price = parse(&p.price)?;
        let amount = parse(&p.amount)?;
        let sender: Id = Id::from(op.sender.as_str());
        let (need_asset, need) = if buy {
            (pr.quote.clone(), mul(&amount, &price)?)
        } else {
            (pr.base.clone(), amount.clone())
        };
        let (base, quote, escrow) = (pr.base.clone(), pr.quote.clone(), pr.escrow.clone());
        let (min_above, max_below, tier) = (pr.min_above.clone(), pr.max_below.clone(), pr.tier);
        if !need_asset.native
            && self.frozen.contains(&(op.sender.clone(), need_asset.name.to_string()))
        {
            return Err(Stop::Python);
        }
        if !p.market {
            if let Some(a) = self.entry(&need_asset.key(&sender))?.avail {
                if lt(&a, &need) {
                    return refused(
                        format!(
                            "insufficient balance for order: need {} {}, available {}",
                            text(&need),
                            head(&need_asset.name, 10)?,
                            text(&a)
                        ),
                        0,
                    );
                }
            }
        }
        // The pair's combined market (``plan_fill``): the pools fill what they price better
        // than the book, within the limit; the book takes the rest.
        let planned = self.plan_pools(pair, buy, &amount, (!p.market).then_some(&price), &sender, p.makers)?;
        if !planned.legs.is_empty() {
            if self.c.router_paused {
                return Err(Stop::Python);
            }
            if p.tif == "alo" {
                return refused("post-only order would take from a pool".into(), 0);
            }
        }
        // The operation's scope: the pools' legs, then the book starts the block, then the
        // order is placed for the rest.
        let (pool_base, pool_fills) = match self.fill_from_pools(pair, &planned, buy, &sender) {
            Ok(v) => v,
            Err(Stop::Refused(m, _)) => return refused(m, self.c.place_gas),
            Err(e) => return Err(e),
        };
        let (height, now) = (self.c.height, self.c.now);
        {
            let book = &mut self.books[pair].book;
            if book.state.block_height != Some(height) {
                book.last.clear();
                match book.new_block(Some(now)) {
                    Ok(()) => book.state.block_height = Some(height),
                    Err(Fail::Refused(m)) => return refused(m, self.c.place_gas),
                    Err(Fail::Native) => return Err(Stop::Python),
                }
            }
        }
        self.take_changed(pair);
        let order = Order {
            id: Id::from(op.order_id.as_str()),
            owner: sender.clone(),
            side: p.side,
            kind: if p.market { Kind::Market } else { Kind::Limit },
            price: price.clone(),
            amount,
            filled: match &pool_base {
                Some(b) => add(&Dec::zero(), b)?,
                None => Dec::zero(),
            },
            status: Status::Open,
            timestamp: p.timestamp,
            stop_price: None,
            nonce: op.nonce,
            expire_time: 0.0,
            tif: Id::from(p.tif.as_str()),
            hidden: p.hidden,
            display_size: parse(&p.display_size)?,
            shown: Dec::zero(),
        };
        let last_nonce = self.book_nonce(pair, &sender)?;
        let mut budget = Some(Budget {
            left: p.makers.max(0),
            visited: 0,
            exhausted: false,
        });
        let placed = {
            let book = &mut self.books[pair].book;
            book.last_nonce = last_nonce;
            book.place_order(order, false, &mut budget)
        };
        let gas = self.c.place_gas + budget.map_or(0, |b| b.visited) * self.c.per_maker;
        let (mut trades, ended) = match placed {
            Ok(v) => v,
            Err((Fail::Refused(m), _)) => {
                self.books[pair].book.last.clear();
                return refused(m, gas);
            }
            Err((Fail::Native, _)) => return Err(Stop::Python),
        };
        if let Some(n) = self.books[pair].book.new_nonce {
            self.set_book_nonce(pair, &sender, n);
        }
        self.take_changed(pair);
        // ``_record_spot_prices``: the pair's last price is the worst its fills reached (a
        // pool's included), and fills that reach a waiting trigger mark it (Python's).
        let mut seen: Vec<Dec> = trades.iter().map(|t| t.price.clone()).filter(positive).collect();
        seen.extend(planned.legs.iter().map(|l| l.2.clone()).filter(positive));
        if let (Some(lo), Some(hi)) = (router_min(&seen), router_max(&seen)) {
            let rises = min_above.as_ref().is_some_and(|p| !lt(hi, p));
            let falls = max_below.as_ref().is_some_and(|p| !lt(p, lo));
            if rises || falls {
                return Err(Stop::Python);
            }
            if !planned.legs.is_empty() {
                let last = if buy { hi.clone() } else { lo.clone() };
                self.books[pair].book.record_price(last);
            }
        }
        // ``_settle_orderbook``: each fill, then the unfilled remainder into the escrow.
        for tr in trades.iter_mut() {
            let buy_order = if tr.buyer == sender { &tr.taker_order_id } else { &tr.maker_order_id };
            if self.parents.contains(&**buy_order) {
                return Err(Stop::Python); // (its base goes to an attached TP/SL)
            }
            match self.settle_trade(pair, tr, &sender) {
                Ok(()) => {}
                Err(Stop::Refused(m, _)) => return refused(m, gas),
                Err(Stop::Python) => return Err(Stop::Python),
            }
            let book = &mut self.books[pair].book;
            book.set_trade_fee(&tr.id, false, tr.taker_fee.clone());
            book.set_trade_fee(&tr.id, true, tr.maker_fee.clone());
        }
        // ``_record_spot_volume``: once every fill settled, on a pair quoted in the settlement
        // asset, each fill's notional counts toward both sides' tiers.
        if tier {
            for tr in &trades {
                let notional = mul(&tr.amount, &tr.price)?;
                self.record_volume(&tr.buyer, &notional)?;
                self.record_volume(&tr.seller, &notional)?;
            }
        }
        let rest = exact(ended.remaining().ok())?;
        if positive(&rest) && ended.is_active() {
            let moved = if buy {
                self.transfer(&sender, &escrow, &quote, &mul(&rest, &price)?, false)
            } else {
                self.transfer(&sender, &escrow, &base, &rest, false)
            };
            match moved {
                Ok(()) => {}
                Err(Stop::Refused(m, _)) => return refused(m, gas),
                Err(Stop::Python) => return Err(Stop::Python),
            }
        }
        if planned.stopped == "self" && !planned.legs.is_empty() {
            self.changes.uncross.push_back(pair); // (``_flag_self_pass``)
        }
        let gas = gas + pool_fills.len() as i64 * self.c.per_maker;
        let data = self.placed_data(pair, &op.order_id, &trades, &ended, &sender, p.side, pool_fills)?;
        Ok((gas, data))
    }

    /// ``plan_fill``'s pools' part for the order (none without a pool that can fill).
    fn plan_pools(
        &mut self,
        pair: usize,
        buy: bool,
        amount: &Dec,
        limit: Option<&Dec>,
        sender: &Id,
        makers: i64,
    ) -> R<router::Planned> {
        let n = self.pairs[pair].pool_count;
        if n == 0 {
            return Ok(router::Planned { buy, book: None, legs: Vec::new(), stopped: "" });
        }
        let pools: Vec<Pool> = (0..n).map(|i| self.changes.pools[&(pair, i)].clone()).collect();
        if !router::can_fill(&pools, buy, limit)? {
            return Ok(router::Planned { buy, book: None, legs: Vec::new(), stopped: "" });
        }
        let rate = self.taker_rate(sender)?;
        let amm = self.amm_fn.clone();
        let mut math = PyMath(&amm);
        let book = &self.books[pair].book;
        let mut no_fee = |_: &Dec| -> RR<Dec> { Ok(Dec::zero()) };
        let planned = router::plan_fill(
            book, &pools, buy, amount, false, limit, sender, Some(makers), &rate, &mut no_fee, true,
            &mut math,
        )?;
        Ok(planned.unwrap_or(router::Planned { buy, book: None, legs: Vec::new(), stopped: "" }))
    }

    /// ``taker_rate``: the sender's taker fee on a billion, per unit (it ranks the book against
    /// the pools).
    fn taker_rate(&mut self, sender: &Id) -> R<Dec> {
        let unit = Dec::parse("1000000000").expect("1e9");
        let (fee, _, _) = self.spot_fee(sender, false, &unit)?;
        div(&fee, &unit)
    }

    /// ``_fill_from_pools``: each pool's leg applied, the taker's side paid into the pool's
    /// holder and what it bought paid out of it. (base from the pools if any, the fills).
    fn fill_from_pools(
        &mut self,
        pair: usize,
        planned: &router::Planned,
        buy: bool,
        sender: &Id,
    ) -> R<(Option<Dec>, Vec<PoolFill>)> {
        if planned.legs.is_empty() {
            return Ok((None, Vec::new()));
        }
        let (base_asset, quote_asset) = (self.pairs[pair].base.clone(), self.pairs[pair].quote.clone());
        let (token_in, token_out) = if buy { (quote_asset, base_asset) } else { (base_asset, quote_asset) };
        let mut base = Dec::zero();
        let mut fills = Vec::with_capacity(planned.legs.len());
        for (i, plan, _end) in &planned.legs {
            let pool = self.changes.pools.get_mut(&(pair, *i)).expect("the pair's pool");
            pool.apply(plan);
            let id = pool.id.clone();
            self.changes.applied.push_back((pair, *i, plan.clone()));
            let holder = self.pairs[pair].holders[*i].clone();
            self.transfer(sender, &holder, &token_in, &plan.amount_in, false)?;
            self.transfer(&holder, sender, &token_out, &plan.amount_out, false)?;
            let leg_base = if buy { &plan.amount_out } else { &plan.amount_in };
            base = add(&base, leg_base)?;
            fills.push(PoolFill { pool_id: id, holder, amount_in: plan.amount_in.clone(), amount_out: plan.amount_out.clone() });
        }
        Ok((Some(base), fills))
    }

    fn placed_data(
        &self,
        pair: usize,
        order_id: &str,
        trades: &[Trade],
        ended: &Order,
        taker: &Id,
        side: Side,
        pool_fills: Vec<PoolFill>,
    ) -> R<Bound<'_, PyDict>> {
        let py = self.py;
        let name = &self.pairs[pair].name;
        let buy = side == Side::Buy;
        let mut amm_prices = Vec::with_capacity(pool_fills.len());
        for f in &pool_fills {
            // (``_amm_fill``: quote per base, the base the taker bought or sold)
            let (amount, quote_amount) =
                if buy { (&f.amount_out, &f.amount_in) } else { (&f.amount_in, &f.amount_out) };
            amm_prices.push(if positive(amount) { text(&div(quote_amount, amount)?) } else { "0".into() });
        }
        let n_trades = trades.len() + pool_fills.len();
        let built = (|| -> PyResult<Bound<'_, PyDict>> {
            let fills = PyList::empty_bound(py);
            for (f, price) in pool_fills.iter().zip(&amm_prices) {
                let (amount, quote_amount) =
                    if buy { (&f.amount_out, &f.amount_in) } else { (&f.amount_in, &f.amount_out) };
                let (buyer, seller) = if buy { (taker, &f.holder) } else { (&f.holder, taker) };
                let d = PyDict::new_bound(py);
                d.set_item("market", name)?;
                d.set_item("venue", "amm")?;
                d.set_item("pool_id", &f.pool_id)?;
                d.set_item("price", price)?;
                d.set_item("amount", text(amount))?;
                d.set_item("quote_amount", text(quote_amount))?;
                d.set_item("buyer", &**buyer)?;
                d.set_item("seller", &**seller)?;
                d.set_item("maker", &*f.holder)?;
                d.set_item("taker", &**taker)?;
                d.set_item("side", side.value())?;
                fills.append(d)?;
            }
            for t in trades {
                let d = PyDict::new_bound(py);
                d.set_item("market", name)?;
                d.set_item("venue", "clob")?;
                d.set_item("trade_id", &t.id)?;
                d.set_item("price", text(&t.price))?;
                d.set_item("amount", text(&t.amount))?;
                d.set_item("buyer", &*t.buyer)?;
                d.set_item("seller", &*t.seller)?;
                let maker = if t.buyer == *taker { &t.seller } else { &t.buyer };
                d.set_item("maker", &**maker)?;
                d.set_item("taker", &**taker)?;
                d.set_item("side", side.value())?;
                d.set_item("maker_order_id", &*t.maker_order_id)?;
                d.set_item("taker_order_id", &*t.taker_order_id)?;
                let fees = PyDict::new_bound(py);
                let of = |who: &Id| if who == taker { &t.taker_fee } else { &t.maker_fee };
                fees.set_item(&*t.buyer, text(of(&t.buyer)))?;
                fees.set_item(&*t.seller, text(of(&t.seller)))?;
                d.set_item("fees", fees)?;
                fills.append(d)?;
            }
            let data = PyDict::new_bound(py);
            data.set_item("order_id", order_id)?;
            data.set_item("trades", n_trades)?;
            data.set_item("filled", text(&ended.filled))?;
            data.set_item("fills", fills)?;
            Ok(data)
        })();
        built.map_err(|_| Stop::Python)
    }

    /// ``best_route``: a hop's exact-input route on its pair's combined market.
    fn best_route(
        &mut self,
        hop: &(String, String, i64),
        amount: &Dec,
        sender: &Id,
        makers: i64,
    ) -> R<Option<router::Planned>> {
        let (token_in, token_out, slot) = hop;
        if token_in == token_out || *slot < 0 {
            return Ok(None);
        }
        let pair = *slot as usize;
        let buy = *token_in != *self.pairs[pair].base.name;
        let o = self.owner(sender)?;
        let rates = o.rates.clone();
        let rate = self.taker_rate(sender)?;
        let n = self.pairs[pair].pool_count;
        let pools: Vec<Pool> = (0..n).map(|i| self.changes.pools[&(pair, i)].clone()).collect();
        let amm = self.amm_fn.clone();
        let mut math = PyMath(&amm);
        let c = &self.c;
        let mut fee_of = |received: &Dec| -> RR<Dec> {
            spot_fee_of(&o, &rates, c, false, received).map(|f| f.0).map_err(|_| Bail)
        };
        let book = &self.books[pair].book;
        Ok(router::plan_fill(
            book, &pools, buy, amount, true, None, sender, Some(makers), &rate, &mut fee_of, false,
            &mut math,
        )?)
    }

    /// ``_route_gas``: each resting order a hop visits, each pool beyond its first.
    fn route_gas(&self, r: &router::Planned) -> i64 {
        let makers = r.book.as_ref().map_or(0, |b| b.makers);
        (makers + (r.legs.len() as i64 - 1).max(0)) * self.c.per_maker
    }

    /// ``plan_swap``: a path's routes, hop by hop within the gas, or why not.
    fn plan_swap(
        &mut self,
        sender: &Id,
        path: &[(String, String, i64)],
        amount_in: &Dec,
        gas_limit: i64,
    ) -> R<Result<Vec<router::Planned>, String>> {
        let hops = path.len() as i64;
        let mut gas = self.c.swap_gas * hops;
        if gas > gas_limit {
            return Ok(Err(format!("a {hops}-hop swap needs at least {gas} gas")));
        }
        let mut amount = amount_in.clone();
        let mut routes = Vec::with_capacity(path.len());
        for (i, hop) in path.iter().enumerate() {
            let makers = (gas_limit - gas).div_euclid(self.c.per_maker).max(0);
            let route = match self.best_route(hop, &amount, sender, makers)? {
                Some(r) if positive(&r.amount_out()?) => r,
                _ => {
                    let error = "No liquidity available for this pair";
                    return Ok(Err(if hops == 1 { error.into() } else { format!("hop {i}: {error}") }));
                }
            };
            gas += self.route_gas(&route);
            amount = route.amount_out()?;
            routes.push(route);
        }
        Ok(Ok(routes))
    }

    /// ``_op_swap`` without a ``path``, ``pool_id`` or ``venue``: (gas, data).
    fn swap(&mut self, op: &OpIn, sw: &SwapIn) -> R<(i64, Bound<'_, PyDict>)> {
        let sender: Id = Id::from(op.sender.as_str());
        let amount_in = parse(&sw.amount_in)?;
        let min_out = parse(&sw.min_out)?;
        if !positive(&amount_in) {
            return refused("amount_in must be positive".into(), 0);
        }
        if sw.deadline > 0.0 && self.c.now > sw.deadline {
            return refused("Transaction deadline expired".into(), 0);
        }
        if let Some(a) = self.entry(&sw.token_in.key(&sender))?.avail {
            if lt(&a, &amount_in) {
                return refused(
                    format!("insufficient token_in: need {}, available {}", text(&amount_in), text(&a)),
                    0,
                );
            }
        }
        // ``choose_swap_path``: the pair, or two hops through a hub when that pays more.
        let mut best: Option<(usize, Dec)> = None;
        let mut error: Option<String> = None;
        for (ci, path) in sw.paths.iter().enumerate() {
            match self.plan_swap(&sender, path, &amount_in, op.gas_limit)? {
                Err(e) => {
                    if best.is_none() && error.is_none() {
                        error = Some(e);
                    }
                }
                Ok(routes) => {
                    let out = routes.last().expect("a hop").amount_out()?;
                    if best.as_ref().is_none_or(|(_, b)| lt(b, &out)) {
                        best = Some((ci, out));
                    }
                }
            }
        }
        let Some((ci, planned_out)) = best else {
            return refused(error.unwrap_or_default(), self.c.swap_gas);
        };
        if positive(&min_out) && lt(&planned_out, &min_out) {
            return refused(
                format!("Slippage exceeded: got {}, minimum {}", text(&planned_out), text(&min_out)),
                0,
            );
        }
        // Hop by hop, each planned again on what the one before bought.
        let path = sw.paths[ci].clone();
        let hops = path.len();
        let mut gas = self.c.swap_gas * hops as i64;
        let mut amount = amount_in.clone();
        let mut spent_in = Dec::zero();
        let mut fee_total = Dec::zero();
        let mut summaries = Vec::with_capacity(hops);
        let mut fills: Vec<FillOut> = Vec::new();
        for (i, hop) in path.iter().enumerate() {
            let makers = (op.gas_limit - gas).div_euclid(self.c.per_maker).max(0);
            let Some(route) = self.best_route(hop, &amount, &sender, makers)? else {
                let error = "No liquidity available for this pair";
                return refused(if hops == 1 { error.into() } else { format!("hop {i}: {error}") }, gas);
            };
            match self.swap_hop(hop.2 as usize, &route, &sender, &mut fills) {
                Ok(()) => {}
                Err(Stop::Refused(m, _)) => return refused(m, gas),
                Err(e) => return Err(e),
            }
            gas += self.route_gas(&route);
            if i == 0 {
                spent_in = route.amount_in()?;
            }
            amount = route.amount_out()?;
            fee_total = add(&fee_total, &route.fee_total()?)?;
            let pool_id = route.legs.first().map(|(k, _, _)| self.changes.pools[&(hop.2 as usize, *k)].id.clone());
            summaries.push((hop.0.clone(), hop.1.clone(), route.amount_in()?, amount.clone(), route.source(), pool_id));
        }
        if positive(&min_out) && lt(&amount, &min_out) {
            return refused(
                format!("Slippage exceeded: got {}, minimum {}", text(&amount), text(&min_out)),
                gas,
            );
        }
        self.changes.swaps += 1;
        let price = if positive(&amount) { text(&div(&spent_in, &amount)?) } else { "0".into() };
        let py = self.py;
        let built = (|| -> PyResult<Bound<'_, PyDict>> {
            let data = PyDict::new_bound(py);
            data.set_item("amount_in", text(&spent_in))?;
            data.set_item("amount_out", text(&amount))?;
            data.set_item("fee_total", text(&fee_total))?;
            data.set_item("price", price)?;
            data.set_item("source", summaries[0].4)?;
            data.set_item("pool_id", summaries[0].5.clone())?;
            let list = PyList::empty_bound(py);
            for f in &fills {
                list.append(f.to_py(py)?)?;
            }
            data.set_item("fills", list)?;
            if hops > 1 {
                let mut tokens: Vec<&str> = vec![path[0].0.as_str()];
                tokens.extend(path.iter().map(|h| h.1.as_str()));
                data.set_item("path", tokens)?;
                let list = PyList::empty_bound(py);
                for (tin, tout, a_in, a_out, source, pool_id) in &summaries {
                    let d = PyDict::new_bound(py);
                    d.set_item("token_in", tin)?;
                    d.set_item("token_out", tout)?;
                    d.set_item("amount_in", text(a_in))?;
                    d.set_item("amount_out", text(a_out))?;
                    d.set_item("source", *source)?;
                    d.set_item("pool_id", pool_id.clone())?;
                    list.append(d)?;
                }
                data.set_item("hops", list)?;
            }
            Ok(data)
        })();
        Ok((gas, built.map_err(|_| Stop::Python)?))
    }

    /// ``_swap_hop``: every leg of a planned hop — the book's as an immediate-or-cancel order
    /// of the router's, each pool's plan — settled with its counterparty; then the pair's
    /// prices (``_record_spot_prices``) and ``_flag_self_pass``.
    fn swap_hop(
        &mut self,
        pair: usize,
        route: &router::Planned,
        sender: &Id,
        fills: &mut Vec<FillOut>,
    ) -> R<()> {
        if self.c.router_paused && !route.is_empty() {
            return Err(Stop::Python); // (``apply_leg`` refuses: Python words it)
        }
        let name = self.pairs[pair].name.clone();
        let (base, quote) = (self.pairs[pair].base.clone(), self.pairs[pair].quote.clone());
        let buy = route.buy;
        let side = if buy { Side::Buy } else { Side::Sell };
        let (token_in, token_out) = if buy { (quote.clone(), base.clone()) } else { (base.clone(), quote.clone()) };
        if let Some(leg) = &route.book {
            self.clob_sequence += 1;
            let id = router_order_id(sender, self.clob_sequence);
            let order = Order {
                id: Id::from(id.as_str()),
                owner: sender.clone(),
                side,
                kind: Kind::Limit,
                price: leg.limit.clone(),
                amount: leg.size.clone(),
                filled: Dec::zero(),
                status: Status::Open,
                timestamp: 0.0,
                stop_price: None,
                nonce: 0,
                expire_time: 0.0,
                tif: Id::from("ioc"),
                hidden: false,
                display_size: Dec::zero(),
                shown: Dec::zero(),
            };
            let mut budget = Some(Budget { left: leg.makers.max(0), visited: 0, exhausted: false });
            let placed = {
                let book = &mut self.books[pair].book;
                book.last.clear();
                book.place_order(order, true, &mut budget)
            };
            let (mut trades, ended) = match placed {
                Ok(v) => v,
                Err((Fail::Refused(m), _)) => return refused(m, 0),
                Err((Fail::Native, _)) => return Err(Stop::Python),
            };
            self.take_changed(pair);
            let mut filled = Dec::zero();
            for t in &trades {
                filled = add(&filled, &t.amount)?;
            }
            if !router_eq(&filled, &leg.size) {
                return refused(
                    format!("order book fill {} differs from its quote {}", text(&filled), text(&leg.size)),
                    0,
                );
            }
            self.settle_book_fills(pair, &mut trades, &ended, sender, buy)?;
            for t in &trades {
                fills.push(FillOut::Book {
                    market: name.clone(),
                    trade: t.clone(),
                    taker: sender.clone(),
                    side,
                });
            }
        }
        for (i, plan, _end) in &route.legs {
            let pool = self.changes.pools.get_mut(&(pair, *i)).expect("the pair's pool");
            pool.apply(plan);
            let id = pool.id.clone();
            self.changes.applied.push_back((pair, *i, plan.clone()));
            let holder = self.pairs[pair].holders[*i].clone();
            self.transfer(sender, &holder, &token_in, &plan.amount_in, false)?;
            self.transfer(&holder, sender, &token_out, &plan.amount_out, false)?;
            let (amount, quote_amount) =
                if buy { (plan.amount_out.clone(), plan.amount_in.clone()) } else { (plan.amount_in.clone(), plan.amount_out.clone()) };
            let price = if positive(&amount) { text(&div(&quote_amount, &amount)?) } else { "0".into() };
            fills.push(FillOut::Pool {
                market: name.clone(),
                pool_id: id,
                price,
                amount,
                quote_amount,
                holder,
                taker: sender.clone(),
                side,
            });
        }
        // ``_record_spot_prices(pair, route)``: the worst price the route reached.
        let mut seen: Vec<Dec> = Vec::new();
        if let Some(b) = &route.book {
            if positive(&b.limit) {
                seen.push(b.limit.clone());
            }
        }
        seen.extend(route.legs.iter().map(|l| l.2.clone()).filter(positive));
        if let (Some(lo), Some(hi)) = (router_min(&seen), router_max(&seen)) {
            let p = &self.pairs[pair];
            let rises = p.min_above.as_ref().is_some_and(|x| !lt(hi, x));
            let falls = p.max_below.as_ref().is_some_and(|x| !lt(x, lo));
            if rises || falls {
                return Err(Stop::Python);
            }
            let last = if buy { hi.clone() } else { lo.clone() };
            self.books[pair].book.record_price(last);
        }
        if route.stopped == "self" && !route.legs.is_empty() {
            self.changes.uncross.push_back(pair);
        }
        Ok(())
    }

    /// ``_settle_orderbook`` for a taker's fills: each settled (the maker's side from the
    /// escrow), their volume, the remainder into the escrow if it rests.
    fn settle_book_fills(
        &mut self,
        pair: usize,
        trades: &mut [Trade],
        ended: &Order,
        sender: &Id,
        buy: bool,
    ) -> R<()> {
        let (base, quote, escrow, tier) = {
            let p = &self.pairs[pair];
            (p.base.clone(), p.quote.clone(), p.escrow.clone(), p.tier)
        };
        for tr in trades.iter_mut() {
            let buy_order = if tr.buyer == *sender { &tr.taker_order_id } else { &tr.maker_order_id };
            if self.parents.contains(&**buy_order) {
                return Err(Stop::Python); // (its base goes to an attached TP/SL)
            }
            self.settle_trade(pair, tr, sender)?;
            let book = &mut self.books[pair].book;
            book.set_trade_fee(&tr.id, false, tr.taker_fee.clone());
            book.set_trade_fee(&tr.id, true, tr.maker_fee.clone());
        }
        if tier {
            for tr in trades.iter() {
                let notional = mul(&tr.amount, &tr.price)?;
                self.record_volume(&tr.buyer, &notional)?;
                self.record_volume(&tr.seller, &notional)?;
            }
        }
        let rest = exact(ended.remaining().ok())?;
        if positive(&rest) && ended.is_active() {
            if buy {
                self.transfer(sender, &escrow, &quote, &mul(&rest, &ended.price)?, false)?;
            } else {
                self.transfer(sender, &escrow, &base, &rest, false)?;
            }
        }
        Ok(())
    }

    /// ``_op_cancel_order`` on the pair's book: (gas, data).
    fn cancel(&mut self, op: &OpIn) -> R<(i64, Bound<'_, PyDict>)> {
        let pair = op.pair;
        if self.pairs[pair].has_stops {
            return Err(Stop::Python);
        }
        let (base, quote, escrow) = {
            let p = &self.pairs[pair];
            (p.base.clone(), p.quote.clone(), p.escrow.clone())
        };
        let found = {
            let book = &mut self.books[pair].book;
            book.last.clear();
            book.cancel_order(&op.order_id, &op.sender)
        };
        let order = match found {
            Ok(Some(o)) => o,
            Ok(None) => return refused(format!("Order {} not found", op.order_id), 0),
            Err(Fail::Refused(m)) => return refused(m, 0),
            Err(Fail::Native) => return Err(Stop::Python),
        };
        self.take_changed(pair);
        // ``_refund_escrow``
        let amount = exact(order.remaining().ok())?;
        if positive(&amount) {
            let owner = order.owner.clone();
            if order.side == Side::Buy {
                self.transfer(&escrow, &owner, &quote, &mul(&amount, &order.price)?, true)?;
            } else {
                self.transfer(&escrow, &owner, &base, &amount, true)?;
            }
        }
        let built = (|| -> PyResult<Bound<'_, PyDict>> {
            let data = PyDict::new_bound(self.py);
            data.set_item("order_id", &op.order_id)?;
            data.set_item("status", "cancelled")?;
            Ok(data)
        })();
        Ok((self.c.cancel_gas, built.map_err(|_| Stop::Python)?))
    }
}

struct OpIn {
    kind: u8, // 0 a cancel, 1 an order, 2 a swap
    lane: String,
    nonce: i64,
    sender: String,
    payer: String,
    reserved: String,
    gas_limit: i64,
    gas_price: i64,
    pair: usize,
    order_id: String,
}

/// ``_spot_fee`` for an owner as it stands (its rates from ``fee_rates``).
fn spot_fee_of(
    o: &Owner,
    rates: &(Dec, Dec),
    c: &Consts,
    is_maker: bool,
    value: &Dec,
) -> R<(Dec, Dec, Option<Id>)> {
    let rate = if !is_maker {
        rates.0.clone()
    } else if positive(&rates.1) {
        rates.1.clone()
    } else {
        Dec::zero()
    };
    let fee = q18(&mul(value, &rate)?, Rounding::HalfUp)?;
    let Some((referrer, volume)) = o.referral.clone().filter(|_| positive(&fee)) else {
        return Ok((fee, Dec::zero(), None));
    };
    let fee = if lt(&volume, &c.referral_cap) {
        q18(&mul(&fee, &c.referee_keep)?, Rounding::HalfUp)?
    } else {
        fee
    };
    let reward = q18(&mul(&fee, &c.referrer_share)?, Rounding::Down)?;
    Ok((fee, reward, Some(referrer)))
}

/// A swap: the tokens (``token_in`` native or not), the amount, the least it accepts, its
/// deadline (0: none), and the paths it may take — each a list of hops (token in, token out,
/// the pair's slot, or -1 where no book trades the pair).
struct SwapIn {
    token_in: Asset,
    amount_in: String,
    min_out: String,
    deadline: f64,
    paths: Vec<Vec<(String, String, i64)>>,
}

/// A fill as a result reports it: the book's (``_clob_fills``) or a pool's (``_amm_fill``).
enum FillOut {
    Book {
        market: String,
        trade: Trade,
        taker: Id,
        side: Side,
    },
    Pool {
        market: String,
        pool_id: String,
        price: String,
        amount: Dec,
        quote_amount: Dec,
        holder: Id,
        taker: Id,
        side: Side,
    },
}

impl FillOut {
    fn to_py<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new_bound(py);
        match self {
            FillOut::Book { market, trade: t, taker, side } => {
                d.set_item("market", market)?;
                d.set_item("venue", "clob")?;
                d.set_item("trade_id", &t.id)?;
                d.set_item("price", text(&t.price))?;
                d.set_item("amount", text(&t.amount))?;
                d.set_item("buyer", &*t.buyer)?;
                d.set_item("seller", &*t.seller)?;
                let maker = if t.buyer == *taker { &t.seller } else { &t.buyer };
                d.set_item("maker", &**maker)?;
                d.set_item("taker", &**taker)?;
                d.set_item("side", side.value())?;
                d.set_item("maker_order_id", &*t.maker_order_id)?;
                d.set_item("taker_order_id", &*t.taker_order_id)?;
                let fees = PyDict::new_bound(py);
                let of = |who: &Id| if who == taker { &t.taker_fee } else { &t.maker_fee };
                fees.set_item(&*t.buyer, text(of(&t.buyer)))?;
                fees.set_item(&*t.seller, text(of(&t.seller)))?;
                d.set_item("fees", fees)?;
            }
            FillOut::Pool { market, pool_id, price, amount, quote_amount, holder, taker, side } => {
                let buy = *side == Side::Buy;
                let (buyer, seller) = if buy { (taker, holder) } else { (holder, taker) };
                d.set_item("market", market)?;
                d.set_item("venue", "amm")?;
                d.set_item("pool_id", pool_id)?;
                d.set_item("price", price)?;
                d.set_item("amount", text(amount))?;
                d.set_item("quote_amount", text(quote_amount))?;
                d.set_item("buyer", &**buyer)?;
                d.set_item("seller", &**seller)?;
                d.set_item("maker", &**holder)?;
                d.set_item("taker", &**taker)?;
                d.set_item("side", side.value())?;
            }
        }
        Ok(d)
    }
}

/// ``Router._deterministic_clob_order_id``: blake2b-8 of ``router:{sender}:{seq}``, in hex.
fn router_order_id(sender: &str, seq: i64) -> String {
    use blake2::digest::{Update, VariableOutput};
    let mut h = blake2::Blake2bVar::new(8).expect("8 bytes");
    h.update(format!("router:{sender}:{seq}").as_bytes());
    let mut out = [0u8; 8];
    h.finalize_variable(&mut out).expect("8 bytes");
    out.iter().map(|b| format!("{b:02x}")).collect()
}

fn router_eq(a: &Dec, b: &Dec) -> bool {
    a.cmp(b) == Ordering::Equal
}

/// A pool's leg of an order (``_amm_fill``).
struct PoolFill {
    pool_id: String,
    holder: Id,
    amount_in: Dec,
    amount_out: Dec,
}

/// Python's ``min`` / ``max`` of a list: the first of the smallest / largest.
fn router_min(xs: &[Dec]) -> Option<&Dec> {
    xs.iter().fold(None, |best: Option<&Dec>, x| match best {
        Some(b) if !lt(x, b) => Some(b),
        _ => Some(x),
    })
}
fn router_max(xs: &[Dec]) -> Option<&Dec> {
    xs.iter().fold(None, |best: Option<&Dec>, x| match best {
        Some(b) if !lt(b, x) => Some(b),
        _ => Some(x),
    })
}

struct PlaceIn {
    market: bool,
    side: Side,
    price: String,
    amount: String,
    tif: String,
    hidden: bool,
    display_size: String,
    timestamp: f64,
    makers: i64,
}

type OpTuple = (
    (u8, String, i64, String, String, String, i64, i64, usize, String),
    Option<(bool, String, String, String, String, bool, String, f64, i64)>,
    Option<SwapTuple>,
);

/// (token_in, whether it is native QRDX, amount_in, min_amount_out, deadline, the paths
/// [[(token in, token out, pair slot or -1)]]).
type SwapTuple = (String, bool, String, String, f64, Vec<Vec<(String, String, i64)>>);

/// A pool as Python gives it: (id, its holder, fee rate, √price Q96, tick, liquidity, fee growth
/// 0 and 1, initialized ticks [(tick, liquidity_net, √ratio)], (√ratio and tick at the minimum
/// and maximum)).
type PoolTuple = (
    String,
    String,
    String,
    String,
    i64,
    String,
    String,
    String,
    Vec<(i64, String, String)>,
    (String, String, i64, i64),
);

type PairTuple<'py> = (
    Bound<'py, NativeBook>,
    Bound<'py, PyDict>,
    String,
    (String, bool, bool),
    (String, bool, bool),
    String,
    Vec<PoolTuple>,
    (bool, bool, bool),
    Vec<String>,
    (Option<String>, Option<String>),
);

type Written = (String, String, Option<String>);
type TokenWritten = ((String, String), String, Option<String>);

/// What a run did: (operations run; each one's (success, gas used, fee, error, data); QRDX
/// entries written, then token entries, each (key, delta, loaded balance or None) in the order
/// first written; the lanes' new nonces; the books' new owner nonces (pair, owner, nonce); the
/// fee tokens' new pending amounts; the block's fees and staker fees; orders placed; the orders
/// handed out that changed (pair, order); the pairs whose handed-out orders a failure detached;
/// the clearinghouse's volumes, lifetime volumes and referral volumes written, each in order).
type RunOut<'py> = (
    usize,
    Vec<(bool, i64, String, String, Option<Bound<'py, PyDict>>)>,
    Vec<Written>,
    Vec<TokenWritten>,
    Vec<(String, i64)>,
    Vec<(usize, String, i64)>,
    Vec<(String, String)>,
    (String, String),
    usize,
    Vec<(usize, Bound<'py, PyDict>)>,
    Vec<usize>,
    (VolumesOut, PoolsOut),
);

/// The plans applied, (pair, pool, plan) in order — a plan as (zero_for_one, amount_in,
/// amount_out, fee, protocol_fee, √price Q96, tick, liquidity, fee growth, crossings
/// [(tick, fg0, fg1)], exhausted) — the pairs ``_flag_self_pass`` marks, the swaps done, the
/// router's order-book sequence.
type PoolsOut = (Vec<(usize, usize, PlanOut)>, Vec<usize>, usize, i64);
type PlanOut = (
    bool,
    String,
    String,
    String,
    String,
    String,
    i64,
    String,
    String,
    Vec<(i64, String, String)>,
    bool,
);

type VolumesOut = (
    Vec<(String, Vec<(i64, String)>)>,
    Vec<(String, String)>,
    Vec<(String, String)>,
);

/// ``process_transaction`` over a run of plain spot orders and cancels judged includable (the
/// module's comment, and qrdx/exchange/order_lane.py, which builds the arguments).
#[pyfunction]
#[allow(clippy::too_many_arguments)]
pub fn order_lane_run<'py>(
    py: Python<'py>,
    ops: Vec<OpTuple>,
    pairs: Vec<PairTuple<'py>>,
    frozen: Vec<(String, String)>,
    parents: HashSet<String>,
    dicts: (Bound<'py, PyDict>, Bound<'py, PyDict>, Bound<'py, PyDict>, Bound<'py, PyDict>),
    lanes: Bound<'py, PyDict>,
    fee_tokens: Bound<'py, PyDict>,
    owner_info: Bound<'py, PyAny>,
    amm: (Bound<'py, PyAny>, bool, i64),
    consts: (String, String, String, String, String, String, i64, f64, i64, i64, i64),
    tiers: (Vec<(String, String, String)>, i64, i64, String, String, String, i64),
    totals: (String, String),
    floors: HashMap<String, String>,
) -> PyResult<RunOut<'py>> {
    let bad = |what: &str| pyo3::exceptions::PyValueError::new_err(format!("order lane: {what}"));
    let dec = |s: &str| Dec::parse(s).ok_or_else(|| bad(s));
    let mut books = Vec::with_capacity(pairs.len());
    let mut pair_list = Vec::with_capacity(pairs.len());
    let mut pool_states: Vec<((usize, usize), Pool)> = Vec::new();
    for (slot, (book, nonces, name, base, quote, escrow, pools, flags, handed, triggers)) in
        pairs.into_iter().enumerate()
    {
        books.push(book.try_borrow_mut()?);
        let asset = |a: (String, bool, bool)| Asset {
            name: Id::from(a.0.as_str()),
            native: a.1,
            paused: a.2,
        };
        let pool_count = pools.len();
        let holders: Vec<Id> = pools.iter().map(|p| Id::from(p.1.as_str())).collect();
        for (i, (id, _holder, fee, sqrt, tick, liquidity, fg0, fg1, ticks, ends)) in
            pools.into_iter().enumerate()
        {
            let mut t = Vec::with_capacity(ticks.len());
            for (k, net, ratio) in ticks {
                t.push((k, dec(&net)?, dec(&ratio)?));
            }
            pool_states.push((
                (slot, i),
                Pool {
                    id,
                    fee: dec(&fee)?,
                    sqrt: dec(&sqrt)?,
                    tick,
                    liquidity: dec(&liquidity)?,
                    fg0: dec(&fg0)?,
                    fg1: dec(&fg1)?,
                    ticks: std::sync::Arc::new(t),
                    min_ratio: dec(&ends.0)?,
                    max_ratio: dec(&ends.1)?,
                    min_tick: ends.2,
                    max_tick: ends.3,
                },
            ));
        }
        pair_list.push(Pair {
            nonces,
            name,
            base: asset(base),
            quote: asset(quote),
            escrow: Id::from(escrow.as_str()),
            pool_count,
            holders,
            places_bail: flags.0,
            tier: flags.1,
            has_stops: flags.2,
            handed: handed.into_iter().collect(),
            min_above: triggers.0.as_deref().map(dec).transpose()?,
            max_below: triggers.1.as_deref().map(dec).transpose()?,
        });
    }
    let c = Consts {
        treasury: Id::from(consts.0.as_str()),
        staker_holder: Id::from(consts.1.as_str()),
        staker_share: dec(&consts.2)?,
        referee_keep: dec(&consts.3)?,
        referrer_share: dec(&consts.4)?,
        wei: dec(&consts.5)?,
        height: consts.6,
        now: consts.7,
        place_gas: consts.8,
        cancel_gas: consts.9,
        per_maker: consts.10,
        tiers: tiers
            .0
            .iter()
            .map(|(f, t, m)| Ok((dec(f)?, dec(t)?, dec(m)?)))
            .collect::<PyResult<Vec<_>>>()?,
        volume_days: tiers.1,
        day: tiers.2,
        vault: Id::from(tiers.3.as_str()),
        protocol: Id::from(tiers.4.as_str()),
        referral_cap: dec(&tiers.5)?,
        router_paused: amm.1,
        swap_gas: tiers.6,
    };
    if c.tiers.is_empty() {
        return Err(bad("fee tiers"));
    }
    let mut block_fees = dec(&totals.0)?;
    let mut run = Run {
        py,
        books,
        pairs: &pair_list,
        dicts: Dicts {
            deltas: dicts.0,
            avail: dicts.1,
            token_deltas: dicts.2,
            token_avail: dicts.3,
        },
        fee_tokens_dict: fee_tokens,
        owner_fn: owner_info,
        amm_fn: amm.0,
        frozen: frozen.into_iter().collect(),
        parents,
        c,
        changes: Changes {
            entries: IMap::new(),
            written: IMap::new(),
            order: Vector::new(),
            book_nonces: IMap::new(),
            book_nonce_order: Vector::new(),
            fee_tokens: IMap::new(),
            fee_token_order: Vector::new(),
            staker_fees: dec(&totals.1)?,
            owners: IMap::new(),
            volume_order: Vector::new(),
            lifetime_order: Vector::new(),
            referral_order: Vector::new(),
            pools: pool_states.into_iter().collect(),
            applied: Vector::new(),
            uncross: Vector::new(),
            swaps: 0,
        },
        changed: Vec::new(),
        clob_sequence: amm.2,
        floors: floors
            .iter()
            .map(|(a, f)| Ok((Id::from(a.as_str()), dec(f)?)))
            .collect::<PyResult<HashMap<_, _>>>()?,
    };
    let mut lane_nonces: HashMap<String, i64> = HashMap::new();
    let mut lane_order: Vec<String> = Vec::new();
    let mut results = Vec::with_capacity(ops.len());
    let mut handed: HashMap<(usize, Id), Order> = HashMap::new();
    let mut detached: Vec<usize> = Vec::new();
    let mut placed = 0usize;
    let mut done = 0usize;

    for (head_in, place_in, swap_in) in ops {
        let op = OpIn {
            kind: head_in.0,
            lane: head_in.1,
            nonce: head_in.2,
            sender: head_in.3,
            payer: head_in.4,
            reserved: head_in.5,
            gas_limit: head_in.6,
            gas_price: head_in.7,
            pair: head_in.8,
            order_id: head_in.9,
        };
        if op.pair >= run.pairs.len() {
            break;
        }
        // The wrapper's own checks: a judged block's operation passes them (Python raises).
        let expected = match lane_nonces.get(&op.lane) {
            Some(n) => *n,
            None => match lanes.get_item(&op.lane).map(|v| v.map(|v| v.extract::<i64>())) {
                Ok(None) => 0,
                Ok(Some(Ok(n))) => n,
                _ => break,
            },
        };
        let base_gas = match op.kind {
            0 => run.c.cancel_gas,
            1 => run.c.place_gas,
            _ => run.c.swap_gas,
        };
        if expected != op.nonce || op.gas_limit < base_gas {
            break;
        }
        let swap = match (&swap_in, op.kind) {
            (Some(w), 2) => Some(SwapIn {
                token_in: Asset { name: Id::from(w.0.as_str()), native: w.1, paused: false },
                amount_in: w.2.clone(),
                min_out: w.3.clone(),
                deadline: w.4,
                paths: w.5.clone(),
            }),
            (None, 0 | 1) => None,
            _ => break,
        };
        let place = match (&place_in, op.kind == 1) {
            (Some(p), true) => Some(PlaceIn {
                market: p.0,
                side: match p.1.as_str() {
                    "buy" => Side::Buy,
                    "sell" => Side::Sell,
                    _ => break,
                },
                price: p.2.clone(),
                amount: p.3.clone(),
                tif: p.4.clone(),
                hidden: p.5,
                display_size: p.6.clone(),
                timestamp: p.7,
                makers: p.8,
            }),
            (None, false) => None,
            _ => break,
        };
        // The operation, all or nothing.
        let saved = run.changes.clone();
        let saved_books: Vec<_> = run.books.iter().map(|b| b.book.state.clone()).collect();
        let saved_sequence = run.clob_sequence;
        run.changed.clear();
        let outcome = match (&place, &swap) {
            (Some(p), _) => run.place(&op, p).map(|(g, d)| (g, d.unbind())),
            (None, Some(w)) => run.swap(&op, w).map(|(g, d)| (g, d.unbind())),
            (None, None) => run.cancel(&op).map(|(g, d)| (g, d.unbind())),
        };
        let (success, gas, error, data) = match outcome {
            Ok((gas, data)) => {
                for (pair, o) in run.changed.drain(..) {
                    handed.insert((pair, o.id.clone()), o);
                }
                if op.kind == 1 {
                    placed += 1;
                }
                (true, gas, String::new(), Some(data.into_bound(py)))
            }
            Err(Stop::Refused(message, gas)) => {
                // (the router's sequence is not taken back: Python's is not either)
                run.changes = saved;
                for (b, state) in run.books.iter_mut().zip(saved_books) {
                    b.book.state = state;
                    b.book.last.clear();
                }
                for (pair, _) in run.changed.drain(..) {
                    if !detached.contains(&pair) {
                        detached.push(pair);
                    }
                }
                (false, gas, message, None)
            }
            Err(Stop::Python) => {
                run.changes = saved;
                run.clob_sequence = saved_sequence;
                for (b, state) in run.books.iter_mut().zip(saved_books) {
                    b.book.state = state;
                    b.book.last.clear();
                }
                break;
            }
        };
        // Its nonce, then its gas: the reservation back, less what it used.
        if !lane_nonces.contains_key(&op.lane) {
            lane_order.push(op.lane.clone());
        }
        lane_nonces.insert(op.lane.clone(), op.nonce + 1);
        let used = if gas == 0 { base_gas } else { gas.min(op.gas_limit) };
        let fee = div(
            &mul(&int(used).map_err(|_| bad("gas"))?, &int(op.gas_price).map_err(|_| bad("gas"))?)
                .map_err(|_| bad("fee"))?,
            &run.c.wei,
        )
        .map_err(|_| bad("fee"))?;
        let back = sub(&parse(&op.reserved).map_err(|_| bad("reserved"))?, &fee).map_err(|_| bad("fee"))?;
        if run.record(Key::Qrdx(Id::from(op.payer.as_str())), &back).is_err() {
            return Err(bad("the payer's entry"));
        }
        block_fees = add(&block_fees, &fee).map_err(|_| bad("fees"))?;
        results.push((success, used, text(&fee), error, data));
        done += 1;
    }

    // What the run wrote, for Python to write back.
    let ch = &run.changes;
    let mut qrdx_out = Vec::new();
    let mut token_out = Vec::new();
    for key in ch.order.iter() {
        let e = &ch.entries[key];
        let delta = text(e.delta.as_ref().expect("a written entry has a delta"));
        let avail = e.avail.as_ref().map(text);
        match key {
            Key::Qrdx(a) => qrdx_out.push((a.to_string(), delta, avail)),
            Key::Token(a, t) => token_out.push(((a.to_string(), t.to_string()), delta, avail)),
        }
    }
    let lanes_out = lane_order.into_iter().map(|l| {
        let n = lane_nonces[&l];
        (l, n)
    });
    let book_nonces_out = ch
        .book_nonce_order
        .iter()
        .map(|k| (k.0, k.1.to_string(), ch.book_nonces[k]))
        .collect();
    let fee_tokens_out = ch
        .fee_token_order
        .iter()
        .map(|t| (t.to_string(), text(&ch.fee_tokens[t])))
        .collect();
    let mut handed_out = Vec::new();
    for ((pair, _), o) in handed {
        handed_out.push((pair, crate::book::order_dict(py, &o)?));
    }
    let owner = |id: &Id| &ch.owners[id];
    let volumes = (
        ch.volume_order
            .iter()
            .map(|id| (id.to_string(), owner(id).days.iter().map(|(d, n)| (*d, text(n))).collect()))
            .collect(),
        ch.lifetime_order.iter().map(|id| (id.to_string(), text(&owner(id).lifetime))).collect(),
        ch.referral_order
            .iter()
            .map(|id| (id.to_string(), text(&owner(id).referral.as_ref().expect("a referral").1)))
            .collect(),
    );
    let plan_out = |pl: &Plan| -> PlanOut {
        (
            pl.zfo,
            text(&pl.amount_in),
            text(&pl.amount_out),
            text(&pl.fee),
            text(&pl.protocol_fee),
            text(&pl.sqrt),
            pl.tick,
            text(&pl.liquidity),
            text(&pl.fg),
            pl.crossings.iter().map(|(t, a, b)| (*t, text(a), text(b))).collect(),
            pl.exhausted,
        )
    };
    let pools_out: PoolsOut = (
        ch.applied.iter().map(|(pair, i, pl)| (*pair, *i, plan_out(pl))).collect(),
        ch.uncross.iter().copied().collect(),
        ch.swaps,
        run.clob_sequence,
    );
    Ok((
        done,
        results,
        qrdx_out,
        token_out,
        lanes_out.collect(),
        book_nonces_out,
        fee_tokens_out,
        (text(&block_fees), text(&ch.staker_fees)),
        placed,
        handed_out,
        detached,
        (volumes, pools_out),
    ))
}
