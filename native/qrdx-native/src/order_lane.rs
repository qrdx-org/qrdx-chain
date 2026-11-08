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
    buy_pool: Option<Dec>,
    sell_pool: Option<Dec>,
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
}

struct Run<'a, 'py> {
    py: Python<'py>,
    books: Vec<PyRefMut<'py, NativeBook>>,
    pairs: &'a [Pair<'py>],
    dicts: Dicts<'py>,
    fee_tokens_dict: Bound<'py, PyDict>,
    owner_fn: Bound<'py, PyAny>,
    frozen: HashSet<(String, String)>,
    parents: HashSet<String>,
    c: Consts,
    changes: Changes,
    // what the operation in progress changed of its book's orders: (book, order) as it last was
    changed: Vec<(usize, Order)>,
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
        };
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
        let o = self.owner(owner)?;
        let (taker, maker) = self.fee_rates(&o)?;
        let rate = if !is_maker {
            taker
        } else if positive(&maker) {
            maker
        } else {
            Dec::zero()
        };
        let fee = q18(&mul(value, &rate)?, Rounding::HalfUp)?;
        let Some((referrer, volume)) = o.referral.filter(|_| positive(&fee)) else {
            return Ok((fee, Dec::zero(), None));
        };
        let fee = if lt(&volume, &self.c.referral_cap) {
            q18(&mul(&fee, &self.c.referee_keep)?, Rounding::HalfUp)?
        } else {
            fee
        };
        let reward = q18(&mul(&fee, &self.c.referrer_share)?, Rounding::Down)?;
        Ok((fee, reward, Some(referrer)))
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

    /// ``_op_place_order`` for a plain limit order: (gas, data). The caller keeps the book and
    /// the changes from before it, and puts them back if it stops.
    fn place(&mut self, op: &OpIn, p: &PlaceIn) -> R<(i64, Bound<'_, PyDict>)> {
        let pair = op.pair;
        let pr = &self.pairs[pair];
        if pr.places_bail {
            return Err(Stop::Python);
        }
        let buy = p.side == Side::Buy;
        let price = parse(&p.price)?;
        let amount = parse(&p.amount)?;
        // An order that reaches a pool's price takes from the pool first: Python's.
        if buy {
            if pr.buy_pool.as_ref().is_some_and(|e| lt(e, &price)) {
                return Err(Stop::Python);
            }
        } else if pr.sell_pool.as_ref().is_some_and(|e| lt(&price, e)) {
            return Err(Stop::Python);
        }
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
        // The operation's scope: the book starts the block, then the order is placed.
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
            kind: Kind::Limit,
            price: price.clone(),
            amount,
            filled: Dec::zero(),
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
        // ``_record_spot_prices``: fills that reach a waiting trigger mark it (Python's).
        if let Some(first) = trades.first() {
            let (mut lo, mut hi) = (&first.price, &first.price);
            for t in &trades[1..] {
                if lt(&t.price, lo) {
                    lo = &t.price;
                }
                if lt(hi, &t.price) {
                    hi = &t.price;
                }
            }
            let rises = min_above.as_ref().is_some_and(|p| !lt(hi, p));
            let falls = max_below.as_ref().is_some_and(|p| !lt(p, lo));
            if rises || falls {
                return Err(Stop::Python);
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
        let data = self.placed_data(pair, &op.order_id, &trades, &ended, &sender, p.side)?;
        Ok((gas, data))
    }

    fn placed_data(
        &self,
        pair: usize,
        order_id: &str,
        trades: &[Trade],
        ended: &Order,
        taker: &Id,
        side: Side,
    ) -> R<Bound<'_, PyDict>> {
        let py = self.py;
        let name = &self.pairs[pair].name;
        let built = (|| -> PyResult<Bound<'_, PyDict>> {
            let fills = PyList::empty_bound(py);
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
            data.set_item("trades", trades.len())?;
            data.set_item("filled", text(&ended.filled))?;
            data.set_item("fills", fills)?;
            Ok(data)
        })();
        built.map_err(|_| Stop::Python)
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
    place: bool,
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

struct PlaceIn {
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
    (bool, String, i64, String, String, String, i64, i64, usize, String),
    Option<(String, String, String, String, bool, String, f64, i64)>,
);

type PairTuple<'py> = (
    Bound<'py, NativeBook>,
    Bound<'py, PyDict>,
    String,
    (String, bool, bool),
    (String, bool, bool),
    String,
    Option<String>,
    Option<String>,
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
    VolumesOut,
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
    consts: (String, String, String, String, String, String, i64, f64, i64, i64, i64),
    tiers: (Vec<(String, String, String)>, i64, i64, String, String, String),
    totals: (String, String),
) -> PyResult<RunOut<'py>> {
    let bad = |what: &str| pyo3::exceptions::PyValueError::new_err(format!("order lane: {what}"));
    let dec = |s: &str| Dec::parse(s).ok_or_else(|| bad(s));
    let mut books = Vec::with_capacity(pairs.len());
    let mut pair_list = Vec::with_capacity(pairs.len());
    for (book, nonces, name, base, quote, escrow, buy_pool, sell_pool, flags, handed, triggers) in
        pairs
    {
        books.push(book.try_borrow_mut()?);
        let asset = |a: (String, bool, bool)| Asset {
            name: Id::from(a.0.as_str()),
            native: a.1,
            paused: a.2,
        };
        pair_list.push(Pair {
            nonces,
            name,
            base: asset(base),
            quote: asset(quote),
            escrow: Id::from(escrow.as_str()),
            buy_pool: buy_pool.as_deref().map(dec).transpose()?,
            sell_pool: sell_pool.as_deref().map(dec).transpose()?,
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
        },
        changed: Vec::new(),
    };
    let mut lane_nonces: HashMap<String, i64> = HashMap::new();
    let mut lane_order: Vec<String> = Vec::new();
    let mut results = Vec::with_capacity(ops.len());
    let mut handed: HashMap<(usize, Id), Order> = HashMap::new();
    let mut detached: Vec<usize> = Vec::new();
    let mut placed = 0usize;
    let mut done = 0usize;

    for (head_in, place_in) in ops {
        let op = OpIn {
            place: head_in.0,
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
        let base_gas = if op.place { run.c.place_gas } else { run.c.cancel_gas };
        if expected != op.nonce || op.gas_limit < base_gas {
            break;
        }
        let place = match (&place_in, op.place) {
            (Some(p), true) => Some(PlaceIn {
                side: match p.0.as_str() {
                    "buy" => Side::Buy,
                    "sell" => Side::Sell,
                    _ => break,
                },
                price: p.1.clone(),
                amount: p.2.clone(),
                tif: p.3.clone(),
                hidden: p.4,
                display_size: p.5.clone(),
                timestamp: p.6,
                makers: p.7,
            }),
            (None, false) => None,
            _ => break,
        };
        // The operation, all or nothing.
        let saved = run.changes.clone();
        let saved_book = run.books[op.pair].book.state.clone();
        run.changed.clear();
        let outcome = match &place {
            Some(p) => run.place(&op, p).map(|(g, d)| (g, d.unbind())),
            None => run.cancel(&op).map(|(g, d)| (g, d.unbind())),
        };
        let (success, gas, error, data) = match outcome {
            Ok((gas, data)) => {
                for (pair, o) in run.changed.drain(..) {
                    handed.insert((pair, o.id.clone()), o);
                }
                if op.place {
                    placed += 1;
                }
                (true, gas, String::new(), Some(data.into_bound(py)))
            }
            Err(Stop::Refused(message, gas)) => {
                run.changes = saved;
                let book = &mut run.books[op.pair].book;
                book.state = saved_book;
                book.last.clear();
                if !run.changed.is_empty() && !detached.contains(&op.pair) {
                    detached.push(op.pair);
                }
                (false, gas, message, None)
            }
            Err(Stop::Python) => {
                run.changes = saved;
                let book = &mut run.books[op.pair].book;
                book.state = saved_book;
                book.last.clear();
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
        volumes,
    ))
}
