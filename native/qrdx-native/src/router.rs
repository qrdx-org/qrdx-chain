//! A pair's pools and the router's walk of its combined market, for the order lane
//! (qrdx/exchange/amm.py, qrdx/exchange/router.py; docs/EXCHANGE_ENGINE.md, E5).
//!
//! Python is the reference, step for step: ``ConcentratedLiquidityPool.quote`` (a partial
//! quote, as the router always asks) with ``_swap_step`` / ``_swap_step_out`` and the amount
//! and √price functions under their own rounding contexts, ``liquid_sqrt``, ``SwapPlan.then``,
//! and ``Router.plan_fill`` for an order (the base it buys or sells: the pools quoted by what
//! they deliver for a buy). Values keep Python's spelling wherever it can travel on (a
//! ``min`` takes the first of equal values, a sort is stable).
//!
//! Three values are Python's own, asked for (``Transcendental``): the tick at a √price (a
//! logarithm), a square root (a limit's √price), a pool's end price (``(√p / Q96) ** 2``, a
//! power): exactly what Python computes, rather than a port of ``decimal``'s transcendental
//! functions. Each tick's √ratio comes with the pool.

use std::cmp::Ordering;
use std::sync::Arc;

use crate::book::{Book, Id};
use crate::dec::{Ctx, Dec, Rounding};

/// Python's ``_CTX`` (amm, router, orderbook) and ``_UP`` / ``_DOWN``.
const HALF: Ctx = Ctx::new(78, Rounding::HalfEven);
const UP: Ctx = Ctx::new(78, Rounding::Ceiling);
const DOWN: Ctx = Ctx::new(78, Rounding::Floor);
const SPLIT_STEPS: usize = 40;

/// Something Python would raise on, or a value not reproduced: the operation is Python's.
pub(crate) struct Bail;

pub(crate) type RR<T> = Result<T, Bail>;

fn ok(v: Option<Dec>) -> RR<Dec> {
    v.ok_or(Bail)
}
fn add(a: &Dec, b: &Dec, c: &Ctx) -> RR<Dec> {
    ok(a.add(b, c))
}
fn sub(a: &Dec, b: &Dec, c: &Ctx) -> RR<Dec> {
    ok(a.sub(b, c))
}
fn mul(a: &Dec, b: &Dec, c: &Ctx) -> RR<Dec> {
    ok(a.mul(b, c))
}
fn div(a: &Dec, b: &Dec, c: &Ctx) -> RR<Dec> {
    ok(a.div(b, c))
}
fn lt(a: &Dec, b: &Dec) -> bool {
    a.cmp(b) == Ordering::Less
}
fn le(a: &Dec, b: &Dec) -> bool {
    a.cmp(b) != Ordering::Greater
}
fn eq(a: &Dec, b: &Dec) -> bool {
    a.cmp(b) == Ordering::Equal
}
fn positive(a: &Dec) -> bool {
    !a.is_zero() && !a.neg
}
fn zero() -> Dec {
    Dec::zero()
}
fn one() -> Dec {
    Dec::parse("1").expect("1")
}
fn q96() -> Dec {
    Dec::parse("79228162514264337593543950336").expect("2**96")
}
/// Python's ``-x`` under ``_CTX``: a zero stays positive.
fn negate(a: &Dec) -> RR<Dec> {
    let n = if a.is_zero() { Dec { neg: false, ..a.clone() } } else { a.neg() };
    ok(n.fix(&HALF))
}
/// ``x.quantize(AMOUNT_QUANTUM, rounding)`` under ``ctx``.
fn q18(a: &Dec, rounding: Rounding, ctx: &Ctx) -> RR<Dec> {
    ok(a.quantize(-18, rounding, ctx))
}
/// Python's ``min`` of a sequence: the first of the smallest.
fn py_min<'a>(items: impl IntoIterator<Item = &'a Dec>) -> Option<&'a Dec> {
    let mut best: Option<&Dec> = None;
    for x in items {
        if best.is_none_or(|b| lt(x, b)) {
            best = Some(x);
        }
    }
    best
}
fn py_max<'a>(items: impl IntoIterator<Item = &'a Dec>) -> Option<&'a Dec> {
    let mut best: Option<&Dec> = None;
    for x in items {
        if best.is_none_or(|b| lt(b, x)) {
            best = Some(x);
        }
    }
    best
}

/// Python's own values (module comment).
pub(crate) trait Transcendental {
    /// ``amm._tick_at(s)``: the tick of a plain √price.
    fn tick_at(&mut self, s: &Dec) -> RR<i64>;
    /// ``x.sqrt()`` under ``_CTX``.
    fn sqrt(&mut self, x: &Dec) -> RR<Dec>;
    /// ``(q96 / Q96) ** 2`` under ``_CTX``: a plain price.
    fn squared(&mut self, q96: &Dec) -> RR<Dec>;
}

// ── a pool ──────────────────────────────────────────────────────────────────────────────────

/// A pool as the router reads it (``PoolState``), and as the run moves it.
#[derive(Clone)]
pub(crate) struct Pool {
    pub id: String,
    pub fee: Dec,   // fee_tier.rate
    pub sqrt: Dec,  // Q96
    pub tick: i64,
    pub liquidity: Dec,
    pub fg0: Dec,
    pub fg1: Dec,
    /// Initialized ticks, ascending: (tick, liquidity_net, its plain √ratio).
    pub ticks: Arc<Vec<(i64, Dec, Dec)>>,
    pub min_ratio: Dec, // _sqrt_ratio(MIN_TICK)
    pub max_ratio: Dec, // _sqrt_ratio(MAX_TICK)
    pub min_tick: i64,
    pub max_tick: i64,
}

/// ``SwapPlan``.
#[derive(Clone, Debug)]
pub(crate) struct Plan {
    pub zfo: bool,
    pub amount_in: Dec,
    pub amount_out: Dec,
    pub fee: Dec,
    pub protocol_fee: Dec,
    pub sqrt: Dec, // Q96
    pub tick: i64,
    pub liquidity: Dec,
    pub fg: Dec,
    pub crossings: Vec<(i64, Dec, Dec)>,
    pub exhausted: bool,
}

impl Plan {
    /// ``SwapPlan.then``.
    fn then(&self, nxt: &Plan) -> RR<Plan> {
        let mut crossings = self.crossings.clone();
        crossings.extend(nxt.crossings.iter().cloned());
        Ok(Plan {
            zfo: self.zfo,
            amount_in: add(&self.amount_in, &nxt.amount_in, &HALF)?,
            amount_out: add(&self.amount_out, &nxt.amount_out, &HALF)?,
            fee: add(&self.fee, &nxt.fee, &HALF)?,
            protocol_fee: add(&self.protocol_fee, &nxt.protocol_fee, &HALF)?,
            sqrt: nxt.sqrt.clone(),
            tick: nxt.tick,
            liquidity: nxt.liquidity.clone(),
            fg: nxt.fg.clone(),
            crossings,
            exhausted: nxt.exhausted,
        })
    }
}

/// ``amount0_delta``: token0 between plain √prices for liquidity L.
fn amount0_delta(s_a: &Dec, s_b: &Dec, liquidity: &Dec, round_up: bool) -> RR<Dec> {
    let (s_a, s_b) = if lt(s_b, s_a) { (s_b, s_a) } else { (s_a, s_b) };
    if !positive(liquidity) || eq(s_a, s_b) {
        return Ok(zero());
    }
    let (hi, lo) = if round_up { (&UP, &DOWN) } else { (&DOWN, &UP) };
    let numerator = mul(liquidity, &sub(s_b, s_a, hi)?, hi)?;
    let denominator = mul(s_a, s_b, lo)?;
    let value = div(&numerator, &denominator, hi)?;
    q18(&value, if round_up { Rounding::Ceiling } else { Rounding::Floor }, &HALF)
}

/// ``amount1_delta``: token1 between plain √prices for liquidity L.
fn amount1_delta(s_a: &Dec, s_b: &Dec, liquidity: &Dec, round_up: bool) -> RR<Dec> {
    let (s_a, s_b) = if lt(s_b, s_a) { (s_b, s_a) } else { (s_a, s_b) };
    if !positive(liquidity) || eq(s_a, s_b) {
        return Ok(zero());
    }
    let c = if round_up { &UP } else { &DOWN };
    let value = mul(liquidity, &sub(s_b, s_a, c)?, c)?;
    q18(&value, if round_up { Rounding::Ceiling } else { Rounding::Floor }, &HALF)
}

fn next_sqrt_from_input(s: &Dec, liquidity: &Dec, amount: &Dec, zfo: bool) -> RR<Dec> {
    if zfo {
        let numerator = mul(liquidity, s, &UP)?;
        let denominator = add(liquidity, &mul(amount, s, &DOWN)?, &DOWN)?;
        return div(&numerator, &denominator, &UP);
    }
    add(s, &div(amount, liquidity, &DOWN)?, &DOWN)
}

fn next_sqrt_from_output(s: &Dec, liquidity: &Dec, amount: &Dec, zfo: bool) -> RR<Dec> {
    if zfo {
        let step = div(amount, liquidity, &UP)?;
        return sub(s, &step, &DOWN);
    }
    let numerator = mul(liquidity, s, &UP)?;
    let product = mul(amount, s, &UP)?;
    let denominator = sub(liquidity, &product, &DOWN)?;
    div(&numerator, &denominator, &UP)
}

/// ``amount_in * fee_rate / (1 - fee_rate)``, rounded up to a unit.
fn fee_on(amount_in: &Dec, fee_rate: &Dec) -> RR<Dec> {
    let v = div(&mul(amount_in, fee_rate, &UP)?, &sub(&one(), fee_rate, &UP)?, &UP)?;
    q18(&v, Rounding::Ceiling, &UP)
}

/// ``_swap_step``: (√price after, input, output, fee).
fn swap_step(
    s: &Dec,
    s_target: &Dec,
    liquidity: &Dec,
    remaining: &Dec,
    fee_rate: &Dec,
    zfo: bool,
    exact_out: bool,
) -> RR<(Dec, Dec, Dec, Dec)> {
    if exact_out {
        return swap_step_out(s, s_target, liquidity, remaining, fee_rate, zfo);
    }
    let less_fee = q18(
        &mul(remaining, &sub(&one(), fee_rate, &DOWN)?, &DOWN)?,
        Rounding::Floor,
        &DOWN,
    )?;
    let to_target = if zfo {
        amount0_delta(s_target, s, liquidity, true)?
    } else {
        amount1_delta(s, s_target, liquidity, true)?
    };
    let (s_next, reached) = if positive(liquidity) && lt(&less_fee, &to_target) {
        (next_sqrt_from_input(s, liquidity, &less_fee, zfo)?, false)
    } else {
        (s_target.clone(), true)
    };
    let (amount_in, amount_out) = if zfo {
        (amount0_delta(&s_next, s, liquidity, true)?, amount1_delta(&s_next, s, liquidity, false)?)
    } else {
        (amount1_delta(s, &s_next, liquidity, true)?, amount0_delta(s, &s_next, liquidity, false)?)
    };
    let fee = if !reached {
        sub(remaining, &amount_in, &HALF)?
    } else if positive(&amount_in) {
        fee_on(&amount_in, fee_rate)?
    } else {
        zero()
    };
    Ok((s_next, amount_in, amount_out, fee))
}

/// ``_swap_step_out``.
fn swap_step_out(
    s: &Dec,
    s_target: &Dec,
    liquidity: &Dec,
    remaining: &Dec,
    fee_rate: &Dec,
    zfo: bool,
) -> RR<(Dec, Dec, Dec, Dec)> {
    let to_target = if zfo {
        amount1_delta(s_target, s, liquidity, false)?
    } else {
        amount0_delta(s, s_target, liquidity, false)?
    };
    let mut reached = true;
    let mut s_next = s_target.clone();
    if positive(liquidity) && lt(remaining, &to_target) {
        s_next = next_sqrt_from_output(s, liquidity, remaining, zfo)?;
        reached = false;
        if if zfo { le(&s_next, s_target) } else { le(s_target, &s_next) } {
            s_next = s_target.clone();
            reached = true;
        }
    }
    let (amount_in, mut amount_out) = if zfo {
        (amount0_delta(&s_next, s, liquidity, true)?, amount1_delta(&s_next, s, liquidity, false)?)
    } else {
        (amount1_delta(s, &s_next, liquidity, true)?, amount0_delta(s, &s_next, liquidity, false)?)
    };
    if !reached || lt(remaining, &amount_out) {
        amount_out = remaining.clone();
    }
    let fee = if positive(&amount_in) { fee_on(&amount_in, fee_rate)? } else { zero() };
    Ok((s_next, amount_in, amount_out, fee))
}

impl Pool {
    /// ``_next_tick``: the highest initialized tick ≤ ``tick`` moving down, the lowest above it
    /// moving up (its index).
    fn next_tick(&self, tick: i64, zfo: bool) -> Option<usize> {
        let i = self.ticks.partition_point(|t| t.0 <= tick);
        if zfo {
            i.checked_sub(1)
        } else if i < self.ticks.len() {
            Some(i)
        } else {
            None
        }
    }

    fn start(&self, zfo: bool, start: Option<&Plan>) -> RR<(Dec, i64, Dec, Dec)> {
        Ok(match start {
            Some(p) => (div(&p.sqrt, &q96(), &HALF)?, p.tick, p.liquidity.clone(), p.fg.clone()),
            None => (
                div(&self.sqrt, &q96(), &HALF)?,
                self.tick,
                self.liquidity.clone(),
                if zfo { self.fg0.clone() } else { self.fg1.clone() },
            ),
        })
    }

    /// ``quote`` with a ``sqrt_limit`` (the router's: a partial quote).
    pub fn quote(
        &self,
        amount: &Dec,
        zfo: bool,
        limit: &Dec,
        exact_out: bool,
        start: Option<&Plan>,
        py: &mut dyn Transcendental,
    ) -> RR<Plan> {
        if !positive(amount) {
            return Err(Bail);
        }
        if !eq(amount, &ok(amount.quantize(-18, Rounding::HalfEven, &HALF))?) {
            return Err(Bail);
        }
        if start.is_some_and(|p| p.zfo != zfo) {
            return Err(Bail);
        }
        let (mut s, mut tick, mut liquidity, mut fg) = self.start(zfo, start)?;
        let other = if zfo { self.fg1.clone() } else { self.fg0.clone() };
        let lp_share = Dec::parse("0.70").expect("FEE_LP_SHARE");
        let (mut remaining, mut got_in, mut out) = (amount.clone(), zero(), zero());
        let (mut fee_total, mut protocol) = (zero(), zero());
        let mut crossings = Vec::new();
        let mut exhausted = false;
        let mut cursor = tick;
        while positive(&remaining) {
            if if zfo { le(&s, limit) } else { le(limit, &s) } {
                break;
            }
            let nxt = self.next_tick(cursor, zfo);
            if nxt.is_none() && !positive(&liquidity) {
                exhausted = true;
                break;
            }
            let (target_tick, s_tick) = match nxt {
                Some(i) => (self.ticks[i].0, self.ticks[i].2.clone()),
                None if zfo => (self.min_tick, self.min_ratio.clone()),
                None => (self.max_tick, self.max_ratio.clone()),
            };
            if (if zfo { le(&s, &s_tick) } else { le(&s_tick, &s) }) && nxt.is_none() {
                exhausted = true;
                break;
            }
            let s_target =
                if if zfo { lt(&s_tick, limit) } else { lt(limit, &s_tick) } { limit.clone() } else { s_tick.clone() };
            let (s_next, step_in, step_out, step_fee) =
                swap_step(&s, &s_target, &liquidity, &remaining, &self.fee, zfo, exact_out)?;
            let spent = add(&step_in, &step_fee, &HALF)?;
            remaining = sub(&remaining, if exact_out { &step_out } else { &spent }, &HALF)?;
            got_in = add(&got_in, &spent, &HALF)?;
            out = add(&out, &step_out, &HALF)?;
            fee_total = add(&fee_total, &step_fee, &HALF)?;
            if positive(&liquidity) && positive(&step_fee) {
                let lp_fee = q18(&mul(&step_fee, &lp_share, &HALF)?, Rounding::Floor, &HALF)?;
                protocol = add(&protocol, &sub(&step_fee, &lp_fee, &HALF)?, &HALF)?;
                fg = add(&fg, &div(&lp_fee, &liquidity, &DOWN)?, &DOWN)?;
            } else {
                protocol = add(&protocol, &step_fee, &HALF)?;
            }
            s = s_next;
            if eq(&s, &s_tick) {
                let Some(i) = nxt else {
                    if positive(&remaining) {
                        exhausted = true;
                    }
                    tick = target_tick;
                    break;
                };
                let net = &self.ticks[i].1;
                let (fg0, fg1) = if zfo { (fg.clone(), other.clone()) } else { (other.clone(), fg.clone()) };
                crossings.push((target_tick, fg0, fg1));
                liquidity = if zfo { sub(&liquidity, net, &HALF)? } else { add(&liquidity, net, &HALF)? };
                if liquidity.neg && !liquidity.is_zero() {
                    return Err(Bail);
                }
                tick = if zfo { target_tick - 1 } else { target_tick };
                cursor = tick;
            } else {
                tick = py.tick_at(&s)?;
                break;
            }
        }
        let amount_in = if !exact_out && !positive(&remaining) { amount.clone() } else { got_in };
        Ok(Plan {
            zfo,
            amount_in,
            amount_out: out,
            fee: fee_total,
            protocol_fee: protocol,
            sqrt: mul(&s, &q96(), &HALF)?,
            tick,
            liquidity,
            fg,
            crossings,
            exhausted,
        })
    }

    /// ``liquid_sqrt``: where a swap this way first meets liquidity (a plain √price).
    pub fn liquid_sqrt(&self, zfo: bool, start: Option<&Plan>) -> RR<Option<Dec>> {
        let (s, tick, mut liquidity, _) = self.start(zfo, start)?;
        if positive(&liquidity) {
            return Ok(Some(s));
        }
        let mut cursor = tick;
        loop {
            let Some(i) = self.next_tick(cursor, zfo) else {
                return Ok(None);
            };
            let (t, net, ratio) = &self.ticks[i];
            liquidity = if zfo { sub(&liquidity, net, &HALF)? } else { add(&liquidity, net, &HALF)? };
            if positive(&liquidity) {
                return Ok(Some(ratio.clone()));
            }
            cursor = if zfo { t - 1 } else { *t };
        }
    }

    /// The plan applied: where the pool stands after it (``apply``'s fields the router reads).
    pub fn apply(&mut self, plan: &Plan) {
        if plan.zfo {
            self.fg0 = plan.fg.clone();
        } else {
            self.fg1 = plan.fg.clone();
        }
        self.sqrt = plan.sqrt.clone();
        self.tick = plan.tick;
        self.liquidity = plan.liquidity.clone();
    }
}

// ── the router's walk (``plan_fill``, for an order) ─────────────────────────────────────────

struct Walk<'a> {
    pool: &'a Pool,
    plan: Option<Plan>,
    eff: Option<Dec>,
}

/// The order book's leg of a route: what the taker pays in, receives (after its taker fees),
/// those fees, the base traded, the worst level it takes, the resting orders it visits.
#[derive(Clone)]
pub(crate) struct BookLeg {
    pub spent: Dec,
    pub got: Dec,
    pub fees: Dec,
    pub size: Dec,
    pub limit: Dec,
    pub makers: i64,
}

/// ``Route`` from ``plan_fill``: the book's leg (if it trades), then each pool's plan (in pool
/// id order, those that deliver something) with the pair's price where it left the pool; why
/// it stopped short.
pub(crate) struct Planned {
    pub buy: bool,
    pub book: Option<BookLeg>,
    pub legs: Vec<(usize, Plan, Dec)>,
    pub stopped: &'static str,
}

impl Planned {
    fn sum(&self, book: impl Fn(&BookLeg) -> &Dec, pool: impl Fn(&Plan) -> &Dec) -> RR<Dec> {
        let mut total = zero();
        if let Some(b) = &self.book {
            total = add(&total, book(b), &HALF)?;
        }
        for (_, p, _) in &self.legs {
            total = add(&total, pool(p), &HALF)?;
        }
        Ok(total)
    }
    /// ``Route.amount_in`` / ``amount_out`` / ``fee_total``: the legs' sums.
    pub fn amount_in(&self) -> RR<Dec> {
        self.sum(|b| &b.spent, |p| &p.amount_in)
    }
    pub fn amount_out(&self) -> RR<Dec> {
        self.sum(|b| &b.got, |p| &p.amount_out)
    }
    pub fn fee_total(&self) -> RR<Dec> {
        self.sum(|b| &b.fees, |p| &p.fee)
    }
    /// ``Route.source``: "hybrid" with more than one venue or pool, else the venue.
    pub fn source(&self) -> &'static str {
        if self.legs.len() > 1 || (self.book.is_some() && !self.legs.is_empty()) {
            "hybrid"
        } else if self.legs.is_empty() {
            "clob"
        } else {
            "amm"
        }
    }
    pub fn is_empty(&self) -> bool {
        self.book.is_none() && self.legs.is_empty()
    }
}

/// Whether any of the pools could take part in an order's fill: one whose first price, fee
/// included, is better than the limit (a pool's price moves only once it fills, so without one
/// the walk takes only the book).
pub(crate) fn can_fill(pools: &[Pool], buy: bool, limit: Option<&Dec>) -> RR<bool> {
    let zfo = !buy;
    for pool in pools {
        let Some(s0) = pool.liquid_sqrt(zfo, None)? else { continue };
        let Some(limit) = limit else { return Ok(true) };
        let keep = sub(&one(), &pool.fee, &HALF)?;
        let raw = mul(&s0, &s0, &HALF)?;
        let eff = if buy { div(&raw, &keep, &HALF)? } else { mul(&raw, &keep, &HALF)? };
        if if buy { lt(&eff, limit) } else { lt(limit, &eff) } {
            return Ok(true);
        }
    }
    Ok(false)
}

/// ``Router.plan_fill(pair, buy, amount, exact_in, limit, sender, max_makers)`` on a pair's
/// book and candidate pools (in id order: not paused, token0 the base). ``rate``: the
/// sender's taker rate (``taker_rate``); ``fee_of``: its taker fee on what it receives.
/// ``pools_only``: the caller reads only the pools' legs (an order) — then nothing is planned
/// when no pool can ever fill, and the book's leg is not totalled. None: nothing fills.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_fill(
    book: &Book,
    pools: &[Pool],
    buy: bool,
    amount: &Dec,
    exact_in: bool,
    limit: Option<&Dec>,
    sender: &str,
    max_makers: Option<i64>,
    rate: &Dec,
    fee_of: &mut dyn FnMut(&Dec) -> RR<Dec>,
    pools_only: bool,
    py: &mut dyn Transcendental,
) -> RR<Option<Planned>> {
    if !positive(amount) {
        return Ok(None);
    }
    let zfo = !buy;
    let out_mode = buy && !exact_in;
    let key = |eff: &Dec| -> RR<Dec> { if buy { Ok(eff.clone()) } else { negate(eff) } };
    let pool_eff = |pool: &Pool, raw: &Dec| -> RR<Dec> {
        let keep = sub(&one(), &pool.fee, &HALF)?;
        if buy { div(raw, &keep, &HALF) } else { mul(raw, &keep, &HALF) }
    };
    let mut state: Vec<Walk> = Vec::with_capacity(pools.len());
    for pool in pools {
        let eff = match pool.liquid_sqrt(zfo, None)? {
            Some(s0) => Some(pool_eff(pool, &mul(&s0, &s0, &HALF)?)?),
            None => None,
        };
        state.push(Walk { pool, plan: None, eff });
    }
    // (no pool that can ever fill: the walk takes only the book, and nothing of a pool)
    let limit_key = match limit {
        Some(l) => Some(key(l)?),
        None => None,
    };
    let mut any = false;
    for w in &state {
        if let Some(e) = &w.eff {
            let k = key(e)?;
            if limit_key.as_ref().is_none_or(|lk| lt(&k, lk)) {
                any = true;
            }
        }
    }
    if !any && pools_only {
        return Ok(None); // (a pool's price moves only once it fills)
    }
    let levels = book.level_prices(!buy);
    let (mut li, mut qi) = (0usize, 0usize);
    let mut queue: Option<Vec<(Id, Dec)>> = None;
    let mut book_open = true;
    let mut left = max_makers;
    let mut remaining = amount.clone();
    let mut stopped: &'static str = "";
    let mut self_stop = false;
    let mut steps = 0usize;
    let (mut size, mut spent, mut got, mut fees) = (zero(), zero(), zero(), zero());
    let mut visited = 0i64;
    let mut book_limit = zero();
    let keep_rate = sub(&one(), rate, &HALF)?;
    let pool_limit = |pool: &Pool, eff: Option<&Dec>, py: &mut dyn Transcendental| -> RR<Dec> {
        let Some(eff) = eff else {
            return Ok(if zfo { pool.min_ratio.clone() } else { pool.max_ratio.clone() });
        };
        let keep = sub(&one(), &pool.fee, &HALF)?;
        let raw = if buy { mul(eff, &keep, &HALF)? } else { div(eff, &keep, &HALF)? };
        if positive(&raw) { py.sqrt(&raw) } else { Ok(pool.min_ratio.clone()) }
    };
    let measure =
        |p: &Plan| -> Dec { if out_mode { p.amount_out.clone() } else { p.amount_in.clone() } };
    let units = |a: &Dec| -> RR<Dec> {
        let u = q18(a, Rounding::Down, &HALF)?;
        Ok(if eq(&u, a) { a.clone() } else { u })
    };
    fn quote_to(
        w: &Walk,
        amt: &Dec,
        limit: &Dec,
        buy: bool,
        out_mode: bool,
        py: &mut dyn Transcendental,
    ) -> RR<Plan> {
        w.pool.quote(amt, !buy, limit, out_mode, w.plan.as_ref(), py)
    }
    // ``commit``: the walk's plan of the pool goes on, and where it now stands.
    let commit = |w: &mut Walk, plan: Plan, reached: Option<&Dec>| -> RR<()> {
        let plan = match &w.plan {
            None => plan,
            Some(p) => p.then(&plan)?,
        };
        w.eff = if plan.exhausted {
            None
        } else if positive(&plan.liquidity) && reached.is_some() {
            reached.cloned()
        } else {
            match w.pool.liquid_sqrt(zfo, Some(&plan))? {
                Some(s1) => Some(pool_eff(w.pool, &mul(&s1, &s1, &HALF)?)?),
                None => None,
            }
        };
        w.plan = Some(plan);
        Ok(())
    };

    while positive(&remaining) && stopped.is_empty() {
        steps += 1;
        if steps > 64 + 4 * (levels.len() + state.len()) {
            break;
        }
        let mut level_price: Option<Dec> = None;
        while book_open && li < levels.len() {
            let lp = &levels[li];
            if let Some(l) = limit {
                if if buy { lt(l, lp) } else { lt(lp, l) } {
                    book_open = false;
                    break;
                }
            }
            if queue.is_none() {
                queue = Some(book.fill_queue(!buy, lp).map_err(|_| Bail)?);
                qi = 0;
            }
            if qi >= queue.as_ref().map_or(0, |q| q.len()) {
                li += 1;
                queue = None;
                continue;
            }
            level_price = Some(lp.clone());
            break;
        }
        // (key, 0 for the book or 1 for a pool, pool index)
        let mut options: Vec<(Dec, u8, usize)> = Vec::new();
        if let Some(lp) = &level_price {
            let book_eff = if buy { div(lp, &keep_rate, &HALF)? } else { mul(lp, &keep_rate, &HALF)? };
            options.push((key(&book_eff)?, 0, usize::MAX));
        }
        for (i, w) in state.iter().enumerate() {
            if let Some(e) = &w.eff {
                let k = key(e)?;
                if limit_key.as_ref().is_none_or(|lk| lt(&k, lk)) {
                    options.push((k, 1, i));
                }
            }
        }
        if options.is_empty() {
            break;
        }
        // (stable, by key, then the book first, then the pool's id)
        options.sort_by(|a, b| {
            a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then_with(|| {
                let id = |i: usize| if i == usize::MAX { "" } else { state[i].pool.id.as_str() };
                id(a.2).cmp(id(b.2))
            })
        });
        let (best_key, kind) = (options[0].0.clone(), options[0].1);
        if kind == 0 {
            let lp = level_price.clone().expect("the book's level");
            let q = queue.as_mut().expect("the level's queue");
            while qi < q.len() && positive(&remaining) {
                let (owner, offered) = q[qi].clone();
                if &*owner == sender {
                    book_open = false;
                    self_stop = true;
                    break;
                }
                if left.is_some_and(|l| l <= 0) {
                    stopped = "budget";
                    break;
                }
                let bound = if buy && exact_in {
                    q18(&div(&remaining, &lp, &HALF)?, Rounding::Down, &HALF)?
                } else {
                    remaining.clone()
                };
                let take = if lt(&bound, &offered) { bound } else { offered.clone() };
                if !positive(&take) {
                    stopped = "dust";
                    break;
                }
                if let Some(l) = left.as_mut() {
                    *l -= 1;
                }
                visited += 1;
                let notional = mul(&take, &lp, &HALF)?;
                if !pools_only {
                    let received = if buy { take.clone() } else { notional.clone() };
                    let fee = fee_of(&received)?;
                    size = add(&size, &take, &HALF)?;
                    spent = add(&spent, if buy { &notional } else { &take }, &HALF)?;
                    got = add(&got, &sub(&received, &fee, &HALF)?, &HALF)?;
                    fees = add(&fees, &fee, &HALF)?;
                } else {
                    size = add(&size, &take, &HALF)?;
                }
                book_limit = lp.clone();
                remaining =
                    sub(&remaining, if buy && exact_in { &notional } else { &take }, &HALF)?;
                if lt(&take, &offered) {
                    q[qi] = (owner, sub(&offered, &take, &HALF)?);
                } else {
                    qi += 1;
                }
            }
            continue;
        }
        // Pools: every pool at the best price moves to the next price anything else offers.
        let active: Vec<usize> =
            options.iter().filter(|o| o.1 == 1 && eq(&o.0, &best_key)).map(|o| o.2).collect();
        let mut beyond: Vec<Dec> =
            options.iter().filter(|o| lt(&best_key, &o.0)).map(|o| o.0.clone()).collect();
        if let Some(lk) = &limit_key {
            beyond.push(lk.clone());
        }
        let target_key = py_min(&beyond).cloned();
        let target = match &target_key {
            Some(k) => Some(if buy { k.clone() } else { negate(k)? }),
            None => None,
        };
        let amt = units(&remaining)?;
        if !positive(&amt) {
            stopped = "dust";
            break;
        }
        let mut plans: Vec<(usize, Plan)> = Vec::with_capacity(active.len());
        for &i in &active {
            let lim = pool_limit(state[i].pool, target.as_ref(), py)?;
            plans.push((i, quote_to(&state[i], &amt, &lim, buy, out_mode, py)?));
        }
        let mut total = zero();
        for (_, q) in &plans {
            total = add(&total, &measure(q), &HALF)?;
        }
        if plans.iter().any(|(_, q)| !positive(&q.amount_out) && positive(&q.amount_in)) {
            stopped = "dust";
            break;
        }
        if le(&total, &amt) {
            for (i, q) in plans {
                commit(&mut state[i], q, target.as_ref())?;
            }
            remaining = sub(&remaining, &total, &HALF)?;
            continue;
        }
        // More than is left: split it so they end at one marginal price.
        let mut lo = best_key.clone();
        let mut hi = match &target_key {
            Some(k) => k.clone(),
            None => {
                let mut ends = Vec::with_capacity(plans.len());
                for (i, q) in &plans {
                    ends.push(key(&pool_eff(state[*i].pool, &py.squared(&q.sqrt)?)?)?);
                }
                py_max(&ends).cloned().ok_or(Bail)?
            }
        };
        let two = Dec::parse("2").expect("2");
        for _ in 0..SPLIT_STEPS {
            let mid = div(&add(&lo, &hi, &HALF)?, &two, &HALF)?;
            let eff = if buy { mid.clone() } else { negate(&mid)? };
            let mut f_mid = zero();
            for &i in &active {
                let lim = pool_limit(state[i].pool, Some(&eff), py)?;
                f_mid = add(&f_mid, &measure(&quote_to(&state[i], &amt, &lim, buy, out_mode, py)?), &HALF)?;
            }
            if le(&f_mid, &remaining) {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        let at = if buy { lo.clone() } else { negate(&lo)? };
        let mut used = zero();
        for &i in &active {
            let lim = pool_limit(state[i].pool, Some(&at), py)?;
            let q = quote_to(&state[i], &amt, &lim, buy, out_mode, py)?;
            used = add(&used, &measure(&q), &HALF)?;
            commit(&mut state[i], q, Some(&at))?;
        }
        remaining = sub(&remaining, &used, &HALF)?;
        let rest = units(&remaining)?;
        if positive(&rest) {
            // the exact rest to the deepest of them (most liquidity, then the lowest id)
            let deepest = *active
                .iter()
                .reduce(|a, b| {
                    let (la, lb) = (
                        &state[*a].plan.as_ref().expect("committed").liquidity,
                        &state[*b].plan.as_ref().expect("committed").liquidity,
                    );
                    match la.cmp(lb) {
                        Ordering::Less => b,
                        Ordering::Greater => a,
                        // ([-ord(c) for c in id]: the larger is the smaller id, or a prefix's
                        // extension)
                        Ordering::Equal => {
                            let neg = |s: &str| s.chars().map(|c| -(c as i64)).collect::<Vec<_>>();
                            if neg(&state[*b].pool.id) > neg(&state[*a].pool.id) { b } else { a }
                        }
                    }
                })
                .expect("an active pool");
            let lim = pool_limit(state[deepest].pool, target.as_ref(), py)?;
            let q = quote_to(&state[deepest], &rest, &lim, buy, out_mode, py)?;
            if !positive(&q.amount_out) && positive(&q.amount_in) {
                stopped = "dust";
                break;
            }
            let m = measure(&q);
            commit(&mut state[deepest], q, target.as_ref())?;
            remaining = sub(&remaining, &m, &HALF)?;
        }
    }
    let book_leg = positive(&size).then(|| BookLeg {
        spent,
        got,
        fees,
        size,
        limit: book_limit,
        makers: visited,
    });
    let mut legs = Vec::new();
    let mut order: Vec<usize> = (0..state.len()).collect();
    order.sort_by(|a, b| state[*a].pool.id.cmp(&state[*b].pool.id));
    for i in order {
        let Some(plan) = state[i].plan.clone() else { continue };
        if !positive(&plan.amount_out) {
            continue;
        }
        let end = py.squared(&plan.sqrt)?;
        legs.push((i, plan, end));
    }
    if book_leg.is_none() && legs.is_empty() {
        return Ok(None);
    }
    let stopped = if !stopped.is_empty() {
        stopped
    } else if self_stop {
        "self"
    } else {
        ""
    };
    Ok(Some(Planned { buy, book: book_leg, legs, stopped }))
}
