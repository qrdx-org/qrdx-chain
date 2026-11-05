//! Python's `Decimal`, exactly, for the exchange engine (docs/EXCHANGE_ENGINE.md).
//!
//! Every amount, price and fee in the exchange is a `Decimal` computed under a context (the
//! consensus ones: precision 78, rounding half-even, or a directed rounding where the exchange
//! rounds in someone's favour). A native component that computes a different digit computes a
//! different state root, so this module is a port of CPython's own reference implementation
//! (`Lib/_pydecimal.py`: `_fix`, `_rescale`, the rounding functions, `__add__`, `__mul__`,
//! `__truediv__`, `quantize`, `_cmp`, `__str__`), whose results are the C `decimal`'s.
//!
//! A value is a sign, a coefficient of any size and an exponent. What the port does not follow
//! it refuses — `None`, and the caller hands the work to Python, which raises or computes as it
//! always has: an infinity or a NaN, an exponent past ±100,000 (Python's limits are ±999,999;
//! the exchange's values are within ±80), a result Python would raise on (division by zero, a
//! quantize past the precision, overflow) or would make subnormal, a numeral Python's
//! `Decimal()` reads in a way this parser does not (whitespace, underscores, non-ASCII digits).
//!
//! `tests/test_native_decimal.py` holds it to Python's `decimal` on random values in every
//! rounding and the precisions the exchange uses.

use std::cmp::Ordering;
use std::sync::OnceLock;

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, ToPrimitive, Zero};

/// The exponents this module computes with; past them, Python does.
const EXP_LIMIT: i64 = 100_000;
/// Python's default context bounds (`Context(prec=…, rounding=…)` keeps them).
const EMAX: i64 = 999_999;
const EMIN: i64 = -999_999;
/// Powers of ten cached up to this many digits (larger ones are computed).
const POW_CACHE: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rounding {
    Down,
    Up,
    HalfUp,
    HalfDown,
    HalfEven,
    Ceiling,
    Floor,
    Up05,
}

impl Rounding {
    /// Python's name for it (`decimal.ROUND_HALF_EVEN` is "ROUND_HALF_EVEN").
    pub fn from_name(name: &str) -> Option<Rounding> {
        Some(match name {
            "ROUND_DOWN" => Rounding::Down,
            "ROUND_UP" => Rounding::Up,
            "ROUND_HALF_UP" => Rounding::HalfUp,
            "ROUND_HALF_DOWN" => Rounding::HalfDown,
            "ROUND_HALF_EVEN" => Rounding::HalfEven,
            "ROUND_CEILING" => Rounding::Ceiling,
            "ROUND_FLOOR" => Rounding::Floor,
            "ROUND_05UP" => Rounding::Up05,
            _ => return None,
        })
    }
}

/// A context: Python's `Context(prec=prec, rounding=rounding)` (Emax 999,999, Emin −999,999,
/// clamp 0; the default traps — InvalidOperation, DivisionByZero, Overflow — are refusals here).
#[derive(Clone, Copy, Debug)]
pub struct Ctx {
    pub prec: usize,
    pub rounding: Rounding,
}

impl Ctx {
    pub const fn new(prec: usize, rounding: Rounding) -> Ctx {
        Ctx { prec, rounding }
    }

    fn etiny(&self) -> i64 {
        EMIN - self.prec as i64 + 1
    }

    fn etop(&self) -> i64 {
        EMAX - self.prec as i64 + 1
    }
}

/// The exchange's consensus context (`orderbook._CTX`, `clearinghouse._CONTEXT`, `amm._CTX`).
pub const EXCHANGE: Ctx = Ctx::new(78, Rounding::HalfEven);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dec {
    pub neg: bool,
    pub coef: BigUint,
    pub exp: i64,
}

fn pow10(n: usize) -> BigUint {
    static CACHE: OnceLock<Vec<BigUint>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| {
        let mut v = Vec::with_capacity(POW_CACHE + 1);
        let mut p = BigUint::one();
        for _ in 0..=POW_CACHE {
            v.push(p.clone());
            p *= 10u32;
        }
        v
    });
    if n <= POW_CACHE {
        cache[n].clone()
    } else {
        BigUint::from(10u32).pow(n as u32)
    }
}

/// The number of decimal digits of ``n`` (1 for zero), as ``len(str(n))``.
fn ndigits(n: &BigUint) -> usize {
    if n.is_zero() {
        return 1;
    }
    let bits = n.bits() as f64;
    // (an estimate within one of the answer, then corrected)
    let mut d = (bits * std::f64::consts::LOG10_2).floor() as usize + 1;
    if d > 1 && *n < pow10(d - 1) {
        d -= 1;
    } else if *n >= pow10(d) {
        d += 1;
    }
    d
}

impl Dec {
    pub fn zero() -> Dec {
        Dec {
            neg: false,
            coef: BigUint::zero(),
            exp: 0,
        }
    }

    pub fn is_zero(&self) -> bool {
        self.coef.is_zero()
    }

    fn in_range(self) -> Option<Dec> {
        (self.exp.abs() <= EXP_LIMIT).then_some(self)
    }

    /// ``Decimal(text)`` for a finite numeral: an optional sign, digits with at most one point,
    /// an optional exponent. Anything else (whitespace, underscores, specials, non-ASCII) is
    /// refused.
    pub fn parse(text: &str) -> Option<Dec> {
        let b = text.as_bytes();
        let mut i = 0;
        let neg = match b.first() {
            Some(b'-') => {
                i = 1;
                true
            }
            Some(b'+') => {
                i = 1;
                false
            }
            _ => false,
        };
        let mut digits = String::new();
        let mut frac: i64 = 0;
        let mut point = false;
        let mut any = false;
        while i < b.len() {
            match b[i] {
                c @ b'0'..=b'9' => {
                    digits.push(c as char);
                    any = true;
                    if point {
                        frac += 1;
                    }
                }
                b'.' if !point => point = true,
                _ => break,
            }
            i += 1;
        }
        if !any {
            return None;
        }
        let mut exp: i64 = 0;
        if i < b.len() {
            if b[i] != b'e' && b[i] != b'E' {
                return None;
            }
            let rest = &text[i + 1..];
            let body = rest.strip_prefix(['+', '-']).unwrap_or(rest);
            if body.is_empty() || body.len() > 7 || !body.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            exp = rest.parse::<i64>().ok()?;
        }
        let coef = BigUint::parse_bytes(digits.as_bytes(), 10)?;
        Dec {
            neg,
            coef,
            exp: exp.checked_sub(frac)?,
        }
        .in_range()
    }

    /// ``str(d)``: Python's scientific string (``Decimal.__str__``, capitals).
    pub fn to_python_string(&self) -> String {
        let int = self.coef.to_str_radix(10);
        let sign = if self.neg { "-" } else { "" };
        let leftdigits = self.exp + int.len() as i64;
        let dotplace = if self.exp <= 0 && leftdigits > -6 {
            leftdigits
        } else {
            1
        };
        let (intpart, fracpart) = if dotplace <= 0 {
            (
                "0".to_string(),
                format!(".{}{}", "0".repeat((-dotplace) as usize), int),
            )
        } else if dotplace as usize >= int.len() {
            (
                format!("{}{}", int, "0".repeat(dotplace as usize - int.len())),
                String::new(),
            )
        } else {
            (
                int[..dotplace as usize].to_string(),
                format!(".{}", &int[dotplace as usize..]),
            )
        };
        let exp = if leftdigits == dotplace {
            String::new()
        } else {
            format!("E{:+}", leftdigits - dotplace)
        };
        format!("{sign}{intpart}{fracpart}{exp}")
    }

    /// The same value with its coefficient's trailing zeros dropped (and 0 for every zero):
    /// equal values are equal here, whatever their spelling.
    pub fn normalized(&self) -> Dec {
        if self.is_zero() {
            return Dec::zero();
        }
        let mut coef = self.coef.clone();
        let mut exp = self.exp;
        loop {
            let (q, r) = coef.div_rem(&BigUint::from(10u32));
            if !r.is_zero() {
                break;
            }
            coef = q;
            exp += 1;
        }
        Dec {
            neg: self.neg,
            coef,
            exp,
        }
    }

    /// ``orderbook.price_text``: the value's one spelling (``str`` of ``normalized``).
    pub fn canonical_text(&self) -> String {
        self.normalized().to_python_string()
    }

    /// ``self.adjusted()``: the exponent of the most significant digit.
    pub fn adjusted(&self) -> i64 {
        self.exp + ndigits(&self.coef) as i64 - 1
    }

    // ── rounding (``_pick_rounding_function``) ────────────────────────────────────────────

    /// Of the coefficient's digits, keep the first ``keep``: (the kept part, 1 to round up,
    /// 0 if the dropped digits are all zero, −1 to truncate). ``keep`` < its digit count.
    fn round_digits(&self, keep: usize, rounding: Rounding) -> (BigUint, i32) {
        let total = ndigits(&self.coef);
        debug_assert!(keep < total);
        let dropped = total - keep;
        let unit = pow10(dropped);
        let (kept, rest) = self.coef.div_rem(&unit);
        let all_zeros = rest.is_zero();
        let half = pow10(dropped - 1) * 5u32;
        let first_dropped_high = rest >= half; // the first dropped digit is 5–9
        let exact_half = rest == half;
        let down = if all_zeros { 0 } else { -1 };
        let half_up = if first_dropped_high { 1 } else { down };
        let last_kept = if keep == 0 {
            None
        } else {
            Some((&kept % 10u32).to_u32().unwrap_or(0))
        };
        let changed = match rounding {
            Rounding::Down => down,
            Rounding::Up => -down,
            Rounding::HalfUp => half_up,
            Rounding::HalfDown => {
                if exact_half {
                    -1
                } else {
                    half_up
                }
            }
            Rounding::HalfEven => {
                if exact_half && last_kept.is_none_or(|d| d % 2 == 0) {
                    -1
                } else {
                    half_up
                }
            }
            Rounding::Ceiling => {
                if self.neg {
                    down
                } else {
                    -down
                }
            }
            Rounding::Floor => {
                if self.neg {
                    -down
                } else {
                    down
                }
            }
            Rounding::Up05 => {
                if last_kept.is_some_and(|d| d != 0 && d != 5) {
                    down
                } else {
                    -down
                }
            }
        };
        (kept, changed)
    }

    /// ``_fix(context)``: rounded to the context's precision. None where Python would raise
    /// (overflow) or go subnormal.
    pub fn fix(&self, ctx: &Ctx) -> Option<Dec> {
        let etiny = ctx.etiny();
        let etop = ctx.etop();
        if self.is_zero() {
            let new_exp = self.exp.max(etiny).min(EMAX);
            if new_exp != self.exp {
                return None; // (clamped: past what the exchange's values reach)
            }
            return Some(self.clone());
        }
        let len = ndigits(&self.coef) as i64;
        let mut exp_min = len + self.exp - ctx.prec as i64;
        if exp_min > etop || exp_min < etiny {
            return None; // (overflow, or subnormal)
        }
        if self.exp >= exp_min {
            return Some(self.clone()); // (representable as it is)
        }
        let digits = len + self.exp - exp_min; // ≥ 0: exp_min − exp < len
        let (kept, changed) = self.round_digits(digits as usize, ctx.rounding);
        let mut coef = kept;
        if changed > 0 {
            coef += 1u32;
            if ndigits(&coef) > ctx.prec {
                coef /= 10u32;
                exp_min += 1;
            }
        }
        if exp_min > etop {
            return None;
        }
        Some(Dec {
            neg: self.neg,
            coef,
            exp: exp_min,
        })
    }

    /// ``_rescale(exp, rounding)``: to exponent ``exp`` exactly, padding or rounding.
    pub fn rescale(&self, exp: i64, rounding: Rounding) -> Dec {
        if self.is_zero() {
            return Dec {
                neg: self.neg,
                coef: BigUint::zero(),
                exp,
            };
        }
        if self.exp >= exp {
            return Dec {
                neg: self.neg,
                coef: &self.coef * pow10((self.exp - exp) as usize),
                exp,
            };
        }
        let digits = ndigits(&self.coef) as i64 + self.exp - exp;
        let (kept, changed) = if digits < 0 {
            // (below half a unit of the target: replaced by 10**(exp-1) before rounding)
            let tiny = Dec {
                neg: self.neg,
                coef: BigUint::one(),
                exp: exp - 1,
            };
            tiny.round_digits(0, rounding)
        } else {
            self.round_digits(digits as usize, rounding)
        };
        let coef = if changed == 1 { kept + 1u32 } else { kept };
        Dec {
            neg: self.neg,
            coef,
            exp,
        }
    }

    // ── arithmetic ────────────────────────────────────────────────────────────────────────

    pub fn neg(&self) -> Dec {
        Dec {
            neg: !self.neg,
            coef: self.coef.clone(),
            exp: self.exp,
        }
    }

    /// ``self + other`` under ``ctx``.
    pub fn add(&self, other: &Dec, ctx: &Ctx) -> Option<Dec> {
        let mut exp = self.exp.min(other.exp);
        let negativezero = ctx.rounding == Rounding::Floor && self.neg != other.neg;
        if self.is_zero() && other.is_zero() {
            let neg = (self.neg && other.neg) || negativezero;
            return Dec {
                neg,
                coef: BigUint::zero(),
                exp,
            }
            .fix(ctx);
        }
        if self.is_zero() {
            exp = exp.max(other.exp - ctx.prec as i64 - 1);
            return other.rescale(exp, ctx.rounding).fix(ctx);
        }
        if other.is_zero() {
            exp = exp.max(self.exp - ctx.prec as i64 - 1);
            return self.rescale(exp, ctx.rounding).fix(ctx);
        }
        // ``_normalize``: a much smaller operand only decides rounding
        let (a, b) = normalize(self, other, ctx.prec);
        let (result_neg, coef) = if a.neg != b.neg {
            match a.coef.cmp(&b.coef) {
                Ordering::Equal => {
                    return Dec {
                        neg: negativezero,
                        coef: BigUint::zero(),
                        exp,
                    }
                    .fix(ctx);
                }
                Ordering::Greater => (a.neg, &a.coef - &b.coef),
                Ordering::Less => (b.neg, &b.coef - &a.coef),
            }
        } else {
            (a.neg, &a.coef + &b.coef)
        };
        Dec {
            neg: result_neg,
            coef,
            exp: a.exp,
        }
        .in_range()?
        .fix(ctx)
    }

    pub fn sub(&self, other: &Dec, ctx: &Ctx) -> Option<Dec> {
        self.add(&other.neg(), ctx)
    }

    /// ``self * other`` under ``ctx``.
    pub fn mul(&self, other: &Dec, ctx: &Ctx) -> Option<Dec> {
        let neg = self.neg != other.neg;
        let exp = self.exp + other.exp;
        let coef = if self.is_zero() || other.is_zero() {
            BigUint::zero()
        } else {
            &self.coef * &other.coef
        };
        Dec { neg, coef, exp }.in_range()?.fix(ctx)
    }

    /// ``self / other`` under ``ctx``; None for a zero divisor (Python raises).
    pub fn div(&self, other: &Dec, ctx: &Ctx) -> Option<Dec> {
        if other.is_zero() {
            return None;
        }
        let neg = self.neg != other.neg;
        let (coef, exp) = if self.is_zero() {
            (BigUint::zero(), self.exp - other.exp)
        } else {
            let shift = ndigits(&other.coef) as i64 - ndigits(&self.coef) as i64 + ctx.prec as i64 + 1;
            let mut exp = self.exp - other.exp - shift;
            let (mut coef, remainder) = if shift >= 0 {
                (&self.coef * pow10(shift as usize)).div_rem(&other.coef)
            } else {
                self.coef.div_rem(&(&other.coef * pow10((-shift) as usize)))
            };
            if !remainder.is_zero() {
                // not exact: a last digit of 0 or 5 would round as if it were exact
                if (&coef % 5u32).is_zero() {
                    coef += 1u32;
                }
            } else {
                let ideal = self.exp - other.exp;
                while exp < ideal && (&coef % 10u32).is_zero() {
                    coef /= 10u32;
                    exp += 1;
                }
            }
            (coef, exp)
        };
        Dec { neg, coef, exp }.in_range()?.fix(ctx)
    }

    /// ``self.quantize(Decimal(f"1E{exp}"), rounding)`` under ``ctx``; None where Python raises
    /// (the result needs more digits than the precision).
    pub fn quantize(&self, exp: i64, rounding: Rounding, ctx: &Ctx) -> Option<Dec> {
        if !(ctx.etiny() <= exp && exp <= EMAX) || exp.abs() > EXP_LIMIT {
            return None;
        }
        if self.is_zero() {
            return Dec {
                neg: self.neg,
                coef: BigUint::zero(),
                exp,
            }
            .fix(ctx);
        }
        let adjusted = self.adjusted();
        if adjusted > EMAX || adjusted - exp + 1 > ctx.prec as i64 {
            return None;
        }
        let ans = self.rescale(exp, rounding);
        if ans.adjusted() > EMAX || ndigits(&ans.coef) > ctx.prec {
            return None;
        }
        if !ans.is_zero() && ans.adjusted() < EMIN {
            return None; // (subnormal: never in the exchange)
        }
        ans.fix(ctx)
    }

    /// Python's comparison (``_cmp``): by value; 0 and −0 are equal.
    pub fn cmp(&self, other: &Dec) -> Ordering {
        match (self.is_zero(), other.is_zero()) {
            (true, true) => return Ordering::Equal,
            (true, false) => {
                return if other.neg {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            }
            (false, true) => {
                return if self.neg {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
            _ => {}
        }
        if self.neg != other.neg {
            return if self.neg {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }
        let magnitude = {
            let (sa, oa) = (self.adjusted(), other.adjusted());
            if sa != oa {
                sa.cmp(&oa)
            } else {
                // equal adjusted exponents: compare the coefficients at a common exponent
                let e = self.exp.min(other.exp);
                let a = &self.coef * pow10((self.exp - e) as usize);
                let b = &other.coef * pow10((other.exp - e) as usize);
                a.cmp(&b)
            }
        };
        if self.neg {
            magnitude.reverse()
        } else {
            magnitude
        }
    }
}

/// ``_normalize(op1, op2, prec)``: both at one exponent, a far smaller operand replaced by the
/// unit just below the larger's precision (it can only decide the rounding).
fn normalize(op1: &Dec, op2: &Dec, prec: usize) -> (Dec, Dec) {
    let (tmp, other, swapped) = if op1.exp < op2.exp {
        (op2.clone(), op1.clone(), true)
    } else {
        (op1.clone(), op2.clone(), false)
    };
    let mut tmp = tmp;
    let mut other = other;
    let tmp_len = ndigits(&tmp.coef) as i64;
    let other_len = ndigits(&other.coef) as i64;
    let exp = tmp.exp + (-1i64).min(tmp_len - prec as i64 - 2);
    if other_len + other.exp - 1 < exp {
        other.coef = BigUint::one();
        other.exp = exp;
    }
    tmp.coef = &tmp.coef * pow10((tmp.exp - other.exp) as usize);
    tmp.exp = other.exp;
    if swapped {
        (other, tmp)
    } else {
        (tmp, other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Dec {
        Dec::parse(s).unwrap()
    }

    #[test]
    fn strings_are_pythons() {
        for s in ["0", "-0", "1.50", "0E-18", "1E+3", "123.456", "0.000001", "1E-7", "-1.2E+6"] {
            assert_eq!(d(s).to_python_string(), s, "{s}");
        }
        assert_eq!(d("1e3").to_python_string(), "1E+3");
        assert!(Dec::parse("NaN").is_none() && Dec::parse(" 1").is_none());
        assert!(Dec::parse("1_000").is_none() && Dec::parse("1e").is_none());
    }

    #[test]
    fn arithmetic_is_pythons() {
        let c = EXCHANGE;
        assert_eq!(d("1").add(&d("0.10"), &c).unwrap().to_python_string(), "1.10");
        assert_eq!(d("0.1").sub(&d("0.1"), &c).unwrap().to_python_string(), "0.0");
        assert_eq!(d("1").div(&d("3"), &Ctx::new(5, Rounding::HalfEven)).unwrap().to_python_string(), "0.33333");
        assert_eq!(d("10").div(&d("4"), &c).unwrap().to_python_string(), "2.5");
        assert_eq!(d("2.5").quantize(0, Rounding::HalfEven, &c).unwrap().to_python_string(), "2");
        assert_eq!(d("3.5").quantize(0, Rounding::HalfEven, &c).unwrap().to_python_string(), "4");
        assert!(d("1").div(&d("0"), &c).is_none());
        assert_eq!(d("-0").cmp(&d("0")), Ordering::Equal);
    }
}

/// For the differential tests: ``op`` ("add", "sub", "mul", "div", "quantize", "cmp") of the
/// numerals ``a`` and ``b`` under ``Context(prec, rounding)`` — Python's ``str`` of the result
/// (for "cmp": "-1", "0" or "1"; for "quantize": ``a.quantize(b)``), or None where this module
/// refuses (and Python decides).
#[pyo3::pyfunction]
pub fn dec_eval(op: &str, a: &str, b: &str, prec: usize, rounding: &str) -> Option<String> {
    let ctx = Ctx::new(prec, Rounding::from_name(rounding)?);
    let (x, y) = (Dec::parse(a)?, Dec::parse(b)?);
    let out = match op {
        "add" => x.add(&y, &ctx)?,
        "sub" => x.sub(&y, &ctx)?,
        "mul" => x.mul(&y, &ctx)?,
        "div" => x.div(&y, &ctx)?,
        "quantize" => x.quantize(y.exp, ctx.rounding, &ctx)?,
        "cmp" => {
            return Some(
                match x.cmp(&y) {
                    Ordering::Less => "-1",
                    Ordering::Equal => "0",
                    Ordering::Greater => "1",
                }
                .to_string(),
            )
        }
        _ => return None,
    };
    Some(out.to_python_string())
}
