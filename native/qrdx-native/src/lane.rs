//! Plain QRDX transfers, judged and run natively (qrdx/exchange/transfer_lane.py).
//!
//! A block's exchange section is judged as a whole before any of it runs (``section_errors``)
//! and then run transaction by transaction (``process_transaction``). For a transfer of native
//! QRDX, signed by its own account's single key, everything those passes decide that depends on
//! state is arithmetic over a few dicts: each lane's next nonce, what each payer owes the block
//! in fees, each address's available balance and its delta for the block, the block's fees.
//! Python checks everything else about each transaction with its own functions (its form, its
//! signer, its fee floor, its amount, its recipient) and hands a run of them here.
//!
//! The arithmetic is Python's ``Decimal``, exactly: a value is a coefficient and an exponent, a
//! sum takes the smaller exponent, a comparison is by value. Values come in as Python writes
//! them (``str(Decimal)``) and go back as ``<coefficient>E<exponent>``, which ``Decimal`` reads
//! to the same coefficient and exponent. What is not reproduced exactly — a coefficient past
//! 128 bits, a negative zero, an infinity — makes the call bail, and Python runs the run itself.
//!
//! The order in which addresses first enter the block's delta dict is part of what the flush
//! does (two forms of one account apply in order), so it is returned too.

use std::cmp::Ordering;
use std::collections::HashMap;

use pyo3::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Dec {
    coef: i128,
    exp: i32,
}

const ZERO: Dec = Dec { coef: 0, exp: 0 };

fn pow10(n: u32) -> Option<i128> {
    10i128.checked_pow(n)
}

impl Dec {
    /// Python's ``str(Decimal)`` of a finite value (plain or scientific notation). None for
    /// anything else, or a negative zero.
    fn parse(s: &str) -> Option<Dec> {
        let b = s.as_bytes();
        let mut i = 0;
        let negative = match b.first() {
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
        let mut coef: i128 = 0;
        let mut digits = 0;
        let mut frac = 0i32;
        let mut point = false;
        while i < b.len() {
            match b[i] {
                c @ b'0'..=b'9' => {
                    coef = coef.checked_mul(10)?.checked_add((c - b'0') as i128)?;
                    digits += 1;
                    if point {
                        frac += 1;
                    }
                }
                b'.' if !point => point = true,
                _ => break,
            }
            i += 1;
        }
        if digits == 0 {
            return None;
        }
        let mut exp: i32 = 0;
        if i < b.len() {
            if b[i] != b'E' && b[i] != b'e' {
                return None;
            }
            exp = std::str::from_utf8(&b[i + 1..]).ok()?.parse::<i32>().ok()?;
            if exp.abs() > 1_000 {
                return None;
            }
        }
        if negative && coef == 0 {
            return None; // (a negative zero: Python's sign rules for it are not reproduced)
        }
        Some(Dec {
            coef: if negative { -coef } else { coef },
            exp: exp.checked_sub(frac)?,
        })
    }

    fn render(self) -> String {
        format!("{}E{}", self.coef, self.exp)
    }

    /// Both at the smaller exponent (exactly), or None past 128 bits.
    fn aligned(self, other: Dec) -> Option<(i128, i128, i32)> {
        let e = self.exp.min(other.exp);
        let a = self.coef.checked_mul(pow10((self.exp - e) as u32)?)?;
        let b = other.coef.checked_mul(pow10((other.exp - e) as u32)?)?;
        Some((a, b, e))
    }

    fn add(self, other: Dec) -> Option<Dec> {
        let (a, b, e) = self.aligned(other)?;
        Some(Dec {
            coef: a.checked_add(b)?,
            exp: e,
        })
    }

    fn neg(self) -> Dec {
        Dec {
            coef: -self.coef,
            exp: self.exp,
        }
    }

    fn sub(self, other: Dec) -> Option<Dec> {
        self.add(other.neg())
    }

    fn cmp(self, other: Dec) -> Option<Ordering> {
        let (a, b, _) = self.aligned(other)?;
        Some(a.cmp(&b))
    }
}

fn dec(s: &str) -> Option<Dec> {
    Dec::parse(s)
}

/// A dict that remembers the order keys entered it, as a Python dict does.
struct Ordered {
    values: HashMap<String, Dec>,
    added: Vec<String>, // keys absent at the start, in the order they were added
}

impl Ordered {
    fn get(&self, k: &str) -> Option<Dec> {
        self.values.get(k).copied()
    }

    fn set(&mut self, k: &str, v: Dec) {
        if self.values.insert(k.to_string(), v).is_none() {
            self.added.push(k.to_string());
        }
    }
}

/// ``section_errors`` over a run of plain transfers: ``txs`` = [(lane, nonce, payer, max fee)],
/// ``nonces`` = {lane: expected next}, ``owed`` = {payer: owed so far}, ``balance`` = {payer:
/// held or None}. Returns ({lane: next nonce}, {payer: owed}) if every one may be in the block,
/// else None: Python judges the run itself (and words the refusal).
#[pyfunction]
pub fn lane_judge(
    txs: Vec<(String, u64, String, String)>,
    nonces: HashMap<String, u64>,
    owed: HashMap<String, String>,
    balance: HashMap<String, Option<String>>,
) -> Option<(HashMap<String, u64>, HashMap<String, String>)> {
    let mut nonces = nonces;
    let mut owing: HashMap<String, Dec> = HashMap::new();
    for (payer, v) in &owed {
        owing.insert(payer.clone(), dec(v)?);
    }
    let mut held: HashMap<String, Option<Dec>> = HashMap::new();
    for (payer, v) in &balance {
        held.insert(
            payer.clone(),
            match v {
                None => None,
                Some(s) => Some(dec(s)?),
            },
        );
    }
    for (lane, nonce, payer, max_fee) in &txs {
        let expected = *nonces.get(lane)?;
        if *nonce != expected {
            return None;
        }
        let need = owing.get(payer).copied().unwrap_or(ZERO).add(dec(max_fee)?)?;
        let avail = (*held.get(payer)?)?;
        if avail.cmp(need)? == Ordering::Less {
            return None;
        }
        owing.insert(payer.clone(), need);
        nonces.insert(lane.clone(), nonce + 1);
    }
    let owed_out = owing.into_iter().map(|(k, v)| (k, v.render())).collect();
    Some((nonces, owed_out))
}

/// What ``lane_run`` hands back: each transaction's outcome — (it ran, the available balance it
/// found when it did not: None when none was loaded) — each lane's next nonce, each touched delta
/// and available balance, the addresses that entered the delta dict in order, and the block's
/// fees.
type RunOut = (
    Vec<(bool, Option<String>)>,
    HashMap<String, u64>,
    Vec<(String, String)>,
    Vec<String>,
    Vec<(String, String)>,
    String,
);

/// ``process_transaction`` over a run of plain transfers judged includable:
/// ``txs`` = [(lane, nonce, sender, to, amount, payer, reserved, fee)]; ``nonces`` = {lane:
/// expected}; ``deltas`` / ``available`` = {address: value or None if absent}; ``fees``: the
/// block's fees so far. None: bail (a nonce out of sequence — Python raises as it does — or a
/// value not reproduced exactly).
#[pyfunction]
#[allow(clippy::type_complexity)]
pub fn lane_run(
    txs: Vec<(String, u64, String, String, String, String, String, String)>,
    nonces: HashMap<String, u64>,
    deltas: HashMap<String, Option<String>>,
    available: HashMap<String, Option<String>>,
    fees: String,
) -> Option<RunOut> {
    let mut nonces = nonces;
    let mut delta = Ordered {
        values: HashMap::new(),
        added: Vec::new(),
    };
    for (k, v) in &deltas {
        if let Some(s) = v {
            delta.values.insert(k.clone(), dec(s)?);
        }
    }
    let mut avail: HashMap<String, Dec> = HashMap::new();
    for (k, v) in &available {
        if let Some(s) = v {
            avail.insert(k.clone(), dec(s)?);
        }
    }
    let mut touched_delta: Vec<String> = Vec::new();
    let mut touched_avail: Vec<String> = Vec::new();
    let mut block_fees = dec(&fees)?;
    let mut outcomes = Vec::with_capacity(txs.len());

    // ``_record_balance_delta``
    fn record(
        delta: &mut Ordered,
        avail: &mut HashMap<String, Dec>,
        touched_delta: &mut Vec<String>,
        touched_avail: &mut Vec<String>,
        addr: &str,
        d: Dec,
    ) -> Option<()> {
        let v = delta.get(addr).unwrap_or(ZERO).add(d)?;
        delta.set(addr, v);
        touched_delta.push(addr.to_string());
        if let Some(a) = avail.get(addr).copied() {
            avail.insert(addr.to_string(), a.add(d)?);
            touched_avail.push(addr.to_string());
        }
        Some(())
    }

    for (lane, nonce, sender, to, amount, payer, reserved, fee) in &txs {
        if *nonces.get(lane)? != *nonce {
            return None;
        }
        let v = dec(amount)?;
        // the operation: the sender's available QRDX must cover the amount
        let found = avail.get(sender).copied();
        let short = match found {
            None => true,
            Some(a) => a.cmp(v)? == Ordering::Less,
        };
        if short {
            outcomes.push((false, found.map(|a| a.render())));
        } else {
            record(&mut delta, &mut avail, &mut touched_delta, &mut touched_avail, sender, v.neg())?;
            record(&mut delta, &mut avail, &mut touched_delta, &mut touched_avail, to, v)?;
            outcomes.push((true, None));
        }
        // its nonce, then its gas: the reservation back, less what it used
        nonces.insert(lane.clone(), nonce + 1);
        let f = dec(fee)?;
        let back = dec(reserved)?.sub(f)?;
        record(&mut delta, &mut avail, &mut touched_delta, &mut touched_avail, payer, back)?;
        block_fees = block_fees.add(f)?;
    }
    touched_delta.sort();
    touched_delta.dedup();
    touched_avail.sort();
    touched_avail.dedup();
    let deltas_out = touched_delta
        .iter()
        .map(|k| (k.clone(), delta.get(k).expect("a touched delta").render()))
        .collect();
    let avail_out = touched_avail
        .iter()
        .map(|k| (k.clone(), avail[k].render()))
        .collect();
    Some((
        outcomes,
        nonces,
        deltas_out,
        delta.added,
        avail_out,
        block_fees.render(),
    ))
}

#[cfg(test)]
mod tests {
    use super::Dec;

    #[test]
    fn python_decimal_strings() {
        let p = |s| Dec::parse(s).map(|d| (d.coef, d.exp));
        assert_eq!(p("0.0002"), Some((2, -4)));
        assert_eq!(p("1000"), Some((1000, 0)));
        assert_eq!(p("1E+3"), Some((1, 3)));
        assert_eq!(p("-1.50"), Some((-150, -2)));
        assert_eq!(p("0E-8"), Some((0, -8)));
        assert_eq!(p("4E-5"), Some((4, -5)));
        assert_eq!(p("-0"), None);
        assert_eq!(p("Infinity"), None);
        assert_eq!(p("NaN"), None);
        assert_eq!(p(""), None);
        let a = Dec::parse("0.00004").unwrap();
        assert_eq!(a.sub(a).unwrap().render(), "0E-5");
        assert_eq!(Dec::parse("1").unwrap().add(Dec::parse("0.10").unwrap()).unwrap().render(), "110E-2");
    }
}
