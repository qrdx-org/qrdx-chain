"""
End-to-end exchange exercise: wallets + capital → custom tokens → trading
pairs → limit orders → a leveraged perpetual position.

This drives the REAL exchange engine (qrdx.exchange) through its single
deterministic entry point, ``ExchangeStateManager.process_transaction``, plus
real qRC20 custom tokens with real Dilithium-signed transfers and real PQ
wallets. No stubs.

Flow:
  1. Create PQ wallets and set up capital (QRDX collateral ledger).
  2. Deploy two custom qRC20 tokens (qBTC, qUSD) and fund wallets with them
     using real PQ-signed transfers.
  3. Create a trading pair (concentrated-liquidity AMM pool, which also spins
     up the matching order book + TWAP oracle).
  4. Add liquidity.
  5. Place limit orders on the order book and match a maker/taker pair.
  6. Open a leveraged perpetual position (the "limit order with leverage"),
     verify margin = notional / leverage, enforce the leverage cap, then close
     it for PnL.
  7. Finalize the block and compute the consensus state root.

Runnable directly (``python tests/test_exchange_e2e_leverage.py``) for a
readable report, or via pytest as ``test_exchange_e2e_leverage``.
"""

import asyncio
from decimal import Decimal


import pytest

from qrdx.crypto.pq.dilithium import PQPrivateKey, PQPublicKey, PQSignature, verify
from qrdx.tokens.qrc20 import QRC20Token, QRC20Registry, _make_transfer_digest
from qrdx.exchange import (
    ExchangeStateManager,
    ExchangeTransaction,
    ExchangeOpType,
    PerpSide,
)
from qrdx.exchange.amm import FeeTier, PoolType


# ─────────────────────────────────────────────────────────────────────────
#  Wallet + capital helpers
# ─────────────────────────────────────────────────────────────────────────

class Wallet:
    """A real PQ (Dilithium3) wallet with a QRDX collateral ledger."""

    def __init__(self, label: str, qrdx_capital: Decimal):
        self.label = label
        self.key = PQPrivateKey.generate()
        self.pub = self.key.public_key
        self.address = self.pub.to_address()
        # QRDX collateral available for staking / margin.
        self.capital = qrdx_capital

    def spend(self, amount: Decimal, reason: str):
        """Deduct capital, asserting the wallet is actually funded for it."""
        assert self.capital >= amount, (
            f"{self.label} undercapitalised for {reason}: "
            f"need {amount}, have {self.capital}"
        )
        self.capital -= amount


def make_tx(sender_addr, op_type, params, nonce, gas_limit=1_000_000):
    return ExchangeTransaction(
        op_type=op_type,
        sender=sender_addr,
        nonce=nonce,
        params=params,
        gas_limit=gas_limit,
        gas_price=Decimal("1"),
    )


# ─────────────────────────────────────────────────────────────────────────
#  The end-to-end exercise
# ─────────────────────────────────────────────────────────────────────────

async def run_exchange_e2e(report=False):
    def say(*a):
        if report:
            print(*a)

    # ---- 1. Wallets + capital -------------------------------------------
    issuer    = Wallet("Token Issuer",  Decimal("0"))        # mints the tokens
    lp        = Wallet("Liquidity Prov", Decimal("50000"))   # AMM pool stake + liquidity
    maker     = Wallet("Market Maker",   Decimal("100000"))  # posts limit sells
    taker     = Wallet("Taker/Long",     Decimal("100000"))  # limit buy + leveraged long
    hedger    = Wallet("Hedger/Short",   Decimal("100000"))  # leveraged short
    wallets = [issuer, lp, maker, taker, hedger]

    # Every wallet must have a distinct, real PQ address.
    assert len({w.address for w in wallets}) == len(wallets)
    for w in wallets:
        assert w.address.startswith("0xPQ"), f"{w.label} is not a PQ wallet"
    say("\n=== 1. Wallets + capital ===")
    for w in wallets:
        say(f"  {w.label:14} {w.address[:26]}…  capital={w.capital} QRDX")

    # ---- 2. Custom qRC20 tokens with real PQ-signed transfers -----------
    # Inject a real Dilithium verifier so transfers are genuinely PQ-verified.
    pubkeys = {w.address: w.pub for w in wallets}

    async def pq_verify(address: str, message: bytes, signature: bytes) -> bool:
        pk = pubkeys.get(address)
        if pk is None:
            return False
        return verify(pk, message, PQSignature.from_bytes(signature))

    registry = QRC20Registry()
    qbtc = registry.deploy(QRC20Token(
        "Quantum Bitcoin", "qBTC", decimals=8,
        total_supply=Decimal("1000"), deployer=issuer.address,
        verify_signature_fn=pq_verify,
    ))
    qusd = registry.deploy(QRC20Token(
        "Quantum USD", "qUSD", decimals=2,
        total_supply=Decimal("100000000"), deployer=issuer.address,
        verify_signature_fn=pq_verify,
    ))
    assert qbtc.balance_of(issuer.address) == Decimal("1000")
    assert qusd.balance_of(issuer.address) == Decimal("100000000")

    async def signed_transfer(token, frm: Wallet, to: Wallet, amount: Decimal):
        nonce = token._nonces.get(frm.address, 0)
        digest = _make_transfer_digest(token.symbol, frm.address, to.address, amount, nonce)
        sig = frm.key.sign(digest).to_bytes()
        return await token.transfer(frm.address, to.address, amount, signature=sig)

    # Distribute token capital from the issuer to the participants.
    await signed_transfer(qbtc, issuer, maker,  Decimal("100"))
    await signed_transfer(qbtc, issuer, lp,     Decimal("50"))
    await signed_transfer(qusd, issuer, taker,  Decimal("3000000"))
    await signed_transfer(qusd, issuer, hedger, Decimal("3000000"))
    await signed_transfer(qusd, issuer, lp,     Decimal("1500000"))

    assert qbtc.balance_of(maker.address) == Decimal("100")
    assert qusd.balance_of(taker.address) == Decimal("3000000")
    # Conservation: issuer balance reduced by exactly what was distributed.
    assert qbtc.balance_of(issuer.address) == Decimal("1000") - Decimal("150")
    say("\n=== 2. Custom qRC20 tokens (real PQ-signed transfers) ===")
    say(f"  qBTC supply={qbtc.total_supply}  maker={qbtc.balance_of(maker.address)} qBTC")
    say(f"  qUSD supply={qusd.total_supply}  taker={qusd.balance_of(taker.address)} qUSD")

    # ---- 3. Trading pair (AMM pool + order book + oracle) ---------------
    ExchangeStateManager.reset_instance()
    sm = ExchangeStateManager.get_instance()
    sm.begin_block(block_height=1, block_timestamp=1_700_000_000.0)

    # The engine advances a sender's nonce only on success, so query it each
    # time rather than tracking locally (a rejected tx must not consume a nonce).
    def next_nonce(addr):
        return sm.get_nonce(addr)

    POOL_STAKE = Decimal("10000")  # STANDARD pool stake requirement
    lp.spend(POOL_STAKE, "AMM pool stake")
    r = sm.process_transaction(make_tx(
        lp.address, ExchangeOpType.CREATE_POOL,
        {
            "token0": "qBTC", "token1": "qUSD",
            "fee_tier": int(FeeTier.MEDIUM),
            "pool_type": int(PoolType.STANDARD),
            "initial_sqrt_price": "173.205080756",  # ~ sqrt(30000) → 1 qBTC ≈ 30000 qUSD
            "stake_amount": str(POOL_STAKE),
        },
        next_nonce(lp.address),
    ))
    assert r.success, f"CREATE_POOL failed: {r.error}"
    pool_id = r.data["pool_id"]
    pair = r.data["pair"]
    assert sm.get_order_book(pair) is not None, "order book not auto-created"
    assert sm.get_oracle(pair) is not None, "oracle not auto-created"
    say("\n=== 3. Trading pair created ===")
    say(f"  pair={pair}  pool_id={pool_id[:16]}…  (order book + TWAP oracle attached)")

    # ---- 4. Add liquidity -----------------------------------------------
    lp.spend(Decimal("5000"), "AMM liquidity")
    r = sm.process_transaction(make_tx(
        lp.address, ExchangeOpType.ADD_LIQUIDITY,
        {"pool_id": pool_id, "tick_lower": -887220, "tick_upper": 887220, "amount": "5000"},
        next_nonce(lp.address),
    ))
    assert r.success, f"ADD_LIQUIDITY failed: {r.error}"
    say("\n=== 4. Liquidity added ===")
    say(f"  position={r.data['position_id'][:16]}…  amount=5000")

    # ---- 5. Limit orders on the order book ------------------------------
    # Maker posts a resting SELL limit; taker crosses it with a BUY limit.
    r = sm.process_transaction(make_tx(
        maker.address, ExchangeOpType.PLACE_ORDER,
        {"pair": pair, "side": "sell", "order_type": "limit", "price": "30000", "amount": "1"},
        next_nonce(maker.address),
    ))
    assert r.success, f"maker PLACE_ORDER failed: {r.error}"
    assert r.data["trades"] == 0, "resting sell should not match an empty book"

    r = sm.process_transaction(make_tx(
        taker.address, ExchangeOpType.PLACE_ORDER,
        {"pair": pair, "side": "buy", "order_type": "limit", "price": "30000", "amount": "1"},
        next_nonce(taker.address),
    ))
    assert r.success, f"taker PLACE_ORDER failed: {r.error}"
    assert r.data["trades"] >= 1, "crossing buy limit should match the resting sell"
    assert Decimal(r.data["filled"]) == Decimal("1"), "taker order should be fully filled"
    say("\n=== 5. Limit orders matched ===")
    say(f"  maker SELL 1 qBTC @30000  ↔  taker BUY 1 qBTC @30000  → trades={r.data['trades']}, filled={r.data['filled']}")

    # ---- 6. Leveraged perpetual positions (clearinghouse order book) -----
    # Perps trade on an order book: every position has a counterparty, so whatever one
    # trader makes another loses (docs/PERPS_CLEARINGHOUSE.md). The market is set up on the
    # clearinghouse directly and priced as an authorized oracle reporter would.
    ch = sm.clearinghouse
    market = ch.create_market("qBTC", "qUSD", max_leverage=Decimal("20"))
    market_id = market.id
    LEVERAGE = Decimal("10")
    SIZE = Decimal("2")          # 2 qBTC
    ENTRY = Decimal("30000")     # qUSD per qBTC
    notional = SIZE * ENTRY                      # 60,000
    expected_margin = notional / LEVERAGE        # 6,000 at 10x
    ch.set_oracle_price(market_id, ENTRY)

    for who, collateral in ((taker, Decimal("20000")), (hedger, Decimal("20000"))):
        who.spend(collateral, "perp collateral deposit")
        r = sm.process_transaction(make_tx(who.address, ExchangeOpType.PERP_DEPOSIT,
                                           {"amount": str(collateral)}, next_nonce(who.address)))
        assert r.success, f"PERP_DEPOSIT failed: {r.error}"
    for who, lev in ((taker, LEVERAGE), (hedger, Decimal("5"))):
        r = sm.process_transaction(make_tx(who.address, ExchangeOpType.PERP_SET_LEVERAGE,
                                           {"market_id": market_id, "leverage": str(lev)},
                                           next_nonce(who.address)))
        assert r.success, f"PERP_SET_LEVERAGE failed: {r.error}"

    # Leverage cap is enforced: 25x must be rejected (max is 20x).
    r = sm.process_transaction(make_tx(taker.address, ExchangeOpType.PERP_SET_LEVERAGE,
                                       {"market_id": market_id, "leverage": "25"},
                                       next_nonce(taker.address)))
    assert not r.success, "leverage above the 20x cap must be rejected"

    # The hedger rests a sell; the taker lifts it. One trade, two equal and opposite positions.
    r = sm.process_transaction(make_tx(hedger.address, ExchangeOpType.PERP_ORDER,
                                       {"market_id": market_id, "side": "sell",
                                        "size": str(SIZE), "price": str(ENTRY)},
                                       next_nonce(hedger.address)))
    assert r.success, f"hedger sell failed: {r.error}"
    r = sm.process_transaction(make_tx(taker.address, ExchangeOpType.PERP_ORDER,
                                       {"market_id": market_id, "side": "buy",
                                        "size": str(SIZE), "price": str(ENTRY)},
                                       next_nonce(taker.address)))
    assert r.success and len(r.data["fills"]) == 1, f"taker buy failed: {r.error}"
    assert ch.accounts[taker.address].positions[market_id].size == SIZE
    assert ch.accounts[hedger.address].positions[market_id].size == -SIZE
    assert ch.cross_requirement(taker.address) == expected_margin

    say("\n=== 6. Leveraged perpetual positions (order book) ===")
    say(f"  market={market_id}  max_leverage={market.max_leverage}x")
    say(f"  taker LONG {SIZE} qBTC @ {ENTRY} {LEVERAGE}x vs hedger SHORT {SIZE} @ {ENTRY} 5x")
    say(f"  taker initial margin = {expected_margin} (notional {notional}); 25x REJECTED")

    # ---- 7. Close for PnL, finalize the block -------------------------
    EXIT = Decimal("31000")  # +1000 per qBTC to the long — and −1000 per qBTC to the short
    ch.set_oracle_price(market_id, EXIT)
    r = sm.process_transaction(make_tx(hedger.address, ExchangeOpType.PERP_ORDER,
                                       {"market_id": market_id, "side": "buy",
                                        "size": str(SIZE), "price": str(EXIT),
                                        "reduce_only": True},
                                       next_nonce(hedger.address)))
    assert r.success, f"hedger close failed: {r.error}"
    r = sm.process_transaction(make_tx(taker.address, ExchangeOpType.PERP_ORDER,
                                       {"market_id": market_id, "side": "sell",
                                        "size": str(SIZE), "price": str(EXIT),
                                        "reduce_only": True},
                                       next_nonce(taker.address)))
    assert r.success, f"taker close failed: {r.error}"
    realized = Decimal(r.data["fills"][0]["realized"][taker.address])
    hedger_realized = Decimal(r.data["fills"][0]["realized"][hedger.address])
    expected_pnl = SIZE * (EXIT - ENTRY)
    assert realized == expected_pnl, f"PnL should be {expected_pnl}, got {realized}"
    assert hedger_realized == -expected_pnl, "the hedger's loss is exactly the taker's gain"
    assert ch.identity_gap() == 0 and ch.net_size(market_id) == 0

    state_root = sm.finalize_block()
    assert isinstance(state_root, str) and len(state_root) > 0
    stats = sm.get_stats()

    say("\n=== 7. Settlement ===")
    say(f"  taker closes LONG @ {EXIT}  → realized PnL = +{realized}; hedger {hedger_realized}")
    say(f"  block state_root = {state_root[:32]}…")
    say(f"  engine stats: {stats}")
    say("\n✅ Full exchange path exercised: tokens → pair → limit orders → leverage → settlement\n")

    return {
        "pair": pair,
        "pool_id": pool_id,
        "market_id": market_id,
        "long_margin": expected_margin,
        "realized_pnl": realized,
        "state_root": state_root,
        "stats": stats,
        "perp_trades": market.book.total_trades,
    }


# ─────────────────────────────────────────────────────────────────────────
#  pytest entry points
# ─────────────────────────────────────────────────────────────────────────

async def test_exchange_e2e_full_flow():
    """Tokens → pair → limit orders → leveraged perp → settlement, end to end."""
    result = await run_exchange_e2e(report=False)
    assert result["long_margin"] == Decimal("6000")
    assert result["realized_pnl"] == Decimal("2000")
    assert result["market_id"] == "qBTC-qUSD-PERP"
    # Both sides of the perp trade existed and both were closed by order-book fills.
    assert result["perp_trades"] == 2


if __name__ == "__main__":
    asyncio.run(run_exchange_e2e(report=True))
