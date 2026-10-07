"""
Native QRDX is a spot asset: pools and order books pair "QRDX" with any token, and settle the
QRDX side in account balances (account_state) — the trader's, the pool's holder's, the book's
escrow's — with no wrapping step. Any spelling of QRDX names the same asset; QRDX sorts after
token addresses, so a QRDX pair's price is QRDX per token and its book is quoted in QRDX.
"""
import json
import os
import tempfile
from decimal import Decimal

import pytest

from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from qrdx.exchange import block_processor as BP
from qrdx.exchange.tokens import NATIVE_ASSET

D = Decimal
LP, TRADER, MAKER = ("0xPQ" + c * 64 for c in "abc")
_nonces = {}


def _tx(sender, op, **params):
    n = _nonces.get(sender, 0)
    _nonces[sender] = n + 1
    return ExchangeTransaction(op_type=op, sender=sender, nonce=n, params=params,
                               gas_limit=1_000_000)


@pytest.fixture
def mgr():
    _nonces.clear()
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    BP.apply_enforcement(m)                         # the production gates, fees included
    m.begin_block(1, 1_700_000_000.0)
    yield m
    ExchangeStateManager.reset_instance()


def _run(m, sender, op, **params):
    r = m.process_transaction(_tx(sender, op, **params))
    return r


def _setup(m):
    """A token, and a QRDX/token pool at 2 QRDX per token with LP liquidity."""
    for who in (LP, TRADER, MAKER):
        m.set_available_balance(who, D(1_000_000))
    r = _run(m, LP, ExchangeOpType.TOKEN_DEPLOY, name="Tok", symbol="TOK", total_supply="1000000")
    assert r.success, r.error
    tok = r.data["token_address"]
    m.set_available_token_balance(LP, tok, D(1_000_000))
    for who in (TRADER, MAKER):
        m.set_available_token_balance(who, tok, D(0))
    r = _run(m, LP, ExchangeOpType.CREATE_POOL, token0="qrdx", token1=tok.upper().replace("0X", "0x"),
             fee_tier=3000, pool_type="STANDARD", initial_price="2", stake_amount="10000")
    assert r.success, r.error
    pid = r.data["pool_id"]
    holder = m.pool_holder_address(pid)
    m.set_available_balance(holder, D(0))
    m.set_available_token_balance(holder, tok, D(0))
    escrow = m.orderbook_escrow_address(f"{tok}:{NATIVE_ASSET}")
    m.set_available_balance(escrow, D(0))
    m.set_available_token_balance(escrow, tok, D(0))
    r = _run(m, LP, ExchangeOpType.ADD_LIQUIDITY, pool_id=pid, tick_lower=-60000,
             tick_upper=60000, amount="100000")
    assert r.success, r.error
    return tok, pid, holder, escrow


def _qrdx(m, who):
    return m.balance_deltas().get(who, D(0))


def test_a_pool_pairs_native_qrdx_with_a_token(mgr):
    tok, pid, holder, _ = _setup(mgr)
    pool = mgr.pool_manager.get_pool(pid)
    assert (pool.state.token0, pool.state.token1) == (tok, NATIVE_ASSET)   # canonical, sorted
    # the LP's QRDX went into the pool's holder account, as did its tokens
    assert _qrdx(mgr, holder) > 0 and mgr.token_balance_deltas()[(holder, tok)] > 0
    before_trader = mgr.available_balance(TRADER)
    r = _run(mgr, TRADER, ExchangeOpType.SWAP, token_in="QRDX", token_out=tok, amount_in="100")
    assert r.success, r.error
    got = D(r.data["amount_out"])
    assert got > 0 and mgr.token_balance_deltas()[(TRADER, tok)] == got
    paid = before_trader - mgr.available_balance(TRADER)
    assert paid == 100 + r.fee                                  # 100 QRDX in, plus its gas
    r = _run(mgr, TRADER, ExchangeOpType.SWAP, token_in=tok, token_out="Qrdx", amount_in=str(got))
    assert r.success, r.error                                    # and back, into QRDX
    assert D(r.data["amount_out"]) > 0


def test_qrdx_is_conserved_through_liquidity_swaps_and_removal(mgr):
    tok, pid, holder, _ = _setup(mgr)
    for i in range(6):
        a, b = ("QRDX", tok) if i % 2 == 0 else (tok, "QRDX")
        amount = "50" if a == "QRDX" else "20"
        assert _run(mgr, TRADER, ExchangeOpType.SWAP, token_in=a, token_out=b,
                    amount_in=amount).success
    pos = next(iter(mgr.pool_manager.get_pool(pid).state.positions))
    assert _run(mgr, LP, ExchangeOpType.REMOVE_LIQUIDITY, pool_id=pid, position_id=pos).success
    # every QRDX move pairs a debit with a credit; only gas (burned) and the pool stake
    # (debited from the creator, held by the protocol) leave the accounts
    total = sum(mgr.balance_deltas().values(), D(0))
    assert total == -(mgr.block_fees + D(10000))
    pool = mgr.pool_manager.get_pool(pid)
    left = _qrdx(mgr, holder)
    assert D(0) <= left - pool.state.protocol_fees_1 < D("1e-12")   # only the protocol's fees


def test_an_order_book_quoted_in_qrdx(mgr):
    tok, _, _, escrow = _setup(mgr)
    mgr.set_available_token_balance(MAKER, tok, D(500))
    pair = f"QRDX:{tok}"                                         # either order, any casing
    r = _run(mgr, TRADER, ExchangeOpType.PLACE_ORDER, pair=pair, side="buy",
             order_type="limit", price="1.5", amount="40")
    assert r.success, r.error
    assert _qrdx(mgr, escrow) == D(60)                           # 40 × 1.5 QRDX escrowed
    r = _run(mgr, MAKER, ExchangeOpType.PLACE_ORDER, pair=pair, side="sell",
             order_type="limit", price="1.5", amount="10")
    assert r.success, r.error                                    # fills 10 at 1.5
    assert mgr.token_balance_deltas()[(TRADER, tok)] == D(10)
    assert _qrdx(mgr, MAKER) == D(15) - r.fee                    # the sale's proceeds …
    assert _qrdx(mgr, escrow) == D(45)                           # … came out of the escrow
    book = mgr._order_books[f"{tok}:{NATIVE_ASSET}"]
    oid = next(iter(book._orders))
    assert _run(mgr, TRADER, ExchangeOpType.CANCEL_ORDER, pair=pair, order_id=oid).success
    assert _qrdx(mgr, escrow) == 0                               # refunded in full


def test_a_pool_that_cannot_pay_qrdx_out_refuses_the_swap(mgr):
    tok, pid, holder, _ = _setup(mgr)
    mgr.set_available_token_balance(TRADER, tok, D(1000))
    mgr.set_available_balance(holder, D(0))                      # as if drained elsewhere
    pool = mgr.pool_manager.get_pool(pid)
    digest = pool.state_digest()
    r = _run(mgr, TRADER, ExchangeOpType.SWAP, token_in=tok, token_out="QRDX", amount_in="10")
    assert not r.success and "cannot cover" in r.error
    assert pool.state_digest() == digest


def test_a_trader_cannot_swap_its_gas_money(mgr):
    _setup(mgr)
    tok = next(iter(mgr.tokens.tokens))
    mgr.set_available_balance(TRADER, D("100.0005"))             # 100 + less than the reservation
    r = _run(mgr, TRADER, ExchangeOpType.SWAP, token_in="QRDX", token_out=tok, amount_in="100")
    assert not r.success and ("cannot cover" in r.error or "insufficient" in r.error), r.error


async def test_the_block_path_preloads_qrdx_for_holders_and_escrow():
    """Through the real preload: every QRDX debit — the trader's, the pool holder's, the
    book escrow's — is loaded from account balances, so none is refused as "not loaded"."""
    class Ledger:
        async def get_token_balance(self, token, holder):
            return D(10 ** 9)

        async def get_address_balance(self, address):
            return D(10 ** 9)

    _nonces.clear()
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    BP.apply_enforcement(m)
    db, h, results = Ledger(), [0], []

    async def block(*txs):
        h[0] += 1
        m.begin_block(h[0], 1_700_000_000.0 + h[0])
        await BP.preload_sender_balances(db, txs, m)
        await BP.preload_token_balances(db, txs, m)
        out = [m.process_transaction(t) for t in txs]
        results.extend(zip((t.op_type.name for t in txs), out))
        m.commit_block()
        return out

    try:
        (dep,) = await block(_tx(LP, ExchangeOpType.TOKEN_DEPLOY, name="T", symbol="T",
                                 total_supply="1000000"))
        tok = dep.data["token_address"]
        (pool,) = await block(_tx(LP, ExchangeOpType.CREATE_POOL, token0=tok, token1="QRDX",
                                  fee_tier=3000, pool_type="STANDARD", initial_price="1",
                                  stake_amount="10000"))
        pid = pool.data["pool_id"]
        await block(_tx(LP, ExchangeOpType.ADD_LIQUIDITY, pool_id=pid, tick_lower=-6000,
                        tick_upper=6000, amount="100000"))
        (order,) = await block(_tx(MAKER, ExchangeOpType.PLACE_ORDER, pair=f"{tok}:qrdx",
                                   side="buy", order_type="limit", price="0.99", amount="5"))
        await block(_tx(TRADER, ExchangeOpType.SWAP, token_in="QRDX", token_out=tok,
                        amount_in="3", venue="amm"),
                    _tx(TRADER, ExchangeOpType.SWAP, token_in=tok, token_out="QRDX",
                        amount_in="1", venue="amm"),
                    _tx(TRADER, ExchangeOpType.SWAP, token_in=tok, token_out="QRDX",
                        amount_in="1", venue="clob"))
        await block(_tx(MAKER, ExchangeOpType.CANCEL_ORDER, pair=f"QRDX:{tok}",
                        order_id=order.data["order_id"]))
        refused = [(n, r.error) for n, r in results if not r.success]
        assert refused == [], refused
    finally:
        ExchangeStateManager.reset_instance()


async def test_forward_and_rebuild_agree_on_a_qrdx_pool(monkeypatch):
    from qrdx.crypto.pq.dilithium import PQPrivateKey
    from qrdx.database_sqlite import DatabaseSQLite
    from qrdx.exchange import encode_exchange_txs
    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    try:
        k1, k2 = PQPrivateKey.generate(), PQPrivateKey.generate()
        a1, a2 = k1.public_key.to_address(), k2.public_key.to_address()
        tok = ExchangeStateManager.derive_token_address(a1, 0, "TOK")
        nonces = {a1: 0, a2: 0}

        def tx(key, op, **params):
            addr = key.public_key.to_address()
            t = ExchangeTransaction(op_type=op, sender=addr, nonce=nonces[addr], params=params,
                                    gas_limit=1_000_000)
            nonces[addr] += 1
            t.public_key = key.public_key.to_bytes()
            t.signature = key.sign(t.signing_bytes()).to_bytes()
            return t

        async def add(h, txs=(), alloc=()):
            bh = f"{h:064x}"
            await db.add_block(block_hash=bh, block_height=h, block_content="",
                               validator_address="0xPQ" + "00" * 32, timestamp=1_700_000_000 + h)
            for i, (r, amount) in enumerate(alloc):
                await db.add_transaction(tx_hash=f"a{i}", block_hash=bh, tx_hex=json.dumps(
                    {"type": "genesis_allocation", "recipient": r, "amount": amount}))
            if txs:
                await db.add_block_exchange_txs(bh, encode_exchange_txs(list(txs)))

        await add(0, alloc=[(a1, "1000000"), (a2, "1000000")])
        await add(1, [tx(k1, ExchangeOpType.TOKEN_DEPLOY, name="T", symbol="TOK",
                         total_supply="1000000")])
        await add(2, [tx(k1, ExchangeOpType.CREATE_POOL, token0="QRDX", token1=tok,
                         fee_tier=3000, pool_type="STANDARD", initial_price="2",
                         stake_amount="10000")])
        await add(3, [tx(k1, ExchangeOpType.ADD_LIQUIDITY, token0=tok, token1="QRDX",
                         tick_lower=-60000, tick_upper=60000, amount="100000")])
        await add(4, [tx(k2, ExchangeOpType.SWAP, token_in="QRDX", token_out=tok,
                         amount_in="250"),
                      tx(k2, ExchangeOpType.PLACE_ORDER, pair=f"{tok}:QRDX", side="buy",
                         order_type="limit", price="1", amount="7")])
        tip = 4

        await db.seed_genesis_account_state()
        await db.connection.commit()
        ExchangeStateManager.reset_instance()
        m = ExchangeStateManager.get_instance()
        BP.apply_enforcement(m)
        for h in range(1, tip + 1):
            txs = BP.decode_exchange_txs(await db.get_block_exchange_txs(f"{h:064x}"))
            await BP.preload_sender_balances(db, txs, m)
            await BP.preload_token_balances(db, txs, m)
            ok, err, _ = BP.process_exchange_transactions(h, float(1_700_000_000 + h), txs, m)
            assert ok, err
            assert len(m._block_results) == len(txs), "a transaction was refused before running"
            assert all(r.success for r in m._block_results), [r.error for r in m._block_results]
            m.commit_block()
            await BP.flush_exchange_balance_deltas(db, m, enforce=True)
            await BP.flush_token_balance_deltas(db, m)
        await db.connection.commit()
        pid = next(iter(m.pool_manager._pools))
        holder = m.pool_holder_address(pid)
        assert await db.get_address_balance(holder) > 0                  # QRDX in the pool
        escrow = m.orderbook_escrow_address(f"{tok}:QRDX")
        assert await db.get_address_balance(escrow) == D(7)              # QRDX on the book
        forward = (await db.get_account_state_root(), await db.get_token_balances_root(),
                   m.compute_state_root())

        await db.clear_account_state()
        await db.seed_genesis_account_state()
        await db.connection.commit()
        await db.clear_token_balances()
        ExchangeStateManager.reset_instance()
        await BP.rebuild_exchange_state_from_chain(db, flush_to_account_state=True)
        await db.connection.commit()
        rebuilt = (await db.get_account_state_root(), await db.get_token_balances_root(),
                   ExchangeStateManager.get_instance().compute_state_root())
        assert rebuilt == forward
    finally:
        ExchangeStateManager.reset_instance()
        await db.close()
        os.remove(path)
