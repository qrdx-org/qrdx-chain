"""
The exchange audit of 2026-10-27 (docs/EXCHANGE_AUDIT.md): one test for each defect it found
that the other test files do not already pin.

* A token's issuer could lock other people's funds in a shared protocol holder: freeze a pool's
  holder, pause the token, or pull the token out of the pool as its permanent delegate — and the
  pool's liquidity providers could no longer withdraw even their QRDX.
* State outside the undo scopes: a failed operation left a created pool, a bridge withdrawal's
  number, a proposal's number, the master freeze and oracle votes behind.
* The spot-trigger tick walked every order book whenever any trigger existed; each block reset
  every book.
"""
from decimal import Decimal

import pytest

from qrdx.exchange import ExchangeOpType as Op, ExchangeStateManager, ExchangeTransaction

D = Decimal
ISSUER, LP, ALICE = ("0xPQ" + c * 64 for c in "abc")
T = 1_700_000_000

_nonces = {}


def _tx(sender, op, **params):
    n = _nonces.get(sender, 0)
    _nonces[sender] = n + 1
    return ExchangeTransaction(op_type=op, sender=sender, nonce=n, params=params,
                               gas_limit=10_000_000, gas_price=10**9)


def _run(m, sender, op, **params):
    return m.process_transaction(_tx(sender, op, **params))


@pytest.fixture
def mgr():
    _nonces.clear()
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    m.enforce_spot_settlement = True
    m.enforce_orderbook_settlement = True
    for w in (ISSUER, LP, ALICE):
        m.set_available_balance(w, D(10**8))
    m.begin_block(1, float(T))
    yield m
    ExchangeStateManager.reset_instance()


# ── a token's issuer cannot lock the protocol's shared holders ────────────

def _issuers_pool(m, **authority):
    """ISSUER's token X, pooled against QRDX by LP; the LP's position."""
    r = _run(m, ISSUER, Op.TOKEN_DEPLOY, name="X", symbol="XX", total_supply="1000000",
             **authority)
    assert r.success, r.error
    x = r.data["token_address"]
    if authority.get("default_frozen"):                        # (every account starts frozen)
        for who in (LP, ALICE):
            assert _run(m, ISSUER, Op.TOKEN_THAW, token_address=x, account=who).success
    m.set_available_token_balance(LP, x, D(100_000))
    m.set_available_token_balance(ALICE, x, D(100_000))
    r = _run(m, LP, Op.CREATE_POOL, token0=x, token1="QRDX", fee_tier=3000,
             pool_type="STANDARD", initial_price="1", stake_amount="25")
    assert r.success, r.error
    pid = r.data["pool_id"]
    holder = m.pool_holder_address(pid)
    m.set_available_balance(holder, D(0))
    m.set_available_token_balance(holder, x, D(0))
    escrow = m.orderbook_escrow_address(r.data["pair"])
    m.set_available_balance(escrow, D(0))
    m.set_available_token_balance(escrow, x, D(0))
    r = _run(m, LP, Op.ADD_LIQUIDITY, pool_id=pid, tick_lower=-60000, tick_upper=60000,
             amount="10000")
    assert r.success, r.error
    return x, pid, holder, r.data["position_id"], escrow


def test_an_issuer_cannot_freeze_a_pools_holder(mgr):
    """It could: the pool's LPs then could not withdraw at all, their QRDX included."""
    x, pid, holder, pos, _ = _issuers_pool(mgr, freeze_authority=ISSUER)
    r = _run(mgr, ISSUER, Op.TOKEN_FREEZE, token_address=x, account=holder)
    assert not r.success and "cannot be frozen" in r.error
    assert _run(mgr, LP, Op.REMOVE_LIQUIDITY, pool_id=pid, position_id=pos).success


def test_a_default_frozen_token_does_not_freeze_a_pools_holder(mgr):
    x, pid, holder, pos, _ = _issuers_pool(mgr, freeze_authority=ISSUER, default_frozen=True)
    assert not mgr.tokens.is_frozen(x, holder)
    assert _run(mgr, LP, Op.REMOVE_LIQUIDITY, pool_id=pid, position_id=pos).success


def test_a_permanent_delegate_cannot_pull_tokens_out_of_a_pool(mgr):
    """It could, and the pool then could not cover its positions: withdrawals failed."""
    x, pid, holder, pos, _ = _issuers_pool(mgr, permanent_delegate=ISSUER)
    mgr.set_available_token_balance(holder, x, mgr.available_token_balance(holder, x))
    r = _run(mgr, ISSUER, Op.TOKEN_TRANSFER_FROM, token_address=x,
             **{"from": holder, "to": ISSUER, "amount": "100"})
    assert not r.success and "protocol holds" in r.error
    r = _run(mgr, ISSUER, Op.TOKEN_BURN, token_address=x, amount="100", **{"from": holder})
    assert not r.success and "protocol holds" in r.error
    assert _run(mgr, LP, Op.REMOVE_LIQUIDITY, pool_id=pid, position_id=pos).success


def test_a_paused_token_stops_trading_but_not_withdrawals_or_refunds(mgr):
    x, pid, holder, pos, escrow = _issuers_pool(mgr, pausable=True, pause_authority=ISSUER)
    pair = f"{x}:QRDX"
    r = _run(mgr, ALICE, Op.PLACE_ORDER, pair=pair, side="sell", order_type="limit",
             price="1.5", amount="10")                        # rests: escrows 10 X
    assert r.success, r.error
    oid = r.data["order_id"]
    assert _run(mgr, ISSUER, Op.TOKEN_PAUSE, token_address=x).success
    r = _run(mgr, ALICE, Op.SWAP, token_in=x, token_out="QRDX", amount_in="10")
    assert not r.success and "paused" in r.error              # no trading…
    assert _run(mgr, ALICE, Op.CANCEL_ORDER, pair=pair, order_id=oid).success  # …but refunds
    assert mgr.token_balance_deltas().get((escrow, x), D(0)) == 0
    r = _run(mgr, LP, Op.REMOVE_LIQUIDITY, pool_id=pid, position_id=pos)
    assert r.success, r.error                                  # …and withdrawals, QRDX too


# ── a failed operation leaves nothing behind ───────────────────────────────

class _Boom(Exception):
    pass


def _fails_cleanly(m, body):
    """Run ``body`` in an operation's undo scope and fail it: the state root must be as it was
    and the plain fields it changed put back."""
    before = m.compute_state_root()
    with pytest.raises(_Boom):
        with m.atomic():
            body()
            raise _Boom()
    assert m.compute_state_root() == before


def test_a_failed_pool_creation_leaves_no_pool_book_or_counter(mgr):
    seq = mgr.pool_manager._pool_sequence
    _fails_cleanly(mgr, lambda: mgr._execute_op(_tx(
        LP, Op.CREATE_POOL, token0="0x" + "11" * 20, token1="QRDX", fee_tier=3000,
        pool_type="STANDARD", initial_price="1", stake_amount="25")))
    assert mgr.pool_manager._pool_sequence == seq and not mgr.pool_manager._pools
    assert not mgr._order_books and not mgr.router._order_books


def test_a_failed_bridge_withdrawal_leaves_no_withdrawal_number(mgr):
    before = mgr.bridge.next_withdrawal
    _fails_cleanly(mgr, lambda: mgr.bridge.record_withdrawal({"amount": "1"}))
    assert mgr.bridge.next_withdrawal == before and not mgr.bridge.withdrawals


def test_a_failed_proposal_leaves_no_proposal_number(mgr):
    g = mgr.governance
    before = g.next_id
    committee = {ALICE.lower(): D(1000)}
    _fails_cleanly(mgr, lambda: g.propose(ALICE, {"action": "freeze_master"}, 1, committee))
    assert g.next_id == before


def test_a_failed_oracle_vote_leaves_no_vote(mgr, oracle_committee, genesis_btc):
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    m.begin_block(1, float(T))
    oracle_committee.load(m)
    _fails_cleanly(m, lambda: m._execute_op(oracle_committee.vote({"BTC": "30000"})))
    assert not m.oracle_votes


# ── the tick's spot triggers cost the pairs that hold them ─────────────────

def test_the_trigger_tick_and_the_block_start_leave_idle_books_alone(mgr, monkeypatch):
    from qrdx.exchange.orderbook import OrderBook, SelfTradeAction

    for i in range(50):
        key = f"0x{i:040x}:QRDX"
        book = OrderBook(pool_id=key, self_trade_action=SelfTradeAction.CANCEL_TAKER)
        book.last_price = D(1)
        mgr._order_books[key] = book
        mgr.router.register_order_book(key, book)
    pair = "0x" + "0" * 40 + ":QRDX"
    mgr.trading.spot_triggers["t"] = mgr.trading.new_spot_trigger(
        owner=ALICE, pair=pair, side="sell", kind="sl", trigger_price=D("0.5"), amount=D(1),
        limit_price=D(0), tif="ioc", max_makers=5, escrowed=D(1))
    assert mgr.trading.trigger_pairs() == [pair]
    resets = []
    real_new_block = OrderBook.new_block

    def counting(self, now=None):
        resets.append(self)
        return real_new_block(self, now)

    monkeypatch.setattr(OrderBook, "new_block", counting)
    mgr.begin_block(2, float(T + 1))
    assert resets == []                                           # no book starts eagerly
    book = mgr._order_books[pair]
    book._block_order_count[ALICE] = 50                           # (at its per-block limit)
    mgr.set_available_token_balance(ALICE, "0x" + "0" * 40, D(10))
    mgr.begin_block(3, float(T + 2))
    r = _run(mgr, ALICE, Op.PLACE_ORDER, pair=pair, side="sell", order_type="limit",
             price="2", amount="1")
    assert r.success, r.error                                     # its first use started it
    assert resets == [book] and book._block_order_count == {ALICE: 1}


# ── a block cannot carry exchange transactions nobody signed ──────────────

async def test_a_block_without_an_exchange_root_cannot_carry_forged_transactions(monkeypatch):
    """CRITICAL (found in this audit): the importer verified the exchange section's signatures
    only when the block declared an exchange state root. A proposer that left the root out had
    its section "trust-replayed": every transaction executed unverified, so it could move any
    account's funds with an unsigned transaction in its name."""
    import os
    import tempfile

    from qrdx.crypto.pq.dilithium import PQPrivateKey
    from qrdx.database_sqlite import DatabaseSQLite
    from qrdx.exchange import block_processor as BP, encode_exchange_txs
    from qrdx.node import main as node_main
    from qrdx.node import block_import

    victim_key = PQPrivateKey.generate()
    victim = victim_key.public_key.to_address()
    thief = "0xPQ" + "e" * 64
    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    try:
        monkeypatch.setattr(node_main, "db", db, raising=False)
        import json

        await db.add_block(block_hash="00" * 32, block_height=0, block_content="",
                           validator_address="0xPQ" + "00" * 32, timestamp=T)
        await db.add_transaction(tx_hash="alloc-victim", block_hash="00" * 32, tx_hex=json.dumps(
            {"type": "genesis_allocation", "recipient": victim, "amount": "1000"}))
        await db.seed_genesis_account_state()
        ExchangeStateManager.reset_instance()
        mgr = ExchangeStateManager.get_instance()
        BP.apply_enforcement(mgr)
        deploy = ExchangeTransaction(op_type=Op.TOKEN_DEPLOY, sender=victim, nonce=0,
                                     params={"name": "V", "symbol": "VVV",
                                             "total_supply": "1000"},
                                     gas_limit=2_000_000, gas_price=10**9)
        deploy.public_key = victim_key.public_key.to_bytes()
        deploy.signature = victim_key.sign(deploy.signing_bytes()).to_bytes()
        await BP.preload_sender_balances(db, [deploy], mgr, 1)
        ok, err, _ = BP.process_exchange_transactions(1, float(T + 1), [deploy], mgr)
        assert ok, err
        mgr.commit_block()
        await BP.flush_token_balance_deltas(db, mgr)
        token = ExchangeStateManager.derive_token_address(victim, 0, "VVV")
        assert await db.get_token_balance(token, victim) == 1000

        forged = ExchangeTransaction(op_type=Op.TOKEN_TRANSFER, sender=victim, nonce=1,
                                     params={"token_address": token, "to": thief,
                                             "amount": "1000"},
                                     gas_limit=2_000_000, gas_price=10**9)  # never signed
        ok, err = await block_import._apply_exchange_section_on_import(
            2, float(T + 2), encode_exchange_txs([forged]), None)
        assert not ok and "failed verification" in err
        assert await db.get_token_balance(token, thief) == 0
        assert await db.get_token_balance(token, victim) == 1000
    finally:
        ExchangeStateManager.reset_instance()
        await db.close()
        os.remove(path)


def test_a_tokens_view_shows_what_its_issuer_can_still_do(mgr):
    """The powers an issuer keeps over holders (freeze, clawback, …) were there only as raw
    authorities and extensions; a wallet now gets them in plain terms."""
    from qrdx.exchange import views

    r = _run(mgr, ISSUER, Op.TOKEN_DEPLOY, name="Plain", symbol="PLN", total_supply="1000")
    assert views.token(mgr, r.data["token_address"])["issuer_powers"] == []
    r = _run(mgr, ISSUER, Op.TOKEN_DEPLOY, name="Held", symbol="HLD", total_supply="1000",
             freeze_authority=ISSUER, permanent_delegate=ISSUER, pausable=True,
             pause_authority=ISSUER, mint_authority=ISSUER)
    assert r.success, r.error
    powers = views.token(mgr, r.data["token_address"])["issuer_powers"]
    assert [p["power"] for p in powers] == ["mint", "freeze", "pause", "clawback"]
    assert all(p["by"] == ISSUER for p in powers)
    listed = {t["token_address"]: t for t in views.tokens(mgr)}
    assert listed[r.data["token_address"]]["issuer_powers"] == powers


def test_an_agents_swap_takes_the_best_route(mgr):
    """An agent could name the pool its swap used (``pool_id``, ``venue``): the account's funds
    into a thin pool the agent owns, past better prices. An agent's swap now takes the best
    route; the account's own swaps may still name one."""
    bot = "0xPQ" + "f" * 64
    a, b = "0x" + "11" * 20, "0x" + "22" * 20
    for who in (ALICE, LP):
        for t in (a, b):
            mgr.set_available_token_balance(who, t, D(1_000_000))
    r = _run(mgr, LP, Op.CREATE_POOL, token0=a, token1=b, fee_tier=3000, pool_type="STANDARD",
             initial_price="1", stake_amount="25")
    pid = r.data["pool_id"]
    for who, t in ((mgr.pool_holder_address(pid), a), (mgr.pool_holder_address(pid), b)):
        mgr.set_available_token_balance(who, t, D(0))
    assert _run(mgr, LP, Op.ADD_LIQUIDITY, pool_id=pid, tick_lower=-60000, tick_upper=60000,
                amount="100000").success
    assert _run(mgr, ALICE, Op.AGENT_APPROVE, agent=bot).success

    def agent_swap(**how):
        n = mgr.get_nonce(f"{ALICE}|{bot}")
        return mgr.process_transaction(ExchangeTransaction(
            op_type=Op.SWAP, sender=ALICE, signer=bot, nonce=n, gas_limit=10_000_000,
            gas_price=10**9, params={"token_in": a, "token_out": b, "amount_in": "10", **how}))

    for how in ({"pool_id": pid}, {"venue": "amm"}):
        r = agent_swap(**how)
        assert not r.success and "best route" in r.error
    assert agent_swap().success                                   # the best route: fine
    assert _run(mgr, ALICE, Op.SWAP, token_in=a, token_out=b, amount_in="10",
                pool_id=pid).success                              # the account's own: fine


# ── one validator cannot fill the bridge's state with deposits that never happened ──

def _fake_deposit(i, to=ALICE):
    from qrdx.exchange.bridge import Deposit

    return Deposit(42161, i + 1, "0x" + "aa" * 20, "0x" + "de" * 20, to, D(1), 0)


def test_a_validators_unmet_attestations_are_capped(monkeypatch):
    """A validator could attest made-up deposits without limit: each sat in the state for a
    day and every block's expiry walked them all (20 ms a block at 100,000)."""
    from qrdx.exchange import bridge as B

    monkeypatch.setattr(B, "MAX_PENDING_PER_VOTER", 3)
    br = B.Bridge()
    committee = {"bad": D(1), "honest": D(10)}
    for i in range(5):
        br.attest(_fake_deposit(i), "bad", D(1000), committee)
    assert len(br.pending) == 3                                   # the rest ignored
    assert br.attest(_fake_deposit(9), "honest", D(1000), committee)  # others unaffected
    br.complete(_fake_deposit(9))
    assert len(br.pending) == 3 and _fake_deposit(9).id in br.done
    br.attest(_fake_deposit(0), "honest", D(1000), committee)     # joining is not new for it
    br.expire(D(1000) + B.ATTESTATION_MAX_AGE + 1)                # a day later: all lapsed
    assert len(br.pending) == 0
    br.attest(_fake_deposit(7), "bad", D(200_000), committee)     # room again
    assert len(br.pending) == 1


def test_expiry_and_completion_touch_only_their_entries():
    from qrdx.exchange import bridge as B

    br = B.Bridge()
    committee = {"a": D(1), "b": D(1), "c": D(1)}
    br.attest(_fake_deposit(1), "a", D(100), committee)
    br.attest(_fake_deposit(2), "a", D(5000), committee)
    br.attest(_fake_deposit(2, to=LP), "b", D(5000), committee)   # a different content, same id
    br.expire(D(100) + B.ATTESTATION_MAX_AGE + 1)                  # only the first is that old
    assert sorted(k.split("|")[0] for k in br.pending) == [_fake_deposit(2).id] * 2
    br.complete(_fake_deposit(2))                                  # both contents of its id go
    assert not br.pending


def test_a_head_of_a_chain_the_network_does_not_bridge_is_skipped(monkeypatch, oracle_committee):
    """Heads were recorded for any chain id a vote named, each for an hour."""
    from qrdx import constants

    monkeypatch.setattr(constants, "BRIDGE_ASSETS",
                        ("USDC:42161:0xaf88d065e77c8cc2239327c5edb3a432268e5831:6",))
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    m.begin_block(1, float(T))
    oracle_committee.load(m)
    vote = oracle_committee.vote({})
    head = {"height": 5, "hash": "0x" + "1" * 64, "state_root": "0x" + "2" * 64, "timestamp": 1}
    vote.params = {"prices": {}, "heads": [{"chain": 99, **head}, {"chain": 42161, **head}]}
    vote.signature = oracle_committee.key.sign(vote.signing_bytes()).to_bytes()
    r = m.process_transaction(vote)
    assert r.success, r.error
    assert r.data["ignored_heads"] == [99] and r.data["heads"] == [42161]
    assert {k.split("|")[0] for k, _ in m.bridge.head_votes.peek_items()} == {"42161"}
    ExchangeStateManager.reset_instance()
