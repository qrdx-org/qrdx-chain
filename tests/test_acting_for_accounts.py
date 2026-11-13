"""
Acting for an account (docs/TRADING_FEATURES.md): agent keys and sub-accounts.

An exchange transaction carries an optional ``signer``: the key that signed it when that is not
``sender``. The signature binds to the signer; execution then requires the account to have
authorized it — an agent it approved (trading operations only, until the approval expires or
is revoked), or the master of a sub-account — and refuses anything else before it consumes a
nonce or gas. A signer's transactions take their nonces from their own lane, so a bot and its
owner's wallet never race for the account's nonce.
"""
from decimal import Decimal as D

import pytest

from qrdx.crypto.account_id import is_synthetic_holder, to_account_id
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from qrdx.exchange.mempool import ExchangeMempool
from qrdx.exchange.trading import AGENTS_PER_ACCOUNT, subaccount_address

MID = "BTC-QRDX-PERP"
T0 = 1_700_000_000


class Key:
    def __init__(self):
        self.key = PQPrivateKey.generate()
        self.addr = self.key.public_key.to_address()

    def sign(self, tx):
        tx.public_key = self.key.public_key.to_bytes()
        tx.signature = self.key.sign(tx.signing_bytes()).to_bytes()
        return tx


@pytest.fixture(scope="module")
def keys():
    return {name: Key() for name in ("owner", "bot", "stranger")}


@pytest.fixture
def m(keys):
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.begin_block(1, float(T0))
    mgr.clearinghouse.create_market("BTC")
    mgr.clearinghouse.set_oracle_price(MID, D(100), now=T0)
    for k in keys.values():
        mgr.clearinghouse.deposit(k.addr, D(100_000))
    yield mgr
    ExchangeStateManager.reset_instance()


def _tx(m, sender, op, params, signer="", nonce=None):
    t = ExchangeTransaction(op_type=op, sender=sender, signer=signer, params=params,
                            nonce=m.get_nonce(f"{sender}|{signer}" if signer else sender)
                            if nonce is None else nonce, gas_limit=10 ** 6)
    return t


def _order(price="99"):
    return {"market_id": MID, "side": "buy", "size": "1", "price": price}


def test_the_signature_binds_to_the_signer_and_the_signer_is_signed(keys):
    owner, bot = keys["owner"], keys["bot"]
    t = bot.sign(ExchangeTransaction(op_type=ExchangeOpType.PERP_ORDER, sender=owner.addr,
                                     signer=bot.addr, nonce=0, params=_order()))
    assert t.verify()
    forged = ExchangeTransaction.from_dict({**t.to_dict(), "signer": keys["stranger"].addr})
    assert not forged.verify()                            # the signer is in what was signed
    unbound = ExchangeTransaction.from_dict({k: v for k, v in t.to_dict().items()
                                             if k != "signer"})
    assert not unbound.verify()                           # …and the key is not the owner's
    plain = ExchangeTransaction(op_type=ExchangeOpType.PERP_ORDER, sender=owner.addr, nonce=0,
                                params=_order())
    assert b"signer" not in plain.signing_bytes() and "signer" not in plain.to_dict()
    same = ExchangeTransaction(op_type=ExchangeOpType.PERP_ORDER, sender=owner.addr,
                               signer=owner.addr, nonce=0, params=_order())
    assert same.tx_hash() == plain.tx_hash()              # signing for yourself: one form
    round_trip = ExchangeTransaction.from_dict(t.to_dict())
    assert round_trip.tx_hash() == t.tx_hash() and round_trip.verify()


def test_an_approved_agent_trades_for_the_account_in_its_own_nonce_lane(m, keys):
    owner, bot = keys["owner"].addr, keys["bot"].addr
    r = m.process_transaction(_tx(m, owner, ExchangeOpType.PERP_ORDER, _order(), signer=bot))
    assert not r.success and "may not act" in r.error
    assert m.get_nonce(f"{owner}|{bot}") == 0 and m.get_nonce(owner) == 0   # nothing consumed
    assert m.process_transaction(_tx(m, owner, ExchangeOpType.AGENT_APPROVE,
                                     {"agent": bot, "name": "mm"})).success
    r = m.process_transaction(_tx(m, owner, ExchangeOpType.PERP_ORDER, _order(), signer=bot))
    assert r.success, r.error
    meta = m.clearinghouse.markets[MID].orders[r.data["order_id"]]
    assert meta.owner == owner                            # the account's order, not the bot's
    assert m.get_nonce(f"{owner}|{bot}") == 1 and m.get_nonce(owner) == 1   # lanes apart
    batch = {"actions": [{"op": "PERP_ORDER", "params": _order("98")},
                         {"op": "PERP_CANCEL", "params": {"market_id": MID,
                                                          "order_id": r.data["order_id"]}}]}
    assert m.process_transaction(_tx(m, owner, ExchangeOpType.BATCH, batch, signer=bot)).success


@pytest.mark.parametrize("op, params", [
    (ExchangeOpType.PERP_WITHDRAW, {"amount": "10"}),
    (ExchangeOpType.TOKEN_TRANSFER, {"token_address": "0x" + "1" * 40, "to": "x",
                                     "amount": "1"}),
    (ExchangeOpType.AGENT_APPROVE, {"agent": "0xPQ" + "2" * 64}),
    (ExchangeOpType.SUBACCOUNT_CREATE, {}),
    (ExchangeOpType.BATCH, {"actions": [{"op": "PERP_WITHDRAW", "params": {"amount": "1"}}]}),
])
def test_an_agent_trades_but_never_moves_funds(m, keys, op, params):
    owner, bot = keys["owner"].addr, keys["bot"].addr
    m.process_transaction(_tx(m, owner, ExchangeOpType.AGENT_APPROVE, {"agent": bot}))
    before = m.clearinghouse.commitment()
    r = m.process_transaction(_tx(m, owner, op, params, signer=bot))
    assert not r.success and ("may not sign" in r.error or "may not act" in r.error), r.error
    assert m.get_nonce(f"{owner}|{bot}") == 0 and m.clearinghouse.commitment() == before


def test_an_approval_expires_and_can_be_revoked_by_either_side(m, keys):
    owner, bot = keys["owner"].addr, keys["bot"].addr
    m.process_transaction(_tx(m, owner, ExchangeOpType.AGENT_APPROVE,
                              {"agent": bot, "valid_until": T0 + 60}))
    assert m.process_transaction(_tx(m, owner, ExchangeOpType.PERP_ORDER, _order(),
                                     signer=bot)).success
    m.begin_block(2, float(T0 + 60))
    r = m.process_transaction(_tx(m, owner, ExchangeOpType.PERP_ORDER, _order(), signer=bot))
    assert not r.success and "expired" in r.error
    m.process_transaction(_tx(m, owner, ExchangeOpType.AGENT_APPROVE, {"agent": bot}))
    assert m.process_transaction(_tx(m, owner, ExchangeOpType.AGENT_REVOKE, {"agent": bot},
                                     signer=bot)).success          # it gives itself up
    r = m.process_transaction(_tx(m, owner, ExchangeOpType.PERP_ORDER, _order(), signer=bot))
    assert not r.success and "may not act" in r.error


def test_approvals_are_bounded_and_checked(m, keys):
    owner = keys["owner"].addr
    for i in range(AGENTS_PER_ACCOUNT):
        assert m.process_transaction(_tx(m, owner, ExchangeOpType.AGENT_APPROVE,
                                         {"agent": "0xPQ" + f"{i:064x}"})).success
    for params, error in [
        ({"agent": "0xPQ" + "f" * 64}, "at most"),
        ({"agent": "0x" + "1" * 40}, "post-quantum"),
        ({"agent": owner}, "itself"),
        ({"agent": "0xPQ" + "0" * 64, "valid_until": T0 - 1}, "passed"),
    ]:
        r = m.process_transaction(_tx(m, owner, ExchangeOpType.AGENT_APPROVE, params))
        assert not r.success and error in r.error, (params, r.error)


def test_a_sub_account_is_its_own_margin_account_acted_for_only_by_its_master(m, keys):
    owner, bot, stranger = keys["owner"].addr, keys["bot"].addr, keys["stranger"].addr
    r = m.process_transaction(_tx(m, owner, ExchangeOpType.SUBACCOUNT_CREATE, {"name": "hedge"}))
    sub = r.data["subaccount"]
    assert sub == subaccount_address(owner, 0) and is_synthetic_holder(sub)
    assert to_account_id(sub) != to_account_id(owner)
    m.clearinghouse.deposit(sub, D(1_000))
    r = m.process_transaction(_tx(m, sub, ExchangeOpType.PERP_ORDER, _order(), signer=owner))
    assert r.success, r.error
    assert m.clearinghouse.markets[MID].orders[r.data["order_id"]].owner == sub
    r = m.process_transaction(_tx(m, sub, ExchangeOpType.PERP_ORDER, _order(),
                                  signer=stranger))
    assert not r.success and "may not act" in r.error
    # The master's agent trades for the sub-account too.
    m.process_transaction(_tx(m, owner, ExchangeOpType.AGENT_APPROVE, {"agent": bot}))
    assert m.process_transaction(_tx(m, sub, ExchangeOpType.PERP_ORDER, _order("97"),
                                     signer=bot)).success
    r = m.process_transaction(_tx(m, sub, ExchangeOpType.SUBACCOUNT_CREATE, {}, signer=owner))
    assert not r.success and "only the account itself" in r.error


def test_sub_account_transfers_move_real_balances_both_ways(m, keys):
    owner = keys["owner"].addr
    sub = m.process_transaction(_tx(m, owner, ExchangeOpType.SUBACCOUNT_CREATE,
                                    {})).data["subaccount"]
    m.set_available_token_balance(owner, "0xtok", D(50))
    m.set_available_token_balance(sub, "0xtok", D(0))
    ok = m.process_transaction(_tx(m, owner, ExchangeOpType.SUBACCOUNT_TRANSFER, {
        "subaccount": sub, "asset": "0xtok", "amount": "30", "direction": "to_sub"}))
    assert ok.success, ok.error
    r = m.process_transaction(_tx(m, owner, ExchangeOpType.SUBACCOUNT_TRANSFER, {
        "subaccount": sub, "asset": "0xtok", "amount": "31", "direction": "from_sub"}))
    assert not r.success and "insufficient" in r.error
    assert m.process_transaction(_tx(m, owner, ExchangeOpType.SUBACCOUNT_TRANSFER, {
        "subaccount": sub, "asset": "0xtok", "amount": "10", "direction": "from_sub"})).success
    d = m.token_balance_deltas()
    assert d[(owner, "0xtok")] == -20 and d[(sub, "0xtok")] == 20


def test_the_mempool_queues_each_signer_in_its_own_lane_and_only_if_authorized(m, keys):
    owner, bot = keys["owner"], keys["bot"]
    pool = ExchangeMempool()
    signed = bot.sign(_tx(m, owner.addr, ExchangeOpType.PERP_ORDER, _order(), signer=bot.addr,
                          nonce=0))
    ok, err = pool.admit(signed)
    assert not ok and "may not act" in err
    m.process_transaction(_tx(m, owner.addr, ExchangeOpType.AGENT_APPROVE, {"agent": bot.addr}))
    assert pool.admit(signed) == (True, "")
    own = owner.sign(_tx(m, owner.addr, ExchangeOpType.PERP_ORDER, _order("98"), nonce=1))
    assert pool.admit(own) == (True, "")                  # the account's lane: nonce 1
    chosen = pool.select_for_block()
    assert {t.tx_hash() for t in chosen} == {signed.tx_hash(), own.tx_hash()}


# ── user vaults ─────────────────────────────────────────────────────────────

def _vault(m, leader, amount="1000", **kw):
    r = m.process_transaction(_tx(m, leader, ExchangeOpType.VAULT_CREATE,
                                  {"amount": amount, "name": "alpha", **kw}))
    assert r.success, r.error
    return r.data["vault"]


def test_a_vault_trades_by_its_leaders_signature_and_only_trades(m, keys):
    leader, bot, stranger = keys["owner"].addr, keys["bot"].addr, keys["stranger"].addr
    vault = _vault(m, leader)
    assert is_synthetic_holder(vault)
    ch = m.clearinghouse
    assert ch.accounts[vault].collateral == 1000 and ch.accounts[leader].collateral == 99_000
    r = m.process_transaction(_tx(m, vault, ExchangeOpType.PERP_ORDER, _order(), signer=leader))
    assert r.success, r.error
    assert ch.markets[MID].orders[r.data["order_id"]].owner == vault
    for signer in (stranger, bot):
        r = m.process_transaction(_tx(m, vault, ExchangeOpType.PERP_ORDER, _order(),
                                      signer=signer))
        assert not r.success and "may not act" in r.error
    m.process_transaction(_tx(m, leader, ExchangeOpType.AGENT_APPROVE, {"agent": bot}))
    assert m.process_transaction(_tx(m, vault, ExchangeOpType.PERP_ORDER, _order("98"),
                                     signer=bot)).success           # the leader's agent
    r = m.process_transaction(_tx(m, vault, ExchangeOpType.PERP_WITHDRAW, {"amount": "1"},
                                  signer=leader))
    assert not r.success and "may not sign" in r.error
    r = m.process_transaction(_tx(m, vault, ExchangeOpType.PERP_ORDER, _order("111"),
                                  signer=leader))
    assert not r.success and "worse than the mark" in r.error


def test_joining_and_leaving_a_vault_at_nav_with_the_leaders_profit_share(m, keys):
    leader, joiner, taker = keys["owner"].addr, keys["stranger"].addr, keys["bot"].addr
    ch = m.clearinghouse
    vault = _vault(m, leader, profit_share="0.2")
    r = m.process_transaction(_tx(m, joiner, ExchangeOpType.VAULT_DEPOSIT,
                                  {"vault": vault, "amount": "1000"}))
    assert r.success and D(r.data["shares"]) == 1000           # NAV 1 a share
    # The vault goes long 10 at 100; the mark rises to 110: NAV 2,100 → 1.05 a share.
    ch.place_order(taker, MID, "ask", "sell", D(10), D(100), 0)
    assert m.process_transaction(_tx(m, vault, ExchangeOpType.PERP_ORDER, {
        "market_id": MID, "side": "buy", "size": "10", "price": "100"}, signer=leader)).success
    ch.set_oracle_price(MID, D(110), now=T0)
    r = m.process_transaction(_tx(m, joiner, ExchangeOpType.VAULT_WITHDRAW,
                                  {"vault": vault, "shares": "1000"}))
    assert not r.success and "locked" in r.error
    m.begin_block(2, float(T0 + 24 * 3600))
    before = ch.accounts[leader].collateral
    ch.place_order(taker, MID, "bid", "buy", D(10), D(110), 0)       # the vault takes profit
    assert m.process_transaction(_tx(m, vault, ExchangeOpType.PERP_ORDER, {
        "market_id": MID, "side": "sell", "size": "10", "price": "110", "reduce_only": True},
        signer=leader)).success
    nav = ch.cross_equity(vault)
    r = m.process_transaction(_tx(m, joiner, ExchangeOpType.VAULT_WITHDRAW,
                                  {"vault": vault, "shares": "1000"}))
    assert r.success, r.error
    value = (D(1000) * nav / 2000).quantize(D("1e-18"))
    fee = ((value - 1000) * D("0.2")).quantize(D("1e-18"))
    assert D(r.data["value"]) == value - fee and D(r.data["profit_share"]) == fee
    assert ch.accounts[leader].collateral == before + fee
    assert ch.identity_gap() == 0


def test_the_leader_keeps_its_minimum_share(m, keys):
    leader, joiner = keys["owner"].addr, keys["stranger"].addr
    vault = _vault(m, leader, amount="100")
    r = m.process_transaction(_tx(m, joiner, ExchangeOpType.VAULT_DEPOSIT,
                                  {"vault": vault, "amount": "2000"}))
    assert not r.success and "at least" in r.error              # 100 / 2,100 < 5 %
    assert m.process_transaction(_tx(m, joiner, ExchangeOpType.VAULT_DEPOSIT,
                                     {"vault": vault, "amount": "1900"})).success
    r = m.process_transaction(_tx(m, leader, ExchangeOpType.VAULT_WITHDRAW,
                                  {"vault": vault, "shares": "1"}))
    assert not r.success and "at least" in r.error
    for params, error in [({"amount": "99"}, "at least 100"),
                          ({"amount": "100", "profit_share": "0.6"}, "profit share")]:
        r = m.process_transaction(_tx(m, leader, ExchangeOpType.VAULT_CREATE, params))
        assert not r.success and error in r.error


def test_a_vaults_gas_is_paid_by_its_leader(m, keys):
    from qrdx.exchange import block_processor as BP

    leader = keys["owner"].addr
    vault = _vault(m, leader)
    BP.apply_enforcement(m)
    m.set_available_balance(leader, D(10))
    r = m.process_transaction(_tx(m, vault, ExchangeOpType.PERP_ORDER, _order(), signer=leader))
    assert r.success, r.error
    assert m.balance_deltas()[leader] == -r.fee and vault not in m.balance_deltas()
