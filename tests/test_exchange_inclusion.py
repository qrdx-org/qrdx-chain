"""
Which exchange transactions a block may carry (chain-spec feature ``exchange_inclusion``;
docs/KNOWN_ISSUES.md, "Unfunded exchange transactions rode in blocks for free").

A transaction refused before it runs — reported: its payer could not cover gas_limit × gas_price
— used to be admitted, selected and carried in a block without executing, paying or consuming
its nonce. One zero-balance account could fill blocks with it again and again. Now:

* admission refuses a transaction whose payer cannot pay for its gas;
* a proposer judges its whole selection before running anything, on the balances its importers
  will read, and leaves out what may not be in the block;
* a block that carries such a transaction is invalid, and each payer's fees are reserved before
  anything in the block runs, so an earlier operation cannot starve a later one's gas.
"""
from decimal import Decimal as D

import pytest

from qrdx import chain_spec as cs
from qrdx import constants
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import ExchangeMempool, ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from qrdx.exchange import block_processor as BP
from qrdx.exchange.submission import ExchangeSubmitter

GWEI = 10 ** 9
GAS = 1_000_000
MAX_FEE = D(GAS * GWEI) / D(10 ** 18)                      # 0.001 QRDX reserved per transaction
ALICE, BOB, EVE = "0xPQ" + "a" * 64, "0xPQ" + "b" * 64, "0xPQ" + "e" * 64
MID = "BTC-QRDX-PERP"
T0 = 1_700_000_000
Op = ExchangeOpType


@pytest.fixture(autouse=True)
def _one_gwei_floor(monkeypatch):
    monkeypatch.setattr(constants, "EXCHANGE_MIN_GAS_PRICE_WEI", GWEI)


@pytest.fixture
def m():
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    BP.apply_enforcement(mgr)
    mgr.begin_block(1, float(T0))
    yield mgr
    ExchangeStateManager.reset_instance()


def _tx(op, params=None, sender=ALICE, nonce=0, signer="", gas_price=GWEI):
    return ExchangeTransaction(op_type=op, sender=sender, signer=signer, nonce=nonce,
                               params=params or {}, gas_limit=GAS, gas_price=gas_price)


def _block(m, txs, balances, height=2):
    for holder, amount in balances.items():
        m.set_available_balance(holder, D(amount))
    return BP.process_exchange_transactions(height, float(T0 + height), txs, m)


def _without_the_rule():
    return cs.use_spec(cs.build_spec(
        "qrdx-test-no-inclusion", 991242, {}, dev=True,
        features=[f for f in cs.GENESIS_DEFAULT_FEATURES if f != "exchange_inclusion"]))


def test_the_reported_case_an_unfunded_account_cannot_be_carried(m):
    tx = _tx(Op.CANCEL_ALL, sender=EVE)
    m.set_available_balance(EVE, D(0))
    assert "insufficient QRDX for gas" in m.section_errors([tx], 2, float(T0 + 2))[0]
    ok, err, _root = _block(m, [tx], {EVE: 0})
    assert not ok and "exchange transaction 0 may not be in the block" in err
    assert "insufficient QRDX for gas" in err
    assert m.get_nonce(EVE) == 0 and m.balance_deltas() == {}


def test_before_the_rule_it_rode_along_unexecuted_and_could_again(m):
    """The finding, on a network without the rule: carried, unpaid, nonce unconsumed — so the
    same nonce can be carried again in the next block."""
    with _without_the_rule():
        for height in (2, 3):
            ok, _err, _root = _block(m, [_tx(Op.CANCEL_ALL, sender=EVE)], {EVE: 0}, height)
            assert ok and m.get_nonce(EVE) == 0 and m.balance_deltas() == {}


def test_a_payers_fees_in_a_block_count_together(m):
    txs = [_tx(Op.CANCEL_ALL, nonce=0), _tx(Op.CANCEL_ALL, nonce=1)]
    m.set_available_balance(ALICE, MAX_FEE)                 # enough for one, not two
    errors = m.section_errors(txs, 2, float(T0 + 2))
    assert list(errors) == [1] and "may cost 0.002" in errors[1]
    assert not _block(m, txs, {ALICE: MAX_FEE})[0]
    assert _block(m, txs[:1], {ALICE: MAX_FEE})[0] and m.get_nonce(ALICE) == 1


def test_a_refused_transaction_takes_its_lane_with_it(m):
    txs = [_tx(Op.CANCEL_ALL, sender=EVE, nonce=0), _tx(Op.CANCEL_ALL, sender=EVE, nonce=1),
           _tx(Op.CANCEL_ALL, sender=BOB, nonce=0)]
    errors = m.section_errors(txs, 2, float(T0 + 2), {EVE: D(0), BOB: D(1)}.get)
    assert sorted(errors) == [0, 1] and "out of sequence" in errors[1]


def test_judging_a_block_changes_nothing(m):
    m.set_available_balance(ALICE, D(5))
    before = (m.compute_state_root(), m._block_clock(), m.exchange_base_fee)
    m.section_errors([_tx(Op.CANCEL_ALL)], 9, float(T0 + 99), base_fee=7 * GWEI)
    assert (m.compute_state_root(), m._block_clock(), m.exchange_base_fee) == before


def test_an_earlier_operation_cannot_spend_a_later_ones_gas(m):
    """Fees are reserved up front: the transfer cannot take the QRDX the cancel's gas needs.
    Before the rule the transfer went through and the cancel was then refused for gas — left
    in the block unexecuted."""
    held = D(1) + 2 * MAX_FEE
    txs = [_tx(Op.TOKEN_TRANSFER, {"token_address": "QRDX", "to": BOB, "amount": "1.001"}),
           _tx(Op.CANCEL_ALL, nonce=1)]
    ok, _err, _root = _block(m, txs, {ALICE: held})
    assert ok and m.get_nonce(ALICE) == 2
    transfer, cancel = m._block_results
    assert not transfer.success and "insufficient QRDX" in transfer.error
    assert cancel.success and cancel.fee > 0
    assert m.balance_deltas()[ALICE] == -(transfer.fee + cancel.fee)

    ExchangeStateManager.reset_instance()
    old = ExchangeStateManager.get_instance()
    BP.apply_enforcement(old)
    with _without_the_rule():
        ok, _err, _root = _block(old, txs, {ALICE: held})
    assert ok and old.get_nonce(ALICE) == 1                 # the cancel never ran
    assert [r.success for r in old._block_results] == [True]


def test_a_signer_revoked_earlier_in_the_block_fails_and_pays(m):
    """Judged at the block's start the agent may act; the revoke runs first, so its order runs
    as a failure — paying for its gas and consuming its lane's nonce, never a free ride."""
    owner, bot = ALICE, "0xPQ" + "c" * 64
    m.clearinghouse.create_market("BTC")
    m.clearinghouse.set_oracle_price(MID, D(100), now=T0)
    m.clearinghouse.deposit(owner, D(1000))
    m.set_available_balance(owner, D(1))
    assert m.process_transaction(_tx(Op.AGENT_APPROVE, {"agent": bot})).success
    order = _tx(Op.PERP_ORDER, {"market_id": MID, "side": "buy", "size": "1", "price": "99"},
                sender=owner, signer=bot, nonce=0)
    txs = [_tx(Op.AGENT_REVOKE, {"agent": bot}, nonce=1), order]
    assert m.section_errors(txs, 2, float(T0 + 2), {owner: D(1)}.get) == {}
    ok, err, _root = _block(m, txs, {owner: D(1)})
    assert ok, err
    revoke, refused = m._block_results
    assert revoke.success and not refused.success and "may not act" in refused.error
    assert refused.fee > 0 and m.get_nonce(f"{owner}|{bot}") == 1
    assert not m.clearinghouse.markets[MID].orders


def test_the_free_lane_needs_a_holding_to_be_carried(m, monkeypatch):
    monkeypatch.setattr(constants, "EXCHANGE_FREE_TRADING", True)
    tx = _tx(Op.CANCEL_ALL, sender=EVE, gas_price=0)
    assert tx.free_eligible()
    errors = m.section_errors([tx], 2, float(T0 + 2), {EVE: D(0)}.get)
    assert "free trading needs a holding" in errors[0]
    assert not _block(m, [tx], {EVE: 0})[0]


class _Ledger:
    """The balances account_state holds (what a node pre-loads)."""

    def __init__(self, balances):
        self.balances = balances

    async def get_address_balance(self, address):
        return self.balances.get(address, D(0))

    async def get_token_balance(self, token, holder):
        return D(0)


async def test_the_proposer_leaves_out_what_may_not_be_in_the_block_and_its_importers_agree():
    ledger = _Ledger({ALICE: D(5), BOB: D(5)})
    txs = [_tx(Op.CANCEL_ALL, sender=ALICE), _tx(Op.CANCEL_ALL, sender=BOB),
           _tx(Op.CANCEL_ALL, sender=EVE), _tx(Op.CANCEL_ALL, sender=EVE, nonce=1)]

    async def run(selection, proposer):
        ExchangeStateManager.reset_instance()
        mgr = ExchangeStateManager.get_instance()
        BP.apply_enforcement(mgr)
        if proposer:
            selection, refused = await BP.includable_exchange_txs(
                ledger, selection, 2, float(T0 + 2), None, mgr)
        else:
            refused = []
        await BP.preload_sender_balances(ledger, selection, mgr, 2)
        await BP.preload_token_balances(ledger, selection, mgr)
        ok, err, root = BP.process_exchange_transactions(2, float(T0 + 2), selection, mgr)
        assert ok, err
        return selection, refused, root

    try:
        kept, refused, proposed = await run(txs, proposer=True)
        assert kept == txs[:2] and [t.sender for t, _ in refused] == [EVE, EVE]
        assert "insufficient QRDX for gas" in refused[0][1]
        _same, _none, imported = await run(kept, proposer=False)
        assert imported == proposed
    finally:
        ExchangeStateManager.reset_instance()


class _Key:
    def __init__(self):
        self.key = PQPrivateKey.generate()
        self.addr = self.key.public_key.to_address()

    def signed(self, op, params, nonce=0):
        tx = ExchangeTransaction(op_type=op, sender=self.addr, nonce=nonce, params=params,
                                 gas_limit=GAS, gas_price=GWEI)
        tx.public_key = self.key.public_key.to_bytes()
        tx.signature = self.key.sign(tx.signing_bytes()).to_bytes()
        return tx


async def test_admission_refuses_a_payer_who_cannot_pay_for_its_gas():
    ExchangeStateManager.reset_instance()
    try:
        rich, broke = _Key(), _Key()
        balances = {rich.addr: D(1), broke.addr: D(0)}

        async def balance(address):
            return balances[address]

        async def forward(url, tx_dict):
            pass

        pool = ExchangeMempool(nonce_provider=lambda lane: 0)
        sub = ExchangeSubmitter(lambda: pool, lambda: [], forward, get_balance=balance)
        ok, err, _h = await sub.submit(broke.signed(Op.CANCEL_ALL, {}))
        assert not ok and "insufficient QRDX for gas" in err and pool.size() == 0
        ok, err, tx_hash = await sub.submit(rich.signed(Op.CANCEL_ALL, {}))
        assert ok and pool.contains(tx_hash)
    finally:
        ExchangeStateManager.reset_instance()
