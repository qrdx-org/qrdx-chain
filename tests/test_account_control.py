"""
Account control (docs/ACCOUNT_CONTROL.md): who may sign for an account, as consensus state —
controllers bound to it, its own key on or off, a delay on changes its own key signs — and
multisig keys that sign like any other, on the exchange and in the EVM.
"""
import os
import tempfile
from decimal import Decimal as D

import pytest

from qrdx.constants import CHAIN_ID
from qrdx.contracts.evm_mempool import verify_delegated_spend
from qrdx.crypto import multisig_wire
from qrdx.crypto.account_id import to_account_id
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import ExchangeOpType as Op
from qrdx.exchange import ExchangeStateManager, ExchangeTransaction
from qrdx.exchange.block_processor import verify_exchange_tx
from qrdx.exchange.transactions import EXCHANGE_GAS_COSTS, MULTISIG_GAS_PER_SIGNATURE
from qrdx.transactions.pq_tx import PQTransaction, decode_pq_tx

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
    return {n: Key() for n in ("owner", "cold", "thief", "bot")}


@pytest.fixture(scope="module")
def msig():
    members = [PQPrivateKey.generate() for _ in range(3)]
    return members, multisig_wire.keyset_of([k.public_key for k in members], 2)


@pytest.fixture
def m(keys, msig):
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.begin_block(1, float(T0))
    mgr.clearinghouse.create_market("BTC")
    mgr.clearinghouse.set_oracle_price(MID, D(100), now=T0)
    for addr in [k.addr for k in keys.values()] + [msig[1].address]:
        mgr.clearinghouse.deposit(addr, D(10_000))
    yield mgr
    ExchangeStateManager.reset_instance()


def _tx(m, sender, op, params, signer=""):
    lane = f"{sender}|{signer}" if signer else sender
    return ExchangeTransaction(op_type=op, sender=sender, signer=signer, params=params,
                               nonce=m.get_nonce(lane), gas_limit=10 ** 6)


def _run(m, sender, op, params, signer=""):
    return m.process_transaction(_tx(m, sender, op, params, signer))


def _policy(m, sender, signer="", **params):
    return _run(m, sender, Op.ACCOUNT_POLICY, params, signer)


ORDER = {"market_id": MID, "side": "buy", "size": "1", "price": "99"}


def _tick(m, t):
    from qrdx.exchange.block_processor import _execute_block_boundary_duties

    m.begin_block(int(t), float(t))
    _execute_block_boundary_duties(m, int(t), float(t))


# ── binding and the own key ─────────────────────────────────────────────────

def test_a_bound_controller_signs_anything_for_the_account(m, keys):
    owner, cold = keys["owner"].addr, keys["cold"].addr
    r = _run(m, owner, Op.PERP_WITHDRAW, {"amount": "1"}, signer=cold)
    assert not r.success and "may not act" in r.error
    assert _policy(m, owner, action="add_controller", controller=cold).data["applied"]
    r = _run(m, owner, Op.PERP_WITHDRAW, {"amount": "1"}, signer=cold)   # not only trading
    assert r.success, r.error
    assert _run(m, owner, Op.PERP_ORDER, ORDER, signer=cold).success
    signed = keys["cold"].sign(_tx(m, owner, Op.PERP_ORDER, ORDER, signer=cold))
    assert verify_exchange_tx(signed) == (True, "")


def test_with_its_own_key_off_only_its_controllers_sign_for_it(m, keys):
    owner, cold, bot = keys["owner"].addr, keys["cold"].addr, keys["bot"].addr
    r = _policy(m, owner, action="own_key", enabled=False)
    assert not r.success and "bind a controller" in r.error
    _policy(m, owner, action="add_controller", controller=cold)
    _run(m, owner, Op.AGENT_APPROVE, {"agent": bot})
    assert _policy(m, owner, signer=cold, action="own_key", enabled=False).success
    nonce = m.get_nonce(owner)
    r = _run(m, owner, Op.PERP_ORDER, ORDER)
    assert not r.success and "turned off" in r.error and m.get_nonce(owner) == nonce  # untouched
    r = _run(m, owner, Op.PERP_ORDER, ORDER, signer=bot)
    assert not r.success and "agents act for it no more" in r.error
    assert _run(m, owner, Op.PERP_ORDER, ORDER, signer=cold).success
    r = _policy(m, owner, signer=cold, action="remove_controller", controller=cold)
    assert not r.success and "keeps a controller" in r.error


def test_a_turned_off_key_signs_for_nothing(m, keys):
    owner, cold = keys["owner"].addr, keys["cold"].addr
    thief = keys["thief"].addr
    _policy(m, owner, action="add_controller", controller=cold)
    # The controller's own account turns its key off: it is no controller any more either.
    _policy(m, cold, action="add_controller", controller=thief)
    _policy(m, cold, signer=thief, action="own_key", enabled=False)
    r = _run(m, owner, Op.PERP_ORDER, ORDER, signer=cold)
    assert not r.success and "turned off" in r.error


# ── the delay ───────────────────────────────────────────────────────────────

def test_the_own_keys_changes_wait_out_the_delay_and_controllers_cancel_them(m, keys):
    owner, cold, thief = keys["owner"].addr, keys["cold"].addr, keys["thief"].addr
    _policy(m, owner, action="add_controller", controller=cold)
    assert _policy(m, owner, action="delay", seconds=3600).data["applied"]   # longer: at once
    # A stolen own key tries to bind the thief: it waits, in the open.
    r = _policy(m, owner, action="add_controller", controller=thief)
    assert r.success and not r.data["applied"] and D(r.data["due"]) == T0 + 3600
    assert not m.authority.may_control(owner, thief)
    cid = r.data["change_id"]
    assert _policy(m, owner, signer=cold, action="cancel", change_id=cid).success
    _tick(m, T0 + 3601)
    assert not m.authority.may_control(owner, thief)


def test_a_waiting_change_applies_at_its_time_unless_the_own_key_was_turned_off(m, keys):
    owner, cold, thief = keys["owner"].addr, keys["cold"].addr, keys["thief"].addr
    _policy(m, owner, action="add_controller", controller=cold)
    _policy(m, owner, action="delay", seconds=60)
    first = _policy(m, owner, action="delay", seconds=30)            # shorter: it waits
    _tick(m, T0 + 59)
    assert m.authority.policy(owner).delay == 60
    _tick(m, T0 + 60)
    assert m.authority.policy(owner).delay == 30 and first.success
    _policy(m, owner, action="add_controller", controller=thief)     # waits 30 s…
    _policy(m, owner, signer=cold, action="own_key", enabled=False)  # …the controller acts
    _tick(m, T0 + 100)
    assert not m.authority.may_control(owner, thief)                # dropped


@pytest.mark.parametrize("params, error", [
    ({"action": "add_controller", "controller": "0x" + "1" * 40}, "post-quantum"),
    ({"action": "delay", "seconds": 10 ** 9}, "delay is"),
    ({"action": "own_key", "enabled": "false"}, "true or false"),
    ({"action": "remove_controller", "controller": "0xPQ" + "1" * 64}, "not a controller"),
])
def test_policy_changes_that_make_no_sense_are_refused(m, keys, params, error):
    r = _policy(m, keys["owner"].addr, **params)
    assert not r.success and error in r.error


def test_an_account_does_not_control_itself_and_agents_do_not_change_policies(m, keys):
    owner, bot = keys["owner"].addr, keys["bot"].addr
    r = _policy(m, owner, action="add_controller", controller=owner)
    assert not r.success and "itself" in r.error
    _run(m, owner, Op.AGENT_APPROVE, {"agent": bot})
    r = _policy(m, owner, signer=bot, action="add_controller", controller=bot)
    assert not r.success


# ── multisig ────────────────────────────────────────────────────────────────

def _msig_sign(tx, members, keyset):
    tx.public_key, tx.signature = multisig_wire.sign(keyset, members, tx.signing_bytes())
    return tx


def test_a_multisig_account_signs_exchange_transactions(m, msig):
    members, keyset = msig
    tx = _tx(m, keyset.address, Op.PERP_ORDER, ORDER)
    tx.gas_limit = EXCHANGE_GAS_COSTS[Op.PERP_ORDER] + 2 * MULTISIG_GAS_PER_SIGNATURE
    _msig_sign(tx, members[:2], keyset)
    assert tx.verify() and verify_exchange_tx(tx) == (True, "")
    r = m.process_transaction(tx)
    assert r.success, r.error
    assert r.gas_used == EXCHANGE_GAS_COSTS[Op.PERP_ORDER] + 2 * MULTISIG_GAS_PER_SIGNATURE


def test_too_few_signers_or_too_little_gas_is_refused(m, msig):
    members, keyset = msig
    tx = _tx(m, keyset.address, Op.PERP_ORDER, ORDER)
    _msig_sign(tx, members[:2], keyset)
    tx.signature = tx.signature.replace(b'"m":2', b'"m":1')         # claim a lower threshold
    assert not tx.verify()
    other = multisig_wire.keyset_of([k.public_key for k in members], 3)  # another keyset
    tx = _msig_sign(_tx(m, keyset.address, Op.PERP_ORDER, ORDER), members, other)
    assert not tx.verify()                                            # derives to another address
    tx = _msig_sign(_tx(m, keyset.address, Op.PERP_ORDER, ORDER), members[:2], keyset)
    tx.gas_limit = EXCHANGE_GAS_COSTS[Op.PERP_ORDER]
    ok, err = verify_exchange_tx(tx)
    assert not ok and "does not cover" in err


def test_a_multisig_controller(m, keys, msig):
    members, keyset = msig
    owner = keys["owner"].addr
    _policy(m, owner, action="add_controller", controller=keyset.address)
    tx = _tx(m, owner, Op.PERP_WITHDRAW, {"amount": "1"}, signer=keyset.address)
    _msig_sign(tx, members[1:], keyset)
    assert tx.verify()
    assert m.process_transaction(tx).success


# ── the EVM ─────────────────────────────────────────────────────────────────

def _evm(priv=None, keyset=None, members=None, on_behalf_of=None):
    tx = PQTransaction(chain_id=CHAIN_ID, nonce=0, gas_price=10 ** 9, gas_limit=900_000,
                       to=bytes(20), value=1, data=b"", on_behalf_of=on_behalf_of)
    if keyset is not None:
        tx.public_key, tx.signature = multisig_wire.sign(keyset, members, tx.signing_hash())
        return tx
    return tx.sign(priv)


async def test_a_controller_spends_from_the_account_it_controls_in_the_evm(m, keys):
    from qrdx.database_sqlite import DatabaseSQLite

    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    try:
        owner = keys["owner"]
        source = bytes.fromhex(to_account_id(owner.addr)[2:])
        raw = "0x" + _evm(keys["cold"].key, on_behalf_of=source).encode().hex()
        ok, why = await verify_delegated_spend(db, raw)
        assert not ok
        _policy(m, owner.addr, action="add_controller", controller=keys["cold"].addr)
        assert await verify_delegated_spend(db, raw) == (True, "")
        own = "0x" + _evm(owner.key).encode().hex()
        assert await verify_delegated_spend(db, own) == (True, "")
        _policy(m, owner.addr, signer=keys["cold"].addr, action="own_key", enabled=False)
        ok, why = await verify_delegated_spend(db, own)
        assert not ok and "turned off" in why                     # its own key, refused
    finally:
        path = db.db_path
        await db.close()
        os.remove(path)


def test_a_multisig_signs_an_evm_transaction(msig):
    members, keyset = msig
    tx = _evm(keyset=keyset, members=members[:2])
    decoded = decode_pq_tx(tx.encode())
    assert decoded.verify() and decoded.sender() == to_account_id(keyset.address)
    single = PQTransaction(chain_id=CHAIN_ID, nonce=0, gas_price=1, gas_limit=1, to=bytes(20),
                           value=0, data=b"").sign(members[0])
    assert decoded.intrinsic_gas() > single.intrinsic_gas()      # every partial verified
    tampered = decode_pq_tx(tx.encode())
    tampered.value = 2
    assert not tampered.verify()


def test_policies_are_committed(m, keys):
    root = m.compute_state_root()
    _policy(m, keys["owner"].addr, action="add_controller", controller=keys["cold"].addr)
    assert m.compute_state_root() != root
    m.verify_commitments()
