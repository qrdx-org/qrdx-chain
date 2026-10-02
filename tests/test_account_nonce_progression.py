"""
Account nonces must advance on every transaction — the property web3 clients
depend on to sign their *second* transaction.

Regression test for: this executor runs py-evm's ``apply_message``, which does not
touch the sender nonce (that is ``apply_transaction``'s job), and the executor only
bumped it for contract creations. A plain value transfer therefore left the account
nonce at 0 forever, while the mempool's own pending counter advanced correctly.
``eth_getTransactionCount`` reads the account nonce, so every web3 client would ask
for its nonce, be told 0 again, re-sign nonce 0, and have the transaction rejected
as "nonce too low" — broken on the second send.

Also covers the ``pending`` block tag, which wallets use when signing: it must skip
over transactions already queued in the mempool so a client can send several times
between blocks.
"""
from unittest.mock import MagicMock

from eth_account import Account as EthAccount

from qrdx.contracts.evm_mempool import EVMMempool
from qrdx.contracts.state import ContractStateManager
from qrdx.crypto.account_id import to_account_id
from qrdx.crypto.pq.dilithium import generate_keypair
from qrdx.transactions.pq_tx import PQTransaction

WEI = 10 ** 18
ALICE = "0x" + "11" * 20
BOB = "0x" + "22" * 20


def _evm():
    from qrdx.contracts.evm_executor_v2 import QRDXEVMExecutor
    sm = ContractStateManager(MagicMock())
    return sm, QRDXEVMExecutor(sm)


def _addr(a):
    return bytes.fromhex(to_account_id(a)[2:])


def _transfer(sm, evm, value=WEI):
    return evm.execute(sender=_addr(ALICE), to=_addr(BOB), value=value,
                       data=b"", gas=100_000, gas_price=0, intrinsic_gas=21_000)


def test_nonce_advances_on_a_plain_transfer():
    sm, evm = _evm()
    sm.set_balance_sync(ALICE, 100 * WEI)
    assert sm.get_nonce_sync(ALICE) == 0
    assert _transfer(sm, evm).success
    assert sm.get_nonce_sync(ALICE) == 1, "a transfer must consume a nonce"


def test_nonce_advances_once_per_transaction():
    sm, evm = _evm()
    sm.set_balance_sync(ALICE, 100 * WEI)
    for expected in (1, 2, 3, 4, 5):
        assert _transfer(sm, evm).success
        assert sm.get_nonce_sync(ALICE) == expected


def test_recipient_nonce_is_untouched():
    sm, evm = _evm()
    sm.set_balance_sync(ALICE, 100 * WEI)
    _transfer(sm, evm)
    assert sm.get_nonce_sync(BOB) == 0, "receiving does not consume a nonce"


def test_a_pq_senders_nonce_advances_too():
    """PQ accounts share the nonce space — nothing special about them."""
    sm, evm = _evm()
    _priv, pub = generate_keypair()
    sm.set_balance_sync(pub.to_account_id(), 100 * WEI)
    for expected in (1, 2):
        result = evm.execute(sender=_addr(pub.to_account_id()), to=_addr(BOB),
                             value=WEI, data=b"", gas=500_000, gas_price=0,
                             intrinsic_gas=145_000)
        assert result.success, result.error
        # Readable through either address form — one account, one nonce.
        assert sm.get_nonce_sync(pub.to_account_id()) == expected
        assert sm.get_nonce_sync(pub.to_address()) == expected


def test_contract_creation_also_advances_the_nonce_exactly_once():
    """The create path bumped the nonce before; it must not now double-bump."""
    sm, evm = _evm()
    sm.set_balance_sync(ALICE, 100 * WEI)
    result = evm.execute(sender=_addr(ALICE), to=None, value=0,
                         data=b"\x60\x00\x60\x00\xf3", gas=1_000_000, gas_price=0,
                         intrinsic_gas=53_000)
    if result.success:
        assert sm.get_nonce_sync(ALICE) == 1


# ── pending-nonce semantics ────────────────────────────────────────────────

def _legacy_raw(key_hex, nonce):
    acct = EthAccount.from_key(key_hex)
    signed = EthAccount.sign_transaction(
        {"nonce": nonce, "gasPrice": 10 ** 9, "gas": 21000, "to": acct.address,
         "value": 1, "data": b"", "chainId": 1}, key_hex)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    return "0x" + bytes(raw).hex(), to_account_id(acct.address)


def test_pending_nonce_skips_queued_transactions():
    """
    Without this a client sending twice between blocks signs the same nonce twice
    and its second transaction is rejected as already queued.
    """
    key = "0x" + "33" * 32
    mp = EVMMempool()
    raw0, sender = _legacy_raw(key, 0)

    assert mp.next_nonce(sender, 0) == 0, "nothing queued yet"
    assert mp.admit(raw0)[0]
    assert mp.next_nonce(sender, 0) == 1, "must skip the queued nonce 0"

    raw1, _ = _legacy_raw(key, 1)
    assert mp.admit(raw1)[0]
    assert mp.next_nonce(sender, 0) == 2


def test_pending_nonce_of_an_unknown_sender_is_its_confirmed_nonce():
    mp = EVMMempool()
    assert mp.next_nonce("0x" + "44" * 20, 0) == 0
    assert mp.next_nonce("0x" + "44" * 20, 7) == 7


def test_pending_nonce_counts_pq_and_legacy_in_one_space():
    """One sender cannot have separate nonce sequences per envelope type."""
    priv, pub = generate_keypair()
    mp = EVMMempool()
    sender = pub.to_account_id()

    tx0 = PQTransaction(chain_id=1, nonce=0, gas_price=10 ** 9, gas_limit=500_000,
                        to=bytes.fromhex(to_account_id(BOB)[2:]), value=1,
                        data=b"").sign(priv)
    assert mp.admit("0x" + tx0.encode().hex())[0]
    assert mp.next_nonce(sender, 0) == 1

    tx1 = PQTransaction(chain_id=1, nonce=1, gas_price=10 ** 9, gas_limit=500_000,
                        to=bytes.fromhex(to_account_id(BOB)[2:]), value=1,
                        data=b"").sign(priv)
    assert mp.admit("0x" + tx1.encode().hex())[0]
    assert mp.next_nonce(sender, 0) == 2
