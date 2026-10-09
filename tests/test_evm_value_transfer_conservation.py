"""
Native value transfers must move EXACTLY the transferred amount.

Regression test for a double-counting bug in ``QRDXEVMExecutor.execute``: the EVM
performs the value transfer internally (``apply_message``), ``_sync_from_evm``
wrote those post-execution balances back, and then ``execute`` applied ``value``
a *second* time by hand — so every native transfer credited the recipient 2x and
debited the sender 2x, and a reverted call still moved funds (the VM rolls its own
transfer back; the manual credit did not).

The bug was deterministic, so it never produced a fork — every node inflated
identically — which is exactly why a root-convergence soak could not find it and
why an exact-amount assertion is the only thing that can. Assertions here are on
precise amounts, never on "balance decreased".
"""
from unittest.mock import MagicMock

import pytest

from qrdx.contracts.state import ContractStateManager
from qrdx.crypto.account_id import to_account_id
from qrdx.constants import CHAIN_ID  # the network's chain id (chain spec)

WEI = 10 ** 18
ALICE = "0x" + "11" * 20
BOB = "0x" + "22" * 20


def _evm():
    from qrdx.contracts.evm_executor_v2 import QRDXEVMExecutor
    sm = ContractStateManager(MagicMock())
    return sm, QRDXEVMExecutor(sm)


def _addr(a):
    return bytes.fromhex(to_account_id(a)[2:])


def test_recipient_receives_exactly_the_transferred_value():
    sm, evm = _evm()
    sm.set_balance_sync(ALICE, 100 * WEI)

    result = evm.execute(sender=_addr(ALICE), to=_addr(BOB), value=5 * WEI,
                         data=b"", gas=100_000, gas_price=0)

    assert result.success, result.error
    assert sm.get_balance_sync(BOB) == 5 * WEI, "recipient credited the wrong amount"
    assert sm.get_balance_sync(ALICE) == 95 * WEI, "sender debited the wrong amount"


def test_total_supply_is_conserved_across_a_transfer():
    """The invariant the double-credit violated: nothing is minted by a transfer."""
    sm, evm = _evm()
    sm.set_balance_sync(ALICE, 100 * WEI)
    before = sm.get_balance_sync(ALICE) + sm.get_balance_sync(BOB)

    evm.execute(sender=_addr(ALICE), to=_addr(BOB), value=30 * WEI,
                data=b"", gas=100_000, gas_price=0)

    after = sm.get_balance_sync(ALICE) + sm.get_balance_sync(BOB)
    assert after == before == 100 * WEI, f"supply changed: {before} → {after}"


@pytest.mark.parametrize("value", [1, 10 ** 9, WEI, 17 * WEI, 99 * WEI])
def test_conservation_holds_at_every_magnitude(value):
    sm, evm = _evm()
    sm.set_balance_sync(ALICE, 100 * WEI)
    evm.execute(sender=_addr(ALICE), to=_addr(BOB), value=value,
                data=b"", gas=100_000, gas_price=0)
    assert sm.get_balance_sync(BOB) == value
    assert sm.get_balance_sync(ALICE) == 100 * WEI - value


def test_repeated_transfers_do_not_compound_the_error():
    """Three transfers of 1 QRDX move 3 QRDX total, not 6."""
    sm, evm = _evm()
    sm.set_balance_sync(ALICE, 100 * WEI)
    for _ in range(3):
        evm.execute(sender=_addr(ALICE), to=_addr(BOB), value=WEI,
                    data=b"", gas=100_000, gas_price=0)
    assert sm.get_balance_sync(BOB) == 3 * WEI
    assert sm.get_balance_sync(ALICE) == 97 * WEI


def test_zero_value_transfer_moves_nothing():
    sm, evm = _evm()
    sm.set_balance_sync(ALICE, 100 * WEI)
    evm.execute(sender=_addr(ALICE), to=_addr(BOB), value=0,
                data=b"", gas=100_000, gas_price=0)
    assert sm.get_balance_sync(BOB) == 0
    assert sm.get_balance_sync(ALICE) == 100 * WEI


def test_gas_is_charged_once_on_top_of_the_value():
    """
    Gas must still be charged — removing the manual value application must not have
    taken the gas charge with it.
    """
    from qrdx.contracts.evm_mempool import intrinsic_gas_legacy

    sm, evm = _evm()
    sm.set_balance_sync(ALICE, 100 * WEI)
    gas_price = 10 ** 9
    floor = intrinsic_gas_legacy(b"")

    result = evm.execute(sender=_addr(ALICE), to=_addr(BOB), value=WEI,
                         data=b"", gas=100_000, gas_price=gas_price,
                         intrinsic_gas=floor)

    assert result.success, result.error
    assert result.gas_used == floor == 21_000
    expected = 100 * WEI - WEI - floor * gas_price
    assert sm.get_balance_sync(ALICE) == expected
    assert sm.get_balance_sync(BOB) == WEI, "gas must not inflate the recipient"


def test_a_plain_transfer_is_not_free():
    """
    ``apply_message`` reports gas_used == 0 for an EOA-to-EOA transfer (it does no
    transaction-level gas accounting), so the intrinsic floor is the ONLY thing
    that makes a native transfer cost anything. Without it, transfers are free.
    """
    from qrdx.contracts.evm_mempool import intrinsic_gas_legacy

    sm, evm = _evm()
    sm.set_balance_sync(ALICE, 100 * WEI)
    result = evm.execute(sender=_addr(ALICE), to=_addr(BOB), value=WEI,
                         data=b"", gas=100_000, gas_price=10 ** 9,
                         intrinsic_gas=intrinsic_gas_legacy(b""))
    assert result.gas_used == 21_000
    assert sm.get_balance_sync(ALICE) < 99 * WEI, "no fee was charged"


def test_the_charge_never_exceeds_the_authorised_gas_limit():
    """A floor above the sender's gas limit must be capped, never over-charged."""
    sm, evm = _evm()
    sm.set_balance_sync(ALICE, 100 * WEI)
    result = evm.execute(sender=_addr(ALICE), to=_addr(BOB), value=WEI,
                         data=b"", gas=5_000, gas_price=10 ** 9,
                         intrinsic_gas=1_000_000)
    assert result.gas_used == 5_000


def test_pq_envelope_is_charged_its_larger_floor():
    """
    The PQ floor exists to price a ~5.3KB authentication envelope. Requiring it at
    admission is not enough — it has to actually be DEBITED, or the spam protection
    is nominal only.
    """
    from qrdx.contracts.evm_mempool import intrinsic_gas_legacy, parse_eth_raw_tx
    from qrdx.crypto.pq.dilithium import generate_keypair
    from qrdx.transactions.pq_tx import PQTransaction

    priv, pub = generate_keypair()
    tx = PQTransaction(chain_id=CHAIN_ID, nonce=0, gas_price=10 ** 9, gas_limit=500_000,
                       to=_addr(BOB), value=WEI, data=b"").sign(priv)
    parsed = parse_eth_raw_tx("0x" + tx.encode().hex())
    pq_floor = int(parsed["intrinsic_gas"])
    assert pq_floor > intrinsic_gas_legacy(b"") * 5, "PQ envelope is underpriced"

    sm, evm = _evm()
    sm.set_balance_sync(pub.to_account_id(), 100 * WEI)
    result = evm.execute(sender=_addr(pub.to_account_id()), to=_addr(BOB),
                         value=WEI, data=b"", gas=500_000, gas_price=10 ** 9,
                         intrinsic_gas=pq_floor)
    assert result.gas_used == pq_floor
    assert sm.get_balance_sync(pub.to_address()) == 100 * WEI - WEI - pq_floor * 10 ** 9


def test_sender_paying_itself_is_a_no_op_apart_from_gas():
    sm, evm = _evm()
    sm.set_balance_sync(ALICE, 100 * WEI)
    evm.execute(sender=_addr(ALICE), to=_addr(ALICE), value=10 * WEI,
                data=b"", gas=100_000, gas_price=0)
    assert sm.get_balance_sync(ALICE) == 100 * WEI, "self-transfer changed the balance"
