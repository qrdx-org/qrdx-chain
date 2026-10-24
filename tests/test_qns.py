"""
QNS, the QRDX Name Service (docs/QNS.md): names are native NFTs in a protocol collection only
the protocol mints, registered for years at QNS_PRICE_PER_YEAR (10 QRDX by default) paid to the
treasury, resolving while they last; plus who controls an address (docs/CONSENSUS_ROADMAP.md B)
and every protocol holder's address (A).
"""
from decimal import Decimal as D

import pytest

from qrdx import constants
from qrdx.exchange import ExchangeOpType as Op
from qrdx.exchange import ExchangeStateManager, ExchangeTransaction, views
from qrdx.exchange.qns import (
    QNS_COLLECTION,
    QNS_GRACE_SECONDS,
    YEAR_SECONDS,
    name_token_id,
    normalize,
)

T0 = 1_700_000_000
ALICE = "0xPQ" + "a" * 64
BOB = "0xPQ" + "b" * 64
TREASURY = constants.SYSTEM_WALLET_ADDRESSES["TREASURY_MULTISIG"]


@pytest.fixture
def m():
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.begin_block(1, float(T0))
    for who in (ALICE, BOB):
        mgr.set_available_balance(who, D(1_000))
    yield mgr
    ExchangeStateManager.reset_instance()


def _tx(m, who, op, **params):
    return m.process_transaction(ExchangeTransaction(
        op_type=op, sender=who, nonce=m.get_nonce(who), params=params, gas_limit=10 ** 6))


def _at(m, t):
    m.begin_block(int(t), float(t))
    for who in (ALICE, BOB):
        m.set_available_balance(who, D(1_000))


def test_a_name_is_an_nft_paid_for_by_the_year(m):
    r = _tx(m, ALICE, Op.QNS_REGISTER, name="Alice", years=2)
    assert r.success, r.error
    price = 2 * constants.QNS_PRICE_PER_YEAR                       # 5 characters: the base price
    assert r.data["name"] == "alice.qrdx" and D(r.data["paid"]) == price
    assert m.balance_deltas()[ALICE] == -price and m.balance_deltas()[TREASURY] == price
    nft = m.nfts.items.peek((QNS_COLLECTION, name_token_id("alice.qrdx")))
    assert nft.owner == ALICE and nft.name == "alice.qrdx"
    assert m.nfts.get(QNS_COLLECTION).mint_authority.startswith("0xQNSA")
    now = D(T0)
    assert m.qns.resolve(m.nfts, "alice.qrdx", now) == ALICE
    assert views.controlled(m, ALICE)["names"] == ["alice.qrdx"]
    r = _tx(m, BOB, Op.QNS_REGISTER, name="alice.qrdx")
    assert not r.success and "registered" in r.error


def test_a_name_moves_as_an_nft_and_its_owner_sets_its_records(m):
    _tx(m, ALICE, Op.QNS_REGISTER, name="alice")
    r = _tx(m, BOB, Op.QNS_SET_RECORD, name="alice", key="address", value=BOB)
    assert not r.success and "owner" in r.error
    assert _tx(m, ALICE, Op.NFT_TRANSFER, collection=QNS_COLLECTION,
               token_id=str(name_token_id("alice.qrdx")), to=BOB).success
    assert _tx(m, BOB, Op.QNS_SET_RECORD, name="alice", key="address", value=BOB).success
    assert _tx(m, BOB, Op.QNS_SET_RECORD, name="alice", key="url", value="https://x").success
    summary = views_name(m, "alice.qrdx")
    assert summary["owner"] == BOB and summary["resolves_to"] == BOB
    assert summary["texts"] == {"url": "https://x"}


def views_name(m, name):
    from qrdx.exchange.qns import summary

    return summary(m.qns, m.nfts, name, D(m._block_clock()))


def test_a_primary_name_is_valid_only_while_the_name_resolves_to_its_account(m):
    _tx(m, ALICE, Op.QNS_REGISTER, name="alice")
    r = _tx(m, BOB, Op.QNS_SET_PRIMARY, name="alice")
    assert not r.success and "does not resolve" in r.error
    assert _tx(m, ALICE, Op.QNS_SET_PRIMARY, name="alice").success
    assert m.qns.reverse(m.nfts, ALICE, D(T0)) == "alice.qrdx"
    _tx(m, ALICE, Op.QNS_SET_RECORD, name="alice", key="address", value=BOB)
    assert m.qns.reverse(m.nfts, ALICE, D(T0)) is None                 # no longer its


def test_names_expire_lapse_and_are_reclaimed(m):
    _tx(m, ALICE, Op.QNS_REGISTER, name="alice")
    _at(m, T0 + YEAR_SECONDS)
    assert m.qns.resolve(m.nfts, "alice.qrdx", D(T0 + YEAR_SECONDS)) is None   # expired
    r = _tx(m, BOB, Op.QNS_REGISTER, name="alice")
    assert not r.success                                               # still in its grace
    assert _tx(m, BOB, Op.QNS_RENEW, name="alice", years=1).success   # anyone may renew
    assert m.qns.resolve(m.nfts, "alice.qrdx", D(T0 + YEAR_SECONDS)) == ALICE
    lapse = T0 + 2 * YEAR_SECONDS + QNS_GRACE_SECONDS
    _at(m, lapse)
    assert not _tx(m, ALICE, Op.QNS_RENEW, name="alice").success
    r = _tx(m, BOB, Op.QNS_REGISTER, name="alice")
    assert r.success, r.error
    nft = m.nfts.items.peek((QNS_COLLECTION, name_token_id("alice.qrdx")))
    assert nft.owner == BOB and m.nfts.get(QNS_COLLECTION).burned == 1


@pytest.mark.parametrize("name", ["ab", "-abc", "abc-", "a_b", "x" * 60, "ab.c.qrdx", ""])
def test_what_is_not_a_name_is_refused(name):
    with pytest.raises(ValueError):
        normalize(name)


def test_registering_needs_the_price_and_the_years_are_bounded(m):
    m.set_available_balance(ALICE, constants.QNS_PRICE_PER_YEAR / 2)
    r = _tx(m, ALICE, Op.QNS_REGISTER, name="alice")
    assert not r.success and f"costs {constants.QNS_PRICE_PER_YEAR}" in r.error
    r = _tx(m, BOB, Op.QNS_REGISTER, name="bob", years=11)
    assert not r.success and "years" in r.error
    assert _tx(m, BOB, Op.QNS_REGISTER, name="bob", years=10).success
    r = _tx(m, BOB, Op.QNS_RENEW, name="bob")
    assert not r.success and "at most 10 years" in r.error


def test_a_failed_registration_leaves_no_nft_behind(m):
    """The NFT registry's owner index rolls back with the operation (qrdx/exchange/undo.py)."""
    _tx(m, ALICE, Op.QNS_REGISTER, name="alice")
    before = (m.nfts.owned(ALICE), m.compute_state_root())
    m.set_available_balance(BOB, D(0))
    assert not _tx(m, BOB, Op.QNS_REGISTER, name="bobby").success
    assert m.nfts.owned(ALICE) == before[0] and m.nfts.owned(BOB) == []


# ── addresses and who controls them ─────────────────────────────────────────

def test_every_protocol_holder_has_an_address(m):
    from qrdx.crypto.account_id import is_synthetic_holder, to_account_id

    out = views.protocol_addresses(m)
    for key in ("perps_holder", "backstop_vault", "protocol_vault_shares", "veto_escrow",
                "bridge_mint_authority", "qns_mint_authority"):
        assert is_synthetic_holder(out[key]), key
        to_account_id(out[key])
    assert "TREASURY_MULTISIG" in out["system_wallets"]


def test_who_controls_an_address_both_ways(m):
    from qrdx.crypto import multisig_wire
    from qrdx.crypto.pq.dilithium import PQPrivateKey

    members = [PQPrivateKey.generate() for _ in range(3)]
    keyset = multisig_wire.keyset_of([k.public_key for k in members], 2)
    assert _tx(m, BOB, Op.ACCOUNT_POLICY, action="publish_keyset", keyset={
        "m": 2, "public_keys": [k.public_key.to_hex() for k in members]}).success
    assert _tx(m, ALICE, Op.ACCOUNT_POLICY, action="add_controller",
               controller=keyset.address).success
    who = views.authority(m, ALICE)
    assert who["controllers"][0]["address"] == keyset.address
    assert who["controllers"][0]["members"]["threshold"] == 2
    assert sorted(who["controllers"][0]["members"]["members"]) == sorted(
        k.public_key.to_address() for k in members)
    from qrdx.crypto.account_id import to_account_id

    assert views.controlled(m, keyset.address)["controls"] == [to_account_id(ALICE)]
    member = members[0].public_key.to_address()
    assert views.controlled(m, member)["multisigs"] == [keyset.address.lower()]


def test_short_names_cost_more(m):
    """ENS's ratios: a 3-character name 128 base prices a year, a 4-character one 32."""
    from qrdx.exchange.qns import price_factor

    assert [price_factor(n) for n in ("abc.qrdx", "abcd.qrdx", "abcde.qrdx", "x" * 40)] == [
        128, 32, 1, 1]
    m.set_available_balance(ALICE, D(1_000))
    r = _tx(m, ALICE, Op.QNS_REGISTER, name="abc")
    assert r.success and D(r.data["paid"]) == 128 * constants.QNS_PRICE_PER_YEAR
